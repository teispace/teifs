//! Bucket notifications to a real MySQL or `MariaDB`. Runs when `TEIFS_TEST_MYSQL` names a
//! server (`HOST:PORT`) whose user `teifs` has the password `TEIFS_TEST_MYSQL_PASSWORD` and
//! owns the database `teifs`; `TEIFS_TEST_MYSQL_PUBLIC_KEY`, when set, is the server's
//! `public_key.pem` (nightly CI starts MySQL 8.4 and MariaDB, and reads the tables back with
//! their clients); skipped otherwise.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use aws_sdk_s3::{
    primitives::ByteStream,
    types::{Event, NotificationConfiguration, QueueConfiguration},
};
use common::{SECRET_KEY, client, start_with};
use teifs_server::{Format, Mysql, ServerKey, TargetConfig, TargetKind};
use zeroize::Zeroizing;

fn target(id: &str, address: &str, format: Format, password: &str, key: ServerKey) -> TargetConfig {
    let table = format!("teifs_{id}");
    let mut db = Mysql::new(address, "teifs", &table, format, "teifs").unwrap();
    db.password = Some(Zeroizing::new(password.into()));
    db.server_key = key;
    TargetConfig::new(id, TargetKind::Mysql(db)).unwrap()
}

#[tokio::test]
async fn events_reach_a_real_mysql() {
    let Ok(address) = std::env::var("TEIFS_TEST_MYSQL") else {
        eprintln!("skipped: TEIFS_TEST_MYSQL isn't set");
        return;
    };
    let password = std::env::var("TEIFS_TEST_MYSQL_PASSWORD").unwrap();
    // MySQL 8 wants the whole password the first time: encrypted with the key it was
    // given, or asked for.
    let given = std::env::var("TEIFS_TEST_MYSQL_PUBLIC_KEY").map_or(ServerKey::Ask, |path| {
        ServerKey::from_pem(&std::fs::read(path).unwrap()).unwrap()
    });
    let targets = vec![
        target("objects", &address, Format::Namespace, &password, given),
        target("log", &address, Format::Access, &password, ServerKey::Ask),
        target("wrong", &address, Format::Access, "not-it", ServerKey::Ask),
    ];
    let server = start_with(|config| config.notify = targets).await;
    let s3 = client(&server, SECRET_KEY);
    for id in ["objects", "log", "wrong"] {
        s3.create_bucket().bucket(id).send().await.unwrap();
        let rule = QueueConfiguration::builder()
            .queue_arn(format!("arn:teifs:sqs::{id}:mysql"))
            .events(Event::from("s3:ObjectCreated:*"))
            .events(Event::from("s3:ObjectRemoved:*"))
            .build()
            .unwrap();
        let set = s3
            .put_bucket_notification_configuration()
            .bucket(id)
            .notification_configuration(
                NotificationConfiguration::builder()
                    .queue_configurations(rule)
                    .build(),
            )
            .send()
            .await;
        if id == "wrong" {
            let err = format!("{:?}", set.unwrap_err());
            assert!(err.contains("1045"), "{err}");
            continue;
        }
        set.unwrap();
        for key in ["a.txt", "dir/b c.txt"] {
            s3.put_object()
                .bucket(id)
                .key(key)
                .body(ByteStream::from_static(b"hi"))
                .send()
                .await
                .unwrap();
        }
        s3.delete_object()
            .bucket(id)
            .key("a.txt")
            .send()
            .await
            .unwrap();
    }
    for id in ["objects", "log"] {
        common::sent(&server, "mysql", id, 3).await;
    }
}
