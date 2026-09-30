//! Bucket notifications to a real PostgreSQL. Runs when `TEIFS_TEST_POSTGRES` names a
//! server (`HOST:PORT`) whose user `teifs` has the password `TEIFS_TEST_POSTGRES_PASSWORD`
//! and owns the database `teifs` (nightly CI starts one, signing in with SCRAM-SHA-256,
//! and reads the tables back with `psql`); skipped otherwise.

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
use teifs_server::{Format, Postgres, TargetConfig, TargetKind};
use zeroize::Zeroizing;

fn target(id: &str, address: &str, table: &str, format: Format, password: &str) -> TargetConfig {
    let mut pg = Postgres::new(address, "teifs", table, format, "teifs").unwrap();
    pg.password = Some(Zeroizing::new(password.into()));
    TargetConfig::new(id, TargetKind::Postgres(pg)).unwrap()
}

#[tokio::test]
async fn events_reach_a_real_postgresql() {
    let Ok(address) = std::env::var("TEIFS_TEST_POSTGRES") else {
        eprintln!("skipped: TEIFS_TEST_POSTGRES isn't set");
        return;
    };
    let password = std::env::var("TEIFS_TEST_POSTGRES_PASSWORD").unwrap();
    let targets = vec![
        target(
            "objects",
            &address,
            "teifs_objects",
            Format::Namespace,
            &password,
        ),
        target("log", &address, "teifs_log", Format::Access, &password),
        target("wrong", &address, "teifs_wrong", Format::Access, "not-it"),
    ];
    let server = start_with(|config| config.notify = targets).await;
    let s3 = client(&server, SECRET_KEY);
    for id in ["objects", "log", "wrong"] {
        s3.create_bucket().bucket(id).send().await.unwrap();
        let rule = QueueConfiguration::builder()
            .queue_arn(format!("arn:teifs:sqs::{id}:postgresql"))
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
            assert!(err.contains("28P01"), "{err}");
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
        common::sent(&server, "postgresql", id, 3).await;
    }
}
