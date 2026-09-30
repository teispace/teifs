//! Bucket notifications to a real `RabbitMQ`. Runs when `TEIFS_TEST_AMQP` names a broker
//! (`amqp://HOST:PORT`) whose user `teifs` has the password `TEIFS_TEST_AMQP_PASSWORD`, with
//! the durable direct exchange `teifs` bound to a queue by the key `events` (nightly CI
//! starts one, and reads the messages back through its management API); skipped
//! otherwise.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use aws_sdk_s3::{
    primitives::ByteStream,
    types::{Event, NotificationConfiguration, QueueConfiguration},
};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start_with};
use teifs_server::{Amqp, TargetConfig, TargetKind};
use zeroize::Zeroizing;

fn target(id: &str, url: &str, password: &str, declare: bool) -> TargetConfig {
    let mut amqp = Amqp::new(url, "teifs", "events").unwrap();
    amqp.user = Some("teifs".into());
    amqp.password = Some(Zeroizing::new(password.into()));
    amqp.mandatory = true;
    if !declare {
        amqp.declare = None;
    }
    TargetConfig::new(id, TargetKind::Amqp(amqp)).unwrap()
}

/// Waits until the server counts `count` events sent to `target` (each confirmed by the
/// broker).
async fn sent(server: &Server, target: &str, count: u64) {
    let token = teifs_iam::metrics_token(ACCESS_KEY, SECRET_KEY, None);
    let wanted =
        format!("teifs_notify_sent_total{{target=\"arn:teifs:sqs::{target}:amqp\"}} {count}\n");
    let mut scraped = String::new();
    for _ in 0..300 {
        scraped = reqwest::Client::new()
            .get(format!(
                "{}{}",
                server.endpoint,
                teifs_types::admin::METRICS_PATH
            ))
            .bearer_auth(token.as_str())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        if scraped.contains(&wanted) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("{target} never sent {count} events: {scraped}");
}

#[tokio::test]
async fn events_reach_a_real_rabbitmq() {
    let Ok(url) = std::env::var("TEIFS_TEST_AMQP") else {
        eprintln!("skipped: TEIFS_TEST_AMQP isn't set");
        return;
    };
    let password = std::env::var("TEIFS_TEST_AMQP_PASSWORD").unwrap();
    let targets = vec![
        target("declared", &url, &password, true),
        target("checked", &url, &password, false),
        target("wrong", &url, "not-it", true),
    ];
    let server = start_with(|config| config.notify = targets).await;
    let s3 = client(&server, SECRET_KEY);
    for id in ["declared", "checked", "wrong"] {
        s3.create_bucket().bucket(id).send().await.unwrap();
        let rule = QueueConfiguration::builder()
            .queue_arn(format!("arn:teifs:sqs::{id}:amqp"))
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
            assert!(err.contains("ACCESS_REFUSED"), "{err}");
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
    for id in ["declared", "checked"] {
        sent(&server, id, 3).await;
    }
}
