//! Bucket notifications to a real Kafka broker. Runs when `TEIFS_TEST_KAFKA` names a
//! broker's plain listener and `TEIFS_TEST_KAFKA_SASL` its `SASL_PLAINTEXT` one, which takes
//! PLAIN (`teifs`, `TEIFS_TEST_KAFKA_PLAIN_PASSWORD`) and SCRAM (`teifs`,
//! `TEIFS_TEST_KAFKA_SCRAM_PASSWORD`), with the topic `teifs-events` made (nightly CI
//! starts one, and reads the records back with Kafka's own consumer); skipped otherwise.
//! The four targets compress with gzip, Snappy, LZ4 and zstd, which the broker checks.

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
use teifs_server::{Acks, Compression, Kafka, KafkaSasl, SaslMechanism, TargetConfig, TargetKind};
use zeroize::Zeroizing;

const TOPIC: &str = "teifs-events";

fn target(id: &str, address: &str, sasl: Option<(&str, String)>) -> TargetConfig {
    let mut kafka = Kafka::new(address, TOPIC).unwrap();
    kafka.sasl = sasl.map(|(mechanism, password)| KafkaSasl {
        mechanism: SaslMechanism::parse(mechanism).unwrap(),
        user: "teifs".into(),
        password: Zeroizing::new(password),
    });
    TargetConfig::new(id, TargetKind::Kafka(kafka)).unwrap()
}

#[tokio::test]
async fn events_reach_a_real_kafka_broker() {
    let (Ok(plain), Ok(secured)) = (
        std::env::var("TEIFS_TEST_KAFKA"),
        std::env::var("TEIFS_TEST_KAFKA_SASL"),
    ) else {
        eprintln!("skipped: TEIFS_TEST_KAFKA and TEIFS_TEST_KAFKA_SASL aren't set");
        return;
    };
    let plain_password = std::env::var("TEIFS_TEST_KAFKA_PLAIN_PASSWORD").unwrap();
    let scram_password = std::env::var("TEIFS_TEST_KAFKA_SCRAM_PASSWORD").unwrap();
    let mut targets = vec![
        target("kafka0", &plain, None),
        target("kafka1", &secured, Some(("plain", plain_password))),
        target(
            "kafka2",
            &secured,
            Some(("scram-sha-256", scram_password.clone())),
        ),
        target("kafka3", &secured, Some(("scram-sha-512", scram_password))),
        target("wrong", &secured, Some(("scram-sha-512", "not-it".into()))),
    ];
    let codecs = [
        Compression::Gzip,
        Compression::Snappy,
        Compression::Lz4,
        Compression::Zstd,
    ];
    for (target, codec) in targets.iter_mut().zip(codecs) {
        if let TargetKind::Kafka(kafka) = &mut target.kind {
            kafka.compression = codec;
        }
    }
    if let TargetKind::Kafka(kafka) = &mut targets[1].kind {
        kafka.acks = Acks::Leader;
    }
    let server = start_with(|config| config.notify = targets).await;
    let s3 = client(&server, SECRET_KEY);
    for id in ["kafka0", "kafka1", "kafka2", "kafka3", "wrong"] {
        s3.create_bucket().bucket(id).send().await.unwrap();
        let rule = QueueConfiguration::builder()
            .queue_arn(format!("arn:teifs:sqs::{id}:kafka"))
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
            assert!(err.contains("refused the user or password"), "{err}");
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
    for id in ["kafka0", "kafka1", "kafka2", "kafka3"] {
        common::sent(&server, "kafka", id, 3).await;
    }
}
