//! Bucket notifications to real NSQ, Redis, NATS (`JetStream`) and MQTT servers, each over
//! TLS verified with `TEIFS_TEST_BROKERS_CA` (a CA's PEM that signed their `localhost`
//! certificate). Each runs when its address is set: `TEIFS_TEST_NSQ` (an nsqd that
//! requires TLS), `TEIFS_TEST_REDIS` (password `TEIFS_TEST_REDIS_PASSWORD`),
//! `TEIFS_TEST_NATS` (user `teifs`, password `TEIFS_TEST_NATS_PASSWORD`, a stream taking
//! `s3.events`) and `TEIFS_TEST_MQTT` (user `teifs`, password `TEIFS_TEST_MQTT_PASSWORD`).
//! Nightly CI starts them and reads what they got; skipped otherwise.

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
use teifs_server::{Format, Mqtt, Nats, Nsq, Redis, TargetConfig, TargetKind, tls_config};
use zeroize::Zeroizing;

fn secret(name: &str) -> Zeroizing<String> {
    Zeroizing::new(std::env::var(name).unwrap())
}

#[tokio::test]
async fn events_reach_real_brokers_over_tls() {
    let Ok(ca) = std::env::var("TEIFS_TEST_BROKERS_CA") else {
        eprintln!("skipped: TEIFS_TEST_BROKERS_CA isn't set");
        return;
    };
    let tls = tls_config(Some(&std::fs::read(ca).unwrap()), None).unwrap();
    let address = |name: &str| std::env::var(name).ok();
    let mut targets = Vec::new();
    if let Some(at) = address("TEIFS_TEST_NSQ") {
        let mut nsq = Nsq::new(&at, "s3-events").unwrap();
        nsq.tls = Some(tls.clone());
        targets.push(TargetConfig::new("nsqd", TargetKind::Nsq(nsq)).unwrap());
    }
    if let Some(at) = address("TEIFS_TEST_REDIS") {
        let mut redis = Redis::new(&at, "teifs-events", Format::Namespace).unwrap();
        redis.password = Some(secret("TEIFS_TEST_REDIS_PASSWORD"));
        redis.tls = Some(tls.clone());
        targets.push(TargetConfig::new("redis", TargetKind::Redis(redis)).unwrap());
    }
    if let Some(at) = address("TEIFS_TEST_NATS") {
        let mut nats = Nats::new(&at, "s3.events").unwrap();
        nats.jetstream = true;
        nats.user = Some("teifs".into());
        nats.password = Some(secret("TEIFS_TEST_NATS_PASSWORD"));
        nats.tls = Some(tls.clone());
        targets.push(TargetConfig::new("nats", TargetKind::Nats(nats)).unwrap());
    }
    if let Some(at) = address("TEIFS_TEST_MQTT") {
        let mut mqtt = Mqtt::new(&at, "s3/events", 1).unwrap();
        mqtt.user = Some("teifs".into());
        mqtt.password = Some(secret("TEIFS_TEST_MQTT_PASSWORD"));
        mqtt.tls = Some(tls.clone());
        targets.push(TargetConfig::new("mqtt", TargetKind::Mqtt(mqtt)).unwrap());
    }
    let kinds: Vec<(String, &str)> = targets
        .iter()
        .map(|t| (t.id.clone(), t.kind.name()))
        .collect();
    let server = start_with(|config| config.notify = targets).await;
    let s3 = client(&server, SECRET_KEY);
    for (id, kind) in &kinds {
        let bucket = format!("{id}-events");
        s3.create_bucket().bucket(&bucket).send().await.unwrap();
        let rule = QueueConfiguration::builder()
            .queue_arn(format!("arn:teifs:sqs::{id}:{kind}"))
            .events(Event::from("s3:ObjectCreated:*"))
            .events(Event::from("s3:ObjectRemoved:*"))
            .build()
            .unwrap();
        s3.put_bucket_notification_configuration()
            .bucket(&bucket)
            .notification_configuration(
                NotificationConfiguration::builder()
                    .queue_configurations(rule)
                    .build(),
            )
            .send()
            .await
            .unwrap();
        for key in ["a.txt", "dir/b c.txt"] {
            s3.put_object()
                .bucket(&bucket)
                .key(key)
                .body(ByteStream::from_static(b"hi"))
                .send()
                .await
                .unwrap();
        }
        s3.delete_object()
            .bucket(&bucket)
            .key("a.txt")
            .send()
            .await
            .unwrap();
    }
    for (id, kind) in &kinds {
        common::sent(&server, kind, id, 3).await;
    }
}
