//! Bucket notifications, end to end: a configuration set and read with the AWS SDK, S3's
//! checks, the test event, and each operation's event, as a webhook receives it.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use aws_sdk_s3::{
    Client,
    operation::RequestId,
    primitives::ByteStream,
    types::{
        CompletedMultipartUpload, CompletedPart, Delete, Event, FilterRule, FilterRuleName,
        NotificationConfiguration, NotificationConfigurationFilter, ObjectIdentifier,
        QueueConfiguration, S3KeyFilter, Tag, Tagging,
    },
};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, code, start_with};
use teifs_notify::testing::Receiver;
use teifs_server::{TargetConfig, TargetKind, Webhook};
use teifs_types::notify::{EventMessage, TestEvent};

const ARN: &str = "arn:minio:sqs::primary:webhook";

async fn server(receiver: &Receiver) -> Server {
    let hook = Webhook::new(receiver.url(), None).unwrap();
    let target = TargetConfig::new("primary", TargetKind::Webhook(hook)).unwrap();
    start_with(|config| config.notify = vec![target]).await
}

fn queue(id: Option<&str>, events: &[&str], prefix: Option<&str>) -> QueueConfiguration {
    let filter = prefix.map(|prefix| {
        NotificationConfigurationFilter::builder()
            .key(
                S3KeyFilter::builder()
                    .filter_rules(
                        FilterRule::builder()
                            .name(FilterRuleName::Prefix)
                            .value(prefix)
                            .build(),
                    )
                    .build(),
            )
            .build()
    });
    QueueConfiguration::builder()
        .set_id(id.map(str::to_owned))
        .queue_arn(ARN)
        .set_events(Some(events.iter().map(|&e| Event::from(e)).collect()))
        .set_filter(filter)
        .build()
        .unwrap()
}

async fn configure(s3: &Client, queues: Vec<QueueConfiguration>) -> Result<(), String> {
    s3.put_bucket_notification_configuration()
        .bucket("bkt")
        .notification_configuration(
            NotificationConfiguration::builder()
                .set_queue_configurations(Some(queues))
                .build(),
        )
        .send()
        .await
        .map(|_| ())
        .map_err(|e| code::<(), _>(Err(e)))
}

/// The events the receiver took (not the test events), once there are `count`.
async fn events(receiver: &Receiver, count: usize) -> Vec<EventMessage> {
    for _ in 0..500 {
        let events: Vec<EventMessage> = receiver
            .taken()
            .iter()
            .filter_map(|post| serde_json::from_str(&post.body).ok())
            .collect();
        if events.len() >= count {
            return events;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the webhook never had {count} events");
}

/// Checks the target's figures in the metrics, once none of its events wait.
async fn target_metrics(server: &Server, wanted: &[(&str, u64)]) {
    let token = teifs_iam::metrics_token(ACCESS_KEY, SECRET_KEY, None);
    let series =
        |name: &str| format!("teifs_notify_{name}{{target=\"arn:teifs:sqs::primary:webhook\"}} ");
    let mut scraped = String::new();
    for _ in 0..100 {
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
        if scraped.contains(&format!("{}0", series("queued"))) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    for (name, value) in wanted {
        let sample = format!("{}{value}\n", series(name));
        assert!(scraped.contains(&sample), "{name}: {scraped}");
    }
}

/// A configuration reads back as S3 answers it, its target gets S3's test event, and a
/// write gets its event, in S3's shape, with the request's details.
#[tokio::test]
async fn a_write_is_sent_as_s3_describes_it() {
    let receiver = Receiver::start(0).await;
    let server = server(&receiver).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("bkt").send().await.unwrap();
    let empty = s3
        .get_bucket_notification_configuration()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    assert!(empty.queue_configurations().is_empty());
    configure(
        &s3,
        vec![queue(None, &["s3:ObjectCreated:*"], Some("images/"))],
    )
    .await
    .unwrap();
    let test: TestEvent = serde_json::from_str(&receiver.posts(1).await[0].body).unwrap();
    assert_eq!(
        (test.event.as_str(), test.bucket.as_str()),
        ("s3:TestEvent", "bkt")
    );
    let config = s3
        .get_bucket_notification_configuration()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    let rule = &config.queue_configurations()[0];
    assert_eq!(rule.queue_arn(), ARN);
    assert_eq!(rule.id().unwrap().len(), 32, "an id is made up");
    let filter = &rule.filter().unwrap().key().unwrap().filter_rules()[0];
    assert_eq!(filter.name(), Some(&FilterRuleName::Prefix));

    s3.put_object()
        .bucket("bkt")
        .key("logs/skipped.txt")
        .body(ByteStream::from_static(b"no"))
        .send()
        .await
        .unwrap();
    let put = s3
        .put_object()
        .bucket("bkt")
        .key("images/my cat.jpg")
        .body(ByteStream::from_static(b"meow"))
        .send()
        .await
        .unwrap();
    let sent = &events(&receiver, 1).await[0];
    assert_eq!(sent.event_name, "s3:ObjectCreated:Put");
    assert_eq!(sent.key, "bkt/images/my cat.jpg");
    let record = &sent.records[0];
    assert_eq!(record.event_version, "2.6");
    assert_eq!(record.event_name, "ObjectCreated:Put");
    assert_eq!(record.user_identity.principal_id, ACCESS_KEY);
    assert_eq!(record.request_parameters.source_ip_address, "127.0.0.1");
    assert_eq!(
        Some(record.response_elements.request_id.as_str()),
        put.request_id()
    );
    assert_eq!(record.s3.configuration_id, rule.id().unwrap());
    assert_eq!(record.s3.bucket.arn, "arn:aws:s3:::bkt");
    let object = &record.s3.object;
    assert_eq!(object.key, "images/my+cat.jpg");
    assert_eq!(object.size, Some(4));
    assert_eq!(
        object.e_tag.as_deref(),
        put.e_tag().map(|e| e.trim_matches('"'))
    );
    assert!(object.version_id.is_none(), "an unversioned bucket's");
    assert!(record.event_time.ends_with('Z') && record.event_time.len() == 24);

    target_metrics(
        &server,
        &[
            ("sent_total", 1),
            ("failed_total", 0),
            ("dropped_total", 0),
            ("queued", 0),
            ("online", 1),
        ],
    )
    .await;
}

/// Each operation sends its own event, in the order they happened.
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn each_operation_sends_its_event() {
    let receiver = Receiver::start(0).await;
    let server = server(&receiver).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("bkt").send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("bkt")
        .versioning_configuration(
            aws_sdk_s3::types::VersioningConfiguration::builder()
                .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let everything = [
        "s3:ObjectCreated:*",
        "s3:ObjectRemoved:*",
        "s3:ObjectTagging:*",
        "s3:ObjectAccessed:Head",
    ];
    configure(&s3, vec![queue(Some("all"), &everything, None)])
        .await
        .unwrap();
    let body = |b: &'static [u8]| ByteStream::from_static(b);
    let put = s3
        .put_object()
        .bucket("bkt")
        .key("a")
        .body(body(b"1"))
        .send()
        .await
        .unwrap();
    s3.copy_object()
        .bucket("bkt")
        .key("b")
        .copy_source("bkt/a")
        .send()
        .await
        .unwrap();
    let upload = s3
        .create_multipart_upload()
        .bucket("bkt")
        .key("c")
        .send()
        .await
        .unwrap();
    let part = s3
        .upload_part()
        .bucket("bkt")
        .key("c")
        .upload_id(upload.upload_id().unwrap())
        .part_number(1)
        .body(body(b"part"))
        .send()
        .await
        .unwrap();
    s3.complete_multipart_upload()
        .bucket("bkt")
        .key("c")
        .upload_id(upload.upload_id().unwrap())
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(
                    CompletedPart::builder()
                        .part_number(1)
                        .e_tag(part.e_tag().unwrap())
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    s3.put_object_tagging()
        .bucket("bkt")
        .key("a")
        .tagging(
            Tagging::builder()
                .tag_set(Tag::builder().key("k").value("v").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    s3.head_object()
        .bucket("bkt")
        .key("a")
        .send()
        .await
        .unwrap();
    // Not asked for.
    s3.get_object().bucket("bkt").key("a").send().await.unwrap();
    let marker = s3
        .delete_object()
        .bucket("bkt")
        .key("a")
        .send()
        .await
        .unwrap();
    // Removing versions, a delete marker's too, is a delete.
    for version in [put.version_id(), marker.version_id()] {
        s3.delete_object()
            .bucket("bkt")
            .key("a")
            .version_id(version.unwrap())
            .send()
            .await
            .unwrap();
    }
    s3.delete_objects()
        .bucket("bkt")
        .delete(
            Delete::builder()
                .objects(ObjectIdentifier::builder().key("b").build().unwrap())
                .objects(ObjectIdentifier::builder().key("c").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let names: Vec<(String, String)> = events(&receiver, 10)
        .await
        .into_iter()
        .map(|e| (e.event_name, e.key))
        .collect();
    let expected = [
        ("s3:ObjectCreated:Put", "bkt/a"),
        ("s3:ObjectCreated:Copy", "bkt/b"),
        ("s3:ObjectCreated:CompleteMultipartUpload", "bkt/c"),
        ("s3:ObjectTagging:Put", "bkt/a"),
        ("s3:ObjectAccessed:Head", "bkt/a"),
        ("s3:ObjectRemoved:DeleteMarkerCreated", "bkt/a"),
        ("s3:ObjectRemoved:Delete", "bkt/a"),
        ("s3:ObjectRemoved:Delete", "bkt/a"),
        ("s3:ObjectRemoved:DeleteMarkerCreated", "bkt/b"),
        ("s3:ObjectRemoved:DeleteMarkerCreated", "bkt/c"),
    ];
    let expected: Vec<(String, String)> = expected
        .iter()
        .map(|(n, k)| ((*n).to_owned(), (*k).to_owned()))
        .collect();
    assert_eq!(names, expected);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        events(&receiver, 10).await.len(),
        10,
        "an event not asked for"
    );
    let sequencers: Vec<String> = events(&receiver, 10)
        .await
        .iter()
        .map(|e| e.records[0].s3.object.sequencer.clone())
        .collect();
    // One request's events share it (a key has one event per request).
    assert!(
        sequencers.windows(2).all(|w| w[0] <= w[1]),
        "{sequencers:?}"
    );
    assert!(sequencers[0] < sequencers[9]);
}

/// S3's refusals: an unknown target, overlapping rules, `EventBridge`, and a target that
/// doesn't take the test event (unless the request says to skip it); nothing changes.
#[tokio::test]
async fn bad_configurations_change_nothing() {
    let receiver = Receiver::start(0).await;
    let server = server(&receiver).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("bkt").send().await.unwrap();
    let created = &["s3:ObjectCreated:*"];
    let mut unknown = queue(None, created, None);
    unknown.queue_arn = "arn:minio:sqs::elsewhere:webhook".into();
    assert_eq!(
        configure(&s3, vec![unknown]).await,
        Err("InvalidArgument".into())
    );
    let overlapping = vec![
        queue(Some("1"), created, Some("a")),
        queue(Some("2"), &["s3:ObjectCreated:Put"], Some("ab")),
    ];
    assert_eq!(
        configure(&s3, overlapping).await,
        Err("InvalidArgument".into())
    );
    let bridge = s3
        .put_bucket_notification_configuration()
        .bucket("bkt")
        .notification_configuration(
            NotificationConfiguration::builder()
                .event_bridge_configuration(
                    aws_sdk_s3::types::EventBridgeConfiguration::builder().build(),
                )
                .build(),
        )
        .send()
        .await;
    assert_eq!(code(bridge), "NotImplemented");

    receiver.fail(1);
    let refused = configure(&s3, vec![queue(None, created, None)]).await;
    assert_eq!(refused, Err("InvalidArgument".into()));
    let config = s3
        .get_bucket_notification_configuration()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    assert!(config.queue_configurations().is_empty());
    receiver.fail(1);
    let skipped = s3
        .put_bucket_notification_configuration()
        .bucket("bkt")
        .skip_destination_validation(true)
        .notification_configuration(
            NotificationConfiguration::builder()
                .queue_configurations(queue(None, created, None))
                .build(),
        )
        .send()
        .await;
    assert_eq!(code(skipped), "ok");
    // An empty configuration removes the rules.
    configure(&s3, Vec::new()).await.unwrap();
    let config = s3
        .get_bucket_notification_configuration()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    assert!(config.queue_configurations().is_empty());
}

/// What lifecycle rules remove is sent too: the current version hidden by a delete
/// marker, then that version and the marker removed.
#[tokio::test]
async fn lifecycle_expirations_are_sent() {
    use aws_sdk_s3::types::{
        BucketLifecycleConfiguration, BucketVersioningStatus, ExpirationStatus,
        LifecycleExpiration, LifecycleRule, LifecycleRuleFilter, NoncurrentVersionExpiration,
        VersioningConfiguration,
    };
    let receiver = Receiver::start(0).await;
    let hook = Webhook::new(receiver.url(), None).unwrap();
    let target = TargetConfig::new("primary", TargetKind::Webhook(hook)).unwrap();
    let server = start_with(|config| {
        config.notify = vec![target];
        config.lifecycle_day = Some(std::time::Duration::from_millis(300));
    })
    .await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("bkt").send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("bkt")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    configure(&s3, vec![queue(None, &["s3:LifecycleExpiration:*"], None)])
        .await
        .unwrap();
    let rule = LifecycleRule::builder()
        .id("all")
        .status(ExpirationStatus::Enabled)
        .filter(LifecycleRuleFilter::builder().prefix("").build())
        .expiration(LifecycleExpiration::builder().days(1).build())
        .noncurrent_version_expiration(
            NoncurrentVersionExpiration::builder()
                .noncurrent_days(1)
                .build(),
        )
        .build()
        .unwrap();
    s3.put_bucket_lifecycle_configuration()
        .bucket("bkt")
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let put = s3
        .put_object()
        .bucket("bkt")
        .key("a")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    let sent = events(&receiver, 3).await;
    let names: Vec<&str> = sent.iter().map(|e| e.event_name.as_str()).collect();
    assert_eq!(
        names,
        [
            "s3:LifecycleExpiration:DeleteMarkerCreated",
            "s3:LifecycleExpiration:Delete",
            "s3:LifecycleExpiration:Delete",
        ]
    );
    let version = |n: usize| sent[n].records[0].s3.object.version_id.clone();
    assert_eq!(version(1).as_deref(), put.version_id());
    assert_eq!(version(2), version(0), "the marker made is the one removed");
    assert_eq!(sent[0].records[0].user_identity.principal_id, "");
}

/// A rule may name an SQS queue by its own ARN, as on S3: it gets S3's test event and
/// each event as S3 sends it, and the rule reads back as it was written.
#[tokio::test]
async fn rules_name_sqs_queues_by_their_aws_arns() {
    use teifs_notify::testing::AwsServer;
    use teifs_server::{AwsCredentials, Sqs};
    let aws = AwsServer::start("eu-west-1", "AKIDTEIFS", "s3cret").await;
    let mut sqs = Sqs::new(
        &format!("{}/123456789012/orders", aws.url()),
        Some("eu-west-1"),
    )
    .unwrap();
    sqs.credentials = Some(AwsCredentials {
        access_key: "AKIDTEIFS".into(),
        secret: "s3cret".to_owned().into(),
        session_token: None,
    });
    let target = TargetConfig::new("orders", TargetKind::Sqs(sqs)).unwrap();
    let server = start_with(|config| config.notify = vec![target]).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("bkt").send().await.unwrap();
    let arn = "arn:aws:sqs:eu-west-1:123456789012:orders";
    let rule = |arn: &str| {
        QueueConfiguration::builder()
            .queue_arn(arn)
            .events(Event::from("s3:ObjectCreated:*"))
            .build()
            .unwrap()
    };
    configure(&s3, vec![rule(arn)]).await.unwrap();
    assert_eq!(
        configure(&s3, vec![rule("arn:aws:sqs:eu-west-1:123456789012:other")])
            .await
            .unwrap_err(),
        "InvalidArgument"
    );
    let read = s3
        .get_bucket_notification_configuration()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    assert_eq!(read.queue_configurations()[0].queue_arn(), arn);

    s3.put_object()
        .bucket("bkt")
        .key("a.txt")
        .body(ByteStream::from_static(b"hi"))
        .send()
        .await
        .unwrap();
    let requests = aws.requests(2).await;
    let bodies: Vec<serde_json::Value> = requests
        .iter()
        .map(|r| {
            let sent: serde_json::Value = serde_json::from_str(&r.body).unwrap();
            serde_json::from_str(sent["MessageBody"].as_str().unwrap()).unwrap()
        })
        .collect();
    assert_eq!(bodies[0]["Event"], "s3:TestEvent");
    let record = &bodies[1]["Records"][0];
    assert_eq!(record["eventName"], "ObjectCreated:Put");
    assert_eq!(record["s3"]["object"]["key"], "a.txt");
    assert!(bodies[1].get("EventName").is_none(), "no MinIO envelope");
}
