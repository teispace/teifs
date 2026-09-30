use zeroize::Zeroizing;

use super::*;
use crate::testing::Receiver;

fn hook(receiver: &Receiver, id: &str) -> TargetConfig {
    let hook = Webhook::new(receiver.url(), Some(Zeroizing::new("t0ken".into()))).unwrap();
    TargetConfig::new(id, TargetKind::Webhook(hook)).unwrap()
}

fn events(arn: &TargetArn, range: std::ops::Range<u32>) -> Vec<(TargetArn, Vec<u8>)> {
    range
        .map(|n| (arn.clone(), format!("{{\"n\":{n}}}").into_bytes()))
        .collect()
}

fn bodies(receiver: &Receiver) -> Vec<String> {
    receiver.taken().into_iter().map(|post| post.body).collect()
}

/// Every event is sent, one per request with the token, in order, after a target that
/// failed takes them again.
#[tokio::test]
async fn events_are_sent_in_order_after_failures() {
    let receiver = Receiver::start(3).await;
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![hook(&receiver, "primary")],
    )
    .unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::primary:webhook").unwrap();
    assert!(notifier.has(&arn));
    notifier.queue(events(&arn, 0..5)).await.unwrap();
    notifier.queue(events(&arn, 5..8)).await.unwrap();
    let posts = receiver.posts(8).await;
    let expected: Vec<String> = (0..8).map(|n| format!("{{\"n\":{n}}}")).collect();
    assert_eq!(bodies(&receiver), expected);
    assert!(
        posts
            .iter()
            .all(|p| p.authorization == "Bearer t0ken" && p.content_type == "application/json")
    );
    // The receiver has the last event before the sender reads its answer and counts it.
    for _ in 0..500 {
        let stats = &notifier.stats()[0];
        if stats.sent == 8 && stats.queued == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stats = &notifier.stats()[0];
    assert_eq!(
        (stats.sent, stats.failed, stats.dropped, stats.queued),
        (8, 3, 0, 0)
    );
    assert!(stats.online);
    notifier.stop().await;
}

/// Events for a target that's down wait on the drive, and are sent after a restart;
/// what was sent isn't sent again.
#[tokio::test]
async fn waiting_events_survive_a_restart() {
    let receiver = Receiver::start(0).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.db");
    let notifier = Notifier::start(&path, vec![hook(&receiver, "primary")]).unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::primary:webhook").unwrap();
    notifier.queue(events(&arn, 0..2)).await.unwrap();
    receiver.posts(2).await;
    receiver.fail(usize::MAX);
    notifier.queue(events(&arn, 2..4)).await.unwrap();
    while receiver.tries() < 3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    notifier.stop().await;
    assert_eq!(notifier.stats()[0].queued, 2);
    assert!(!notifier.stats()[0].online);

    receiver.fail(0);
    let notifier = Notifier::start(&path, vec![hook(&receiver, "primary")]).unwrap();
    assert_eq!(notifier.stats()[0].queued, 2, "counted from the drive");
    receiver.posts(4).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let expected: Vec<String> = (0..4).map(|n| format!("{{\"n\":{n}}}")).collect();
    assert_eq!(bodies(&receiver), expected);
    notifier.stop().await;
}

/// A target with too many events waiting drops new ones, and counts them; an event for
/// a target the server doesn't have is skipped.
#[tokio::test]
async fn a_full_queue_drops_new_events() {
    let receiver = Receiver::start(usize::MAX).await;
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start_with_limit(
        &dir.path().join("events.db"),
        vec![hook(&receiver, "primary")],
        3,
    )
    .unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::primary:webhook").unwrap();
    let other = TargetArn::parse("arn:teifs:sqs::other:webhook").unwrap();
    notifier.queue(events(&arn, 0..5)).await.unwrap();
    notifier.queue(events(&other, 0..5)).await.unwrap();
    let stats = &notifier.stats()[0];
    assert_eq!((stats.queued, stats.dropped), (3, 2));
    notifier.stop().await;
}

#[test]
fn targets_are_named_as_arns_can_name_them() {
    let hook = Webhook::new("http://localhost/", None).unwrap();
    let target = TargetConfig::new("primary-1", TargetKind::Webhook(hook.clone())).unwrap();
    assert_eq!(target.arn().to_string(), "arn:teifs:sqs::primary-1:webhook");
    for bad in ["", "a:b", "a b", "ü"] {
        assert!(
            TargetConfig::new(bad, TargetKind::Webhook(hook.clone())).is_err(),
            "{bad}"
        );
    }
    assert!(Notifier::none().is_empty());
}

/// An event as the server queues it: `name` on `BUCKET/KEY`.
pub(crate) fn message(name: &str, key: &str) -> Vec<u8> {
    let (bucket, object) = key.split_once('/').unwrap();
    serde_json::to_vec(&serde_json::json!({
        "EventName": name, "Key": key,
        "Records": [{
            "eventVersion": "2.6", "eventSource": "aws:s3", "awsRegion": "us-east-1",
            "eventTime": "2026-09-30T12:00:00.000Z",
            "eventName": name.trim_start_matches("s3:"),
            "userIdentity": {"principalId": "key"},
            "requestParameters": {"sourceIPAddress": "127.0.0.1"},
            "responseElements": {"x-amz-request-id": "1", "x-amz-id-2": "drive"},
            "s3": {
                "s3SchemaVersion": "1.0", "configurationId": "rule",
                "bucket": {"name": bucket, "ownerIdentity": {"principalId": "o"},
                           "arn": format!("arn:aws:s3:::{bucket}")},
                "object": {"key": object, "sequencer": "1"}
            }
        }]
    }))
    .unwrap()
}

/// Elasticsearch targets: the index is made when missing, and each event is a document,
/// one per object (removed with it) or one per event.
#[tokio::test]
async fn elasticsearch_keeps_a_document_per_object_or_per_event() {
    let receiver = Receiver::start(0).await;
    let base = receiver.url().to_owned();
    let mut objects = Elasticsearch::new(&base, "objects", Format::Namespace).unwrap();
    objects.api_key = Some(Zeroizing::new("k3y".into()));
    let mut log = Elasticsearch::new(&base, "log", Format::Access).unwrap();
    log.username = Some("elastic".into());
    log.password = Some(Zeroizing::new("pw".into()));
    receiver.missing("/hook/objects");
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![
            TargetConfig::new("objects", TargetKind::Elasticsearch(objects)).unwrap(),
            TargetConfig::new("log", TargetKind::Elasticsearch(log)).unwrap(),
        ],
    )
    .unwrap();
    let (objects, log) = (
        TargetArn::parse("arn:teifs:sqs::objects:elasticsearch").unwrap(),
        TargetArn::parse("arn:teifs:sqs::log:elasticsearch").unwrap(),
    );
    notifier.send_now(&objects, b"test".to_vec()).await.unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a b.jpg");
    let delete = message("s3:ObjectRemoved:Delete", "photos/a b.jpg");
    notifier
        .queue(vec![
            (objects.clone(), put.clone()),
            (objects, delete),
            (log.clone(), put),
        ])
        .await
        .unwrap();
    let taken = receiver.posts(5).await;
    let id = elasticsearch::document_id("photos/a b.jpg");
    let requests: Vec<(String, String)> = taken
        .iter()
        .map(|p| (p.method.clone(), p.path.clone()))
        .collect();
    let objects_requests: Vec<_> = requests
        .iter()
        .filter(|(_, p)| p.contains("/objects"))
        .cloned()
        .collect();
    assert_eq!(
        objects_requests,
        [
            ("PUT".to_owned(), "/hook/objects".to_owned()),
            ("PUT".to_owned(), format!("/hook/objects/_doc/{id}")),
            ("DELETE".to_owned(), format!("/hook/objects/_doc/{id}")),
        ],
        "made, written, removed"
    );
    let log_requests: Vec<_> = taken.iter().filter(|p| p.path.contains("/log")).collect();
    assert_eq!(
        log_requests
            .iter()
            .map(|p| (p.method.as_str(), p.path.as_str()))
            .collect::<Vec<_>>(),
        [("HEAD", "/hook/log"), ("POST", "/hook/log/_doc")]
    );
    let document: serde_json::Value = serde_json::from_str(&log_requests[1].body).unwrap();
    assert_eq!(document["Records"][0]["s3"]["object"]["key"], "a b.jpg");
    assert_eq!(document.as_object().unwrap().len(), 1, "only Records");
    assert_eq!(log_requests[1].authorization, "Basic ZWxhc3RpYzpwdw==");
    assert!(
        taken
            .iter()
            .filter(|p| p.path.contains("/objects"))
            .all(|p| p.authorization == "ApiKey k3y")
    );
    assert!(
        !taken.iter().any(|p| p.body == "test"),
        "no test document is written"
    );
    notifier.stop().await;
}

/// Redis targets: a hash with a field per object (removed with it), or a list with an
/// entry per event; the password and database are used, and a key of the wrong type is
/// refused.
#[tokio::test]
async fn redis_keeps_a_field_per_object_or_an_entry_per_event() {
    use crate::testing::RedisServer;
    let server = RedisServer::start("none", Some("pw")).await;
    let mut objects = Redis::new(server.address(), "objects", Format::Namespace).unwrap();
    objects.password = Some(Zeroizing::new("pw".into()));
    objects.db = Some(2);
    let mut log = Redis::new(server.address(), "log", Format::Access).unwrap();
    log.password = Some(Zeroizing::new("pw".into()));
    log.user = Some("teifs".into());
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![
            TargetConfig::new("objects", TargetKind::Redis(objects)).unwrap(),
            TargetConfig::new("log", TargetKind::Redis(log)).unwrap(),
        ],
    )
    .unwrap();
    let objects = TargetArn::parse("arn:teifs:sqs::objects:redis").unwrap();
    let log = TargetArn::parse("arn:teifs:sqs::log:redis").unwrap();
    notifier.send_now(&objects, b"test".to_vec()).await.unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    notifier
        .queue(vec![
            (objects.clone(), put.clone()),
            (objects, message("s3:ObjectRemoved:Delete", "photos/a.jpg")),
        ])
        .await
        .unwrap();
    notifier.queue(vec![(log, put)]).await.unwrap();
    let commands = server.commands(9).await;
    let names: Vec<String> = commands
        .iter()
        .map(|c| c[..2.min(c.len())].join(" "))
        .collect();
    // The test's connection, kept for the events; the log's own.
    let objects_commands: Vec<&String> = names
        .iter()
        .filter(|n| n.contains("objects") || n.starts_with("SELECT") || n.starts_with("PING"))
        .collect();
    assert_eq!(
        objects_commands,
        [
            "SELECT 2",
            "TYPE objects",
            "PING",
            "HSET objects",
            "HDEL objects"
        ]
    );
    let hset = commands.iter().find(|c| c[0] == "HSET").unwrap();
    assert_eq!(hset[2], "photos/a.jpg");
    let value: serde_json::Value = serde_json::from_str(&hset[3]).unwrap();
    assert_eq!(value["Records"][0]["s3"]["object"]["key"], "a.jpg");
    let rpush = commands.iter().find(|c| c[0] == "RPUSH").unwrap();
    let entry: serde_json::Value = serde_json::from_str(&rpush[2]).unwrap();
    assert_eq!(entry[0]["EventTime"], "2026-09-30T12:00:00.000Z");
    assert_eq!(entry[0]["Event"][0]["eventName"], "ObjectCreated:Put");
    assert!(names.contains(&"TYPE log".to_owned()));
    notifier.stop().await;

    // A key that holds something else, or a wrong password, fails the test.
    let hash = RedisServer::start("hash", None).await;
    let wrong = Redis::new(hash.address(), "k", Format::Access).unwrap();
    let err = wrong.test().await.unwrap_err();
    assert!(
        err.contains("holds a hash") && err.contains("needs a list"),
        "{err}"
    );
    let mut bad = Redis::new(server.address(), "k", Format::Access).unwrap();
    bad.password = Some(Zeroizing::new("nope".into()));
    assert!(bad.test().await.unwrap_err().contains("WRONGPASS"));
}

/// NSQ targets: each event published to the topic as a webhook gets it, heartbeats
/// answered.
#[tokio::test]
async fn nsq_publishes_each_event() {
    use crate::testing::NsqServer;
    let server = NsqServer::start().await;
    let nsq = Nsq::new(server.address(), "s3-events").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![TargetConfig::new("queue", TargetKind::Nsq(nsq)).unwrap()],
    )
    .unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::queue:nsq").unwrap();
    notifier.send_now(&arn, b"test".to_vec()).await.unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    notifier
        .queue(vec![(arn.clone(), put.clone()), (arn, put.clone())])
        .await
        .unwrap();
    let published = server.published(2).await;
    assert_eq!(published.len(), 2, "the test publishes nothing");
    assert_eq!(published[0].0, "s3-events");
    assert_eq!(published[0].1.as_bytes(), &put[..]);
    // IDENTIFY's and each PUB's heartbeat, the last answered after its PUB was kept.
    for _ in 0..100 {
        if server.nops() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.nops(), 3);
    notifier.stop().await;

    let nowhere = Nsq::new("127.0.0.1:1", "t").unwrap();
    assert!(nowhere.test().await.unwrap_err().contains("can't connect"));
}
