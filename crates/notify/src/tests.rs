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
