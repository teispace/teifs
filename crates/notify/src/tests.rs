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
    let stats = &notifier.stats()[0];
    assert_eq!((stats.sent, stats.failed, stats.dropped), (8, 3, 0));
    for _ in 0..100 {
        if notifier.stats()[0].queued == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(notifier.stats()[0].queued, 0);
    assert!(notifier.stats()[0].online);
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
