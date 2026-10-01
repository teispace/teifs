//! `MinIO`'s service calls: restart, stop, freeze and unfreeze (`mc admin service`).

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use std::time::Duration;

use aws_sdk_s3::primitives::ByteStream;
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start, user};
use signing::signed;
use teifs_server::Stop;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

async fn service(server: &Server, key: (&str, &str), query: &str) -> (u16, String) {
    signed(
        server,
        key,
        "POST",
        &format!("/minio/admin/v3/service?{query}"),
        &[],
        b"",
    )
    .await
}

/// Whether listing buckets answers within a short while.
async fn answers(server: &Server) -> bool {
    let root = client(server, SECRET_KEY);
    tokio::time::timeout(Duration::from_millis(500), root.list_buckets().send())
        .await
        .is_ok()
}

#[tokio::test]
async fn freezes_hold_s3_requests_until_as_many_unfreezes() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    for _ in 0..2 {
        let (status, answer) = service(&server, ROOT, "action=freeze&type=2&dry-run=false").await;
        assert_eq!(status, 200, "{answer}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&answer).unwrap(),
            serde_json::json!({"action": "freeze", "dryRun": false})
        );
    }
    // A write waits...
    let held = tokio::spawn({
        let root = root.clone();
        async move {
            root.put_object()
                .bucket("photos")
                .key("a.txt")
                .body(ByteStream::from_static(b"hello"))
                .send()
                .await
        }
    });
    assert!(!answers(&server).await);
    // ...while the admin API and health checks answer.
    let (status, _) = signed(&server, ROOT, "GET", "/minio/admin/v3/info", &[], b"").await;
    assert_eq!(status, 200);
    let health = reqwest::get(format!("{}/minio/health/live", server.endpoint))
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    // A dry run changes nothing.
    service(&server, ROOT, "action=unfreeze&type=2&dry-run=true").await;
    service(&server, ROOT, "action=unfreeze&type=2&dry-run=false").await;
    assert!(!answers(&server).await, "one freeze is left");
    assert!(!held.is_finished());
    // The first form answers nothing.
    let (status, answer) = service(&server, ROOT, "action=unfreeze").await;
    assert_eq!((status, answer.as_str()), (200, ""));
    held.await.unwrap().unwrap();
    assert!(answers(&server).await);
}

#[tokio::test]
async fn restart_and_stop_answer_first_and_dry_runs_do_nothing() {
    let server = start().await;
    let host = server.endpoint.trim_start_matches("http://");
    for action in ["restart", "stop"] {
        let (status, answer) = service(
            &server,
            ROOT,
            &format!("action={action}&type=2&dry-run=true"),
        )
        .await;
        assert_eq!(status, 200, "{answer}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&answer).unwrap(),
            serde_json::json!({"action": action, "dryRun": true, "results": [{"host": host}]})
        );
    }
    assert!(answers(&server).await);
    assert!(!server.running.is_finished());

    // Frozen requests are let go as the server stops.
    service(&server, ROOT, "action=freeze").await;
    let root = client(&server, SECRET_KEY);
    let held = tokio::spawn(async move { root.list_buckets().send().await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, answer) = service(&server, ROOT, "action=restart&type=2&dry-run=false").await;
    assert_eq!(status, 200, "{answer}");
    let stopped = tokio::time::timeout(Duration::from_secs(10), server.running)
        .await
        .expect("it stops")
        .unwrap();
    assert_eq!(stopped, Some(Stop::Restart));
    held.await.unwrap().unwrap();
}

#[tokio::test]
async fn stop_is_reported_to_whoever_runs_the_server() {
    let server = start().await;
    let (status, answer) = service(&server, ROOT, "action=stop").await;
    assert_eq!((status, answer.as_str()), (200, ""));
    let stopped = tokio::time::timeout(Duration::from_secs(10), server.running)
        .await
        .expect("it stops")
        .unwrap();
    assert_eq!(stopped, Some(Stop::Stop));
}

#[tokio::test]
async fn each_call_needs_its_own_action() {
    let server = start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"admin:ServiceFreeze"}]}"#;
    user(&server, "ops", Some(policy));
    let key = server.iam.create_access_key("ops").unwrap();
    let ops = (key.info.id.as_str(), key.secret.as_str());
    for (action, may) in [
        ("freeze", true),
        ("unfreeze", true),
        ("restart", false),
        ("stop", false),
    ] {
        let (status, answer) = service(
            &server,
            ops,
            &format!("action={action}&type=2&dry-run=true"),
        )
        .await;
        assert_eq!(status == 200, may, "{action}: {answer}");
        if !may {
            assert_eq!(status, 403, "{action}: {answer}");
            assert!(answer.contains("AccessDenied"), "{answer}");
        }
    }
    // Stopping isn't restarting.
    let policy =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"admin:ServiceStop"}]}"#;
    user(&server, "stopper", Some(policy));
    let key = server.iam.create_access_key("stopper").unwrap();
    let stopper = (key.info.id.as_str(), key.secret.as_str());
    for (action, status) in [("stop", 200), ("restart", 403), ("freeze", 403)] {
        let query = format!("action={action}&type=2&dry-run=true");
        assert_eq!(
            service(&server, stopper, &query).await.0,
            status,
            "{action}"
        );
    }
    for query in ["action=cancel-restart&type=2", "type=2", ""] {
        let (status, answer) = service(&server, ROOT, query).await;
        assert_eq!(status, 400, "{query}: {answer}");
        assert!(answer.contains("MalformedPOSTRequest"), "{answer}");
    }
    assert!(!server.running.is_finished());
}
