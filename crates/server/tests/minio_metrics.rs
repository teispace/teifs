//! `MinIO`'s live metrics (`mc admin scanner status`, the console's realtime view) and
//! lock list (`mc admin top locks`).

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, client, start};
use serde_json::Value;
use signing::signed_response;

#[tokio::test]
async fn realtime_metrics_count_s3_s_requests_and_end_after_n() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("counted").send().await.unwrap();
    s3.head_bucket().bucket("missing").send().await.unwrap_err();
    // Admin calls aren't S3's: they aren't counted.
    signed_response(&server, root, "GET", "/minio/admin/v3/info", &[], &[]).await;

    let started = std::time::Instant::now();
    let answer = signed_response(
        &server,
        root,
        "GET",
        "/minio/admin/v3/metrics?types=1024&n=2&interval=1s&hosts=&by-host=true",
        &[],
        &[],
    )
    .await;
    assert_eq!(answer.status(), 200);
    let text = answer.text().await.unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));
    let documents: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(documents.len(), 2, "{text}");
    assert_eq!(documents[0]["final"], false);
    assert_eq!(documents[1]["final"], true);
    let node = documents[0]["hosts"][0].as_str().unwrap();
    assert!(server.endpoint.ends_with(node), "{node}");
    let api = &documents[0]["aggregated"]["api"];
    assert_eq!(api["nodes"], 1);
    let since = &api["since_start"];
    assert_eq!(since["requests"], 2, "{since}");
    assert_eq!(since["errors_4xx"], 1);
    assert!(since["requestTimeSecs"].as_f64().unwrap() > 0.0);
    assert_eq!(documents[0]["by_host"][node]["api"]["nodes"], 1);
}

#[tokio::test]
async fn there_are_no_locks_to_list_or_release() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let locks = signed_response(
        &server,
        root,
        "GET",
        "/minio/admin/v3/top/locks?count=10&stale=false",
        &[],
        &[],
    )
    .await;
    assert_eq!(locks.status(), 200);
    assert_eq!(locks.text().await.unwrap(), "[]");
    let unlocked = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/force-unlock?paths=b/k",
        &[],
        &[],
    )
    .await;
    assert_eq!(unlocked.status(), 200);
    let refused = signed_response(
        &server,
        root,
        "GET",
        "/minio/admin/v3/top/locks?count=ten",
        &[],
        &[],
    )
    .await;
    assert_eq!(refused.status(), 400);
}
