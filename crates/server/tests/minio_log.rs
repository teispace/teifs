//! `MinIO`'s console log (`mc admin logs`): what the server logged, the last lines first,
//! then as it's logged.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use std::time::Duration;

use common::{ACCESS_KEY, SECRET_KEY, start};
use serde_json::Value;
use signing::signed_response;
use tracing_subscriber::layer::SubscriberExt as _;

/// The log's documents, read until `count` have come (a space keeps it alive).
async fn documents(log: &mut reqwest::Response, count: usize) -> Vec<Value> {
    let mut text = String::new();
    let mut found = Vec::new();
    while found.len() < count {
        let chunk = tokio::time::timeout(Duration::from_secs(10), log.chunk())
            .await
            .expect("a line within 10 s")
            .unwrap()
            .expect("the log goes on");
        text.push_str(std::str::from_utf8(&chunk).unwrap());
        while let Some(end) = text.find('\n') {
            let line = text[..end].trim().to_owned();
            text.drain(..=end);
            if !line.is_empty() {
                found.push(serde_json::from_str(&line).unwrap());
            }
        }
    }
    found
}

#[tokio::test]
async fn mc_admin_logs_reads_what_was_logged_then_what_is() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(teifs_server::ConsoleLayer),
    )
    .unwrap();
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    tracing::error!(bucket = "pics", "the first error");
    tracing::warn!("a warning");
    tracing::error!("the second error");

    let mut errors = signed_response(
        &server,
        root,
        "GET",
        "/minio/admin/v3/log?node=&limit=2&logType=error",
        &[],
        &[],
    )
    .await;
    assert_eq!(errors.status(), 200);
    let first = documents(&mut errors, 2).await;
    assert_eq!(first[0]["error"]["message"], "the first error");
    assert_eq!(first[0]["error"]["variables"]["bucket"], "pics");
    assert_eq!(first[0]["errKind"], "ERROR");
    assert_eq!(first[1]["error"]["message"], "the second error");
    let node = first[0]["node"].as_str().unwrap().to_owned();
    assert!(server.endpoint.ends_with(&node), "{node}");

    tracing::warn!("not an error");
    tracing::error!("an error as it happens");
    let next = documents(&mut errors, 1).await;
    assert_eq!(next[0]["error"]["message"], "an error as it happens");

    // Another node's log is empty: a server is one node.
    let mut elsewhere = signed_response(
        &server,
        root,
        "GET",
        "/minio/admin/v3/log?node=elsewhere:9000&limit=5",
        &[],
        &[],
    )
    .await;
    let mut ours = signed_response(
        &server,
        root,
        "GET",
        &format!("/minio/admin/v3/log?node={node}&limit=1&logType=warning"),
        &[],
        &[],
    )
    .await;
    assert_eq!(
        documents(&mut ours, 1).await[0]["error"]["message"],
        "not an error"
    );
    let nothing = tokio::time::timeout(Duration::from_millis(1500), async {
        loop {
            let chunk = elsewhere.chunk().await.unwrap().unwrap();
            if !chunk.iter().all(u8::is_ascii_whitespace) {
                return chunk;
            }
        }
    })
    .await;
    assert!(nothing.is_err(), "only keep-alive spaces: {nothing:?}");
}
