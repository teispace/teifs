//! `MinIO`'s live trace (`mc admin trace`): the requests a server answers, as
//! `madmin.TraceInfo` documents, filtered as `MinIO` filters them.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use std::time::Duration;

use common::{ACCESS_KEY, SECRET_KEY, client, start};
use serde_json::Value;
use signing::signed_response;

/// The trace's documents, read until `count` have come (a space keeps it alive).
async fn documents(trace: &mut reqwest::Response, count: usize) -> Vec<Value> {
    let mut text = String::new();
    let mut found = Vec::new();
    while found.len() < count {
        let chunk = tokio::time::timeout(Duration::from_secs(10), trace.chunk())
            .await
            .expect("a trace within 10 s")
            .unwrap()
            .expect("the trace goes on");
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
async fn mc_admin_trace_shows_minio_s_trace_documents() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let trace = "/minio/admin/v3/trace";
    // As madmin asks: S3's calls only, errors only.
    let mut errors = signed_response(
        &server,
        root,
        "GET",
        &format!("{trace}?err=true&threshold=0s&threshold-ttfb=0s&types=4"),
        &[],
        &[],
    )
    .await;
    assert_eq!(errors.status(), 200);
    // An older mc: every type it knew.
    let mut all =
        signed_response(&server, root, "GET", &format!("{trace}?all=true"), &[], &[]).await;

    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("traced").send().await.unwrap();
    s3.get_object()
        .bucket("traced")
        .key("gone")
        .send()
        .await
        .unwrap_err();
    // An admin call is MinIO's internal type.
    signed_response(&server, root, "GET", "/minio/admin/v3/info", &[], &[]).await;

    let failed = &documents(&mut errors, 1).await[0];
    assert_eq!(failed["type"], 4);
    assert_eq!(failed["funcname"], "s3.GetObject");
    assert_eq!(failed["path"], "/traced/gone");
    assert_eq!(failed["http"]["request"]["method"], "GET");
    assert_eq!(failed["http"]["response"]["statuscode"], 404);
    assert_eq!(
        failed["http"]["request"]["headers"]["authorization"][0],
        "REDACTED"
    );
    assert!(failed["dur"].as_u64().unwrap() > 0);

    let seen = documents(&mut all, 3).await;
    let names: Vec<(&str, u64)> = seen
        .iter()
        .map(|d| (d["funcname"].as_str().unwrap(), d["type"].as_u64().unwrap()))
        .collect();
    assert_eq!(
        names,
        [
            ("s3.CreateBucket", 4),
            ("s3.GetObject", 4),
            ("admin.ServerInfo", 8)
        ]
    );
    assert_eq!(seen[0]["http"]["request"]["method"], "PUT");
}

#[tokio::test]
async fn a_trace_takes_the_options_minio_reads() {
    let server = start().await;
    let refused = signed_response(
        &server,
        (ACCESS_KEY, SECRET_KEY),
        "GET",
        "/minio/admin/v3/trace?types=4&threshold=soon",
        &[],
        &[],
    )
    .await;
    assert_eq!(refused.status(), 400);
    let error: Value = serde_json::from_str(&refused.text().await.unwrap()).unwrap();
    assert_eq!(error["Code"], "InvalidRequest");
}
