//! `MinIO`'s profiling: `mc admin profile` and its older start-then-download pair.
//! CPU profiles are taken on Unix only.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use std::io::Read as _;

use common::{ACCESS_KEY, SECRET_KEY, start};
use serde_json::Value;
use signing::signed_response;

/// The files in a profile's zip, by name.
async fn unzipped(answer: reqwest::Response) -> Vec<(String, Vec<u8>)> {
    assert_eq!(answer.status(), 200);
    assert_eq!(answer.headers()["content-type"], "application/zip");
    let bytes = answer.bytes().await.unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    (0..zip.len())
        .map(|i| {
            let mut file = zip.by_index(i).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            (file.name().to_owned(), bytes)
        })
        .collect()
}

#[tokio::test]
async fn mc_admin_profile_answers_a_cpu_profile_in_a_zip() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let started = std::time::Instant::now();
    let answer = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/profile?profilerType=cpu,mem&duration=1s",
        &[],
        &[],
    )
    .await;
    let files = unzipped(answer).await;
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    assert_eq!(files[0].0, "cluster.info");
    let info: Value = serde_json::from_slice(&files[0].1).unwrap();
    assert_eq!(info["info"]["no_of_servers"], 1);
    assert_eq!(info["info"]["no_of_drives"], 1);
    let node = server.endpoint.trim_start_matches("http://");
    assert_eq!(files[1].0, format!("profile-{node}-cpu.pprof"));
    assert_eq!(files[1].1[..2], [0x1f, 0x8b], "gzipped pprof");
    assert_eq!(files.len(), 2, "mem isn't taken");

    // Only Go's: nothing to take.
    let refused = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/profile?profilerType=goroutines&duration=1s",
        &[],
        &[],
    )
    .await;
    assert_eq!(refused.status(), 400);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("XMinioAdminProfilerNotEnabled")
    );
    let bad = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/profile?profilerType=cpu&duration=forever",
        &[],
        &[],
    )
    .await;
    assert_eq!(bad.status(), 400);
}

#[tokio::test]
async fn profiling_starts_then_downloads_once() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let started = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/profiling/start?profilerType=cpu,heap",
        &[],
        &[],
    )
    .await;
    assert_eq!(started.status(), 200);
    let results: Value = started.json().await.unwrap();
    let node = server.endpoint.trim_start_matches("http://");
    assert_eq!(results[0]["nodeName"], node);
    assert_eq!(results[0]["success"], true);
    assert_eq!(results[1]["success"], false);
    assert_eq!(results[1]["error"], "profiler type unknown");

    let path = "/minio/admin/v3/profiling/download";
    let download = signed_response(&server, root, "GET", path, &[], &[]).await;
    let files = unzipped(download).await;
    let names: Vec<_> = files.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        ["cluster.info", &format!("profile-{node}-cpu.pprof")]
    );
    let again = signed_response(&server, root, "GET", path, &[], &[]).await;
    assert_eq!(again.status(), 400);
}
