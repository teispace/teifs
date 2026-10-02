//! `MinIO`'s speed tests: `mc admin speedtest` (objects) and `mc support perf drive`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, client, start};
use serde_json::Value;
use signing::signed_response;

/// The documents a speed test sent, the keep-alive ones included.
fn documents(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn the_object_speed_test_writes_reads_and_clears_up() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let answer = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/speedtest?size=65536&concurrent=2&duration=1s",
        &[],
        &[],
    )
    .await;
    assert_eq!(answer.status(), 200);
    let text = answer.text().await.unwrap();
    let sent = documents(&text);
    let result = sent.last().unwrap();
    assert_eq!(result["servers"], 1, "{text}");
    assert_eq!(result["size"], 65536);
    assert_eq!(result["concurrent"], 2);
    for stats in ["PUTStats", "GETStats"] {
        let stats = &result[stats];
        assert!(stats["throughputPerSec"].as_u64().unwrap() > 0, "{stats}");
        assert!(stats["objectsPerSec"].as_u64().unwrap() > 0, "{stats}");
        assert!(
            stats["responseTime"]["max"].as_u64().unwrap() > 0,
            "{stats}"
        );
        let server_stats = &stats["servers"][0];
        assert!(
            server
                .endpoint
                .ends_with(server_stats["endpoint"].as_str().unwrap())
        );
        assert_eq!(server_stats["err"], "");
    }
    assert!(result["GETStats"]["ttfb"]["max"].as_u64().unwrap() > 0);
    // A keep-alive answer came while it ran: an empty result.
    assert!(sent.len() >= 2, "{text}");
    assert_eq!(sent[0]["servers"], 0);

    // What it wrote, and the bucket it made, are gone; S3 answers again.
    let s3 = client(&server, SECRET_KEY);
    let buckets = s3.list_buckets().send().await.unwrap();
    assert!(buckets.buckets().is_empty(), "{buckets:?}");
}

#[tokio::test]
async fn the_object_speed_test_keeps_what_it_wrote_when_asked() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("perf").send().await.unwrap();
    let answer = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/speedtest?size=4096&concurrent=1&duration=1s&bucket=perf&noclear=true",
        &[],
        &[],
    )
    .await;
    assert_eq!(answer.status(), 200);
    answer.text().await.unwrap();
    let listed = s3
        .list_objects_v2()
        .bucket("perf")
        .prefix("speedtest/")
        .send()
        .await
        .unwrap();
    assert!(listed.key_count().unwrap() > 0);
}

#[tokio::test]
async fn the_object_speed_test_refuses_what_it_can_t_do() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let too_big = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/speedtest?size=1099511627776&concurrent=1000",
        &[],
        &[],
    )
    .await;
    assert_eq!(too_big.status(), 507);
    assert!(
        too_big
            .text()
            .await
            .unwrap()
            .contains("XMinioSpeedtestInsufficientCapacity")
    );

    // Someone who may run it, but not write to the bucket asked for.
    server.iam.create_user("tester", None, &[], None).unwrap();
    server
        .iam
        .put_inline(
            teifs_iam::Owner::User("tester"),
            "policy",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"admin:OBDInfo","Resource":"*"}]}"#,
        )
        .unwrap();
    let key = server.iam.create_access_key("tester").unwrap();
    let refused = signed_response(
        &server,
        (&key.info.id, &key.secret),
        "POST",
        "/minio/admin/v3/speedtest?size=4096&concurrent=1&duration=1s&bucket=other",
        &[],
        &[],
    )
    .await;
    assert_eq!(refused.status(), 403);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("XMinioSpeedtestInsufficientPermissions")
    );

    let net = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/speedtest/net",
        &[],
        &[],
    )
    .await;
    assert_eq!(net.status(), 501);
}

#[tokio::test]
async fn the_drive_speed_test_writes_and_reads_each_disk() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let answer = signed_response(
        &server,
        root,
        "POST",
        "/minio/admin/v3/speedtest/drive?serial=true&blocksize=65536&filesize=1048576",
        &[],
        &[],
    )
    .await;
    assert_eq!(answer.status(), 200);
    let text = answer.text().await.unwrap();
    let result = documents(&text).pop().unwrap();
    assert!(
        server
            .endpoint
            .ends_with(result["endpoint"].as_str().unwrap())
    );
    let disk = &result["drivePerf"][0];
    assert!(disk["writeThroughput"].as_u64().unwrap() > 0, "{text}");
    assert!(disk["readThroughput"].as_u64().unwrap() > 0, "{text}");
    assert!(disk.get("error").is_none(), "{text}");
    let tmp = server.dir.path().join(".teifs/tmp");
    let left: Vec<_> = std::fs::read_dir(&tmp)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().starts_with("speedtest-"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}
