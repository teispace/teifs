//! `MinIO`'s heal (`mc admin heal`): a drive keeps one copy, so a heal checks what it
//! holds and reports each bucket and object, and changes nothing.

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

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

async fn post(server: &common::Server, path: &str, body: &[u8]) -> (u16, Value) {
    let answer = signed_response(server, ROOT, "POST", path, &[], body).await;
    let status = answer.status().as_u16();
    (
        status,
        serde_json::from_str(&answer.text().await.unwrap()).unwrap(),
    )
}

/// Flips one bit of a file, keeping its size and modification time: rot.
fn rot(path: &std::path::Path) {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let modified = std::fs::metadata(path).unwrap().modified().unwrap();
    let byte = std::fs::read(path).unwrap()[3];
    // In place, without truncating: nothing reading it meanwhile sees it cut short.
    let mut file = std::fs::File::options().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(3)).unwrap();
    file.write_all(&[byte ^ 1]).unwrap();
    file.set_modified(modified).unwrap();
}

/// Polls a heal with its token until it's done, collecting its results.
async fn results(server: &common::Server, path: &str, token: &str) -> (Value, Vec<Value>) {
    let mut items = Vec::new();
    for _ in 0..100 {
        let (status, polled) = post(server, &format!("{path}?clientToken={token}"), b"").await;
        assert_eq!(status, 200, "{polled}");
        items.extend(polled["Items"].as_array().unwrap().iter().cloned());
        if polled["Summary"] != "running" {
            return (polled, items);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the heal didn't finish");
}

#[tokio::test]
async fn mc_admin_heal_reports_each_bucket_and_object() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("pics").send().await.unwrap();
    for key in ["2026/a.txt", "2026/b.txt", "top.txt"] {
        s3.put_object()
            .bucket("pics")
            .key(key)
            .body(b"the bytes of a picture".to_vec().into())
            .send()
            .await
            .unwrap();
    }
    rot(&server.dir.path().join("pics/2026/b.txt"));

    // A deep scan of a prefix, recursive: each object, its bytes compared.
    let path = "/minio/admin/v3/heal/pics/2026";
    let opts = br#"{"recursive":true,"dryRun":false,"remove":false,"recreate":false,"scanMode":2,"updateParity":false,"nolock":false}"#;
    let (status, started) = post(&server, path, opts).await;
    assert_eq!(status, 200, "{started}");
    let token = started["clientToken"].as_str().unwrap().to_owned();
    assert!(started["startTime"].as_str().is_some());
    let (done, items) = results(&server, path, &token).await;
    assert_eq!(done["Summary"], "finished");
    assert_eq!(done["Settings"]["scanMode"], 2);
    let seen: Vec<(&str, &str, &str)> = items
        .iter()
        .map(|i| {
            (
                i["type"].as_str().unwrap(),
                i["object"].as_str().unwrap(),
                i["before"]["drives"][0]["state"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("bucket", "", "ok"),
            ("object", "2026/a.txt", "ok"),
            ("object", "2026/b.txt", "corrupt"),
        ]
    );
    let detail = items[2]["detail"].as_str().unwrap();
    assert!(detail.starts_with("its bytes don't match its "), "{detail}");
    assert_eq!(items[2]["after"], items[2]["before"], "nothing is changed");
    let ids: Vec<u64> = items
        .iter()
        .map(|i| i["resultId"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, [1, 2, 3]);

    // Not recursive, a normal scan: the keys right under the prefix, metadata only.
    let (_, started) = post(&server, "/minio/admin/v3/heal/pics", b"{}").await;
    let token = started["clientToken"].as_str().unwrap().to_owned();
    let (_, items) = results(&server, "/minio/admin/v3/heal/pics", &token).await;
    let objects: Vec<&str> = items
        .iter()
        .map(|i| i["object"].as_str().unwrap())
        .collect();
    assert_eq!(objects, ["", "top.txt"]);

    // The whole drive: each bucket.
    let (_, started) = post(&server, "/minio/admin/v3/heal/", b"{}").await;
    let token = started["clientToken"].as_str().unwrap().to_owned();
    let (done, items) = results(&server, "/minio/admin/v3/heal/", &token).await;
    assert_eq!(done["Summary"], "finished");
    assert_eq!(items[0]["type"], "bucket");
    assert_eq!(items[0]["bucket"], "pics");
}

#[tokio::test]
async fn heal_requests_are_checked_as_minio_checks_them() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("docs").send().await.unwrap();
    for (path, query, body, status, code) in [
        (
            "/minio/admin/v3/heal/missing",
            "",
            &b"{}"[..],
            404,
            "NoSuchBucket",
        ),
        (
            "/minio/admin/v3/heal/docs",
            "",
            b"not json",
            400,
            "XMinioRequestBodyParse",
        ),
        (
            "/minio/admin/v3/heal/docs",
            "forceStart&forceStop",
            b"{}",
            400,
            "InvalidRequest",
        ),
        (
            "/minio/admin/v3/heal/docs",
            "clientToken=wrong",
            b"",
            200,
            "",
        ),
    ] {
        let (got, answer) = post(&server, &format!("{path}?{query}"), body).await;
        assert_eq!(got, status, "{path}?{query}: {answer}");
        if code.is_empty() {
            // No heal on that path: it finished long ago.
            assert_eq!(answer["Summary"], "finished");
        } else {
            assert_eq!(answer["Code"], code, "{path}?{query}");
        }
    }

    // A stop with nothing running is told so; a stop ends the heal and forgets it.
    let (status, stopped) = post(&server, "/minio/admin/v3/heal/docs?forceStop", b"{}").await;
    assert_eq!(
        (status, &stopped["clientToken"]),
        (200, &Value::from("unknown"))
    );
    let (_, started) = post(&server, "/minio/admin/v3/heal/docs", b"{}").await;
    let token = started["clientToken"].as_str().unwrap();
    let (_, stopped) = post(&server, "/minio/admin/v3/heal/docs?forceStop", b"{}").await;
    assert_eq!(stopped["clientToken"], token);
    let (_, gone) = post(
        &server,
        &format!("/minio/admin/v3/heal/docs?clientToken={token}"),
        b"",
    )
    .await;
    assert_eq!(gone["Summary"], "finished");
}

#[tokio::test]
async fn the_background_heal_is_the_scrub() {
    let server = start().await;
    let (status, state) = post(&server, "/minio/admin/v3/background-heal/status", b"").await;
    assert_eq!(status, 200, "{state}");
    assert_eq!(state["ScannedItemsCount"], 0);
    assert_eq!(state["offline_nodes"], serde_json::json!([]));
    let set = &state["sets"][0];
    assert_eq!(set["disks"][0]["state"], "ok");
    assert_eq!(state["sc_parity"]["STANDARD"], 0);
}
