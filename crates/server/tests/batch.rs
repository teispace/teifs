//! Batch jobs through `MinIO`'s admin API, as `mc batch` calls it: an `expire` job is
//! started from YAML, runs in the background (on after a restart), says how far it got,
//! and sends its result where it asked; jobs are listed, described without their
//! secrets, and cancelled.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::Duration;

use aws_sdk_s3::{
    Client,
    primitives::ByteStream,
    types::{BucketVersioningStatus, VersioningConfiguration},
};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};

#[macro_use]
mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, restart, start, start_with};
use signing::signed;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

const TOKEN: &str = "Bearer dummy-batch-token-0001";

async fn versioned(root: &Client, bucket: &str) {
    root.create_bucket().bucket(bucket).send().await.unwrap();
    let enabled = VersioningConfiguration::builder()
        .status(BucketVersioningStatus::Enabled)
        .build();
    root.put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(enabled)
        .send()
        .await
        .unwrap();
}

async fn put(root: &Client, bucket: &str, key: &str) {
    root.put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(b"12345"))
        .send()
        .await
        .unwrap();
}

/// Each key's versions left: (key, is a delete marker).
async fn left(root: &Client, bucket: &str) -> Vec<(String, bool)> {
    let listing = root
        .list_object_versions()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
    let mut left: Vec<_> = listing
        .versions()
        .iter()
        .map(|v| (v.key().unwrap().to_owned(), false))
        .chain(
            listing
                .delete_markers()
                .iter()
                .map(|m| (m.key().unwrap().to_owned(), true)),
        )
        .collect();
    left.sort();
    left
}

async fn admin(server: &Server, method: &str, path: &str, body: &str) -> (u16, String) {
    let path = format!("/minio/admin/v3/{path}");
    signed(server, ROOT, method, &path, &[], body.as_bytes()).await
}

async fn json(server: &Server, path: &str) -> Value {
    let (status, body) = admin(server, "GET", path, "").await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

/// Waits for job `id` to end; its last metric.
async fn ended(server: &Server, id: &str) -> Value {
    for _ in 0..200 {
        let metric = json(server, &format!("status-job?jobId={id}")).await["LastMetric"].clone();
        if metric["status"] != "waiting" && metric["status"] != "in-progress" {
            return metric;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} never ended");
}

/// A listener that takes one request and answers 200: its head and body.
async fn receiver() -> (String, mpsc::Receiver<(String, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0; 4096];
        let (head, length) = loop {
            let n = stream.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..at]).into_owned();
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                buf.drain(..at + 4);
                break (head, length);
            }
        };
        while buf.len() < length {
            let n = stream.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        tx.send((head, buf)).await.unwrap();
    });
    (format!("http://{address}/batch"), rx)
}

#[tokio::test]
async fn an_expire_job_runs_says_how_far_it_got_and_sends_its_result() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    versioned(&root, "logs").await;
    for _ in 0..3 {
        put(&root, "logs", "app/a.log").await;
    }
    put(&root, "logs", "app/b.txt").await;
    put(&root, "logs", "app/gone.log").await;
    root.delete_object()
        .bucket("logs")
        .key("app/gone.log")
        .send()
        .await
        .unwrap();
    put(&root, "logs", "keep/c.log").await;
    let (endpoint, mut sent) = receiver().await;
    let job = format!(
        "expire:
  apiVersion: v1
  bucket: logs
  prefix: app/
  rules:
    - type: object
      name: \"*.log\"
      size:
        lessThan: 1KiB
      purge:
        retainVersions: 1
    - type: deleted
  notify:
    endpoint: {endpoint}
    token: {TOKEN}
  retry:
    attempts: 2
    delay: 10ms
"
    );
    let (status, body) = admin(&server, "POST", "start-job", &job).await;
    assert_eq!(status, 200, "{body}");
    let started: Value = serde_json::from_str(&body).unwrap();
    let id = started["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("expire-"), "{id}");
    assert_eq!(started["type"], "expire");
    assert_eq!(started["user"], ACCESS_KEY);

    let metric = ended(&server, &id).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    assert_eq!(metric["complete"], true);
    assert_eq!(metric["jobType"], "expire");
    let expired = &metric["expired"];
    assert_eq!(
        (&expired["objects"], &expired["deleteMarkers"]),
        (&3.into(), &1.into()),
        "{metric}"
    );
    // `a.log` keeps its newest version, `gone.log` goes with its marker; `b.txt` and
    // what's outside the prefix stay.
    assert_eq!(
        left(&root, "logs").await,
        [
            ("app/a.log".to_owned(), false),
            ("app/b.txt".to_owned(), false),
            ("keep/c.log".to_owned(), false),
        ]
    );
    let (head, body) = tokio::time::timeout(Duration::from_secs(10), sent.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(head.starts_with("POST /batch "), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("authorization: {}", TOKEN.to_ascii_lowercase())),
        "{head}"
    );
    let result: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["jobID"], id.as_str());
    assert_eq!(result["complete"], true);
    assert_eq!(
        (&result["objects"], &result["deleteMarkers"]),
        (&3.into(), &1.into())
    );
    assert_eq!(result["bytesTransferred"], 15);

    // Listed and described, the token hidden.
    let listed = json(&server, "list-jobs?jobType=expire&bucket=logs").await;
    assert_eq!(listed["jobs"][0]["id"], id.as_str());
    assert_eq!(listed["jobs"][0]["status"], "completed");
    assert_eq!(
        json(&server, "list-jobs?bucket=other").await["jobs"],
        Value::Array(Vec::new())
    );
    let (status, described) = admin(&server, "GET", &format!("describe-job?jobId={id}"), "").await;
    assert_eq!(status, 200);
    assert!(described.contains("**REDACTED**"), "{described}");
    assert!(!described.contains("dummy-batch-token"), "{described}");
    assert!(described.contains("bucket: logs"), "{described}");
    // Cancelling one that ended changes nothing.
    let (status, _) = admin(&server, "DELETE", &format!("cancel-job?id={id}"), "").await;
    assert_eq!(status, 204);
    assert_eq!(ended(&server, &id).await["status"], "completed");
}

#[tokio::test]
async fn jobs_resume_after_a_restart_and_can_be_cancelled() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    versioned(&root, "data").await;
    for i in 0..20 {
        put(&root, "data", &format!("k{i:02}")).await;
    }
    let job = "expire:\n  apiVersion: v1\n  bucket: data\n  rules:\n    - type: object\n";
    let (status, body) = admin(&server, "POST", "start-job", job).await;
    assert_eq!(status, 200, "{body}");
    let first: Value = serde_json::from_str(&body).unwrap();
    let server = restart(server, |_| {}).await;
    let root = client(&server, SECRET_KEY);
    let metric = ended(&server, first["id"].as_str().unwrap()).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    assert_eq!(metric["expired"]["objects"], 20);
    assert!(left(&root, "data").await.is_empty());

    // A cancelled job never runs again.
    put(&root, "data", "late").await;
    let (_, body) = admin(&server, "POST", "start-job", job).await;
    let second: Value = serde_json::from_str(&body).unwrap();
    let id = second["id"].as_str().unwrap();
    let (status, _) = admin(&server, "DELETE", &format!("cancel-job?id={id}"), "").await;
    assert_eq!(status, 204);
    assert_eq!(ended(&server, id).await["status"], "canceled");
    let (status, body) = admin(&server, "DELETE", "cancel-job?id=expire-missing", "").await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("XMinioAdminNoSuchJob"), "{body}");
}

#[tokio::test]
async fn jobs_that_cant_run_are_refused_and_kinds_are_told() {
    let server = start().await;
    let start_job = |yaml: &'static str| {
        let server = &server;
        async move { admin(server, "POST", "start-job", yaml).await }
    };
    let (status, body) =
        start_job("expire:\n  apiVersion: v1\n  bucket: nowhere\n  rules: []\n").await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("NoSuchSourceBucket"), "{body}");
    let (status, body) = start_job("replicate:\n  apiVersion: v1\n").await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("replication"), "{body}");
    let (status, body) = start_job("expire: [").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        json(&server, "list-supported-job-types").await,
        serde_json::json!(["replicate", "keyrotate", "expire"])
    );
    let (status, template) = admin(&server, "GET", "generate-job?jobType=expire", "").await;
    assert_eq!(status, 200);
    assert!(template.starts_with("expire:\n"), "{template}");
    let (status, _) = admin(&server, "GET", "generate-job?jobType=compress", "").await;
    assert_eq!(status, 400);
    let (status, body) = admin(&server, "GET", "status-job?jobId=expire-missing", "").await;
    assert_eq!(status, 404, "{body}");
    let (status, _) = admin(&server, "GET", "status-job", "").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn a_job_that_couldnt_remove_everything_failed_and_says_why() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket()
        .bucket("vault")
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
    put(&root, "vault", "free").await;
    let until = aws_sdk_s3::primitives::DateTime::from_secs(4_102_444_800);
    root.put_object()
        .bucket("vault")
        .key("held")
        .object_lock_mode(aws_sdk_s3::types::ObjectLockMode::Compliance)
        .object_lock_retain_until_date(until)
        .body(ByteStream::from_static(b"12345"))
        .send()
        .await
        .unwrap();
    let job = "expire:\n  apiVersion: v1\n  bucket: vault\n  rules:\n    - type: object\n";
    let (status, body) = admin(&server, "POST", "start-job", job).await;
    assert_eq!(status, 200, "{body}");
    let id: Value = serde_json::from_str(&body).unwrap();
    let metric = ended(&server, id["id"].as_str().unwrap()).await;
    assert_eq!(metric["status"], "failed", "{metric}");
    assert_eq!(
        (&metric["complete"], &metric["failed"]),
        (&false.into(), &true.into())
    );
    assert_eq!(metric["expired"]["objects"], 1);
    assert_eq!(metric["expired"]["objectsFailed"], 1);
    assert!(
        metric["lastError"].as_str().unwrap().starts_with("held "),
        "{metric}"
    );
    assert_eq!(left(&root, "vault").await, [("held".to_owned(), false)]);
}

#[tokio::test]
async fn a_keyrotate_job_seals_encrypted_versions_under_another_key() {
    let server = start_with(|c| c.default_layout = teifs_store::Layout::Object).await;
    let root = client(&server, SECRET_KEY);
    versioned(&root, "vault").await;
    let (status, body) = admin(&server, "POST", "kms/key/create?key-id=fresh", "").await;
    assert_eq!(status, 200, "{body}");
    for key in ["a", "b"] {
        root.put_object()
            .bucket("vault")
            .key(key)
            .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256)
            .body(ByteStream::from_static(b"12345"))
            .send()
            .await
            .unwrap();
    }
    // Encrypted by the bucket's default (SSE-S3), as on AWS.
    put(&root, "vault", "c").await;
    // A key the KMS doesn't have is refused before the job starts.
    let job = |key: &str| {
        format!(
            "keyrotate:\n  apiVersion: v1\n  bucket: vault\n  encryption:\n    type: sse-kms\n    key: {key}\n"
        )
    };
    let (status, body) = admin(&server, "POST", "start-job", &job("missing")).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("can't be used"), "{body}");
    let (status, body) = admin(&server, "POST", "start-job", &job("fresh")).await;
    assert_eq!(status, 200, "{body}");
    let id: Value = serde_json::from_str(&body).unwrap();
    let metric = ended(&server, id["id"].as_str().unwrap()).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    assert_eq!(metric["jobType"], "keyrotate");
    assert_eq!(metric["rotation"]["objects"], 3, "{metric}");
    assert_eq!(metric["rotation"]["objectsFailed"], 0);
    for key in ["a", "b", "c"] {
        let head = root
            .head_object()
            .bucket("vault")
            .key(key)
            .send()
            .await
            .unwrap();
        assert_eq!(
            head.server_side_encryption(),
            Some(&aws_sdk_s3::types::ServerSideEncryption::AwsKms)
        );
        assert!(head.ssekms_key_id().unwrap().ends_with("fresh"), "{head:?}");
        let got = root
            .get_object()
            .bucket("vault")
            .key(key)
            .send()
            .await
            .unwrap();
        assert_eq!(
            got.body.collect().await.unwrap().into_bytes().as_ref(),
            b"12345"
        );
    }
}
