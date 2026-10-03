//! `MinIO`'s `replicate` batch job between two TeiFS servers: pushed from a bucket here
//! and pulled from another service's, every version keeping its id and time (or, with
//! plain S3 at one end, each key's current object); filtered; refused when it can't
//! run; failing the versions it can't copy.

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
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use serde_json::Value;

mod common;
mod signing;

use common::{
    ACCESS_KEY, SECRET_KEY, Server, client,
    faulty::{Answer, Faulty},
    start, start_with,
};
use signing::signed;
use teifs_store::Layout;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

async fn bucket(root: &Client, name: &str, versioned: bool) {
    root.create_bucket().bucket(name).send().await.unwrap();
    if versioned {
        let enabled = VersioningConfiguration::builder()
            .status(BucketVersioningStatus::Enabled)
            .build();
        root.put_bucket_versioning()
            .bucket(name)
            .versioning_configuration(enabled)
            .send()
            .await
            .unwrap();
    }
}

/// Writes `body` to `key`; the version's id.
async fn put(root: &Client, bucket: &str, key: &str, body: &'static [u8]) -> String {
    root.put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(body))
        .send()
        .await
        .unwrap()
        .version_id
        .unwrap_or_default()
}

/// Each version and delete marker: (key, version id, is a delete marker), sorted.
async fn versions(root: &Client, bucket: &str) -> Vec<(String, String, bool)> {
    let mut all = Vec::new();
    let (mut key_marker, mut version_marker) = (None, None);
    loop {
        let listing = root
            .list_object_versions()
            .bucket(bucket)
            .set_key_marker(key_marker)
            .set_version_id_marker(version_marker)
            .send()
            .await
            .unwrap();
        all.extend(listing.versions().iter().map(|v| {
            (
                v.key().unwrap().to_owned(),
                v.version_id().unwrap().to_owned(),
                false,
            )
        }));
        all.extend(listing.delete_markers().iter().map(|m| {
            (
                m.key().unwrap().to_owned(),
                m.version_id().unwrap().to_owned(),
                true,
            )
        }));
        if !listing.is_truncated().unwrap_or_default() {
            break;
        }
        key_marker = listing.next_key_marker().map(str::to_owned);
        version_marker = listing.next_version_id_marker().map(str::to_owned);
    }
    all.sort();
    all
}

async fn body(root: &Client, bucket: &str, key: &str) -> Vec<u8> {
    let got = root
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap();
    got.body.collect().await.unwrap().to_vec()
}

async fn admin(server: &Server, method: &str, path: &str, body: &str) -> (u16, String) {
    let path = format!("/minio/admin/v3/{path}");
    signed(server, ROOT, method, &path, &[], body.as_bytes()).await
}

/// Starts `yaml` on `server`; the job's id.
async fn started(server: &Server, yaml: &str) -> String {
    let (status, body) = admin(server, "POST", "start-job", yaml).await;
    assert_eq!(status, 200, "{body}");
    let result: Value = serde_json::from_str(&body).unwrap();
    result["id"].as_str().unwrap().to_owned()
}

/// Waits for job `id` to end; its last metric.
async fn ended(server: &Server, id: &str) -> Value {
    for _ in 0..600 {
        let (status, body) = admin(server, "GET", &format!("status-job?jobId={id}"), "").await;
        assert_eq!(status, 200, "{body}");
        let metric = serde_json::from_str::<Value>(&body).unwrap()["LastMetric"].clone();
        if metric["status"] != "waiting" && metric["status"] != "in-progress" {
            return metric;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} never ended");
}

/// The YAML of a job copying `source` to `target`, which are ends' YAML.
fn job(source: &str, target: &str, flags: &str) -> String {
    format!("replicate:\n  apiVersion: v1\n  source:\n{source}  target:\n{target}{flags}")
}

/// An end of a job here: its type, bucket and anything else.
fn here(kind: &str, bucket: &str, more: &str) -> String {
    format!("    type: {kind}\n    bucket: {bucket}\n{more}")
}

/// An end of a job on `server`, signed in with its root keys (or `secret`).
fn there(server: &Server, kind: &str, bucket: &str, more: &str) -> String {
    there_as(server, kind, bucket, more, SECRET_KEY)
}

fn there_as(server: &Server, kind: &str, bucket: &str, more: &str, secret: &str) -> String {
    there_at(&server.endpoint, kind, bucket, more, secret)
}

fn there_at(endpoint: &str, kind: &str, bucket: &str, more: &str, secret: &str) -> String {
    format!(
        "    type: {kind}\n    bucket: {bucket}\n    endpoint: {endpoint}\n    credentials:\n      accessKey: {ACCESS_KEY}\n      secretKey: {secret}\n{more}"
    )
}

#[tokio::test]
async fn a_pushed_job_sends_every_version_and_delete_marker_with_its_id_and_time() {
    let (near, far) = (start().await, start().await);
    let (local, remote) = (client(&near, SECRET_KEY), client(&far, SECRET_KEY));
    bucket(&local, "photos", true).await;
    bucket(&remote, "backup", true).await;
    let first = put(&local, "photos", "a.txt", b"first").await;
    let second = put(&local, "photos", "a.txt", b"second!").await;
    let gone = put(&local, "photos", "b.txt", b"bee").await;
    let marker = local
        .delete_object()
        .bucket("photos")
        .key("b.txt")
        .send()
        .await
        .unwrap()
        .version_id
        .unwrap();
    put(&local, "photos", "skip/c.txt", b"not this one").await;

    let yaml = job(
        &here("minio", "photos", "    prefix: [a, b]\n"),
        &there(&far, "minio", "backup", "    prefix: copy\n"),
        "",
    );
    let id = started(&near, &yaml).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    let counts = &metric["replicate"];
    assert_eq!(counts["objects"], 3, "{metric}");
    assert_eq!(counts["deleteMarkers"], 1, "{metric}");
    assert_eq!(counts["bytesTransferred"], 5 + 7 + 3, "{metric}");
    assert_eq!(counts["objectsFailed"], 0, "{metric}");
    assert_eq!(counts["lastBucket"], "backup", "{metric}");

    let mut want = vec![
        ("copy/a.txt".to_owned(), first.clone(), false),
        ("copy/a.txt".to_owned(), second, false),
        ("copy/b.txt".to_owned(), gone, false),
        ("copy/b.txt".to_owned(), marker, true),
    ];
    want.sort();
    assert_eq!(versions(&remote, "backup").await, want);
    assert_eq!(body(&remote, "backup", "copy/a.txt").await, b"second!");
    let (local_first, remote_first) = (
        local
            .head_object()
            .bucket("photos")
            .key("a.txt")
            .version_id(&first)
            .send()
            .await
            .unwrap(),
        remote
            .head_object()
            .bucket("backup")
            .key("copy/a.txt")
            .version_id(&first)
            .send()
            .await
            .unwrap(),
    );
    assert_eq!(remote_first.last_modified, local_first.last_modified);
    assert_eq!(remote_first.e_tag, local_first.e_tag);

    // Run again, nothing changes: each version is there once.
    let id = started(&near, &yaml).await;
    assert_eq!(ended(&near, &id).await["status"], "completed");
    assert_eq!(versions(&remote, "backup").await.len(), 4);
}

/// The other service's `source` bucket: `x.png` twice (tagged, with metadata), `y.txt`,
/// and `z.txt` removed; `x.png`'s version ids, oldest first.
async fn pulled_source(remote: &Client) -> (String, String) {
    bucket(remote, "source", true).await;
    let tagged = |key: &'static str, body: &'static [u8]| {
        let remote = remote.clone();
        async move {
            remote
                .put_object()
                .bucket("source")
                .key(key)
                .content_type("image/png")
                .metadata("camera", "x100")
                .tagging("team=ops&env=prod")
                .body(ByteStream::from_static(body))
                .send()
                .await
                .unwrap()
                .version_id
                .unwrap()
        }
    };
    let old = tagged("x.png", b"old picture").await;
    let new = tagged("x.png", b"new picture").await;
    put(remote, "source", "y.txt", b"untagged").await;
    put(remote, "source", "z.txt", b"removed").await;
    remote
        .delete_object()
        .bucket("source")
        .key("z.txt")
        .send()
        .await
        .unwrap();
    (old, new)
}

#[tokio::test]
async fn a_pulled_job_copies_what_its_filter_takes_with_tags_and_metadata() {
    let (near, far) = (start().await, start().await);
    let (local, remote) = (client(&near, SECRET_KEY), client(&far, SECRET_KEY));
    let (old, new) = pulled_source(&remote).await;
    bucket(&local, "inbox", true).await;
    let filter = "  flags:\n    filter:\n      tags:\n        - key: team\n          value: o*\n";
    let yaml = job(
        &there(&far, "minio", "source", ""),
        &here("minio", "inbox", ""),
        filter,
    );
    let id = started(&near, &yaml).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    assert_eq!(metric["replicate"]["objects"], 2, "{metric}");
    // Delete markers have no tags: the filter doesn't take them.
    assert_eq!(metric["replicate"]["deleteMarkers"], 0, "{metric}");
    let mut want = vec![
        ("x.png".to_owned(), old, false),
        ("x.png".to_owned(), new.clone(), false),
    ];
    want.sort();
    assert_eq!(versions(&local, "inbox").await, want);
    let head = local
        .head_object()
        .bucket("inbox")
        .key("x.png")
        .send()
        .await
        .unwrap();
    assert_eq!(head.version_id.as_deref(), Some(new.as_str()));
    assert_eq!(head.content_type.as_deref(), Some("image/png"));
    assert_eq!(
        head.metadata.unwrap().get("camera").map(String::as_str),
        Some("x100")
    );
    let tags = local
        .get_object_tagging()
        .bucket("inbox")
        .key("x.png")
        .send()
        .await
        .unwrap();
    let mut tags: Vec<_> = tags
        .tag_set()
        .iter()
        .map(|t| (t.key().to_owned(), t.value().to_owned()))
        .collect();
    tags.sort();
    assert_eq!(
        tags,
        [
            ("env".to_owned(), "prod".to_owned()),
            ("team".to_owned(), "ops".to_owned())
        ]
    );
}

#[tokio::test]
async fn a_pulled_job_without_a_filter_copies_every_version_or_with_s3_the_current_ones() {
    let (near, far) = (start().await, start().await);
    let (local, remote) = (client(&near, SECRET_KEY), client(&far, SECRET_KEY));
    pulled_source(&remote).await;
    bucket(&local, "plain", false).await;
    // Without a filter, every version and delete marker, as they are.
    bucket(&local, "everything", true).await;
    let yaml = job(
        &there(&far, "minio", "source", ""),
        &here("minio", "everything", ""),
        "",
    );
    let id = started(&near, &yaml).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["replicate"]["objects"], 4, "{metric}");
    assert_eq!(metric["replicate"]["deleteMarkers"], 1, "{metric}");
    assert_eq!(
        versions(&local, "everything").await,
        versions(&remote, "source").await
    );

    // With plain S3 at one end: each key's current object, as a new version, and no
    // delete marker.
    let yaml = job(
        &there(&far, "s3", "source", ""),
        &here("minio", "plain", "    prefix: mirror/\n"),
        "",
    );
    let id = started(&near, &yaml).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    assert_eq!(metric["replicate"]["objects"], 2, "{metric}");
    let plain: Vec<_> = versions(&local, "plain")
        .await
        .into_iter()
        .map(|(key, _, marker)| (key, marker))
        .collect();
    assert_eq!(
        plain,
        [
            ("mirror/x.png".to_owned(), false),
            ("mirror/y.txt".to_owned(), false)
        ]
    );
    assert_eq!(body(&local, "plain", "mirror/x.png").await, b"new picture");
}

#[tokio::test]
async fn jobs_go_on_from_page_to_page_both_ways() {
    // Scratch drives: a thousand writes needn't each be synced.
    let scratch = |c: &mut teifs_server::Config| c.durability = teifs_server::Durability::None;
    let (near, far) = (start_with(scratch).await, start_with(scratch).await);
    let (local, remote) = (client(&near, SECRET_KEY), client(&far, SECRET_KEY));
    bucket(&remote, "many", true).await;
    bucket(&local, "versions", true).await;
    bucket(&local, "current", false).await;
    let mut puts = tokio::task::JoinSet::new();
    for n in 0..1_003 {
        let remote = remote.clone();
        puts.spawn(async move {
            put(&remote, "many", &format!("k{n:04}"), b"x").await;
        });
        if puts.len() >= 32 {
            puts.join_next().await.unwrap().unwrap();
        }
    }
    while let Some(done) = puts.join_next().await {
        done.unwrap();
    }
    // One key with two versions, so a page can end between them.
    put(&remote, "many", "k0999", b"y").await;

    for (kind, bucket) in [("minio", "versions"), ("s3", "current")] {
        let yaml = job(
            &there(&far, kind, "many", ""),
            &here("minio", bucket, ""),
            "",
        );
        let id = started(&near, &yaml).await;
        let metric = ended(&near, &id).await;
        assert_eq!(metric["status"], "completed", "{kind}: {metric}");
        let copied = if kind == "minio" { 1_004 } else { 1_003 };
        assert_eq!(metric["replicate"]["objects"], copied, "{kind}: {metric}");
        assert_eq!(versions(&local, bucket).await.len(), copied, "{kind}");
    }
    assert_eq!(
        versions(&local, "versions").await,
        versions(&remote, "many").await
    );
    // And pushed back, a page of keys at a time.
    bucket(&remote, "back", true).await;
    let yaml = job(
        &here("minio", "versions", ""),
        &there(&far, "minio", "back", ""),
        "",
    );
    let id = started(&near, &yaml).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["replicate"]["objects"], 1_004, "{metric}");
    assert_eq!(
        versions(&remote, "back").await,
        versions(&remote, "many").await
    );
    assert_eq!(body(&local, "current", "k0999").await, b"y");
}

#[tokio::test]
async fn jobs_that_cant_run_are_refused_and_secrets_are_hidden() {
    let (near, far) = (start().await, start().await);
    let (local, remote) = (client(&near, SECRET_KEY), client(&far, SECRET_KEY));
    bucket(&local, "versioned", true).await;
    bucket(&remote, "unversioned", false).await;
    let refused = |yaml: String| {
        let near = &near;
        async move { admin(near, "POST", "start-job", &yaml).await }
    };

    let (status, body) = refused(job(
        &here("minio", "nowhere", ""),
        &there(&far, "minio", "unversioned", ""),
        "",
    ))
    .await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("NoSuchSourceBucket"), "{body}");
    let (status, body) = refused(job(
        &here("minio", "versioned", ""),
        &there(&far, "minio", "missing", ""),
        "",
    ))
    .await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("NoSuchTargetBucket"), "{body}");
    let (status, body) = refused(job(
        &here("minio", "versioned", ""),
        &there(&far, "minio", "unversioned", ""),
        "",
    ))
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("InvalidBucketState"), "{body}");
    bucket(&local, "flat", false).await;
    bucket(&remote, "versions", true).await;
    let (status, body) = refused(job(
        &there(&far, "minio", "versions", ""),
        &here("minio", "flat", ""),
        "",
    ))
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("InvalidBucketState"), "{body}");
    let (status, body) = refused(job(
        &here("minio", "versioned", ""),
        &there_as(&far, "minio", "unversioned", "", "dummy-wrong-secret"),
        "",
    ))
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("can't be reached"), "{body}");
    assert!(!body.contains("dummy-wrong-secret"), "{body}");

    // With plain S3 at one end, versioning needn't match; each key's current object
    // goes, and none whose current version is a delete marker.
    put(&local, "versioned", "kept.txt", b"kept").await;
    put(&local, "versioned", "deleted.txt", b"deleted").await;
    local
        .delete_object()
        .bucket("versioned")
        .key("deleted.txt")
        .send()
        .await
        .unwrap();
    let id = started(
        &near,
        &job(
            &here("minio", "versioned", ""),
            &there(&far, "s3", "unversioned", ""),
            "",
        ),
    )
    .await;
    let (status, described) = admin(&near, "GET", &format!("describe-job?jobId={id}"), "").await;
    assert_eq!(status, 200, "{described}");
    assert!(!described.contains(SECRET_KEY), "{described}");
    assert!(described.contains("**REDACTED**"), "{described}");
    assert!(described.contains(&far.endpoint), "{described}");
    let metric = ended(&near, &id).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    assert_eq!(metric["replicate"]["objects"], 1, "{metric}");
    assert_eq!(metric["replicate"]["deleteMarkers"], 0, "{metric}");
    let copied: Vec<_> = versions(&remote, "unversioned")
        .await
        .into_iter()
        .map(|(key, _, _)| key)
        .collect();
    assert_eq!(copied, ["kept.txt"]);
    // The secret is kept sealed on the drive.
    let system = std::fs::read(near.dir.path().join(".teifs/system.db")).unwrap();
    assert!(
        !system
            .windows(SECRET_KEY.len())
            .any(|w| w == SECRET_KEY.as_bytes())
    );
}

#[tokio::test]
async fn versions_that_cant_be_copied_fail_the_job_and_say_why() {
    // SSE-C needs an object bucket.
    let near = start_with(|c| c.default_layout = Layout::Object).await;
    let far = start().await;
    let (local, remote) = (client(&near, SECRET_KEY), client(&far, SECRET_KEY));
    bucket(&local, "mixed", true).await;
    bucket(&remote, "copies", true).await;
    put(&local, "mixed", "fine.txt", b"fine").await;
    let key = [7u8; 32];
    local
        .put_object()
        .bucket("mixed")
        .key("secret.txt")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(STANDARD.encode(key))
        .sse_customer_key_md5(STANDARD.encode(Md5::digest(key)))
        .body(ByteStream::from_static(b"customer"))
        .send()
        .await
        .unwrap();
    let yaml = job(
        &here("minio", "mixed", ""),
        &there(&far, "minio", "copies", ""),
        "  flags:\n    retry:\n      attempts: 2\n      delay: 1ms\n",
    );
    let id = started(&near, &yaml).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["status"], "failed", "{metric}");
    assert_eq!(metric["replicate"]["objects"], 1, "{metric}");
    assert_eq!(metric["replicate"]["objectsFailed"], 1, "{metric}");
    assert_eq!(metric["replicate"]["bytesFailed"], 8, "{metric}");
    let why = metric["lastError"].as_str().unwrap();
    assert!(why.contains("secret.txt") && why.contains("SSE-C"), "{why}");
    // Refused for good: not tried again.
    assert_eq!(metric["retryAttempts"], 0, "{metric}");
    assert_eq!(body(&remote, "copies", "fine.txt").await, b"fine");
}

#[tokio::test]
async fn unversioned_buckets_copy_their_objects_both_ways() {
    let (near, far) = (start().await, start().await);
    let (local, remote) = (client(&near, SECRET_KEY), client(&far, SECRET_KEY));
    for name in ["outbox", "inbox"] {
        bucket(&local, name, false).await;
        bucket(&remote, name, false).await;
    }
    put(&local, "outbox", "pushed.txt", b"pushed").await;
    put(&remote, "outbox", "pulled.txt", b"pulled").await;
    for yaml in [
        job(
            &here("minio", "outbox", ""),
            &there(&far, "minio", "inbox", ""),
            "",
        ),
        job(
            &there(&far, "minio", "outbox", ""),
            &here("minio", "inbox", ""),
            "",
        ),
    ] {
        let id = started(&near, &yaml).await;
        let metric = ended(&near, &id).await;
        assert_eq!(metric["status"], "completed", "{metric}");
        assert_eq!(metric["replicate"]["objects"], 1, "{metric}");
    }
    assert_eq!(body(&remote, "inbox", "pushed.txt").await, b"pushed");
    assert_eq!(body(&local, "inbox", "pulled.txt").await, b"pulled");
}

#[tokio::test]
async fn what_fails_for_a_while_is_tried_again_and_a_missing_bucket_ends_the_job() {
    let (near, far) = (start().await, start().await);
    let (local, remote) = (client(&near, SECRET_KEY), client(&far, SECRET_KEY));
    bucket(&local, "here", true).await;
    bucket(&remote, "there", true).await;
    put(&local, "here", "a.txt", b"a").await;
    put(&remote, "there", "b.txt", b"b").await;
    let faulty = Faulty::new(&far.endpoint).await;
    let endpoint = format!("http://{}", faulty.address);
    let retry = "  flags:\n    retry:\n      attempts: 3\n      delay: 1ms\n";

    // A version the target can't take for a moment.
    faulty.fail("PUT", "/there/a.txt", Answer::Status(503, "SlowDown"), 1);
    let pushed = job(
        &here("minio", "here", ""),
        &there_at(&endpoint, "minio", "there", "", SECRET_KEY),
        retry,
    );
    let id = started(&near, &pushed).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    assert_eq!(metric["replicate"]["objects"], 1, "{metric}");
    assert_eq!(metric["retryAttempts"], 1, "{metric}");
    assert!(faulty.unspent().is_empty());

    // A listing the other service can't answer for a moment: the page is tried again.
    let pulled = job(
        &there_at(&endpoint, "minio", "there", "", SECRET_KEY),
        &here("minio", "here", ""),
        retry,
    );
    faulty.fail("GET", "versions", Answer::Status(503, "SlowDown"), 1);
    let id = started(&near, &pulled).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["status"], "completed", "{metric}");
    assert_eq!(metric["replicate"]["objects"], 2, "{metric}");
    assert_eq!(metric["retryAttempts"], 1, "{metric}");
    assert!(faulty.unspent().is_empty());

    // The bucket gone: the job ends at once.
    faulty.fail(
        "GET",
        "versions",
        Answer::Status(404, "NoSuchBucket"),
        usize::MAX,
    );
    let id = started(&near, &pulled).await;
    let metric = ended(&near, &id).await;
    assert_eq!(metric["status"], "failed", "{metric}");
    assert_eq!(metric["retryAttempts"], 0, "{metric}");
    assert_eq!(faulty.count("GET", "versions"), 3);
}
