//! Drives written by earlier releases open intact. `fixtures/format-<n>.tar.gz` is a drive
//! and its keyring, written through the S3 and admin APIs by the build that wrote format
//! `<n>`; `format-<n>.json` is everything those APIs said about it then. Every build opens
//! each fixture and must still say all of it: what's added since (a new field, a new
//! setting) may appear, but nothing may change or go.
//!
//! A fixture is written once, when a release changes the format, and never again:
//! `TEIFS_WRITE_FIXTURE=<dir> cargo test -p teifs-server --test format_fixtures --
//! --ignored` writes the current format's into `<dir>`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{collections::BTreeMap, fs, path::Path, time::SystemTime};

use aws_sdk_s3::{
    Client,
    primitives::{ByteStream, DateTime},
    types::{
        BucketLifecycleConfiguration, BucketLoggingStatus, BucketVersioningStatus,
        CompletedMultipartUpload, CompletedPart, CorsConfiguration, CorsRule, DefaultRetention,
        ExpirationStatus, LifecycleExpiration, LifecycleRule, LifecycleRuleFilter, LoggingEnabled,
        ObjectLockConfiguration, ObjectLockEnabled, ObjectLockLegalHold, ObjectLockLegalHoldStatus,
        ObjectLockRetention, ObjectLockRetentionMode, ObjectLockRule, OwnershipControls,
        OwnershipControlsRule, PublicAccessBlockConfiguration, ServerSideEncryption, Tag, Tagging,
        VersioningConfiguration,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use serde_json::{Value, json};
use teifs_types::admin::{ADMIN_BUCKETS, ADMIN_IAM};

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, start_with};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
/// The format the newest fixture was written in.
const NEWEST: u32 = 2;

/// The customer key of the fixture's SSE-C object: a test value, written in this file.
const CUSTOMER_KEY: [u8; 32] = *b"format-fixture-customer-key-0001";

/// A keyring with one key whose material is a plain pattern: a test value, so the fixture
/// holds no secret worth the name.
fn keyring() -> String {
    let material: Vec<u8> = (0u8..32).collect();
    json!({
        "version": 1,
        "keys": {"teifs-default": [{
            "version": 1,
            "material": STANDARD.encode(material),
            "createdMs": 1_790_000_000_000_i64,
        }]},
    })
    .to_string()
}

/// A server on the drive in `drive`, with the keyring in `keys`.
async fn serve(drive: &Path, keys: &Path) -> Server {
    let (drive, keys) = (drive.to_owned(), keys.join("keyring.json"));
    start_with(move |config| {
        config.dir = drive;
        config.kms_keyring = Some(keys);
    })
    .await
}

/// A bucket of `layout` (`object` or `folder`).
async fn bucket(s3: &Client, name: &str, layout: &'static str, lock: bool) {
    s3.create_bucket()
        .bucket(name)
        .object_lock_enabled_for_bucket(lock)
        .customize()
        .mutate_request(move |request| {
            request
                .headers_mut()
                .insert(teifs_s3::LAYOUT_HEADER, layout);
        })
        .send()
        .await
        .unwrap();
}

async fn put(s3: &Client, bucket: &str, key: &str, body: &[u8]) -> Option<String> {
    s3.put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(body.to_vec()))
        .send()
        .await
        .unwrap()
        .version_id
}

async fn versioning(s3: &Client, bucket: &str) {
    s3.put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
}

fn customer() -> (String, String) {
    (
        STANDARD.encode(CUSTOMER_KEY),
        STANDARD.encode(Md5::digest(CUSTOMER_KEY)),
    )
}

/// Writes something of everything the format holds.
async fn write_drive(server: &Server) {
    let s3 = client(server, SECRET_KEY);

    // An object bucket: inline and file objects, SSE-S3 (its default), SSE-KMS and
    // SSE-C, metadata and tags, an upload in progress, and settings of every kind.
    bucket(&s3, "objects", "object", false).await;
    s3.put_object()
        .bucket("objects")
        .key("small.txt")
        .content_type("text/plain")
        .metadata("author", "fixture")
        .tagging("team=storage&kind=note")
        .body(ByteStream::from_static(b"small, inline"))
        .send()
        .await
        .unwrap();
    let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    put(&s3, "objects", "data/big.bin", &big).await;
    s3.put_object()
        .bucket("objects")
        .key("kms.bin")
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .body(ByteStream::from_static(b"under the named key"))
        .send()
        .await
        .unwrap();
    let (key, key_md5) = customer();
    s3.put_object()
        .bucket("objects")
        .key("customer.bin")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&key)
        .sse_customer_key_md5(&key_md5)
        .body(ByteStream::from_static(b"under the customer's key"))
        .send()
        .await
        .unwrap();
    let upload = s3
        .create_multipart_upload()
        .bucket("objects")
        .key("unfinished.bin")
        .send()
        .await
        .unwrap();
    s3.upload_part()
        .bucket("objects")
        .key("unfinished.bin")
        .upload_id(upload.upload_id().unwrap())
        .part_number(1)
        .body(ByteStream::from_static(b"the first part"))
        .send()
        .await
        .unwrap();

    // A folder bucket: plain files, an empty folder, and an object uploaded in parts.
    bucket(&s3, "files", "folder", false).await;
    s3.put_bucket_policy()
        .bucket("files")
        .policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::files/logs/*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    // Settings last: its logging delivers to `files`.
    settings(&s3, "objects").await;
    access(&s3, "objects").await;
    s3.put_object()
        .bucket("files")
        .key("notes/hello world+ü.txt")
        .content_type("text/plain; charset=utf-8")
        .metadata("topic", "fixtures")
        .body(ByteStream::from_static(b"hello world"))
        .send()
        .await
        .unwrap();
    put(&s3, "files", "empty/", b"").await;
    let upload = s3
        .create_multipart_upload()
        .bucket("files")
        .key("video.bin")
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let mut parts = Vec::new();
    for (number, body) in [(1, vec![0u8; 5 * 1024 * 1024]), (2, b"tail".to_vec())] {
        let part = s3
            .upload_part()
            .bucket("files")
            .key("video.bin")
            .upload_id(id)
            .part_number(number)
            .body(ByteStream::from(body))
            .send()
            .await
            .unwrap();
        parts.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(part.e_tag().unwrap())
                .build(),
        );
    }
    s3.complete_multipart_upload()
        .bucket("files")
        .key("video.bin")
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build(),
        )
        .send()
        .await
        .unwrap();

    // Versions in both layouts: versions stacked, delete markers, Object Lock.
    bucket(&s3, "locked", "object", true).await;
    s3.put_object_lock_configuration()
        .bucket("locked")
        .object_lock_configuration(
            ObjectLockConfiguration::builder()
                .object_lock_enabled(ObjectLockEnabled::Enabled)
                .rule(
                    ObjectLockRule::builder()
                        .default_retention(
                            DefaultRetention::builder()
                                .mode(ObjectLockRetentionMode::Governance)
                                .days(1)
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let first = put(&s3, "locked", "doc.txt", b"one").await.unwrap();
    put(&s3, "locked", "doc.txt", b"two").await;
    s3.put_object_legal_hold()
        .bucket("locked")
        .key("doc.txt")
        .version_id(&first)
        .legal_hold(
            ObjectLockLegalHold::builder()
                .status(ObjectLockLegalHoldStatus::On)
                .build(),
        )
        .send()
        .await
        .unwrap();
    s3.put_object_retention()
        .bucket("locked")
        .key("doc.txt")
        .version_id(&first)
        .retention(
            ObjectLockRetention::builder()
                .mode(ObjectLockRetentionMode::Compliance)
                .retain_until_date(DateTime::from_secs(4_070_908_800))
                .build(),
        )
        // Governance (the default retention) gives way to compliance only when bypassed.
        .bypass_governance_retention(true)
        .send()
        .await
        .unwrap();
    s3.delete_object()
        .bucket("locked")
        .key("doc.txt")
        .send()
        .await
        .unwrap();
    put(&s3, "locked", "doc.txt", b"three").await;
    put(&s3, "locked", "gone.txt", b"soon gone").await;
    s3.delete_object()
        .bucket("locked")
        .key("gone.txt")
        .send()
        .await
        .unwrap();
    bucket(&s3, "history", "folder", false).await;
    put(&s3, "history", "a.txt", b"before versioning").await;
    versioning(&s3, "history").await;
    put(&s3, "history", "a.txt", b"first version").await;
    put(&s3, "history", "a.txt", b"second version").await;
    put(&s3, "history", "b/c.txt", b"deleted").await;
    s3.delete_object()
        .bucket("history")
        .key("b/c.txt")
        .send()
        .await
        .unwrap();

    // Users, groups and policies.
    let iam = &server.iam;
    iam.create_user("alice", None, &[], None).unwrap();
    iam.put_inline(
        teifs_iam::Owner::User("alice"),
        "own-folder",
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::files/alice/*"}}"#,
    )
    .unwrap();
    iam.create_access_key("alice").unwrap();
    let readers = iam
        .create_policy(
            "readers",
            None,
            Some("Reads every bucket"),
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}}"#,
            &[],
        )
        .unwrap();
    iam.create_group("team", None).unwrap();
    iam.add_user_to_group("team", "alice").unwrap();
    iam.attach(teifs_iam::Owner::Group("team"), &readers.arn)
        .unwrap();
}

/// A bucket's settings, one of each kind the S3 API sets.
async fn settings(s3: &Client, bucket: &str) {
    s3.put_bucket_tagging()
        .bucket(bucket)
        .tagging(
            Tagging::builder()
                .tag_set(
                    Tag::builder()
                        .key("owner")
                        .value("fixtures")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    s3.put_bucket_cors()
        .bucket(bucket)
        .cors_configuration(
            CorsConfiguration::builder()
                .cors_rules(
                    CorsRule::builder()
                        .allowed_methods("GET")
                        .allowed_origins("https://example.com")
                        .max_age_seconds(600)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    s3.put_bucket_policy()
        .bucket(bucket)
        .policy(format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::{bucket}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    s3.put_bucket_lifecycle_configuration()
        .bucket(bucket)
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(
                    LifecycleRule::builder()
                        .id("old-logs")
                        .status(ExpirationStatus::Enabled)
                        .filter(LifecycleRuleFilter::builder().prefix("logs/").build())
                        .expiration(LifecycleExpiration::builder().days(3650).build())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
}

/// The settings that say who may do what.
async fn access(s3: &Client, bucket: &str) {
    s3.put_public_access_block()
        .bucket(bucket)
        .public_access_block_configuration(
            PublicAccessBlockConfiguration::builder()
                .block_public_acls(true)
                .ignore_public_acls(true)
                .block_public_policy(false)
                .restrict_public_buckets(false)
                .build(),
        )
        .send()
        .await
        .unwrap();
    s3.put_bucket_ownership_controls()
        .bucket(bucket)
        .ownership_controls(
            OwnershipControls::builder()
                .rules(
                    OwnershipControlsRule::builder()
                        .object_ownership(aws_sdk_s3::types::ObjectOwnership::BucketOwnerEnforced)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    s3.put_bucket_logging()
        .bucket(bucket)
        .bucket_logging_status(
            BucketLoggingStatus::builder()
                .logging_enabled(
                    LoggingEnabled::builder()
                        .target_bucket("files")
                        .target_prefix("logs/")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
}

/// Everything the S3 and admin APIs say about the drive: buckets with their settings,
/// every version of every object (with its attributes, tags, lock and contents' MD5),
/// uploads in progress with their parts, and users, groups and policies.
async fn describe(server: &Server) -> Value {
    let s3 = client(server, SECRET_KEY);
    let (status, buckets) = signing::signed(
        server,
        (ACCESS_KEY, SECRET_KEY),
        "GET",
        ADMIN_BUCKETS,
        &[],
        b"",
    )
    .await;
    assert_eq!(status, 200, "{buckets}");
    let mut buckets: Value = serde_json::from_str(&buckets).unwrap();
    buckets.as_object_mut().unwrap().remove("exportedMs");
    let (status, iam) =
        signing::signed(server, (ACCESS_KEY, SECRET_KEY), "GET", ADMIN_IAM, &[], b"").await;
    assert_eq!(status, 200, "{iam}");
    let mut iam: Value = serde_json::from_str(&iam).unwrap();
    iam.as_object_mut().unwrap().remove("exportedMs");
    let mut objects = BTreeMap::new();
    let mut uploads = BTreeMap::new();
    let listed = s3.list_buckets().send().await.unwrap();
    for name in listed.buckets().iter().filter_map(|b| b.name()) {
        objects.insert(name.to_owned(), versions(&s3, name).await);
        uploads.insert(name.to_owned(), in_progress(&s3, name).await);
    }
    json!({"buckets": buckets, "iam": iam, "objects": objects, "uploads": uploads})
}

async fn versions(s3: &Client, bucket: &str) -> Vec<Value> {
    let listing = s3
        .list_object_versions()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
    assert!(!listing.is_truncated().unwrap_or(false));
    let mut out = Vec::new();
    for marker in listing.delete_markers() {
        out.push(json!({
            "key": marker.key(),
            "versionId": marker.version_id(),
            "latest": marker.is_latest(),
            "deleteMarker": true,
            "modified": marker.last_modified().map(DateTime::secs),
        }));
    }
    // Access logs arrive when they arrive: an opened drive delivers the ones it holds.
    for version in listing
        .versions()
        .iter()
        .filter(|v| !v.key().unwrap().starts_with("logs/"))
    {
        let key = version.key().unwrap();
        let id = version.version_id().filter(|id| *id != "null");
        let sse_c = key == "customer.bin";
        let (customer_key, customer_md5) = customer();
        let head = s3
            .head_object()
            .bucket(bucket)
            .key(key)
            .set_version_id(id.map(str::to_owned))
            .set_sse_customer_algorithm(sse_c.then(|| "AES256".to_owned()))
            .set_sse_customer_key(sse_c.then(|| customer_key.clone()))
            .set_sse_customer_key_md5(sse_c.then(|| customer_md5.clone()))
            .send()
            .await
            .unwrap();
        let body = s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .set_version_id(id.map(str::to_owned))
            .set_sse_customer_algorithm(sse_c.then(|| "AES256".to_owned()))
            .set_sse_customer_key(sse_c.then_some(customer_key))
            .set_sse_customer_key_md5(sse_c.then_some(customer_md5))
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes();
        let tags = s3
            .get_object_tagging()
            .bucket(bucket)
            .key(key)
            .set_version_id(id.map(str::to_owned))
            .send()
            .await
            .unwrap();
        let tags: BTreeMap<&str, &str> = tags
            .tag_set()
            .iter()
            .map(|t| (t.key(), t.value()))
            .collect();
        out.push(json!({
            "key": key,
            "versionId": version.version_id(),
            "latest": version.is_latest(),
            "etag": version.e_tag(),
            "size": version.size(),
            "modified": version.last_modified().map(DateTime::secs),
            "md5": STANDARD.encode(Md5::digest(&body)),
            "contentType": head.content_type(),
            "metadata": head.metadata(),
            "sse": head.server_side_encryption().map(|s| s.as_str().to_owned()),
            "sseCustomer": head.sse_customer_algorithm(),
            "lockMode": head.object_lock_mode().map(|m| m.as_str().to_owned()),
            "retainUntil": head.object_lock_retain_until_date().map(DateTime::secs),
            "legalHold": head.object_lock_legal_hold_status().map(|s| s.as_str().to_owned()),
            "tags": tags,
        }));
    }
    out.sort_by_key(|v| {
        (
            v["key"].to_string(),
            v["modified"].to_string(),
            v["versionId"].to_string(),
        )
    });
    out
}

async fn in_progress(s3: &Client, bucket: &str) -> Vec<Value> {
    let listed = s3
        .list_multipart_uploads()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
    let mut out = Vec::new();
    for upload in listed.uploads() {
        let (key, id) = (upload.key().unwrap(), upload.upload_id().unwrap());
        let parts = s3
            .list_parts()
            .bucket(bucket)
            .key(key)
            .upload_id(id)
            .send()
            .await
            .unwrap();
        let parts: Vec<Value> = parts
            .parts()
            .iter()
            .map(|p| json!({"number": p.part_number(), "etag": p.e_tag(), "size": p.size()}))
            .collect();
        out.push(json!({"key": key, "uploadId": id, "parts": parts}));
    }
    out
}

/// Whether `actual` says all `expected` does: the same values, with objects free to
/// have more fields. Panics naming the first difference.
fn contains(expected: &Value, actual: &Value, at: &str) {
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            for (field, value) in expected {
                let Some(found) = actual.get(field) else {
                    panic!("{at}.{field} is gone (was {value})");
                };
                contains(value, found, &format!("{at}.{field}"));
            }
        }
        (Value::Array(expected), Value::Array(actual)) => {
            assert_eq!(
                expected.len(),
                actual.len(),
                "{at}: {} entries, was {}: {actual:?}",
                actual.len(),
                expected.len()
            );
            for (i, (expected, actual)) in expected.iter().zip(actual).enumerate() {
                contains(expected, actual, &format!("{at}[{i}]"));
            }
        }
        _ => assert_eq!(expected, actual, "{at}"),
    }
}

/// Every file's and folder's modification time under `root`, by path, to the nanosecond
/// (a tarball keeps whole seconds).
fn mtimes(root: &Path, dir: &Path, out: &mut BTreeMap<String, u64>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let ns = modified
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        out.insert(rel, u64::try_from(ns).unwrap());
        if path.is_dir() {
            mtimes(root, &path, out);
        }
    }
}

#[tokio::test]
#[ignore = "writes a fixture: run once, when a release changes the format"]
async fn write_the_current_formats_fixture() {
    let Some(out) = std::env::var_os("TEIFS_WRITE_FIXTURE") else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let (drive, keys) = (root.path().join("drive"), root.path().join("keys"));
    fs::create_dir_all(&drive).unwrap();
    fs::create_dir_all(&keys).unwrap();
    fs::write(keys.join("keyring.json"), keyring()).unwrap();
    let server = serve(&drive, &keys).await;
    write_drive(&server).await;
    let description = describe(&server).await;
    common::stop(server).await;

    let mut times = BTreeMap::new();
    mtimes(root.path(), root.path(), &mut times);
    let format = teifs_store::FORMAT;
    let tarball =
        fs::File::create(Path::new(&out).join(format!("format-{format}.tar.gz"))).unwrap();
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        tarball,
        flate2::Compression::best(),
    ));
    tar.append_dir_all(".", root.path()).unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    let manifest = json!({
        "about": format!("A drive written by TeiFS format {format} through the S3 and admin APIs (tests/format_fixtures.rs), with its keyring; `description` is what those APIs said about it."),
        "mtimesNs": times,
        "description": description,
    });
    fs::write(
        Path::new(&out).join(format!("format-{format}.json")),
        serde_json::to_string_pretty(&manifest).unwrap() + "\n",
    )
    .unwrap();
}

/// Unpacks fixture `format` as a faithful restore would: the same bytes and modification
/// times, new inodes.
fn restore(format: u32) -> (tempfile::TempDir, Value) {
    let dir = tempfile::tempdir().unwrap();
    let archive = fs::File::open(format!("{FIXTURES}/format-{format}.tar.gz")).unwrap();
    tar::Archive::new(flate2::read::GzDecoder::new(archive))
        .unpack(dir.path())
        .unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(format!("{FIXTURES}/format-{format}.json")).unwrap())
            .unwrap();
    // Folders' too: a folder object's time is its folder's.
    for (rel, ns) in manifest["mtimesNs"].as_object().unwrap() {
        let ns = ns.as_u64().unwrap();
        let time = filetime::FileTime::from_unix_time(
            i64::try_from(ns / 1_000_000_000).unwrap(),
            u32::try_from(ns % 1_000_000_000).unwrap(),
        );
        filetime::set_file_mtime(dir.path().join(rel), time).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let keyring = dir.path().join("keys/keyring.json");
        fs::set_permissions(keyring, fs::Permissions::from_mode(0o600)).unwrap();
    }
    (dir, manifest)
}

#[tokio::test]
async fn every_format_since_2_opens_with_everything_intact() {
    for format in 2..=NEWEST {
        let (dir, manifest) = restore(format);
        let server = serve(&dir.path().join("drive"), &dir.path().join("keys")).await;
        let now = describe(&server).await;
        contains(&manifest["description"], &now, &format!("format {format}"));
        // And it takes writes.
        let s3 = client(&server, SECRET_KEY);
        put(&s3, "objects", "after-upgrade.txt", b"new").await;
        put(&s3, "files", "after-upgrade.txt", b"new").await;
        common::stop(server).await;
    }
}
