//! The on-disk format: new drives get `format.json`, drives written by older releases are
//! upgraded with everything intact, and drives from newer releases are refused.
//!
//! `fixtures/format-<n>.tar.gz` holds a drive written by the release that used format
//! `<n>`, and `format-<n>.json` what it contains. Every released format keeps its fixture,
//! so each build proves it can still open every drive ever written.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{Duration, SystemTime},
};

use serde::Deserialize;
use teifs_store::{FORMAT, Layout, Store, StoreError};
use tempfile::TempDir;

#[derive(Deserialize)]
struct Manifest {
    mtimes_ns: BTreeMap<String, u64>,
    objects: Vec<ExpectedObject>,
    uploads: Vec<ExpectedUpload>,
}

#[derive(Deserialize)]
struct ExpectedObject {
    bucket: String,
    key: String,
    etag: String,
    attrs: serde_json::Value,
}

#[derive(Deserialize)]
struct ExpectedUpload {
    id: String,
    bucket: String,
    key: String,
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Unpacks a fixture drive the way a faithful backup restore would: same bytes, same
/// modification times, new inodes.
fn restore(format: u32) -> (TempDir, Manifest) {
    let dir = tempfile::tempdir().unwrap();
    let archive = fs::File::open(format!("{FIXTURES}/format-{format}.tar.gz")).unwrap();
    tar::Archive::new(flate2::read::GzDecoder::new(archive))
        .unpack(dir.path())
        .unwrap();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(format!("{FIXTURES}/format-{format}.json")).unwrap())
            .unwrap();
    for (rel, mtime_ns) in &manifest.mtimes_ns {
        let path = dir.path().join(rel);
        if path.is_file() {
            let file = fs::File::options().write(true).open(&path).unwrap();
            file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_nanos(*mtime_ns))
                .unwrap();
        }
    }
    (dir, manifest)
}

async fn assert_intact(store: &Store, manifest: &Manifest) {
    for expected in &manifest.objects {
        let info = store.head(&expected.bucket, &expected.key).await.unwrap();
        assert_eq!(info.etag, expected.etag, "{}", expected.key);
        assert_eq!(
            serde_json::to_value(&info.attrs).unwrap(),
            expected.attrs,
            "{}",
            expected.key
        );
    }
    for expected in &manifest.uploads {
        let upload = store.upload(&expected.id).await.unwrap();
        assert_eq!(
            (upload.bucket.as_str(), upload.key.as_str()),
            (expected.bucket.as_str(), expected.key.as_str())
        );
        assert_eq!(
            store.parts(&expected.id, 0, 100, None).await.unwrap().len(),
            1
        );
    }
}

fn system(dir: &Path) -> std::path::PathBuf {
    dir.join(teifs_store::SYSTEM_DIR)
}

#[tokio::test]
async fn format_0_drives_are_upgraded_intact() {
    let (dir, manifest) = restore(0);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.format().format, FORMAT);
    assert_intact(&store, &manifest).await;

    let system = system(dir.path());
    assert!(system.join("index.db").is_file());
    assert!(system.join("system.db").is_file());
    assert!(system.join("backups/pre-format-1/meta.db").is_file());
    assert!(!system.join("meta.db").exists());
    assert!(!system.join("meta.db-wal").exists());

    // Opening again changes nothing: same drive, same objects.
    let id = store.format().drive.clone();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.format().drive, id);
    assert_intact(&store, &manifest).await;
}

#[tokio::test]
async fn every_released_format_opens_intact() {
    for format in 0..=1 {
        let (dir, manifest) = restore(format);
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.format().format, FORMAT, "format {format}");
        assert_intact(&store, &manifest).await;
    }
}

#[tokio::test]
async fn format_1_drives_are_backed_up_before_their_upgrade() {
    let (dir, manifest) = restore(1);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.format().format, FORMAT);
    let backups = system(dir.path()).join(format!("backups/pre-format-{FORMAT}"));
    assert!(backups.join("index.db").is_file());
    assert!(backups.join("system.db").is_file());
    assert_intact(&store, &manifest).await;
    // Every bucket in a format 1 drive is a folder bucket, and new object buckets work.
    assert_eq!(store.head_bucket("photos").await.unwrap(), Layout::Folder);
    store.create_bucket("fresh", Layout::Object).await.unwrap();
    store
        .put_bytes("fresh", "a/../b", b"x", teifs_store::ObjectAttrs::default())
        .await
        .unwrap();
}

#[tokio::test]
async fn an_upgrade_that_stopped_halfway_is_redone() {
    let (dir, manifest) = restore(0);
    let system = system(dir.path());
    // What a crash before `format.json` was written leaves behind.
    fs::create_dir_all(system.join("backups/pre-format-1")).unwrap();
    fs::write(system.join("backups/pre-format-1/meta.db"), b"half").unwrap();
    fs::write(system.join("index.db.upgrading"), b"half").unwrap();

    let store = Store::open(dir.path()).unwrap();
    assert_intact(&store, &manifest).await;
    assert!(!system.join("index.db.upgrading").exists());
}

#[tokio::test]
async fn new_drives_get_a_permanent_id() {
    let dir = tempfile::tempdir().unwrap();
    let first = Store::open(dir.path()).unwrap().format().clone();
    assert_eq!(first.format, FORMAT);
    assert_eq!(first.drive.len(), 36);
    let again = Store::open(dir.path()).unwrap().format().clone();
    assert_eq!(again, first);
}

#[test]
fn drives_from_newer_releases_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(system(dir.path())).unwrap();
    fs::write(
        system(dir.path()).join("format.json"),
        r#"{"format":99,"drive":"x","created":"2030-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    match Store::open(dir.path()) {
        Err(StoreError::NewerFormat { found: 99 }) => {}
        other => panic!("expected NewerFormat, got {other:?}"),
    }
}

#[test]
fn a_damaged_format_file_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(system(dir.path())).unwrap();
    fs::write(system(dir.path()).join("format.json"), b"{not json").unwrap();
    assert!(matches!(
        Store::open(dir.path()),
        Err(StoreError::CorruptFormat(_))
    ));
}

#[tokio::test]
async fn buckets_remember_when_teifs_created_them() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let before = SystemTime::now() - Duration::from_secs(1);
    store.create_bucket("photos", Layout::Folder).await.unwrap();
    let listed = store.list_buckets().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].created >= before);
}
