//! Small objects kept in the index: no file of their own, read back whole and in ranges,
//! encrypted like files, through versions, copies and a reopened drive.

use std::sync::Arc;

use tempfile::TempDir;
use tokio::io::AsyncReadExt;

use super::*;

struct Drive {
    dir: TempDir,
    _keys: TempDir,
    store: Store,
}

/// A drive with a KMS, so object buckets encrypt (SSE-S3) as they do by default.
async fn drive() -> Drive {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let store = open(dir.path(), &keys);
    store.create_bucket("docs", Layout::Object).await.unwrap();
    Drive {
        dir,
        _keys: keys,
        store,
    }
}

fn open(root: &std::path::Path, keys: &TempDir) -> Store {
    let kms = Arc::new(LocalKms::open(keys.path().join("keyring.json")).unwrap());
    let options = StoreOptions {
        kms: Some(kms),
        ..StoreOptions::default()
    };
    Store::open_with(root, options).unwrap()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 7 % 251).unwrap())
        .collect()
}

/// How many data files object buckets hold.
fn data_files(drive: &Drive) -> usize {
    fn count(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir).map_or(0, |entries| {
            entries
                .map(|entry| entry.unwrap().path())
                .map(|path| if path.is_dir() { count(&path) } else { 1 })
                .sum()
        })
    }
    count(&drive.dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR))
}

async fn put(store: &Store, key: &str, bytes: &[u8]) -> ObjectInfo {
    store
        .put_bytes("docs", key, bytes, ObjectAttrs::default())
        .await
        .unwrap()
}

async fn read_range(store: &Store, key: &str, version: Option<&str>, at: u64, len: u64) -> Vec<u8> {
    let (_, body) = store.read_with("docs", key, version, None).await.unwrap();
    let mut out = Vec::new();
    body.expect("an object has a body")
        .range(at, len)
        .await
        .unwrap()
        .read_to_end(&mut out)
        .await
        .unwrap();
    out
}

async fn read_all(store: &Store, key: &str) -> Vec<u8> {
    read_range(store, key, None, 0, u64::MAX).await
}

#[tokio::test]
async fn a_small_object_is_kept_in_the_index_and_reads_back() {
    let drive = drive().await;
    // Encrypted, it still fits.
    let bytes = pattern(30_000);
    let info = put(&drive.store, "small", &bytes).await;
    assert_eq!(info.size, 30_000);
    assert_eq!(data_files(&drive), 0);
    assert_eq!(read_all(&drive.store, "small").await, bytes);
    // Ranges at the start, in the middle, past the end and after it.
    for (at, len) in [(0, 10), (12_345, 2_000), (29_990, 100), (30_000, 5)] {
        let end = usize::try_from((at + len).min(30_000)).unwrap();
        let at_usize = usize::try_from(at).unwrap();
        assert_eq!(
            read_range(&drive.store, "small", None, at, len).await,
            bytes[at_usize..end]
        );
    }
    let head = drive.store.head("docs", "small").await.unwrap();
    assert_eq!(head.etag, info.etag);
}

#[tokio::test]
async fn an_empty_object_is_kept_in_the_index() {
    let drive = drive().await;
    put(&drive.store, "empty", b"").await;
    assert_eq!(data_files(&drive), 0);
    assert_eq!(read_all(&drive.store, "empty").await, b"");
}

#[tokio::test]
async fn bigger_objects_and_uploads_in_parts_get_files() {
    let drive = drive().await;
    let big = pattern(usize::try_from(INLINE_MAX).unwrap() + 1);
    put(&drive.store, "big", &big).await;
    assert_eq!(data_files(&drive), 1);
    assert_eq!(read_all(&drive.store, "big").await, big);

    let upload = drive
        .store
        .create_upload(
            "docs",
            "parts",
            ObjectAttrs::default(),
            None,
            &Encryption::None,
            None,
            None,
        )
        .await
        .unwrap();
    let mut staged = drive.store.stage();
    staged.write(b"one part").await.unwrap();
    let part = drive
        .store
        .put_part(&upload.id, 1, staged, std::collections::BTreeMap::new())
        .await
        .unwrap();
    drive
        .store
        .complete(
            &upload.id,
            vec![(1, part.etag)],
            Precondition::default(),
            CompleteWith::default(),
        )
        .await
        .unwrap();
    assert_eq!(data_files(&drive), 2);
    assert_eq!(read_all(&drive.store, "parts").await, b"one part");
}

#[tokio::test]
async fn replacing_and_deleting_moves_between_the_index_and_files() {
    let drive = drive().await;
    let big = pattern(usize::try_from(INLINE_MAX).unwrap() * 2);
    put(&drive.store, "k", &big).await;
    assert_eq!(data_files(&drive), 1);
    // A small object replacing a file-stored one frees the file.
    put(&drive.store, "k", b"small now").await;
    assert_eq!(data_files(&drive), 0);
    assert_eq!(read_all(&drive.store, "k").await, b"small now");
    put(&drive.store, "k", &big).await;
    assert_eq!(read_all(&drive.store, "k").await, big);
    drive
        .store
        .delete_with("docs", "k", None, Precondition::default(), false)
        .await
        .unwrap();
    put(&drive.store, "other", b"stays").await;
    drive
        .store
        .delete_with("docs", "other", None, Precondition::default(), false)
        .await
        .unwrap();
    assert!(drive.store.head("docs", "other").await.is_err());
    assert_eq!(data_files(&drive), 0);
}

#[tokio::test]
async fn each_version_keeps_its_own_bytes() {
    let drive = drive().await;
    drive
        .store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    let one = put(&drive.store, "k", b"one").await;
    let two = put(&drive.store, "k", b"two!").await;
    let v1 = one.version_id.unwrap();
    let v2 = two.version_id.unwrap();
    assert_eq!(
        read_range(&drive.store, "k", Some(&v1), 0, 10).await,
        b"one"
    );
    assert_eq!(
        read_range(&drive.store, "k", Some(&v2), 0, 10).await,
        b"two!"
    );
    // The listing describes them without their bytes.
    let listing = drive
        .store
        .list_versions(
            "docs",
            crate::VersionsQuery {
                max_keys: 10,
                ..crate::VersionsQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(listing.versions.len(), 2);
    assert_eq!(data_files(&drive), 0);
}

#[tokio::test]
async fn copies_of_a_small_object_keep_its_bytes() {
    let drive = drive().await;
    let dir = tempfile::tempdir().unwrap();
    // Unencrypted, so the copy is made from the stored bytes, not read and written again.
    let plain = Store::open(dir.path()).unwrap();
    plain.create_bucket("from", Layout::Object).await.unwrap();
    plain
        .create_bucket("to-objects", Layout::Object)
        .await
        .unwrap();
    plain
        .create_bucket("to-folder", Layout::Folder)
        .await
        .unwrap();
    plain
        .put_bytes("from", "k", b"copied bytes", ObjectAttrs::default())
        .await
        .unwrap();
    for to in ["to-objects", "to-folder"] {
        plain
            .copy(("from", "k"), (to, "k"), None, Precondition::default())
            .await
            .unwrap();
        let (_, body) = plain.read(to, "k").await.unwrap();
        let mut out = Vec::new();
        body.unwrap()
            .all()
            .await
            .unwrap()
            .read_to_end(&mut out)
            .await
            .unwrap();
        assert_eq!(out, b"copied bytes", "copied to {to}");
    }
    // And an encrypted one, read and written again.
    put(&drive.store, "src", b"sealed bytes").await;
    drive
        .store
        .copy(
            ("docs", "src"),
            ("docs", "dst"),
            None,
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(read_all(&drive.store, "dst").await, b"sealed bytes");
}

#[tokio::test]
async fn small_objects_survive_reopening_the_drive() {
    let Drive {
        dir,
        _keys: keys,
        store,
    } = drive().await;
    put(&store, "k", b"kept").await;
    drop(store);
    let store = open(dir.path(), &keys);
    assert_eq!(read_all(&store, "k").await, b"kept");
}

#[tokio::test]
async fn a_small_upload_is_held_without_a_staged_file() {
    let drive = drive().await;
    let staged_files = || std::fs::read_dir(&drive.store.inner.tmp).unwrap().count();
    let mut small = drive
        .store
        .stage_for("docs", &Encryption::S3)
        .await
        .unwrap();
    small.write(&pattern(1000)).await.unwrap();
    small.finish().await.unwrap();
    assert_eq!(staged_files(), 0);
    // Bigger than a batch: written as it arrives.
    let big_bytes = pattern(300 * 1024);
    let mut big = drive
        .store
        .stage_for("docs", &Encryption::S3)
        .await
        .unwrap();
    big.write(&big_bytes).await.unwrap();
    big.finish().await.unwrap();
    assert_eq!(staged_files(), 1);
    for (key, staged) in [("small", small), ("big", big)] {
        drive
            .store
            .commit(
                "docs",
                key,
                staged,
                ObjectAttrs::default(),
                Precondition::default(),
            )
            .await
            .unwrap();
    }
    assert_eq!(staged_files(), 0);
    assert_eq!(read_all(&drive.store, "small").await, pattern(1000));
    assert_eq!(read_all(&drive.store, "big").await, big_bytes);
    assert_eq!(data_files(&drive), 1);
}
