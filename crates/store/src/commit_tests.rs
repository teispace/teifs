//! An object bucket's write puts its data file in place before the commit lock and
//! records it under the lock: what changed in between is settled when it's recorded.

use teifs_meta::NULL_VERSION;
use teifs_types::LockMode;
use tempfile::TempDir;

use super::*;
use crate::test_util::in_both_layouts;
use crate::{
    lock::{DefaultRetention, RetentionPeriod},
    objects::{Finished, Written, read_footer},
};

in_both_layouts!(
    only_one_of_many_concurrent_create_only_writes_wins,
    concurrent_versioned_writes_each_make_a_version,
);

async fn concurrently(
    store: &std::sync::Arc<Store>,
    writes: usize,
    key: impl Fn(usize) -> String,
    precondition: Precondition,
) -> Vec<Result<ObjectInfo>> {
    let tasks: Vec<_> = (0..writes)
        .map(|i| {
            let (store, key, precondition) = (store.clone(), key(i), precondition.clone());
            tokio::spawn(async move {
                let mut staged = store.stage().await?;
                staged.write(format!("write {i}").as_bytes()).await?;
                store
                    .commit("docs", &key, staged, ObjectAttrs::default(), precondition)
                    .await
            })
        })
        .collect();
    let mut answers = Vec::new();
    for task in tasks {
        answers.push(task.await.unwrap());
    }
    answers
}

async fn only_one_of_many_concurrent_create_only_writes_wins(layout: Layout) {
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(dir.path()).unwrap());
    store.create_bucket("docs", layout).await.unwrap();
    let only_new = Precondition {
        if_none_match: Some(Match::Any),
        ..Precondition::default()
    };
    let answers = concurrently(&store, 32, |_| "same.txt".to_owned(), only_new).await;
    let won: Vec<_> = answers.iter().filter_map(|a| a.as_ref().ok()).collect();
    assert_eq!(won.len(), 1);
    assert!(
        answers
            .iter()
            .filter(|a| a.is_err())
            .all(|a| matches!(a, Err(StoreError::PreconditionFailed)))
    );
    let head = store.head("docs", "same.txt").await.unwrap();
    assert_eq!(head.etag, won[0].etag);
    // Nothing the losers wrote is left behind.
    let leftovers = std::fs::read_dir(dir.path().join(".teifs/tmp"))
        .unwrap()
        .count();
    assert_eq!(leftovers, 0);
}

async fn concurrent_versioned_writes_each_make_a_version(layout: Layout) {
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::open(dir.path()).unwrap());
    store.create_bucket("docs", layout).await.unwrap();
    store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    let answers = concurrently(
        &store,
        24,
        |i| format!("k{}", i % 3),
        Precondition::default(),
    )
    .await;
    let mut ids: Vec<_> = answers
        .into_iter()
        .map(|a| a.unwrap().version_id.unwrap())
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 24);
    let query = crate::VersionsQuery {
        max_keys: 1000,
        ..crate::VersionsQuery::default()
    };
    let listing = store.list_versions("docs", query).await.unwrap();
    assert_eq!(listing.versions.len(), 24);
    assert_eq!(listing.versions.iter().filter(|v| v.latest).count(), 3);
}

async fn object_bucket() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("docs", Layout::Object).await.unwrap();
    (dir, store)
}

fn resolved(store: &Store) -> ObjectBucket {
    match store.inner.bucket("docs").unwrap() {
        Bucket::Object(bucket) => bucket,
        Bucket::Folder(..) => unreachable!("an object bucket"),
    }
}

/// Writes `bytes` as `key` without recording it; also returns its data file.
async fn write(store: &Store, key: &str, bytes: &[u8]) -> (Written, PathBuf) {
    let mut staged = store.stage().await.unwrap();
    staged.write(bytes).await.unwrap();
    staged.finish().await.unwrap();
    let etag = teifs_types::hex(&staged.md5());
    let finished = Finished::plain(staged.path(), staged.size(), etag, ObjectAttrs::default());
    let written = store
        .inner
        .write_object(&resolved(store), key, finished)
        .unwrap();
    staged.keep();
    let path = written.path().to_owned();
    assert!(path.is_file());
    (written, path)
}

fn record(store: &Store, written: Written, precondition: &Precondition) -> Result<ObjectInfo> {
    let conn = store.inner.lock();
    store
        .inner
        .record_object(&conn, &resolved(store), written, precondition)
}

#[tokio::test]
async fn a_write_recorded_after_versioning_was_enabled_gets_a_version_id() {
    let (_dir, store) = object_bucket().await;
    let (written, path) = write(&store, "a.txt", b"hello").await;
    store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    let info = record(&store, written, &Precondition::default()).unwrap();
    let version_id = info.version_id.unwrap();
    assert_ne!(version_id, NULL_VERSION);
    // The footer says so too, so a rebuilt index would agree.
    let footer = read_footer(&path).unwrap().unwrap();
    assert_eq!(footer.version.as_deref(), Some(version_id.as_str()));
    let head = store
        .head_version("docs", "a.txt", Some(&version_id))
        .await
        .unwrap();
    assert_eq!(head.size, 5);
}

#[tokio::test]
async fn a_write_recorded_after_object_lock_was_set_gets_the_default_retention() {
    let (_dir, store) = object_bucket().await;
    store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    let (written, path) = write(&store, "a.txt", b"hello").await;
    let lock = ObjectLock {
        default_retention: Some(DefaultRetention {
            mode: LockMode::Governance,
            period: RetentionPeriod::Days(1),
        }),
    };
    store.set_bucket_object_lock("docs", lock).await.unwrap();
    let info = record(&store, written, &Precondition::default()).unwrap();
    let retention = info.attrs.retention.unwrap();
    assert_eq!(retention.mode, LockMode::Governance);
    let footer = read_footer(&path).unwrap().unwrap();
    assert_eq!(footer.attrs.retention, Some(retention));
}

#[tokio::test]
async fn a_write_whose_precondition_fails_when_recorded_leaves_no_file() {
    let (_dir, store) = object_bucket().await;
    let (written, path) = write(&store, "a.txt", b"mine").await;
    // Someone else's write of the key lands first.
    store
        .put_bytes("docs", "a.txt", b"theirs", ObjectAttrs::default())
        .await
        .unwrap();
    let only_new = Precondition {
        if_none_match: Some(Match::Any),
        ..Precondition::default()
    };
    let refused = record(&store, written, &only_new);
    assert!(matches!(refused, Err(StoreError::PreconditionFailed)));
    assert!(!path.exists());
    assert_eq!(store.head("docs", "a.txt").await.unwrap().size, 6);
}

#[tokio::test]
async fn a_group_records_each_write_on_its_own() {
    let (_dir, store) = object_bucket().await;
    let id = resolved(&store).id;
    let (first, first_path) = write(&store, "a.txt", b"first").await;
    let (second, second_path) = write(&store, "a.txt", b"second").await;
    let (other, other_path) = write(&store, "b.txt", b"other").await;
    let only_new = Precondition {
        if_none_match: Some(Match::Any),
        ..Precondition::default()
    };
    let group = |written| ("docs".to_owned(), id.clone(), written);
    let (a, b, c) = (group(first), group(second), group(other));
    let answers = store.inner.record_all(vec![
        (a.0, a.1, a.2, only_new.clone()),
        // Sees the write before it in the group: `a.txt` exists now.
        (b.0, b.1, b.2, only_new),
        (c.0, c.1, c.2, Precondition::default()),
    ]);
    assert_eq!(answers[0].as_ref().unwrap().size, 5);
    assert!(matches!(answers[1], Err(StoreError::PreconditionFailed)));
    assert_eq!(answers[2].as_ref().unwrap().size, 5);
    assert!(first_path.is_file() && !second_path.exists() && other_path.is_file());
    assert_eq!(store.head("docs", "a.txt").await.unwrap().size, 5);
    assert_eq!(store.head("docs", "b.txt").await.unwrap().size, 5);
}

#[tokio::test]
async fn a_group_replacing_a_version_removes_the_old_file() {
    let (_dir, store) = object_bucket().await;
    let id = resolved(&store).id;
    let (old, old_path) = write(&store, "a.txt", b"old").await;
    let (new, new_path) = write(&store, "a.txt", b"newer").await;
    let answers = store.inner.record_all(vec![
        ("docs".to_owned(), id.clone(), old, Precondition::default()),
        ("docs".to_owned(), id, new, Precondition::default()),
    ]);
    assert!(answers.iter().all(Result::is_ok));
    assert!(!old_path.exists() && new_path.is_file());
    assert!(store.inner.lock().garbage(10).unwrap().is_empty());
    assert_eq!(store.head("docs", "a.txt").await.unwrap().size, 5);
}

#[tokio::test]
async fn a_write_to_a_bucket_deleted_meanwhile_is_refused_and_removed() {
    let (_dir, store) = object_bucket().await;
    let id = resolved(&store).id;
    let (written, path) = write(&store, "a.txt", b"hello").await;
    store.delete_bucket("docs").await.unwrap();
    store.create_bucket("docs", Layout::Object).await.unwrap();
    let answers = store.inner.record_all(vec![(
        "docs".to_owned(),
        id,
        written,
        Precondition::default(),
    )]);
    assert!(matches!(answers[0], Err(StoreError::NoSuchBucket)));
    assert!(!path.exists());
    assert!(matches!(
        store.head("docs", "a.txt").await,
        Err(StoreError::NoSuchKey)
    ));
}

#[tokio::test]
async fn concurrent_writes_are_all_recorded() {
    let (_dir, store) = object_bucket().await;
    let store = std::sync::Arc::new(store);
    let writes: Vec<_> = (0..64)
        .map(|i| {
            let store = store.clone();
            tokio::spawn(async move {
                let key = format!("k{i}");
                store
                    .put_bytes("docs", &key, key.as_bytes(), ObjectAttrs::default())
                    .await
            })
        })
        .collect();
    for write in writes {
        write.await.unwrap().unwrap();
    }
    for i in 0..64 {
        let key = format!("k{i}");
        let head = store.head("docs", &key).await.unwrap();
        assert_eq!(head.size, key.len() as u64);
    }
}
