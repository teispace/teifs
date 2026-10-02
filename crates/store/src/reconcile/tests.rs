//! Files changed outside TeiFS: hashed, re-adopted, forgotten.

use std::{
    collections::BTreeMap,
    fs,
    time::{Duration, SystemTime},
};

use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{Layout, MIN_PART_SIZE, Precondition, Store};

async fn store() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("bkt", Layout::Folder).await.unwrap();
    (dir, store)
}

fn step() -> Step {
    Step {
        now: SystemTime::now(),
        cancel: CancellationToken::new(),
    }
}

/// Runs the job until it rests after a full pass.
fn pass(inner: &Inner) {
    let mut job = IndexFolders::default();
    for _ in 0..10_000 {
        if job.step(inner, &step()).unwrap() == 0 {
            return;
        }
    }
    panic!("the pass never ended");
}

/// Moves a file's modification time, as a copy tool that doesn't keep it would.
fn touch(path: &std::path::Path) {
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(SystemTime::now() - Duration::from_hours(48))
        .unwrap();
}

#[tokio::test]
async fn files_added_outside_get_their_md5() {
    let (dir, store) = store().await;
    fs::write(dir.path().join("bkt/hello.txt"), b"hello").unwrap();
    fs::create_dir_all(dir.path().join("bkt/deep/er")).unwrap();
    fs::write(dir.path().join("bkt/deep/er/x"), b"").unwrap();
    assert!(
        store
            .head("bkt", "hello.txt")
            .await
            .unwrap()
            .etag
            .ends_with("-1")
    );
    pass(&store.inner);
    let head = store.head("bkt", "hello.txt").await.unwrap();
    assert_eq!(head.etag, "5d41402abc4b2a76b9719d911017c592");
    let empty = store.head("bkt", "deep/er/x").await.unwrap();
    assert_eq!(empty.etag, "d41d8cd98f00b204e9800998ecf8427e");
}

#[tokio::test]
async fn restored_files_keep_their_metadata() {
    let (dir, store) = store().await;
    let attrs = ObjectAttrs {
        content_type: Some("text/csv".into()),
        tags: [("k".to_owned(), "v".to_owned())].into(),
        ..ObjectAttrs::default()
    };
    let put = store
        .put_bytes("bkt", "data.csv", b"a,b\n1,2\n", attrs.clone())
        .await
        .unwrap();
    touch(&dir.path().join("bkt/data.csv"));
    assert_ne!(store.head("bkt", "data.csv").await.unwrap().etag, put.etag);
    pass(&store.inner);
    let head = store.head("bkt", "data.csv").await.unwrap();
    assert_eq!(head.etag, put.etag);
    assert_eq!(head.attrs.content_type, attrs.content_type);
    assert_eq!(head.attrs.tags, attrs.tags);
}

#[tokio::test]
async fn restored_multipart_files_keep_their_etag() {
    let (dir, store) = store().await;
    let upload = store
        .create_upload(
            "bkt",
            "big.bin",
            ObjectAttrs::default(),
            None,
            &crate::Encryption::None,
            None,
            None,
        )
        .await
        .unwrap();
    let first = vec![3u8; usize::try_from(MIN_PART_SIZE).unwrap()];
    let mut etags = Vec::new();
    for (number, bytes) in [(1, first.as_slice()), (2, b"tail".as_slice())] {
        let mut staged = store.stage();
        staged.write(bytes).await.unwrap();
        let part = store
            .put_part(&upload.id, number, staged, BTreeMap::new())
            .await
            .unwrap();
        etags.push((number, part.etag));
    }
    let done = store
        .complete(
            &upload.id,
            etags,
            Precondition::default(),
            crate::CompleteWith::default(),
        )
        .await
        .unwrap();
    assert!(done.etag.ends_with("-2"));
    touch(&dir.path().join("bkt/big.bin"));
    pass(&store.inner);
    let head = store.head("bkt", "big.bin").await.unwrap();
    assert_eq!(head.etag, done.etag);
    assert_eq!(head.parts.len(), 2);
}

#[tokio::test]
async fn changed_files_lose_their_old_metadata() {
    let (dir, store) = store().await;
    let attrs = ObjectAttrs {
        content_type: Some("text/plain".into()),
        ..ObjectAttrs::default()
    };
    store.put_bytes("bkt", "f", b"old", attrs).await.unwrap();
    fs::write(dir.path().join("bkt/f"), b"new!").unwrap();
    touch(&dir.path().join("bkt/f"));
    pass(&store.inner);
    let head = store.head("bkt", "f").await.unwrap();
    assert_eq!(head.etag, hex(&Md5::digest(b"new!")));
    assert_eq!(head.attrs, ObjectAttrs::default());
}

#[tokio::test]
async fn rows_of_deleted_files_are_forgotten_but_kept_folders_stay() {
    let (dir, store) = store().await;
    // Enough files for several pages, so rows between pages are pruned too. A first
    // pass gives them rows.
    for i in 0..(ENTRIES_PER_STEP + 300) {
        fs::write(dir.path().join(format!("bkt/f{i:05}")), b"x").unwrap();
    }
    pass(&store.inner);
    assert!(store.inner.lock().get("bkt", "f01299").unwrap().is_some());
    let folder = ObjectAttrs {
        content_type: Some("application/x-directory".into()),
        ..ObjectAttrs::default()
    };
    store.put_bytes("bkt", "dir/", b"", folder).await.unwrap();
    store
        .put_bytes("bkt", "dir/child", b"c", ObjectAttrs::default())
        .await
        .unwrap();
    for gone in ["f00000", "f00999", "f01000", "f01299"] {
        fs::remove_file(dir.path().join("bkt").join(gone)).unwrap();
    }
    pass(&store.inner);
    let conn = store.inner.lock();
    for gone in ["f00000", "f00999", "f01000", "f01299"] {
        assert!(conn.get("bkt", gone).unwrap().is_none(), "{gone}");
    }
    assert!(conn.get("bkt", "f00500").unwrap().is_some());
    assert!(conn.get("bkt", "dir/").unwrap().is_some());
    assert!(conn.get("bkt", "dir/child").unwrap().is_some());
}

#[test]
fn hashing_by_parts_matches_multipart_etags() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    let bytes: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(&path, &bytes).unwrap();
    let stamp = Stamp::of(&fs::metadata(&path).unwrap());
    let sizes = [1_048_577, 1_000_000, 951_423];
    let hashes = hash_file(&path, stamp, Some(&sizes), &step())
        .unwrap()
        .unwrap();
    let mut offset = 0;
    let expected: Vec<[u8; 16]> = sizes
        .iter()
        .map(|size| {
            let end = offset + usize::try_from(*size).unwrap();
            let md5 = Md5::digest(&bytes[offset..end]).into();
            offset = end;
            md5
        })
        .collect();
    assert!(hashes.matches(&multipart_etag(&expected)));
    assert!(hashes.matches(&hex(&Md5::digest(&bytes))));
    // Part sizes that don't add up to the file are ignored.
    let wrong = hash_file(&path, stamp, Some(&[1, 2]), &step())
        .unwrap()
        .unwrap();
    assert!(wrong.parts.is_none());
}

#[tokio::test]
async fn stopping_leaves_the_row_alone() {
    let (dir, store) = store().await;
    fs::write(dir.path().join("bkt/a"), b"a").unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let stopping = Step {
        now: SystemTime::now(),
        cancel,
    };
    IndexFolders::default()
        .step(&store.inner, &stopping)
        .unwrap();
    assert!(store.inner.lock().get("bkt", "a").unwrap().is_none());
}

#[tokio::test]
async fn a_step_stops_at_its_byte_budget_and_the_next_carries_on() {
    let (dir, store) = store().await;
    let big = vec![7u8; usize::try_from(BYTES_PER_STEP / 2 + 1).unwrap()];
    for name in ["a", "b"] {
        fs::write(dir.path().join("bkt").join(name), &big).unwrap();
    }
    fs::write(dir.path().join("bkt/c"), b"small").unwrap();
    let mut job = IndexFolders::default();
    job.step(&store.inner, &step()).unwrap();
    let rows = |key: &str| store.inner.lock().get("bkt", key).unwrap().is_some();
    // Two halves and a byte: over budget after b, so c waits for the next step.
    assert!(rows("a") && rows("b") && !rows("c"));
    job.step(&store.inner, &step()).unwrap();
    assert!(rows("c"));
}
