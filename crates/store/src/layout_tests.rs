//! S3 behaviour both bucket layouts share, run against each, and what only object
//! buckets can do.

#![allow(clippy::too_many_lines, reason = "scenario tests read top to bottom")]

use std::fs;

use tempfile::TempDir;
use tokio::io::AsyncReadExt;

use super::*;

const LAYOUTS: [Layout; 2] = [Layout::Folder, Layout::Object];

async fn bucket(layout: Layout) -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_files(dir.path()).unwrap();
    store.create_bucket("bkt", layout).await.unwrap();
    (dir, store)
}

async fn get(store: &Store, key: &str) -> Vec<u8> {
    let (_, body) = store.read("bkt", key).await.unwrap();
    let mut out = Vec::new();
    body.unwrap()
        .all()
        .await
        .unwrap()
        .read_to_end(&mut out)
        .await
        .unwrap();
    out
}

fn attrs(content_type: &str) -> ObjectAttrs {
    ObjectAttrs {
        content_type: Some(content_type.to_owned()),
        ..ObjectAttrs::default()
    }
}

#[tokio::test]
async fn round_trips_overwrites_and_deletes() {
    for layout in LAYOUTS {
        let (_dir, store) = bucket(layout).await;
        let first = store
            .put_bytes("bkt", "a/b.txt", b"one", attrs("text/plain"))
            .await
            .unwrap();
        assert_eq!(first.etag, "f97c5d29941bfb1b2fdab0874906ab82", "{layout:?}");
        assert_eq!(get(&store, "a/b.txt").await, b"one");
        let head = store.head("bkt", "a/b.txt").await.unwrap();
        assert_eq!(
            (head.size, head.attrs.content_type.as_deref()),
            (3, Some("text/plain"))
        );

        store
            .put_bytes("bkt", "a/b.txt", b"second", ObjectAttrs::default())
            .await
            .unwrap();
        assert_eq!(get(&store, "a/b.txt").await, b"second");
        assert_eq!(
            store
                .head("bkt", "a/b.txt")
                .await
                .unwrap()
                .attrs
                .content_type,
            None
        );

        store.delete("bkt", "a/b.txt").await.unwrap();
        assert!(matches!(
            store.head("bkt", "a/b.txt").await,
            Err(StoreError::NoSuchKey)
        ));
        // Deleting what isn't there succeeds, as in S3.
        store.delete("bkt", "a/b.txt").await.unwrap();
    }
}

#[tokio::test]
async fn ranges_read_only_the_object() {
    for layout in LAYOUTS {
        let (_dir, store) = bucket(layout).await;
        store
            .put_bytes("bkt", "k", b"0123456789", ObjectAttrs::default())
            .await
            .unwrap();
        let (_, body) = store.read("bkt", "k").await.unwrap();
        let mut out = Vec::new();
        body.unwrap()
            .range(7, 100)
            .await
            .unwrap()
            .read_to_end(&mut out)
            .await
            .unwrap();
        // Never the footer an object bucket's file ends with.
        assert_eq!(out, b"789", "{layout:?}");
    }
}

#[tokio::test]
async fn listings_page_and_roll_up_the_same_way() {
    let keys = ["a", "b/1", "b/2", "b/c/3", "c", "d/", "e/x"];
    for layout in LAYOUTS {
        let (_dir, store) = bucket(layout).await;
        for key in keys {
            store
                .put_bytes("bkt", key, b"", ObjectAttrs::default())
                .await
                .unwrap();
        }
        let all = store
            .list(
                "bkt",
                ListQuery {
                    prefix: String::new(),
                    delimiter: None,
                    after: None,
                    max_keys: 1000,
                },
            )
            .await
            .unwrap();
        let listed: Vec<_> = all.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(listed, keys, "{layout:?}");

        // Delimited, one entry per page: prefixes count as entries and pages resume.
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let page = store
                .list(
                    "bkt",
                    ListQuery {
                        prefix: String::new(),
                        delimiter: Some("/".into()),
                        after: after.clone(),
                        max_keys: 1,
                    },
                )
                .await
                .unwrap();
            seen.extend(page.objects.iter().map(|o| o.key.clone()));
            seen.extend(page.prefixes.iter().cloned());
            if !page.truncated {
                break;
            }
            after = page.next;
        }
        assert_eq!(seen, ["a", "b/", "c", "d/", "e/"], "{layout:?}");

        let under_b = store
            .list(
                "bkt",
                ListQuery {
                    prefix: "b/".into(),
                    delimiter: Some("/".into()),
                    after: None,
                    max_keys: 1000,
                },
            )
            .await
            .unwrap();
        let objects: Vec<_> = under_b.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(
            (objects, under_b.prefixes),
            (vec!["b/1", "b/2"], vec!["b/c/".to_owned()])
        );
    }
}

#[tokio::test]
async fn copies_work_within_and_across_layouts() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_files(dir.path()).unwrap();
    store.create_bucket("folder", Layout::Folder).await.unwrap();
    store
        .create_bucket("objects", Layout::Object)
        .await
        .unwrap();
    store
        .put_bytes("folder", "src.txt", b"payload", attrs("text/plain"))
        .await
        .unwrap();

    for (from, to) in [
        (("folder", "src.txt"), ("objects", "a/copy")),
        (("objects", "a/copy"), ("objects", "b/copy")),
        (("objects", "b/copy"), ("folder", "back.txt")),
    ] {
        let copied = store
            .copy(from, to, None, Precondition::default())
            .await
            .unwrap();
        assert_eq!(
            copied.etag, "321c3cf486ed509164edec1e1981fec8",
            "{from:?} → {to:?}"
        );
        assert_eq!(copied.attrs.content_type.as_deref(), Some("text/plain"));
        let (_, body) = store.read(to.0, to.1).await.unwrap();
        let mut out = Vec::new();
        body.unwrap()
            .all()
            .await
            .unwrap()
            .read_to_end(&mut out)
            .await
            .unwrap();
        assert_eq!(out, b"payload");
    }
    // The folder bucket got a plain file with exactly the bytes: no footer.
    assert_eq!(
        fs::read(dir.path().join("folder/back.txt")).unwrap(),
        b"payload"
    );

    // Onto itself with new metadata.
    let replaced = store
        .copy(
            ("objects", "a/copy"),
            ("objects", "a/copy"),
            Some(attrs("image/png")),
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(replaced.attrs.content_type.as_deref(), Some("image/png"));
    assert!(matches!(
        store
            .copy(
                ("objects", "a/copy"),
                ("objects", "a/copy"),
                None,
                Precondition::default()
            )
            .await,
        Err(StoreError::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn object_buckets_take_keys_folders_cant() {
    let (_dir, store) = bucket(Layout::Object).await;
    for key in [
        "a",
        "a/b",
        "a/../b",
        "//x",
        "/lead",
        "Case",
        "case",
        ".teifs-tmp/x",
        "CON",
        "a\\b",
        "dir/",
    ] {
        store
            .put_bytes("bkt", key, key.as_bytes(), ObjectAttrs::default())
            .await
            .unwrap();
    }
    for key in ["a", "a/b", "a/../b", "Case", "case", "dir/"] {
        assert_eq!(get(&store, key).await, key.as_bytes(), "{key}");
    }
    let (_dir, folder) = bucket(Layout::Folder).await;
    folder
        .put_bytes("bkt", "a", b"", ObjectAttrs::default())
        .await
        .unwrap();
    assert!(
        folder
            .put_bytes("bkt", "a/b", b"", ObjectAttrs::default())
            .await
            .is_err()
    );
    assert!(
        folder
            .put_bytes("bkt", "a/../b", b"", ObjectAttrs::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn replaced_and_deleted_objects_free_their_files() {
    let (dir, store) = bucket(Layout::Object).await;
    let files = || {
        walk(&dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR))
            .into_iter()
            .filter(|p| p.is_file())
            .count()
    };
    store
        .put_bytes("bkt", "k", b"one", ObjectAttrs::default())
        .await
        .unwrap();
    store
        .put_bytes("bkt", "k", b"two", ObjectAttrs::default())
        .await
        .unwrap();
    assert_eq!(files(), 1);
    store.delete("bkt", "k").await.unwrap();
    assert_eq!(files(), 0);
}

#[tokio::test]
async fn object_buckets_survive_reopening() {
    let dir = tempfile::tempdir().unwrap();
    {
        let store = Store::open_files(dir.path()).unwrap();
        store.create_bucket("keep", Layout::Object).await.unwrap();
        store
            .put_bytes("keep", "x/y", b"kept", attrs("text/plain"))
            .await
            .unwrap();
    }
    let store = Store::open_files(dir.path()).unwrap();
    assert_eq!(store.head_bucket("keep").await.unwrap(), Layout::Object);
    let info = store.head("keep", "x/y").await.unwrap();
    assert_eq!(
        (info.size, info.attrs.content_type.as_deref()),
        (4, Some("text/plain"))
    );
}

#[tokio::test]
async fn buckets_of_both_layouts_list_together_and_names_stay_unique() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_files(dir.path()).unwrap();
    store.create_bucket("alpha", Layout::Object).await.unwrap();
    store.create_bucket("beta", Layout::Folder).await.unwrap();
    // A folder with an object bucket's name isn't another bucket.
    fs::create_dir(dir.path().join("alpha")).unwrap();
    let listed: Vec<_> = store
        .list_buckets()
        .await
        .unwrap()
        .into_iter()
        .map(|b| (b.name, b.layout))
        .collect();
    assert_eq!(
        listed,
        [
            ("alpha".to_owned(), Layout::Object),
            ("beta".to_owned(), Layout::Folder)
        ]
    );
    assert!(matches!(
        store.create_bucket("alpha", Layout::Folder).await,
        Err(StoreError::BucketExists)
    ));
    assert!(matches!(
        store.create_bucket("beta", Layout::Object).await,
        Err(StoreError::BucketExists)
    ));

    store
        .put_bytes("alpha", "k", b"x", ObjectAttrs::default())
        .await
        .unwrap();
    assert!(matches!(
        store.delete_bucket("alpha").await,
        Err(StoreError::BucketNotEmpty)
    ));
    store.delete("alpha", "k").await.unwrap();
    store.delete_bucket("alpha").await.unwrap();
    // The folder that had the name is a bucket of its own now.
    assert_eq!(store.head_bucket("alpha").await.unwrap(), Layout::Folder);
}

#[tokio::test]
async fn multipart_uploads_complete_into_object_buckets() {
    let (_dir, store) = bucket(Layout::Object).await;
    let upload = store
        .create_upload(
            "bkt",
            "big/../file",
            attrs("video/mp4"),
            None,
            &Encryption::None,
            None,
            None,
        )
        .await
        .unwrap();
    let listed = store.uploads("bkt", "", None, 10).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, "big/../file");
    let part = vec![7u8; usize::try_from(MIN_PART_SIZE).unwrap()];
    let mut etags = Vec::new();
    for (number, bytes) in [(1, part.as_slice()), (2, b"tail".as_slice())] {
        let mut staged = store.stage().await.unwrap();
        staged.write(bytes).await.unwrap();
        let stored = store
            .put_part(&upload.id, number, staged, BTreeMap::new())
            .await
            .unwrap();
        etags.push((number, stored.etag));
    }
    let info = store
        .complete(
            &upload.id,
            etags,
            Precondition::default(),
            CompleteWith::default(),
        )
        .await
        .unwrap();
    assert!(info.etag.ends_with("-2"));
    assert_eq!(info.size, MIN_PART_SIZE + 4);
    let bytes = get(&store, "big/../file").await;
    assert_eq!(bytes.len() as u64, MIN_PART_SIZE + 4);
    assert_eq!(&bytes[bytes.len() - 4..], b"tail");
}

#[tokio::test]
async fn completed_uploads_remember_their_parts() {
    for layout in LAYOUTS {
        let (dir, store) = bucket(layout).await;
        let upload = store
            .create_upload(
                "bkt",
                "f.bin",
                attrs("x/y"),
                None,
                &Encryption::None,
                None,
                None,
            )
            .await
            .unwrap();
        let first = vec![1u8; usize::try_from(MIN_PART_SIZE).unwrap()];
        let sums: BTreeMap<String, String> = [("CRC32".to_owned(), "abc=".to_owned())].into();
        let mut etags = Vec::new();
        for (number, bytes, checksums) in [
            (1, first.as_slice(), sums.clone()),
            (2, b"end".as_slice(), BTreeMap::new()),
        ] {
            let mut staged = store.stage().await.unwrap();
            staged.write(bytes).await.unwrap();
            let part = store
                .put_part(&upload.id, number, staged, checksums)
                .await
                .unwrap();
            etags.push((number, part.etag));
        }
        let done = store
            .complete(
                &upload.id,
                etags,
                Precondition::default(),
                CompleteWith::default(),
            )
            .await
            .unwrap();
        let expected = vec![
            PartInfo {
                size: MIN_PART_SIZE,
                checksums: sums.clone(),
            },
            PartInfo {
                size: 3,
                checksums: BTreeMap::new(),
            },
        ];
        assert_eq!(done.parts, expected, "{layout:?}");
        assert_eq!(store.head("bkt", "f.bin").await.unwrap().parts, expected);

        // Replacing metadata in place keeps the parts; a fresh put has none.
        let copied = store
            .copy(
                ("bkt", "f.bin"),
                ("bkt", "f.bin"),
                Some(attrs("a/b")),
                Precondition::default(),
            )
            .await
            .unwrap();
        assert_eq!(copied.parts, expected, "{layout:?}");
        // The parts survive closing and reopening the drive.
        drop(store);
        let store = Store::open_files(dir.path()).unwrap();
        assert_eq!(store.head("bkt", "f.bin").await.unwrap().parts, expected);
        let plain = store
            .put_bytes("bkt", "f.bin", b"one piece", ObjectAttrs::default())
            .await
            .unwrap();
        assert!(plain.parts.is_empty());
        assert!(store.head("bkt", "f.bin").await.unwrap().parts.is_empty());
    }
}

#[tokio::test]
async fn a_drive_is_opened_by_one_store_at_a_time() {
    let (dir, store) = bucket(Layout::Object).await;
    // A second open would clear the first one's staged writes: it's refused, untouched.
    let staged = store.inner.tmp.join("in-flight");
    fs::write(&staged, b"half an upload").unwrap();
    assert!(matches!(
        Store::open_files(dir.path()),
        Err(StoreError::DriveInUse)
    ));
    assert!(staged.exists());
    drop(store);
    assert!(Store::open_files(dir.path()).is_ok());
}

#[tokio::test]
async fn tags_change_without_touching_the_object() {
    for layout in LAYOUTS {
        let (_dir, store) = bucket(layout).await;
        let put = store
            .put_bytes("bkt", "t.txt", b"tagged", attrs("text/plain"))
            .await
            .unwrap();
        let tags: BTreeMap<String, String> = [("k".to_owned(), "v".to_owned())].into();
        let tagged = store
            .set_tags("bkt", "t.txt", None, tags.clone())
            .await
            .unwrap();
        let head = store.head("bkt", "t.txt").await.unwrap();
        assert_eq!(head.attrs.tags, tags, "{layout:?}");
        assert_eq!(head.etag, put.etag);
        assert_eq!(head.modified, put.modified);
        assert_eq!(tagged.etag, put.etag);
        assert_eq!(head.attrs.content_type.as_deref(), Some("text/plain"));
        store
            .set_tags("bkt", "t.txt", None, BTreeMap::new())
            .await
            .unwrap();
        assert!(
            store
                .head("bkt", "t.txt")
                .await
                .unwrap()
                .attrs
                .tags
                .is_empty()
        );
        assert!(matches!(
            store.set_tags("bkt", "missing", None, tags).await,
            Err(StoreError::NoSuchKey)
        ));
    }
}

#[tokio::test]
async fn files_changed_outside_can_be_tagged() {
    let (dir, store) = bucket(Layout::Folder).await;
    fs::write(dir.path().join("bkt/by-hand.txt"), b"hello").unwrap();
    let tags: BTreeMap<String, String> = [("k".to_owned(), "v".to_owned())].into();
    store
        .set_tags("bkt", "by-hand.txt", None, tags.clone())
        .await
        .unwrap();
    let head = store.head("bkt", "by-hand.txt").await.unwrap();
    assert_eq!(head.attrs.tags, tags);
    // Its ETag is the real MD5, not a provisional one.
    assert_eq!(head.etag, "5d41402abc4b2a76b9719d911017c592");
}

#[tokio::test]
async fn orphan_files_from_a_crash_are_swept() {
    let dir = tempfile::tempdir().unwrap();
    let data_file;
    {
        let store = Store::open_files(dir.path()).unwrap();
        store.create_bucket("bkt", Layout::Object).await.unwrap();
        store
            .put_bytes("bkt", "k", b"x", ObjectAttrs::default())
            .await
            .unwrap();
        data_file = walk(&dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR))
            .into_iter()
            .find(|p| p.is_file())
            .unwrap();
        // As if the process died after the row went but before the file did.
        let conn = store.inner.lock();
        let bucket_id = store.inner.system().bucket("bkt").unwrap().unwrap().id;
        let removed = conn.delete_null_version(&bucket_id, "k", now_ms()).unwrap();
        assert_eq!(removed.len(), 1);
    }
    assert!(data_file.exists());
    let _store = Store::open_files(dir.path()).unwrap();
    assert!(!data_file.exists());
}

use std::{collections::BTreeMap, path::PathBuf};

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            }
            out.push(path);
        }
    }
    out
}

#[tokio::test]
async fn conditional_writes_and_deletes_follow_aws() {
    for layout in LAYOUTS {
        let (_dir, store) = bucket(layout).await;
        let if_match = |etag: &str| Precondition {
            if_match: Some(if etag == "*" {
                Match::Any
            } else {
                Match::ETag(etag.into())
            }),
            ..Precondition::default()
        };
        let put = |pre: Precondition| {
            let store = store.clone();
            async move {
                let mut staged = store.stage().await.unwrap();
                staged.write(b"v").await.unwrap();
                store
                    .commit("bkt", "k", staged, ObjectAttrs::default(), pre)
                    .await
            }
        };
        // If-Match on a missing object: NoSuchKey, as on AWS (not 412).
        assert!(
            matches!(put(if_match("*")).await, Err(StoreError::NoSuchKey)),
            "{layout:?}"
        );
        let etag = put(Precondition::default()).await.unwrap().etag;
        assert!(matches!(
            put(if_match("nope")).await,
            Err(StoreError::PreconditionFailed)
        ));
        put(if_match(&etag)).await.unwrap();

        // Deletes: a mismatch fails; a match deletes; a missing object always succeeds.
        assert!(matches!(
            store.delete_if("bkt", "k", None, if_match("nope")).await,
            Err(StoreError::PreconditionFailed)
        ));
        let size_mismatch = Precondition {
            if_size: Some(99),
            ..Precondition::default()
        };
        assert!(matches!(
            store.delete_if("bkt", "k", None, size_mismatch).await,
            Err(StoreError::PreconditionFailed)
        ));
        store
            .delete_if("bkt", "k", None, if_match(&etag))
            .await
            .unwrap();
        assert!(store.head("bkt", "k").await.is_err());
        store
            .delete_if("bkt", "k", None, if_match("nope"))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn renames_keep_the_object_and_honour_conditions() {
    for layout in LAYOUTS {
        let (_dir, store) = bucket(layout).await;
        let info = store
            .put_bytes("bkt", "a/one.txt", b"payload", attrs("text/plain"))
            .await
            .unwrap();
        store
            .rename(
                "bkt",
                "a/one.txt",
                "b/two.txt",
                Precondition::default(),
                Precondition::default(),
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            store.head("bkt", "a/one.txt").await,
            Err(StoreError::NoSuchKey)
        ));
        let moved = store.head("bkt", "b/two.txt").await.unwrap();
        assert_eq!(
            (moved.etag.as_str(), moved.attrs.content_type.as_deref()),
            (info.etag.as_str(), Some("text/plain")),
            "{layout:?}"
        );
        assert_eq!(get(&store, "b/two.txt").await, b"payload");

        // Not over an existing object when the destination must not exist.
        store
            .put_bytes("bkt", "c", b"other", ObjectAttrs::default())
            .await
            .unwrap();
        let only_new = Precondition {
            if_none_match: Some(Match::Any),
            ..Precondition::default()
        };
        assert!(matches!(
            store
                .rename(
                    "bkt",
                    "b/two.txt",
                    "c",
                    Precondition::default(),
                    only_new,
                    None
                )
                .await,
            Err(StoreError::PreconditionFailed)
        ));
        // …and when it doesn't exist, the rename goes ahead.
        let only_new = Precondition {
            if_none_match: Some(Match::Any),
            ..Precondition::default()
        };
        store
            .rename("bkt", "c", "fresh", Precondition::default(), only_new, None)
            .await
            .unwrap();
        store
            .rename(
                "bkt",
                "fresh",
                "c",
                Precondition::default(),
                Precondition::default(),
                None,
            )
            .await
            .unwrap();
        // A source that doesn't match.
        let wrong = Precondition {
            if_match: Some(Match::ETag("nope".into())),
            ..Precondition::default()
        };
        assert!(matches!(
            store
                .rename(
                    "bkt",
                    "b/two.txt",
                    "d",
                    wrong,
                    Precondition::default(),
                    None
                )
                .await,
            Err(StoreError::PreconditionFailed)
        ));
        // Over an existing object by default; retried with the same token, nothing more.
        let token = Some("retry-1".to_owned());
        store
            .rename(
                "bkt",
                "b/two.txt",
                "c",
                Precondition::default(),
                Precondition::default(),
                token.clone(),
            )
            .await
            .unwrap();
        store
            .rename(
                "bkt",
                "b/two.txt",
                "c",
                Precondition::default(),
                Precondition::default(),
                token.clone(),
            )
            .await
            .unwrap();
        assert_eq!(get(&store, "c").await, b"payload");
        assert!(matches!(
            store
                .rename(
                    "bkt",
                    "c",
                    "e",
                    Precondition::default(),
                    Precondition::default(),
                    token
                )
                .await,
            Err(StoreError::IdempotencyMismatch)
        ));
        assert!(matches!(
            store
                .rename(
                    "bkt",
                    "missing",
                    "f",
                    Precondition::default(),
                    Precondition::default(),
                    None
                )
                .await,
            Err(StoreError::NoSuchKey)
        ));
    }
}
