use std::{collections::BTreeMap, fs, path::Path};

use tempfile::TempDir;

use super::*;

fn drive() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    (dir, store)
}

async fn with_bucket() -> (TempDir, Store) {
    let (dir, store) = drive();
    store.create_bucket("photos", Layout::Folder).await.unwrap();
    (dir, store)
}

async fn read_all(store: &Store, bucket: &str, key: &str) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let (_, body) = store.read(bucket, key).await.unwrap();
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

fn keys(listing: &Listing) -> Vec<&str> {
    listing.objects.iter().map(|o| o.key.as_str()).collect()
}

#[tokio::test]
async fn objects_are_plain_files() {
    let (dir, store) = with_bucket().await;
    let info = store
        .put_bytes(
            "photos",
            "2026/trip/a.txt",
            b"hello",
            ObjectAttrs::default(),
        )
        .await
        .unwrap();
    assert_eq!(info.etag, "5d41402abc4b2a76b9719d911017c592");
    assert_eq!(info.size, 5);
    assert_eq!(
        fs::read(dir.path().join("photos/2026/trip/a.txt")).unwrap(),
        b"hello"
    );
    assert_eq!(
        read_all(&store, "photos", "2026/trip/a.txt").await,
        b"hello"
    );
    // Nothing of TeiFS's lands in the bucket.
    assert!(
        fs::read_dir(dir.path().join(SYSTEM_DIR).join("tmp"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn attributes_are_kept_beside_the_file() {
    let (_dir, store) = with_bucket().await;
    let attrs = ObjectAttrs {
        content_type: Some("text/markdown".into()),
        user: [("owner".to_owned(), "krishna".to_owned())].into(),
        ..ObjectAttrs::default()
    };
    store
        .put_bytes("photos", "notes.md", b"# hi", attrs.clone())
        .await
        .unwrap();
    let info = store.head("photos", "notes.md").await.unwrap();
    assert_eq!(info.attrs, attrs);
    assert_eq!(info.content_type(), "text/markdown");
}

#[tokio::test]
async fn files_changed_outside_get_a_provisional_etag_and_lose_stale_attributes() {
    let (dir, store) = with_bucket().await;
    let attrs = ObjectAttrs {
        content_type: Some("text/x-custom".into()),
        ..ObjectAttrs::default()
    };
    store
        .put_bytes("photos", "a.txt", b"one", attrs)
        .await
        .unwrap();

    // Another program rewrites the file.
    std::thread::sleep(std::time::Duration::from_millis(5));
    fs::write(dir.path().join("photos/a.txt"), b"three").unwrap();
    let info = store.head("photos", "a.txt").await.unwrap();
    assert!(info.etag.ends_with("-1"), "{}", info.etag);
    assert_eq!(info.size, 5);
    assert_eq!(info.attrs, ObjectAttrs::default());
    assert_eq!(info.content_type(), "text/plain");
    // Stable while the file doesn't change.
    assert_eq!(store.head("photos", "a.txt").await.unwrap().etag, info.etag);

    // A file dropped in by hand is an object too.
    fs::write(dir.path().join("photos/b.bin"), b"x").unwrap();
    let listing = store
        .list(
            "photos",
            ListQuery {
                max_keys: 100,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(keys(&listing), ["a.txt", "b.bin"]);
}

#[tokio::test]
async fn listing_follows_s3_byte_order() {
    let (_dir, store) = with_bucket().await;
    // '-' (0x2d) < '.' (0x2e) < '/' (0x2f) < '0' (0x30): a naive folder walk gets this wrong.
    for key in ["a/b", "a-b", "a.b", "a0", "a/c/d", "b"] {
        store
            .put_bytes("photos", key, b"", ObjectAttrs::default())
            .await
            .unwrap();
    }
    let all = store
        .list(
            "photos",
            ListQuery {
                max_keys: 100,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(keys(&all), ["a-b", "a.b", "a/b", "a/c/d", "a0", "b"]);
    assert!(!all.truncated);

    let rolled = store
        .list(
            "photos",
            ListQuery {
                delimiter: Some("/".into()),
                max_keys: 100,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(keys(&rolled), ["a-b", "a.b", "a0", "b"]);
    assert_eq!(rolled.prefixes, ["a/"]);

    let under = store
        .list(
            "photos",
            ListQuery {
                prefix: "a/".into(),
                delimiter: Some("/".into()),
                max_keys: 100,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(keys(&under), ["a/b"]);
    assert_eq!(under.prefixes, ["a/c/"]);

    let partial = store
        .list(
            "photos",
            ListQuery {
                prefix: "a".into(),
                max_keys: 100,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(keys(&partial), ["a-b", "a.b", "a/b", "a/c/d", "a0"]);
}

/// Folders of every size, next to loose keys, rolled up page by page in an object bucket
/// (whose listings read rows in batches that shrink after each folder and grow again),
/// list exactly what the keys say, objects and versions alike.
#[tokio::test]
async fn folders_of_every_size_roll_up_page_by_page() {
    let (_dir, store) = drive();
    store.create_bucket("many", Layout::Object).await.unwrap();
    let mut keys = Vec::new();
    for folder in 0..12 {
        // Empty folders aren't keys; others hold 1 to 400 keys.
        let len = [0, 1, 2, 7, 8, 9, 31, 33, 130, 400, 3, 1][folder];
        for i in 0..len {
            keys.push(format!("f{folder:02}/{i:04}"));
        }
        keys.push(format!("loose{folder:02}"));
    }
    for key in &keys {
        store
            .put_bytes("many", key, b"", ObjectAttrs::default())
            .await
            .unwrap();
    }
    let mut expected: Vec<String> = keys
        .iter()
        .map(|k| match k.find('/') {
            Some(at) => k[..=at].to_owned(),
            None => k.clone(),
        })
        .collect();
    expected.sort();
    expected.dedup();
    for max_keys in [1, 2, 5, 9, 1000] {
        let (mut seen, mut after) = (Vec::new(), None);
        loop {
            let page = store
                .list(
                    "many",
                    ListQuery {
                        delimiter: Some("/".into()),
                        after: after.clone(),
                        max_keys,
                        ..ListQuery::default()
                    },
                )
                .await
                .unwrap();
            assert!(page.objects.len() + page.prefixes.len() <= max_keys);
            seen.extend(page.objects.iter().map(|o| o.key.clone()));
            seen.extend(page.prefixes.iter().cloned());
            if !page.truncated {
                break;
            }
            after = page.next;
        }
        seen.sort();
        assert_eq!(seen, expected, "max_keys {max_keys}");

        let (mut seen, mut marker) = (Vec::new(), None);
        loop {
            let page = store
                .list_versions(
                    "many",
                    VersionsQuery {
                        delimiter: Some("/".into()),
                        key_marker: marker.clone(),
                        max_keys,
                        ..VersionsQuery::default()
                    },
                )
                .await
                .unwrap();
            seen.extend(page.versions.iter().map(|v| v.info.key.clone()));
            seen.extend(page.prefixes.iter().cloned());
            if !page.truncated {
                break;
            }
            marker = page.next.map(|(key, _)| key);
        }
        seen.sort();
        assert_eq!(seen, expected, "versions, max_keys {max_keys}");
    }
}

#[tokio::test]
async fn pages_resume_after_keys_and_common_prefixes() {
    let (_dir, store) = with_bucket().await;
    for key in ["a", "b/1", "b/2", "c", "d/1", "e"] {
        store
            .put_bytes("photos", key, b"", ObjectAttrs::default())
            .await
            .unwrap();
    }
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = store
            .list(
                "photos",
                ListQuery {
                    delimiter: Some("/".into()),
                    after: after.clone(),
                    max_keys: 2,
                    ..ListQuery::default()
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
    seen.sort();
    assert_eq!(seen, ["a", "b/", "c", "d/", "e"]);

    // A plain start-after key.
    let rest = store
        .list(
            "photos",
            ListQuery {
                after: Some(After::Key("b/1".into())),
                max_keys: 100,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(keys(&rest), ["b/2", "c", "d/1", "e"]);
}

#[tokio::test]
async fn folders_created_on_purpose_stay_and_implicit_ones_go() {
    let (dir, store) = with_bucket().await;
    store
        .put_bytes("photos", "albums/", b"", ObjectAttrs::default())
        .await
        .unwrap();
    store
        .put_bytes("photos", "albums/2026/a.jpg", b"x", ObjectAttrs::default())
        .await
        .unwrap();
    store.delete("photos", "albums/2026/a.jpg").await.unwrap();
    // `2026` was only there for the file; `albums` was created as a folder.
    assert!(!dir.path().join("photos/albums/2026").exists());
    assert!(dir.path().join("photos/albums").is_dir());
    let listing = store
        .list(
            "photos",
            ListQuery {
                max_keys: 100,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(keys(&listing), ["albums/"]);
    assert_eq!(listing.objects[0].etag, "d41d8cd98f00b204e9800998ecf8427e");

    store.delete("photos", "albums/").await.unwrap();
    assert!(!dir.path().join("photos/albums").exists());
    // Deleting what isn't there succeeds.
    store.delete("photos", "nothing/here").await.unwrap();
}

#[tokio::test]
async fn keys_that_collide_on_disk_are_refused() {
    let (_dir, store) = with_bucket().await;
    store
        .put_bytes("photos", "a", b"file", ObjectAttrs::default())
        .await
        .unwrap();
    assert!(matches!(
        store
            .put_bytes("photos", "a/b", b"x", ObjectAttrs::default())
            .await,
        Err(StoreError::KeyConflict(_))
    ));
    store
        .put_bytes("photos", "dir/x", b"x", ObjectAttrs::default())
        .await
        .unwrap();
    assert!(matches!(
        store
            .put_bytes("photos", "dir", b"x", ObjectAttrs::default())
            .await,
        Err(StoreError::KeyConflict(_))
    ));
    assert!(matches!(
        store
            .put_bytes("photos", "../escape", b"x", ObjectAttrs::default())
            .await,
        Err(StoreError::InvalidName(NameError::InvalidKey(_)))
    ));
}

#[tokio::test]
async fn letter_case_is_kept_apart_or_refused() {
    let (dir, store) = with_bucket().await;
    store
        .put_bytes("photos", "Readme.md", b"x", ObjectAttrs::default())
        .await
        .unwrap();
    let insensitive = dir.path().join("photos/README.MD").exists();
    let other = store
        .put_bytes("photos", "README.md", b"y", ObjectAttrs::default())
        .await;
    if insensitive {
        // One file can't hold both keys: refused, and the first is untouched.
        assert!(matches!(other, Err(StoreError::KeyConflict(_))));
        assert!(matches!(
            store.head("photos", "README.md").await,
            Err(StoreError::NoSuchKey)
        ));
    } else {
        other.unwrap();
    }
    assert_eq!(read_all(&store, "photos", "Readme.md").await, b"x");
}

#[cfg(unix)]
#[tokio::test]
async fn links_never_lead_out_of_a_bucket() {
    let (dir, store) = with_bucket().await;
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"s").unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("photos/link")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret"),
        dir.path().join("photos/file-link"),
    )
    .unwrap();
    assert!(matches!(
        store.head("photos", "link/secret").await,
        Err(StoreError::NoSuchKey)
    ));
    assert!(matches!(
        store.head("photos", "file-link").await,
        Err(StoreError::NoSuchKey)
    ));
    assert!(matches!(
        store
            .put_bytes("photos", "link/new", b"x", ObjectAttrs::default())
            .await,
        Err(StoreError::KeyConflict(_))
    ));
    assert!(!outside.path().join("new").exists());
    let listing = store
        .list(
            "photos",
            ListQuery {
                max_keys: 100,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert!(listing.objects.is_empty() && listing.prefixes.is_empty());
}

#[tokio::test]
async fn preconditions_guard_writes() {
    let (_dir, store) = with_bucket().await;
    let create_only = Precondition {
        if_none_match: Some(Match::Any),
        ..Precondition::default()
    };
    let mut staged = store.stage();
    staged.write(b"1").await.unwrap();
    let first = store
        .commit(
            "photos",
            "k",
            staged,
            ObjectAttrs::default(),
            create_only.clone(),
        )
        .await
        .unwrap();

    let staged = store.stage();
    assert!(matches!(
        store
            .commit("photos", "k", staged, ObjectAttrs::default(), create_only)
            .await,
        Err(StoreError::PreconditionFailed)
    ));
    let wrong = Precondition {
        if_match: Some(Match::ETag("\"nope\"".into())),
        ..Precondition::default()
    };
    let staged = store.stage();
    assert!(matches!(
        store
            .commit("photos", "k", staged, ObjectAttrs::default(), wrong)
            .await,
        Err(StoreError::PreconditionFailed)
    ));
    let right = Precondition {
        if_match: Some(Match::ETag(format!("\"{}\"", first.etag))),
        ..Precondition::default()
    };
    let mut staged = store.stage();
    staged.write(b"2").await.unwrap();
    store
        .commit("photos", "k", staged, ObjectAttrs::default(), right)
        .await
        .unwrap();
    assert_eq!(read_all(&store, "photos", "k").await, b"2");
}

#[tokio::test]
async fn failed_uploads_leave_nothing_behind() {
    let (dir, store) = with_bucket().await;
    let mut staged = store.stage();
    staged.write(b"partial").await.unwrap();
    drop(staged);
    assert!(
        fs::read_dir(dir.path().join(SYSTEM_DIR).join("tmp"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        fs::read_dir(dir.path().join("photos"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn copies_keep_or_replace_attributes() {
    let (_dir, store) = with_bucket().await;
    let attrs = ObjectAttrs {
        content_type: Some("text/x-a".into()),
        ..ObjectAttrs::default()
    };
    let source = store
        .put_bytes("photos", "a", b"data", attrs.clone())
        .await
        .unwrap();
    store.create_bucket("backup", Layout::Folder).await.unwrap();

    let copy = store
        .copy(
            ("photos", "a"),
            ("backup", "x/a"),
            None,
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(copy.etag, source.etag);
    assert_eq!(copy.attrs, attrs);
    assert_eq!(read_all(&store, "backup", "x/a").await, b"data");

    assert!(matches!(
        store
            .copy(
                ("photos", "a"),
                ("photos", "a"),
                None,
                Precondition::default()
            )
            .await,
        Err(StoreError::InvalidRequest(_))
    ));
    let replaced = ObjectAttrs {
        content_type: Some("text/x-b".into()),
        ..ObjectAttrs::default()
    };
    let same = store
        .copy(
            ("photos", "a"),
            ("photos", "a"),
            Some(replaced.clone()),
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(same.attrs, replaced);
    assert_eq!(same.etag, source.etag);
}

#[tokio::test]
async fn multipart_uploads_join_parts_with_s3s_etag() {
    let (dir, store) = with_bucket().await;
    let upload = store
        .create_upload(
            "photos",
            "big.bin",
            ObjectAttrs::default(),
            Some("key1".into()),
            &Encryption::None,
            None,
            None,
        )
        .await
        .unwrap();
    let first = vec![1u8; usize::try_from(MIN_PART_SIZE).unwrap()];
    let mut etags = Vec::new();
    for (number, bytes) in [(1, first.as_slice()), (2, b"tail".as_slice())] {
        let mut staged = store.stage();
        staged.write(bytes).await.unwrap();
        etags.push((
            number,
            store
                .put_part(&upload.id, number, staged, BTreeMap::new())
                .await
                .unwrap()
                .etag,
        ));
    }
    assert_eq!(
        store.parts(&upload.id, 0, 100, None).await.unwrap().len(),
        2
    );
    assert_eq!(
        store.uploads("photos", "", None, 100).await.unwrap().len(),
        1
    );

    let info = store
        .complete(
            &upload.id,
            etags.clone(),
            Precondition::default(),
            CompleteWith::default(),
        )
        .await
        .unwrap();
    let md5s: Vec<[u8; 16]> = etags
        .iter()
        .map(|(_, e)| teifs_types::md5_of_etag(e).unwrap())
        .collect();
    assert_eq!(info.etag, teifs_types::multipart_etag(&md5s));
    assert_eq!(info.size, MIN_PART_SIZE + 4);
    assert_eq!(
        fs::metadata(dir.path().join("photos/big.bin"))
            .unwrap()
            .len(),
        MIN_PART_SIZE + 4
    );
    assert!(matches!(
        store.upload(&upload.id).await,
        Err(StoreError::NoSuchUpload)
    ));
    assert!(
        !dir.path()
            .join(SYSTEM_DIR)
            .join("uploads")
            .join(&upload.id)
            .exists()
    );
}

#[tokio::test]
async fn a_capped_upload_stores_parts_only_up_to_its_total() {
    let (_dir, store) = with_bucket().await;
    let upload = store
        .create_upload(
            "photos",
            "capped",
            ObjectAttrs::default(),
            None,
            &Encryption::None,
            None,
            Some(10),
        )
        .await
        .unwrap();
    let put = |number: u32, bytes: &'static [u8]| {
        let store = &store;
        let id = upload.id.clone();
        async move {
            let mut staged = store.stage();
            staged.write(bytes).await.unwrap();
            store.put_part(&id, number, staged, BTreeMap::new()).await
        }
    };
    put(1, b"123456").await.unwrap();
    assert_eq!(store.part_room(&upload, 2).await.unwrap(), Some(4));
    assert!(matches!(
        put(2, b"12345").await,
        Err(StoreError::EntityTooLarge)
    ));
    // A replaced part leaves room for what it was.
    assert_eq!(store.part_room(&upload, 1).await.unwrap(), Some(10));
    put(1, b"1234").await.unwrap();
    put(2, b"123456").await.unwrap();
    assert_eq!(store.part_room(&upload, 3).await.unwrap(), Some(0));
    assert!(matches!(
        put(3, b"1").await,
        Err(StoreError::EntityTooLarge)
    ));
    let parts = store.parts(&upload.id, 0, 100, None).await.unwrap();
    let sizes: Vec<u64> = parts.iter().map(|p| p.size).collect();
    assert_eq!(sizes, [4, 6], "refused parts leave the upload as it was");
    let uncapped = store
        .create_upload(
            "photos",
            "open",
            ObjectAttrs::default(),
            None,
            &Encryption::None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(store.part_room(&uncapped, 1).await.unwrap(), None);
}

#[tokio::test]
async fn multipart_rules_are_enforced() {
    let (_dir, store) = with_bucket().await;
    let upload = store
        .create_upload(
            "photos",
            "k",
            ObjectAttrs::default(),
            None,
            &Encryption::None,
            None,
            None,
        )
        .await
        .unwrap();
    let mut etags = Vec::new();
    for number in [1, 2] {
        let mut staged = store.stage();
        staged.write(b"small").await.unwrap();
        etags.push((
            number,
            store
                .put_part(&upload.id, number, staged, BTreeMap::new())
                .await
                .unwrap()
                .etag,
        ));
    }
    assert!(matches!(
        store
            .complete(
                &upload.id,
                etags.clone(),
                Precondition::default(),
                CompleteWith::default()
            )
            .await,
        Err(StoreError::EntityTooSmall)
    ));
    let reversed = vec![etags[1].clone(), etags[0].clone()];
    assert!(matches!(
        store
            .complete(
                &upload.id,
                reversed,
                Precondition::default(),
                CompleteWith::default()
            )
            .await,
        Err(StoreError::InvalidPartOrder)
    ));
    assert!(matches!(
        store
            .complete(
                &upload.id,
                vec![(1, "\"bad\"".into())],
                Precondition::default(),
                CompleteWith::default()
            )
            .await,
        Err(StoreError::InvalidPart)
    ));
    // Parts need not be numbered without gaps; one small last part is fine.
    store
        .complete(
            &upload.id,
            vec![etags[1].clone()],
            Precondition::default(),
            CompleteWith::default(),
        )
        .await
        .unwrap();

    let other = store
        .create_upload(
            "photos",
            "k2",
            ObjectAttrs::default(),
            None,
            &Encryption::None,
            None,
            None,
        )
        .await
        .unwrap();
    store.abort(&other.id).await.unwrap();
    assert!(matches!(
        store.abort(&other.id).await,
        Err(StoreError::NoSuchUpload)
    ));
}

#[tokio::test]
async fn buckets_are_folders() {
    let (dir, store) = drive();
    store.create_bucket("alpha", Layout::Folder).await.unwrap();
    store.create_bucket("beta", Layout::Folder).await.unwrap();
    fs::create_dir(dir.path().join("Not_A_Bucket")).unwrap();
    let names: Vec<_> = store
        .list_buckets()
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, ["alpha", "beta"]);
    assert!(matches!(
        store.create_bucket("alpha", Layout::Folder).await,
        Err(StoreError::BucketExists)
    ));
    assert!(matches!(
        store.create_bucket("Bad_Name", Layout::Folder).await,
        Err(StoreError::InvalidName(NameError::InvalidBucketName(_)))
    ));

    store
        .put_bytes("alpha", "x", b"1", ObjectAttrs::default())
        .await
        .unwrap();
    assert!(matches!(
        store.delete_bucket("alpha").await,
        Err(StoreError::BucketNotEmpty)
    ));
    store.delete("alpha", "x").await.unwrap();
    store.delete_bucket("alpha").await.unwrap();
    assert!(matches!(
        store.head_bucket("alpha").await,
        Err(StoreError::NoSuchBucket)
    ));
    assert!(!Path::new(&dir.path().join("alpha")).exists());
}

#[tokio::test]
async fn reopening_keeps_metadata_and_clears_leftovers() {
    let (dir, store) = with_bucket().await;
    let attrs = ObjectAttrs {
        cache_control: Some("no-store".into()),
        ..ObjectAttrs::default()
    };
    store
        .put_bytes("photos", "a", b"1", attrs.clone())
        .await
        .unwrap();
    let staged = store.stage();
    std::mem::forget(staged); // As if the process died mid-upload.
    drop(store);

    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.head("photos", "a").await.unwrap().attrs, attrs);
    assert!(
        fs::read_dir(dir.path().join(SYSTEM_DIR).join("tmp"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn copies_keep_checksums_of_the_bytes_but_not_of_parts() {
    let sums: BTreeMap<String, String> = [("SHA256".to_owned(), "abc=".to_owned())].into();
    let full = ObjectAttrs {
        checksums: sums.clone(),
        ..ObjectAttrs::default()
    };
    let composite = ObjectAttrs {
        checksums: [("SHA256".to_owned(), "abc=-3".to_owned())].into(),
        checksum_type: Some(teifs_types::ChecksumType::Composite),
        ..ObjectAttrs::default()
    };
    let replacement = ObjectAttrs {
        content_type: Some("text/plain".into()),
        ..ObjectAttrs::default()
    };
    // A copy shares the source's bytes: a full-object checksum still describes them.
    assert_eq!(copied_attrs(full.clone(), None).checksums, sums);
    let replaced = copied_attrs(full.clone(), Some(replacement.clone()));
    assert_eq!(replaced.checksums, sums);
    assert_eq!(replaced.content_type.as_deref(), Some("text/plain"));
    // It has no parts, so a composite checksum doesn't carry over.
    let copied = copied_attrs(composite.clone(), None);
    assert!(copied.checksums.is_empty() && copied.checksum_type.is_none());
    // Replacing metadata in place keeps the bytes and the parts, so every checksum.
    let in_place = replaced_attrs(&composite, replacement);
    assert_eq!(in_place.checksums, composite.checksums);
    assert_eq!(in_place.checksum_type, composite.checksum_type);
    assert_eq!(in_place.content_type.as_deref(), Some("text/plain"));
}

#[tokio::test]
async fn bucket_tags_are_kept_in_its_settings() {
    let (dir, store) = drive();
    // A folder made by hand is a bucket too, and can be tagged.
    fs::create_dir(dir.path().join("by-hand")).unwrap();
    assert_eq!(store.bucket_tags("by-hand").await.unwrap(), None);
    let tags: BTreeMap<String, String> = [("team".to_owned(), "a".to_owned())].into();
    store
        .set_bucket_tags("by-hand", Some(tags.clone()))
        .await
        .unwrap();
    assert_eq!(store.bucket_tags("by-hand").await.unwrap(), Some(tags));
    store.set_bucket_tags("by-hand", None).await.unwrap();
    assert_eq!(store.bucket_tags("by-hand").await.unwrap(), None);
    assert!(matches!(
        store.bucket_tags("nope").await,
        Err(StoreError::NoSuchBucket)
    ));
}

#[tokio::test]
async fn abac_buckets_change_tags_only_one_by_one() {
    let (_dir, store) = drive();
    let tags = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    };
    let options = NewBucket {
        tags: Some(tags(&[("team", "a")])),
        ..NewBucket::default()
    };
    for (name, layout) in [("objects", Layout::Object), ("folder", Layout::Folder)] {
        store
            .create_bucket_with(name, layout, options.clone())
            .await
            .unwrap();
        assert_eq!(
            store.bucket_tags(name).await.unwrap(),
            Some(tags(&[("team", "a")]))
        );
        // Off, the tags decide nothing, and are replaced as a whole.
        assert!(!store.bucket_abac(name).await.unwrap());
        assert_eq!(store.bucket_access(name).await.unwrap().abac_tags, None);
        store
            .set_bucket_tags(name, Some(tags(&[("team", "b")])))
            .await
            .unwrap();

        store.set_bucket_abac(name, true).await.unwrap();
        assert!(store.bucket_abac(name).await.unwrap());
        assert_eq!(
            store.bucket_access(name).await.unwrap().abac_tags,
            Some(tags(&[("team", "b")]))
        );
        for replace in [Some(tags(&[("team", "c")])), None] {
            assert!(matches!(
                store.set_bucket_tags(name, replace).await,
                Err(StoreError::InvalidRequest(_))
            ));
        }
        // One by one: added, replaced, removed, within the limit.
        store
            .tag_bucket(name, tags(&[("team", "c"), ("env", "prod")]), 2)
            .await
            .unwrap();
        assert!(matches!(
            store.tag_bucket(name, tags(&[("cost", "x")]), 2).await,
            Err(StoreError::TooManyTags(2))
        ));
        assert_eq!(
            store.bucket_tags(name).await.unwrap(),
            Some(tags(&[("env", "prod"), ("team", "c")]))
        );
        store
            .untag_bucket(name, vec!["team".into(), "missing".into()])
            .await
            .unwrap();
        assert_eq!(
            store.bucket_access(name).await.unwrap().abac_tags,
            Some(tags(&[("env", "prod")]))
        );
        store.untag_bucket(name, vec!["env".into()]).await.unwrap();
        assert_eq!(store.bucket_tags(name).await.unwrap(), None);
        // With no tags, ABAC still decides: with none.
        assert_eq!(
            store.bucket_access(name).await.unwrap().abac_tags,
            Some(BTreeMap::new())
        );
        store.set_bucket_abac(name, false).await.unwrap();
        store.set_bucket_tags(name, None).await.unwrap();
    }
    assert!(matches!(
        store.set_bucket_abac("nope", true).await,
        Err(StoreError::NoSuchBucket)
    ));
}

#[tokio::test]
async fn new_buckets_block_public_access() {
    let (dir, store) = drive();
    let blocked = BucketAccess {
        public_access_block: Some(PublicAccessBlock::ALL),
        ownership: Some(ObjectOwnership::BucketOwnerEnforced),
        ..BucketAccess::default()
    };
    for (name, layout) in [("objects", Layout::Object), ("folder", Layout::Folder)] {
        store.create_bucket(name, layout).await.unwrap();
        assert_eq!(store.bucket_access(name).await.unwrap(), blocked);
    }
    // A folder made by hand is as new, before and after its settings are first written.
    fs::create_dir(dir.path().join("by-hand")).unwrap();
    assert_eq!(store.bucket_access("by-hand").await.unwrap(), blocked);
    let policy = r#"{"Statement":[]}"#.to_owned();
    store
        .set_bucket_policy("by-hand", Some(policy.clone()))
        .await
        .unwrap();
    let access = store.bucket_access("by-hand").await.unwrap();
    assert_eq!(access.policy, Some(policy));
    assert_eq!(access.public_access_block, Some(PublicAccessBlock::ALL));

    let open = PublicAccessBlock {
        block_public_policy: true,
        ..PublicAccessBlock::default()
    };
    store
        .set_bucket_public_access_block("by-hand", Some(open))
        .await
        .unwrap();
    store.set_bucket_policy("by-hand", None).await.unwrap();
    assert_eq!(
        store.bucket_access("by-hand").await.unwrap(),
        BucketAccess {
            public_access_block: Some(open),
            ownership: Some(ObjectOwnership::BucketOwnerEnforced),
            ..BucketAccess::default()
        }
    );
    store
        .set_bucket_public_access_block("by-hand", None)
        .await
        .unwrap();
    store.set_bucket_ownership("by-hand", None).await.unwrap();
    assert_eq!(
        store.bucket_access("by-hand").await.unwrap(),
        BucketAccess::default()
    );
    for result in [
        store.bucket_access("nope").await.map(drop),
        store.set_bucket_policy("nope", None).await,
        store.set_bucket_public_access_block("nope", None).await,
    ] {
        assert!(matches!(result, Err(StoreError::NoSuchBucket)));
    }
}

#[tokio::test]
async fn ownership_and_acls_are_kept() {
    let (dir, store) = drive();
    let public = Acl {
        grants: vec![AclGrant {
            grantee: Grantee::AllUsers,
            permission: Permission::Read,
        }],
    };
    let options = NewBucket {
        ownership: Some(ObjectOwnership::ObjectWriter),
        acl: Some(public.clone()),
        ..NewBucket::default()
    };
    for (name, layout) in [("objects", Layout::Object), ("folder", Layout::Folder)] {
        store
            .create_bucket_with(name, layout, options.clone())
            .await
            .unwrap();
        let access = store.bucket_access(name).await.unwrap();
        assert_eq!(access.ownership, Some(ObjectOwnership::ObjectWriter));
        assert_eq!(access.acl.as_ref(), Some(&public));
        store.set_bucket_acl(name, None).await.unwrap();
        store
            .set_bucket_ownership(name, Some(ObjectOwnership::BucketOwnerPreferred))
            .await
            .unwrap();
        let access = store.bucket_access(name).await.unwrap();
        assert_eq!(
            (access.ownership, access.acl),
            (Some(ObjectOwnership::BucketOwnerPreferred), None)
        );

        // An object's ACL changes nothing else about it.
        store
            .put_bytes(name, "a.txt", b"hello", ObjectAttrs::default())
            .await
            .unwrap();
        let before = store.head(name, "a.txt").await.unwrap();
        let after = store
            .set_acl(name, "a.txt", None, Some(public.clone()))
            .await
            .unwrap();
        assert_eq!(after.attrs.acl.as_ref(), Some(&public));
        assert_eq!((after.etag, after.modified), (before.etag, before.modified));
        assert_eq!(
            store.head(name, "a.txt").await.unwrap().attrs.acl,
            Some(public.clone())
        );
        assert!(matches!(
            store.set_acl(name, "missing", None, None).await,
            Err(StoreError::NoSuchKey)
        ));
    }
    // A file replaced outside TeiFS loses the old file's ACL: it's private again.
    fs::write(dir.path().join("folder/a.txt"), b"changed outside").unwrap();
    assert_eq!(store.head("folder", "a.txt").await.unwrap().attrs.acl, None);
    assert_eq!(
        ObjectOwnership::parse("ObjectWriter"),
        Some(ObjectOwnership::ObjectWriter)
    );
    assert_eq!(ObjectOwnership::parse("objectwriter"), None);
    assert!(!ObjectOwnership::default().acls_enabled());
}

#[tokio::test]
async fn ownership_and_bucket_acls_guard_each_other() {
    let (_dir, store) = drive();
    let public = Acl {
        grants: vec![AclGrant {
            grantee: Grantee::AllUsers,
            permission: Permission::Read,
        }],
    };
    store
        .create_bucket("enforced", Layout::Object)
        .await
        .unwrap();
    assert!(matches!(
        store.set_bucket_acl("enforced", Some(Acl::private())).await,
        Err(StoreError::AclsDisabled)
    ));
    // S3's defaults before April 2023: no ownership setting (ACLs on), no Block Public
    // Access.
    let options = NewBucket {
        ownership: None,
        block_public_access: false,
        acl: Some(public),
        tags: None,
        object_lock: false,
    };
    store
        .create_bucket_with("writer", Layout::Folder, options)
        .await
        .unwrap();
    let enforce = Some(ObjectOwnership::BucketOwnerEnforced);
    assert!(matches!(
        store.set_bucket_ownership("writer", enforce).await,
        Err(StoreError::AclGrantsOthers)
    ));
    // Refused changes change nothing; another setting that keeps ACLs is fine.
    let access = store.bucket_access("writer").await.unwrap();
    assert_eq!((access.ownership, access.public_access_block), (None, None));
    let writer = Some(ObjectOwnership::ObjectWriter);
    store.set_bucket_ownership("writer", writer).await.unwrap();
    store
        .set_bucket_acl("writer", Some(Acl::private()))
        .await
        .unwrap();
    store.set_bucket_ownership("writer", enforce).await.unwrap();
    assert!(matches!(
        store.set_bucket_acl("missing", None).await,
        Err(StoreError::NoSuchBucket)
    ));
}

#[tokio::test]
async fn the_account_block_public_access_applies_with_every_bucket() {
    let (dir, store) = drive();
    assert_eq!(store.account_public_access_block().await.unwrap(), None);
    store
        .create_bucket("objects", Layout::Object)
        .await
        .unwrap();
    let access = store.bucket_access("objects").await.unwrap();
    assert_eq!(access.account_public_access_block, None);
    let policy_only = PublicAccessBlock {
        block_public_policy: true,
        ..PublicAccessBlock::default()
    };
    store
        .set_account_public_access_block(Some(policy_only))
        .await
        .unwrap();
    // A folder made by hand sees it too, and it survives a restart.
    fs::create_dir(dir.path().join("by-hand")).unwrap();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    for bucket in ["objects", "by-hand"] {
        let access = store.bucket_access(bucket).await.unwrap();
        assert_eq!(access.account_public_access_block, Some(policy_only));
    }
    store.set_account_public_access_block(None).await.unwrap();
    assert_eq!(store.account_public_access_block().await.unwrap(), None);

    // Together, each setting is on where either has it.
    let acls = PublicAccessBlock {
        block_public_acls: true,
        restrict_public_buckets: true,
        ..PublicAccessBlock::default()
    };
    let both = PublicAccessBlock {
        block_public_policy: true,
        ..acls
    };
    assert_eq!(acls.or(policy_only), both);
    assert_eq!(policy_only.or(acls), both);
    assert_eq!(
        PublicAccessBlock::default().or(PublicAccessBlock::ALL),
        PublicAccessBlock::ALL
    );
}

#[tokio::test]
async fn copies_never_take_the_source_acl() {
    let (_dir, store) = drive();
    let acl = Some(Acl::private());
    for (name, layout) in [("objects", Layout::Object), ("folder", Layout::Folder)] {
        store.create_bucket(name, layout).await.unwrap();
        store
            .put_bytes(name, "src", b"hello", ObjectAttrs::default())
            .await
            .unwrap();
        store.set_acl(name, "src", None, acl.clone()).await.unwrap();
    }
    for (from, to) in [
        ("objects", "objects"),
        ("folder", "folder"),
        ("objects", "folder"),
        ("folder", "objects"),
    ] {
        let copy = store
            .copy((from, "src"), (to, "copy"), None, Precondition::default())
            .await
            .unwrap();
        assert_eq!(copy.attrs.acl, None, "{from} to {to}");
        let named = ObjectAttrs {
            acl: acl.clone(),
            ..ObjectAttrs::default()
        };
        let copy = store
            .copy(
                (from, "src"),
                (to, "named"),
                Some(named),
                Precondition::default(),
            )
            .await
            .unwrap();
        assert_eq!(copy.attrs.acl, acl, "{from} to {to}");
    }
}

#[tokio::test]
async fn large_folders_list_the_same_from_the_cache() {
    let (dir, store) = drive();
    store.create_bucket("big", Layout::Folder).await.unwrap();
    let root = dir.path().join("big");
    let mut expected = Vec::new();
    for i in 0..1_500 {
        let key = format!("f{i:05}");
        fs::write(root.join(&key), b"x").unwrap();
        expected.push(key);
    }
    fs::create_dir(root.join("m")).unwrap();
    for name in ["a", "b"] {
        fs::write(root.join("m").join(name), b"x").unwrap();
        expected.push(format!("m/{name}"));
    }
    expected.sort();
    // Settled folders are served from the cache.
    let old = SystemTime::now() - std::time::Duration::from_secs(60);
    crate::test_util::set_folder_modified(&root, old);

    let list_all = |delimiter: Option<&str>| {
        let store = store.clone();
        let delimiter = delimiter.map(str::to_owned);
        async move {
            let (mut keys, mut prefixes, mut after) = (Vec::new(), Vec::new(), None);
            loop {
                let page = store
                    .list(
                        "big",
                        ListQuery {
                            delimiter: delimiter.clone(),
                            after,
                            max_keys: 100,
                            ..ListQuery::default()
                        },
                    )
                    .await
                    .unwrap();
                keys.extend(page.objects.into_iter().map(|o| o.key));
                prefixes.extend(page.prefixes);
                if !page.truncated {
                    return (keys, prefixes);
                }
                after = page.next;
            }
        }
    };
    for _ in 0..2 {
        assert_eq!(list_all(None).await.0, expected);
    }
    let (keys, prefixes) = list_all(Some("/")).await;
    assert_eq!(keys.len(), 1_500);
    assert_eq!(prefixes, ["m/"]);

    // A file added later changes the folder's time: it's listed at once.
    fs::write(root.join("f00000a"), b"x").unwrap();
    let (keys, _) = list_all(None).await;
    assert_eq!(keys.len(), expected.len() + 1);
    assert_eq!(keys[1], "f00000a");
    // So is a deletion.
    fs::remove_file(root.join("f00001")).unwrap();
    let (keys, _) = list_all(None).await;
    assert!(!keys.contains(&"f00001".to_owned()));
}

#[tokio::test]
async fn every_durability_mode_keeps_what_it_wrote() {
    for durability in [Durability::Strict, Durability::Relaxed, Durability::None] {
        let dir = tempfile::tempdir().unwrap();
        let open = || {
            Store::open_with(
                dir.path(),
                StoreOptions {
                    durability,
                    ..StoreOptions::default()
                },
            )
            .unwrap()
        };
        let store = open();
        for layout in [Layout::Folder, Layout::Object] {
            let name = format!("{layout:?}").to_lowercase();
            store.create_bucket(&name, layout).await.unwrap();
            store
                .put_bytes(&name, "a/b", b"kept", ObjectAttrs::default())
                .await
                .unwrap();
        }
        drop(store);
        let store = open();
        for name in ["folder", "object"] {
            let (_, body) = store.read(name, "a/b").await.unwrap();
            let mut bytes = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(
                &mut body.unwrap().all().await.unwrap(),
                &mut bytes,
            )
            .await
            .unwrap();
            assert_eq!(bytes, b"kept", "{durability:?} {name}");
        }
    }
}

fn not_portable<T>(result: &Result<T>) -> bool {
    matches!(
        result,
        Err(StoreError::InvalidName(NameError::InvalidKey(_)))
    )
}

#[tokio::test]
async fn folder_buckets_only_create_portable_names() {
    let (_dir, store) = with_bucket().await;
    store.create_bucket("objs", Layout::Object).await.unwrap();
    store
        .put_bytes("photos", "ok.txt", b"x", ObjectAttrs::default())
        .await
        .unwrap();
    for key in ["CON", "a/nul.txt", "a:b", "what?", "dot.", "space "] {
        let put = store
            .put_bytes("photos", key, b"x", ObjectAttrs::default())
            .await;
        assert!(not_portable(&put), "{key:?}");
        assert!(
            not_portable(&store.check_write("photos", Some(key), None).await),
            "{key:?} is refused before any bytes are read"
        );
        let rename = store
            .rename(
                "photos",
                "ok.txt",
                key,
                Precondition::default(),
                Precondition::default(),
                None,
            )
            .await;
        assert!(not_portable(&rename), "{key:?}");
        let copy = store
            .copy(
                ("photos", "ok.txt"),
                ("photos", key),
                None,
                Precondition::default(),
            )
            .await;
        assert!(not_portable(&copy), "{key:?}");
        let upload = store
            .create_upload(
                "photos",
                key,
                ObjectAttrs::default(),
                None,
                &Encryption::None,
                None,
                None,
            )
            .await;
        assert!(not_portable(&upload), "{key:?}");
        // Object buckets store keys by id: any S3 key is fine.
        store
            .put_bytes("objs", key, b"x", ObjectAttrs::default())
            .await
            .unwrap();
    }
    assert!(
        store
            .check_write("photos", Some("fine/name"), None)
            .await
            .is_ok()
    );
    assert!(matches!(
        store.create_bucket("nul", Layout::Folder).await,
        Err(StoreError::InvalidName(NameError::InvalidBucketName(_)))
    ));
    store.create_bucket("nul", Layout::Object).await.unwrap();
    assert_eq!(read_all(&store, "photos", "ok.txt").await, b"x");
}

#[cfg(not(windows))]
#[tokio::test]
async fn names_put_there_by_hand_stay_readable() {
    let (dir, store) = with_bucket().await;
    // Another program's file with a name Windows can't hold: listed, read and deleted
    // like any other, even though TeiFS wouldn't create it.
    fs::write(dir.path().join("photos/a:b"), b"by hand").unwrap();
    let query = ListQuery {
        max_keys: 100,
        ..ListQuery::default()
    };
    let listing = store.list("photos", query).await.unwrap();
    assert_eq!(keys(&listing), ["a:b"]);
    assert_eq!(read_all(&store, "photos", "a:b").await, b"by hand");
    store.delete("photos", "a:b").await.unwrap();
    assert!(!dir.path().join("photos/a:b").exists());
}

#[cfg(not(windows))]
#[tokio::test]
async fn host_rules_create_any_name_this_system_holds() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_with(
        dir.path(),
        StoreOptions {
            key_rules: KeyRules::Host,
            ..StoreOptions::default()
        },
    )
    .unwrap();
    store.create_bucket("con", Layout::Folder).await.unwrap();
    for key in ["CON", "a:b", "dot.", "what?"] {
        store
            .put_bytes("con", key, key.as_bytes(), ObjectAttrs::default())
            .await
            .unwrap();
        assert_eq!(read_all(&store, "con", key).await, key.as_bytes());
    }
}

#[tokio::test]
async fn unicode_forms_are_kept_apart_or_refused() {
    let (dir, store) = with_bucket().await;
    let (composed, decomposed) = ("caf\u{e9}", "cafe\u{301}");
    store
        .put_bytes("photos", composed, b"nfc", ObjectAttrs::default())
        .await
        .unwrap();
    // APFS and HFS+ look names up regardless of form; most others keep them apart.
    let insensitive = dir.path().join("photos").join(decomposed).exists();
    let other = store
        .put_bytes("photos", decomposed, b"nfd", ObjectAttrs::default())
        .await;
    if insensitive {
        assert!(matches!(other, Err(StoreError::KeyConflict(_))));
        assert!(matches!(
            store.head("photos", decomposed).await,
            Err(StoreError::NoSuchKey)
        ));
        // A folder in the other form is refused too.
        let folder = store
            .put_bytes(
                "photos",
                &format!("{composed}/in"),
                b"",
                ObjectAttrs::default(),
            )
            .await;
        assert!(
            matches!(folder, Err(StoreError::KeyConflict(_))),
            "{folder:?}"
        );
        store
            .put_bytes("photos", "d\u{ef}r/a", b"", ObjectAttrs::default())
            .await
            .unwrap();
        let folder = store
            .put_bytes("photos", "di\u{308}r/b", b"", ObjectAttrs::default())
            .await;
        assert!(
            matches!(folder, Err(StoreError::KeyConflict(_))),
            "{folder:?}"
        );
    } else {
        other.unwrap();
        assert_eq!(read_all(&store, "photos", decomposed).await, b"nfd");
    }
    assert_eq!(read_all(&store, "photos", composed).await, b"nfc");
}
