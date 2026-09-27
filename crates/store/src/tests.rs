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
    let mut staged = store.stage().await.unwrap();
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

    let staged = store.stage().await.unwrap();
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
    let staged = store.stage().await.unwrap();
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
    let mut staged = store.stage().await.unwrap();
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
    let mut staged = store.stage().await.unwrap();
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
        )
        .await
        .unwrap();
    let first = vec![1u8; usize::try_from(MIN_PART_SIZE).unwrap()];
    let mut etags = Vec::new();
    for (number, bytes) in [(1, first.as_slice()), (2, b"tail".as_slice())] {
        let mut staged = store.stage().await.unwrap();
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
        )
        .await
        .unwrap();
    let mut etags = Vec::new();
    for number in [1, 2] {
        let mut staged = store.stage().await.unwrap();
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
    let staged = store.stage().await.unwrap();
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
