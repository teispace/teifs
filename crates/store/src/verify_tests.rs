//! Integrity checks find damage planted on the disk (bytes changed, cut off or removed,
//! in plain, encrypted and multipart objects and in folder buckets' files) and tell it
//! apart from what they can't judge.

use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};

use super::*;
use crate::checksum::Checksums;

struct Drive {
    dir: tempfile::TempDir,
    _keys: tempfile::TempDir,
    store: Store,
}

async fn drive() -> Drive {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let kms = Arc::new(LocalKms::open(keys.path().join("keyring.json")).unwrap());
    let store = Store::open_with(
        dir.path(),
        StoreOptions {
            kms: Some(kms),
            // Every object in a file, for the tests that damage files.
            inline_max: Some(0),
            ..StoreOptions::default()
        },
    )
    .unwrap();
    store.create_bucket("obj", Layout::Object).await.unwrap();
    store.create_bucket("dir", Layout::Folder).await.unwrap();
    Drive {
        dir,
        _keys: keys,
        store,
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 13 % 251).unwrap())
        .collect()
}

fn crc64(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut sums = Checksums::default();
    sums.add("CRC64NVME");
    sums.update(bytes);
    sums.finish()
}

async fn put(store: &Store, bucket: &str, key: &str, bytes: &[u8], encryption: &Encryption) {
    put_with(store, bucket, key, bytes, encryption, BTreeMap::new()).await;
}

async fn put_with(
    store: &Store,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    encryption: &Encryption,
    checksums: BTreeMap<String, String>,
) {
    let mut staged = store.stage_for(bucket, encryption).await.unwrap();
    staged.write(bytes).await.unwrap();
    let attrs = ObjectAttrs {
        checksums,
        ..ObjectAttrs::default()
    };
    store
        .commit(bucket, key, staged, attrs, Precondition::default())
        .await
        .unwrap();
}

/// The data file of `key`'s current version in the object bucket `obj`.
async fn data_file(store: &Store, key: &str) -> PathBuf {
    let key = key.to_owned();
    store
        .blocking(move |inner| {
            let Bucket::Object(bucket) = inner.bucket("obj")? else {
                unreachable!("obj is an object bucket")
            };
            let row = Inner::version_row(&inner.lock(), &bucket, &key, None)?;
            Ok(bucket.data_path(row.object_id.as_deref().unwrap()))
        })
        .await
        .unwrap()
}

/// Flips one bit of the file at `path`, `at` bytes in, keeping its modification time.
fn flip(path: &std::path::Path, at: usize) {
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let mut bytes = fs::read(path).unwrap();
    bytes[at] ^= 1;
    fs::write(path, bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
}

async fn verdict(store: &Store, bucket: &str, key: &str) -> Verdict {
    store.verify_version(bucket, key, None).await.unwrap()
}

fn damaged(damage: Damage) -> Verdict {
    damage.into()
}

#[tokio::test]
async fn plain_objects_are_checked_against_their_checksums_and_etag() {
    let drive = drive().await;
    let store = &drive.store;
    let bytes = pattern(300_000);
    put_with(
        store,
        "obj",
        "sum",
        &bytes,
        &Encryption::None,
        crc64(&bytes),
    )
    .await;
    put(store, "obj", "md5", &bytes, &Encryption::None).await;
    put(store, "obj", "cut", &bytes, &Encryption::None).await;
    put(store, "obj", "gone", &bytes, &Encryption::None).await;
    put(store, "obj", "empty", b"", &Encryption::None).await;
    for key in ["sum", "md5", "cut", "gone", "empty"] {
        assert_eq!(verdict(store, "obj", key).await, Verdict::Intact, "{key}");
    }

    flip(&data_file(store, "sum").await, 1000);
    assert_eq!(
        verdict(store, "obj", "sum").await,
        damaged(Damage::Checksum {
            algorithm: "CRC64NVME".into(),
            part: None
        })
    );
    // Without a checksum, the ETag (the MD5) catches it.
    flip(&data_file(store, "md5").await, 299_999);
    assert_eq!(verdict(store, "obj", "md5").await, damaged(Damage::Etag));
    let cut = data_file(store, "cut").await;
    fs::File::options()
        .write(true)
        .open(&cut)
        .unwrap()
        .set_len(1000)
        .unwrap();
    assert_eq!(
        verdict(store, "obj", "cut").await,
        damaged(Damage::Truncated)
    );
    fs::remove_file(data_file(store, "gone").await).unwrap();
    assert_eq!(
        verdict(store, "obj", "gone").await,
        damaged(Damage::Missing)
    );
}

#[tokio::test]
async fn encrypted_objects_are_checked_as_they_decrypt() {
    let drive = drive().await;
    let store = &drive.store;
    let bytes = pattern(200_000);
    let kms = Encryption::Kms {
        key: None,
        context: BTreeMap::new(),
        bucket_key: false,
    };
    let customer = CustomerKey::parse(
        "AES256",
        &STANDARD.encode([4u8; 32]),
        &STANDARD.encode(Md5::digest([4u8; 32])),
    )
    .unwrap();
    put(store, "obj", "s3", &bytes, &Encryption::S3).await;
    put_with(store, "obj", "kms", &bytes, &kms, crc64(&bytes)).await;
    put(store, "obj", "c", &bytes, &Encryption::Customer(customer)).await;
    assert_eq!(verdict(store, "obj", "s3").await, Verdict::Intact);
    assert_eq!(verdict(store, "obj", "kms").await, Verdict::Intact);
    // TeiFS doesn't keep customer keys.
    assert_eq!(
        verdict(store, "obj", "c").await,
        Unverifiable::CustomerKey.into()
    );
    for key in ["s3", "kms"] {
        flip(&data_file(store, key).await, 70_000);
        assert_eq!(
            verdict(store, "obj", key).await,
            damaged(Damage::Tampered),
            "{key}"
        );
    }

    // Without the KMS, encrypted objects can't be opened, let alone checked.
    put(store, "obj", "sealed", &bytes, &Encryption::S3).await;
    put(store, "obj", "open", &bytes, &Encryption::None).await;
    let Drive { dir, _keys, store } = drive;
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        verdict(&store, "obj", "sealed").await,
        Unverifiable::NoKms.into()
    );
    assert_eq!(verdict(&store, "obj", "open").await, Verdict::Intact);
}

#[tokio::test]
async fn a_damaged_part_is_named() {
    let drive = drive().await;
    let store = &drive.store;
    let size = usize::try_from(MIN_PART_SIZE).unwrap();
    let parts = [pattern(size), vec![7u8; 1000]];
    for (key, sums) in [("summed", true), ("plain", false)] {
        let upload = store
            .create_upload(
                "obj",
                key,
                ObjectAttrs::default(),
                None,
                &Encryption::None,
                None,
                None,
            )
            .await
            .unwrap();
        let mut etags = Vec::new();
        for (number, bytes) in (1..).zip(&parts) {
            let mut staged = store.stage_part(&upload.id, number, None).await.unwrap();
            staged.write(bytes).await.unwrap();
            let checksums = if sums { crc64(bytes) } else { BTreeMap::new() };
            let part = store
                .put_part(&upload.id, number, staged, checksums)
                .await
                .unwrap();
            etags.push((number, part.etag));
        }
        store
            .complete(
                &upload.id,
                etags,
                Precondition::default(),
                CompleteWith::default(),
            )
            .await
            .unwrap();
        assert_eq!(verdict(store, "obj", key).await, Verdict::Intact, "{key}");
        flip(&data_file(store, key).await, size + 10);
    }
    assert_eq!(
        verdict(store, "obj", "summed").await,
        damaged(Damage::Checksum {
            algorithm: "CRC64NVME".into(),
            part: Some(2)
        })
    );
    // The multipart ETag is made of the parts' MD5s.
    assert_eq!(verdict(store, "obj", "plain").await, damaged(Damage::Etag));
}

#[tokio::test]
async fn folder_files_rot_is_told_from_an_edit() {
    let drive = drive().await;
    let store = &drive.store;
    let bytes = pattern(50_000);
    put(store, "dir", "a.txt", &bytes, &Encryption::None).await;
    put(store, "dir", "b.txt", &bytes, &Encryption::None).await;
    let path = |name: &str| drive.dir.path().join("dir").join(name);
    assert_eq!(verdict(store, "dir", "a.txt").await, Verdict::Intact);
    // Same size and time, different bytes: rot.
    flip(&path("a.txt"), 5);
    assert_eq!(verdict(store, "dir", "a.txt").await, damaged(Damage::Etag));
    // Edited outside TeiFS: nothing recorded fits it yet.
    fs::write(path("b.txt"), b"edited").unwrap();
    assert_eq!(
        verdict(store, "dir", "b.txt").await,
        Unverifiable::NothingToCompare.into()
    );
}

#[tokio::test]
async fn a_pass_covers_every_version_and_resumes() {
    let drive = drive().await;
    let store = &drive.store;
    store
        .set_bucket_versioning("obj", Versioning::Enabled)
        .await
        .unwrap();
    for (bucket, key, bytes) in [
        ("obj", "a", &b"one"[..]),
        ("obj", "a", b"two"),
        ("obj", "b", b"three"),
        ("dir", "x", b"four"),
    ] {
        put(store, bucket, key, bytes, &Encryption::None).await;
    }
    store.delete("obj", "b").await.unwrap();
    store.create_bucket("zzz", Layout::Object).await.unwrap();
    flip(&data_file(store, "a").await, 0);

    // One at a time, the cursor saved and read back between steps.
    let mut cursor = VerifyCursor::default();
    let mut seen = Vec::new();
    loop {
        let json = serde_json::to_string(&cursor).unwrap();
        cursor = serde_json::from_str(&json).unwrap();
        let step = store.verify_next(&mut cursor, None, 1).await.unwrap();
        if step.is_empty() {
            break;
        }
        seen.extend(step);
    }
    let names: Vec<_> = seen
        .iter()
        .map(|c| format!("{}/{}", c.bucket, c.key))
        .collect();
    // Buckets in name order; each key's versions newest first; no delete marker.
    assert_eq!(names, ["dir/x", "obj/a", "obj/a", "obj/b"]);
    assert_eq!(seen[1].verdict, damaged(Damage::Etag));
    assert!(
        [&seen[0], &seen[2], &seen[3]]
            .iter()
            .all(|c| c.verdict == Verdict::Intact)
    );
    assert!(
        store
            .verify_next(&mut cursor, None, 10)
            .await
            .unwrap()
            .is_empty()
    );

    // One bucket only.
    let mut cursor = VerifyCursor::default();
    let only = store
        .verify_next(&mut cursor, Some("dir"), 10)
        .await
        .unwrap();
    assert_eq!(only.len(), 1);
    assert!(
        store
            .verify_next(&mut cursor, Some("dir"), 10)
            .await
            .unwrap()
            .is_empty()
    );
    let json = serde_json::to_value(&only[0]).unwrap();
    assert_eq!(json["verdict"], "intact");
    let json = serde_json::to_value(&seen[1]).unwrap();
    assert_eq!(
        (&json["verdict"], &json["problem"]),
        (&"damaged".into(), &"etag".into())
    );
}
