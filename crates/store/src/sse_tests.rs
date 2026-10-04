//! Encryption at rest: every mode round-trips, ranges decrypt only what they need,
//! nothing readable reaches the disk, and wrong or missing keys fail cleanly.

use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use teifs_crypto::DEFAULT_KEY;

use crate::{
    objects::crypt_of,
    sse::{Crypt, Resealed},
};
use teifs_types::{LockMode, SseMode};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;

use super::*;

struct Drive {
    dir: TempDir,
    _keys: TempDir,
    store: Store,
    kms: Arc<LocalKms>,
}

async fn drive() -> Drive {
    let dir = tempfile::tempdir().unwrap();
    // The keyring lives outside the drive, as it must.
    let keys = tempfile::tempdir().unwrap();
    let kms = Arc::new(LocalKms::open(keys.path().join("keyring.json")).unwrap());
    let store = Store::open_with(
        dir.path(),
        StoreOptions {
            kms: Some(kms.clone()),
            ..StoreOptions::default()
        },
    )
    .unwrap();
    store.create_bucket("vault", Layout::Object).await.unwrap();
    Drive {
        dir,
        _keys: keys,
        store,
        kms,
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 7 % 251).unwrap())
        .collect()
}

fn customer(byte: u8) -> CustomerKey {
    let key = [byte; 32];
    CustomerKey::parse(
        "AES256",
        &STANDARD.encode(key),
        &STANDARD.encode(Md5::digest(key)),
    )
    .unwrap()
}

/// SSE-KMS under the managed key.
fn managed_kms() -> Encryption {
    Encryption::Kms {
        key: None,
        context: BTreeMap::new(),
        bucket_key: false,
    }
}

async fn put(store: &Store, key: &str, bytes: &[u8], encryption: &Encryption) -> ObjectInfo {
    let mut staged = store.stage_for("vault", encryption).await.unwrap();
    staged.write(bytes).await.unwrap();
    store
        .commit(
            "vault",
            key,
            staged,
            ObjectAttrs::default(),
            Precondition::default(),
        )
        .await
        .unwrap()
}

async fn get(store: &Store, key: &str, customer: Option<&CustomerKey>) -> Result<Vec<u8>> {
    let (_, body) = store.read_with("vault", key, None, customer).await?;
    let mut out = Vec::new();
    body.unwrap().all().await?.read_to_end(&mut out).await?;
    Ok(out)
}

async fn get_range(store: &Store, key: &str, start: u64, len: u64) -> Vec<u8> {
    let (_, body) = store.read("vault", key).await.unwrap();
    let mut out = Vec::new();
    body.unwrap()
        .range(start, len)
        .await
        .unwrap()
        .read_to_end(&mut out)
        .await
        .unwrap();
    out
}

fn data_files(drive: &Drive) -> Vec<PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &drive.dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR),
        &mut out,
    );
    out
}

#[tokio::test]
async fn sse_s3_round_trips_and_never_stores_plaintext() {
    let drive = drive().await;
    let secret = b"a sentence nobody should find on the disk. ".repeat(5000);
    let info = put(&drive.store, "doc", &secret, &Encryption::S3).await;
    // SSE-S3 keeps the MD5 ETag, as AWS does.
    assert_eq!(info.etag, teifs_types::hex(&Md5::digest(&secret)));
    assert_eq!(info.sse.as_ref().map(|s| s.mode), Some(SseMode::S3));
    assert_eq!(get(&drive.store, "doc", None).await.unwrap(), secret);

    for file in data_files(&drive) {
        let bytes = fs::read(file).unwrap();
        assert!(!bytes.windows(40).any(|w| w == &secret[..40]));
    }
    let head = drive.store.head("vault", "doc").await.unwrap();
    assert_eq!(head.size, secret.len() as u64);
}

/// A body arriving in small pieces, written batch by batch while more arrives, comes
/// back whole in every mode, with the MD5 of all of it.
#[tokio::test]
async fn bytes_arriving_in_pieces_across_many_batches_round_trip() {
    let drive = drive().await;
    let bytes = pattern(1_300_000);
    let key = customer(9);
    for (name, encryption, customer) in [
        ("plain", Encryption::None, None),
        ("s3", Encryption::S3, None),
        ("c", Encryption::Customer(key.clone()), Some(&key)),
        (
            "dsse",
            Encryption::Dsse {
                key: None,
                context: BTreeMap::new(),
            },
            None,
        ),
    ] {
        let mut staged = drive.store.stage_for("vault", &encryption).await.unwrap();
        for piece in bytes.chunks(7_919) {
            staged.write(piece).await.unwrap();
        }
        staged.finish().await.unwrap();
        assert_eq!(
            staged.md5(),
            <[u8; 16]>::from(Md5::digest(&bytes)),
            "{name}"
        );
        // Finishing again changes nothing.
        staged.finish().await.unwrap();
        assert_eq!(staged.size(), bytes.len() as u64);
        drive
            .store
            .commit(
                "vault",
                name,
                staged,
                ObjectAttrs::default(),
                Precondition::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            get(&drive.store, name, customer).await.unwrap(),
            bytes,
            "{name}"
        );
    }
}

#[tokio::test]
async fn ranges_decrypt_across_package_and_part_boundaries() {
    let drive = drive().await;
    let package = teifs_crypto::PACKAGE_SIZE as u64;
    // Reads decrypt 16 packages at a time: objects and ranges across those batches too.
    for len in [
        0,
        1,
        package,
        package + 1,
        3 * package + 5,
        16 * package,
        40 * package + 7,
    ] {
        let data = pattern(usize::try_from(len).unwrap());
        put(&drive.store, "r", &data, &Encryption::S3).await;
        for (start, want) in [
            (0, len),
            (0, 1),
            (len.saturating_sub(1), 1),
            (package.saturating_sub(3).min(len), 7),
            (package.min(len), package),
            (len / 2, len),
            ((15 * package + 3).min(len), 2 * package),
            ((16 * package).min(len), 17 * package + 1),
        ] {
            let got = get_range(&drive.store, "r", start, want).await;
            let from = usize::try_from(start.min(len)).unwrap();
            let to = usize::try_from((start + want).min(len)).unwrap();
            assert_eq!(got, &data[from..to], "len {len}, {start}+{want}");
        }
    }
}

#[tokio::test]
async fn sse_kms_uses_named_keys_and_seals_checksums() {
    let drive = drive().await;
    drive.kms.create_key("photos").await.unwrap();
    let encryption = Encryption::Kms {
        key: Some("photos".into()),
        context: BTreeMap::from([("app".into(), "album".into())]),
        bucket_key: false,
    };
    let mut staged = drive.store.stage_for("vault", &encryption).await.unwrap();
    staged.write(b"picture").await.unwrap();
    let attrs = ObjectAttrs {
        checksums: BTreeMap::from([("CRC32".into(), "abcd".into())]),
        ..ObjectAttrs::default()
    };
    let info = drive
        .store
        .commit("vault", "p", staged, attrs, Precondition::default())
        .await
        .unwrap();
    // Not the MD5, as AWS does for SSE-KMS; and the checksum isn't stored in the clear.
    assert_ne!(info.etag, teifs_types::hex(&Md5::digest(b"picture")));
    assert!(info.attrs.checksums.is_empty());
    let (read, _) = drive.store.read("vault", "p").await.unwrap();
    assert_eq!(read.attrs.checksums["CRC32"], "abcd");
    assert_eq!(read.sse.unwrap().kms_key.as_deref(), Some("photos"));

    let missing = Encryption::Kms {
        key: Some("missing".into()),
        context: BTreeMap::new(),
        bucket_key: false,
    };
    assert!(drive.store.stage_for("vault", &missing).await.is_err());
}

#[tokio::test]
async fn sse_c_needs_the_right_key() {
    let drive = drive().await;
    let key = customer(1);
    put(
        &drive.store,
        "c",
        b"private",
        &Encryption::Customer(key.clone()),
    )
    .await;
    assert!(matches!(
        get(&drive.store, "c", None).await,
        Err(StoreError::CustomerKeyRequired)
    ));
    assert!(matches!(
        get(&drive.store, "c", Some(&customer(2))).await,
        Err(StoreError::WrongCustomerKey)
    ));
    assert_eq!(
        get(&drive.store, "c", Some(&key)).await.unwrap(),
        b"private"
    );
    let (info, _) = drive
        .store
        .read_with("vault", "c", None, Some(&key))
        .await
        .unwrap();
    assert_eq!(info.sse.unwrap().customer_key_md5, Some(key.md5_base64()));

    put(&drive.store, "plain", b"x", &Encryption::None).await;
    assert!(matches!(
        get(&drive.store, "plain", Some(&key)).await,
        Err(StoreError::CustomerKeyNotApplicable)
    ));
}

#[tokio::test]
async fn multipart_uploads_encrypt_each_part() {
    let drive = drive().await;
    for encryption in [Encryption::S3, Encryption::Customer(customer(3))] {
        let key = match &encryption {
            Encryption::Customer(k) => Some(k.clone()),
            _ => None,
        };
        let upload = drive
            .store
            .create_upload(
                "vault",
                "big",
                ObjectAttrs::default(),
                None,
                &encryption,
                None,
                None,
            )
            .await
            .unwrap();
        let first = pattern(usize::try_from(MIN_PART_SIZE).unwrap() + 3);
        let second = pattern(70_000);
        let mut etags = Vec::new();
        for (number, bytes) in [(1, &first), (2, &second)] {
            let mut staged = drive
                .store
                .stage_part(&upload.id, number, key.as_ref())
                .await
                .unwrap();
            staged.write(bytes).await.unwrap();
            let part = drive
                .store
                .put_part(&upload.id, number, staged, BTreeMap::new())
                .await
                .unwrap();
            etags.push((number, part.etag));
        }
        let info = drive
            .store
            .complete(
                &upload.id,
                etags,
                Precondition::default(),
                CompleteWith::default(),
            )
            .await
            .unwrap();
        assert_eq!(info.size, (first.len() + second.len()) as u64);
        let mut whole = first.clone();
        whole.extend_from_slice(&second);
        assert_eq!(get(&drive.store, "big", key.as_ref()).await.unwrap(), whole);
        if key.is_none() {
            // A range across the boundary between the two parts.
            let start = first.len() as u64 - 10;
            let got = get_range(&drive.store, "big", start, 30).await;
            let from = usize::try_from(start).unwrap();
            assert_eq!(got, &whole[from..from + 30]);
        }
    }
    // Parts of an SSE-C upload need the key.
    let upload = drive
        .store
        .create_upload(
            "vault",
            "k",
            ObjectAttrs::default(),
            None,
            &Encryption::Customer(customer(4)),
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        drive.store.stage_part(&upload.id, 1, None).await,
        Err(StoreError::CustomerKeyRequired)
    ));
}

#[tokio::test]
async fn copies_re_encrypt_under_their_own_key() {
    let drive = drive().await;
    let key = customer(5);
    put(
        &drive.store,
        "src",
        b"contents",
        &Encryption::Customer(key.clone()),
    )
    .await;
    // SSE-C source → SSE-S3 copy.
    drive
        .store
        .copy_with(
            ("vault", "src", None),
            ("vault", "s3copy"),
            None,
            Precondition::default(),
            Some(&key),
            &Encryption::S3,
        )
        .await
        .unwrap();
    assert_eq!(
        get(&drive.store, "s3copy", None).await.unwrap(),
        b"contents"
    );
    // SSE-S3 source → plain copy in a folder bucket.
    drive
        .store
        .create_bucket("plainfiles", Layout::Folder)
        .await
        .unwrap();
    drive
        .store
        .copy(
            ("vault", "s3copy"),
            ("plainfiles", "out.txt"),
            None,
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        fs::read(drive.dir.path().join("plainfiles/out.txt")).unwrap(),
        b"contents"
    );
    // Encrypting an existing object in place.
    put(&drive.store, "later", b"now encrypted", &Encryption::None).await;
    let info = drive
        .store
        .copy_with(
            ("vault", "later", None),
            ("vault", "later"),
            None,
            Precondition::default(),
            None,
            &Encryption::S3,
        )
        .await
        .unwrap();
    assert_eq!(info.sse.map(|s| s.mode), Some(SseMode::S3));
    assert_eq!(
        get(&drive.store, "later", None).await.unwrap(),
        b"now encrypted"
    );
}

#[tokio::test]
async fn tampered_data_fails_instead_of_returning_garbage() {
    let drive = drive().await;
    put(&drive.store, "t", &pattern(200_000), &Encryption::S3).await;
    let file = data_files(&drive).pop().unwrap();
    let mut bytes = fs::read(&file).unwrap();
    bytes[70_000] ^= 1;
    fs::write(&file, bytes).unwrap();
    assert!(get(&drive.store, "t", None).await.is_err());
}

#[tokio::test]
async fn encryption_needs_an_object_bucket_and_a_kms() {
    let drive = drive().await;
    drive
        .store
        .create_bucket("folder", Layout::Folder)
        .await
        .unwrap();
    assert!(matches!(
        drive.store.stage_for("folder", &Encryption::S3).await,
        Err(StoreError::InvalidRequest(_))
    ));

    let dir = tempfile::tempdir().unwrap();
    let no_kms = Store::open(dir.path()).unwrap();
    no_kms.create_bucket("vault", Layout::Object).await.unwrap();
    assert!(matches!(
        no_kms.stage_for("vault", &Encryption::S3).await,
        Err(StoreError::NoKms)
    ));
    // SSE-C doesn't need a KMS.
    put(&no_kms, "c", b"x", &Encryption::Customer(customer(6))).await;
}

#[tokio::test]
async fn another_keyring_cant_read_the_drive() {
    let drive = drive().await;
    put(&drive.store, "k", b"secret", &Encryption::S3).await;
    let other_keys = tempfile::tempdir().unwrap();
    let other = Arc::new(LocalKms::open(other_keys.path().join("keyring.json")).unwrap());
    drop(drive.store);
    let store = Store::open_with(
        drive.dir.path(),
        StoreOptions {
            kms: Some(other),
            ..StoreOptions::default()
        },
    )
    .unwrap();
    assert!(get(&store, "k", None).await.is_err());
}

#[tokio::test]
async fn encrypted_objects_rename_without_re_encryption() {
    let drive = drive().await;
    put(&drive.store, "before", b"sealed bytes", &Encryption::S3).await;
    let files = data_files(&drive);
    drive
        .store
        .rename(
            "vault",
            "before",
            "after",
            Precondition::default(),
            Precondition::default(),
            None,
        )
        .await
        .unwrap();
    // The same data file, still readable: the key is bound to the object id, not its key.
    assert_eq!(data_files(&drive), files);
    assert_eq!(
        get(&drive.store, "after", None).await.unwrap(),
        b"sealed bytes"
    );
}

/// Every file under the drive, `.teifs` included (databases, logs, data files).
fn all_files(drive: &Drive) -> Vec<PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(drive.dir.path(), &mut out);
    out
}

#[tokio::test]
async fn multipart_checksums_are_sealed_under_kms_and_customer_keys() {
    let drive = drive().await;
    let part_sum = "PART-CHECKSUM-IN-THE-CLEAR";
    let whole_sum = "OBJECT-CHECKSUM-IN-THE-CLEAR-1";
    for (name, encryption) in [
        ("kms", managed_kms()),
        ("ssec", Encryption::Customer(customer(5))),
    ] {
        let key = match &encryption {
            Encryption::Customer(k) => Some(k.clone()),
            _ => None,
        };
        let upload = drive
            .store
            .create_upload(
                "vault",
                name,
                ObjectAttrs::default(),
                None,
                &encryption,
                None,
                None,
            )
            .await
            .unwrap();
        let mut staged = drive
            .store
            .stage_part(&upload.id, 1, key.as_ref())
            .await
            .unwrap();
        staged.write(b"one part").await.unwrap();
        let sums: BTreeMap<String, String> = [("SHA256".to_owned(), part_sum.to_owned())].into();
        let part = drive
            .store
            .put_part(&upload.id, 1, staged, sums.clone())
            .await
            .unwrap();
        // Listing opens them with the key (SSE-KMS always; SSE-C only with it).
        let listed = drive
            .store
            .parts(&upload.id, 0, 10, key.as_ref())
            .await
            .unwrap();
        assert_eq!(listed[0].checksums, sums, "{name}");
        if key.is_some() {
            let blind = drive.store.parts(&upload.id, 0, 10, None).await.unwrap();
            assert!(blind[0].checksums.is_empty());
            // Sealing the object's checksum needs the customer's key.
            let without_key = drive
                .store
                .complete(
                    &upload.id,
                    vec![(1, part.etag.clone())],
                    Precondition::default(),
                    CompleteWith {
                        checksums: [("SHA256".to_owned(), whole_sum.to_owned())].into(),
                        ..CompleteWith::default()
                    },
                )
                .await;
            assert!(matches!(without_key, Err(StoreError::CustomerKeyRequired)));
        }
        let object_sums: BTreeMap<String, String> =
            [("SHA256".to_owned(), whole_sum.to_owned())].into();
        drive
            .store
            .complete(
                &upload.id,
                vec![(1, part.etag)],
                Precondition::default(),
                CompleteWith {
                    checksums: object_sums.clone(),
                    checksum_type: Some(teifs_types::ChecksumType::Composite),
                    customer: key.clone(),
                    replica: None,
                },
            )
            .await
            .unwrap();

        // Reading with the key shows them; describing without it doesn't.
        let (info, _) = drive
            .store
            .read_with("vault", name, None, key.as_ref())
            .await
            .unwrap();
        assert_eq!(info.attrs.checksums, object_sums, "{name}");
        assert_eq!(info.parts[0].checksums, sums);
        let head = drive.store.head("vault", name).await.unwrap();
        assert!(head.attrs.checksums.is_empty());
        assert!(head.parts[0].checksums.is_empty());
    }
    // Nothing on the disk holds either checksum in the clear.
    // (The drive's lock file is empty, and Windows won't read it while it's locked.)
    for file in all_files(&drive)
        .into_iter()
        .filter(|f| !f.ends_with("lock"))
    {
        let bytes = fs::read(&file).unwrap();
        for secret in [part_sum, whole_sum] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "{secret} in {}",
                file.display()
            );
        }
    }
}

/// An SSE-S3 object uploaded in one part, with checksums for the part and the whole.
async fn sse_s3_upload(drive: &Drive, key: &str, bytes: &[u8]) -> ObjectInfo {
    let store = &drive.store;
    let upload = store
        .create_upload(
            "vault",
            key,
            ObjectAttrs::default(),
            None,
            &Encryption::S3,
            None,
            None,
        )
        .await
        .unwrap();
    let mut staged = store.stage_part(&upload.id, 1, None).await.unwrap();
    staged.write(bytes).await.unwrap();
    let part = store
        .put_part(
            &upload.id,
            1,
            staged,
            [("SHA256".into(), "part-sum".into())].into(),
        )
        .await
        .unwrap();
    store
        .complete(
            &upload.id,
            vec![(1, part.etag)],
            Precondition::default(),
            CompleteWith {
                checksums: [("SHA256".into(), "whole-sum".into())].into(),
                checksum_type: Some(teifs_types::ChecksumType::Composite),
                customer: None,
                replica: None,
            },
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn encryption_is_updated_by_sealing_the_data_key_again() {
    let drive = drive().await;
    drive.kms.create_key("photos").await.unwrap();
    let bytes = pattern(100_000);
    let before = sse_s3_upload(&drive, "k", &bytes).await;
    assert_eq!(before.sse.as_ref().unwrap().mode, SseMode::S3);
    let stored: Vec<Vec<u8>> = data_files(&drive)
        .iter()
        .map(|p| fs::read(p).unwrap())
        .collect();

    drive
        .store
        .update_encryption("vault", "k", None, "photos", true)
        .await
        .unwrap();
    // The data isn't touched; the ETag and the modification time stay.
    let after: Vec<Vec<u8>> = data_files(&drive)
        .iter()
        .map(|p| fs::read(p).unwrap())
        .collect();
    assert_eq!(after, stored);
    let head = drive.store.head("vault", "k").await.unwrap();
    assert_eq!((&head.etag, head.modified), (&before.etag, before.modified));
    let sse = head.sse.unwrap();
    assert_eq!(
        (sse.mode, sse.kms_key.as_deref(), sse.bucket_key),
        (SseMode::Kms, Some("photos"), true)
    );
    // SSE-KMS keeps checksums sealed: shown only to a read.
    assert!(head.attrs.checksums.is_empty() && head.parts[0].checksums.is_empty());
    let (read, _) = drive.store.read("vault", "k").await.unwrap();
    assert_eq!(read.attrs.checksums["SHA256"], "whole-sum");
    assert_eq!(read.parts[0].checksums["SHA256"], "part-sum");
    assert_eq!(get(&drive.store, "k", None).await.unwrap(), bytes);

    // From one KMS key to another; checksums aren't sealed twice.
    drive
        .store
        .update_encryption("vault", "k", None, DEFAULT_KEY, false)
        .await
        .unwrap();
    let (read, _) = drive.store.read("vault", "k").await.unwrap();
    let sse = read.sse.unwrap();
    assert_eq!(
        (sse.kms_key.as_deref(), sse.bucket_key),
        (Some(DEFAULT_KEY), false)
    );
    assert_eq!(read.attrs.checksums["SHA256"], "whole-sum");
    assert_eq!(read.parts[0].checksums["SHA256"], "part-sum");
    assert_eq!(get(&drive.store, "k", None).await.unwrap(), bytes);
}

#[tokio::test]
async fn encryption_updates_are_refused_as_s3_refuses_them() {
    let drive = drive().await;
    let store = &drive.store;
    let update = |key: &'static str, kms_key: &'static str| {
        store.update_encryption("vault", key, None, kms_key, false)
    };
    put(store, "plain", b"p", &Encryption::None).await;
    put(store, "ssec", b"c", &Encryption::Customer(customer(3))).await;
    put(store, "s3", b"s", &Encryption::S3).await;
    assert!(
        matches!(update("plain", DEFAULT_KEY).await, Err(StoreError::InvalidRequest(m)) if m.contains("unencrypted"))
    );
    assert!(
        matches!(update("ssec", DEFAULT_KEY).await, Err(StoreError::InvalidRequest(m)) if m.contains("SSE-C"))
    );
    assert!(matches!(
        update("gone", DEFAULT_KEY).await,
        Err(StoreError::NoSuchKey)
    ));
    // An unknown key changes nothing.
    assert!(matches!(
        update("s3", "missing").await,
        Err(StoreError::Crypto(CryptoError::NoSuchKey(_)))
    ));
    let head = store.head("vault", "s3").await.unwrap();
    assert_eq!(head.sse.unwrap().mode, SseMode::S3);
    // Folder buckets keep plain files.
    store.create_bucket("files", Layout::Folder).await.unwrap();
    assert!(matches!(
        store
            .update_encryption("files", "a", None, DEFAULT_KEY, false)
            .await,
        Err(StoreError::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn encryption_updates_name_versions_and_respect_object_lock() {
    let drive = drive().await;
    let store = &drive.store;
    store
        .set_bucket_versioning("vault", Versioning::Enabled)
        .await
        .unwrap();
    store
        .set_bucket_object_lock(
            "vault",
            ObjectLock {
                default_retention: None,
            },
        )
        .await
        .unwrap();
    let first = put(store, "k", b"one", &Encryption::S3).await;
    put(store, "k", b"two", &Encryption::S3).await;
    let old = first.version_id.unwrap();
    // A version by its id; the current one stays as it was.
    store
        .update_encryption("vault", "k", Some(&old), DEFAULT_KEY, false)
        .await
        .unwrap();
    let mode = |info: ObjectInfo| info.sse.unwrap().mode;
    assert_eq!(
        mode(store.head_version("vault", "k", Some(&old)).await.unwrap()),
        SseMode::Kms
    );
    assert_eq!(mode(store.head("vault", "k").await.unwrap()), SseMode::S3);

    // A legal hold or a retention of either mode refuses it.
    store
        .set_legal_hold("vault", "k", None, true)
        .await
        .unwrap();
    let update = || store.update_encryption("vault", "k", None, DEFAULT_KEY, false);
    assert!(matches!(update().await, Err(StoreError::ObjectLocked)));
    store
        .set_legal_hold("vault", "k", None, false)
        .await
        .unwrap();
    let until = now_ms() + 60_000;
    let governance = Retention {
        mode: LockMode::Governance,
        until_ms: until,
    };
    store
        .set_retention("vault", "k", None, Some(governance), false)
        .await
        .unwrap();
    assert!(matches!(update().await, Err(StoreError::ObjectLocked)));
    store
        .set_retention("vault", "k", None, None, true)
        .await
        .unwrap();
    update().await.unwrap();
    assert_eq!(mode(store.head("vault", "k").await.unwrap()), SseMode::Kms);
    // A delete marker has no encryption to update.
    store.delete("vault", "k").await.unwrap();
    assert!(matches!(
        update().await,
        Err(StoreError::DeleteMarker { .. })
    ));
}

#[tokio::test]
async fn an_object_written_meanwhile_keeps_its_own_key() {
    let drive = drive().await;
    let store = &drive.store;
    put(store, "k", b"old", &Encryption::S3).await;
    // Read, sealed again; then the object is written again before the record is.
    let (bucket_id, row) = store.updatable_row("vault", "k", None).await.unwrap();
    let crypt = crypt_of(&row).unwrap().unwrap();
    let context = crypt.context(&store.inner.format.drive, &bucket_id);
    let data_key = drive.kms.unseal(&crypt.sealed, &context).await.unwrap();
    let sealed = drive.kms.seal(None, &context, &data_key).await.unwrap();
    put(store, "k", b"new", &Encryption::S3).await;
    let new = Resealed {
        mode: SseMode::Kms,
        crypt,
        sealed,
        bucket_key: false,
        data_key,
    };
    assert!(matches!(
        store.write_resealed("vault", "k", row, new, true).await,
        Err(StoreError::ChangedMeanwhile)
    ));
    // The new object keeps its own key; trying again starts from what's there now.
    assert_eq!(get(store, "k", None).await.unwrap(), b"new");
    store
        .update_encryption("vault", "k", None, DEFAULT_KEY, false)
        .await
        .unwrap();
    assert_eq!(get(store, "k", None).await.unwrap(), b"new");
}

/// The encryption record of `key`'s current version.
async fn crypt(store: &Store, key: &str) -> Crypt {
    let key = key.to_owned();
    store
        .blocking(move |inner| {
            let Bucket::Object(bucket) = inner.bucket("vault")? else {
                unreachable!("vault is an object bucket")
            };
            let row = Inner::version_row(&inner.lock(), &bucket, &key, None)?;
            Ok(crypt_of(&row)?.unwrap())
        })
        .await
        .unwrap()
}

/// The parts record (JSON) of `key`'s current version.
async fn parts_record(store: &Store, key: &str) -> String {
    let key = key.to_owned();
    store
        .blocking(move |inner| {
            let Bucket::Object(bucket) = inner.bucket("vault")? else {
                unreachable!("vault is an object bucket")
            };
            let row = Inner::version_row(&inner.lock(), &bucket, &key, None)?;
            Ok(row.parts.unwrap())
        })
        .await
        .unwrap()
}

/// The KMS key and version that seal the data key of `key`'s current version.
async fn sealed_by(store: &Store, key: &str) -> (String, u32) {
    let sealed = crypt(store, key).await.sealed;
    (sealed.kms_key, sealed.kms_version)
}

/// The KMS key and version that seal the DSSE-KMS outer key of `key`'s current version.
async fn outer_sealed_by(store: &Store, key: &str) -> (String, u32) {
    let sealed = crypt(store, key).await.outer.unwrap();
    (sealed.kms_key, sealed.kms_version)
}

#[tokio::test]
async fn rewrap_seals_old_key_versions_under_the_newest() {
    let drive = drive().await;
    let store = &drive.store;
    drive.kms.create_key("photos").await.unwrap();
    store
        .set_bucket_versioning("vault", Versioning::Enabled)
        .await
        .unwrap();
    store
        .set_bucket_object_lock(
            "vault",
            ObjectLock {
                default_retention: None,
            },
        )
        .await
        .unwrap();
    let photos = Encryption::Kms {
        key: Some("photos".into()),
        context: [("app".into(), "album".into())].into(),
        bucket_key: true,
    };
    let bytes = pattern(70_000);
    let s3 = sse_s3_upload(&drive, "s3", &bytes).await;
    assert!(!s3.attrs.checksums.is_empty());
    // Folder buckets have nothing to rewrap.
    store.create_bucket("plain", Layout::Folder).await.unwrap();
    let before = put(store, "kms", &bytes, &photos).await;
    put(store, "c", &bytes, &Encryption::Customer(customer(3))).await;
    // Locked, and still rewrapped: nothing about it changes.
    store
        .set_legal_hold("vault", "kms", None, true)
        .await
        .unwrap();
    let upload = store
        .create_upload(
            "vault",
            "up",
            ObjectAttrs::default(),
            None,
            &photos,
            None,
            None,
        )
        .await
        .unwrap();
    let mut staged = store.stage_part(&upload.id, 1, None).await.unwrap();
    staged.write(&bytes).await.unwrap();
    let part = store
        .put_part(&upload.id, 1, staged, BTreeMap::new())
        .await
        .unwrap();
    drive.kms.rotate_key("photos").await.unwrap();
    drive.kms.rotate_key(DEFAULT_KEY).await.unwrap();

    // A dry run counts; a real one reseals under version 2, once.
    let counted = Rewrapped {
        newest: 2,
        versions: 1,
        uploads: 1,
        changed_meanwhile: 0,
    };
    assert_eq!(store.rewrap("photos", true).await.unwrap(), counted);
    assert_eq!(sealed_by(store, "kms").await, ("photos".into(), 1));
    assert_eq!(store.rewrap("photos", false).await.unwrap(), counted);
    assert_eq!(sealed_by(store, "kms").await, ("photos".into(), 2));
    let after = store.head("vault", "kms").await.unwrap();
    assert_eq!(
        (&after.etag, after.modified, &after.sse),
        (&before.etag, before.modified, &before.sse)
    );
    assert!(after.sse.as_ref().unwrap().bucket_key);
    assert_eq!(get(store, "kms", None).await.unwrap(), bytes);
    let nothing = Rewrapped {
        newest: 2,
        ..Rewrapped::default()
    };
    assert_eq!(store.rewrap("photos", false).await.unwrap(), nothing);

    // The upload finishes with its resealed key.
    store
        .complete(
            &upload.id,
            vec![(1, part.etag)],
            Precondition::default(),
            CompleteWith::default(),
        )
        .await
        .unwrap();
    assert_eq!(get(store, "up", None).await.unwrap(), bytes);

    // SSE-S3 objects go with the managed key; SSE-C ones have no KMS key.
    assert_eq!(sealed_by(store, "s3").await, (DEFAULT_KEY.into(), 1));
    let managed = store.rewrap(DEFAULT_KEY, false).await.unwrap();
    assert_eq!((managed.versions, managed.uploads), (1, 0));
    assert_eq!(sealed_by(store, "s3").await, (DEFAULT_KEY.into(), 2));
    let head = store.head("vault", "s3").await.unwrap();
    assert_eq!(head.sse.unwrap().mode, SseMode::S3);
    // Its checksums stay in the open, as SSE-S3 keeps them.
    assert_eq!(head.attrs.checksums, s3.attrs.checksums);
    assert_eq!(get(store, "s3", None).await.unwrap(), bytes);
    assert_eq!(get(store, "c", Some(&customer(3))).await.unwrap(), bytes);
    assert!(matches!(
        store.rewrap("nope", true).await,
        Err(StoreError::Crypto(teifs_crypto::CryptoError::NoSuchKey(_)))
    ));
}

fn dsse(key: &str) -> Encryption {
    Encryption::Dsse {
        key: Some(key.into()),
        context: [("app".into(), "album".into())].into(),
    }
}

#[tokio::test]
async fn dsse_kms_encrypts_twice_under_independent_keys() {
    let drive = drive().await;
    let store = &drive.store;
    drive.kms.create_key("photos").await.unwrap();
    let data = pattern(3 * teifs_crypto::PACKAGE_SIZE + 5);
    let mut staged = store.stage_for("vault", &dsse("photos")).await.unwrap();
    staged.write(&data).await.unwrap();
    let attrs = ObjectAttrs {
        checksums: BTreeMap::from([("CRC32".into(), "abcd".into())]),
        ..ObjectAttrs::default()
    };
    let info = store
        .commit("vault", "d", staged, attrs, Precondition::default())
        .await
        .unwrap();
    // Like SSE-KMS: no MD5 ETag, sealed checksums, the key reported, no Bucket Key.
    assert_ne!(info.etag, teifs_types::hex(&Md5::digest(&data)));
    assert!(info.attrs.checksums.is_empty());
    let (read, _) = store.read("vault", "d").await.unwrap();
    assert_eq!(read.attrs.checksums["CRC32"], "abcd");
    let sse = read.sse.unwrap();
    assert_eq!(
        (sse.mode, sse.kms_key.as_deref(), sse.bucket_key),
        (SseMode::Dsse, Some("photos"), false)
    );
    assert_eq!(get(store, "d", None).await.unwrap(), data);
    let package = teifs_crypto::PACKAGE_SIZE as u64;
    let got = get_range(store, "d", package - 3, 10).await;
    let from = usize::try_from(package - 3).unwrap();
    assert_eq!(got, &data[from..from + 10]);

    // The data key alone doesn't open what's on disk: the second layer needs the second
    // key, sealed by the managed key.
    let crypt = crypt(store, "d").await;
    assert_eq!(sealed_by(store, "d").await, ("photos".into(), 1));
    assert_eq!(outer_sealed_by(store, "d").await, (DEFAULT_KEY.into(), 1));
    let bucket_id = store.object_bucket_id("vault").await.unwrap();
    let context = crypt.context(&store.inner.format.drive, &bucket_id);
    let inner = drive.kms.unseal(&crypt.sealed, &context).await.unwrap();
    let outer = drive
        .kms
        .unseal(crypt.outer.as_ref().unwrap(), &context.clone().outer())
        .await
        .unwrap();
    // Each seal opens only under its own context.
    assert!(
        drive
            .kms
            .unseal(crypt.outer.as_ref().unwrap(), &context)
            .await
            .is_err()
    );
    let file = fs::read(data_files(&drive).pop().unwrap()).unwrap();
    let stored = &file[..usize::try_from(teifs_crypto::ciphertext_len(data.len() as u64)).unwrap()];
    assert!(teifs_crypto::decrypt_part(&inner, None, 1, stored).is_err());
    assert_eq!(
        teifs_crypto::decrypt_part(&inner, Some(&outer), 1, stored).unwrap(),
        data
    );

    // A record with a missing or stray outer key is refused.
    let kms: &dyn teifs_crypto::Kms = drive.kms.as_ref();
    let drive_id = &store.inner.format.drive;
    for broken in [
        Crypt {
            outer: None,
            ..crypt.clone()
        },
        Crypt {
            mode: SseMode::Kms,
            ..crypt.clone()
        },
    ] {
        assert!(matches!(
            crate::sse::outer_key(Some(kms), &broken, drive_id, &bucket_id).await,
            Err(StoreError::CorruptMetadata)
        ));
    }

    // UpdateObjectEncryption refuses DSSE-KMS sources, as S3 does.
    assert!(matches!(
        store
            .update_encryption("vault", "d", None, "photos", false)
            .await,
        Err(StoreError::InvalidRequest(m)) if m.contains("DSSE-KMS")
    ));
    assert!(store.stage_for("vault", &dsse("missing")).await.is_err());
}

#[tokio::test]
async fn dsse_kms_uploads_and_copies_keep_both_layers() {
    let drive = drive().await;
    let store = &drive.store;
    let upload = store
        .create_upload(
            "vault",
            "big",
            ObjectAttrs::default(),
            None,
            &Encryption::Dsse {
                key: None,
                context: BTreeMap::new(),
            },
            None,
            None,
        )
        .await
        .unwrap();
    let first = pattern(usize::try_from(MIN_PART_SIZE).unwrap() + 3);
    let second = pattern(70_000);
    let mut etags = Vec::new();
    for (number, bytes) in [(1, &first), (2, &second)] {
        let mut staged = store.stage_part(&upload.id, number, None).await.unwrap();
        staged.write(bytes).await.unwrap();
        let part = store
            .put_part(&upload.id, number, staged, BTreeMap::new())
            .await
            .unwrap();
        etags.push((number, part.etag));
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
    let sse = info.sse.unwrap();
    assert_eq!(
        (sse.mode, sse.kms_key.as_deref()),
        (SseMode::Dsse, Some(DEFAULT_KEY))
    );
    let mut whole = first.clone();
    whole.extend_from_slice(&second);
    assert_eq!(get(store, "big", None).await.unwrap(), whole);
    let start = first.len() as u64 - 10;
    let from = usize::try_from(start).unwrap();
    assert_eq!(
        get_range(store, "big", start, 30).await,
        &whole[from..from + 30]
    );

    // DSSE-KMS → SSE-S3 and back, each copy under keys of its own.
    for (from, to, encryption, mode) in [
        ("big", "s3", Encryption::S3, SseMode::S3),
        ("s3", "again", dsse(DEFAULT_KEY), SseMode::Dsse),
    ] {
        let info = store
            .copy_with(
                ("vault", from, None),
                ("vault", to),
                None,
                Precondition::default(),
                None,
                &encryption,
            )
            .await
            .unwrap();
        assert_eq!(info.sse.map(|s| s.mode), Some(mode));
        assert_eq!(get(store, to, None).await.unwrap(), whole);
    }
    assert_ne!(
        crypt(store, "again").await.outer,
        crypt(store, "big").await.outer
    );
}

#[tokio::test]
async fn rewrap_reseals_dsse_kms_outer_keys_with_the_managed_key() {
    let drive = drive().await;
    let store = &drive.store;
    drive.kms.create_key("photos").await.unwrap();
    let bytes = pattern(70_000);
    put(store, "d", &bytes, &dsse("photos")).await;
    let upload = store
        .create_upload(
            "vault",
            "up",
            ObjectAttrs::default(),
            None,
            &dsse("photos"),
            None,
            None,
        )
        .await
        .unwrap();
    let mut staged = store.stage_part(&upload.id, 1, None).await.unwrap();
    staged.write(&bytes).await.unwrap();
    let part = store
        .put_part(&upload.id, 1, staged, BTreeMap::new())
        .await
        .unwrap();
    drive.kms.rotate_key("photos").await.unwrap();
    drive.kms.rotate_key(DEFAULT_KEY).await.unwrap();

    // Each key rewraps only the seals it made.
    let photos = store.rewrap("photos", false).await.unwrap();
    assert_eq!((photos.versions, photos.uploads), (1, 1));
    assert_eq!(sealed_by(store, "d").await, ("photos".into(), 2));
    assert_eq!(outer_sealed_by(store, "d").await, (DEFAULT_KEY.into(), 1));
    let managed = store.rewrap(DEFAULT_KEY, false).await.unwrap();
    assert_eq!((managed.versions, managed.uploads), (1, 1));
    assert_eq!(sealed_by(store, "d").await, ("photos".into(), 2));
    assert_eq!(outer_sealed_by(store, "d").await, (DEFAULT_KEY.into(), 2));
    let nothing = store.rewrap(DEFAULT_KEY, false).await.unwrap();
    assert_eq!((nothing.versions, nothing.uploads), (0, 0));
    assert_eq!(get(store, "d", None).await.unwrap(), bytes);
    assert_eq!(
        store.head("vault", "d").await.unwrap().sse.unwrap().mode,
        SseMode::Dsse
    );

    // The upload finishes with both its keys resealed.
    store
        .complete(
            &upload.id,
            vec![(1, part.etag)],
            Precondition::default(),
            CompleteWith::default(),
        )
        .await
        .unwrap();
    assert_eq!(get(store, "up", None).await.unwrap(), bytes);
    assert_eq!(outer_sealed_by(store, "up").await, (DEFAULT_KEY.into(), 2));
}

#[tokio::test]
async fn parts_sent_again_or_skipped_keep_keys_of_their_own() {
    let drive = drive().await;
    let store = &drive.store;
    let size = usize::try_from(MIN_PART_SIZE).unwrap();
    let (a, b, c) = (pattern(size), vec![1u8; size], pattern(70_000));
    for (key, encryption) in [
        ("plain", Encryption::None),
        ("s3", Encryption::S3),
        ("dsse", dsse(DEFAULT_KEY)),
        ("c", Encryption::Customer(customer(9))),
    ] {
        let customer = match &encryption {
            Encryption::Customer(k) => Some(k.clone()),
            _ => None,
        };
        let upload = store
            .create_upload(
                "vault",
                key,
                ObjectAttrs::default(),
                None,
                &encryption,
                None,
                None,
            )
            .await
            .unwrap();
        let send = |number: u32, bytes: Vec<u8>| {
            let (id, customer) = (upload.id.clone(), customer.clone());
            async move {
                let mut staged = store
                    .stage_part(&id, number, customer.as_ref())
                    .await
                    .unwrap();
                staged.write(&bytes).await.unwrap();
                store
                    .put_part(&id, number, staged, BTreeMap::new())
                    .await
                    .unwrap()
                    .etag
            }
        };
        // The same bytes sent twice as part 1 are stored under different keys.
        let file = store.inner.uploads.join(&upload.id).join("1");
        send(1, a.clone()).await;
        let first = fs::read(&file).unwrap();
        let one = send(1, a.clone()).await;
        let plain = matches!(encryption, Encryption::None);
        assert_eq!(fs::read(&file).unwrap() == first, plain, "{key}");
        // Part numbers with gaps: 1, 3 and 7.
        let three = send(3, b.clone()).await;
        let seven = send(7, c.clone()).await;
        send(5, a.clone()).await;
        store
            .complete(
                &upload.id,
                vec![(1, one), (3, three), (7, seven)],
                Precondition::default(),
                CompleteWith::default(),
            )
            .await
            .unwrap();
        let whole = [a.clone(), b.clone(), c.clone()].concat();
        assert_eq!(
            get(store, key, customer.as_ref()).await.unwrap(),
            whole,
            "{key}"
        );
        // Only encrypted objects record their parts' keys.
        assert_eq!(
            parts_record(store, key).await.contains("keys"),
            !plain,
            "{key}"
        );
        if customer.is_none() {
            let start = 2 * size as u64 - 5;
            let from = usize::try_from(start).unwrap();
            assert_eq!(
                get_range(store, key, start, 20).await,
                &whole[from..from + 20],
                "{key}"
            );
        }
    }
}

#[test]
fn part_keys_come_from_the_record_or_count_from_one() {
    use crate::objects::sealed_parts;
    let row = |parts: Option<&str>| teifs_meta::VersionRow {
        bucket_id: "b".into(),
        key: "k".into(),
        version_id: "null".into(),
        delete_marker: false,
        object_id: None,
        size: 9,
        etag: String::new(),
        modified_ms: 0,
        attrs: ObjectAttrs::default(),
        crypt: None,
        parts: parts.map(str::to_owned),
        inline: None,
        seq: 0,
        latest: true,
    };
    let ids = |parts: Option<&str>| sealed_parts(&row(parts));
    assert_eq!(ids(None).unwrap(), [(9, teifs_crypto::PartId::from(1))]);
    // Stored before part keys were recorded: numbered 1, 2, … without salts.
    assert_eq!(
        ids(Some(r#"{"sizes":[5,4]}"#)).unwrap(),
        [(5, 1.into()), (4, 2.into())]
    );
    let salt = "000102030405060708090a0b0c0d0e0f";
    let keyed =
        format!(r#"{{"sizes":[5,4],"keys":[{{"number":2}},{{"number":9,"salt":"{salt}"}}]}}"#);
    assert_eq!(
        ids(Some(&keyed)).unwrap(),
        [
            (5, 2.into()),
            (
                4,
                teifs_crypto::PartId {
                    number: 9,
                    salt: teifs_types::unhex(salt),
                }
            )
        ]
    );
    for bad in [
        r#"{"sizes":[5,4],"keys":[{"number":2}]}"#.to_owned(),
        keyed.replace(salt, "00"),
    ] {
        assert!(
            matches!(ids(Some(&bad)), Err(StoreError::CorruptMetadata)),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn an_encrypted_copy_seals_the_checksum_it_asked_for_and_says_what_it_is() {
    let d = drive().await;
    d.store
        .put_bytes("vault", "a", b"data", ObjectAttrs::default())
        .await
        .unwrap();
    let mut sha256 = checksum::Checksums::default();
    assert!(sha256.add("SHA256"));
    sha256.update(b"data");
    let wanted = sha256.finish();
    let copy = d
        .store
        .copy_how(
            ("vault", "a", None),
            ("vault", "b"),
            None,
            Precondition::default(),
            CopyHow {
                source_key: None,
                encryption: &managed_kms(),
                checksum: Some("SHA256"),
            },
        )
        .await
        .unwrap();
    assert_eq!(copy.attrs.checksums, wanted);
    // Sealed: only a read (which opens the encryption) shows them.
    assert!(
        d.store
            .head("vault", "b")
            .await
            .unwrap()
            .attrs
            .checksums
            .is_empty()
    );
    let (read, _) = d.store.read("vault", "b").await.unwrap();
    assert_eq!(read.attrs.checksums, wanted);
    assert_eq!(read.sse.unwrap().mode, SseMode::Kms);
}
