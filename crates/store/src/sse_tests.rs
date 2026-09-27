//! Encryption at rest: every mode round-trips, ranges decrypt only what they need,
//! nothing readable reaches the disk, and wrong or missing keys fail cleanly.

use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use teifs_types::SseMode;
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
    let (_, body) = store.read_with("vault", key, customer).await?;
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

#[tokio::test]
async fn ranges_decrypt_across_package_and_part_boundaries() {
    let drive = drive().await;
    let package = teifs_crypto::PACKAGE_SIZE as u64;
    for len in [0, 1, package, package + 1, 3 * package + 5] {
        let data = pattern(usize::try_from(len).unwrap());
        put(&drive.store, "r", &data, &Encryption::S3).await;
        for (start, want) in [
            (0, len),
            (0, 1),
            (len.saturating_sub(1), 1),
            (package.saturating_sub(3).min(len), 7),
            (package.min(len), package),
            (len / 2, len),
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
        .read_with("vault", "c", Some(&key))
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
            .create_upload("vault", "big", ObjectAttrs::default(), None, &encryption)
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
            .complete(&upload.id, etags, Precondition::default())
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
            ("vault", "src"),
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
            ("vault", "later"),
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
