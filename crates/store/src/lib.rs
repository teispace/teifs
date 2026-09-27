//! TeiFS's storage. A drive is a folder with two kinds of bucket:
//!
//! - **folder buckets** ([`folder`]): a folder at the drive's root whose objects are plain
//!   files at their keys' paths, usable by anything else;
//! - **object buckets** ([`objects`]): every key S3 allows, stored by id under `.teifs`.
//!
//! What S3 needs beyond the bytes lives in `.teifs/index.db` and `.teifs/system.db` (the
//! `teifs-meta` crate). Writes are staged in `.teifs/tmp`, synced and put in place under
//! one commit lock, so every object is either its old or its new version, and its
//! recorded ETag always belongs to its bytes.

mod body;
mod error;
mod folder;
mod format;
mod list;
mod multipart;
mod objects;
mod settings;
mod sse;
mod staged;

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use teifs_meta::{BucketRecord, Index, System};

pub use body::{BodyReader, ObjectBody};
pub use error::{Result, StoreError};
pub use format::{DriveFormat, FORMAT};
pub use list::{After, ListQuery, Listing};
pub use multipart::{MAX_PART_NUMBER, MIN_PART_SIZE};
pub use settings::{BucketEncryption, DefaultEncryption};
pub use sse::Encryption;
pub use staged::Staged;
pub use teifs_crypto::{CryptoError, CustomerKey, Kms, LocalKms, TransitKms};
pub use teifs_meta::{Layout, Part, Upload};
pub use teifs_types::{MAX_KEY_LEN, NameError, ObjectAttrs, ObjectInfo, ObjectKey, check_bucket};
pub use teifs_types::{SseInfo, SseMode};

use error::not_found_as;
use folder::Found;
use objects::{BUCKETS_DIR, Finished, ObjectBucket};
use staged::{TmpFile, sync_dir};

/// The folder in a drive's root that holds TeiFS's own data.
pub const SYSTEM_DIR: &str = ".teifs";

/// A bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketInfo {
    /// Its name.
    pub name: String,
    /// How it stores objects.
    pub layout: Layout,
    /// When it was created (for a folder made outside TeiFS, when the folder was).
    pub created: SystemTime,
}

/// A bucket, resolved to where its objects are.
#[derive(Debug, Clone)]
enum Bucket {
    /// A folder bucket: its name and its (canonical) folder.
    Folder(String, PathBuf),
    /// An object bucket.
    Object(ObjectBucket),
}

/// Which current object a write or copy may replace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Precondition {
    /// `If-Match`: the object must exist (and have this ETag).
    pub if_match: Option<Match>,
    /// `If-None-Match`: the object must not exist (or not have this ETag).
    pub if_none_match: Option<Match>,
}

/// An `If-Match` / `If-None-Match` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// `*`: any object.
    Any,
    /// An ETag (quotes optional).
    ETag(String),
}

impl Match {
    fn matches(&self, info: &ObjectInfo) -> bool {
        match self {
            Match::Any => true,
            Match::ETag(etag) => etag.trim_matches('"') == info.etag,
        }
    }
}

impl Precondition {
    /// Whether the write may only create the object (`If-None-Match: *`).
    fn creates_only(&self) -> bool {
        self.if_none_match == Some(Match::Any)
    }

    fn check(&self, current: Option<&ObjectInfo>) -> Result<()> {
        let ok_match = self
            .if_match
            .as_ref()
            .is_none_or(|m| current.is_some_and(|info| m.matches(info)));
        let ok_none = self
            .if_none_match
            .as_ref()
            .is_none_or(|m| current.is_none_or(|info| !m.matches(info)));
        if ok_match && ok_none {
            Ok(())
        } else {
            Err(StoreError::PreconditionFailed)
        }
    }
}

/// A drive.
#[derive(Debug, Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    root: PathBuf,
    system_dir: PathBuf,
    tmp: PathBuf,
    uploads: PathBuf,
    /// The index, also the commit lock: whoever changes a file holds it until the file
    /// and its row agree again.
    db: Mutex<Index>,
    /// The system database. Taken after `db` when both are needed.
    system: Mutex<System>,
    format: DriveFormat,
    /// Seals and unseals the data keys of encrypted objects (set once, at or after open).
    kms: std::sync::OnceLock<Arc<dyn Kms>>,
    /// The encryption settings of object buckets that have none of their own.
    default_encryption: BucketEncryption,
}

/// How to open a drive.
#[derive(Debug, Clone, Default)]
pub struct StoreOptions {
    /// The KMS for encryption at rest. Without one, writes that ask for SSE-S3 or SSE-KMS
    /// and reads of such objects fail; SSE-C still works. See also [`Store::attach_kms`].
    pub kms: Option<Arc<dyn Kms>>,
    /// The encryption settings of object buckets that have none of their own; `None`
    /// means AWS's default ([`BucketEncryption::aws_default`]).
    pub default_encryption: Option<BucketEncryption>,
}

impl Store {
    /// Opens the drive at `root` (which must exist), creating `.teifs` inside it, and
    /// upgrading the drive's format first if an older TeiFS wrote it. No KMS: see
    /// [`Store::open_with`].
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(root, StoreOptions::default())
    }

    /// Opens the drive at `root` with `options`.
    pub fn open_with(root: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        let root = fs::canonicalize(root.as_ref())?;
        if !root.is_dir() {
            return Err(StoreError::Io(io::Error::new(
                io::ErrorKind::NotADirectory,
                "the drive must be a folder",
            )));
        }
        let system_dir = root.join(SYSTEM_DIR);
        let tmp = system_dir.join("tmp");
        let uploads = system_dir.join("uploads");
        fs::create_dir_all(&uploads)?;
        fs::create_dir_all(system_dir.join(BUCKETS_DIR))?;
        // Whatever was being written when the last run stopped is gone for good.
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp)?;
        sweep_bucket_staging(&root);
        let format = format::prepare(&system_dir)?;
        let db = Index::open(&system_dir.join(format::INDEX_DB))?;
        let system_db = System::open(&system_dir.join(format::SYSTEM_DB))?;
        let inner = Inner {
            root,
            system_dir,
            tmp,
            uploads,
            db: Mutex::new(db),
            system: Mutex::new(system_db),
            format,
            kms: std::sync::OnceLock::new(),
            default_encryption: options
                .default_encryption
                .unwrap_or_else(BucketEncryption::aws_default),
        };
        if let Some(kms) = options.kms {
            let _ = inner.kms.set(kms);
        }
        inner.sweep_garbage(&inner.lock())?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The drive's format record: its format version and permanent id.
    #[must_use]
    pub fn format(&self) -> &DriveFormat {
        &self.inner.format
    }

    /// The drive's folder.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    /// Gives the store its KMS after opening (a keyring named by the drive's id can only
    /// be found once the drive is open). Fails if it already has one.
    pub fn attach_kms(&self, kms: Arc<dyn Kms>) -> Result<()> {
        self.inner
            .kms
            .set(kms)
            .map_err(|_| StoreError::InvalidRequest("the store already has a KMS"))
    }

    fn kms(&self) -> Option<&dyn Kms> {
        self.inner.kms.get().map(AsRef::as_ref)
    }

    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Inner) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || f(&inner))
            .await
            .expect("storage task panicked")
    }

    /// Every bucket, by name: the drive's folders and its object buckets.
    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>> {
        self.blocking(|inner| {
            let records = inner.system().buckets()?;
            let mut buckets: Vec<BucketInfo> = records
                .iter()
                .filter(|r| r.layout == Layout::Object)
                .map(|r| BucketInfo {
                    name: r.name.clone(),
                    layout: Layout::Object,
                    created: from_ms(r.created_ms),
                })
                .collect();
            for entry in fs::read_dir(&inner.root)? {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if check_bucket(&name).is_err() {
                    continue;
                }
                let record = records.iter().find(|r| r.name == name);
                // An object bucket owns its name; a folder that has it too isn't a bucket.
                if record.is_some_and(|r| r.layout == Layout::Object) {
                    continue;
                }
                // A bucket may be a symlink to a folder elsewhere (another disk).
                let Ok(meta) = fs::metadata(entry.path()) else {
                    continue;
                };
                if meta.is_dir() {
                    let created = record
                        .map(|r| from_ms(r.created_ms))
                        .or_else(|| meta.created().ok())
                        .or_else(|| meta.modified().ok())
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    buckets.push(BucketInfo {
                        name,
                        layout: Layout::Folder,
                        created,
                    });
                }
            }
            buckets.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(buckets)
        })
        .await
    }

    /// Creates a bucket with the given layout.
    pub async fn create_bucket(&self, name: &str, layout: Layout) -> Result<()> {
        check_bucket(name)?;
        let name = name.to_owned();
        self.blocking(move |inner| {
            let _lock = inner.lock();
            let taken = inner.system().bucket(&name)?.is_some()
                || fs::symlink_metadata(inner.root.join(&name)).is_ok();
            if taken {
                return Err(StoreError::BucketExists);
            }
            let id = uuid::Uuid::new_v4().simple().to_string();
            match layout {
                Layout::Folder => match fs::create_dir(inner.root.join(&name)) {
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(StoreError::BucketExists);
                    }
                    other => {
                        other?;
                        sync_dir(&inner.root)?;
                    }
                },
                Layout::Object => {
                    let dir = inner.system_dir.join(BUCKETS_DIR).join(&id);
                    fs::create_dir_all(&dir)?;
                    sync_dir(&inner.system_dir.join(BUCKETS_DIR))?;
                }
            }
            inner.system().record_bucket(&BucketRecord {
                id,
                name,
                layout,
                created_ms: now_ms(),
            })?;
            Ok(())
        })
        .await
    }

    /// Fails with [`StoreError::NoSuchBucket`] unless the bucket exists; its layout.
    pub async fn head_bucket(&self, name: &str) -> Result<Layout> {
        let name = name.to_owned();
        self.blocking(move |inner| {
            Ok(match inner.bucket(&name)? {
                Bucket::Folder(..) => Layout::Folder,
                Bucket::Object(_) => Layout::Object,
            })
        })
        .await
    }

    /// Deletes an empty bucket, and any uploads to it left unfinished.
    pub async fn delete_bucket(&self, name: &str) -> Result<()> {
        let name = name.to_owned();
        self.blocking(move |inner| {
            let conn = inner.lock();
            match inner.bucket(&name)? {
                Bucket::Folder(_, dir) => {
                    if fs::read_dir(&dir)?.next().is_some() {
                        return Err(StoreError::BucketNotEmpty);
                    }
                    // A bucket that's a symlink goes as a symlink; its target folder stays.
                    if fs::symlink_metadata(inner.root.join(&name))?.is_symlink() {
                        fs::remove_file(inner.root.join(&name))?;
                    } else {
                        fs::remove_dir(&dir)?;
                    }
                }
                Bucket::Object(bucket) => {
                    if conn.bucket_has_versions(&bucket.id)? {
                        return Err(StoreError::BucketNotEmpty);
                    }
                    let _ = fs::remove_dir_all(&bucket.dir);
                }
            }
            let unfinished = conn.list_uploads(&name, "", None, usize::MAX)?;
            conn.forget_bucket(&name)?;
            inner.system().forget_bucket(&name)?;
            drop(conn);
            for upload in unfinished {
                let _ = fs::remove_dir_all(inner.uploads.join(&upload.id));
            }
            Ok(())
        })
        .await
    }

    /// Starts writing an object's bytes; commit them with [`Store::commit`].
    pub async fn stage(&self) -> Result<Staged> {
        Staged::create(&self.inner.tmp).await
    }

    /// Starts writing an object's bytes for `bucket`, encrypted as `encryption` asks.
    /// Encryption needs an object bucket.
    pub async fn stage_for(&self, bucket: &str, encryption: &Encryption) -> Result<Staged> {
        if matches!(encryption, Encryption::None) {
            return self.stage().await;
        }
        let name = bucket.to_owned();
        let bucket_id = self
            .blocking(move |inner| match inner.bucket(&name)? {
                Bucket::Object(bucket) => Ok(bucket.id),
                Bucket::Folder(..) => Err(StoreError::InvalidRequest(
                    "encryption at rest needs an object bucket",
                )),
            })
            .await?;
        let object_id = uuid::Uuid::now_v7().simple().to_string();
        let keyed = sse::new_key(
            self.kms(),
            encryption,
            &self.inner.format.drive,
            &bucket_id,
            &object_id,
        )
        .await?
        .ok_or(StoreError::InvalidRequest("no encryption was asked for"))?;
        Staged::create_sealed(&self.inner.tmp, keyed, bucket_id, 1).await
    }

    /// Puts staged bytes in place as `bucket`/`key`, replacing what was there.
    pub async fn commit(
        &self,
        bucket: &str,
        key: &str,
        mut staged: Staged,
        mut attrs: ObjectAttrs,
        precondition: Precondition,
    ) -> Result<ObjectInfo> {
        staged.finish().await?;
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        self.blocking(move |inner| {
            let conn = inner.lock();
            let bucket = inner.bucket(&bucket)?;
            let md5 = staged.md5();
            let (etag, sealed, stored_len) = match staged.sealing() {
                None => (teifs_types::hex(&md5), None, staged.size()),
                Some(sealing) => {
                    if !matches!(&bucket, Bucket::Object(b) if b.id == sealing.bucket_id) {
                        return Err(StoreError::InvalidRequest(
                            "the upload was encrypted for another bucket",
                        ));
                    }
                    let mut crypt = sealing.keyed.crypt.clone();
                    let key = &sealing.keyed.data_key;
                    let etag = if crypt.mode == teifs_types::SseMode::S3 {
                        teifs_types::hex(&md5)
                    } else {
                        // Checksums would say something about the plaintext.
                        if !attrs.checksums.is_empty() {
                            let json =
                                serde_json::to_vec(&attrs.checksums).expect("checksums serialize");
                            crypt.checksums = Some(base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                key.seal_metadata(&json),
                            ));
                            attrs.checksums.clear();
                        }
                        teifs_types::hex(&key.etag_for(&md5))
                    };
                    let object = crypt.object.clone();
                    let stored = teifs_crypto::ciphertext_len(staged.size());
                    (etag, Some((object, crypt)), stored)
                }
            };
            let finished = Finished {
                tmp: staged.path(),
                size: staged.size(),
                stored_len,
                etag,
                attrs,
                sealed,
                parts: None,
            };
            let info = inner.commit_to(&conn, &bucket, &key, finished, &precondition)?;
            staged.keep();
            Ok(info)
        })
        .await
    }

    /// Writes `bytes` as `bucket`/`key` (for small objects and tests).
    pub async fn put_bytes(
        &self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        attrs: ObjectAttrs,
    ) -> Result<ObjectInfo> {
        let mut staged = self.stage().await?;
        staged.write(bytes).await?;
        self.commit(bucket, key, staged, attrs, Precondition::default())
            .await
    }

    /// What's known about an object.
    pub async fn head(&self, bucket: &str, key: &str) -> Result<ObjectInfo> {
        Ok(self.read(bucket, key).await?.0)
    }

    /// An object and its bytes (`None` for a folder). The bytes are the ones `ObjectInfo`
    /// describes, even if the object is replaced while they're being read.
    pub async fn read(&self, bucket: &str, key: &str) -> Result<(ObjectInfo, Option<ObjectBody>)> {
        self.read_with(bucket, key, None).await
    }

    /// Like [`Store::read`], with the customer key an SSE-C object needs.
    pub async fn read_with(
        &self,
        bucket: &str,
        key: &str,
        customer: Option<&CustomerKey>,
    ) -> Result<(ObjectInfo, Option<ObjectBody>)> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        let (mut info, file, sealed) = self
            .blocking(move |inner| match inner.bucket(&bucket)? {
                Bucket::Folder(name, dir) => {
                    let key = ObjectKey::parse(&key).map_err(|_| StoreError::NoSuchKey)?;
                    let (info, file) = inner.open_folder_object(&name, &dir, &key)?;
                    Ok((info, file, None))
                }
                Bucket::Object(bucket) => {
                    let (row, file) = Inner::open_object(&inner.lock(), &bucket, &key)?;
                    let sealed = match objects::crypt_of(&row)? {
                        Some(crypt) => Some((crypt, bucket.id, objects::part_sizes(&row)?)),
                        None => None,
                    };
                    Ok((objects::to_info(&row), file, sealed))
                }
            })
            .await?;
        let Some((crypt, bucket_id, parts)) = sealed else {
            if customer.is_some() {
                return Err(StoreError::CustomerKeyNotApplicable);
            }
            let body = file.map(|file| ObjectBody::new(file, info.size, None));
            return Ok((info, body));
        };
        let data_key = sse::data_key(
            self.kms(),
            &crypt,
            &self.inner.format.drive,
            &bucket_id,
            customer,
        )
        .await?;
        if let Some(sealed) = &crypt.checksums {
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sealed)
                .map_err(|_| StoreError::CorruptMetadata)?;
            let json = data_key.open_metadata(&bytes)?;
            info.attrs.checksums =
                serde_json::from_slice(&json).map_err(|_| StoreError::CorruptMetadata)?;
        }
        info.sse = Some(crypt.info(customer.map(CustomerKey::md5_base64)));
        let body = file.map(|file| {
            ObjectBody::new(
                file,
                info.size,
                Some(body::Decrypt {
                    key: data_key,
                    parts,
                }),
            )
        });
        Ok((info, body))
    }

    /// Deletes an object. Deleting one that doesn't exist succeeds, as in S3.
    pub async fn delete(&self, bucket: &str, key: &str) -> Result<()> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        self.blocking(move |inner| {
            let conn = inner.lock();
            match inner.bucket(&bucket)? {
                Bucket::Folder(name, dir) => match ObjectKey::parse(&key) {
                    Ok(key) => Inner::delete_folder_object(&conn, &name, &dir, &key),
                    Err(_) => Ok(()),
                },
                Bucket::Object(bucket) => Inner::delete_object(&conn, &bucket, &key),
            }
        })
        .await
    }

    /// Copies an object. `attrs` replaces its attributes (S3's `REPLACE` directive);
    /// `None` keeps them. Copying an object onto itself needs new attributes.
    pub async fn copy(
        &self,
        from: (&str, &str),
        to: (&str, &str),
        attrs: Option<ObjectAttrs>,
        precondition: Precondition,
    ) -> Result<ObjectInfo> {
        self.copy_with(from, to, attrs, precondition, None, &Encryption::None)
            .await
    }

    /// Copies an object, reading an SSE-C source with `source_key` and encrypting the
    /// copy as `encryption` asks (as S3 does, the copy doesn't inherit the source's
    /// encryption). Unencrypted copies clone the bytes where the disk can; anything
    /// encrypted is decrypted and encrypted again under the copy's own key.
    pub async fn copy_with(
        &self,
        from: (&str, &str),
        to: (&str, &str),
        attrs: Option<ObjectAttrs>,
        precondition: Precondition,
        source_key: Option<&CustomerKey>,
        encryption: &Encryption,
    ) -> Result<ObjectInfo> {
        let (src_bucket, src_key) = (from.0.to_owned(), from.1.to_owned());
        let (dst_bucket, dst_key) = (to.0.to_owned(), to.1.to_owned());
        let source_encrypted = {
            let (bucket, key) = (src_bucket.clone(), src_key.clone());
            self.blocking(move |inner| match inner.bucket(&bucket)? {
                Bucket::Object(b) => Ok(Inner::object_row(&inner.lock(), &b, &key)?
                    .is_some_and(|row| row.crypt.is_some())),
                Bucket::Folder(..) => Ok(false),
            })
            .await?
        };
        let same = src_bucket == dst_bucket && src_key == dst_key;
        if source_encrypted || source_key.is_some() || !matches!(encryption, Encryption::None) {
            if same && attrs.is_none() && matches!(encryption, Encryption::None) {
                return Err(StoreError::InvalidRequest(
                    "copying an object onto itself needs new metadata or encryption",
                ));
            }
            return self
                .copy_through(from, to, attrs, precondition, source_key, encryption)
                .await;
        }
        self.blocking(move |inner| {
            let (src, dst) = (inner.bucket(&src_bucket)?, inner.bucket(&dst_bucket)?);
            match (&src, &dst) {
                (Bucket::Folder(src_name, _), Bucket::Folder(dst_name, _)) => {
                    let src_key = ObjectKey::parse(&src_key).map_err(|_| StoreError::NoSuchKey)?;
                    let dst_key = ObjectKey::parse(&dst_key)?;
                    inner.copy_folder(src_name, &src_key, dst_name, &dst_key, attrs, &precondition)
                }
                (Bucket::Object(a), Bucket::Object(b)) if a.id == b.id && same => {
                    let attrs = attrs.ok_or(StoreError::InvalidRequest(
                        "copying an object onto itself needs new metadata",
                    ))?;
                    Inner::replace_object_attrs(&inner.lock(), a, &src_key, &attrs, &precondition)
                }
                _ => inner.copy_across(&src, &src_key, &dst, &dst_key, attrs, &precondition),
            }
        })
        .await
    }

    /// Copies by reading (decrypting) the source and writing (encrypting) the copy.
    async fn copy_through(
        &self,
        from: (&str, &str),
        to: (&str, &str),
        attrs: Option<ObjectAttrs>,
        precondition: Precondition,
        source_key: Option<&CustomerKey>,
        encryption: &Encryption,
    ) -> Result<ObjectInfo> {
        use tokio::io::AsyncReadExt;
        let (source, body) = self.read_with(from.0, from.1, source_key).await?;
        let mut staged = self.stage_for(to.0, encryption).await?;
        if let Some(body) = body {
            let mut reader = body.all().await?;
            let mut buf = vec![0; 256 * 1024];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                staged.write(&buf[..n]).await?;
            }
        }
        let attrs = attrs.unwrap_or(source.attrs);
        self.commit(to.0, to.1, staged, attrs, precondition).await
    }
}

impl Inner {
    fn system(&self) -> MutexGuard<'_, System> {
        self.system
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock(&self) -> MutexGuard<'_, Index> {
        // A panic while holding it can't leave a half-applied change: every change is one
        // transaction or one rename.
        self.db
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn system_dir(&self) -> &Path {
        &self.system_dir
    }

    /// Resolves a bucket: an object bucket by its record, else a folder at the root.
    fn bucket(&self, name: &str) -> Result<Bucket> {
        if check_bucket(name).is_err() {
            return Err(StoreError::NoSuchBucket);
        }
        if let Some(record) = self.system().bucket(name)?
            && record.layout == Layout::Object
        {
            return Ok(Bucket::Object(ObjectBucket {
                dir: self.system_dir.join(BUCKETS_DIR).join(&record.id),
                id: record.id,
            }));
        }
        Ok(Bucket::Folder(name.to_owned(), self.bucket_dir(name)?))
    }

    /// The bucket's folder, resolved (a bucket may be a symlink to a folder elsewhere).
    fn bucket_dir(&self, name: &str) -> Result<PathBuf> {
        if check_bucket(name).is_err() {
            return Err(StoreError::NoSuchBucket);
        }
        let dir = fs::canonicalize(self.root.join(name))
            .map_err(|e| not_found_as(e, StoreError::NoSuchBucket))?;
        if !dir.is_dir() {
            return Err(StoreError::NoSuchBucket);
        }
        Ok(dir)
    }

    /// Makes finished bytes the object `key` in `bucket`. Holds the commit lock (`conn`).
    fn commit_to(
        &self,
        conn: &Index,
        bucket: &Bucket,
        key: &str,
        finished: Finished<'_>,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        match bucket {
            Bucket::Folder(name, _) => {
                if finished.sealed.is_some() {
                    return Err(StoreError::InvalidRequest(
                        "encryption at rest needs an object bucket",
                    ));
                }
                let key = ObjectKey::parse(key)?;
                if key.is_folder() {
                    if finished.size > 0 {
                        return Err(StoreError::InvalidRequest(
                            "a folder (a key ending in `/`) can't have content",
                        ));
                    }
                    return self.make_folder(conn, name, &key, finished.attrs, precondition);
                }
                // A copied file may have leftovers (an object bucket's footer) to cut off.
                fs::OpenOptions::new()
                    .write(true)
                    .open(finished.tmp)?
                    .set_len(finished.stored_len)?;
                self.commit_file(
                    conn,
                    name,
                    &key,
                    finished.tmp,
                    finished.etag,
                    finished.attrs,
                    precondition,
                )
            }
            Bucket::Object(bucket) => {
                Inner::commit_object(conn, bucket, key, finished, precondition)
            }
        }
    }

    /// Copies between buckets of different layouts, or between object buckets: the bytes
    /// are cloned where the disk can (APFS, Btrfs, XFS), else copied.
    fn copy_across(
        &self,
        src: &Bucket,
        src_key: &str,
        dst: &Bucket,
        dst_key: &str,
        attrs: Option<ObjectAttrs>,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let tmp = TmpFile::new(&self.tmp);
        let source = match src {
            Bucket::Folder(name, dir) => {
                let key = ObjectKey::parse(src_key).map_err(|_| StoreError::NoSuchKey)?;
                match Inner::find(dir, &key)? {
                    Found::File(path, meta) => {
                        fs::copy(&path, &tmp.path)?;
                        Inner::info(&self.lock(), name, key.as_str(), &meta)?
                    }
                    Found::Folder(_, meta) => {
                        fs::File::create(&tmp.path)?;
                        Inner::info(&self.lock(), name, key.as_str(), &meta)?
                    }
                    Found::Missing | Found::Other => return Err(StoreError::NoSuchKey),
                }
            }
            Bucket::Object(bucket) => {
                // Under the commit lock, so the file can't be replaced and removed mid-copy.
                let conn = self.lock();
                let row =
                    Inner::object_row(&conn, bucket, src_key)?.ok_or(StoreError::NoSuchKey)?;
                match &row.object_id {
                    Some(id) => fs::copy(bucket.data_path(id), &tmp.path).map(drop)?,
                    None => fs::File::create(&tmp.path).map(drop)?,
                }
                objects::to_info(&row)
            }
        };
        // A copy's ETag is its MD5; a known one carries over, else it's worked out now.
        let etag = match teifs_types::md5_of_etag(&source.etag) {
            Some(_) => source.etag.clone(),
            None => teifs_types::hex(&md5_file(&tmp.path)?),
        };
        let attrs = attrs.unwrap_or(source.attrs);
        let conn = self.lock();
        let finished = Finished::plain(&tmp.path, source.size, etag, attrs);
        let info = self.commit_to(&conn, dst, dst_key, finished, precondition)?;
        tmp.keep();
        Ok(info)
    }
}

/// A time in milliseconds since the Unix epoch.
fn from_ms(ms: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(u64::try_from(ms).unwrap_or(0))
}

/// Removes what writes to buckets on other disks left staged when the last run stopped.
fn sweep_bucket_staging(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let staging = entry.path().join(teifs_types::BUCKET_STAGING);
        if staging.is_dir() {
            let _ = fs::remove_dir_all(staging);
        }
    }
}

/// The MD5 of a file's bytes.
fn md5_file(path: &Path) -> Result<[u8; 16]> {
    use io::Read;
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0; 256 * 1024];
    loop {
        match file.read(&mut buf)? {
            0 => return Ok(hasher.finalize().into()),
            n => hasher.update(&buf[..n]),
        }
    }
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod layout_tests;
#[cfg(test)]
mod sse_tests;
#[cfg(test)]
mod tests;
