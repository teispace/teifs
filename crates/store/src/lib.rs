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
mod cache;
pub mod checksum;
mod diagnose;
mod error;
mod filesystem;
mod folder;
mod folder_versions;
mod folders;
mod format;
mod jobs;
mod lifecycle;
mod list;
mod lock;
mod multipart;
mod objects;
mod reconcile;
mod repair;
mod rewrap;
mod settings;
mod snapshots;
mod space;
mod sse;
mod staged;
mod stages;
#[cfg(test)]
mod test_util;
mod usage;
mod verify;

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use teifs_meta::{BucketRecord, Index, System};

pub use body::{BodyReader, ObjectBody};
pub use diagnose::{Database, Diagnosis, diagnose};
pub use error::{Result, StoreError};
pub use filesystem::remote_file_system;
pub use format::{DriveFormat, FORMAT};
pub use jobs::{Expirations, JobOptions, JobStatus, Jobs};
pub use lifecycle::{
    And, Condition, DAY_MS, Expiration, Expiry, Lifecycle, LifecycleRule, MAX_LIFECYCLE_RULES,
    MAX_NEWER_NONCURRENT, MAX_RULE_ID_LEN, NoncurrentExpiration, RuleFilter, Tag,
};
pub use list::{After, ListQuery, Listing, ObjectVersion, VersionListing, VersionsQuery};
pub use lock::{
    DefaultRetention, MAX_RETENTION_DAYS, MAX_RETENTION_YEARS, ObjectLock, RetentionPeriod,
};
pub use multipart::{CompleteWith, MAX_PART_NUMBER, MIN_PART_SIZE};
pub use repair::{Finding, Repair, RepairOptions, RepairReport, Stray};
pub use rewrap::Rewrapped;
pub use settings::{
    BucketAccess, BucketEncryption, BucketSettings, CorsRule, DefaultEncryption, NewBucket,
    ObjectOwnership, PublicAccessBlock,
};
pub use snapshots::{Restored, restore};
pub use space::{Disk, Health};
pub use sse::Encryption;
pub use staged::Staged;
pub use stages::{Stage, StageTimes};
pub use teifs_crypto::{
    AwsKms, CryptoError, CustomerKey, DEFAULT_KEY, DefaultKeyNamed, KesAuth, KesKms, Kms, LocalKms,
    TransitKms, create_private, replace_private,
};
pub use teifs_meta::{Layout, Part, Upload, Usage, Versioning};
pub use teifs_types::admin::Snapshot;
pub use teifs_types::{
    Acl, AclGrant, ChecksumType, Grantee, LockMode, OWNER_ID, PartInfo, Permission, Retention,
    SseInfo, SseMode, UploadChecksum,
};
pub use teifs_types::{MAX_KEY_LEN, NameError, ObjectAttrs, ObjectInfo, ObjectKey, check_bucket};
use teifs_types::{check_folder_bucket, configs::Configurations};
pub use usage::BucketUsage;
pub use verify::{Checked, Damage, Unverifiable, Verdict, VerifyCursor};

use error::not_found_as;
use folder::{FolderBucket, Found};
pub use objects::Deleted;
use objects::{BUCKETS_DIR, Finished, ObjectBucket};
use staged::{TmpFile, sync_dir};

/// The folder in a drive's root that holds TeiFS's own data.
pub const SYSTEM_DIR: &str = ".teifs";

/// An object found for reading: what's known, its file (`None` for a folder), and for an
/// encrypted one how, its bucket's id and its parts (sizes and keys).
type Located = (
    ObjectInfo,
    Option<fs::File>,
    Option<(sse::Crypt, String, Vec<(u64, teifs_crypto::PartId)>)>,
);

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
    /// A folder bucket.
    Folder(FolderBucket),
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
    /// Deletes only: the object must have this size (`x-amz-if-match-size`).
    pub if_size: Option<u64>,
    /// Deletes only: the object must have been modified at this second
    /// (`x-amz-if-match-last-modified-time`).
    pub if_modified_at: Option<SystemTime>,
    /// Renames only: the object must exist and have changed after this time.
    pub if_modified_since: Option<SystemTime>,
    /// Renames only: the object must exist and not have changed after this time.
    pub if_unmodified_since: Option<SystemTime>,
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
    /// Whether it has any condition.
    fn is_conditional(&self) -> bool {
        *self != Self::default()
    }

    /// Whether the write may only create the object (`If-None-Match: *`).
    fn creates_only(&self) -> bool {
        self.if_none_match == Some(Match::Any)
    }

    /// Checks a write against the object it would replace. As on AWS, `If-Match` on an
    /// object that doesn't exist is `NoSuchKey`, not a failed precondition.
    fn check(&self, current: Option<&ObjectInfo>) -> Result<()> {
        if self.if_match.is_some() && current.is_none() {
            return Err(StoreError::NoSuchKey);
        }
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

    /// Whether a rename's source or destination meets these conditions. Any condition
    /// but `If-None-Match` needs the object to exist; `If-None-Match: *` needs it not to.
    fn holds(&self, current: Option<&ObjectInfo>) -> bool {
        let seconds = |t: SystemTime| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        };
        let needs_existing = self.if_match.is_some()
            || self.if_modified_since.is_some()
            || self.if_unmodified_since.is_some();
        match current {
            // Nothing there: only conditions that need an object fail.
            None => !needs_existing,
            Some(info) => {
                self.if_match.as_ref().is_none_or(|m| m.matches(info))
                    && self.if_none_match.as_ref().is_none_or(|m| !m.matches(info))
                    && self
                        .if_modified_since
                        .is_none_or(|t| seconds(info.modified) > seconds(t))
                    && self
                        .if_unmodified_since
                        .is_none_or(|t| seconds(info.modified) <= seconds(t))
            }
        }
    }

    /// Checks a delete: whether to go ahead (`false` when there's nothing to delete,
    /// which succeeds whatever the conditions, as on AWS).
    fn check_delete(&self, current: Option<&ObjectInfo>) -> Result<bool> {
        let Some(info) = current else {
            return Ok(false);
        };
        let seconds = |t: SystemTime| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        };
        let ok = self.if_match.as_ref().is_none_or(|m| m.matches(info))
            && self.if_size.is_none_or(|size| size == info.size)
            && self
                .if_modified_at
                .is_none_or(|t| seconds(t) == seconds(info.modified));
        if ok {
            Ok(true)
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
    /// How hard writes are made to survive a power cut.
    durability: Durability,
    /// Which names folder buckets may create.
    key_rules: KeyRules,
    /// The drive's lock: one process at a time.
    _lock: fs::File,
    /// Large folders' sorted contents, for folder-bucket listings.
    folders: folders::FolderCache,
    uploads: PathBuf,
    /// The index, also the commit lock: whoever changes a file holds it until the file
    /// and its row agree again.
    db: Mutex<Index>,
    /// The system database. Taken after `db` when both are needed.
    system: Mutex<System>,
    format: DriveFormat,
    /// Seals and unseals the data keys of encrypted objects (set once, at or after open).
    kms: std::sync::OnceLock<teifs_crypto::Measured>,
    /// Told what the lifecycle job removes (set once, after open), while whoever set it
    /// keeps it: a listener that holds the store doesn't keep the drive open for ever.
    expirations: std::sync::OnceLock<std::sync::Weak<dyn jobs::Expirations>>,
    /// The encryption settings of object buckets that have none of their own.
    default_encryption: BucketEncryption,
    /// What each background job has done since the drive opened.
    jobs: jobs::StatusMap,
    /// Held while a snapshot is written or old ones are removed, so a prune never
    /// takes a snapshot being written for one in progress.
    snapshots: Mutex<()>,
    /// Buckets' lifecycle configurations, read once.
    lifecycles: cache::SettingCache<lifecycle::Lifecycle>,
    /// Buckets' notification rules, read once.
    notifications: cache::SettingCache<teifs_types::notify::NotificationConfig>,
    /// Buckets' access logging, read once.
    logging: cache::SettingCache<teifs_types::logging::LoggingConfig>,
    /// Buckets' website configurations, read once.
    websites: cache::SettingCache<teifs_types::website::WebsiteConfig>,
    /// Buckets' quotas, read once.
    quotas: cache::SettingCache<u64>,
    /// Buckets' Requester Pays and reporting configurations, read once.
    configurations: cache::SettingCache<Configurations>,
    /// How long a lifecycle "day" is, in milliseconds (shorter only in tests).
    day_ms: i64,
    /// How long each stage of reads and writes takes.
    stages: stages::StageTimes,
}

/// How hard a write is made to survive a power cut before it's acknowledged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Durability {
    /// File data, folder entries and the index are synced before a write is
    /// acknowledged: nothing acknowledged is lost.
    #[default]
    Strict,
    /// File data is synced; folder entries and the index are left to the operating
    /// system. A power cut can lose the last moments' writes, and never corrupts.
    Relaxed,
    /// Nothing is synced (scratch data): a power cut can lose recent writes, and still
    /// never corrupts.
    None,
}

/// Which names TeiFS may create in folder buckets. Object buckets store keys by id, so
/// they take any key S3 allows either way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KeyRules {
    /// Only names every supported system can hold (Windows' rules everywhere), so the
    /// drive can move between systems.
    #[default]
    Portable,
    /// Whatever this system can hold. Files written this way may be unreachable, or
    /// reach something else, on another system.
    Host,
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
    /// How hard writes are made to survive a power cut.
    pub durability: Durability,
    /// Which names folder buckets may create.
    pub key_rules: KeyRules,
    /// How long a day is for lifecycle rules; `None` is a real day. Shorter days are
    /// for testing rules without waiting.
    pub lifecycle_day: Option<std::time::Duration>,
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
        fs::create_dir_all(&system_dir)?;
        // One process per drive, before touching anything another might be using.
        let lock = lock_drive(&system_dir)?;
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
        db.set_synchronous(match options.durability {
            Durability::Strict => "FULL",
            Durability::Relaxed => "NORMAL",
            Durability::None => "OFF",
        })?;
        let system_db = System::open(&system_dir.join(format::SYSTEM_DB))?;
        let inner = Inner {
            root,
            system_dir,
            tmp,
            durability: options.durability,
            key_rules: options.key_rules,
            _lock: lock,
            folders: folders::FolderCache::default(),
            uploads,
            db: Mutex::new(db),
            system: Mutex::new(system_db),
            format,
            kms: std::sync::OnceLock::new(),
            expirations: std::sync::OnceLock::new(),
            jobs: jobs::StatusMap::default(),
            snapshots: Mutex::new(()),
            lifecycles: cache::SettingCache::default(),
            notifications: cache::SettingCache::default(),
            logging: cache::SettingCache::default(),
            websites: cache::SettingCache::default(),
            quotas: cache::SettingCache::default(),
            configurations: cache::SettingCache::default(),
            stages: stages::new(),
            day_ms: options.lifecycle_day.map_or(lifecycle::DAY_MS, |day| {
                i64::try_from(day.as_millis()).unwrap_or(i64::MAX).max(1)
            }),
            default_encryption: options
                .default_encryption
                .unwrap_or_else(BucketEncryption::aws_default),
        };
        if let Some(kms) = options.kms {
            let _ = inner.kms.set(teifs_crypto::Measured::new(kms));
        }
        inner.sweep_garbage(&inner.lock(), usize::MAX)?;
        // Retries come within minutes; a day of tokens is plenty.
        inner
            .lock()
            .expire_client_tokens(now_ms() - 24 * 60 * 60 * 1000)?;
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

    /// Where bucket notifications wait to be sent.
    #[must_use]
    pub fn events_db(&self) -> PathBuf {
        self.inner.system_dir.join(format::EVENTS_DB)
    }

    /// Where buckets' access log records wait to be delivered.
    #[must_use]
    pub fn access_log_dir(&self) -> PathBuf {
        self.inner.system_dir.join(format::ACCESS_LOGS)
    }

    /// The drive's system database, which IAM keeps its state in too.
    #[must_use]
    pub fn system_db(&self) -> PathBuf {
        self.inner.system_dir.join(format::SYSTEM_DB)
    }

    /// Gives the store its KMS after opening (a keyring named by the drive's id can only
    /// be found once the drive is open). Fails if it already has one.
    pub fn attach_kms(&self, kms: Arc<dyn Kms>) -> Result<()> {
        self.inner
            .kms
            .set(teifs_crypto::Measured::new(kms))
            .map_err(|_| StoreError::InvalidRequest("the store already has a KMS"))
    }

    /// Tells `to` what the lifecycle job removes from now on, for as long as the caller
    /// keeps `to`. Fails if it's told something else already.
    pub fn tell_expirations(&self, to: &Arc<dyn Expirations>) -> Result<()> {
        self.inner
            .expirations
            .set(Arc::downgrade(to))
            .map_err(|_| StoreError::InvalidRequest("the store already tells expirations"))
    }

    /// Tells whoever wants to know that the lifecycle job removed something.
    async fn expired(&self, bucket: &str, key: &str, version_id: Option<String>, marker: bool) {
        if let Some(to) = self
            .inner
            .expirations
            .get()
            .and_then(std::sync::Weak::upgrade)
        {
            to.expired(bucket, key, version_id, marker).await;
        }
    }

    /// The KMS the drive's keys are sealed with, once it has one.
    #[must_use]
    pub fn kms(&self) -> Option<&dyn Kms> {
        self.inner.kms.get().map(|kms| kms as &dyn Kms)
    }

    /// What the KMS's calls have come to since the store was opened, if it has one.
    #[must_use]
    pub fn kms_metrics(&self) -> Option<teifs_crypto::KmsMetrics> {
        self.inner.kms.get().map(teifs_crypto::Measured::metrics)
    }

    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Inner) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = Arc::clone(&self.inner);
        // What's logged there belongs to the request (its span) that asked.
        let span = tracing::Span::current();
        tokio::task::spawn_blocking(move || span.in_scope(|| f(&inner)))
            .await
            .expect("storage task panicked")
    }

    /// Every bucket, by name: the drive's folders and its object buckets.
    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>> {
        self.blocking(Inner::buckets).await
    }

    /// Creates a bucket with the given layout.
    pub async fn create_bucket(&self, name: &str, layout: Layout) -> Result<()> {
        self.create_bucket_with(name, layout, NewBucket::default())
            .await
    }

    /// Creates a bucket with its first settings, recorded with it.
    pub async fn create_bucket_with(
        &self,
        name: &str,
        layout: Layout,
        options: NewBucket,
    ) -> Result<()> {
        match layout {
            Layout::Object => check_bucket(name)?,
            Layout::Folder => {
                check_folder_bucket(name, self.inner.key_rules == KeyRules::Portable)?;
            }
        }
        let name = name.to_owned();
        // Object Lock needs versioning, which it turns on for good.
        let versioning = if options.object_lock {
            Versioning::Enabled
        } else {
            Versioning::Unversioned
        };
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
            inner.system().record_bucket(
                &BucketRecord {
                    id,
                    name,
                    layout,
                    created_ms: now_ms(),
                    versioning,
                },
                &settings::new_bucket_config(options),
            )?;
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
                Bucket::Folder(FolderBucket { dir, versions, .. }) => {
                    if fs::read_dir(&dir)?.next().is_some() {
                        return Err(StoreError::BucketNotEmpty);
                    }
                    if let Some(versions) = versions {
                        if conn.bucket_has_versions(&versions.id)? {
                            return Err(StoreError::BucketNotEmpty);
                        }
                        let _ = fs::remove_dir_all(&versions.dir);
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
            inner.settings_changed();
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
        let since = std::time::Instant::now();
        let keyed = sse::new_key(
            self.kms(),
            encryption,
            &self.inner.format.drive,
            &bucket_id,
            &object_id,
        )
        .await?
        .ok_or(StoreError::InvalidRequest("no encryption was asked for"))?;
        stages::record(&self.inner.stages, "write", "key", since);
        Staged::create_sealed(
            &self.inner.tmp,
            keyed,
            bucket_id,
            teifs_crypto::PartId::from(1),
        )
        .await
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
            let waited = std::time::Instant::now();
            let conn = inner.lock();
            stages::record(&inner.stages, "write", "lock", waited);
            let since = std::time::Instant::now();
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
                            crypt.checksums = Some(sse::seal_sums(key, &attrs.checksums));
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
            stages::record(&inner.stages, "write", "commit", since);
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

    /// What's known about an object without opening its encryption: no key is needed,
    /// and checksums sealed under SSE-KMS or SSE-C are left out.
    pub async fn head(&self, bucket: &str, key: &str) -> Result<ObjectInfo> {
        self.head_version(bucket, key, None).await
    }

    /// Like [`Store::head`], for a version of the object (`None`: the current one).
    pub async fn head_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<ObjectInfo> {
        let (mut info, _, sealed) = self.locate(bucket, key, version_id).await?;
        if let Some((crypt, ..)) = sealed {
            info.sse = Some(crypt.info(None));
            for part in &mut info.parts {
                part.checksums = sse::open_part_sums(None, std::mem::take(&mut part.checksums))?;
            }
        }
        Ok(info)
    }

    /// Finds a version of an object for reading (`None`: the current one).
    async fn locate(&self, bucket: &str, key: &str, version_id: Option<&str>) -> Result<Located> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        let version_id = version_id.map(str::to_owned);
        self.blocking(move |inner| match inner.bucket(&bucket)? {
            Bucket::Folder(bucket) => {
                let key = ObjectKey::parse(&key).map_err(|_| StoreError::NoSuchKey)?;
                let (info, file) =
                    inner.open_folder_object(&bucket, &key, version_id.as_deref())?;
                Ok((info, file, None))
            }
            Bucket::Object(bucket) => {
                let (row, file) =
                    Inner::open_object(&inner.lock(), &bucket, &key, version_id.as_deref())?;
                let sealed = match objects::crypt_of(&row)? {
                    Some(crypt) => Some((crypt, bucket.id.clone(), objects::sealed_parts(&row)?)),
                    None => None,
                };
                Ok((bucket.info(&row), file, sealed))
            }
        })
        .await
    }

    /// An object and its bytes (`None` for a folder). The bytes are the ones `ObjectInfo`
    /// describes, even if the object is replaced while they're being read.
    pub async fn read(&self, bucket: &str, key: &str) -> Result<(ObjectInfo, Option<ObjectBody>)> {
        self.read_with(bucket, key, None, None).await
    }

    /// Like [`Store::read`], for a version of the object (`None`: the current one), with
    /// the customer key an SSE-C object needs.
    pub async fn read_with(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        customer: Option<&CustomerKey>,
    ) -> Result<(ObjectInfo, Option<ObjectBody>)> {
        let since = std::time::Instant::now();
        let (mut info, file, sealed) = self.locate(bucket, key, version_id).await?;
        stages::record(&self.inner.stages, "read", "locate", since);
        let Some((crypt, bucket_id, parts)) = sealed else {
            if customer.is_some() {
                return Err(StoreError::CustomerKeyNotApplicable);
            }
            let body = file.map(|file| ObjectBody::new(file, info.size, None));
            return Ok((info, body));
        };
        let since = std::time::Instant::now();
        let data_key = sse::data_key(
            self.kms(),
            &crypt,
            &self.inner.format.drive,
            &bucket_id,
            customer,
        )
        .await?;
        let outer =
            sse::outer_key(self.kms(), &crypt, &self.inner.format.drive, &bucket_id).await?;
        stages::record(&self.inner.stages, "read", "key", since);
        if let Some(sealed) = &crypt.checksums {
            info.attrs.checksums = sse::open_sums(&data_key, sealed)?;
        }
        for part in &mut info.parts {
            part.checksums =
                sse::open_part_sums(Some(&data_key), std::mem::take(&mut part.checksums))?;
        }
        info.sse = Some(crypt.info(customer.map(CustomerKey::md5_base64)));
        let body = file.map(|file| {
            ObjectBody::new(
                file,
                info.size,
                Some(body::Decrypt {
                    key: data_key,
                    outer,
                    parts,
                }),
            )
        });
        Ok((info, body))
    }

    /// Replaces the tags of a version of an object (`None`: the current one). Its bytes,
    /// ETag and modification time don't change.
    pub async fn set_tags(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        tags: std::collections::BTreeMap<String, String>,
    ) -> Result<ObjectInfo> {
        self.change_attrs(bucket, key, version_id, move |attrs| {
            attrs.tags = tags;
            Ok(())
        })
        .await
    }

    /// Replaces the ACL of a version of an object (`None`: the current one; an ACL of
    /// `None`: private). Its bytes, ETag and modification time don't change.
    pub async fn set_acl(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        acl: Option<Acl>,
    ) -> Result<ObjectInfo> {
        self.change_attrs(bucket, key, version_id, move |attrs| {
            attrs.acl = acl;
            Ok(())
        })
        .await
    }

    /// Changes the attributes of a version of an object in place, if `change` allows.
    async fn change_attrs(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        change: impl FnOnce(&mut ObjectAttrs) -> Result<()> + Send + 'static,
    ) -> Result<ObjectInfo> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        let version_id = version_id.map(str::to_owned);
        self.blocking(move |inner| match inner.bucket(&bucket)? {
            Bucket::Folder(bucket) => {
                let key = ObjectKey::parse(&key).map_err(|_| StoreError::NoSuchKey)?;
                inner.change_folder_attrs(&bucket, &key, version_id.as_deref(), change)
            }
            Bucket::Object(bucket) => {
                let conn = inner.lock();
                let mut row = Inner::version_row(&conn, &bucket, &key, version_id.as_deref())?;
                change(&mut row.attrs)?;
                conn.set_version_attrs(&bucket.id, &key, &row.version_id, &row.attrs, None)?;
                Ok(bucket.info(&row))
            }
        })
        .await
    }

    /// Deletes an object. Deleting one that doesn't exist succeeds, as in S3.
    pub async fn delete(&self, bucket: &str, key: &str) -> Result<()> {
        self.delete_if(bucket, key, None, Precondition::default())
            .await
            .map(drop)
    }

    /// Deletes an object if it meets `precondition` (`If-Match`, size, modification
    /// time), as the bucket's versioning says ([`Inner::delete_object`]); with a
    /// version id, removes that version for good. One that doesn't exist is gone
    /// already, which succeeds.
    pub async fn delete_if(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        precondition: Precondition,
    ) -> Result<Deleted> {
        self.delete_with(bucket, key, version_id, precondition, false)
            .await
    }

    /// Like [`Store::delete_if`]; removing a version that a governance-mode retention
    /// protects needs `bypass` (the caller may `s3:BypassGovernanceRetention` and asked).
    /// Nothing removes a version under a legal hold or a compliance-mode retention.
    pub async fn delete_with(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        precondition: Precondition,
        bypass: bool,
    ) -> Result<Deleted> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        let version_id = version_id.map(str::to_owned);
        self.blocking(move |inner| {
            let conn = inner.lock();
            match inner.bucket(&bucket)? {
                Bucket::Folder(bucket) => {
                    let Ok(key) = ObjectKey::parse(&key) else {
                        return Ok(Deleted::default());
                    };
                    match (version_id, bucket.versioned()) {
                        (Some(id), _) => inner.delete_folder_version(
                            &conn,
                            &bucket,
                            &key,
                            &id,
                            &precondition,
                            bypass,
                        ),
                        (None, Some(versions)) => inner.delete_folder_versioned(
                            &conn,
                            &bucket,
                            versions,
                            &key,
                            &precondition,
                        ),
                        (None, None) => {
                            let current = match Inner::find(&bucket.dir, &key)? {
                                Found::File(_, meta) | Found::Folder(_, meta) => {
                                    Some(Inner::info(&conn, &bucket.name, key.as_str(), &meta)?)
                                }
                                Found::Missing | Found::Other => None,
                            };
                            if precondition.check_delete(current.as_ref())? {
                                Inner::delete_folder_object(
                                    &conn,
                                    &bucket.name,
                                    &bucket.dir,
                                    &key,
                                )?;
                            }
                            Ok(Deleted::default())
                        }
                    }
                }
                Bucket::Object(bucket) => match version_id {
                    None => Inner::delete_object(&conn, &bucket, &key, &precondition),
                    Some(id) => Inner::delete_object_version(
                        &conn,
                        &bucket,
                        &key,
                        &id,
                        &precondition,
                        bypass,
                    ),
                },
            }
        })
        .await
    }

    /// Renames `from` to `to` in one bucket, keeping the bytes, metadata and encryption:
    /// a rename of the file in a folder bucket, of the row in an object bucket. The
    /// source must meet `source`, the destination `destination` (412 otherwise). A
    /// repeated request with the same `client_token` does nothing more; the same token
    /// with other parameters is refused.
    pub async fn rename(
        &self,
        bucket: &str,
        from: &str,
        to: &str,
        source: Precondition,
        destination: Precondition,
        client_token: Option<String>,
    ) -> Result<()> {
        let (bucket, from, to) = (bucket.to_owned(), from.to_owned(), to.to_owned());
        self.blocking(move |inner| {
            let conn = inner.lock();
            let request = format!("rename\n{bucket}\n{from}\n{to}");
            if let Some(token) = &client_token {
                match conn.client_token(token)? {
                    Some(done) if done == request => return Ok(()),
                    Some(_) => return Err(StoreError::IdempotencyMismatch),
                    None => {}
                }
            }
            match inner.bucket(&bucket)? {
                Bucket::Folder(FolderBucket {
                    name,
                    dir,
                    versions,
                }) => {
                    if versions.is_some_and(|v| v.versioning != Versioning::Unversioned) {
                        return Err(StoreError::InvalidRequest(
                            "objects can't be renamed in a bucket with versioning",
                        ));
                    }
                    let src = ObjectKey::parse(&from).map_err(|_| StoreError::NoSuchKey)?;
                    let dst = inner.new_key(&to)?;
                    inner.rename_folder_object(
                        &conn,
                        &name,
                        &dir,
                        &src,
                        &dst,
                        &source,
                        &destination,
                    )?;
                }
                Bucket::Object(bucket) => {
                    if bucket.versioning != Versioning::Unversioned {
                        return Err(StoreError::InvalidRequest(
                            "objects can't be renamed in a bucket with versioning",
                        ));
                    }
                    teifs_types::check_object_key(&to)?;
                    let current =
                        Inner::object_row(&conn, &bucket, &from)?.ok_or(StoreError::NoSuchKey)?;
                    let target = Inner::object_row(&conn, &bucket, &to)?;
                    let info = |row: &teifs_meta::VersionRow| bucket.info(row);
                    if !source.holds(Some(&info(&current)))
                        || !destination.holds(target.as_ref().map(info).as_ref())
                    {
                        return Err(StoreError::PreconditionFailed);
                    }
                    if from != to {
                        let replaced =
                            conn.rename_null_version(&bucket.id, &from, &to, now_ms())?;
                        Inner::remove_data_files(&conn, &bucket, &replaced);
                    }
                }
            }
            if let Some(token) = &client_token {
                conn.record_client_token(token, &request, now_ms())?;
            }
            Ok(())
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
        let from = (from.0, from.1, None);
        self.copy_with(from, to, attrs, precondition, None, &Encryption::None)
            .await
    }

    /// Copies a version of an object (`from`'s third part; `None`: the current one),
    /// reading an SSE-C source with `source_key` and encrypting the copy as `encryption`
    /// asks (as S3 does, the copy doesn't inherit the source's encryption). Unencrypted
    /// copies clone the bytes where the disk can; anything encrypted is decrypted and
    /// encrypted again under the copy's own key.
    pub async fn copy_with(
        &self,
        from: (&str, &str, Option<&str>),
        to: (&str, &str),
        attrs: Option<ObjectAttrs>,
        precondition: Precondition,
        source_key: Option<&CustomerKey>,
        encryption: &Encryption,
    ) -> Result<ObjectInfo> {
        let (src_bucket, src_key) = (from.0.to_owned(), from.1.to_owned());
        let src_version = from.2.map(str::to_owned);
        let from = (from.0, from.1, src_version.as_deref());
        let (dst_bucket, dst_key) = (to.0.to_owned(), to.1.to_owned());
        let (source_encrypted, versioned) = {
            let (bucket, key, version) = (src_bucket.clone(), src_key.clone(), src_version.clone());
            self.blocking(move |inner| match inner.bucket(&bucket)? {
                Bucket::Object(b) => {
                    let row = Inner::version_row(&inner.lock(), &b, &key, version.as_deref())?;
                    Ok((row.crypt.is_some(), b.versioning != Versioning::Unversioned))
                }
                Bucket::Folder(b) => {
                    inner.older_source(&b, &key, version.as_deref())?;
                    Ok((false, false))
                }
            })
            .await?
        };
        let same = src_bucket == dst_bucket && src_key == dst_key;
        // With versioning, a copy onto itself is a new version; copying a version named by
        // its id onto its key (restoring it) needs nothing new.
        if same
            && attrs.is_none()
            && src_version.is_none()
            && matches!(encryption, Encryption::None)
        {
            return Err(StoreError::InvalidRequest(
                "copying an object onto itself needs new metadata or encryption",
            ));
        }
        if source_encrypted || source_key.is_some() || !matches!(encryption, Encryption::None) {
            return self
                .copy_through(from, to, attrs, precondition, source_key, encryption)
                .await;
        }
        self.blocking(move |inner| {
            let (src, dst) = (inner.bucket(&src_bucket)?, inner.bucket(&dst_bucket)?);
            match (&src, &dst) {
                (Bucket::Folder(a), Bucket::Folder(b))
                    if inner
                        .older_source(a, &src_key, src_version.as_deref())?
                        .is_none() =>
                {
                    let src_key = ObjectKey::parse(&src_key).map_err(|_| StoreError::NoSuchKey)?;
                    let dst_key = inner.new_key(&dst_key)?;
                    inner.copy_folder((a, &src_key), (b, &dst_key), attrs, &precondition)
                }
                (Bucket::Object(a), Bucket::Object(b)) if a.id == b.id && same && !versioned => {
                    let attrs = attrs.ok_or(StoreError::InvalidRequest(
                        "copying an object onto itself needs new metadata",
                    ))?;
                    Inner::replace_object_attrs(&inner.lock(), a, &src_key, &attrs, &precondition)
                }
                _ => {
                    let source = (&src, src_key.as_str(), src_version.as_deref());
                    inner.copy_across(source, &dst, &dst_key, attrs, &precondition)
                }
            }
        })
        .await
    }

    /// Copies by reading (decrypting) the source and writing (encrypting) the copy.
    async fn copy_through(
        &self,
        from: (&str, &str, Option<&str>),
        to: (&str, &str),
        attrs: Option<ObjectAttrs>,
        precondition: Precondition,
        source_key: Option<&CustomerKey>,
        encryption: &Encryption,
    ) -> Result<ObjectInfo> {
        use tokio::io::AsyncReadExt;
        let (source, body) = self.read_with(from.0, from.1, from.2, source_key).await?;
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
        let attrs = copied_attrs(source.attrs, attrs);
        self.commit(to.0, to.1, staged, attrs, precondition).await
    }
}

/// The attributes a copy gets: `replacement`, or the source's. The source's checksums
/// carry over when they describe its bytes, which the copy shares; a composite checksum
/// describes its parts, which a copy doesn't have. As on S3, an ACL and an Object Lock
/// are never copied: the copy has the replacement's, or none (and the bucket's default
/// retention).
pub(crate) fn copied_attrs(source: ObjectAttrs, replacement: Option<ObjectAttrs>) -> ObjectAttrs {
    let (checksums, checksum_type) = match source.checksum_type {
        Some(teifs_types::ChecksumType::Composite) => (std::collections::BTreeMap::new(), None),
        _ => (source.checksums.clone(), None),
    };
    let attrs = replacement.unwrap_or(ObjectAttrs {
        acl: None,
        retention: None,
        legal_hold: None,
        ..source
    });
    ObjectAttrs {
        checksums,
        checksum_type,
        ..attrs
    }
}

/// The attributes an object gets when its metadata is replaced in place: its bytes and
/// parts don't change, so its checksums stay. (Only without versioning, so never under
/// Object Lock.)
pub(crate) fn replaced_attrs(current: &ObjectAttrs, replacement: ObjectAttrs) -> ObjectAttrs {
    ObjectAttrs {
        checksums: current.checksums.clone(),
        checksum_type: current.checksum_type,
        ..replacement
    }
}

impl Inner {
    /// Syncs a written file's data, unless durability is off.
    fn sync_file(&self, path: &Path) -> io::Result<()> {
        if self.durability == Durability::None {
            return Ok(());
        }
        stages::time(&self.stages, "write", "sync", || staged::sync_file(path))
    }

    /// Syncs a folder so a new entry in it survives a power cut, in strict mode.
    fn sync_folder(&self, dir: &Path) -> io::Result<()> {
        if self.durability == Durability::Strict {
            sync_dir(dir)
        } else {
            Ok(())
        }
    }

    /// Every bucket, by name: object buckets from their records, folder buckets from the
    /// drive's folders.
    pub(crate) fn buckets(&self) -> Result<Vec<BucketInfo>> {
        let records = self.system().buckets()?;
        let mut buckets: Vec<BucketInfo> = records
            .iter()
            .filter(|r| r.layout == Layout::Object)
            .map(|r| BucketInfo {
                name: r.name.clone(),
                layout: Layout::Object,
                created: from_ms(r.created_ms),
            })
            .collect();
        for entry in fs::read_dir(&self.root)? {
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
    }

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
        let record = self.system().bucket(name)?;
        // An object bucket's data, or a folder bucket's older versions.
        let store = record.map(|record| {
            let layout = record.layout;
            let store = ObjectBucket {
                dir: self.system_dir.join(BUCKETS_DIR).join(&record.id),
                id: record.id,
                versioning: record.versioning,
            };
            (layout, store)
        });
        match store {
            Some((Layout::Object, bucket)) => Ok(Bucket::Object(bucket)),
            store => Ok(Bucket::Folder(FolderBucket {
                name: name.to_owned(),
                dir: self.bucket_dir(name)?,
                versions: store.map(|(_, versions)| versions),
            })),
        }
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
            Bucket::Folder(bucket) => {
                if finished.sealed.is_some() {
                    return Err(StoreError::InvalidRequest(
                        "encryption at rest needs an object bucket",
                    ));
                }
                let key = self.new_key(key)?;
                if key.is_folder() {
                    if finished.size > 0 {
                        return Err(StoreError::InvalidRequest(
                            "a folder (a key ending in `/`) can't have content",
                        ));
                    }
                    return self.make_folder(conn, bucket, &key, finished.attrs, precondition);
                }
                // A copied file may have leftovers (an object bucket's footer) to cut off.
                fs::OpenOptions::new()
                    .write(true)
                    .open(finished.tmp)?
                    .set_len(finished.stored_len)?;
                let parts = finished.parts.as_ref().map(objects::PartsRecord::to_json);
                self.commit_file(
                    conn,
                    bucket,
                    &key,
                    finished.tmp,
                    finished.etag,
                    finished.attrs,
                    parts,
                    precondition,
                )
            }
            Bucket::Object(bucket) => self.commit_object(conn, bucket, key, finished, precondition),
        }
    }

    /// Copies between buckets of different layouts, or between object buckets: the bytes
    /// are cloned where the disk can (APFS, Btrfs, XFS), else copied.
    fn copy_across(
        &self,
        (src, src_key, src_version): (&Bucket, &str, Option<&str>),
        dst: &Bucket,
        dst_key: &str,
        attrs: Option<ObjectAttrs>,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let tmp = TmpFile::new(&self.tmp);
        // An older version of a folder bucket's object is read from its version store.
        let older = match src {
            Bucket::Folder(bucket) => self.older_source(bucket, src_key, src_version)?,
            Bucket::Object(_) => None,
        };
        let older = older.map(Bucket::Object);
        let source = match older.as_ref().unwrap_or(src) {
            Bucket::Folder(FolderBucket { name, dir, .. }) => {
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
                let row = Inner::version_row(&conn, bucket, src_key, src_version)?;
                match &row.object_id {
                    Some(id) => fs::copy(bucket.data_path(id), &tmp.path).map(drop)?,
                    None => fs::File::create(&tmp.path).map(drop)?,
                }
                bucket.info(&row)
            }
        };
        // A copy's ETag is its MD5; a known one carries over, else it's worked out now.
        let etag = match teifs_types::md5_of_etag(&source.etag) {
            Some(_) => source.etag.clone(),
            None => teifs_types::hex(&md5_file(&tmp.path)?),
        };
        let attrs = copied_attrs(source.attrs, attrs);
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

/// Takes the drive's lock, held until the store is dropped (or the process ends).
pub(crate) fn lock_drive(system_dir: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(system_dir.join("lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(StoreError::DriveInUse),
        Err(fs::TryLockError::Error(err)) => Err(err.into()),
    }
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
mod lifecycle_tests;
#[cfg(test)]
mod lock_tests;
#[cfg(test)]
mod sse_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod verify_tests;
#[cfg(test)]
mod versioning_tests;
