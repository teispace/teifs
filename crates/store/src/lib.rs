//! TeiFS's storage: a drive is a folder, each folder in it is a bucket, and each object
//! is a plain file at the path its key names. What S3 needs beyond the bytes (ETags,
//! content types, user metadata, checksums, multipart uploads) lives in
//! `.teifs/index.db` (the `teifs-meta` index) beside the buckets, so the files stay usable by anything else and
//! a drive can be opened, backed up or left without TeiFS.
//!
//! Writes go to `.teifs/tmp` first, are synced, and are renamed into place under one
//! commit lock, so every object is either its old or its new version, and the stored ETag
//! always belongs to the bytes on disk.

mod error;
mod format;
mod list;
mod multipart;
mod staged;

use std::{
    fs::{self, Metadata},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use teifs_meta::{BucketRecord, Index, Layout, Row, System};

pub use error::{Result, StoreError};
pub use format::{DriveFormat, FORMAT};
pub use list::{After, ListQuery, Listing};
pub use multipart::{MAX_PART_NUMBER, MIN_PART_SIZE};
pub use staged::Staged;
pub use teifs_meta::{Part, Upload};
pub use teifs_types::{MAX_KEY_LEN, NameError, ObjectAttrs, ObjectInfo, ObjectKey, check_bucket};

use error::not_found_as;
use staged::{TmpFile, sync_dir};
use teifs_types::{Stamp, empty_etag, provisional_etag};

/// The folder in a drive's root that holds TeiFS's own data.
pub const SYSTEM_DIR: &str = ".teifs";

/// A bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketInfo {
    /// Its name (the folder's).
    pub name: String,
    /// When its folder was created (or last changed, where creation isn't recorded).
    pub created: SystemTime,
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
    tmp: PathBuf,
    uploads: PathBuf,
    /// The index, also the commit lock: whoever changes a file holds it until the file
    /// and its row agree again.
    db: Mutex<Index>,
    /// The system database. Taken after `db` when both are needed.
    system: Mutex<System>,
    format: DriveFormat,
}

/// What's at an object's path.
enum Found {
    File(PathBuf, Metadata),
    Folder(PathBuf, Metadata),
    /// Nothing.
    Missing,
    /// Something reached through a symlink, or whose name differs in letter case (a
    /// case-insensitive disk): not this key's object, and nothing may be written there.
    Other,
}

impl Store {
    /// Opens the drive at `root` (which must exist), creating `.teifs` inside it, and
    /// upgrading the drive's format first if an older TeiFS wrote it.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = fs::canonicalize(root.as_ref())?;
        if !root.is_dir() {
            return Err(StoreError::Io(io::Error::new(
                io::ErrorKind::NotADirectory,
                "the drive must be a folder",
            )));
        }
        let system = root.join(SYSTEM_DIR);
        let tmp = system.join("tmp");
        let uploads = system.join("uploads");
        fs::create_dir_all(&uploads)?;
        // Whatever was being written when the last run stopped is gone for good.
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp)?;
        let format = format::prepare(&system)?;
        let db = Index::open(&system.join(format::INDEX_DB))?;
        let system_db = System::open(&system.join(format::SYSTEM_DB))?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                tmp,
                uploads,
                db: Mutex::new(db),
                system: Mutex::new(system_db),
                format,
            }),
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

    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Inner) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || f(&inner))
            .await
            .expect("storage task panicked")
    }

    /// Every bucket, by name.
    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>> {
        self.blocking(|inner| {
            let mut buckets = Vec::new();
            for entry in fs::read_dir(&inner.root)? {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if check_bucket(&name).is_err() {
                    continue;
                }
                // A bucket may be a symlink to a folder elsewhere (another disk).
                let Ok(meta) = fs::metadata(entry.path()) else {
                    continue;
                };
                if meta.is_dir() {
                    let recorded = inner.system().bucket(&name)?.map(|r| {
                        SystemTime::UNIX_EPOCH
                            + std::time::Duration::from_millis(
                                u64::try_from(r.created_ms).unwrap_or(0),
                            )
                    });
                    let created = recorded
                        .or_else(|| meta.created().ok())
                        .or_else(|| meta.modified().ok())
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    buckets.push(BucketInfo { name, created });
                }
            }
            buckets.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(buckets)
        })
        .await
    }

    /// Creates a bucket.
    pub async fn create_bucket(&self, name: &str) -> Result<()> {
        check_bucket(name)?;
        let name = name.to_owned();
        self.blocking(move |inner| {
            let _lock = inner.lock();
            match fs::create_dir(inner.root.join(&name)) {
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    Err(StoreError::BucketExists)
                }
                other => {
                    other?;
                    sync_dir(&inner.root)?;
                    inner.system().record_bucket(&BucketRecord {
                        name,
                        layout: Layout::Plain,
                        created_ms: now_ms(),
                    })?;
                    Ok(())
                }
            }
        })
        .await
    }

    /// Fails with [`StoreError::NoSuchBucket`] unless the bucket exists.
    pub async fn head_bucket(&self, name: &str) -> Result<()> {
        let name = name.to_owned();
        self.blocking(move |inner| inner.bucket_dir(&name).map(drop))
            .await
    }

    /// Deletes an empty bucket, and any uploads to it left unfinished.
    pub async fn delete_bucket(&self, name: &str) -> Result<()> {
        let name = name.to_owned();
        self.blocking(move |inner| {
            let conn = inner.lock();
            let dir = inner.bucket_dir(&name)?;
            if fs::read_dir(&dir)?.next().is_some() {
                return Err(StoreError::BucketNotEmpty);
            }
            let unfinished = conn.list_uploads(&name, "", None, usize::MAX)?;
            // A bucket that's a symlink goes as a symlink; its target folder stays.
            if fs::symlink_metadata(inner.root.join(&name))?.is_symlink() {
                fs::remove_file(inner.root.join(&name))?;
            } else {
                fs::remove_dir(&dir)?;
            }
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

    /// Puts staged bytes in place as `bucket`/`key`, replacing what was there.
    pub async fn commit(
        &self,
        bucket: &str,
        key: &str,
        mut staged: Staged,
        attrs: ObjectAttrs,
        precondition: Precondition,
    ) -> Result<ObjectInfo> {
        let key = ObjectKey::parse(key)?;
        if key.is_folder() && staged.size() > 0 {
            return Err(StoreError::InvalidRequest(
                "a folder (a key ending in `/`) can't have content",
            ));
        }
        staged.finish().await?;
        let bucket = bucket.to_owned();
        self.blocking(move |inner| {
            let conn = inner.lock();
            if key.is_folder() {
                return inner.make_folder(&conn, &bucket, &key, attrs, &precondition);
            }
            let etag = teifs_types::hex(&staged.md5());
            let info = inner.commit_file(
                &conn,
                &bucket,
                &key,
                staged.path(),
                etag,
                attrs,
                &precondition,
            )?;
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

    /// An object and its bytes (`None` for a folder). The file is the one `ObjectInfo`
    /// describes, even if the object is replaced while it's being read.
    pub async fn read(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ObjectInfo, Option<tokio::fs::File>)> {
        let key = ObjectKey::parse(key).map_err(|_| StoreError::NoSuchKey)?;
        let bucket = bucket.to_owned();
        self.blocking(move |inner| {
            let dir = inner.bucket_dir(&bucket)?;
            match Inner::find(&dir, &key)? {
                Found::File(path, _) => {
                    let file = fs::File::open(&path)
                        .map_err(|e| not_found_as(e, StoreError::NoSuchKey))?;
                    let meta = file.metadata()?;
                    let info = Inner::info(&inner.lock(), &bucket, key.as_str(), &meta)?;
                    Ok((info, Some(tokio::fs::File::from_std(file))))
                }
                Found::Folder(_, meta) => Ok((
                    Inner::info(&inner.lock(), &bucket, key.as_str(), &meta)?,
                    None,
                )),
                Found::Missing | Found::Other => Err(StoreError::NoSuchKey),
            }
        })
        .await
    }

    /// Deletes an object. Deleting one that doesn't exist succeeds, as in S3. Folders left
    /// empty by it go too, unless they were created on purpose.
    pub async fn delete(&self, bucket: &str, key: &str) -> Result<()> {
        let Ok(key) = ObjectKey::parse(key) else {
            return Ok(());
        };
        let bucket = bucket.to_owned();
        self.blocking(move |inner| {
            let conn = inner.lock();
            let dir = inner.bucket_dir(&bucket)?;
            match Inner::find(&dir, &key)? {
                Found::File(path, _) => {
                    match fs::remove_file(&path) {
                        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err.into()),
                        _ => {}
                    }
                    conn.delete(&bucket, key.as_str())?;
                }
                Found::Folder(path, _) => {
                    conn.delete(&bucket, key.as_str())?;
                    // A folder with something in it keeps existing as the prefix of its keys.
                    if fs::remove_dir(&path).is_err() {
                        return Ok(());
                    }
                }
                Found::Missing | Found::Other => return Ok(()),
            }
            Inner::prune(&conn, &bucket, &dir, key.as_str())
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
        let src_key = ObjectKey::parse(from.1).map_err(|_| StoreError::NoSuchKey)?;
        let dst_key = ObjectKey::parse(to.1)?;
        let (src_bucket, dst_bucket) = (from.0.to_owned(), to.0.to_owned());
        self.blocking(move |inner| {
            inner.copy(
                &src_bucket,
                &src_key,
                &dst_bucket,
                &dst_key,
                attrs,
                &precondition,
            )
        })
        .await
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
        // statement or one rename.
        self.db
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    /// What's at `key` in the bucket folder `dir`.
    fn find(dir: &Path, key: &ObjectKey) -> Result<Found> {
        let path = dir.join(key.rel());
        let real = match fs::canonicalize(&path) {
            Ok(real) => real,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(Found::Missing);
            }
            Err(err) => return Err(err.into()),
        };
        if real != path {
            return Ok(Found::Other);
        }
        let meta = fs::metadata(&path)?;
        Ok(match (meta.is_dir(), key.is_folder()) {
            (true, true) => Found::Folder(path, meta),
            (false, false) if meta.is_file() => Found::File(path, meta),
            _ => Found::Other,
        })
    }

    /// Describes the object at `key`, whose file (or folder) has `meta`.
    fn info(conn: &Index, bucket: &str, key: &str, meta: &Metadata) -> Result<ObjectInfo> {
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let row = conn.get(bucket, key)?;
        if meta.is_dir() {
            let attrs = row.map(|r| r.attrs).unwrap_or_default();
            return Ok(ObjectInfo {
                key: key.to_owned(),
                size: 0,
                modified,
                etag: empty_etag(),
                attrs,
            });
        }
        let stamp = Stamp::of(meta);
        let (etag, attrs) = match row {
            Some(row) if row.stamp.matches(&stamp) => (row.etag, row.attrs),
            _ => (provisional_etag(stamp), ObjectAttrs::default()),
        };
        Ok(ObjectInfo {
            key: key.to_owned(),
            size: stamp.size,
            modified,
            etag,
            attrs,
        })
    }

    /// The object currently at `key`, for preconditions; errors when nothing can be
    /// written there.
    fn current_for_write(
        conn: &Index,
        bucket: &str,
        dir: &Path,
        key: &ObjectKey,
    ) -> Result<Option<ObjectInfo>> {
        match Inner::find(dir, key)? {
            Found::Missing => Ok(None),
            Found::File(_, meta) | Found::Folder(_, meta) => {
                Ok(Some(Inner::info(conn, bucket, key.as_str(), &meta)?))
            }
            Found::Other => {
                let path = dir.join(key.rel());
                Err(StoreError::KeyConflict(
                    if fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) == key.is_folder() {
                        "a name differing only in letter case, or a link, is already there"
                    } else {
                        "a file and a folder can't have the same name"
                    },
                ))
            }
        }
    }

    /// Creates the folders above `key`, refusing to go through a file, a link, or a
    /// folder whose name differs in letter case. Returns the folder the object goes in.
    fn make_parents(dir: &Path, key: &ObjectKey) -> Result<PathBuf> {
        let Some(parent) = key.rel().parent().filter(|p| !p.as_os_str().is_empty()) else {
            return Ok(dir.to_owned());
        };
        let mut created = Vec::new();
        let mut current = dir.to_owned();
        let conflict = |created: &mut Vec<PathBuf>, why| {
            for path in created.drain(..).rev() {
                let _ = fs::remove_dir(path);
            }
            StoreError::KeyConflict(why)
        };
        for segment in parent.components() {
            current.push(segment);
            match fs::create_dir(&current) {
                Ok(()) => created.push(current.clone()),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    if !fs::symlink_metadata(&current)?.is_dir() {
                        return Err(conflict(
                            &mut created,
                            "a file is where a folder in this key would be",
                        ));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotADirectory => {
                    return Err(conflict(
                        &mut created,
                        "a file is where a folder in this key would be",
                    ));
                }
                Err(err) => return Err(err.into()),
            }
        }
        if fs::canonicalize(&current)? != current {
            return Err(conflict(
                &mut created,
                "a folder differing only in letter case, or a link, is already there",
            ));
        }
        for path in &created {
            sync_dir(path.parent().unwrap_or(dir))?;
        }
        Ok(current)
    }

    /// Renames the finished file `tmp` into place as `key` and records it. Holds the lock.
    #[allow(clippy::too_many_arguments)]
    fn commit_file(
        &self,
        conn: &Index,
        bucket: &str,
        key: &ObjectKey,
        tmp: &Path,
        etag: String,
        attrs: ObjectAttrs,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let dir = self.bucket_dir(bucket)?;
        let current = Inner::current_for_write(conn, bucket, &dir, key)?;
        precondition.check(current.as_ref())?;
        let parent = Inner::make_parents(&dir, key)?;
        let path = dir.join(key.rel());
        fs::rename(tmp, &path)?;
        sync_dir(&parent)?;
        let meta = fs::metadata(&path)?;
        let stamp = Stamp::of(&meta);
        conn.put(
            bucket,
            key.as_str(),
            &Row {
                stamp,
                etag: etag.clone(),
                attrs: attrs.clone(),
            },
        )?;
        Ok(ObjectInfo {
            key: key.as_str().to_owned(),
            size: stamp.size,
            modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            etag,
            attrs,
        })
    }

    /// Creates a folder on purpose (a `key/` object): it stays when its last file goes.
    fn make_folder(
        &self,
        conn: &Index,
        bucket: &str,
        key: &ObjectKey,
        attrs: ObjectAttrs,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let dir = self.bucket_dir(bucket)?;
        let current = Inner::current_for_write(conn, bucket, &dir, key)?;
        precondition.check(current.as_ref())?;
        let parent = Inner::make_parents(&dir, key)?;
        let path = dir.join(key.rel());
        match fs::create_dir(&path) {
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            other => other?,
        }
        sync_dir(&parent)?;
        let meta = fs::metadata(&path)?;
        let row = Row {
            stamp: Stamp::of(&meta),
            etag: empty_etag(),
            attrs,
        };
        conn.put(bucket, key.as_str(), &row)?;
        Inner::info(conn, bucket, key.as_str(), &meta)
    }

    /// Removes the folders above `key` that its deletion left empty, stopping at one that
    /// isn't empty or was created on purpose.
    fn prune(conn: &Index, bucket: &str, dir: &Path, key: &str) -> Result<()> {
        let mut prefix = key.trim_end_matches('/');
        while let Some(end) = prefix.rfind('/') {
            prefix = &prefix[..end];
            let folder_key = format!("{prefix}/");
            if conn.is_kept_folder(bucket, &folder_key)?
                || fs::remove_dir(dir.join(prefix)).is_err()
            {
                break;
            }
        }
        Ok(())
    }

    fn copy(
        &self,
        src_bucket: &str,
        src_key: &ObjectKey,
        dst_bucket: &str,
        dst_key: &ObjectKey,
        attrs: Option<ObjectAttrs>,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let src_dir = self.bucket_dir(src_bucket)?;
        let (src_path, src_meta) = match Inner::find(&src_dir, src_key)? {
            Found::File(path, meta) => (path, meta),
            Found::Folder(..) => {
                let conn = self.lock();
                let source = Inner::info(
                    &conn,
                    src_bucket,
                    src_key.as_str(),
                    &fs::metadata(src_dir.join(src_key.rel()))?,
                )?;
                let attrs = attrs.unwrap_or(source.attrs);
                return if dst_key.is_folder() {
                    self.make_folder(&conn, dst_bucket, dst_key, attrs, precondition)
                } else {
                    Err(StoreError::InvalidRequest(
                        "a folder can only be copied to a folder",
                    ))
                };
            }
            Found::Missing | Found::Other => return Err(StoreError::NoSuchKey),
        };
        if dst_key.is_folder() {
            return Err(StoreError::InvalidRequest(
                "a file can't be copied to a folder key",
            ));
        }
        let same = src_bucket == dst_bucket && src_key == dst_key;
        if same {
            let Some(attrs) = attrs else {
                return Err(StoreError::InvalidRequest(
                    "copying an object onto itself needs new metadata",
                ));
            };
            let conn = self.lock();
            let source = Inner::info(&conn, src_bucket, src_key.as_str(), &src_meta)?;
            precondition.check(Some(&source))?;
            // A recorded ETag (plain or multipart) stays; a file changed outside gets its MD5.
            let recorded = conn
                .get(src_bucket, src_key.as_str())?
                .filter(|r| r.stamp.matches(&Stamp::of(&src_meta)));
            let etag = match recorded {
                Some(row) => row.etag,
                None => teifs_types::hex(&md5_file(&src_path)?),
            };
            let row = Row {
                stamp: Stamp::of(&src_meta),
                etag,
                attrs,
            };
            conn.put(src_bucket, src_key.as_str(), &row)?;
            return Inner::info(&conn, src_bucket, src_key.as_str(), &src_meta);
        }

        let source = Inner::info(&self.lock(), src_bucket, src_key.as_str(), &src_meta)?;
        let tmp = TmpFile::new(&self.tmp);
        // Clones the file where the disk can (APFS, Btrfs, XFS), else copies it.
        fs::copy(&src_path, &tmp.path)?;
        // Flushing needs write access on Windows.
        fs::OpenOptions::new()
            .write(true)
            .open(&tmp.path)?
            .sync_all()?;
        let after = fs::metadata(&src_path)?;
        if !Stamp::of(&after).matches(&Stamp::of(&src_meta)) {
            return Err(StoreError::InvalidRequest(
                "the source changed while it was being copied",
            ));
        }
        // A copy's ETag is its MD5; a known one carries over, else it's worked out now.
        let etag = match teifs_types::md5_of_etag(&source.etag) {
            Some(_) => source.etag,
            None => teifs_types::hex(&md5_file(&tmp.path)?),
        };
        let attrs = attrs.unwrap_or(source.attrs);
        let conn = self.lock();
        let info = self.commit_file(
            &conn,
            dst_bucket,
            dst_key,
            &tmp.path,
            etag,
            attrs,
            precondition,
        )?;
        tmp.keep();
        Ok(info)
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
mod tests;
