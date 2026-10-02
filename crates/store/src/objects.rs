//! Object buckets: every key S3 allows, stored by id. Each version is a row in the index
//! (authoritative); its bytes are a data file at
//! `.teifs/buckets/<bucket id>/<aa>/<bb>/<object id>` that ends with a footer describing
//! it, so the index can be rebuilt from the files (`docs/ON_DISK_FORMAT.md`).
//!
//! A write puts the data file in place, then replaces the row in one transaction, then
//! removes the replaced file; a crash in between leaves at most a file nobody refers to,
//! which the sweeper removes.

use std::{
    collections::BTreeMap,
    fs, io,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use teifs_crypto::PartId;
use teifs_meta::{Index, NULL_VERSION, VersionRow, Versioning};

use crate::{
    Durability, Inner, ObjectAttrs, ObjectInfo, PartInfo, Precondition, StoreError,
    error::Result,
    now_ms,
    sse::Crypt,
    staged::{Publish, publish},
    stages,
};

/// Where object buckets keep their data, inside `.teifs`.
pub(crate) const BUCKETS_DIR: &str = "buckets";
/// Marks the end of a data file.
const MAGIC: &[u8; 4] = b"TFSO";
/// The data file footer format.
const FOOTER_VERSION: u8 = 1;

/// An object bucket, resolved.
#[derive(Debug, Clone)]
pub(crate) struct ObjectBucket {
    /// Its permanent id.
    pub id: String,
    /// Where its data files are.
    pub dir: PathBuf,
    /// Its versioning.
    pub versioning: Versioning,
}

/// What a delete did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deleted {
    /// The version it removed, or the delete marker it added; `None` in a bucket that
    /// never had versioning (nothing to name).
    pub version_id: Option<String>,
    /// Whether that version is a delete marker.
    pub delete_marker: bool,
}

/// What a data file's footer records, so the index can be rebuilt from files alone.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Footer<'a> {
    bucket: &'a str,
    key: &'a str,
    object: &'a str,
    size: u64,
    etag: &'a str,
    created_ms: i64,
    attrs: &'a ObjectAttrs,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypt: Option<&'a Crypt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parts: Option<&'a PartsRecord>,
    /// Its version id, unless it's `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
}

/// A data file's footer as read back: what's needed to rebuild the version's row.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredFooter {
    pub bucket: String,
    pub key: String,
    pub object: String,
    pub size: u64,
    pub etag: String,
    pub created_ms: i64,
    pub attrs: ObjectAttrs,
    #[serde(default)]
    pub crypt: Option<Crypt>,
    #[serde(default)]
    pub parts: Option<PartsRecord>,
    #[serde(default)]
    pub version: Option<String>,
}

impl StoredFooter {
    /// The version's row, as it was when the file was written (tags, retention and
    /// other changes since are only in the index).
    pub(crate) fn row(self) -> VersionRow {
        VersionRow {
            bucket_id: self.bucket,
            key: self.key,
            version_id: self.version.unwrap_or_else(|| NULL_VERSION.to_owned()),
            delete_marker: false,
            object_id: Some(self.object),
            size: self.size,
            etag: self.etag,
            modified_ms: self.created_ms,
            attrs: self.attrs,
            crypt: self
                .crypt
                .map(|c| serde_json::to_string(&c).expect("crypt serializes")),
            parts: self.parts.map(|p| p.to_json()),
            inline: None,
            seq: 0,
            latest: false,
        }
    }
}

/// The footer at the end of the data file at `path`; `None` when it has none that can
/// be read (a file cut short, or not a data file).
pub(crate) fn read_footer(path: &Path) -> io::Result<Option<StoredFooter>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    let Some(json_end) = len.checked_sub(9) else {
        return Ok(None);
    };
    let mut tail = [0u8; 9];
    file.seek(SeekFrom::Start(json_end))?;
    file.read_exact(&mut tail)?;
    if &tail[5..] != MAGIC || tail[4] != FOOTER_VERSION {
        return Ok(None);
    }
    let json_len = u64::from(u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]));
    let Some(start) = json_end.checked_sub(json_len) else {
        return Ok(None);
    };
    let mut json = vec![0u8; usize::try_from(json_len).map_err(io::Error::other)?];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut json)?;
    Ok(serde_json::from_slice(&json).ok())
}

/// A multipart object's parts (the row's `parts` column, JSON), in both layouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PartsRecord {
    /// Each part's size in bytes, in order (before encryption).
    pub sizes: Vec<u64>,
    /// Each part's checksums, in the same order; empty when no part had any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checksums: Vec<BTreeMap<String, String>>,
    /// An encrypted object's parts' keys, in the same order: the number each was
    /// uploaded as and the salt in its key. Empty for plain objects, and for encrypted
    /// ones stored before salts (their parts are numbered 1, 2, … then).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<PartKey>,
}

/// Which key encrypts a part of an object (see [`PartsRecord::keys`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PartKey {
    /// The number it was uploaded as.
    pub number: u32,
    /// The salt in its key, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
}

impl PartsRecord {
    pub(crate) fn new(parts: &[PartInfo]) -> Self {
        let checksums = if parts.iter().all(|p| p.checksums.is_empty()) {
            Vec::new()
        } else {
            parts.iter().map(|p| p.checksums.clone()).collect()
        };
        Self {
            sizes: parts.iter().map(|p| p.size).collect(),
            checksums,
            keys: Vec::new(),
        }
    }

    pub(crate) fn to_json(&self) -> String {
        serde_json::to_string(self).expect("parts serialize")
    }

    pub(crate) fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata)
    }

    pub(crate) fn infos(&self) -> Vec<PartInfo> {
        self.sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| PartInfo {
                size,
                checksums: self.checksums.get(i).cloned().unwrap_or_default(),
            })
            .collect()
    }
}

/// Finished bytes about to become an object.
#[derive(Debug)]
pub(crate) struct Finished<'a> {
    /// The staged file: the stored bytes (ciphertext when encrypted), maybe followed by
    /// leftovers to cut off.
    pub tmp: &'a Path,
    /// The object's size (before encryption).
    pub size: u64,
    /// How many bytes of `tmp` are the object's stored bytes.
    pub stored_len: u64,
    /// Its ETag.
    pub etag: String,
    /// Its attributes.
    pub attrs: ObjectAttrs,
    /// When encrypted: the object id its data key is bound to, and the record.
    pub sealed: Option<(String, Crypt)>,
    /// When uploaded in parts: the parts.
    pub parts: Option<PartsRecord>,
}

impl<'a> Finished<'a> {
    /// Unencrypted bytes: stored as they are.
    pub(crate) fn plain(tmp: &'a Path, size: u64, etag: String, attrs: ObjectAttrs) -> Self {
        Self {
            tmp,
            size,
            stored_len: size,
            etag,
            attrs,
            sealed: None,
            parts: None,
        }
    }
}

/// A data file in place but not yet recorded ([`Inner::write_object`]): its footer
/// says what [`Inner::record_object`] is expected to record.
pub(crate) struct Written {
    key: String,
    object_id: String,
    path: PathBuf,
    size: u64,
    stored_len: u64,
    etag: String,
    /// The attributes the write asked for.
    asked: ObjectAttrs,
    /// Those with the bucket's default retention settled.
    attrs: ObjectAttrs,
    crypt: Option<Crypt>,
    parts: Option<PartsRecord>,
    /// The bucket's versioning and Object Lock the footer was written for.
    versioning: Versioning,
    object_lock: Option<crate::lock::ObjectLock>,
    version_id: String,
    created_ms: i64,
}

impl Written {
    /// Its data file.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the data file of a write that won't be recorded.
    pub(crate) fn discard(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl ObjectBucket {
    /// Where the data file `object_id` lives. The fan-out folders come from the id's
    /// random tail (a UUIDv7 starts with the time).
    pub(crate) fn data_path(&self, object_id: &str) -> PathBuf {
        let tail = &object_id[object_id.len().saturating_sub(4)..];
        let (aa, bb) = tail.split_at(tail.len().min(2));
        self.dir.join(aa).join(bb).join(object_id)
    }

    /// The id a new version gets: its own while versioning is on, else `null`.
    fn new_version_id(&self) -> String {
        match self.versioning {
            Versioning::Enabled => uuid::Uuid::now_v7().simple().to_string(),
            Versioning::Unversioned | Versioning::Suspended => NULL_VERSION.to_owned(),
        }
    }

    /// What's known about a version, named when the bucket names versions.
    pub(crate) fn info(&self, row: &VersionRow) -> ObjectInfo {
        ObjectInfo {
            version_id: self
                .versioning
                .names_versions()
                .then(|| row.version_id.clone()),
            ..to_info(row)
        }
    }

    /// The version id a delete names: `None` in a bucket that never had versioning.
    fn named(&self, version_id: &str) -> Option<String> {
        self.versioning
            .names_versions()
            .then(|| version_id.to_owned())
    }
}

/// What's known about a version, without its version id.
fn to_info(row: &VersionRow) -> ObjectInfo {
    let sse = row
        .crypt
        .as_deref()
        .and_then(|json| serde_json::from_str::<Crypt>(json).ok())
        .map(|crypt| crypt.info(None));
    let parts = row
        .parts
        .as_deref()
        .and_then(|json| PartsRecord::parse(json).ok())
        .map(|p| p.infos())
        .unwrap_or_default();
    ObjectInfo {
        key: row.key.clone(),
        size: row.size,
        modified: time_of(row.modified_ms),
        etag: row.etag.clone(),
        attrs: row.attrs.clone(),
        sse,
        parts,
        version_id: None,
    }
}

/// A time in milliseconds since the Unix epoch.
fn time_of(ms: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(u64::try_from(ms).unwrap_or(0))
}

/// What's recorded about an object's encryption, if it's encrypted.
pub(crate) fn crypt_of(row: &VersionRow) -> Result<Option<Crypt>> {
    row.crypt
        .as_deref()
        .map(|json| serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata))
        .transpose()
}

/// An encrypted object's parts: each one's size and which key encrypts it (one part
/// unless it was uploaded in parts).
pub(crate) fn sealed_parts(row: &VersionRow) -> Result<Vec<(u64, PartId)>> {
    let Some(json) = row.parts.as_deref() else {
        return Ok(vec![(row.size, PartId::from(1))]);
    };
    let record = PartsRecord::parse(json)?;
    if record.keys.is_empty() {
        return Ok(record
            .sizes
            .into_iter()
            .zip((1..).map(PartId::from))
            .collect());
    }
    if record.keys.len() != record.sizes.len() {
        return Err(StoreError::CorruptMetadata);
    }
    record
        .sizes
        .into_iter()
        .zip(record.keys)
        .map(|(size, key)| {
            let salt = key
                .salt
                .map(|hex| teifs_types::unhex(&hex).ok_or(StoreError::CorruptMetadata))
                .transpose()?;
            Ok((
                size,
                PartId {
                    number: key.number,
                    salt,
                },
            ))
        })
        .collect()
}

/// Appends the footer: JSON, its length (u32 BE), the footer version, and the magic.
fn append_footer(path: &Path, footer: &Footer<'_>, sync: bool) -> io::Result<()> {
    let json = serde_json::to_vec(footer).expect("the footer serializes");
    let len = u32::try_from(json.len()).map_err(io::Error::other)?;
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(&json)?;
    file.write_all(&len.to_be_bytes())?;
    file.write_all(&[FOOTER_VERSION])?;
    file.write_all(MAGIC)?;
    // One sync covers the bytes and the footer.
    if sync { file.sync_all() } else { Ok(()) }
}

impl Inner {
    /// The current version of `key`, if it exists and isn't a delete marker.
    pub(crate) fn object_row(
        conn: &Index,
        bucket: &ObjectBucket,
        key: &str,
    ) -> Result<Option<VersionRow>> {
        Ok(conn
            .latest_version(&bucket.id, key)?
            .filter(|row| !row.delete_marker))
    }

    /// The version of `key` a read names (`None`: the current one). A delete marker
    /// can't be read: [`StoreError::DeleteMarker`] says which it is.
    pub(crate) fn version_row(
        conn: &Index,
        bucket: &ObjectBucket,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<VersionRow> {
        let row = match version_id {
            None => conn
                .latest_version(&bucket.id, key)?
                .ok_or(StoreError::NoSuchKey)?,
            Some(id) => conn
                .version(&bucket.id, key, id)?
                .ok_or(StoreError::NoSuchVersion)?,
        };
        if row.delete_marker {
            return Err(StoreError::DeleteMarker {
                version_id: bucket.named(&row.version_id),
                modified: time_of(row.modified_ms),
                named: version_id.is_some(),
            });
        }
        Ok(row)
    }

    /// Makes the finished bytes the object `key`. Holds the commit lock (`conn`).
    pub(crate) fn commit_object(
        &self,
        conn: &Index,
        bucket: &ObjectBucket,
        key: &str,
        finished: Finished<'_>,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        // Fail before writing anything when the precondition already can't hold.
        let current = Inner::object_row(conn, bucket, key)?.map(|row| to_info(&row));
        precondition.check(current.as_ref())?;
        let written = self.write_object(bucket, key, finished)?;
        self.record_object(conn, bucket, written, precondition)
    }

    /// Puts the finished bytes in place as a new data file, with the footer the version
    /// is expected to get, without the commit lock: nothing refers to the file until
    /// [`Inner::record_object`] records it.
    pub(crate) fn write_object(
        &self,
        bucket: &ObjectBucket,
        key: &str,
        finished: Finished<'_>,
    ) -> Result<Written> {
        teifs_types::check_object_key(key)?;
        let Finished {
            tmp,
            size,
            stored_len,
            etag,
            attrs,
            sealed,
            parts,
        } = finished;
        let (object_id, crypt) = match sealed {
            Some((object_id, crypt)) => (object_id, Some(crypt)),
            None => (uuid::Uuid::now_v7().simple().to_string(), None),
        };
        let mut written = Written {
            key: key.to_owned(),
            path: bucket.data_path(&object_id),
            object_id,
            size,
            stored_len,
            etag,
            asked: attrs.clone(),
            attrs,
            crypt,
            parts,
            versioning: bucket.versioning,
            object_lock: self.object_lock(Some(bucket))?,
            version_id: bucket.new_version_id(),
            created_ms: now_ms(),
        };
        self.lock_new_version(Some(bucket), &mut written.attrs)?;
        // Anything after the stored bytes (a copied file's old footer) goes first.
        fs::OpenOptions::new()
            .write(true)
            .open(tmp)?
            .set_len(stored_len)?;
        self.append_footer(bucket, &written, tmp)?;
        let parent = written.path.parent().unwrap_or(&bucket.dir);
        fs::create_dir_all(parent)?;
        publish(tmp, &written.path, &bucket.dir, Publish::Replace)?;
        if let Err(err) = self.sync_folder(parent) {
            written.discard();
            return Err(err.into());
        }
        Ok(written)
    }

    /// Records a data file [`Inner::write_object`] put in place as the current version
    /// of its key, if `precondition` holds now; else removes it. When the bucket's
    /// versioning or Object Lock changed in between, the footer is rewritten first.
    /// Holds the commit lock (`conn`).
    pub(crate) fn record_object(
        &self,
        conn: &Index,
        bucket: &ObjectBucket,
        written: Written,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let (info, replaced) = self.record_row(conn, bucket, written, precondition)?;
        Inner::remove_data_files(conn, bucket, &replaced);
        Ok(info)
    }

    /// Records `written` as [`Inner::record_object`] does, but leaves the data files of
    /// the versions it replaced (queued as garbage) for the caller to remove: their ids.
    /// Removes the written file when it isn't recorded.
    pub(crate) fn record_row(
        &self,
        conn: &Index,
        bucket: &ObjectBucket,
        mut written: Written,
        precondition: &Precondition,
    ) -> Result<(ObjectInfo, Vec<String>)> {
        let current = Inner::object_row(conn, bucket, &written.key)?.map(|row| to_info(&row));
        if let Err(err) = precondition.check(current.as_ref()) {
            written.discard();
            return Err(err);
        }
        if let Err(err) = self.settle(bucket, &mut written) {
            written.discard();
            return Err(err);
        }
        let path = written.path.clone();
        let Written {
            key,
            object_id,
            size,
            etag,
            attrs,
            crypt,
            parts,
            version_id,
            created_ms,
            ..
        } = written;
        let row = VersionRow {
            bucket_id: bucket.id.clone(),
            key,
            version_id,
            delete_marker: false,
            object_id: Some(object_id),
            size,
            etag,
            modified_ms: created_ms,
            attrs,
            crypt: crypt.map(|c| serde_json::to_string(&c).expect("crypt serializes")),
            parts: parts.map(|p| p.to_json()),
            inline: None,
            seq: 0,
            latest: true,
        };
        match conn.put_version(&row, created_ms) {
            Ok(replaced) => Ok((bucket.info(&row), replaced)),
            Err(err) => {
                let _ = fs::remove_file(path);
                Err(err.into())
            }
        }
    }

    /// Rewrites a written file's footer when the bucket's versioning or Object Lock
    /// changed since it was written, so the version gets what the bucket says now.
    fn settle(&self, bucket: &ObjectBucket, written: &mut Written) -> Result<()> {
        let object_lock = self.object_lock(Some(bucket))?;
        if written.versioning == bucket.versioning && written.object_lock == object_lock {
            return Ok(());
        }
        written.versioning = bucket.versioning;
        written.object_lock = object_lock;
        written.version_id = bucket.new_version_id();
        written.created_ms = now_ms();
        written.attrs = written.asked.clone();
        self.lock_new_version(Some(bucket), &mut written.attrs)?;
        fs::OpenOptions::new()
            .write(true)
            .open(&written.path)?
            .set_len(written.stored_len)?;
        self.append_footer(bucket, written, &written.path)
    }

    /// Appends `written`'s footer to `path`, synced unless durability is off.
    fn append_footer(&self, bucket: &ObjectBucket, written: &Written, path: &Path) -> Result<()> {
        let footer = Footer {
            bucket: &bucket.id,
            key: &written.key,
            object: &written.object_id,
            size: written.size,
            etag: &written.etag,
            created_ms: written.created_ms,
            attrs: &written.attrs,
            crypt: written.crypt.as_ref(),
            parts: written.parts.as_ref(),
            version: (written.version_id != NULL_VERSION).then_some(written.version_id.as_str()),
        };
        stages::time(&self.stages, "write", "sync", || {
            append_footer(path, &footer, self.durability != Durability::None)
        })?;
        Ok(())
    }

    /// Opens a version of `key` (`None`: the current one): its description and data
    /// file. Under the commit lock the file can't be replaced and removed between reading
    /// the row and opening it; on a snapshot ([`Inner::read_index`]) it can, and opening
    /// it fails with `NotFound`.
    pub(crate) fn open_object(
        conn: &Index,
        bucket: &ObjectBucket,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<(VersionRow, Option<fs::File>)> {
        let row = Inner::version_row(conn, bucket, key, version_id)?;
        let file = match &row.object_id {
            Some(id) => Some(fs::File::open(bucket.data_path(id))?),
            None => None,
        };
        Ok((row, file))
    }

    /// Deletes `key` if it meets `precondition`, as S3 does for the bucket's versioning:
    /// without versioning its `null` version goes; with versioning on a delete marker
    /// becomes current; suspended, a `null` delete marker replaces the `null` version.
    /// Deleting what doesn't exist succeeds (and still adds a marker with versioning).
    pub(crate) fn delete_object(
        conn: &Index,
        bucket: &ObjectBucket,
        key: &str,
        precondition: &Precondition,
    ) -> Result<Deleted> {
        let current = Inner::object_row(conn, bucket, key)?.map(|row| to_info(&row));
        let exists = precondition.check_delete(current.as_ref())?;
        if bucket.versioning == Versioning::Unversioned {
            if exists {
                let removed = conn.delete_null_version(&bucket.id, key, now_ms())?;
                Inner::remove_data_files(conn, bucket, &removed);
            }
            return Ok(Deleted::default());
        }
        if !exists && precondition.is_conditional() {
            return Ok(Deleted::default());
        }
        let now = now_ms();
        let marker = VersionRow {
            bucket_id: bucket.id.clone(),
            key: key.to_owned(),
            version_id: bucket.new_version_id(),
            delete_marker: true,
            object_id: None,
            size: 0,
            etag: String::new(),
            modified_ms: now,
            attrs: ObjectAttrs::default(),
            crypt: None,
            parts: None,
            inline: None,
            seq: 0,
            latest: true,
        };
        let replaced = conn.put_version(&marker, now)?;
        Inner::remove_data_files(conn, bucket, &replaced);
        Ok(Deleted {
            version_id: Some(marker.version_id),
            delete_marker: true,
        })
    }

    /// Removes one version of `key` for good, if it meets `precondition` (a delete
    /// marker has nothing to meet). Removing one that doesn't exist succeeds.
    pub(crate) fn delete_object_version(
        conn: &Index,
        bucket: &ObjectBucket,
        key: &str,
        version_id: &str,
        precondition: &Precondition,
        bypass: bool,
    ) -> Result<Deleted> {
        let Some(row) = conn.version(&bucket.id, key, version_id)? else {
            return Ok(Deleted {
                version_id: bucket.named(version_id),
                delete_marker: false,
            });
        };
        if !row.delete_marker {
            precondition.check_delete(Some(&to_info(&row)))?;
        }
        crate::lock::check_removal(&row.attrs, bypass, now_ms())?;
        if let Some((removed, files)) =
            conn.delete_version(&bucket.id, key, version_id, now_ms())?
        {
            Inner::remove_data_files(conn, bucket, &files);
            return Ok(Deleted {
                version_id: bucket.named(&removed.version_id),
                delete_marker: removed.delete_marker,
            });
        }
        Ok(Deleted::default())
    }

    /// Replaces the attributes of `key` in place (a copy onto itself with new metadata).
    pub(crate) fn replace_object_attrs(
        conn: &Index,
        bucket: &ObjectBucket,
        key: &str,
        attrs: &ObjectAttrs,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let row = Inner::object_row(conn, bucket, key)?.ok_or(StoreError::NoSuchKey)?;
        precondition.check(Some(&to_info(&row)))?;
        let attrs = crate::replaced_attrs(&row.attrs, attrs.clone());
        let now = now_ms();
        conn.set_version_attrs(&bucket.id, key, &row.version_id, &attrs, Some(now))?;
        Ok(ObjectInfo {
            attrs,
            modified: time_of(now),
            ..bucket.info(&row)
        })
    }

    /// Removes data files no version refers to any more, and their garbage entries. A
    /// file that can't be removed now (open on Windows) stays queued for the sweeper.
    /// How many it removed (or found gone); the others stay queued.
    pub(crate) fn remove_data_files(
        conn: &Index,
        bucket: &ObjectBucket,
        object_ids: &[String],
    ) -> usize {
        let mut removed = 0;
        for id in object_ids {
            let gone = match fs::remove_file(bucket.data_path(id)) {
                Ok(()) => true,
                Err(err) => err.kind() == io::ErrorKind::NotFound,
            };
            if gone && conn.drop_garbage(id).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    /// Removes data files the garbage queue holds (left by a crash, or open when first
    /// removed), at most `limit`; how many left the queue.
    pub(crate) fn sweep_garbage(&self, conn: &Index, limit: usize) -> Result<usize> {
        let mut done = 0;
        for (bucket_id, object_id) in conn.garbage(limit)? {
            if conn.object_in_use(&object_id)? {
                conn.drop_garbage(&object_id)?;
                done += 1;
                continue;
            }
            let bucket = ObjectBucket {
                dir: self.system_dir().join(BUCKETS_DIR).join(&bucket_id),
                id: bucket_id,
                versioning: Versioning::Unversioned,
            };
            done += Inner::remove_data_files(conn, &bucket, std::slice::from_ref(&object_id));
        }
        Ok(done)
    }
}
