//! Folder buckets: a folder at the drive's root whose objects are plain files at their
//! keys' paths. What S3 needs beyond the bytes is in the index, valid while a file's
//! stamp matches.

use std::{
    fs::{self, Metadata},
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use teifs_meta::{Index, Row, Versioning};
use teifs_types::{Stamp, empty_etag, provisional_etag};

use crate::{
    Inner, KeyRules, ObjectAttrs, ObjectInfo, ObjectKey, Precondition, StoreError,
    error::{Result, not_found_as},
    md5_file,
    objects::{ObjectBucket, PartsRecord},
    staged::{Publish, TmpFile, publish},
};

/// A folder bucket, resolved.
#[derive(Debug, Clone)]
pub(crate) struct FolderBucket {
    /// Its name.
    pub name: String,
    /// Its folder (canonical: a bucket that's a link is resolved).
    pub dir: PathBuf,
    /// Where its older versions and delete markers go, once it has a record (made by
    /// TeiFS, or given a setting): stored as an object bucket's versions are.
    pub versions: Option<ObjectBucket>,
}

impl FolderBucket {
    /// Its versioning.
    pub(crate) fn versioning(&self) -> Versioning {
        self.versions
            .as_ref()
            .map_or(Versioning::Unversioned, |v| v.versioning)
    }
}

/// What's at an object's path.
pub(crate) enum Found {
    File(PathBuf, Metadata),
    Folder(PathBuf, Metadata),
    /// Nothing.
    Missing,
    /// Something reached through a symlink, or whose name differs in letter case (a
    /// case-insensitive disk): not this key's object, and nothing may be written there.
    Other,
}

impl Inner {
    /// Checks `key` as a name a folder bucket is about to create: beyond what any file
    /// needs, the drive's [`KeyRules`].
    pub(crate) fn new_key(&self, key: &str) -> Result<ObjectKey> {
        let key = ObjectKey::parse(key)?;
        if self.key_rules == KeyRules::Portable {
            key.check_portable()?;
        }
        Ok(key)
    }

    /// Opens a version of the object at `key` (`None`: the current one): its description
    /// and file (`None` for a folder or a delete marker). The current version is the file
    /// at the key's path; older ones are in the bucket's version store. Holding the commit
    /// lock while opening means neither can be replaced and removed in between.
    pub(crate) fn open_folder_object(
        &self,
        bucket: &FolderBucket,
        key: &ObjectKey,
        version_id: Option<&str>,
    ) -> Result<(ObjectInfo, Option<fs::File>)> {
        let conn = self.lock();
        let (file, meta) = match Inner::find(&bucket.dir, key)? {
            Found::File(path, _) => {
                let file =
                    fs::File::open(&path).map_err(|e| not_found_as(e, StoreError::NoSuchKey))?;
                let meta = file.metadata()?;
                (Some(file), meta)
            }
            Found::Folder(_, meta) => (None, meta),
            Found::Missing | Found::Other => {
                return Inner::open_older_version(&conn, bucket, key.as_str(), version_id);
            }
        };
        let info = Inner::info(&conn, &bucket.name, key.as_str(), &meta)?;
        if version_id.is_some_and(|id| id != crate::folder_versions::current_id(&info)) {
            return Inner::open_older_version(&conn, bucket, key.as_str(), version_id);
        }
        Ok((bucket.describe(info), file))
    }

    /// Renames the file at `src` to `dst` (atomic; the bytes don't move) and its row with
    /// it. Holds the commit lock (`conn`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rename_folder_object(
        &self,
        conn: &Index,
        bucket: &str,
        dir: &Path,
        src: &ObjectKey,
        dst: &ObjectKey,
        source: &Precondition,
        destination: &Precondition,
    ) -> Result<()> {
        let (src_path, src_meta) = match Inner::find(dir, src)? {
            Found::File(path, meta) => (path, meta),
            Found::Folder(..) => {
                return Err(StoreError::InvalidRequest("a folder can't be renamed"));
            }
            Found::Missing | Found::Other => return Err(StoreError::NoSuchKey),
        };
        if dst.is_folder() {
            return Err(StoreError::InvalidRequest(
                "an object can't be renamed to a folder key",
            ));
        }
        let current = Inner::info(conn, bucket, src.as_str(), &src_meta)?;
        let target = Inner::current_for_write(conn, bucket, dir, dst)?;
        if !source.holds(Some(&current)) || !destination.holds(target.as_ref()) {
            return Err(StoreError::PreconditionFailed);
        }
        if src == dst {
            return Ok(());
        }
        let parent = self.make_parents(dir, dst)?;
        let how = if destination.creates_only() {
            Publish::CreateNew
        } else {
            Publish::Replace
        };
        publish(&src_path, &dir.join(dst.rel()), dir, how).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                StoreError::PreconditionFailed
            } else {
                err.into()
            }
        })?;
        self.sync_folder(&parent)?;
        if let Some(src_parent) = src_path.parent() {
            self.sync_folder(src_parent)?;
        }
        conn.rename(bucket, src.as_str(), dst.as_str())?;
        Inner::prune(conn, bucket, dir, src.as_str())
    }

    /// Deletes the object at `key`. Folders left empty by it go too, unless they were
    /// created on purpose. Holds the commit lock (`conn`).
    pub(crate) fn delete_folder_object(
        conn: &Index,
        bucket: &str,
        dir: &Path,
        key: &ObjectKey,
    ) -> Result<()> {
        match Inner::find(dir, key)? {
            Found::File(path, _) => {
                match fs::remove_file(&path) {
                    Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err.into()),
                    _ => {}
                }
                conn.delete(bucket, key.as_str())?;
            }
            Found::Folder(path, _) => {
                conn.delete(bucket, key.as_str())?;
                // A folder with something in it keeps existing as the prefix of its keys.
                if fs::remove_dir(&path).is_err() {
                    return Ok(());
                }
            }
            Found::Missing | Found::Other => return Ok(()),
        }
        Inner::prune(conn, bucket, dir, key.as_str())
    }

    /// What's at `key` in the bucket folder `dir`.
    pub(crate) fn find(dir: &Path, key: &ObjectKey) -> Result<Found> {
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

    /// Describes the object at `key`, whose file (or folder) has `meta`. Its version id
    /// is the recorded one (`None`: `null`), not yet named as answers name it
    /// ([`FolderBucket::describe`]).
    pub(crate) fn info(
        conn: &Index,
        bucket: &str,
        key: &str,
        meta: &Metadata,
    ) -> Result<ObjectInfo> {
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
                sse: None,
                parts: Vec::new(),
                version_id: None,
            });
        }
        let stamp = Stamp::of(meta);
        let (etag, attrs, parts, version_id) = match row {
            Some(row) if row.stamp.matches(&stamp) => {
                (row.etag, row.attrs, row.parts, row.version_id)
            }
            _ => (provisional_etag(stamp), ObjectAttrs::default(), None, None),
        };
        let parts = parts
            .as_deref()
            .and_then(|json| PartsRecord::parse(json).ok())
            .map(|p| p.infos())
            .unwrap_or_default();
        Ok(ObjectInfo {
            key: key.to_owned(),
            size: stamp.size,
            modified,
            etag,
            attrs,
            sse: None,
            parts,
            version_id,
        })
    }

    /// The object currently at `key`, for preconditions; errors when nothing can be
    /// written there.
    pub(crate) fn current_for_write(
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
                        "a name differing only in letter case or Unicode form, or a link, is already there"
                    } else {
                        "a file and a folder can't have the same name"
                    },
                ))
            }
        }
    }

    /// Creates the folders above `key`, refusing to go through a file, a link, or a
    /// folder whose name differs in letter case. Returns the folder the object goes in.
    pub(crate) fn make_parents(&self, dir: &Path, key: &ObjectKey) -> Result<PathBuf> {
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
                "a folder differing only in letter case or Unicode form, or a link, is already there",
            ));
        }
        for path in &created {
            self.sync_folder(path.parent().unwrap_or(dir))?;
        }
        Ok(current)
    }

    /// Renames the finished file `tmp`, already synced ([`Inner::sync_file`]), into place
    /// as `key` and records it. With versioning, the file it replaces is kept as an
    /// older version first. Holds the lock.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_file(
        &self,
        conn: &Index,
        bucket: &FolderBucket,
        key: &ObjectKey,
        tmp: &Path,
        etag: String,
        attrs: ObjectAttrs,
        parts: Option<String>,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let (info, replaced) =
            self.place_file(conn, bucket, key, tmp, etag, attrs, parts, precondition)?;
        if let Some(versions) = bucket.versioned() {
            Inner::remove_data_files(conn, versions, &replaced);
        }
        Ok(info)
    }

    /// Does what [`Inner::commit_file`] does, but leaves the data files of older versions
    /// it replaced (queued as garbage) for the caller to remove: their ids.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn place_file(
        &self,
        conn: &Index,
        bucket: &FolderBucket,
        key: &ObjectKey,
        tmp: &Path,
        etag: String,
        mut attrs: ObjectAttrs,
        parts: Option<String>,
        precondition: &Precondition,
    ) -> Result<(ObjectInfo, Vec<String>)> {
        let dir = &bucket.dir;
        let current = Inner::current_for_write(conn, &bucket.name, dir, key)?;
        precondition.check(current.as_ref())?;
        self.lock_new_version(bucket.versions.as_ref(), &mut attrs)?;
        let parent = self.make_parents(dir, key)?;
        let path = dir.join(key.rel());
        let version_id = bucket.new_version_id();
        let archived = match (&current, bucket.versioned()) {
            (Some(_), Some(_)) => {
                let meta = fs::metadata(&path)?;
                self.archive_for_write(
                    conn,
                    bucket,
                    key,
                    Some((&path, &meta)),
                    version_id.as_deref(),
                )?
            }
            _ => None,
        };
        let how = if precondition.creates_only() {
            Publish::CreateNew
        } else {
            Publish::Replace
        };
        if let Err(err) = publish(tmp, &path, dir, how) {
            Inner::unarchive(conn, bucket, key, archived);
            // Something appeared at the key since the check: another program's file.
            return Err(if err.kind() == io::ErrorKind::AlreadyExists {
                StoreError::PreconditionFailed
            } else {
                err.into()
            });
        }
        self.sync_folder(&parent)?;
        let meta = fs::metadata(&path)?;
        let stamp = Stamp::of(&meta);
        let part_infos = parts
            .as_deref()
            .and_then(|json| PartsRecord::parse(json).ok())
            .map(|p| p.infos())
            .unwrap_or_default();
        let replaced = conn.batch(|conn| {
            conn.put(
                &bucket.name,
                key.as_str(),
                &Row {
                    stamp,
                    etag: etag.clone(),
                    attrs: attrs.clone(),
                    parts,
                    version_id: version_id.clone(),
                },
            )?;
            Inner::settle_versions(conn, bucket, key, version_id.as_deref())
        })?;
        let info = bucket.describe(ObjectInfo {
            key: key.as_str().to_owned(),
            size: stamp.size,
            modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            etag,
            attrs,
            sse: None,
            parts: part_infos,
            version_id,
        });
        Ok((info, replaced))
    }

    /// Creates a folder on purpose (a `key/` object): it stays when its last file goes.
    /// Folders have no versions: one is the `null` version whatever the versioning.
    pub(crate) fn make_folder(
        &self,
        conn: &Index,
        bucket: &FolderBucket,
        key: &ObjectKey,
        attrs: ObjectAttrs,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let dir = &bucket.dir;
        let current = Inner::current_for_write(conn, &bucket.name, dir, key)?;
        precondition.check(current.as_ref())?;
        crate::lock::check_folder(key, &attrs)?;
        let parent = self.make_parents(dir, key)?;
        let path = dir.join(key.rel());
        match fs::create_dir(&path) {
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            other => other?,
        }
        self.sync_folder(&parent)?;
        let meta = fs::metadata(&path)?;
        let row = Row {
            stamp: Stamp::of(&meta),
            etag: empty_etag(),
            attrs,
            parts: None,
            version_id: None,
        };
        conn.put(&bucket.name, key.as_str(), &row)?;
        Ok(bucket.describe(Inner::info(conn, &bucket.name, key.as_str(), &meta)?))
    }

    /// Removes the folders above `key` that its deletion left empty, stopping at one that
    /// isn't empty or was created on purpose.
    pub(crate) fn prune(conn: &Index, bucket: &str, dir: &Path, key: &str) -> Result<()> {
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

    /// Copies the current version of `src_key` (its file) to `dst_key`. Onto itself
    /// without versioning, only its attributes change; with versioning, the copy is a
    /// new version like any other.
    pub(crate) fn copy_folder(
        &self,
        (src, src_key): (&FolderBucket, &ObjectKey),
        (dst, dst_key): (&FolderBucket, &ObjectKey),
        attrs: Option<ObjectAttrs>,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let (src_path, src_meta) = match Inner::find(&src.dir, src_key)? {
            Found::File(path, meta) => (path, meta),
            Found::Folder(_, meta) => {
                let conn = self.lock();
                let source = Inner::info(&conn, &src.name, src_key.as_str(), &meta)?;
                let attrs = crate::copied_attrs(source.attrs, attrs);
                return if dst_key.is_folder() {
                    self.make_folder(&conn, dst, dst_key, attrs, precondition)
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
        if src.name == dst.name && src_key == dst_key && dst.versioned().is_none() {
            let Some(attrs) = attrs else {
                return Err(StoreError::InvalidRequest(
                    "copying an object onto itself needs new metadata",
                ));
            };
            let conn = self.lock();
            let source = Inner::info(&conn, &src.name, src_key.as_str(), &src_meta)?;
            precondition.check(Some(&source))?;
            let attrs = crate::replaced_attrs(&source.attrs, attrs);
            // A recorded ETag (plain or multipart) stays; a file changed outside gets its MD5.
            let row = Row {
                attrs,
                ..Inner::file_row(&conn, &src.name, src_key.as_str(), &src_path, &src_meta)?
            };
            conn.put(&src.name, src_key.as_str(), &row)?;
            return Ok(src.describe(Inner::info(&conn, &src.name, src_key.as_str(), &src_meta)?));
        }

        let source = Inner::info(&self.lock(), &src.name, src_key.as_str(), &src_meta)?;
        let tmp = TmpFile::new(&self.tmp);
        // Clones the file where the disk can (APFS, Btrfs, XFS), else copies it.
        fs::copy(&src_path, &tmp.path)?;
        let after = fs::metadata(&src_path)?;
        if !Stamp::of(&after).matches(&Stamp::of(&src_meta)) {
            return Err(StoreError::InvalidRequest(
                "the source changed while it was being copied",
            ));
        }
        // A copy's ETag is its MD5; a known one (and its parts) carries over, else it's
        // worked out now.
        let (etag, parts) = match teifs_types::md5_of_etag(&source.etag) {
            Some(_) => (
                source.etag,
                (!source.parts.is_empty()).then(|| PartsRecord::new(&source.parts).to_json()),
            ),
            None => (teifs_types::hex(&md5_file(&tmp.path)?), None),
        };
        let attrs = crate::copied_attrs(source.attrs, attrs);
        // The copy is ours alone until it's in place: synced before the lock.
        self.sync_file(&tmp.path)?;
        let conn = self.lock();
        let info = self.commit_file(
            &conn,
            dst,
            dst_key,
            &tmp.path,
            etag,
            attrs,
            parts,
            precondition,
        )?;
        tmp.keep();
        Ok(info)
    }
}

impl Inner {
    /// Changes the attributes of a version of the folder-bucket object `key` (`None`:
    /// the current one). The current version's file isn't touched, so its modification
    /// time and ETag stay; a file changed outside TeiFS starts from empty attributes
    /// (its tags and ACL were the old file's) and gets its MD5. An older version's row
    /// changes as an object bucket's does.
    pub(crate) fn change_folder_attrs(
        &self,
        bucket: &FolderBucket,
        key: &ObjectKey,
        version_id: Option<&str>,
        change: impl FnOnce(&mut ObjectAttrs) -> Result<()>,
    ) -> Result<ObjectInfo> {
        let conn = self.lock();
        if let Found::File(path, meta) | Found::Folder(path, meta) = Inner::find(&bucket.dir, key)?
        {
            let row = Inner::file_row(&conn, &bucket.name, key.as_str(), &path, &meta)?;
            let current = row
                .version_id
                .as_deref()
                .unwrap_or(teifs_meta::NULL_VERSION);
            if version_id.is_none_or(|id| id == current) {
                let mut row = row;
                change(&mut row.attrs)?;
                crate::lock::check_folder(key, &row.attrs)?;
                conn.put(&bucket.name, key.as_str(), &row)?;
                return Ok(bucket.describe(Inner::info(&conn, &bucket.name, key.as_str(), &meta)?));
            }
        }
        let Some(versions) = &bucket.versions else {
            return Err(if version_id.is_some() {
                StoreError::NoSuchVersion
            } else {
                StoreError::NoSuchKey
            });
        };
        let mut row = Inner::version_row(&conn, versions, key.as_str(), version_id)?;
        change(&mut row.attrs)?;
        conn.set_version_attrs(
            &versions.id,
            key.as_str(),
            &row.version_id,
            &row.attrs,
            None,
        )?;
        Ok(versions.info(&row))
    }
}
