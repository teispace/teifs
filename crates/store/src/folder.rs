//! Folder buckets: a folder at the drive's root whose objects are plain files at their
//! keys' paths. What S3 needs beyond the bytes is in the index, valid while a file's
//! stamp matches.

use std::{
    fs::{self, Metadata},
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use teifs_meta::{Index, Row};
use teifs_types::{Stamp, empty_etag, provisional_etag};

use crate::{
    Inner, ObjectAttrs, ObjectInfo, ObjectKey, Precondition, StoreError,
    error::{Result, not_found_as},
    md5_file,
    objects::PartsRecord,
    staged::{Publish, TmpFile, publish, sync_dir},
};

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
    /// Opens the object at `key`: its description and file (`None` for a folder).
    pub(crate) fn open_folder_object(
        &self,
        bucket: &str,
        dir: &Path,
        key: &ObjectKey,
    ) -> Result<(ObjectInfo, Option<fs::File>)> {
        match Inner::find(dir, key)? {
            Found::File(path, _) => {
                let file =
                    fs::File::open(&path).map_err(|e| not_found_as(e, StoreError::NoSuchKey))?;
                let meta = file.metadata()?;
                let info = Inner::info(&self.lock(), bucket, key.as_str(), &meta)?;
                Ok((info, Some(file)))
            }
            Found::Folder(_, meta) => Ok((
                Inner::info(&self.lock(), bucket, key.as_str(), &meta)?,
                None,
            )),
            Found::Missing | Found::Other => Err(StoreError::NoSuchKey),
        }
    }

    /// Renames the file at `src` to `dst` (atomic; the bytes don't move) and its row with
    /// it. Holds the commit lock (`conn`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rename_folder_object(
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
        let parent = Inner::make_parents(dir, dst)?;
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
        sync_dir(&parent)?;
        if let Some(src_parent) = src_path.parent() {
            sync_dir(src_parent)?;
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

    /// Describes the object at `key`, whose file (or folder) has `meta`.
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
            });
        }
        let stamp = Stamp::of(meta);
        let (etag, attrs, parts) = match row {
            Some(row) if row.stamp.matches(&stamp) => (row.etag, row.attrs, row.parts),
            _ => (provisional_etag(stamp), ObjectAttrs::default(), None),
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
    pub(crate) fn make_parents(dir: &Path, key: &ObjectKey) -> Result<PathBuf> {
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
    pub(crate) fn commit_file(
        &self,
        conn: &Index,
        bucket: &str,
        key: &ObjectKey,
        tmp: &Path,
        etag: String,
        attrs: ObjectAttrs,
        parts: Option<String>,
        precondition: &Precondition,
    ) -> Result<ObjectInfo> {
        let dir = self.bucket_dir(bucket)?;
        let current = Inner::current_for_write(conn, bucket, &dir, key)?;
        precondition.check(current.as_ref())?;
        // Flushing needs write access on Windows.
        fs::OpenOptions::new().write(true).open(tmp)?.sync_all()?;
        let parent = Inner::make_parents(&dir, key)?;
        let path = dir.join(key.rel());
        let how = if precondition.creates_only() {
            Publish::CreateNew
        } else {
            Publish::Replace
        };
        publish(tmp, &path, &dir, how).map_err(|err| {
            // Something appeared at the key since the check: another program's file.
            if err.kind() == io::ErrorKind::AlreadyExists {
                StoreError::PreconditionFailed
            } else {
                err.into()
            }
        })?;
        sync_dir(&parent)?;
        let meta = fs::metadata(&path)?;
        let stamp = Stamp::of(&meta);
        let part_infos = parts
            .as_deref()
            .and_then(|json| PartsRecord::parse(json).ok())
            .map(|p| p.infos())
            .unwrap_or_default();
        conn.put(
            bucket,
            key.as_str(),
            &Row {
                stamp,
                etag: etag.clone(),
                attrs: attrs.clone(),
                parts,
            },
        )?;
        Ok(ObjectInfo {
            key: key.as_str().to_owned(),
            size: stamp.size,
            modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            etag,
            attrs,
            sse: None,
            parts: part_infos,
        })
    }

    /// Creates a folder on purpose (a `key/` object): it stays when its last file goes.
    pub(crate) fn make_folder(
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
            parts: None,
        };
        conn.put(bucket, key.as_str(), &row)?;
        Inner::info(conn, bucket, key.as_str(), &meta)
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

    pub(crate) fn copy_folder(
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
            let (etag, parts) = match recorded {
                Some(row) => (row.etag, row.parts),
                None => (teifs_types::hex(&md5_file(&src_path)?), None),
            };
            let row = Row {
                stamp: Stamp::of(&src_meta),
                etag,
                attrs,
                parts,
            };
            conn.put(src_bucket, src_key.as_str(), &row)?;
            return Inner::info(&conn, src_bucket, src_key.as_str(), &src_meta);
        }

        let source = Inner::info(&self.lock(), src_bucket, src_key.as_str(), &src_meta)?;
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
        let attrs = attrs.unwrap_or(source.attrs);
        let conn = self.lock();
        let info = self.commit_file(
            &conn,
            dst_bucket,
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
