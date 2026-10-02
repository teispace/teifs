//! Versioning in folder buckets. The current version is the plain file at its key's path
//! (its id in the `objects` row, `null` when none is recorded), so the folder always
//! shows the latest; older versions and delete markers are kept as an object bucket's
//! versions are, rows in `object_versions` with their bytes under
//! `.teifs/buckets/<bucket id>/`.
//!
//! A file becomes an older version by a hard link into that store (a copy when the
//! bucket is on another disk) before anything replaces or removes it, and an older
//! version becomes current again the same way back. The link comes first, then the
//! rows, then the file at the key's path changes, so a crash can leave a version twice
//! (reads prefer the file) but never lose one.

use std::{collections::VecDeque, fs, io, path::Path, time::SystemTime};

use teifs_meta::{Index, NULL_VERSION, Row, VersionRow, Versioning};
use teifs_types::Stamp;

use crate::{
    Deleted, Inner, ObjectAttrs, ObjectInfo, ObjectKey, Precondition, Store, StoreError,
    body::Data,
    error::Result,
    folder::{FolderBucket, Found},
    list::{After, Cursor, ListQuery, ObjectVersion, VersionListing, VersionsQuery, common_prefix},
    lock::check_removal,
    md5_file, now_ms,
    objects::ObjectBucket,
    staged::{Publish, TmpFile, publish},
};

impl FolderBucket {
    /// Its version store, while it has versioning (enabled or suspended).
    pub(crate) fn versioned(&self) -> Option<&ObjectBucket> {
        self.versions
            .as_ref()
            .filter(|v| v.versioning != Versioning::Unversioned)
    }

    /// The id a new version gets: its own while versioning is on, else `null` (`None`).
    pub(crate) fn new_version_id(&self) -> Option<String> {
        (self.versioning() == Versioning::Enabled)
            .then(|| uuid::Uuid::now_v7().simple().to_string())
    }

    /// A version id as answers name it: only in a bucket that has had versioning, and
    /// `null` for `None`.
    pub(crate) fn named(&self, version_id: Option<&str>) -> Option<String> {
        self.versioning()
            .names_versions()
            .then(|| version_id.unwrap_or(NULL_VERSION).to_owned())
    }

    /// `info` with its version named as answers name it.
    pub(crate) fn describe(&self, info: ObjectInfo) -> ObjectInfo {
        ObjectInfo {
            version_id: self.named(info.version_id.as_deref()),
            ..info
        }
    }
}

/// The version id of a current file's description (`Inner::info`'s): `null` when none.
pub(crate) fn current_id(info: &ObjectInfo) -> &str {
    info.version_id.as_deref().unwrap_or(NULL_VERSION)
}

/// Hard-links `from` to `to`, or copies it where links can't go (another disk, a file
/// system without them). Either way `to` then holds `from`'s bytes as they are now.
fn link_or_copy(from: &Path, to: &Path) -> io::Result<()> {
    match fs::hard_link(from, to) {
        Ok(()) => Ok(()),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::CrossesDevices
                    | io::ErrorKind::Unsupported
                    | io::ErrorKind::PermissionDenied
            ) =>
        {
            fs::copy(from, to)?;
            fs::OpenOptions::new().write(true).open(to)?.sync_all()
        }
        Err(err) => Err(err),
    }
}

fn millis(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl Inner {
    /// The recorded row of the file at `key`, if it still describes the file; else a
    /// row for the file as it is (its MD5, no attributes, the `null` version), as TeiFS
    /// takes any file written outside it.
    pub(crate) fn file_row(
        conn: &Index,
        bucket: &str,
        key: &str,
        path: &Path,
        meta: &fs::Metadata,
    ) -> Result<Row> {
        let stamp = Stamp::of(meta);
        if let Some(row) = conn.get(bucket, key)?.filter(|r| r.stamp.matches(&stamp)) {
            return Ok(row);
        }
        Ok(Row {
            stamp,
            etag: if meta.is_dir() {
                teifs_types::empty_etag()
            } else {
                teifs_types::hex(&md5_file(path)?)
            },
            attrs: ObjectAttrs::default(),
            parts: None,
            version_id: None,
        })
    }

    /// Keeps the file at `path` (the current version of `key`) as an older version in
    /// `versions`, replacing an older version with its id. Its id, `None` for `null`.
    fn archive_file(
        &self,
        conn: &Index,
        bucket: &FolderBucket,
        versions: &ObjectBucket,
        key: &ObjectKey,
        (path, meta): (&Path, &fs::Metadata),
    ) -> Result<Option<String>> {
        let row = Inner::file_row(conn, &bucket.name, key.as_str(), path, meta)?;
        let object_id = uuid::Uuid::now_v7().simple().to_string();
        let data = versions.data_path(&object_id);
        let parent = data.parent().unwrap_or(&versions.dir);
        fs::create_dir_all(parent)?;
        link_or_copy(path, &data)?;
        self.sync_folder(parent)?;
        let version = VersionRow {
            bucket_id: versions.id.clone(),
            key: key.as_str().to_owned(),
            version_id: row
                .version_id
                .clone()
                .unwrap_or_else(|| NULL_VERSION.to_owned()),
            delete_marker: false,
            object_id: Some(object_id),
            size: row.stamp.size,
            etag: row.etag,
            modified_ms: millis(meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)),
            attrs: row.attrs,
            crypt: None,
            parts: row.parts,
            inline: None,
            seq: 0,
            latest: false,
        };
        let replaced = conn.put_noncurrent(&version, now_ms())?;
        Inner::remove_data_files(conn, versions, &replaced);
        Ok(row.version_id)
    }

    /// Before the file of `key` is replaced by a new version `new_id` (`None`: `null`):
    /// keeps the current file as an older version, unless both are `null` (then the
    /// new one replaces it, as S3 replaces the `null` version). What was archived, to
    /// undo if the write fails.
    pub(crate) fn archive_for_write(
        &self,
        conn: &Index,
        bucket: &FolderBucket,
        key: &ObjectKey,
        current: Option<(&Path, &fs::Metadata)>,
        new_id: Option<&str>,
    ) -> Result<Option<String>> {
        let (Some(versions), Some(file)) = (bucket.versioned(), current) else {
            return Ok(None);
        };
        if !file.1.is_file() {
            return Ok(None);
        }
        let current_id = conn
            .get(&bucket.name, key.as_str())?
            .filter(|r| r.stamp.matches(&Stamp::of(file.1)))
            .and_then(|r| r.version_id);
        if current_id.is_none() && new_id.is_none() {
            return Ok(None);
        }
        let archived = self.archive_file(conn, bucket, versions, key, file)?;
        Ok(Some(archived.unwrap_or_else(|| NULL_VERSION.to_owned())))
    }

    /// Undoes [`Inner::archive_for_write`] when the write it preceded failed.
    pub(crate) fn unarchive(
        conn: &Index,
        bucket: &FolderBucket,
        key: &ObjectKey,
        archived: Option<String>,
    ) {
        if let (Some(versions), Some(id)) = (bucket.versioned(), archived)
            && let Ok(Some((_, files))) =
                conn.delete_version(&versions.id, key.as_str(), &id, now_ms())
        {
            Inner::remove_data_files(conn, versions, &files);
        }
    }

    /// After the file of `key` became the version `new_id`: a `null` version written
    /// replaces any older `null` one, and no older version stays current. Part of the
    /// batch that records the file; the data files to remove once it's committed.
    pub(crate) fn settle_versions(
        conn: &Index,
        bucket: &FolderBucket,
        key: &ObjectKey,
        new_id: Option<&str>,
    ) -> teifs_meta::Result<Vec<String>> {
        let Some(versions) = bucket.versioned() else {
            return Ok(Vec::new());
        };
        let mut files = Vec::new();
        if new_id.is_none()
            && let Some((_, removed)) =
                conn.delete_version(&versions.id, key.as_str(), NULL_VERSION, now_ms())?
        {
            files = removed;
        }
        conn.demote_versions(&versions.id, key.as_str())?;
        Ok(files)
    }

    /// Deletes `key` in a folder bucket with versioning, as S3 does: the current file is
    /// kept as an older version (unless it's the `null` version and versioning is
    /// suspended) and a delete marker becomes current. A folder (`key/`) has no
    /// versions: it's deleted as without versioning.
    pub(crate) fn delete_folder_versioned(
        &self,
        conn: &Index,
        bucket: &FolderBucket,
        versions: &ObjectBucket,
        key: &ObjectKey,
        precondition: &Precondition,
    ) -> Result<Deleted> {
        let found = Inner::find(&bucket.dir, key)?;
        let current = match &found {
            Found::File(_, meta) | Found::Folder(_, meta) => {
                Some(Inner::info(conn, &bucket.name, key.as_str(), meta)?)
            }
            Found::Missing | Found::Other => None,
        };
        let exists = precondition.check_delete(current.as_ref())?;
        if let Found::Folder(..) = found {
            Inner::delete_folder_object(conn, &bucket.name, &bucket.dir, key)?;
            return Ok(Deleted::default());
        }
        if (!exists && precondition.is_conditional()) || matches!(found, Found::Other) {
            return Ok(Deleted::default());
        }
        let marker_id = bucket.new_version_id();
        if let Found::File(path, meta) = &found {
            let keep = marker_id.is_some()
                || current
                    .as_ref()
                    .is_some_and(|c| current_id(c) != NULL_VERSION);
            if keep {
                self.archive_file(conn, bucket, versions, key, (path, meta))?;
            }
        }
        let now = now_ms();
        let marker = VersionRow {
            bucket_id: versions.id.clone(),
            key: key.as_str().to_owned(),
            version_id: marker_id.unwrap_or_else(|| NULL_VERSION.to_owned()),
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
        Inner::remove_data_files(conn, versions, &replaced);
        if matches!(found, Found::File(..)) {
            Inner::delete_folder_object(conn, &bucket.name, &bucket.dir, key)?;
        }
        Ok(Deleted {
            version_id: Some(marker.version_id),
            delete_marker: true,
        })
    }

    /// Removes one version of `key` for good. When it's the current file, the newest
    /// older version takes its place (its bytes back at the key's path, or a delete
    /// marker). Removing a version that isn't there succeeds.
    pub(crate) fn delete_folder_version(
        &self,
        conn: &Index,
        bucket: &FolderBucket,
        key: &ObjectKey,
        version_id: &str,
        precondition: &Precondition,
        bypass: bool,
    ) -> Result<Deleted> {
        let named = |delete_marker| Deleted {
            version_id: bucket.named(Some(version_id)),
            delete_marker,
        };
        if let Found::File(_, meta) | Found::Folder(_, meta) = Inner::find(&bucket.dir, key)? {
            let current = Inner::info(conn, &bucket.name, key.as_str(), &meta)?;
            if current_id(&current) == version_id {
                precondition.check_delete(Some(&current))?;
                check_removal(&current.attrs, bypass, now_ms())?;
                Inner::delete_folder_object(conn, &bucket.name, &bucket.dir, key)?;
                if let Some(versions) = &bucket.versions {
                    self.restore_newest(conn, bucket, versions, key)?;
                }
                return Ok(named(false));
            }
        }
        let Some(versions) = &bucket.versions else {
            return Ok(named(false));
        };
        let Some(row) = conn.version(&versions.id, key.as_str(), version_id)? else {
            return Ok(named(false));
        };
        if !row.delete_marker {
            precondition.check_delete(Some(&versions.info(&row)))?;
        }
        check_removal(&row.attrs, bypass, now_ms())?;
        let Some((removed, files)) =
            conn.delete_version(&versions.id, key.as_str(), version_id, now_ms())?
        else {
            return Ok(named(false));
        };
        Inner::remove_data_files(conn, versions, &files);
        if removed.latest {
            self.restore_newest(conn, bucket, versions, key)?;
        }
        Ok(named(removed.delete_marker))
    }

    /// With no file at `key`, makes its newest older version current: a delete marker
    /// stays a row, other versions get their bytes back at the key's path.
    fn restore_newest(
        &self,
        conn: &Index,
        bucket: &FolderBucket,
        versions: &ObjectBucket,
        key: &ObjectKey,
    ) -> Result<()> {
        let Some(newest) = conn.newest_version(&versions.id, key.as_str())? else {
            return Ok(());
        };
        let Some(object_id) = newest.object_id.as_deref().filter(|_| !key.is_folder()) else {
            conn.set_latest(&versions.id, key.as_str(), &newest.version_id)?;
            return Ok(());
        };
        let tmp = TmpFile::new(&self.tmp);
        link_or_copy(&versions.data_path(object_id), &tmp.path)?;
        let parent = self.make_parents(&bucket.dir, key)?;
        let path = bucket.dir.join(key.rel());
        publish(&tmp.path, &path, &bucket.dir, Publish::Replace)?;
        tmp.keep();
        self.sync_folder(&parent)?;
        let meta = fs::metadata(&path)?;
        let files = conn.batch(|conn| {
            conn.put(
                &bucket.name,
                key.as_str(),
                &Row {
                    stamp: Stamp::of(&meta),
                    etag: newest.etag.clone(),
                    attrs: newest.attrs.clone(),
                    parts: newest.parts.clone(),
                    version_id: (newest.version_id != NULL_VERSION)
                        .then(|| newest.version_id.clone()),
                },
            )?;
            let removed =
                conn.delete_version(&versions.id, key.as_str(), &newest.version_id, now_ms())?;
            conn.demote_versions(&versions.id, key.as_str())?;
            Ok(removed.map(|(_, files)| files).unwrap_or_default())
        })?;
        Inner::remove_data_files(conn, versions, &files);
        Ok(())
    }

    /// A version of `key` that isn't the current file, for reading: its description
    /// and data file. A delete marker, current or named, is
    /// [`StoreError::DeleteMarker`].
    pub(crate) fn open_older_version(
        conn: &Index,
        bucket: &FolderBucket,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<(ObjectInfo, Option<Data>)> {
        let Some(versions) = &bucket.versions else {
            return Err(if version_id.is_some() {
                StoreError::NoSuchVersion
            } else {
                StoreError::NoSuchKey
            });
        };
        let (row, file) = Inner::open_object(conn, versions, key, version_id)?;
        Ok((versions.info(&row), file))
    }

    /// When `version_id` names an older version of `key` (not its file): the version
    /// store to read it from, as a copy source. Fails as a read of it would when there's
    /// no such version, or it's a delete marker.
    pub(crate) fn older_source(
        &self,
        bucket: &FolderBucket,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<Option<ObjectBucket>> {
        let Some(id) = version_id else {
            return Ok(None);
        };
        let conn = self.lock();
        if let Ok(parsed) = ObjectKey::parse(key)
            && let Found::File(_, meta) | Found::Folder(_, meta) =
                Inner::find(&bucket.dir, &parsed)?
            && current_id(&Inner::info(&conn, &bucket.name, key, &meta)?) == id
        {
            return Ok(None);
        }
        let versions = bucket.versions.as_ref().ok_or(StoreError::NoSuchVersion)?;
        Inner::version_row(&conn, versions, key, Some(id))?;
        Ok(Some(versions.clone()))
    }
}

/// How many versions and prefixes a page holds.
fn filled(listing: &VersionListing) -> usize {
    listing.versions.len() + listing.prefixes.len()
}

/// Whether one more fits on a page of at most `max`; if not, it's truncated.
fn room(listing: &mut VersionListing, max: usize) -> bool {
    listing.truncated = filled(listing) == max;
    !listing.truncated
}

/// The head of one of a folder-bucket version listing's two sources, in key order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Head {
    Key(String),
    Prefix(String),
}

impl Head {
    fn text(&self) -> &str {
        match self {
            Head::Key(k) | Head::Prefix(k) => k,
        }
    }
}

/// The files at their keys' paths (current versions), a page of a plain listing at a
/// time.
struct Files {
    after: Option<After>,
    buf: VecDeque<Result<ObjectInfo, String>>,
    done: bool,
}

/// The version store's rows (older versions, delete markers), newest first per key.
struct Rows {
    from: Cursor,
    buf: VecDeque<VersionRow>,
    done: bool,
}

impl Files {
    /// Past the common prefix `prefix`, when it's next.
    fn skip(&mut self, prefix: &str) {
        if matches!(self.buf.front(), Some(Err(p)) if p == prefix) {
            self.buf.pop_front();
        }
    }
}

impl Rows {
    /// Past every row under the common prefix `prefix`, when it's next: the next page
    /// starts after them all.
    fn skip(&mut self, prefix: &str) {
        if self.buf.front().is_some_and(|r| r.key.starts_with(prefix)) {
            self.from = Cursor::AfterAll(prefix.to_owned());
            self.buf.clear();
            self.done = false;
        }
    }
}

/// Adds a version to a page, which then ends with it.
fn push(listing: &mut VersionListing, info: ObjectInfo, id: &str, latest: bool, marker: bool) {
    listing.next = Some((info.key.clone(), Some(id.to_owned())));
    listing.versions.push(ObjectVersion {
        info: ObjectInfo {
            version_id: Some(id.to_owned()),
            ..info
        },
        latest,
        delete_marker: marker,
    });
}

impl Store {
    /// Lists a folder bucket's versions: each key's file first (its current version),
    /// then its older versions and delete markers from the version store, newest first.
    /// A key without a file has a delete marker, or only older versions, as current.
    pub(crate) async fn list_folder_versions(
        &self,
        bucket: FolderBucket,
        query: VersionsQuery,
    ) -> Result<VersionListing> {
        let mut listing = VersionListing::default();
        if query.max_keys == 0 {
            return Ok(listing);
        }
        let (after, from, mut skip) = self.resume_folder_versions(&bucket, &query).await?;
        let mut files = Files {
            after,
            buf: VecDeque::new(),
            done: false,
        };
        let mut rows = Rows {
            from,
            buf: VecDeque::new(),
            done: bucket.versions.is_none(),
        };
        let max = query.max_keys;
        'list: loop {
            let file = self
                .files_head(&bucket, &query, &mut files, filled(&listing))
                .await?;
            let row = self
                .rows_head(&bucket, &query, &mut rows, filled(&listing))
                .await?;
            let head = match (file, row) {
                (None, None) => break,
                (Some(a), Some(b)) => {
                    if b.text() < a.text() {
                        b
                    } else {
                        a
                    }
                }
                (Some(head), None) | (None, Some(head)) => head,
            };
            match head {
                Head::Prefix(prefix) => {
                    if !room(&mut listing, max) {
                        break;
                    }
                    files.skip(&prefix);
                    rows.skip(&prefix);
                    listing.next = Some((prefix.clone(), None));
                    listing.prefixes.push(prefix);
                }
                Head::Key(key) => {
                    let mut current = None;
                    if matches!(files.buf.front(), Some(Ok(info)) if info.key == key) {
                        if !room(&mut listing, max) {
                            break;
                        }
                        let Some(Ok(info)) = files.buf.pop_front() else {
                            unreachable!("the front was just matched");
                        };
                        let id = current_id(&info).to_owned();
                        push(&mut listing, info, &id, true, false);
                        current = Some(id);
                    } else if skip.as_ref().is_some_and(|(k, _)| *k == key) {
                        current = skip.take().map(|(_, id)| id);
                    }
                    while let Some(Head::Key(next)) = self
                        .rows_head(&bucket, &query, &mut rows, filled(&listing))
                        .await?
                        && next == key
                    {
                        let row = rows.buf.pop_front().expect("the head is a row");
                        // A version kept twice by a crash: it's the file.
                        if current.as_deref() == Some(row.version_id.as_str()) {
                            continue;
                        }
                        if !room(&mut listing, max) {
                            break 'list;
                        }
                        let versions = bucket.versions.as_ref().expect("rows need a store");
                        let latest = row.latest && current.is_none();
                        let info = versions.info(&row);
                        push(
                            &mut listing,
                            info,
                            &row.version_id,
                            latest,
                            row.delete_marker,
                        );
                    }
                }
            }
        }
        if !listing.truncated {
            listing.next = None;
        }
        Ok(listing)
    }

    /// Where both sources start for the query's markers, and a key's current version
    /// id when the page starts among that key's older versions.
    async fn resume_folder_versions(
        &self,
        bucket: &FolderBucket,
        query: &VersionsQuery,
    ) -> Result<(Option<After>, Cursor, Option<(String, String)>)> {
        let Some(key) = query.key_marker.clone() else {
            return Ok((None, Cursor::Start, None));
        };
        // A marker under a common prefix: the prefix was listed, and all it holds.
        if let Some(common) = common_prefix(&key, &query.prefix, query.delimiter.as_deref()) {
            return Ok((
                Some(After::Prefix(common.clone())),
                Cursor::AfterAll(common),
                None,
            ));
        }
        let after = Some(After::Key(key.clone()));
        let Some(version) = query.version_marker.clone() else {
            return Ok((after, Cursor::AfterKey(key), None));
        };
        let bucket = bucket.clone();
        self.blocking(move |inner| {
            let conn = inner.lock();
            if let Ok(parsed) = ObjectKey::parse(&key)
                && let Found::File(_, meta) = Inner::find(&bucket.dir, &parsed)?
                && current_id(&Inner::info(&conn, &bucket.name, &key, &meta)?) == version
            {
                // After the file: every older version of its key follows.
                let from = Cursor::AfterVersion(key.clone(), i64::MAX);
                return Ok((after, from, Some((key, version))));
            }
            let row = match &bucket.versions {
                Some(versions) => conn.version(&versions.id, &key, &version)?,
                None => None,
            };
            Ok(match row {
                Some(row) => (after, Cursor::AfterVersion(row.key, row.seq), None),
                // A version gone since: carry on after its key.
                None => (after, Cursor::AfterKey(key), None),
            })
        })
        .await
    }

    /// The next file or common prefix, fetching a page when needed.
    async fn files_head(
        &self,
        bucket: &FolderBucket,
        query: &VersionsQuery,
        files: &mut Files,
        count: usize,
    ) -> Result<Option<Head>> {
        if files.buf.is_empty() && !files.done {
            let page = self
                .list(
                    &bucket.name,
                    ListQuery {
                        prefix: query.prefix.clone(),
                        delimiter: query.delimiter.clone(),
                        after: files.after.clone(),
                        max_keys: (query.max_keys - count + 1).clamp(1, 1000),
                    },
                )
                .await?;
            files.done = !page.truncated;
            files.after = page.next;
            // Objects and prefixes, each in order, merged.
            let mut prefixes = page.prefixes.into_iter().peekable();
            for info in page.objects {
                while let Some(prefix) = prefixes.next_if(|p| *p < info.key) {
                    files.buf.push_back(Err(prefix));
                }
                files.buf.push_back(Ok(info));
            }
            files.buf.extend(prefixes.map(Err));
        }
        Ok(files.buf.front().map(|item| match item {
            Ok(info) => Head::Key(info.key.clone()),
            Err(prefix) => Head::Prefix(prefix.clone()),
        }))
    }

    /// The next row's key, or the common prefix it rolls up into, fetching a page when
    /// needed.
    async fn rows_head(
        &self,
        bucket: &FolderBucket,
        query: &VersionsQuery,
        rows: &mut Rows,
        count: usize,
    ) -> Result<Option<Head>> {
        if rows.buf.is_empty() && !rows.done {
            let Some(versions) = bucket.versions.clone() else {
                return Ok(None);
            };
            let (prefix, from) = (query.prefix.clone(), rows.from.clone());
            let batch = (query.max_keys - count + 1).clamp(1, 1000);
            let page = self
                .blocking(move |inner| {
                    let conn = inner.lock();
                    Ok(conn.list_versions(&versions.id, &prefix, from.as_versions_from(), batch)?)
                })
                .await?;
            rows.done = page.len() < batch;
            if let Some(last) = page.last() {
                rows.from = Cursor::AfterVersion(last.key.clone(), last.seq);
            }
            rows.buf.extend(page);
        }
        Ok(rows.buf.front().map(|row| {
            match common_prefix(&row.key, &query.prefix, query.delimiter.as_deref()) {
                Some(prefix) => Head::Prefix(prefix),
                None => Head::Key(row.key.clone()),
            }
        }))
    }
}
