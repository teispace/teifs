//! Listing a bucket in S3's order without reading all of it.
//!
//! S3 lists keys in byte order. Within one folder, sorting files by name and folders by
//! `name/` gives exactly that order for everything below it, because every key under a
//! folder starts with the folder's key. So a depth-first walk that sorts each folder once
//! yields keys in order, can skip whole folders that are before the marker or rolled up
//! into a common prefix, and stops as soon as the page is full.

use std::{
    fs,
    path::{Path, PathBuf},
};

use teifs_types::MAX_SEGMENT_LEN;

use teifs_meta::{Index, VersionsFrom};

use crate::{
    Bucket, Inner, ObjectInfo, Store,
    error::Result,
    folder::FolderBucket,
    folders::{Children, FolderCache, start_at},
    objects::ObjectBucket,
};

/// Where a page starts: after this key, or after every key under this common prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum After {
    /// After this key (`StartAfter`, `Marker`, or a page ending in an object).
    Key(String),
    /// After every key starting with this common prefix (a page ending in one).
    Prefix(String),
}

impl After {
    fn marker(&self) -> &str {
        match self {
            After::Key(k) | After::Prefix(k) => k,
        }
    }
}

/// What to list.
#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    /// Only keys starting with this.
    pub prefix: String,
    /// Roll keys up to the first occurrence of this after the prefix (usually `/`).
    pub delimiter: Option<String>,
    /// Start after this.
    pub after: Option<After>,
    /// The most objects plus common prefixes to return.
    pub max_keys: usize,
}

/// One page of a listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// Objects, in key order.
    pub objects: Vec<ObjectInfo>,
    /// Common prefixes, in order.
    pub prefixes: Vec<String>,
    /// Whether more follow.
    pub truncated: bool,
    /// Where the next page starts, when truncated.
    pub next: Option<After>,
}

/// What to list of a bucket's versions.
#[derive(Debug, Clone, Default)]
pub struct VersionsQuery {
    /// Only keys starting with this.
    pub prefix: String,
    /// Roll keys up to the first occurrence of this after the prefix (usually `/`).
    pub delimiter: Option<String>,
    /// Start after this key (`KeyMarker`): after all its versions, or with
    /// `version_marker` after that one.
    pub key_marker: Option<String>,
    /// Start after this version of `key_marker` (`VersionIdMarker`).
    pub version_marker: Option<String>,
    /// The most versions, delete markers and common prefixes to return.
    pub max_keys: usize,
}

/// One version in a versions listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersion {
    /// What's known about it; its `version_id` is always set.
    pub info: ObjectInfo,
    /// Whether it's the key's current version.
    pub latest: bool,
    /// Whether it's a delete marker (no content: its size is 0 and its ETag empty).
    pub delete_marker: bool,
}

/// One page of a versions listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionListing {
    /// Versions and delete markers: keys in order, each key's newest first.
    pub versions: Vec<ObjectVersion>,
    /// Common prefixes, in order.
    pub prefixes: Vec<String>,
    /// Whether more follow.
    pub truncated: bool,
    /// Where the next page starts, when truncated: `NextKeyMarker`, and
    /// `NextVersionIdMarker` unless the page ended in a common prefix.
    pub next: Option<(String, Option<String>)>,
}

enum Item {
    Object(Box<ObjectInfo>),
    Prefix(String),
}

/// A file or folder met by a walk.
pub(crate) struct Entry {
    /// The full key; a folder's ends in `/`.
    pub key: String,
    pub path: PathBuf,
    pub folder: bool,
}

/// What a walk yields next: an object's entry (a file, or an empty folder), or a common
/// prefix.
pub(crate) enum Next {
    Object(Entry),
    Prefix(String),
}

/// A depth-first walk of a folder bucket in key order. It owns its state, so a walk can
/// pause and carry on later (each folder is read when the walk reaches it).
pub(crate) struct FolderWalk {
    query: ListQuery,
    stack: Vec<Frame>,
    last_prefix: Option<String>,
}

/// A folder being walked: its children, and the next one to look at.
struct Frame {
    dir: PathBuf,
    key_prefix: String,
    children: Children,
    next: usize,
}

impl Frame {
    /// A frame positioned for a walk resuming after `after`.
    fn new(dir: PathBuf, key_prefix: String, children: Children, after: Option<&After>) -> Self {
        let next = after.map_or(0, |a| start_at(&key_prefix, &children, a.marker()));
        Self {
            dir,
            key_prefix,
            children,
            next,
        }
    }

    fn next(&mut self) -> Option<Entry> {
        let child = self.children.get(self.next)?;
        self.next += 1;
        Some(Entry {
            key: format!("{}{}", self.key_prefix, child.suffix),
            path: self.dir.join(child.name()),
            folder: child.folder,
        })
    }
}

/// A listing's walk: a cursor, and the index to describe the objects it meets.
struct Walk<'a> {
    inner: &'a Inner,
    bucket: &'a str,
    cursor: FolderWalk,
}

impl Store {
    /// Lists a bucket.
    pub async fn list(&self, bucket: &str, query: ListQuery) -> Result<Listing> {
        let bucket = bucket.to_owned();
        self.blocking(move |inner| {
            let mut listing = Listing::default();
            let dir = match inner.bucket(&bucket)? {
                Bucket::Folder(FolderBucket { dir, .. }) => dir,
                Bucket::Object(object_bucket) => {
                    if query.max_keys > 0 {
                        inner.read_index(|conn| {
                            list_index(conn, &object_bucket, &query, &mut listing)
                        })?;
                    }
                    return Ok(listing);
                }
            };
            if query.max_keys == 0 {
                return Ok(listing);
            }
            let Some(cursor) = FolderWalk::start(&inner.folders, &dir, query.clone())? else {
                return Ok(listing);
            };
            let mut walk = Walk {
                inner,
                bucket: &bucket,
                cursor,
            };
            let mut count = 0;
            while let Some(item) = walk.next_item()? {
                if count == query.max_keys {
                    listing.truncated = true;
                    break;
                }
                count += 1;
                match item {
                    Item::Object(info) => {
                        listing.next = Some(After::Key(info.key.clone()));
                        listing.objects.push(*info);
                    }
                    Item::Prefix(prefix) => {
                        listing.next = Some(After::Prefix(prefix.clone()));
                        listing.prefixes.push(prefix);
                    }
                }
            }
            if !listing.truncated {
                listing.next = None;
            }
            Ok(listing)
        })
        .await
    }
}

impl Walk<'_> {
    fn next_item(&mut self) -> Result<Option<Item>> {
        Ok(match self.cursor.next(&self.inner.folders)? {
            None => None,
            Some(Next::Prefix(prefix)) => Some(Item::Prefix(prefix)),
            Some(Next::Object(entry)) => Some(self.object(&entry)?),
        })
    }

    fn object(&self, entry: &Entry) -> Result<Item> {
        let meta = fs::symlink_metadata(&entry.path)?;
        let info = Inner::info(&self.inner.lock(), self.bucket, &entry.key, &meta)?;
        Ok(Item::Object(Box::new(info)))
    }
}

impl FolderWalk {
    /// Starts at the deepest folder the prefix names; `None` when it names none.
    pub(crate) fn start(cache: &FolderCache, dir: &Path, query: ListQuery) -> Result<Option<Self>> {
        let folder_part = query
            .prefix
            .rfind('/')
            .map_or("", |end| &query.prefix[..=end]);
        let mut start = dir.to_owned();
        for segment in folder_part.split('/').filter(|s| !s.is_empty()) {
            if matches!(segment, "." | "..")
                || segment.len() > MAX_SEGMENT_LEN
                || segment.contains('\\')
            {
                return Ok(None);
            }
            start.push(segment);
        }
        if folder_part.contains("//") || folder_part.starts_with('/') {
            return Ok(None);
        }
        // The start folder must really be there, not through a link or in other letter case.
        match fs::canonicalize(&start) {
            Ok(real) if real == start && real.is_dir() => {}
            _ => return Ok(None),
        }
        let children = cache.children(&start, folder_part.is_empty())?;
        let frame = Frame::new(
            start,
            folder_part.to_owned(),
            children,
            query.after.as_ref(),
        );
        Ok(Some(Self {
            query,
            stack: vec![frame],
            last_prefix: None,
        }))
    }

    /// The next object entry or common prefix, in key order.
    pub(crate) fn next(&mut self, cache: &FolderCache) -> Result<Option<Next>> {
        let prefix = self.query.prefix.as_str();
        while let Some(frame) = self.stack.last_mut() {
            let Some(entry) = frame.next() else {
                self.stack.pop();
                continue;
            };
            let under_prefix = entry.key.starts_with(prefix);
            if entry.folder {
                if !(under_prefix || prefix.starts_with(&entry.key))
                    || self.skips_folder(&entry.key)
                {
                    continue;
                }
            } else if !under_prefix || !self.includes(&entry.key) {
                continue;
            }
            if under_prefix && let Some(common) = self.common_prefix(&entry.key) {
                if self.last_prefix.as_deref() == Some(common.as_str()) {
                    continue;
                }
                self.last_prefix = Some(common.clone());
                return Ok(Some(Next::Prefix(common)));
            }
            if entry.folder {
                let children = cache.children(&entry.path, false)?;
                if children.is_empty() {
                    // An empty folder is the object `key/`.
                    if under_prefix && self.includes(&entry.key) {
                        return Ok(Some(Next::Object(entry)));
                    }
                } else {
                    let frame =
                        Frame::new(entry.path, entry.key, children, self.query.after.as_ref());
                    self.stack.push(frame);
                }
                continue;
            }
            return Ok(Some(Next::Object(entry)));
        }
        Ok(None)
    }

    /// Whether a key comes after the start marker.
    fn includes(&self, key: &str) -> bool {
        match &self.query.after {
            None => true,
            Some(after) => {
                let marker = after.marker();
                key > marker && !(matches!(after, After::Prefix(_)) && key.starts_with(marker))
            }
        }
    }

    /// Whether every key under a folder is at or before the start marker.
    fn skips_folder(&self, folder_key: &str) -> bool {
        match &self.query.after {
            None => false,
            Some(after) => {
                let marker = after.marker();
                (folder_key < marker && !marker.starts_with(folder_key))
                    || (matches!(after, After::Prefix(_)) && folder_key.starts_with(marker))
            }
        }
    }

    /// The common prefix a key rolls up into, if the delimiter occurs after the prefix.
    fn common_prefix(&self, key: &str) -> Option<String> {
        let delimiter = self.query.delimiter.as_deref().filter(|d| !d.is_empty())?;
        let start = self.query.prefix.len();
        let at = key[start..].find(delimiter)?;
        Some(key[..start + at + delimiter.len()].to_owned())
    }
}

impl Store {
    /// Lists a bucket's versions and delete markers. In a folder bucket, each key's file
    /// is its current version ([`Store::list_folder_versions`]).
    pub async fn list_versions(
        &self,
        bucket: &str,
        query: VersionsQuery,
    ) -> Result<VersionListing> {
        let bucket = bucket.to_owned();
        let object_bucket = self
            .blocking(move |inner| match inner.bucket(&bucket)? {
                Bucket::Object(object_bucket) => Ok(Ok(object_bucket)),
                Bucket::Folder(bucket) => Ok(Err(bucket)),
            })
            .await?;
        match object_bucket {
            Ok(bucket) => {
                self.blocking(move |inner| {
                    let mut listing = VersionListing::default();
                    if query.max_keys > 0 {
                        inner.read_index(|conn| {
                            list_versions_index(conn, &bucket, &query, &mut listing)
                        })?;
                    }
                    Ok(listing)
                })
                .await
            }
            Err(bucket) => self.list_folder_versions(bucket, query).await,
        }
    }
}

/// The common prefix `key` rolls up into: up to the first `delimiter` after `prefix`.
pub(crate) fn common_prefix(key: &str, prefix: &str, delimiter: Option<&str>) -> Option<String> {
    let delimiter = delimiter.filter(|d| !d.is_empty())?;
    let rest = key.strip_prefix(prefix)?;
    let at = rest.find(delimiter)?;
    Some(key[..prefix.len() + at + delimiter.len()].to_owned())
}

/// Lists an object bucket from the index: rows in key order, rolled up into common
/// prefixes at the delimiter; a prefix already listed is skipped in one jump.
fn list_index(
    conn: &Index,
    bucket: &ObjectBucket,
    query: &ListQuery,
    listing: &mut Listing,
) -> Result<()> {
    let delimiter = query.delimiter.as_deref();
    let mut from = match &query.after {
        None => Cursor::Start,
        Some(After::Key(key)) => Cursor::AfterKey(key.clone()),
        Some(After::Prefix(prefix)) => Cursor::AfterAll(prefix.clone()),
    };
    let mut count = 0;
    'pages: loop {
        let batch = (query.max_keys - count + 1).clamp(1, 1000);
        let (rows, last) =
            conn.list_latest(&bucket.id, &query.prefix, from.as_versions_from(), batch)?;
        for row in rows {
            if count == query.max_keys {
                listing.truncated = true;
                break 'pages;
            }
            count += 1;
            if let Some(prefix) = common_prefix(&row.key, &query.prefix, delimiter) {
                listing.next = Some(After::Prefix(prefix.clone()));
                from = Cursor::AfterAll(prefix.clone());
                listing.prefixes.push(prefix);
                // Everything else under this prefix is rolled up: jump past it.
                continue 'pages;
            }
            listing.next = Some(After::Key(row.key.clone()));
            listing.objects.push(bucket.info(&row));
        }
        // A page can hold only delete markers: carry on after the last key scanned.
        match last {
            Some(last) => from = Cursor::AfterKey(last),
            None => break,
        }
    }
    if !listing.truncated {
        listing.next = None;
    }
    Ok(())
}

/// Lists an object bucket's versions from the index, rolled up like [`list_index`].
fn list_versions_index(
    conn: &Index,
    bucket: &ObjectBucket,
    query: &VersionsQuery,
    listing: &mut VersionListing,
) -> Result<()> {
    let delimiter = query.delimiter.as_deref();
    let mut from = match (&query.key_marker, &query.version_marker) {
        (None, _) => Cursor::Start,
        // A marker under a common prefix: the prefix was listed, and all it holds.
        (Some(key), _) if let Some(common) = common_prefix(key, &query.prefix, delimiter) => {
            Cursor::AfterAll(common)
        }
        (Some(key), None) => Cursor::AfterKey(key.clone()),
        (Some(key), Some(version)) => match conn.version(&bucket.id, key, version)? {
            Some(row) => Cursor::AfterVersion(row.key, row.seq),
            // A version gone since: its older versions would have followed it, so carry
            // on after the key rather than list them twice or fail the listing.
            None => Cursor::AfterKey(key.clone()),
        },
    };
    let mut count = 0;
    'pages: loop {
        let batch = (query.max_keys - count + 1).clamp(1, 1000);
        let rows = conn.list_versions(&bucket.id, &query.prefix, from.as_versions_from(), batch)?;
        let full = rows.len() == batch;
        for row in rows {
            if count == query.max_keys {
                listing.truncated = true;
                break 'pages;
            }
            count += 1;
            if let Some(prefix) = common_prefix(&row.key, &query.prefix, delimiter) {
                listing.next = Some((prefix.clone(), None));
                from = Cursor::AfterAll(prefix.clone());
                listing.prefixes.push(prefix);
                continue 'pages;
            }
            listing.next = Some((row.key.clone(), Some(row.version_id.clone())));
            from = Cursor::AfterVersion(row.key.clone(), row.seq);
            listing.versions.push(ObjectVersion {
                info: ObjectInfo {
                    version_id: Some(row.version_id.clone()),
                    ..bucket.info(&row)
                },
                latest: row.latest,
                delete_marker: row.delete_marker,
            });
        }
        if !full {
            break;
        }
    }
    if !listing.truncated {
        listing.next = None;
    }
    Ok(())
}

/// An owned [`VersionsFrom`].
#[derive(Debug, Clone)]
pub(crate) enum Cursor {
    Start,
    AfterKey(String),
    AfterVersion(String, i64),
    AfterAll(String),
}

impl Cursor {
    pub(crate) fn as_versions_from(&self) -> VersionsFrom<'_> {
        match self {
            Cursor::Start => VersionsFrom::Start,
            Cursor::AfterKey(key) => VersionsFrom::AfterKey(key),
            Cursor::AfterVersion(key, seq) => VersionsFrom::AfterVersion(key, *seq),
            Cursor::AfterAll(prefix) => VersionsFrom::AfterAll(prefix),
        }
    }
}
