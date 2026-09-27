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

use teifs_meta::{Index, ListFrom};

use crate::{
    Bucket, Inner, ObjectInfo, Store,
    error::Result,
    folders::{Children, FolderCache, start_at},
    objects::to_info,
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
                Bucket::Folder(_, dir) => dir,
                Bucket::Object(object_bucket) => {
                    if query.max_keys > 0 {
                        list_index(&inner.lock(), &object_bucket.id, &query, &mut listing)?;
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

/// Lists an object bucket from the index: rows in key order, rolled up into common
/// prefixes at the delimiter; a prefix already listed is skipped in one jump.
fn list_index(
    conn: &Index,
    bucket_id: &str,
    query: &ListQuery,
    listing: &mut Listing,
) -> Result<()> {
    let delimiter = query.delimiter.as_deref().filter(|d| !d.is_empty());
    let mut from = match &query.after {
        None => Cursor::Start,
        Some(After::Key(key)) => Cursor::AfterKey(key.clone()),
        Some(After::Prefix(prefix)) => Cursor::AfterAll(prefix.clone()),
    };
    let mut count = 0;
    'pages: loop {
        let batch = (query.max_keys - count + 1).clamp(1, 1000);
        let rows = conn.list_latest(bucket_id, &query.prefix, from.as_list_from(), batch)?;
        let Some(last) = rows.last().map(|r| r.key.clone()) else {
            break;
        };
        for row in rows {
            let common = delimiter.and_then(|d| {
                let rest = &row.key[query.prefix.len()..];
                rest.find(d)
                    .map(|at| row.key[..query.prefix.len() + at + d.len()].to_owned())
            });
            if count == query.max_keys {
                listing.truncated = true;
                break 'pages;
            }
            count += 1;
            if let Some(prefix) = common {
                listing.next = Some(After::Prefix(prefix.clone()));
                from = Cursor::AfterAll(prefix.clone());
                listing.prefixes.push(prefix);
                // Everything else under this prefix is rolled up: jump past it.
                continue 'pages;
            }
            listing.next = Some(After::Key(row.key.clone()));
            listing.objects.push(to_info(&row));
        }
        from = Cursor::AfterKey(last);
    }
    if !listing.truncated {
        listing.next = None;
    }
    Ok(())
}

/// An owned [`ListFrom`].
enum Cursor {
    Start,
    AfterKey(String),
    AfterAll(String),
}

impl Cursor {
    fn as_list_from(&self) -> ListFrom<'_> {
        match self {
            Cursor::Start => ListFrom::Start,
            Cursor::AfterKey(key) => ListFrom::AfterKey(key),
            Cursor::AfterAll(prefix) => ListFrom::AfterAll(prefix),
        }
    }
}
