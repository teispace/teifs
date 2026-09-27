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

use crate::{Inner, ObjectInfo, Store, error::Result};

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

struct Entry {
    /// The full key; a folder's ends in `/`.
    key: String,
    path: PathBuf,
    folder: bool,
}

struct Walk<'a> {
    inner: &'a Inner,
    bucket: &'a str,
    query: &'a ListQuery,
    stack: Vec<std::vec::IntoIter<Entry>>,
    last_prefix: Option<String>,
}

impl Store {
    /// Lists a bucket.
    pub async fn list(&self, bucket: &str, query: ListQuery) -> Result<Listing> {
        let bucket = bucket.to_owned();
        self.blocking(move |inner| {
            let dir = inner.bucket_dir(&bucket)?;
            let mut listing = Listing::default();
            if query.max_keys == 0 {
                return Ok(listing);
            }
            let Some(mut walk) = Walk::start(inner, &bucket, &dir, &query)? else {
                return Ok(listing);
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

impl<'a> Walk<'a> {
    /// Starts at the deepest folder the prefix names; `None` when it names none.
    fn start(
        inner: &'a Inner,
        bucket: &'a str,
        dir: &Path,
        query: &'a ListQuery,
    ) -> Result<Option<Self>> {
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
        let entries = read_folder(&start, folder_part)?;
        Ok(Some(Self {
            inner,
            bucket,
            query,
            stack: vec![entries.into_iter()],
            last_prefix: None,
        }))
    }

    fn next_item(&mut self) -> Result<Option<Item>> {
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
                return Ok(Some(Item::Prefix(common)));
            }
            if entry.folder {
                let children = read_folder(&entry.path, &entry.key)?;
                if children.is_empty() {
                    // An empty folder is the object `key/`.
                    if under_prefix && self.includes(&entry.key) {
                        return self.object(&entry).map(Some);
                    }
                } else {
                    self.stack.push(children.into_iter());
                }
                continue;
            }
            return self.object(&entry).map(Some);
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

    fn object(&self, entry: &Entry) -> Result<Item> {
        let meta = fs::symlink_metadata(&entry.path)?;
        let info = Inner::info(&self.inner.lock(), self.bucket, &entry.key, &meta)?;
        Ok(Item::Object(Box::new(info)))
    }
}

/// A folder's files and subfolders in key order. Links, other kinds of files, and names
/// that can't be keys are left out.
fn read_folder(dir: &Path, key_prefix: &str) -> Result<Vec<Entry>> {
    let reader = match fs::read_dir(dir) {
        Ok(reader) => reader,
        // Deleted while the listing ran: nothing in it.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut entries = Vec::new();
    for entry in reader {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.contains('\\') {
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let folder = kind.is_dir();
        if !folder && !kind.is_file() {
            continue;
        }
        let key = if folder {
            format!("{key_prefix}{name}/")
        } else {
            format!("{key_prefix}{name}")
        };
        entries.push(Entry {
            key,
            path: entry.path(),
            folder,
        });
    }
    entries.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    Ok(entries)
}
