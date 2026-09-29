//! Keeping folder buckets' index in step with their files.
//!
//! Files in a folder bucket can be added, changed, restored or deleted by anything, not
//! only TeiFS. A row describes a file only while its size and modification time match,
//! and until a file's MD5 is known its ETag is provisional. The `index-folders` job walks
//! every folder bucket in key order, a page per step, and:
//!
//! - hashes files without a matching row. If the content still matches the old row (a
//!   copy or a restore that lost modification times; multipart ETags are recomputed from
//!   the recorded part sizes), the row is re-adopted with its metadata, tags and
//!   checksums; otherwise the file gets a new row with its MD5;
//! - forgets rows whose files are gone.
//!
//! Hashing happens without the commit lock; the result is written only if, under the
//! lock, the file and its row are still what was hashed, so it never races TeiFS's own
//! writes.

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    io::{self, Read},
    path::Path,
    time::Duration,
};

use md5::{Digest, Md5};
use teifs_meta::{Layout, Row};
use teifs_types::{Stamp, hex, multipart_etag};

use crate::{
    Bucket, Inner, ObjectAttrs, ObjectKey,
    error::Result,
    folder::FolderBucket,
    folder::Found,
    jobs::{Job, Step},
    list::{After, Entry, FolderWalk, ListQuery, Next},
    objects::PartsRecord,
};

/// Files looked at per step.
const ENTRIES_PER_STEP: usize = 1000;
/// Bytes hashed per step (a larger file is hashed whole, in one step).
const BYTES_PER_STEP: u64 = 64 << 20;
/// Rows checked per query when forgetting deleted files.
const PRUNE_BATCH: usize = 1000;
/// How long to rest after a full pass over every folder bucket.
const PASS_IDLE: Duration = Duration::from_mins(30);
/// Read size while hashing.
const CHUNK: usize = 1 << 20;

/// Walks folder buckets, hashing new and changed files and forgetting deleted ones.
#[derive(Default)]
pub(crate) struct IndexFolders {
    /// The bucket being walked.
    bucket: Option<String>,
    /// The last key done in it: where a new walk resumes (after a restart, say).
    after: Option<String>,
    /// The walk itself, kept between steps so no folder is read twice in a pass.
    walk: Option<FolderWalk>,
    /// Entries the walk yielded that a step had no budget left for.
    backlog: VecDeque<Entry>,
    /// A pass just ended: rest before the next.
    rest: bool,
}

impl Job for IndexFolders {
    fn name(&self) -> &'static str {
        "index-folders"
    }

    fn step(&mut self, inner: &Inner, step: &Step) -> Result<usize> {
        if std::mem::take(&mut self.rest) {
            return Ok(0);
        }
        let folders: Vec<String> = inner
            .buckets()?
            .into_iter()
            .filter(|b| b.layout == Layout::Folder)
            .map(|b| b.name)
            .collect();
        // Carry on with the current bucket, or the one after it if it's gone.
        let bucket = match self.bucket.take() {
            Some(current) if folders.contains(&current) => current,
            Some(current) => match folders.iter().find(|name| **name > current) {
                Some(next) => self.start(next),
                None => return Ok(self.end_pass()),
            },
            None => match folders.first() {
                Some(first) => self.start(first),
                None => return Ok(0),
            },
        };
        let (looked_at, finished) = self.scan(inner, &bucket, step)?;
        if finished {
            match folders.iter().find(|name| **name > bucket) {
                Some(next) => {
                    self.start(next);
                }
                None => {
                    self.end_pass();
                }
            }
        } else {
            self.bucket = Some(bucket);
        }
        // The walk moved even when nothing needed doing: that's progress.
        Ok(looked_at.max(1))
    }

    fn idle(&self) -> Duration {
        PASS_IDLE
    }
}

impl IndexFolders {
    /// Makes `bucket` the one to walk, from its start.
    fn start(&mut self, bucket: &str) -> String {
        self.bucket = Some(bucket.to_owned());
        self.after = None;
        self.walk = None;
        self.backlog.clear();
        bucket.to_owned()
    }

    fn end_pass(&mut self) -> usize {
        self.start("");
        self.bucket = None;
        self.rest = true;
        1
    }

    /// Takes the next page of `bucket`; how many entries it looked at (and rows it
    /// forgot), and whether the bucket is done.
    fn scan(&mut self, inner: &Inner, bucket: &str, step: &Step) -> Result<(usize, bool)> {
        let dir = match inner.bucket(bucket)? {
            Bucket::Folder(FolderBucket { dir, .. }) => dir,
            Bucket::Object(_) => return Ok((0, true)),
        };
        if self.walk.is_none() && self.backlog.is_empty() {
            let query = ListQuery {
                after: self.after.clone().map(After::Key),
                max_keys: usize::MAX,
                ..ListQuery::default()
            };
            match FolderWalk::start(&inner.folders, &dir, query)? {
                Some(walk) => self.walk = Some(walk),
                None => return Ok((0, true)),
            }
        }
        // A page of entries (the backlog first), then their rows in one query.
        let mut entries: Vec<Entry> = self.backlog.drain(..).collect();
        while entries.len() < ENTRIES_PER_STEP {
            let Some(walk) = self.walk.as_mut() else {
                break;
            };
            match walk.next(&inner.folders)? {
                None => self.walk = None,
                Some(Next::Prefix(_)) => {}
                Some(Next::Object(entry)) => entries.push(entry),
            }
        }
        let rows: BTreeMap<String, Row> = match entries.last() {
            Some(last) => inner
                .lock()
                .rows_between(bucket, self.after.as_deref(), &last.key)?
                .into_iter()
                .collect(),
            None => BTreeMap::new(),
        };
        let mut seen = Vec::with_capacity(entries.len());
        let mut updates = Vec::new();
        let mut hashed = 0;
        let mut entries = entries.into_iter();
        for entry in entries.by_ref() {
            if !entry.folder {
                let (bytes, update) =
                    check_file(&entry.key, &entry.path, rows.get(&entry.key), step)?;
                hashed += bytes;
                updates.extend(update);
            }
            seen.push(entry.key);
            if hashed >= BYTES_PER_STEP || step.cancel.is_cancelled() {
                break;
            }
        }
        self.backlog.extend(entries);
        apply(inner, bucket, &updates)?;
        let finished = self.walk.is_none() && self.backlog.is_empty();
        let upto = if finished { None } else { seen.last().cloned() };
        let pruned = prune(
            inner,
            bucket,
            &dir,
            self.after.as_deref(),
            upto.as_deref(),
            &seen,
        )?;
        if let Some(last) = seen.last() {
            self.after = Some(last.clone());
        }
        Ok((seen.len() + pruned, finished))
    }
}

/// A row to write, if the file and its row are still what was hashed.
struct Update {
    key: String,
    path: std::path::PathBuf,
    /// The row the decision was based on.
    prior: Option<Row>,
    row: Row,
}

/// Works out one file's new row, if it needs one; how many bytes it hashed.
fn check_file(
    key: &str,
    path: &Path,
    prior: Option<&Row>,
    step: &Step,
) -> Result<(u64, Option<Update>)> {
    let stamp = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Stamp::of(&meta),
        Ok(_) => return Ok((0, None)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok((0, None)),
        Err(err) => return Err(err.into()),
    };
    if prior.is_some_and(|r| r.stamp.matches(&stamp)) {
        return Ok((0, None));
    }
    let part_sizes = prior
        .and_then(|r| r.parts.as_deref())
        .and_then(|json| PartsRecord::parse(json).ok())
        .map(|parts| parts.sizes);
    let Some(hashes) = hash_file(path, stamp, part_sizes.as_deref(), step)? else {
        // Changing as it was read, or the jobs are stopping: next pass.
        return Ok((stamp.size, None));
    };
    // The content an old row describes survives a copy that lost modification times.
    let readopted = prior.filter(|r| hashes.matches(&r.etag));
    let row = Row {
        stamp,
        etag: readopted.map_or_else(|| hex(&hashes.whole), |r| r.etag.clone()),
        attrs: readopted.map_or_else(ObjectAttrs::default, |r| r.attrs.clone()),
        parts: readopted.and_then(|r| r.parts.clone()),
        // The same content keeps its version; other content written outside TeiFS is the
        // `null` version, as any file added by hand.
        version_id: readopted.and_then(|r| r.version_id.clone()),
    };
    let update = Update {
        key: key.to_owned(),
        path: path.to_owned(),
        prior: prior.cloned(),
        row,
    };
    Ok((stamp.size, Some(update)))
}

/// Writes a step's new rows in one transaction, each only if its file is still the one
/// that was hashed and nobody wrote the object meanwhile.
fn apply(inner: &Inner, bucket: &str, updates: &[Update]) -> Result<()> {
    if updates.is_empty() {
        return Ok(());
    }
    inner.lock().batch(|conn| {
        for update in updates {
            let unchanged = fs::symlink_metadata(&update.path)
                .is_ok_and(|m| Stamp::of(&m).matches(&update.row.stamp));
            let current = conn.get(bucket, &update.key)?;
            let same_row = match (&current, &update.prior) {
                (None, None) => true,
                (Some(a), Some(b)) => a.etag == b.etag && a.stamp.matches(&b.stamp),
                _ => false,
            };
            if unchanged && same_row {
                conn.put(bucket, &update.key, &update.row)?;
            }
        }
        Ok(())
    })?;
    Ok(())
}

/// What hashing a file found: its MD5, and each recorded part's MD5 when its size
/// matches the parts.
struct Hashes {
    whole: [u8; 16],
    parts: Option<Vec<[u8; 16]>>,
}

impl Hashes {
    /// Whether this content is what an ETag describes.
    fn matches(&self, etag: &str) -> bool {
        hex(&self.whole) == etag
            || self
                .parts
                .as_ref()
                .is_some_and(|p| multipart_etag(p) == etag)
    }
}

/// Hashes a file in one read, as a whole and in `part_sizes`; `None` if it changed while
/// being read or the jobs are stopping.
fn hash_file(
    path: &Path,
    stamp: Stamp,
    part_sizes: Option<&[u64]>,
    step: &Step,
) -> Result<Option<Hashes>> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let sizes = part_sizes.filter(|sizes| sizes.iter().sum::<u64>() == stamp.size);
    let mut whole = Md5::new();
    let mut parts = sizes.map(|sizes| (sizes.iter().copied(), Vec::with_capacity(sizes.len())));
    let mut part = Md5::new();
    let mut left_in_part = 0u64;
    let mut buf = vec![0; CHUNK];
    loop {
        if step.cancel.is_cancelled() {
            return Ok(None);
        }
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut chunk = &buf[..n];
        whole.update(chunk);
        if let Some((sizes, done)) = parts.as_mut() {
            while !chunk.is_empty() {
                if left_in_part == 0 {
                    match sizes.next() {
                        Some(size) => left_in_part = size,
                        None => break,
                    }
                }
                let take = usize::try_from(left_in_part.min(chunk.len() as u64)).unwrap_or(0);
                part.update(&chunk[..take]);
                chunk = &chunk[take..];
                left_in_part -= take as u64;
                if left_in_part == 0 {
                    done.push(std::mem::replace(&mut part, Md5::new()).finalize().into());
                }
            }
        }
    }
    let after = fs::symlink_metadata(path)?;
    if !Stamp::of(&after).matches(&stamp) {
        return Ok(None);
    }
    Ok(Some(Hashes {
        whole: whole.finalize().into(),
        parts: parts.map(|(_, done)| done),
    }))
}

/// Forgets rows after `after` up to `upto` (to the end when `None`) that no file in
/// `seen` backs and whose file is really gone (a folder marker stays while its folder
/// exists); how many it forgot.
fn prune(
    inner: &Inner,
    bucket: &str,
    dir: &Path,
    after: Option<&str>,
    upto: Option<&str>,
    seen: &[String],
) -> Result<usize> {
    let mut from = after.map(str::to_owned);
    let mut pruned = 0;
    loop {
        let conn = inner.lock();
        let keys = conn.keys_between(bucket, from.as_deref(), upto, PRUNE_BATCH)?;
        let Some(last) = keys.last().cloned() else {
            return Ok(pruned);
        };
        pruned += conn.batch(|conn| {
            let mut forgot = 0;
            for key in keys {
                // `seen` is in key order, like the rows.
                if seen.binary_search(&key).is_ok() {
                    continue;
                }
                let backed = ObjectKey::parse(&key).is_ok_and(|parsed| {
                    matches!(
                        Inner::find(dir, &parsed),
                        Ok(Found::File(..) | Found::Folder(..))
                    )
                });
                if !backed {
                    conn.delete(bucket, &key)?;
                    forgot += 1;
                }
            }
            Ok(forgot)
        })?;
        from = Some(last);
    }
}

#[cfg(test)]
mod tests;
