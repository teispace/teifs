//! Folders' contents in key order, cached for large folders.
//!
//! Listing a folder bucket page by page would otherwise read and sort a large folder
//! again for every page: a full listing of a flat folder of n files costs n²/1000.
//! Large folders' sorted contents are kept, and used only while the folder's
//! modification time is the one they were read at: adding, removing or renaming an entry
//! changes it, so a stale copy is never used. A copy read just after the folder's last
//! change isn't kept, since a change made in the same clock tick would leave the time
//! as it was (git's "racy" rule): within [`RACY_COARSE`] for times in whole seconds (FAT,
//! HFS+, ext3), and [`RACY_FINE`] for finer ones, whose tick is still a few milliseconds
//! on Linux and Windows.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use teifs_types::BUCKET_STAGING;

use crate::error::Result;

/// Folders with fewer entries are read each time (cheap enough).
const MIN_CACHED: usize = 1000;
/// The most entries kept across all folders.
const MAX_ENTRIES: usize = 2_000_000;
/// How long after a folder's last change its contents may be kept, when its times are in
/// whole seconds.
const RACY_COARSE: Duration = Duration::from_secs(2);
/// The same, for times finer than a second.
const RACY_FINE: Duration = Duration::from_millis(100);

/// One file or subfolder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Child {
    /// Its part of the key: the name, with `/` after a folder's.
    pub suffix: Box<str>,
    pub folder: bool,
}

impl Child {
    /// Its name in the folder.
    pub fn name(&self) -> &str {
        self.suffix.trim_end_matches('/')
    }
}

/// A folder's children, sorted by suffix (S3's byte order).
pub(crate) type Children = Arc<Vec<Child>>;

#[derive(Debug, Default)]
pub(crate) struct FolderCache {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    folders: HashMap<PathBuf, Cached>,
    entries: usize,
    clock: u64,
}

#[derive(Debug)]
struct Cached {
    modified: SystemTime,
    children: Children,
    used: u64,
}

impl FolderCache {
    /// The children of `dir` in key order; `root` for a bucket's own folder (its staging
    /// folder isn't content). A folder that's gone has none.
    pub(crate) fn children(&self, dir: &Path, root: bool) -> Result<Children> {
        let modified = match fs::metadata(dir) {
            Ok(meta) => meta.modified().ok(),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Children::default()),
            Err(err) => return Err(err.into()),
        };
        if let Some(modified) = modified {
            let mut state = self.lock();
            state.clock += 1;
            let now = state.clock;
            if let Some(cached) = state.folders.get_mut(dir)
                && cached.modified == modified
            {
                cached.used = now;
                return Ok(Arc::clone(&cached.children));
            }
        }
        let children: Children = Arc::new(read(dir, root)?);
        let settled = modified.is_some_and(settled);
        if let Some(modified) = modified.filter(|_| settled && children.len() >= MIN_CACHED) {
            self.lock().keep(dir, modified, Arc::clone(&children));
        }
        Ok(children)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Whether a folder last changed at `modified` has been still long enough to trust that
/// its time would show a further change.
fn settled(modified: SystemTime) -> bool {
    let whole_second = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .is_ok_and(|d| d.subsec_nanos() == 0);
    let racy = if whole_second { RACY_COARSE } else { RACY_FINE };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age > racy)
}

impl State {
    fn keep(&mut self, dir: &Path, modified: SystemTime, children: Children) {
        if children.len() > MAX_ENTRIES {
            return;
        }
        if let Some(old) = self.folders.remove(dir) {
            self.entries -= old.children.len();
        }
        // Make room by forgetting the least recently used folders.
        while self.entries + children.len() > MAX_ENTRIES {
            let Some(oldest) = self
                .folders
                .iter()
                .min_by_key(|(_, c)| c.used)
                .map(|(path, _)| path.clone())
            else {
                break;
            };
            if let Some(old) = self.folders.remove(&oldest) {
                self.entries -= old.children.len();
            }
        }
        self.clock += 1;
        self.entries += children.len();
        self.folders.insert(
            dir.to_owned(),
            Cached {
                modified,
                children,
                used: self.clock,
            },
        );
    }
}

/// Reads a folder: files and subfolders, sorted. Links, other kinds of files, and names
/// that can't be keys are left out.
fn read(dir: &Path, root: bool) -> Result<Vec<Child>> {
    let reader = match fs::read_dir(dir) {
        Ok(reader) => reader,
        // Deleted while being listed: nothing in it.
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut children = Vec::new();
    for entry in reader {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.contains('\\') || (root && name == BUCKET_STAGING) {
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let folder = kind.is_dir();
        if !folder && !kind.is_file() {
            continue;
        }
        let suffix = if folder {
            format!("{name}/")
        } else {
            name.to_owned()
        };
        children.push(Child {
            suffix: suffix.into_boxed_str(),
            folder,
        });
    }
    children.sort_unstable_by(|a, b| a.suffix.cmp(&b.suffix));
    Ok(children)
}

/// Where to start in a folder's children for a walk that resumes after `marker`: the
/// first child whose key isn't before it, or the folder the marker is inside.
pub(crate) fn start_at(key_prefix: &str, children: &[Child], marker: &str) -> usize {
    match marker.strip_prefix(key_prefix) {
        Some(rest) => {
            let at = children.partition_point(|c| &*c.suffix < rest);
            match at.checked_sub(1).map(|i| &children[i]) {
                Some(before) if before.folder && rest.starts_with(&*before.suffix) => at - 1,
                _ => at,
            }
        }
        // Every key here comes after the marker, or every one before it.
        None if marker < key_prefix => 0,
        None => children.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn children(names: &[&str]) -> Vec<Child> {
        names
            .iter()
            .map(|n| Child {
                suffix: (*n).into(),
                folder: n.ends_with('/'),
            })
            .collect()
    }

    #[test]
    fn walks_resume_where_the_marker_is() {
        let kids = children(&["a", "b/", "c", "d/"]);
        assert_eq!(start_at("", &kids, ""), 0);
        assert_eq!(start_at("", &kids, "a"), 0);
        assert_eq!(start_at("", &kids, "a0"), 1);
        // Inside folder b/: resume in it.
        assert_eq!(start_at("", &kids, "b/x"), 1);
        assert_eq!(start_at("", &kids, "c"), 2);
        assert_eq!(start_at("", &kids, "z"), 4);
        // A deeper folder whose keys all come after, or all before, the marker.
        assert_eq!(start_at("q/", &kids, "b"), 0);
        assert_eq!(start_at("b/", &kids, "c"), 4);
        assert_eq!(start_at("b/", &kids, "b/c"), 2);
    }

    #[test]
    fn large_settled_folders_are_kept_until_they_change() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..MIN_CACHED {
            fs::write(dir.path().join(format!("f{i:05}")), b"").unwrap();
        }
        // Settle the folder: a copy read just after a change isn't kept.
        let old = SystemTime::now() - Duration::from_secs(60);
        crate::test_util::set_folder_modified(dir.path(), old);
        let cache = FolderCache::default();
        let first = cache.children(dir.path(), false).unwrap();
        assert_eq!(first.len(), MIN_CACHED);
        let again = cache.children(dir.path(), false).unwrap();
        assert!(Arc::ptr_eq(&first, &again), "served from the cache");

        // Adding a file changes the folder's time: the cache isn't used.
        fs::write(dir.path().join("new"), b"").unwrap();
        let fresh = cache.children(dir.path(), false).unwrap();
        assert_eq!(fresh.len(), MIN_CACHED + 1);
        assert!(fresh.iter().any(|c| &*c.suffix == "new"));
    }

    #[test]
    fn coarse_times_wait_longer_than_fine_ones() {
        let now = SystemTime::now();
        let whole = |secs_ago: u64| {
            let t = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - secs_ago;
            SystemTime::UNIX_EPOCH + Duration::from_secs(t)
        };
        assert!(!settled(whole(1)) || !settled(whole(0)));
        assert!(settled(whole(3)));
        let fine = now - Duration::from_millis(150) + Duration::from_nanos(1);
        assert!(settled(fine));
        assert!(!settled(
            now - Duration::from_millis(20) + Duration::from_nanos(1)
        ));
        assert!(
            !settled(now + Duration::from_secs(5)),
            "a time in the future isn't settled"
        );
    }

    #[test]
    fn small_or_just_changed_folders_are_read_each_time() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), b"").unwrap();
        let cache = FolderCache::default();
        let one = cache.children(dir.path(), false).unwrap();
        let two = cache.children(dir.path(), false).unwrap();
        assert!(!Arc::ptr_eq(&one, &two));
        assert!(cache.lock().folders.is_empty());
    }

    #[test]
    fn the_bucket_staging_folder_is_not_content() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(BUCKET_STAGING)).unwrap();
        fs::write(dir.path().join("a"), b"").unwrap();
        let cache = FolderCache::default();
        let root = cache.children(dir.path(), true).unwrap();
        assert_eq!(root.iter().map(Child::name).collect::<Vec<_>>(), ["a"]);
        let inner = cache.children(dir.path(), false).unwrap();
        assert_eq!(inner.len(), 2);
    }
}
