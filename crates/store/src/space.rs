//! Disk space: writes are refused before they'd leave the disk with less than a reserve.
//!
//! On a completely full disk even deleting fails (SQLite needs a little room for its
//! write-ahead log), so nobody could free space through S3. Keeping a reserve free for
//! deletes and metadata avoids that; writes that would eat into it get `StorageFull`
//! (`507` over S3) up front instead of failing halfway.

use std::path::Path;

use crate::{Bucket, Inner, Store, StoreError, error::Result, folder::FolderBucket};

const MIB: u64 = 1024 * 1024;
/// The least room kept free: enough for deletes and the index's log.
const MIN_RESERVE: u64 = 64 * MIB;
/// The most room kept free, however large the disk.
const MAX_RESERVE: u64 = 1024 * MIB;

/// The room kept free on a disk of `total` bytes: 0.1 %, within bounds. Small on
/// purpose: a nearly full laptop disk still takes writes while it has room.
fn reserve(total: u64) -> u64 {
    (total / 1000).clamp(MIN_RESERVE, MAX_RESERVE)
}

/// Whether writing `len` bytes to a disk with `available` of `total` bytes free leaves
/// the reserve. Encrypted objects take slightly more room than their size.
fn has_room(available: u64, total: u64, len: u64) -> bool {
    let needed = len.saturating_add(len / 1024);
    available.saturating_sub(needed) >= reserve(total)
}

impl Inner {
    /// Fails with `StorageFull` unless `len` more bytes fit on the disks a write to
    /// `bucket` uses: the drive's (where writes are staged) and a folder bucket's own, if
    /// it's elsewhere.
    pub(crate) fn ensure_space(&self, bucket: &str, len: u64) -> Result<()> {
        let bucket_dir = match self.bucket(bucket)? {
            Bucket::Folder(FolderBucket { dir, .. }) => Some(dir),
            Bucket::Object(_) => None,
        };
        for dir in [Some(self.tmp.as_path()), bucket_dir.as_deref()]
            .into_iter()
            .flatten()
        {
            fits(dir, len)?;
        }
        Ok(())
    }
}

/// Whether two disks are one: the same device, where that can be told, or else the same
/// size and room.
fn same_disk(a: &Disk, b: &Disk) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a), Ok(b)) = (std::fs::metadata(&a.path), std::fs::metadata(&b.path)) {
            return a.dev() == b.dev();
        }
    }
    a.total == b.total && a.available == b.available
}

pub(crate) fn fits(dir: &Path, len: u64) -> Result<()> {
    let stats = fs4::statvfs(dir)?;
    if has_room(stats.available_space(), stats.total_space(), len) {
        Ok(())
    } else {
        Err(StoreError::StorageFull)
    }
}

/// Whether a drive can serve, as a health check asks: cheap, and never waiting for a
/// lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    /// Its index is there: it can serve reads.
    pub readable: bool,
    /// It can serve reads, and its disk has more room than the reserve: it can take writes.
    pub writable: bool,
}

/// A disk the drive uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    /// A folder on it: the drive's, or a folder bucket's kept elsewhere.
    pub path: std::path::PathBuf,
    /// Its size, in bytes.
    pub total: u64,
    /// The bytes free for the drive.
    pub available: u64,
    /// The bytes kept free for deletes and metadata.
    pub reserve: u64,
}

impl Disk {
    /// The disk `path` is on, as the drive sees it.
    pub fn at(path: &Path) -> Result<Self> {
        let stats = fs4::statvfs(path)?;
        Ok(Self {
            path: path.to_owned(),
            total: stats.total_space(),
            available: stats.available_space(),
            reserve: reserve(stats.total_space()),
        })
    }
}

impl Store {
    /// The disks the drive uses: its own, then those of folder buckets kept outside it
    /// (linked folders), each once.
    pub async fn disks(&self) -> Result<Vec<Disk>> {
        self.blocking(|inner| {
            let mut dirs = vec![inner.root.clone()];
            for bucket in inner.buckets()? {
                if bucket.layout == crate::Layout::Folder
                    && let Ok(Bucket::Folder(FolderBucket { dir, .. })) = inner.bucket(&bucket.name)
                    && !dir.starts_with(&inner.root)
                {
                    dirs.push(dir);
                }
            }
            let mut disks: Vec<Disk> = Vec::new();
            for dir in dirs {
                let disk = Disk::at(&dir)?;
                if !disks.iter().any(|seen| same_disk(seen, &disk)) {
                    disks.push(disk);
                }
            }
            Ok(disks)
        })
        .await
    }

    /// Whether the drive can serve reads and take writes. A disk that went away (an
    /// unmounted volume, a removed folder) can't serve either.
    pub async fn health(&self) -> Health {
        let inner = std::sync::Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let readable = inner.system_dir.join(crate::format::INDEX_DB).is_file();
            Health {
                readable,
                writable: readable && fits(&inner.tmp, 0).is_ok(),
            }
        })
        .await
        .unwrap_or(Health {
            readable: false,
            writable: false,
        })
    }

    /// Checks a write before its bytes are read: that `key` (when the write names one)
    /// can be created in `bucket`, and that `len` more bytes (when known) leave the room
    /// kept free for deletes and metadata.
    pub async fn check_write(
        &self,
        bucket: &str,
        key: Option<&str>,
        len: Option<u64>,
    ) -> Result<()> {
        let (bucket, key) = (bucket.to_owned(), key.map(str::to_owned));
        self.blocking(move |inner| {
            if let Some(key) = &key {
                match inner.bucket(&bucket)? {
                    Bucket::Folder(..) => {
                        inner.new_key(key)?;
                    }
                    Bucket::Object(_) => teifs_types::check_object_key(key)?,
                }
            }
            match len {
                Some(len) => inner.ensure_space(&bucket, len),
                None => Ok(()),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * MIB;

    #[test]
    fn the_reserve_is_a_tenth_of_a_percent_within_bounds() {
        assert_eq!(reserve(10 * GIB), MIN_RESERVE);
        assert_eq!(reserve(500 * GIB), GIB / 2);
        assert_eq!(reserve(20_000 * GIB), MAX_RESERVE);
    }

    #[test]
    fn writes_that_would_eat_the_reserve_are_refused() {
        let total = 100 * GIB;
        // 100 GiB: 100 MiB kept free.
        assert!(has_room(10 * GIB, total, 9 * GIB));
        assert!(!has_room(10 * GIB, total, 10 * GIB - 50 * MIB));
        assert!(!has_room(90 * MIB, total, 1));
        assert!(!has_room(10 * GIB, total, u64::MAX));
    }

    #[tokio::test]
    async fn each_disk_the_drive_uses_is_told_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .create_bucket("here", crate::Layout::Folder)
            .await
            .unwrap();
        // A folder bucket kept elsewhere (here on the same disk), linked in.
        #[cfg(unix)]
        {
            let elsewhere = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("linked")).unwrap();
            let buckets = store.list_buckets().await.unwrap();
            assert!(buckets.iter().any(|b| b.name == "linked"));
            assert_eq!(store.disks().await.unwrap().len(), 1);
        }
        let disks = store.disks().await.unwrap();
        assert_eq!(disks.len(), 1);
        let disk = &disks[0];
        assert_eq!(disk.path, std::fs::canonicalize(dir.path()).unwrap());
        assert!(disk.total > 0 && disk.available <= disk.total);
        assert_eq!(disk.reserve, reserve(disk.total));
    }

    #[test]
    fn disks_are_told_apart() {
        let disk = |path: &str, total, available| Disk {
            path: path.into(),
            total,
            available,
            reserve: 0,
        };
        // Folders that can't be looked at: by their size and room.
        assert!(same_disk(
            &disk("/nothing/a", 10, 5),
            &disk("/nothing/b", 10, 5)
        ));
        assert!(!same_disk(
            &disk("/nothing/a", 10, 5),
            &disk("/nothing/b", 10, 4)
        ));
        assert!(!same_disk(
            &disk("/nothing/a", 10, 5),
            &disk("/nothing/b", 11, 5)
        ));
    }

    // Windows can't move a folder with open files in it.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn a_drive_whose_folder_went_away_is_unhealthy() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let healthy = Health {
            readable: true,
            writable: true,
        };
        assert_eq!(store.health().await, healthy);
        // Where writes are staged is gone: reads are served, writes aren't.
        let staging = dir.path().join("staging");
        std::fs::rename(&store.inner.tmp, &staging).unwrap();
        let read_only = Health {
            readable: true,
            writable: false,
        };
        assert_eq!(store.health().await, read_only);
        std::fs::rename(&staging, &store.inner.tmp).unwrap();
        // The index alone is gone.
        let index = store.inner.system_dir.join(crate::format::INDEX_DB);
        let moved_index = dir.path().join("index");
        std::fs::rename(&index, &moved_index).unwrap();
        let gone = Health {
            readable: false,
            writable: false,
        };
        assert_eq!(store.health().await, gone);
        std::fs::rename(&moved_index, &index).unwrap();
        assert_eq!(store.health().await, healthy);
        std::fs::rename(&store.inner.system_dir, dir.path().join("moved")).unwrap();
        let gone = Health {
            readable: false,
            writable: false,
        };
        assert_eq!(store.health().await, gone);
    }

    #[tokio::test]
    async fn a_write_larger_than_the_disk_is_refused_up_front() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .create_bucket("bkt", crate::Layout::Folder)
            .await
            .unwrap();
        let check = |len| store.check_write("bkt", Some("k"), Some(len));
        assert!(check(1024).await.is_ok());
        let err = check(u64::MAX / 2).await.unwrap_err();
        assert!(matches!(err, StoreError::StorageFull));
        assert!(err.is_storage_full());
        assert!(matches!(
            store.check_write("nope", None, Some(1)).await,
            Err(StoreError::NoSuchBucket)
        ));
    }
}
