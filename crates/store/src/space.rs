//! Disk space: writes are refused before they'd leave the disk with less than a reserve.
//!
//! On a completely full disk even deleting fails (SQLite needs a little room for its
//! write-ahead log), so nobody could free space through S3. Keeping a reserve free for
//! deletes and metadata avoids that; writes that would eat into it get `StorageFull`
//! (`507` over S3) up front instead of failing halfway.

use std::path::Path;

use crate::{Bucket, Inner, Store, StoreError, error::Result};

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
            Bucket::Folder(_, dir) => Some(dir),
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

fn fits(dir: &Path, len: u64) -> Result<()> {
    let stats = fs4::statvfs(dir)?;
    if has_room(stats.available_space(), stats.total_space(), len) {
        Ok(())
    } else {
        Err(StoreError::StorageFull)
    }
}

impl Store {
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
