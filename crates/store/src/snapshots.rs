//! Metadata snapshots: consistent copies of the drive's two databases, kept in
//! `.teifs/backups/auto/<UTC time>/` so a damaged or mistakenly changed index or
//! system database can be put back. `index.db` can mostly be rebuilt from the data
//! files, but not delete markers or what changed after a write (tags, retention, legal
//! holds); `system.db` (buckets, settings, IAM) can't be rebuilt at all.
//!
//! A snapshot is written with SQLite's `VACUUM INTO` (consistent while the drive is in
//! use, and compact) into a hidden folder, checked, then renamed into place, so a
//! listed snapshot is always complete.

use std::{
    fs,
    path::{Path, PathBuf},
};

pub use teifs_types::admin::Snapshot;

use crate::{
    Inner, Store, StoreError,
    error::Result,
    format::{BACKUPS, INDEX_DB, SYSTEM_DB},
    jobs::millis,
    staged::sync_dir,
};

/// Where snapshots are kept, inside the backups folder.
pub(crate) const AUTO: &str = "auto";
/// What each snapshot says about itself.
const ABOUT: &str = "snapshot.json";

impl Inner {
    fn snapshots_dir(&self) -> PathBuf {
        self.system_dir.join(BACKUPS).join(AUTO)
    }

    /// Takes a snapshot, named for `at_ms`.
    pub(crate) fn take_snapshot(&self, at_ms: i64) -> Result<Snapshot> {
        let dir = self.snapshots_dir();
        fs::create_dir_all(&dir)?;
        let name = snapshot_name(at_ms);
        let partial = dir.join(format!(".{name}.partial"));
        let _ = fs::remove_dir_all(&partial);
        let result = self.write_snapshot(&partial, &name, at_ms);
        if result.is_err() {
            let _ = fs::remove_dir_all(&partial);
        }
        let mut snapshot = result?;
        let done = dir.join(&name);
        if done.exists() {
            fs::remove_dir_all(&done)?;
        }
        fs::rename(&partial, &done)?;
        sync_dir(&dir)?;
        snapshot.bytes = folder_size(&done);
        Ok(snapshot)
    }

    fn write_snapshot(&self, to: &Path, name: &str, at_ms: i64) -> Result<Snapshot> {
        // As much room as the databases take now, beyond the room kept free.
        let needed: u64 = [INDEX_DB, SYSTEM_DB]
            .iter()
            .flat_map(|db| ["", "-wal"].map(|suffix| self.system_dir.join(format!("{db}{suffix}"))))
            .filter_map(|path| fs::metadata(path).ok())
            .map(|meta| meta.len())
            .sum();
        crate::space::fits(&self.system_dir, needed)?;
        fs::create_dir(to)?;
        for db in [INDEX_DB, SYSTEM_DB] {
            let copy = to.join(db);
            teifs_meta::backup(&self.system_dir.join(db), &copy)?;
            if !teifs_meta::intact(&copy)? {
                return Err(StoreError::CorruptMetadata);
            }
            fs::File::open(&copy)?.sync_all()?;
        }
        let snapshot = Snapshot {
            name: name.to_owned(),
            created_ms: at_ms,
            drive: self.format.drive.clone(),
            format: self.format.format,
            bytes: 0,
        };
        let about = serde_json::to_vec_pretty(&snapshot).expect("a snapshot serializes");
        let mut file = fs::File::create(to.join(ABOUT))?;
        std::io::Write::write_all(&mut file, &about)?;
        file.sync_all()?;
        sync_dir(to)?;
        Ok(snapshot)
    }

    /// The snapshots kept, oldest first.
    pub(crate) fn list_snapshots(&self) -> Result<Vec<Snapshot>> {
        let entries = match fs::read_dir(self.snapshots_dir()) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut snapshots: Vec<Snapshot> = entries
            .flatten()
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .filter_map(|e| {
                let about = fs::read(e.path().join(ABOUT)).ok()?;
                let mut snapshot: Snapshot = serde_json::from_slice(&about).ok()?;
                snapshot.bytes = folder_size(&e.path());
                Some(snapshot)
            })
            .collect();
        snapshots.sort_by(|a, b| (a.created_ms, &a.name).cmp(&(b.created_ms, &b.name)));
        Ok(snapshots)
    }

    /// Removes all but the newest `keep` snapshots, and any left half-written; how many
    /// it removed.
    pub(crate) fn prune_snapshots(&self, keep: usize) -> Result<usize> {
        let dir = self.snapshots_dir();
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().ends_with(".partial") {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
        let snapshots = self.list_snapshots()?;
        let old = snapshots.len().saturating_sub(keep);
        for snapshot in &snapshots[..old] {
            fs::remove_dir_all(dir.join(&snapshot.name))?;
        }
        Ok(old)
    }
}

impl Store {
    /// Takes a snapshot of the drive's metadata now.
    pub async fn take_snapshot(&self) -> Result<Snapshot> {
        let now = millis(std::time::SystemTime::now());
        self.blocking(move |inner| inner.take_snapshot(now)).await
    }

    /// The metadata snapshots kept, oldest first.
    pub async fn snapshots(&self) -> Result<Vec<Snapshot>> {
        self.blocking(Inner::list_snapshots).await
    }
}

/// `20260930T045501.123Z`: sorts by time, and every file system can hold it.
fn snapshot_name(ms: i64) -> String {
    let time = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}.{:03}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.millisecond()
    )
}

fn folder_size(dir: &Path) -> u64 {
    fs::read_dir(dir).map_or(0, |entries| {
        entries
            .flatten()
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_sort_by_time() {
        assert_eq!(snapshot_name(1_790_744_101_123), "20260930T045501.123Z");
        assert_eq!(snapshot_name(0), "19700101T000000.000Z");
    }
}
