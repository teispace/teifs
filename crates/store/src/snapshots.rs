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
    staged::{sync_dir, sync_file},
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
        self.snapshot_into(&self.snapshots_dir(), at_ms)
    }

    /// Writes a snapshot, named for `at_ms`, into a folder of its own in `dir`.
    fn snapshot_into(&self, dir: &Path, at_ms: i64) -> Result<Snapshot> {
        let _one_at_a_time = self.snapshot_lock();
        // A drive whose folder went away (an unmounted disk) has nothing to snapshot, and
        // nothing is made where it was.
        if !self.system_dir.join(INDEX_DB).is_file() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the drive's index is missing",
            )));
        }
        fs::create_dir_all(dir)?;
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
        sync_dir(dir)?;
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
        fs::create_dir(to)?;
        crate::space::fits(to, needed)?;
        for db in [INDEX_DB, SYSTEM_DB] {
            let copy = to.join(db);
            teifs_meta::backup(&self.system_dir.join(db), &copy)?;
            if !teifs_meta::intact(&copy)? {
                return Err(StoreError::CorruptMetadata);
            }
            sync_file(&copy)?;
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

    fn snapshot_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.snapshots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let _one_at_a_time = self.snapshot_lock();
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

    /// Writes a snapshot of the drive's metadata into a folder of its own in `dir` (made
    /// if missing): a backup that [`restore`] can put back.
    pub async fn back_up_to(&self, dir: &Path) -> Result<Snapshot> {
        let now = millis(std::time::SystemTime::now());
        let dir = dir.to_owned();
        self.blocking(move |inner| inner.snapshot_into(&dir, now))
            .await
    }
}

/// What [`restore`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// The snapshot now in use.
    pub snapshot: Snapshot,
    /// Where the metadata it replaced was moved.
    pub previous: PathBuf,
}

/// Puts the snapshot (or backup) in the folder `from` back as the metadata of the drive
/// at `root`, which no process may have open. It must be of this drive, in its format,
/// and intact. The metadata it replaces is moved to `.teifs/backups/pre-restore-<time>/`,
/// never removed. Objects written since keep their bytes: folder buckets' files are
/// indexed again when the drive is next served, object buckets' given back by a repair.
pub fn restore(root: &Path, from: &Path) -> Result<Restored> {
    let system = root.join(crate::SYSTEM_DIR);
    let format = crate::format::read(&system)?;
    let _lock = crate::lock_drive(&system)?;
    let bad = |why: String| StoreError::BadSnapshot(why);
    let about = fs::read(from.join(ABOUT))
        .map_err(|_| bad(format!("{} has no {ABOUT}", from.display())))?;
    let snapshot: Snapshot =
        serde_json::from_slice(&about).map_err(|e| bad(format!("its {ABOUT} is damaged: {e}")))?;
    if snapshot.drive != format.drive {
        return Err(bad(format!(
            "it's of another drive ({}, this one is {})",
            snapshot.drive, format.drive
        )));
    }
    if snapshot.format != format.format {
        return Err(bad(format!(
            "it's in format {}, the drive in format {}",
            snapshot.format, format.format
        )));
    }
    for db in [INDEX_DB, SYSTEM_DB] {
        if !from.join(db).is_file() || !teifs_meta::intact(&from.join(db))? {
            return Err(bad(format!("its {db} is missing or damaged")));
        }
    }
    // Copies first, beside the databases they replace; then the swap, a few renames.
    for db in [INDEX_DB, SYSTEM_DB] {
        let staged = system.join(format!("{db}.restoring"));
        fs::copy(from.join(db), &staged)?;
        sync_file(&staged)?;
    }
    let now = millis(std::time::SystemTime::now());
    let previous = system
        .join(BACKUPS)
        .join(format!("pre-restore-{}", snapshot_name(now)));
    fs::create_dir_all(&previous)?;
    for db in [INDEX_DB, SYSTEM_DB] {
        for suffix in ["", "-wal", "-shm"] {
            let name = format!("{db}{suffix}");
            match fs::rename(system.join(&name), previous.join(&name)) {
                Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err.into()),
                _ => {}
            }
        }
        fs::rename(system.join(format!("{db}.restoring")), system.join(db))?;
    }
    sync_dir(&previous)?;
    sync_dir(&system)?;
    Ok(Restored { snapshot, previous })
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
    use crate::{Layout, ObjectAttrs};

    /// Every data file of the drive's object buckets.
    fn data_files(root: &Path) -> usize {
        fn count(dir: &Path) -> usize {
            fs::read_dir(dir).map_or(0, |entries| {
                entries
                    .flatten()
                    .map(|e| {
                        if e.path().is_dir() {
                            count(&e.path())
                        } else {
                            1
                        }
                    })
                    .sum()
            })
        }
        count(
            &root
                .join(crate::SYSTEM_DIR)
                .join(crate::objects::BUCKETS_DIR),
        )
    }

    #[tokio::test]
    async fn a_backup_is_restored_and_what_it_replaced_is_kept() {
        let drive = tempfile::tempdir().unwrap();
        let backups = tempfile::tempdir().unwrap();
        let store = Store::open(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        store
            .put_bytes("obj", "a", b"one", ObjectAttrs::default())
            .await
            .unwrap();
        let backup = store.back_up_to(backups.path()).await.unwrap();
        let from = backups.path().join(&backup.name);
        assert!(from.join(ABOUT).is_file());
        store
            .put_bytes("obj", "b", b"two", ObjectAttrs::default())
            .await
            .unwrap();
        store.create_bucket("later", Layout::Object).await.unwrap();
        // Not while the drive is open.
        assert!(matches!(
            restore(drive.path(), &from),
            Err(StoreError::DriveInUse)
        ));
        drop(store);

        let restored = restore(drive.path(), &from).unwrap();
        assert_eq!(restored.snapshot, Snapshot { bytes: 0, ..backup });
        assert!(restored.previous.join(SYSTEM_DB).is_file());
        assert!(restored.previous.join(INDEX_DB).is_file());
        let store = Store::open(drive.path()).unwrap();
        assert!(store.head("obj", "a").await.is_ok());
        assert!(matches!(
            store.head("obj", "b").await,
            Err(StoreError::NoSuchKey)
        ));
        assert!(matches!(
            store.head_bucket("later").await,
            Err(StoreError::NoSuchBucket)
        ));
        // The newer object's bytes stay on the disk.
        assert_eq!(data_files(drive.path()), 2);
    }

    /// A drive whose folder went away (an unmounted disk) isn't snapshotted as empty,
    /// and nothing is made where it was.
    // Windows can't move a folder with open files in it.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn a_drive_that_went_away_is_never_snapshotted() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open(drive.path()).unwrap();
        let system = drive.path().join(crate::SYSTEM_DIR);
        fs::rename(&system, drive.path().join("moved")).unwrap();
        assert!(store.take_snapshot().await.is_err());
        let backups = tempfile::tempdir().unwrap();
        assert!(store.back_up_to(backups.path()).await.is_err());
        assert!(!system.exists());
        assert_eq!(fs::read_dir(backups.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_prune_waits_for_a_snapshot_being_written() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open(drive.path()).unwrap();
        // As a snapshot does while it writes its hidden folder.
        let writing = store.inner.snapshot_lock();
        let inner = std::sync::Arc::clone(&store.inner);
        let (done, pruned) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            inner.prune_snapshots(0).unwrap();
            done.send(()).unwrap();
        });
        let wait = std::time::Duration::from_millis(200);
        assert!(pruned.recv_timeout(wait).is_err(), "pruned meanwhile");
        drop(writing);
        pruned.recv_timeout(20 * wait).unwrap();
    }

    #[tokio::test]
    async fn only_an_intact_snapshot_of_the_same_drive_is_restored() {
        let (one, two) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let backups = tempfile::tempdir().unwrap();
        let other = Store::open(two.path()).unwrap();
        let theirs = other.back_up_to(backups.path()).await.unwrap();
        drop(other);
        let store = Store::open(one.path()).unwrap();
        let ours = store.back_up_to(backups.path()).await.unwrap();
        drop(store);
        let bad = |from: &Path| match restore(one.path(), from) {
            Err(StoreError::BadSnapshot(why)) => why,
            other => panic!("{other:?}"),
        };
        assert!(bad(&backups.path().join(&theirs.name)).starts_with("it's of another drive"));
        assert!(bad(backups.path()).ends_with("has no snapshot.json"));
        let ours = backups.path().join(&ours.name);
        let about = fs::read_to_string(ours.join(ABOUT)).unwrap();
        let older = about.replace("\"format\": 2", "\"format\": 1");
        assert_ne!(older, about);
        fs::write(ours.join(ABOUT), older).unwrap();
        assert_eq!(bad(&ours), "it's in format 1, the drive in format 2");
        fs::write(ours.join(ABOUT), about).unwrap();
        let index = ours.join(INDEX_DB);
        let bytes = fs::read(&index).unwrap();
        fs::write(&index, &bytes[..bytes.len() / 2]).unwrap();
        assert_eq!(bad(&ours), "its index.db is missing or damaged");
        // Nothing was touched.
        assert!(!one.path().join(".teifs/backups").exists());
        assert!(Store::open(one.path()).is_ok());
    }

    #[test]
    fn names_sort_by_time() {
        assert_eq!(snapshot_name(1_790_744_101_123), "20260930T045501.123Z");
        assert_eq!(snapshot_name(0), "19700101T000000.000Z");
    }
}
