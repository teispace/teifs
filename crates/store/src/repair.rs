//! Repairs: what a drive's metadata and files disagree about, found and, when asked,
//! set right. The index is the authority for object buckets, and every data file ends
//! with a footer that records its version as it was written, so:
//!
//! - a data file no version refers to (left by a restored snapshot, or a lost index
//!   row) gets its version back from its footer, placed among its key's versions by
//!   when it was written; an older `null` version a crash left behind goes instead;
//! - a version whose data file is missing is reported, and forgotten only when asked;
//! - what can't be told apart safely (no footer, a footer of another bucket, a version
//!   id taken by another file, a folder of no bucket) is reported and left alone;
//! - upload folders of no upload are removed.
//!
//! Nothing is changed without `apply`, nothing is compared with a database SQLite finds
//! damaged, and a repair runs on a drive no server has open.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;
use teifs_meta::{Index, Layout, NULL_VERSION};

use crate::{
    Inner, Store, StoreError,
    error::Result,
    format::{INDEX_DB, SYSTEM_DB},
    now_ms,
    objects::{BUCKETS_DIR, ObjectBucket, read_footer},
};

/// Versions looked at a time when checking for missing data files.
const PAGE: usize = 1000;

/// What a repair may change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepairOptions {
    /// Set right what can be; without it, only report.
    pub apply: bool,
    /// Also forget versions whose data file is missing (with `apply`).
    pub forget_missing: bool,
}

/// Something a repair found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "finding", rename_all = "camelCase")]
pub enum Finding {
    /// A data file no version refers to; its footer gives the version back.
    #[serde(rename_all = "camelCase")]
    Unlisted {
        /// The bucket.
        bucket: String,
        /// The key.
        key: String,
        /// The version id.
        version_id: String,
        /// The data file's id.
        object_id: String,
    },
    /// An older `null` version's data file, replaced since and left by a crash.
    #[serde(rename_all = "camelCase")]
    Superseded {
        /// The bucket.
        bucket: String,
        /// The key.
        key: String,
        /// The data file's id.
        object_id: String,
    },
    /// A version whose data file is missing: its bytes are lost.
    #[serde(rename_all = "camelCase")]
    Missing {
        /// The bucket.
        bucket: String,
        /// The key.
        key: String,
        /// The version id.
        version_id: String,
        /// The data file's id.
        object_id: String,
    },
    /// A file in a bucket's data folder that can't be given a version: left alone.
    #[serde(rename_all = "camelCase")]
    Stray {
        /// The bucket.
        bucket: String,
        /// The file.
        path: PathBuf,
        /// Why it was left alone.
        why: Stray,
    },
    /// A data folder of no bucket this drive has: left alone.
    #[serde(rename_all = "camelCase")]
    UnknownBucket {
        /// The folder's name, a bucket id.
        id: String,
        /// The folder.
        path: PathBuf,
    },
    /// A multipart upload's folder with no upload recorded.
    #[serde(rename_all = "camelCase")]
    StrayUpload {
        /// The upload id.
        id: String,
        /// The folder.
        path: PathBuf,
    },
}

/// Why a file in a bucket's data folder can't be given a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Stray {
    /// It has no footer (a folder bucket's older version, or not TeiFS's).
    NoFooter,
    /// Its footer names another bucket, or another file.
    Elsewhere,
    /// Its version id belongs to another file.
    VersionTaken,
}

/// A finding, and whether the repair set it right.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Repair {
    /// What it found.
    #[serde(flatten)]
    pub finding: Finding,
    /// Whether it was set right.
    pub fixed: bool,
}

/// What a repair looked at and found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairReport {
    /// Data files looked at.
    pub data_files: u64,
    /// Versions with data files looked at.
    pub versions: u64,
    /// What it found, and what it set right.
    pub findings: Vec<Repair>,
}

impl Store {
    /// Finds where the drive's metadata and files disagree, and with `apply` sets right
    /// what can be. For a drive no server has open.
    pub async fn repair(&self, options: RepairOptions) -> Result<RepairReport> {
        self.blocking(move |inner| inner.repair(options)).await
    }
}

/// A bucket that keeps data files: an object bucket, or a folder bucket's older versions.
struct Stored {
    name: String,
    layout: Layout,
    store: ObjectBucket,
}

impl Inner {
    fn repair(&self, options: RepairOptions) -> Result<RepairReport> {
        let conn = self.lock();
        // Nothing is compared with databases SQLite finds damaged: restore a snapshot.
        for db in [INDEX_DB, SYSTEM_DB] {
            if !teifs_meta::intact(&self.system_dir.join(db))? {
                return Err(StoreError::DamagedDatabase(db));
            }
        }
        let mut report = RepairReport::default();
        let buckets: BTreeMap<String, Stored> = self
            .system()
            .buckets()?
            .into_iter()
            .map(|record| {
                let store = ObjectBucket {
                    dir: self.system_dir.join(BUCKETS_DIR).join(&record.id),
                    id: record.id.clone(),
                    versioning: record.versioning,
                };
                let stored = Stored {
                    name: record.name,
                    layout: record.layout,
                    store,
                };
                (record.id, stored)
            })
            .collect();
        self.unknown_buckets(&buckets, &mut report)?;
        for bucket in buckets.values() {
            // Files first: a file given back can take the place of a version whose file
            // is missing.
            Self::unlisted_files(&conn, bucket, options, &mut report)?;
            Self::missing_files(&conn, bucket, options, &mut report)?;
        }
        self.stray_uploads(&conn, options, &mut report)?;
        Ok(report)
    }

    /// Data folders under `.teifs/buckets/` of no bucket.
    fn unknown_buckets(
        &self,
        buckets: &BTreeMap<String, Stored>,
        report: &mut RepairReport,
    ) -> Result<()> {
        for entry in read_dir(&self.system_dir.join(BUCKETS_DIR))? {
            let id = entry.file_name().to_string_lossy().into_owned();
            if entry.path().is_dir() && !buckets.contains_key(&id) {
                report.findings.push(Repair {
                    finding: Finding::UnknownBucket {
                        id,
                        path: entry.path(),
                    },
                    fixed: false,
                });
            }
        }
        Ok(())
    }

    /// Versions whose data file is gone.
    fn missing_files(
        conn: &Index,
        bucket: &Stored,
        options: RepairOptions,
        report: &mut RepairReport,
    ) -> Result<()> {
        let id = &bucket.store.id;
        let mut after: Option<(String, i64)> = None;
        loop {
            let page =
                conn.versions_with_files(id, after.as_ref().map(|(k, s)| (k.as_str(), *s)), PAGE)?;
            let Some(last) = page.last() else {
                return Ok(());
            };
            after = Some((last.key.clone(), last.seq));
            for row in page {
                report.versions += 1;
                let Some(object_id) = row.object_id.clone() else {
                    continue;
                };
                if bucket.store.data_path(&object_id).exists() {
                    continue;
                }
                let fixed = options.apply
                    && options.forget_missing
                    && conn
                        .delete_version(id, &row.key, &row.version_id, now_ms())?
                        .is_some();
                if fixed {
                    // Its file is already gone: nothing left to remove.
                    conn.drop_garbage(&object_id)?;
                }
                report.findings.push(Repair {
                    finding: Finding::Missing {
                        bucket: bucket.name.clone(),
                        key: row.key,
                        version_id: row.version_id,
                        object_id,
                    },
                    fixed,
                });
            }
        }
    }

    /// Data files no version refers to.
    fn unlisted_files(
        conn: &Index,
        bucket: &Stored,
        options: RepairOptions,
        report: &mut RepairReport,
    ) -> Result<()> {
        for path in data_files(&bucket.store.dir)? {
            report.data_files += 1;
            let object_id = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let in_use = conn.bucket_uses_object(&bucket.store.id, &object_id)?;
            if in_use || conn.is_garbage(&object_id)? {
                continue;
            }
            let repair = Self::unlisted(conn, bucket, &path, &object_id, options)?;
            report.findings.push(repair);
        }
        Ok(())
    }

    fn unlisted(
        conn: &Index,
        bucket: &Stored,
        path: &Path,
        object_id: &str,
        options: RepairOptions,
    ) -> Result<Repair> {
        let stray = |why| Repair {
            finding: Finding::Stray {
                bucket: bucket.name.clone(),
                path: path.to_owned(),
                why,
            },
            fixed: false,
        };
        let Some(footer) = read_footer(path)? else {
            return Ok(stray(Stray::NoFooter));
        };
        if footer.bucket != bucket.store.id || footer.object != object_id {
            return Ok(stray(Stray::Elsewhere));
        }
        let row = footer.row();
        let existing = conn.version(&bucket.store.id, &row.key, &row.version_id)?;
        let newer_null = match &existing {
            None => false,
            Some(old) if row.version_id == NULL_VERSION => {
                if old.modified_ms >= row.modified_ms {
                    // Replaced since: what the write that replaced it would have removed.
                    let fixed = options.apply && remove(path)?;
                    return Ok(Repair {
                        finding: Finding::Superseded {
                            bucket: bucket.name.clone(),
                            key: row.key,
                            object_id: object_id.to_owned(),
                        },
                        fixed,
                    });
                }
                true
            }
            Some(_) => return Ok(stray(Stray::VersionTaken)),
        };
        let mut fixed = false;
        if options.apply {
            if newer_null {
                // The index is older than the file: the file is the `null` version now.
                if let Some((_, files)) =
                    conn.delete_version(&bucket.store.id, &row.key, NULL_VERSION, now_ms())?
                {
                    Inner::remove_data_files(conn, &bucket.store, &files);
                }
            }
            let current = bucket.layout == Layout::Object;
            fixed = conn.adopt_version(&row, current)?;
        }
        Ok(Repair {
            finding: Finding::Unlisted {
                bucket: bucket.name.clone(),
                key: row.key,
                version_id: row.version_id,
                object_id: object_id.to_owned(),
            },
            fixed,
        })
    }

    /// Upload folders with no upload recorded.
    fn stray_uploads(
        &self,
        conn: &Index,
        options: RepairOptions,
        report: &mut RepairReport,
    ) -> Result<()> {
        for entry in read_dir(&self.uploads)? {
            let id = entry.file_name().to_string_lossy().into_owned();
            if !entry.path().is_dir() || conn.get_upload(&id)?.is_some() {
                continue;
            }
            let fixed = options.apply && {
                fs::remove_dir_all(entry.path())?;
                true
            };
            report.findings.push(Repair {
                finding: Finding::StrayUpload {
                    id,
                    path: entry.path(),
                },
                fixed,
            });
        }
        Ok(())
    }
}

/// A folder's entries; none when it doesn't exist.
fn read_dir(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    match fs::read_dir(dir) {
        Ok(entries) => Ok(entries.flatten().collect()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err.into()),
    }
}

/// Every file under a bucket's data folder (`<aa>/<bb>/<object id>`).
fn data_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut folders = vec![dir.to_owned()];
    while let Some(folder) = folders.pop() {
        for entry in read_dir(&folder)? {
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                folders.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Removes a file; whether it was there.
fn remove(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(StoreError::from(err)),
    }
}

#[cfg(test)]
mod tests {
    use teifs_meta::Versioning;
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::{ObjectAttrs, VersionsQuery, restore};

    const APPLY: RepairOptions = RepairOptions {
        apply: true,
        forget_missing: false,
    };

    async fn put(store: &Store, bucket: &str, key: &str, bytes: &[u8]) -> String {
        let info = store
            .put_bytes(bucket, key, bytes, ObjectAttrs::default())
            .await
            .unwrap();
        info.version_id.unwrap_or_else(|| NULL_VERSION.to_owned())
    }

    async fn bytes_of(store: &Store, bucket: &str, key: &str) -> Vec<u8> {
        let (_, body) = store.read_with(bucket, key, None, None).await.unwrap();
        let mut out = Vec::new();
        let mut body = body.unwrap().all().await.unwrap();
        body.read_to_end(&mut out).await.unwrap();
        out
    }

    /// `(version id, latest)` of every version of `key`, newest first.
    async fn versions(store: &Store, bucket: &str, key: &str) -> Vec<(String, bool)> {
        let query = VersionsQuery {
            prefix: key.to_owned(),
            max_keys: 1000,
            ..VersionsQuery::default()
        };
        let listing = store.list_versions(bucket, query).await.unwrap();
        listing
            .versions
            .into_iter()
            .map(|v| (v.info.version_id.unwrap(), v.latest))
            .collect()
    }

    /// Every data file of the drive at `root`, by the paths a repair reports.
    fn files(root: &Path) -> Vec<PathBuf> {
        let root = fs::canonicalize(root).unwrap();
        data_files(&root.join(crate::SYSTEM_DIR).join(BUCKETS_DIR)).unwrap()
    }

    fn found(report: &RepairReport) -> Vec<(&str, bool)> {
        report
            .findings
            .iter()
            .map(|r| {
                let what = match r.finding {
                    Finding::Unlisted { .. } => "unlisted",
                    Finding::Superseded { .. } => "superseded",
                    Finding::Missing { .. } => "missing",
                    Finding::Stray { .. } => "stray",
                    Finding::UnknownBucket { .. } => "unknown bucket",
                    Finding::StrayUpload { .. } => "stray upload",
                };
                (what, r.fixed)
            })
            .collect()
    }

    /// Takes a backup of the open drive at `root`; `later` changes it; the backup is
    /// restored; the drive is opened again.
    async fn restored_after<F: AsyncFnOnce(&Store)>(root: &Path, store: Store, later: F) -> Store {
        let backups = tempfile::tempdir().unwrap();
        let backup = store.back_up_to(backups.path()).await.unwrap();
        later(&store).await;
        drop(store);
        restore(root, &backups.path().join(&backup.name)).unwrap();
        Store::open_files(root).unwrap()
    }

    #[tokio::test]
    async fn a_restore_to_an_older_snapshot_gets_newer_objects_back() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        put(&store, "obj", "a", b"one").await;
        let store = restored_after(drive.path(), store, async |store| {
            put(store, "obj", "a", b"one, changed").await;
            put(store, "obj", "b", b"two").await;
            store.create_bucket("later", Layout::Object).await.unwrap();
            put(store, "later", "c", b"three").await;
        })
        .await;

        let report = store.repair(RepairOptions::default()).await.unwrap();
        // `a`'s file from the snapshot was replaced; `c`'s bucket is unknown to it.
        let mut what = found(&report);
        what.sort_unstable();
        assert_eq!(
            what,
            [
                ("missing", false),
                ("unknown bucket", false),
                ("unlisted", false),
                ("unlisted", false),
            ]
        );
        assert_eq!(report.data_files, 2);
        assert_eq!(report.versions, 1);
        // Only a report: nothing changed.
        assert_eq!(
            store.repair(RepairOptions::default()).await.unwrap(),
            report
        );

        let report = store.repair(APPLY).await.unwrap();
        let mut what = found(&report);
        what.sort_unstable();
        assert_eq!(
            what,
            [
                ("unknown bucket", false),
                ("unlisted", true),
                ("unlisted", true),
            ]
        );
        assert_eq!(bytes_of(&store, "obj", "a").await, b"one, changed");
        assert_eq!(bytes_of(&store, "obj", "b").await, b"two");
        assert_eq!(
            versions(&store, "obj", "b").await,
            [(NULL_VERSION.to_owned(), true)]
        );
        // Set right: only the unknown folder is left, for a person to look at.
        let again = store.repair(APPLY).await.unwrap();
        assert_eq!(found(&again), [("unknown bucket", false)]);
        assert!(matches!(
            &again.findings[0].finding,
            Finding::UnknownBucket { path, .. } if path.is_dir()
        ));
    }

    #[tokio::test]
    async fn given_back_versions_take_their_place_by_when_they_were_written() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        store
            .set_bucket_versioning("obj", Versioning::Enabled)
            .await
            .unwrap();
        let first = put(&store, "obj", "k", b"1").await;
        let mut later = Vec::new();
        let store = restored_after(drive.path(), store, async |store| {
            later.push(put(store, "obj", "k", b"2").await);
            later.push(put(store, "obj", "k", b"3").await);
        })
        .await;
        assert_eq!(versions(&store, "obj", "k").await, [(first.clone(), true)]);

        let report = store.repair(APPLY).await.unwrap();
        assert_eq!(found(&report), [("unlisted", true), ("unlisted", true)]);
        assert_eq!(
            versions(&store, "obj", "k").await,
            [
                (later[1].clone(), true),
                (later[0].clone(), false),
                (first, false)
            ]
        );
        assert_eq!(bytes_of(&store, "obj", "k").await, b"3");
    }

    #[tokio::test]
    async fn a_missing_file_is_forgotten_only_when_asked() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        put(&store, "obj", "a", b"one").await;
        put(&store, "obj", "b", b"two").await;
        let lost = files(drive.path());
        fs::remove_file(&lost[0]).unwrap();

        let report = store.repair(APPLY).await.unwrap();
        assert_eq!(found(&report), [("missing", false)]);
        assert_eq!(report.versions, 2);
        let Finding::Missing { key, .. } = &report.findings[0].finding else {
            unreachable!()
        };
        assert_eq!(versions(&store, "obj", key).await.len(), 1);

        let forget = RepairOptions {
            apply: true,
            forget_missing: true,
        };
        // Asked, but only reporting: still nothing changes.
        let report_only = RepairOptions {
            apply: false,
            forget_missing: true,
        };
        let report = store.repair(report_only).await.unwrap();
        assert_eq!(found(&report), [("missing", false)]);
        let report = store.repair(forget).await.unwrap();
        assert_eq!(found(&report), [("missing", true)]);
        assert!(versions(&store, "obj", key).await.is_empty());
        // Its file is gone already: nothing is left queued for the sweeper.
        assert!(store.inner.lock().garbage(10).unwrap().is_empty());
        assert!(store.repair(APPLY).await.unwrap().findings.is_empty());
    }

    #[tokio::test]
    async fn a_null_version_replaced_since_is_removed() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        put(&store, "obj", "a", b"one").await;
        let old = files(drive.path()).remove(0);
        let kept = fs::read(&old).unwrap();
        put(&store, "obj", "a", b"one, changed").await;
        // As a crash between the new version's row and the old file's removal leaves it.
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        fs::write(&old, kept).unwrap();

        let report = store.repair(RepairOptions::default()).await.unwrap();
        assert_eq!(found(&report), [("superseded", false)]);
        assert!(old.is_file());
        let report = store.repair(APPLY).await.unwrap();
        assert_eq!(found(&report), [("superseded", true)]);
        assert!(!old.exists());
        assert_eq!(bytes_of(&store, "obj", "a").await, b"one, changed");
    }

    #[tokio::test]
    async fn what_cant_be_told_apart_is_left_alone() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        store.create_bucket("other", Layout::Object).await.unwrap();
        put(&store, "obj", "a", b"one").await;
        put(&store, "other", "b", b"two").await;
        let ours = files(drive.path())
            .into_iter()
            .find(|f| fs::read(f).unwrap().starts_with(b"one"))
            .unwrap();
        let object_id = ours.file_name().unwrap().to_string_lossy().into_owned();
        let bucket = ours.ancestors().nth(3).unwrap().to_owned();
        let other_bucket = files(drive.path())
            .into_iter()
            .map(|f| f.ancestors().nth(3).unwrap().to_owned())
            .find(|b| *b != bucket)
            .unwrap();
        // No footer.
        let plain = bucket.join("zz").join("zz").join("plain-zzzz");
        fs::create_dir_all(plain.parent().unwrap()).unwrap();
        fs::write(&plain, b"just bytes").unwrap();
        // Another bucket's file.
        let moved = other_bucket.join("yy").join("yy").join(&object_id);
        fs::create_dir_all(moved.parent().unwrap()).unwrap();
        fs::copy(&ours, &moved).unwrap();
        // A copy under another name, whose version id is taken.
        let renamed = bucket.join("xx").join("xx").join("copy-xxxx");
        fs::create_dir_all(renamed.parent().unwrap()).unwrap();
        fs::copy(&ours, &renamed).unwrap();

        let report = store.repair(APPLY).await.unwrap();
        let mut why: Vec<(PathBuf, Stray)> = report
            .findings
            .iter()
            .map(|r| {
                assert!(!r.fixed);
                let Finding::Stray { path, why, .. } = &r.finding else {
                    unreachable!("{r:?}")
                };
                (path.clone(), *why)
            })
            .collect();
        why.sort();
        let mut expected = vec![
            (plain.clone(), Stray::NoFooter),
            (moved.clone(), Stray::Elsewhere),
            (renamed.clone(), Stray::Elsewhere),
        ];
        expected.sort();
        assert_eq!(why, expected);
        assert!(plain.is_file() && moved.is_file() && renamed.is_file());
    }

    #[tokio::test]
    async fn a_version_id_taken_by_another_file_is_left_alone() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        store
            .set_bucket_versioning("obj", Versioning::Enabled)
            .await
            .unwrap();
        put(&store, "obj", "a", b"one").await;
        let ours = files(drive.path()).remove(0);
        let object_id = ours.file_name().unwrap().to_string_lossy().into_owned();
        // The same version, its row pointing at another file: as a hand-edited index.
        {
            let conn = store.inner.lock();
            let bucket_id = store.inner.system().buckets().unwrap()[0].id.clone();
            let rows = conn.versions_with_files(&bucket_id, None, 10).unwrap();
            let mut row = rows[0].clone();
            conn.delete_version(&bucket_id, "a", &row.version_id, 0)
                .unwrap();
            conn.drop_garbage(&object_id).unwrap();
            row.object_id = Some("elsewhere".to_owned());
            assert!(conn.adopt_version(&row, true).unwrap());
        }

        let report = store.repair(APPLY).await.unwrap();
        assert!(matches!(
            &report.findings[..],
            [
                Repair { finding: Finding::Stray { why, .. }, fixed: false },
                Repair { finding: Finding::Missing { .. }, fixed: false },
            ] if *why == Stray::VersionTaken
        ));
        assert!(ours.is_file());
    }

    #[tokio::test]
    async fn a_lost_index_is_rebuilt_from_the_files() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        store
            .set_bucket_versioning("obj", Versioning::Enabled)
            .await
            .unwrap();
        let v1 = put(&store, "obj", "k", b"1").await;
        let v2 = put(&store, "obj", "k", b"2").await;
        put(&store, "obj", "other", b"3").await;
        drop(store);
        let system = drive.path().join(crate::SYSTEM_DIR);
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(system.join(format!("{INDEX_DB}{suffix}")));
        }

        let store = Store::open_files(drive.path()).unwrap();
        let report = store.repair(APPLY).await.unwrap();
        assert_eq!(found(&report), [("unlisted", true); 3]);
        assert_eq!(
            versions(&store, "obj", "k").await,
            [(v2, true), (v1, false)]
        );
        assert_eq!(bytes_of(&store, "obj", "other").await, b"3");
    }

    #[tokio::test]
    async fn a_damaged_database_is_not_repaired_from() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        for i in 0..200 {
            put(&store, "obj", &format!("key-{i:04}"), b"x").await;
        }
        drop(store);
        let index = drive.path().join(crate::SYSTEM_DIR).join(INDEX_DB);
        let _ = fs::remove_file(
            drive
                .path()
                .join(crate::SYSTEM_DIR)
                .join(format!("{INDEX_DB}-wal")),
        );
        // Pages past the schema overwritten.
        let mut bytes = fs::read(&index).unwrap();
        assert!(bytes.len() > 3 * 4096);
        bytes[2 * 4096..3 * 4096].fill(0xA5);
        fs::write(&index, bytes).unwrap();

        let store = Store::open_files(drive.path()).unwrap();
        assert!(matches!(
            store.repair(APPLY).await,
            Err(StoreError::DamagedDatabase(INDEX_DB))
        ));
    }

    #[tokio::test]
    async fn a_file_waiting_to_be_removed_is_left_to_the_sweeper() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        put(&store, "obj", "a", b"one").await;
        {
            // Deleted, its file queued (as when it's open elsewhere on Windows).
            let conn = store.inner.lock();
            let bucket_id = store.inner.system().buckets().unwrap()[0].id.clone();
            conn.delete_version(&bucket_id, "a", NULL_VERSION, 0)
                .unwrap()
                .unwrap();
        }
        assert_eq!(files(drive.path()).len(), 1);
        let report = store.repair(APPLY).await.unwrap();
        assert!(report.findings.is_empty(), "{report:?}");
        assert_eq!(report.data_files, 1);
        assert!(versions(&store, "obj", "a").await.is_empty());
    }

    #[tokio::test]
    async fn upload_folders_of_no_upload_are_removed() {
        let drive = tempfile::tempdir().unwrap();
        let store = Store::open_files(drive.path()).unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        let upload = store
            .create_upload(
                "obj",
                "big",
                ObjectAttrs::default(),
                None,
                &crate::Encryption::None,
                None,
                None,
            )
            .await
            .unwrap();
        let uploads = drive.path().join(crate::SYSTEM_DIR).join("uploads");
        let real = uploads.join(&upload.id);
        fs::create_dir_all(&real).unwrap();
        let stray = uploads.join("no-such-upload");
        fs::create_dir_all(&stray).unwrap();
        fs::write(stray.join("1"), b"part").unwrap();
        // Files beside the upload folders, and beside the buckets' data folders, aren't
        // anyone's (a Finder's .DS_Store, say).
        fs::write(uploads.join(".DS_Store"), b"").unwrap();
        let buckets = drive.path().join(crate::SYSTEM_DIR).join(BUCKETS_DIR);
        fs::write(buckets.join(".DS_Store"), b"").unwrap();

        let report = store.repair(RepairOptions::default()).await.unwrap();
        assert_eq!(found(&report), [("stray upload", false)]);
        let report = store.repair(APPLY).await.unwrap();
        assert_eq!(found(&report), [("stray upload", true)]);
        assert!(!stray.exists());
        assert!(uploads.join(".DS_Store").is_file());
        // A real upload's folder stays.
        assert!(real.is_dir());
        assert!(store.upload(&upload.id).await.is_ok());
    }
}
