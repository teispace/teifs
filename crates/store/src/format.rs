//! The drive's on-disk format: `.teifs/format.json` says which format the drive is in,
//! and older formats are upgraded when the drive is opened, after a backup.
//!
//! Formats (the full specification is `docs/ON_DISK_FORMAT.md`):
//! - **0** (before formats were recorded): one database, `.teifs/meta.db`.
//! - **1**: `format.json`, the index in `index.db`, bucket settings in `system.db`.
//! - **2**: object buckets: bucket ids, object versions in `index.db`, data files under
//!   `.teifs/buckets/`.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, StoreError},
    staged::sync_dir,
};

/// The format this build writes.
pub const FORMAT: u32 = 2;

const FORMAT_FILE: &str = "format.json";
const LEGACY_DB: &str = "meta.db";
/// The index database.
pub(crate) const INDEX_DB: &str = "index.db";
/// The system database.
pub(crate) const SYSTEM_DB: &str = "system.db";
/// Where backups made before an upgrade go.
pub(crate) const BACKUPS: &str = "backups";

/// What `format.json` records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveFormat {
    /// The on-disk format version.
    pub format: u32,
    /// The drive's id, random and permanent.
    pub drive: String,
    /// When the drive was first formatted (RFC 3339).
    pub created: String,
}

/// Reads the drive's format, creating it for a new drive and upgrading an older one.
pub(crate) fn prepare(system: &Path) -> Result<DriveFormat> {
    let path = system.join(FORMAT_FILE);
    match fs::read(&path) {
        Ok(bytes) => {
            let format: DriveFormat = serde_json::from_slice(&bytes)
                .map_err(|e| StoreError::CorruptFormat(e.to_string()))?;
            if format.format > FORMAT {
                return Err(StoreError::NewerFormat {
                    found: format.format,
                });
            }
            // An upgrade from format 0 stopped after its commit point: finish it.
            remove_legacy(system);
            if format.format < FORMAT {
                return upgrade(system, &path, format);
            }
            Ok(format)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if system.join(LEGACY_DB).exists() {
                upgrade_from_0(system)?;
                // Format 0 goes to 1 here; 1 → 2 is only schema migrations, which the
                // databases run when they open (their backup was just made).
            }
            let format = DriveFormat {
                format: FORMAT,
                drive: uuid::Uuid::new_v4().to_string(),
                created: now_rfc3339(),
            };
            write_atomic(
                &path,
                &serde_json::to_vec_pretty(&format).expect("the format serializes"),
            )?;
            remove_legacy(system);
            Ok(format)
        }
        Err(err) => Err(err.into()),
    }
}

/// Upgrades a recorded format to the current one: backs up both databases (their schema
/// migrations run when they open), then records the new format.
fn upgrade(system: &Path, path: &Path, mut format: DriveFormat) -> Result<DriveFormat> {
    let to = FORMAT;
    tracing::info!(from = format.format, to, "upgrading the drive's format");
    let backup_dir = system.join(BACKUPS).join(format!("pre-format-{to}"));
    let _ = fs::remove_dir_all(&backup_dir);
    fs::create_dir_all(&backup_dir)?;
    for db in [INDEX_DB, SYSTEM_DB] {
        if system.join(db).exists() {
            teifs_meta::backup(&system.join(db), &backup_dir.join(db))?;
        }
    }
    format.format = to;
    write_atomic(
        path,
        &serde_json::to_vec_pretty(&format).expect("the format serializes"),
    )?;
    Ok(format)
}

/// Format 0 → 1: `meta.db` becomes `index.db` (same schema). The old database is copied to
/// `backups/pre-format-1/` first. Writing `format.json` afterwards is the commit point:
/// a crash before it redoes the upgrade, one after it only leaves `meta.db` to remove.
fn upgrade_from_0(system: &Path) -> Result<()> {
    tracing::info!("upgrading the drive's format from 0 to 1");
    let legacy = system.join(LEGACY_DB);
    let backup_dir = system.join(BACKUPS).join("pre-format-1");
    // A backup left by an upgrade that stopped halfway is replaced.
    let _ = fs::remove_dir_all(&backup_dir);
    fs::create_dir_all(&backup_dir)?;
    teifs_meta::backup(&legacy, &backup_dir.join(LEGACY_DB))?;
    let staging = system.join(format!("{INDEX_DB}.upgrading"));
    let _ = fs::remove_file(&staging);
    teifs_meta::backup(&legacy, &staging)?;
    fs::rename(&staging, system.join(INDEX_DB))?;
    sync_dir(system)?;
    Ok(())
}

/// Removes format 0's database once format 1 is committed.
fn remove_legacy(system: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(system.join(format!("{LEGACY_DB}{suffix}")));
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use io::Write;
    let tmp: PathBuf = path.with_extension("json.tmp");
    let mut file = fs::File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    Ok(())
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
