//! A look at a drive without opening it: its format, whether a process has it open, its
//! databases' integrity and how its file system treats names. Nothing on the drive is
//! changed (an older format isn't upgraded), so it's safe while `teifs serve` runs.

use std::{fs, path::Path};

use crate::{
    DriveFormat, FORMAT, SYSTEM_DIR, StoreError,
    error::Result,
    format::{self, INDEX_DB, SYSTEM_DB},
    lock_drive,
};

/// What a look at a drive found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    /// The format it records, or why it can't be read.
    pub format: std::result::Result<DriveFormat, String>,
    /// Another process (a running `teifs serve`) has it open.
    pub in_use: bool,
    /// Its index.
    pub index: Database,
    /// Its system database: buckets, settings and IAM.
    pub system: Database,
    /// Whether two names that differ only in case are two files there; `None` when that
    /// couldn't be found out.
    pub case_sensitive: Option<bool>,
}

/// A database's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    /// It passes SQLite's quick check.
    Intact,
    /// It fails it, or isn't a database.
    Damaged,
    /// It isn't there.
    Missing,
}

impl Diagnosis {
    /// Whether this build can serve the drive: its format isn't newer than this one's
    /// (an older one is upgraded when it's served).
    #[must_use]
    pub fn format_supported(&self) -> bool {
        self.format.as_ref().is_ok_and(|f| f.format <= FORMAT)
    }
}

/// Looks at the drive at `root` without opening it. Fails only when `root` isn't a drive:
/// it has no `.teifs` folder.
pub fn diagnose(root: &Path) -> Result<Diagnosis> {
    let system = root.join(SYSTEM_DIR);
    if !system.is_dir() {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "{} isn't a drive: it has no {SYSTEM_DIR} folder",
                root.display()
            ),
        )));
    }
    let format = format::read(&system).map_err(|e| e.to_string());
    // Held for no longer than the look: a drive being served stays served.
    let in_use = matches!(lock_drive(&system), Err(StoreError::DriveInUse));
    Ok(Diagnosis {
        format,
        in_use,
        index: database(&system.join(INDEX_DB)),
        system: database(&system.join(SYSTEM_DB)),
        case_sensitive: case_sensitive(&system.join("tmp")),
    })
}

fn database(path: &Path) -> Database {
    if !path.is_file() {
        return Database::Missing;
    }
    match teifs_meta::intact(path) {
        Ok(true) => Database::Intact,
        Ok(false) | Err(_) => Database::Damaged,
    }
}

/// Whether `dir`'s file system tells names apart by case, found out with a file of its
/// own, removed again.
fn case_sensitive(dir: &Path) -> Option<bool> {
    let name = format!("case-probe-{}", uuid::Uuid::new_v4().simple());
    let lower = dir.join(&name);
    fs::write(&lower, b"").ok()?;
    let other = dir.join(name.to_ascii_uppercase()).exists();
    let _ = fs::remove_file(&lower);
    Some(!other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn a_drive_is_looked_at_without_being_opened() {
        let dir = tempfile::tempdir().unwrap();
        assert!(diagnose(dir.path()).is_err(), "not a drive");
        let store = Store::open(dir.path()).unwrap();
        let open = diagnose(dir.path()).unwrap();
        assert!(open.in_use);
        assert!(open.format_supported());
        assert_eq!(open.format.as_ref().unwrap().format, FORMAT);
        assert_eq!(
            (open.index, open.system),
            (Database::Intact, Database::Intact)
        );
        // As a file of the test's own finds it.
        fs::write(dir.path().join("Probe"), b"").unwrap();
        let insensitive = dir.path().join("probe").exists();
        assert_eq!(open.case_sensitive, Some(!insensitive));
        drop(store);
        let closed = diagnose(dir.path()).unwrap();
        assert!(!closed.in_use);
        // No probe is left behind.
        let left = fs::read_dir(dir.path().join(SYSTEM_DIR).join("tmp"))
            .unwrap()
            .count();
        assert_eq!(left, 0);
        // Looking didn't keep it: it opens again.
        drop(Store::open(dir.path()).unwrap());
    }

    #[test]
    fn damage_and_newer_formats_are_found() {
        let dir = tempfile::tempdir().unwrap();
        drop(Store::open(dir.path()).unwrap());
        let system = dir.path().join(SYSTEM_DIR);
        fs::write(system.join(INDEX_DB), vec![7u8; 8192]).unwrap();
        fs::remove_file(system.join(SYSTEM_DB)).unwrap();
        let mut recorded: serde_json::Value =
            serde_json::from_slice(&fs::read(system.join("format.json")).unwrap()).unwrap();
        recorded["format"] = (FORMAT + 1).into();
        fs::write(system.join("format.json"), recorded.to_string()).unwrap();
        let found = diagnose(dir.path()).unwrap();
        assert_eq!(
            (found.index, found.system),
            (Database::Damaged, Database::Missing)
        );
        assert!(!found.format_supported());
        // Nothing was made up for what's missing.
        assert!(!system.join(SYSTEM_DB).exists());
        fs::write(system.join("format.json"), "nonsense").unwrap();
        let found = diagnose(dir.path()).unwrap();
        assert!(found.format.is_err() && !found.format_supported());
    }
}
