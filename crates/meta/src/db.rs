//! Opening, migrating and backing up a SQLite database.

use std::{path::Path, time::Duration};

use rusqlite::{Connection, OpenFlags};

use crate::{MetaError, Result};

/// Opens (creating it if needed) the database at `path` and brings its schema up to
/// date. `migrations[n]` takes the schema from version `n` to `n + 1`.
///
/// Commits are durable before they return (`synchronous=FULL`); the durability modes
/// that relax this come with the server's settings.
pub(crate) fn open(path: &Path, migrations: &[&str]) -> Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    // On Apple systems fsync() doesn't reach the disk's platters or flash; F_FULLFSYNC
    // does. Without these, a power cut can lose commits that were acknowledged.
    if cfg!(target_vendor = "apple") {
        conn.pragma_update(None, "fullfsync", true)?;
        conn.pragma_update(None, "checkpoint_fullfsync", true)?;
    }
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    let known = i64::try_from(migrations.len()).unwrap_or(i64::MAX);
    let found: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if found > known {
        return Err(MetaError::NewerSchema { found, known });
    }
    if found < known {
        let tx = conn.transaction()?;
        for migration in &migrations[usize::try_from(found).unwrap_or(0)..] {
            tx.execute_batch(migration)?;
        }
        tx.pragma_update(None, "user_version", known)?;
        tx.commit()?;
    }
    Ok(conn)
}

/// Writes a consistent copy of the database at `path` to `to` (which must not exist),
/// including anything still in its write-ahead log.
pub fn backup(path: &Path, to: &Path) -> Result<()> {
    let conn = existing(path)?;
    conn.execute("VACUUM INTO ?1", [to.to_string_lossy()])?;
    Ok(())
}

/// Whether the database at `path` passes SQLite's quick check (a file SQLite can't
/// read as a database doesn't).
pub fn intact(path: &Path) -> Result<bool> {
    let conn = existing(path)?;
    Ok(conn
        .query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))
        .is_ok_and(|answer| answer == "ok"))
}

/// Opens the database at `path`, which must exist: a missing one is an error, never a
/// new empty database (a backup of that would pass for a drive with nothing in it).
fn existing(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    Ok(Connection::open_with_flags(path, flags)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2: &[&str] = &["CREATE TABLE a (x)", "CREATE TABLE b (y)"];

    #[test]
    fn migrates_forward_and_refuses_newer_schemas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        open(&path, &V2[..1]).unwrap();
        let conn = open(&path, V2).unwrap();
        conn.execute("INSERT INTO b VALUES (1)", []).unwrap();
        drop(conn);
        match open(&path, &V2[..1]) {
            Err(MetaError::NewerSchema { found: 2, known: 1 }) => {}
            other => panic!("expected NewerSchema, got {other:?}"),
        }
    }

    #[test]
    fn only_readable_databases_are_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        drop(open(&path, V2).unwrap());
        assert!(intact(&path).unwrap());
        let garbage = dir.path().join("g.db");
        std::fs::write(&garbage, vec![7u8; 8192]).unwrap();
        assert!(!intact(&garbage).unwrap());
    }

    #[test]
    fn commits_are_durable() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("t.db"), V2).unwrap();
        let sync: i64 = conn
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2, "synchronous=FULL");
        let full: i64 = conn
            .pragma_query_value(None, "fullfsync", |r| r.get(0))
            .unwrap();
        assert_eq!(full == 1, cfg!(target_vendor = "apple"));
    }

    #[test]
    fn backups_include_the_write_ahead_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let conn = open(&path, V2).unwrap();
        conn.execute("INSERT INTO a VALUES ('kept')", []).unwrap();
        let copy = dir.path().join("copy.db");
        backup(&path, &copy).unwrap();
        drop(conn);
        let copy = Connection::open(copy).unwrap();
        let x: String = copy.query_row("SELECT x FROM a", [], |r| r.get(0)).unwrap();
        assert_eq!(x, "kept");
    }

    #[test]
    fn a_missing_database_is_never_made_up() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone.db");
        assert!(backup(&missing, &dir.path().join("copy.db")).is_err());
        assert!(intact(&missing).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
