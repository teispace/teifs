//! Opening, migrating and backing up a SQLite database.

use std::{path::Path, time::Duration};

use rusqlite::Connection;

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
    let conn = Connection::open(path)?;
    conn.execute("VACUUM INTO ?1", [to.to_string_lossy()])?;
    Ok(())
}

/// Whether the database at `path` passes SQLite's quick check.
pub fn intact(path: &Path) -> Result<bool> {
    let conn = Connection::open(path)?;
    let answer: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    Ok(answer == "ok")
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
}
