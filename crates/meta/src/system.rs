//! The system database (`.teifs/system.db`): what can't be rebuilt from the files.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::{Result, db};

/// The system database's schema, one entry per version.
const MIGRATIONS: &[&str] = &[
    // 1: buckets TeiFS created, with the layout their objects are stored in.
    "CREATE TABLE buckets (
        name       TEXT    PRIMARY KEY,
        layout     TEXT    NOT NULL,
        created_ms INTEGER NOT NULL,
        config     TEXT    NOT NULL DEFAULT '{}'
     ) WITHOUT ROWID;",
];

/// How a bucket stores its objects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Layout {
    /// Each object is a plain file at its key's path.
    #[default]
    Plain,
}

impl Layout {
    fn as_str(self) -> &'static str {
        match self {
            Layout::Plain => "plain",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(Layout::Plain),
            _ => None,
        }
    }
}

/// What's recorded about a bucket. A folder in the drive without a record is a plain
/// bucket with default settings (made outside TeiFS, or before records existed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketRecord {
    /// Its name.
    pub name: String,
    /// How it stores objects.
    pub layout: Layout,
    /// When TeiFS created it, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// A drive's system database. Not `Sync`: the store keeps it behind a lock.
#[derive(Debug)]
pub struct System {
    conn: Connection,
}

impl System {
    /// Opens the system database at `path`, creating and migrating it.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            conn: db::open(path, MIGRATIONS)?,
        })
    }

    /// Records a bucket TeiFS just created.
    pub fn record_bucket(&self, record: &BucketRecord) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO buckets (name, layout, created_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT (name) DO UPDATE SET layout = excluded.layout,
                   created_ms = excluded.created_ms",
            )?
            .execute(params![
                record.name,
                record.layout.as_str(),
                record.created_ms
            ])?;
        Ok(())
    }

    /// The record of a bucket, if TeiFS created it.
    pub fn bucket(&self, name: &str) -> Result<Option<BucketRecord>> {
        Ok(self
            .conn
            .prepare_cached("SELECT name, layout, created_ms FROM buckets WHERE name = ?1")?
            .query_row([name], |r| {
                Ok(BucketRecord {
                    name: r.get(0)?,
                    // An unknown layout can only come from a newer TeiFS, which bumps the
                    // format so this one never opens the drive; plain is the safe reading.
                    layout: Layout::parse(&r.get::<_, String>(1)?).unwrap_or_default(),
                    created_ms: r.get(2)?,
                })
            })
            .optional()?)
    }

    /// Forgets a deleted bucket.
    pub fn forget_bucket(&self, name: &str) -> Result<()> {
        self.conn
            .prepare_cached("DELETE FROM buckets WHERE name = ?1")?
            .execute([name])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_recorded_and_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let system = System::open(&dir.path().join("system.db")).unwrap();
        let record = BucketRecord {
            name: "photos".into(),
            layout: Layout::Plain,
            created_ms: 42,
        };
        system.record_bucket(&record).unwrap();
        assert_eq!(system.bucket("photos").unwrap(), Some(record));
        system.forget_bucket("photos").unwrap();
        assert_eq!(system.bucket("photos").unwrap(), None);
    }
}
