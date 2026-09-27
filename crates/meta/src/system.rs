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
    // 2: a permanent id per bucket (object buckets store data under it; encryption binds
    //    keys to it).
    "ALTER TABLE buckets ADD COLUMN id TEXT;
     UPDATE buckets SET id = lower(hex(randomblob(16))) WHERE id IS NULL;
     CREATE UNIQUE INDEX buckets_by_id ON buckets (id);",
];

/// How a bucket stores its objects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Layout {
    /// Each object is a plain file at its key's path, in a folder at the drive's root.
    #[default]
    Folder,
    /// Objects are stored by id under `.teifs/`, with every key S3 allows.
    Object,
}

impl Layout {
    fn as_str(self) -> &'static str {
        match self {
            Layout::Folder => "plain",
            Layout::Object => "object",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(Layout::Folder),
            "object" => Some(Layout::Object),
            _ => None,
        }
    }
}

/// What's recorded about a bucket. A folder in the drive without a record is a plain
/// bucket with default settings (made outside TeiFS, or before records existed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketRecord {
    /// Its permanent id.
    pub id: String,
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
                "INSERT INTO buckets (id, name, layout, created_ms) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (name) DO UPDATE SET id = excluded.id, layout = excluded.layout,
                   created_ms = excluded.created_ms",
            )?
            .execute(params![
                record.id,
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
            .prepare_cached("SELECT id, name, layout, created_ms FROM buckets WHERE name = ?1")?
            .query_row([name], record_from_row)
            .optional()?)
    }

    /// Every recorded bucket, by name.
    pub fn buckets(&self) -> Result<Vec<BucketRecord>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT id, name, layout, created_ms FROM buckets ORDER BY name")?;
        let rows = stmt.query_map([], record_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// A bucket's settings (JSON the store owns), if it's recorded.
    pub fn bucket_config(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT config FROM buckets WHERE name = ?1")?
            .query_row([name], |r| r.get(0))
            .optional()?)
    }

    /// Replaces a recorded bucket's settings; false when the bucket isn't recorded.
    pub fn set_bucket_config(&self, name: &str, config: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("UPDATE buckets SET config = ?2 WHERE name = ?1")?
            .execute([name, config])?
            > 0)
    }

    /// Forgets a deleted bucket.
    pub fn forget_bucket(&self, name: &str) -> Result<()> {
        self.conn
            .prepare_cached("DELETE FROM buckets WHERE name = ?1")?
            .execute([name])?;
        Ok(())
    }
}

fn record_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<BucketRecord> {
    Ok(BucketRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        // An unknown layout can only come from a newer TeiFS, whose schema this build
        // refuses to open; folder is the safe reading.
        layout: Layout::parse(&r.get::<_, String>(2)?).unwrap_or_default(),
        created_ms: r.get(3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_recorded_and_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let system = System::open(&dir.path().join("system.db")).unwrap();
        let record = BucketRecord {
            id: "id1".into(),
            name: "photos".into(),
            layout: Layout::Object,
            created_ms: 42,
        };
        system.record_bucket(&record).unwrap();
        assert_eq!(system.bucket("photos").unwrap(), Some(record.clone()));
        assert_eq!(system.buckets().unwrap(), [record]);
        assert_eq!(
            system.bucket_config("photos").unwrap().as_deref(),
            Some("{}")
        );
        assert!(system.set_bucket_config("photos", r#"{"a":1}"#).unwrap());
        assert_eq!(
            system.bucket_config("photos").unwrap().as_deref(),
            Some(r#"{"a":1}"#)
        );
        assert!(!system.set_bucket_config("missing", "{}").unwrap());
        system.forget_bucket("photos").unwrap();
        assert_eq!(system.bucket("photos").unwrap(), None);
    }
}
