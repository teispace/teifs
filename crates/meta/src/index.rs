//! The index (`.teifs/index.db`): what S3 needs about each object that its file doesn't
//! hold, and multipart uploads in progress. Everything here can be rebuilt from the disk.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use teifs_types::{ObjectAttrs, Stamp};

use crate::{Result, db};

/// The index's schema, one entry per version.
const MIGRATIONS: &[&str] = &[
    // 1: objects, uploads and their parts.
    "CREATE TABLE objects (
        bucket   TEXT    NOT NULL,
        key      TEXT    NOT NULL,
        size     INTEGER NOT NULL,
        mtime_ns INTEGER NOT NULL,
        ino      INTEGER NOT NULL,
        etag     TEXT    NOT NULL,
        attrs    TEXT    NOT NULL,
        PRIMARY KEY (bucket, key)
     ) WITHOUT ROWID;
     CREATE TABLE uploads (
        id         TEXT    PRIMARY KEY,
        bucket     TEXT    NOT NULL,
        key        TEXT    NOT NULL,
        owner      TEXT,
        attrs      TEXT    NOT NULL,
        created_ms INTEGER NOT NULL
     );
     CREATE INDEX uploads_by_key ON uploads (bucket, key, id);
     CREATE TABLE parts (
        upload_id   TEXT    NOT NULL,
        part        INTEGER NOT NULL,
        size        INTEGER NOT NULL,
        etag        TEXT    NOT NULL,
        checksums   TEXT    NOT NULL,
        modified_ms INTEGER NOT NULL,
        PRIMARY KEY (upload_id, part)
     ) WITHOUT ROWID;",
];

/// The index of one drive. Not `Sync`: the store keeps it behind its commit lock.
#[derive(Debug)]
pub struct Index {
    conn: Connection,
}

/// What's stored about an object.
#[derive(Debug, Clone)]
pub struct Row {
    /// The file the row describes.
    pub stamp: Stamp,
    /// Its ETag, without quotes.
    pub etag: String,
    /// Its attributes.
    pub attrs: ObjectAttrs,
}

#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
mod cast {
    pub fn to_db(value: u64) -> i64 {
        value as i64
    }
    pub fn from_db(value: i64) -> u64 {
        value as u64
    }
}
use cast::{from_db, to_db};

fn attrs_to_json(attrs: &ObjectAttrs) -> String {
    serde_json::to_string(attrs).expect("attributes serialize")
}

fn attrs_from_json(json: &str) -> ObjectAttrs {
    // A row written by a newer version with fields this one doesn't know still reads.
    serde_json::from_str(json).unwrap_or_default()
}

/// A multipart upload in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    /// Its id.
    pub id: String,
    /// The bucket it writes to.
    pub bucket: String,
    /// The key it writes to.
    pub key: String,
    /// Who started it (an access key), if anyone signed the request.
    pub owner: Option<String>,
    /// The attributes the object gets.
    pub attrs: ObjectAttrs,
    /// When it started, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// A part uploaded so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// Its number (1 to 10,000).
    pub number: u32,
    /// Its size in bytes.
    pub size: u64,
    /// Its ETag (the MD5 of its bytes), without quotes.
    pub etag: String,
    /// Its checksums by algorithm, as S3 sends them.
    pub checksums: std::collections::BTreeMap<String, String>,
    /// When it was uploaded, in milliseconds since the Unix epoch.
    pub modified_ms: i64,
}

fn upload_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Upload> {
    Ok(Upload {
        id: r.get(0)?,
        bucket: r.get(1)?,
        key: r.get(2)?,
        owner: r.get(3)?,
        attrs: attrs_from_json(&r.get::<_, String>(4)?),
        created_ms: r.get(5)?,
    })
}

impl Index {
    /// Opens the index at `path`, creating and migrating it.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            conn: db::open(path, MIGRATIONS)?,
        })
    }

    /// The row for an object, if any.
    pub fn get(&self, bucket: &str, key: &str) -> Result<Option<Row>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT size, mtime_ns, ino, etag, attrs FROM objects WHERE bucket = ?1 AND key = ?2",
        )?;
        let row = stmt
            .query_row(params![bucket, key], |r| {
                Ok(Row {
                    stamp: Stamp {
                        size: from_db(r.get(0)?),
                        mtime_ns: r.get(1)?,
                        ino: from_db(r.get(2)?),
                    },
                    etag: r.get(3)?,
                    attrs: attrs_from_json(&r.get::<_, String>(4)?),
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Records an object's row, replacing any earlier one.
    pub fn put(&self, bucket: &str, key: &str, row: &Row) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO objects (bucket, key, size, mtime_ns, ino, etag, attrs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (bucket, key) DO UPDATE SET
               size = excluded.size, mtime_ns = excluded.mtime_ns, ino = excluded.ino,
               etag = excluded.etag, attrs = excluded.attrs",
            )?
            .execute(params![
                bucket,
                key,
                to_db(row.stamp.size),
                row.stamp.mtime_ns,
                to_db(row.stamp.ino),
                row.etag,
                attrs_to_json(&row.attrs),
            ])?;
        Ok(())
    }

    /// Forgets an object's row.
    pub fn delete(&self, bucket: &str, key: &str) -> Result<()> {
        self.conn
            .prepare_cached("DELETE FROM objects WHERE bucket = ?1 AND key = ?2")?
            .execute(params![bucket, key])?;
        Ok(())
    }

    /// Whether `key` (a folder, ending in `/`) was created on purpose, so it stays when its
    /// last file is deleted.
    pub fn is_kept_folder(&self, bucket: &str, key: &str) -> Result<bool> {
        Ok(self.get(bucket, key)?.is_some())
    }

    /// Forgets everything recorded about a bucket.
    pub fn forget_bucket(&self, bucket: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM parts WHERE upload_id IN (SELECT id FROM uploads WHERE bucket = ?1)",
            [bucket],
        )?;
        self.conn
            .execute("DELETE FROM uploads WHERE bucket = ?1", [bucket])?;
        self.conn
            .execute("DELETE FROM objects WHERE bucket = ?1", [bucket])?;
        Ok(())
    }

    /// Records a new multipart upload.
    pub fn insert_upload(&self, upload: &Upload) -> Result<()> {
        self.conn.execute(
            "INSERT INTO uploads (id, bucket, key, owner, attrs, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![upload.id, upload.bucket, upload.key, upload.owner, attrs_to_json(&upload.attrs), upload.created_ms],
        )?;
        Ok(())
    }

    /// A multipart upload, if it exists.
    pub fn get_upload(&self, id: &str) -> Result<Option<Upload>> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT id, bucket, key, owner, attrs, created_ms FROM uploads WHERE id = ?1",
            )?
            .query_row([id], upload_from_row)
            .optional()?)
    }

    /// Uploads in a bucket, ordered by key then id, after the given markers.
    pub fn list_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<(&str, &str)>,
        limit: usize,
    ) -> Result<Vec<Upload>> {
        let (key_marker, id_marker) = after.unwrap_or(("", ""));
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, bucket, key, owner, attrs, created_ms FROM uploads
             WHERE bucket = ?1 AND substr(key, 1, length(?2)) = ?2 AND (key > ?3 OR (key = ?3 AND id > ?4))
             ORDER BY key, id LIMIT ?5",
        )?;
        let rows = stmt.query_map(
            params![
                bucket,
                prefix,
                key_marker,
                id_marker,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            upload_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Forgets a multipart upload and its parts.
    pub fn delete_upload(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM parts WHERE upload_id = ?1", [id])?;
        self.conn
            .execute("DELETE FROM uploads WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Records an uploaded part, replacing one with the same number.
    pub fn put_part(&self, upload_id: &str, part: &Part) -> Result<()> {
        self.conn.prepare_cached(
            "INSERT INTO parts (upload_id, part, size, etag, checksums, modified_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (upload_id, part) DO UPDATE SET
               size = excluded.size, etag = excluded.etag, checksums = excluded.checksums,
               modified_ms = excluded.modified_ms",
        )?
        .execute(params![
            upload_id,
            part.number,
            to_db(part.size),
            part.etag,
            serde_json::to_string(&part.checksums).expect("checksums serialize"),
            part.modified_ms,
        ])?;
        Ok(())
    }

    /// Parts of an upload with numbers above `after`, in order.
    pub fn list_parts(&self, upload_id: &str, after: u32, limit: usize) -> Result<Vec<Part>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT part, size, etag, checksums, modified_ms FROM parts
             WHERE upload_id = ?1 AND part > ?2 ORDER BY part LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![upload_id, after, i64::try_from(limit).unwrap_or(i64::MAX)],
            |r| {
                Ok(Part {
                    number: r.get(0)?,
                    size: from_db(r.get(1)?),
                    etag: r.get(2)?,
                    checksums: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
                    modified_ms: r.get(4)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}
