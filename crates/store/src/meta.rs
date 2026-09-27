//! The metadata database (`.teidrive/meta.db`): what S3 needs that a file system doesn't
//! keep (ETags, content types, user metadata, checksums) and multipart uploads in progress.
//!
//! Files stay the source of truth. A row applies only while its file's [`Stamp`] is
//! unchanged; a file written by anything else simply has no current row.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::{
    error::Result,
    object::{ObjectAttrs, Stamp},
};

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

/// Opens (creating and migrating) the database.
pub(crate) fn open(path: &Path) -> Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let version = usize::try_from(version).unwrap_or(0);
    if version < MIGRATIONS.len() {
        let tx = conn.transaction()?;
        for migration in &MIGRATIONS[version..] {
            tx.execute_batch(migration)?;
        }
        tx.pragma_update(
            None,
            "user_version",
            i64::try_from(MIGRATIONS.len()).expect("few migrations"),
        )?;
        tx.commit()?;
    }
    Ok(conn)
}

/// What's stored about an object.
#[derive(Debug, Clone)]
pub(crate) struct Row {
    pub stamp: Stamp,
    pub etag: String,
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
pub(crate) use cast::{from_db, to_db};

fn attrs_to_json(attrs: &ObjectAttrs) -> String {
    serde_json::to_string(attrs).expect("attributes serialize")
}

fn attrs_from_json(json: &str) -> ObjectAttrs {
    // A row written by a newer version with fields this one doesn't know still reads.
    serde_json::from_str(json).unwrap_or_default()
}

pub(crate) fn get(conn: &Connection, bucket: &str, key: &str) -> Result<Option<Row>> {
    let mut stmt = conn.prepare_cached(
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

pub(crate) fn put(conn: &Connection, bucket: &str, key: &str, row: &Row) -> Result<()> {
    conn.prepare_cached(
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

pub(crate) fn delete(conn: &Connection, bucket: &str, key: &str) -> Result<()> {
    conn.prepare_cached("DELETE FROM objects WHERE bucket = ?1 AND key = ?2")?
        .execute(params![bucket, key])?;
    Ok(())
}

/// Whether `key` (a folder, ending in `/`) was created on purpose, so it stays when its
/// last file is deleted.
pub(crate) fn is_kept_folder(conn: &Connection, bucket: &str, key: &str) -> Result<bool> {
    Ok(get(conn, bucket, key)?.is_some())
}

pub(crate) fn forget_bucket(conn: &Connection, bucket: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM parts WHERE upload_id IN (SELECT id FROM uploads WHERE bucket = ?1)",
        [bucket],
    )?;
    conn.execute("DELETE FROM uploads WHERE bucket = ?1", [bucket])?;
    conn.execute("DELETE FROM objects WHERE bucket = ?1", [bucket])?;
    Ok(())
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

pub(crate) fn insert_upload(conn: &Connection, upload: &Upload) -> Result<()> {
    conn.execute(
        "INSERT INTO uploads (id, bucket, key, owner, attrs, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![upload.id, upload.bucket, upload.key, upload.owner, attrs_to_json(&upload.attrs), upload.created_ms],
    )?;
    Ok(())
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

pub(crate) fn get_upload(conn: &Connection, id: &str) -> Result<Option<Upload>> {
    Ok(conn
        .prepare_cached(
            "SELECT id, bucket, key, owner, attrs, created_ms FROM uploads WHERE id = ?1",
        )?
        .query_row([id], upload_from_row)
        .optional()?)
}

/// Uploads in a bucket, ordered by key then id, after the given markers.
pub(crate) fn list_uploads(
    conn: &Connection,
    bucket: &str,
    prefix: &str,
    after: Option<(&str, &str)>,
    limit: usize,
) -> Result<Vec<Upload>> {
    let (key_marker, id_marker) = after.unwrap_or(("", ""));
    let mut stmt = conn.prepare_cached(
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

pub(crate) fn delete_upload(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM parts WHERE upload_id = ?1", [id])?;
    conn.execute("DELETE FROM uploads WHERE id = ?1", [id])?;
    Ok(())
}

pub(crate) fn put_part(conn: &Connection, upload_id: &str, part: &Part) -> Result<()> {
    conn.prepare_cached(
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
pub(crate) fn list_parts(
    conn: &Connection,
    upload_id: &str,
    after: u32,
    limit: usize,
) -> Result<Vec<Part>> {
    let mut stmt = conn.prepare_cached(
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
