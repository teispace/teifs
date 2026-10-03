//! The index (`.teifs/index.db`): for folder buckets, what S3 needs about each object
//! that its file doesn't hold (rebuildable from the disk); for object buckets, every
//! object version (authoritative); and multipart uploads in progress.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use teifs_types::{ObjectAttrs, Stamp};

use crate::{MetaError, Result, db};

/// An open transaction or savepoint ([`Index::begin`]).
pub(crate) struct Tx<'a> {
    conn: &'a Connection,
    /// Whether it began the transaction (it isn't a savepoint inside another).
    outermost: bool,
    done: bool,
}

impl Tx<'_> {
    /// Keeps its writes (commits them, when it's the outermost).
    ///
    /// A commit that fails (an I/O error, a full disk) can leave SQLite's transaction
    /// open; it's rolled back then, or every later batch would be a savepoint inside it
    /// that "commits" without writing anything, and be acknowledged and lost.
    pub(crate) fn commit(mut self) -> Result<()> {
        self.done = true;
        if let Err(err) = self.conn.execute_batch("RELEASE tx") {
            if self.outermost && !self.conn.is_autocommit() {
                let _ = self.conn.execute_batch("ROLLBACK");
            } else if !self.outermost {
                let _ = self.conn.execute_batch("ROLLBACK TO tx; RELEASE tx");
            }
            return Err(err.into());
        }
        Ok(())
    }
}

impl std::ops::Deref for Tx<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.conn.execute_batch("ROLLBACK TO tx; RELEASE tx");
        }
    }
}

/// The index's schema, one entry per version.
pub(crate) const MIGRATIONS: &[&str] = &[
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
    // 2: object buckets: one row per object version (keys as bytes, so comparisons are
    //    S3's byte order), and data files waiting to be removed.
    "CREATE TABLE object_versions (
        bucket_id     TEXT    NOT NULL,
        key           BLOB    NOT NULL,
        seq           INTEGER NOT NULL,
        version_id    TEXT    NOT NULL,
        latest        INTEGER NOT NULL,
        delete_marker INTEGER NOT NULL,
        object_id     TEXT,
        size          INTEGER NOT NULL,
        etag          TEXT    NOT NULL,
        modified_ms   INTEGER NOT NULL,
        attrs         TEXT    NOT NULL,
        crypt         TEXT,
        parts         TEXT,
        data          BLOB,
        PRIMARY KEY (bucket_id, key, seq)
     ) WITHOUT ROWID;
     CREATE INDEX object_versions_latest ON object_versions (bucket_id, key) WHERE latest = 1;
     CREATE INDEX object_versions_by_object ON object_versions (object_id)
        WHERE object_id IS NOT NULL;
     CREATE TABLE garbage (
        object_id TEXT    PRIMARY KEY,
        bucket_id TEXT    NOT NULL,
        queued_ms INTEGER NOT NULL
     ) WITHOUT ROWID;",
    // 3: multipart uploads to encrypted objects keep their sealed data key.
    "ALTER TABLE uploads ADD COLUMN crypt TEXT;",
    // 4: client tokens of idempotent requests (RenameObject), and what they asked for.
    "CREATE TABLE client_tokens (
        token      TEXT    PRIMARY KEY,
        request    TEXT    NOT NULL,
        created_ms INTEGER NOT NULL
     ) WITHOUT ROWID;",
    // 5: folder buckets record the parts of multipart objects too.
    "ALTER TABLE objects ADD COLUMN parts TEXT;",
    // 6: the checksum a multipart upload's object gets, and what completed uploads
    // answered (a retried Complete gets the same answer).
    "ALTER TABLE uploads ADD COLUMN checksum TEXT;
     CREATE TABLE completed_uploads (
        id           TEXT    PRIMARY KEY,
        bucket       TEXT    NOT NULL,
        key          TEXT    NOT NULL,
        result       TEXT    NOT NULL,
        completed_ms INTEGER NOT NULL
     ) WITHOUT ROWID;",
    // 7: the most a multipart upload's object may be, when its creation was capped.
    "ALTER TABLE uploads ADD COLUMN max_size INTEGER;",
    // 8: the version id of a folder bucket's current file (NULL: `null`).
    "ALTER TABLE objects ADD COLUMN version_id TEXT;",
    // 9: the salt in an encrypted part's key (hex; NULL for plain parts and older ones).
    "ALTER TABLE parts ADD COLUMN salt TEXT;",
    // 10: what each bucket holds, kept by triggers.
    crate::usage::MIGRATION,
    // 11: deletes of versions waiting to be replicated (the versions themselves are gone).
    crate::replicated_deletes::MIGRATION,
];

/// The index of one drive. Not `Sync`: the store keeps it behind its commit lock.
#[derive(Debug)]
pub struct Index {
    pub(crate) conn: Connection,
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
    /// Its parts, when it was uploaded in parts (JSON the store owns).
    pub parts: Option<String>,
    /// Its version id, in a bucket with versioning; `None` is `null`.
    pub version_id: Option<String>,
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

pub(crate) fn attrs_to_json(attrs: &ObjectAttrs) -> String {
    serde_json::to_string(attrs).expect("attributes serialize")
}

pub(crate) fn attrs_from_json(json: &str) -> ObjectAttrs {
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
    /// How the object will be encrypted (JSON the store owns), if it will be.
    pub crypt: Option<String>,
    /// The checksum the object will get (JSON the store owns), if any.
    pub checksum: Option<String>,
    /// The most the object may be, all parts together, if its creation capped it.
    pub max_size: Option<u64>,
}

/// A completed multipart upload, remembered for a while so a retried Complete gets the
/// same answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedUpload {
    /// The bucket it wrote to.
    pub bucket: String,
    /// The key it wrote to.
    pub key: String,
    /// What Complete answered (JSON the store owns).
    pub result: String,
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
    /// For an encrypted part, the salt in its key (hex).
    pub salt: Option<String>,
}

/// A row from `size, mtime_ns, ino, etag, attrs, parts, version_id` (the first seven
/// columns).
fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        stamp: Stamp {
            size: from_db(r.get(0)?),
            mtime_ns: r.get(1)?,
            ino: from_db(r.get(2)?),
        },
        etag: r.get(3)?,
        attrs: attrs_from_json(&r.get::<_, String>(4)?),
        parts: r.get(5)?,
        version_id: r.get(6)?,
    })
}

fn upload_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Upload> {
    Ok(Upload {
        id: r.get(0)?,
        bucket: r.get(1)?,
        key: r.get(2)?,
        owner: r.get(3)?,
        attrs: attrs_from_json(&r.get::<_, String>(4)?),
        created_ms: r.get(5)?,
        crypt: r.get(6)?,
        checksum: r.get(7)?,
        max_size: r.get::<_, Option<i64>>(8)?.map(from_db),
    })
}

// Pages of a folder bucket's rows, for the pass that indexes its files. Each bound is a
// plain comparison so SQLite seeks to it (no key is empty, so `> ''` starts at the
// first): an optional bound written `(?2 IS NULL OR key > ?2)` can't be used to seek,
// and every page would read the bucket from its first key.
const ROWS_BETWEEN: &str = "SELECT size, mtime_ns, ino, etag, attrs, parts, version_id, key
     FROM objects WHERE bucket = ?1 AND key > ?2 AND key <= ?3 ORDER BY key";
const KEYS_BETWEEN: &str = "SELECT key FROM objects
     WHERE bucket = ?1 AND key > ?2 AND key <= ?3 ORDER BY key LIMIT ?4";
const KEYS_AFTER: &str =
    "SELECT key FROM objects WHERE bucket = ?1 AND key > ?2 ORDER BY key LIMIT ?3";

impl Index {
    /// Opens the index at `path`, creating and migrating it.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            conn: db::open(path, MIGRATIONS)?,
        })
    }

    /// Opens another connection to the index at `path` (already opened, so migrated,
    /// by [`Index::open`]) that can only read. A read in [`Index::try_batch`] sees one
    /// snapshot: the commits made before it began.
    pub fn open_reader(path: &Path) -> Result<Self> {
        Ok(Self {
            conn: db::open_reader(path)?,
        })
    }

    /// How far commits are synced before they return: `FULL` (every commit survives a
    /// power cut), `NORMAL` (the last commits may be lost, the database never breaks), or
    /// `OFF` (the operating system decides).
    pub fn set_synchronous(&self, level: &str) -> Result<()> {
        debug_assert!(matches!(level, "FULL" | "NORMAL" | "OFF"));
        self.conn.pragma_update(None, "synchronous", level)?;
        Ok(())
    }

    /// Runs `change` in one transaction: its writes are committed and synced together,
    /// or not at all. Many small writes cost one sync instead of one each.
    /// Batches nest: one inside another is part of the outer one.
    pub fn batch<T>(&self, change: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        self.try_batch(change)
    }

    /// [`Index::batch`] for a change with errors of its own (any a [`MetaError`]
    /// converts to): one that fails is undone.
    pub fn try_batch<T, E: From<MetaError>>(
        &self,
        change: impl FnOnce(&Self) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let tx = self.begin()?;
        let out = change(self)?;
        tx.commit()?;
        Ok(out)
    }

    /// Starts a transaction, or a savepoint inside the one already open, so a change
    /// made of several writes can be part of a larger one ([`Index::batch`]). Dropped
    /// without [`Tx::commit`], its writes are undone.
    pub(crate) fn begin(&self) -> Result<Tx<'_>> {
        let outermost = self.conn.is_autocommit();
        self.conn.execute_batch("SAVEPOINT tx")?;
        Ok(Tx {
            conn: &self.conn,
            outermost,
            done: false,
        })
    }

    /// The row for an object, if any.
    pub fn get(&self, bucket: &str, key: &str) -> Result<Option<Row>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT size, mtime_ns, ino, etag, attrs, parts, version_id FROM objects
             WHERE bucket = ?1 AND key = ?2",
        )?;
        Ok(stmt.query_row(params![bucket, key], row_from).optional()?)
    }

    /// A folder bucket's rows after `after` (from the start when `None`) up to and
    /// including `upto`, in key order: one query for a page of keys.
    pub fn rows_between(
        &self,
        bucket: &str,
        after: Option<&str>,
        upto: &str,
    ) -> Result<Vec<(String, Row)>> {
        let mut stmt = self.conn.prepare_cached(ROWS_BETWEEN)?;
        let rows = stmt.query_map(params![bucket, after.unwrap_or(""), upto], |r| {
            Ok((r.get(7)?, row_from(r)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Records an object's row, replacing any earlier one.
    pub fn put(&self, bucket: &str, key: &str, row: &Row) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO objects (bucket, key, size, mtime_ns, ino, etag, attrs, parts, version_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (bucket, key) DO UPDATE SET
               size = excluded.size, mtime_ns = excluded.mtime_ns, ino = excluded.ino,
               etag = excluded.etag, attrs = excluded.attrs, parts = excluded.parts,
               version_id = excluded.version_id",
            )?
            .execute(params![
                bucket,
                key,
                to_db(row.stamp.size),
                row.stamp.mtime_ns,
                to_db(row.stamp.ino),
                row.etag,
                attrs_to_json(&row.attrs),
                row.parts,
                row.version_id,
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

    /// What an idempotent request with `token` asked for, if one was done.
    pub fn client_token(&self, token: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT request FROM client_tokens WHERE token = ?1")?
            .query_row([token], |r| r.get(0))
            .optional()?)
    }

    /// Records that the request `request` with `token` was done.
    pub fn record_client_token(&self, token: &str, request: &str, now_ms: i64) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO client_tokens (token, request, created_ms) VALUES (?1, ?2, ?3)",
            )?
            .execute(params![token, request, now_ms])?;
        Ok(())
    }

    /// Forgets client tokens recorded before `before_ms`.
    pub fn expire_client_tokens(&self, before_ms: i64) -> Result<()> {
        self.conn
            .prepare_cached("DELETE FROM client_tokens WHERE created_ms < ?1")?
            .execute([before_ms])?;
        Ok(())
    }

    /// Keys of a folder bucket's rows after `after` (from the start when `None`) up to
    /// and including `upto` (to the end when `None`), in key order, at most `limit`.
    pub fn keys_between(
        &self,
        bucket: &str,
        after: Option<&str>,
        upto: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let after = after.unwrap_or("");
        let keys = match upto {
            Some(upto) => self
                .conn
                .prepare_cached(KEYS_BETWEEN)?
                .query_map(params![bucket, after, upto, limit], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?,
            None => self
                .conn
                .prepare_cached(KEYS_AFTER)?
                .query_map(params![bucket, after, limit], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?,
        };
        Ok(keys)
    }

    /// Moves a folder bucket's row from one key to another (a rename keeps the file).
    pub fn rename(&self, bucket: &str, from: &str, to: &str) -> Result<()> {
        let tx = self.begin()?;
        tx.execute(
            "DELETE FROM objects WHERE bucket = ?1 AND key = ?2",
            params![bucket, to],
        )?;
        tx.execute(
            "UPDATE objects SET key = ?3 WHERE bucket = ?1 AND key = ?2",
            params![bucket, from, to],
        )?;
        tx.commit()?;
        Ok(())
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
            "INSERT INTO uploads (id, bucket, key, owner, attrs, created_ms, crypt, checksum, max_size)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                upload.id,
                upload.bucket,
                upload.key,
                upload.owner,
                attrs_to_json(&upload.attrs),
                upload.created_ms,
                upload.crypt,
                upload.checksum,
                upload.max_size.map(to_db)
            ],
        )?;
        Ok(())
    }

    /// A multipart upload, if it exists.
    pub fn get_upload(&self, id: &str) -> Result<Option<Upload>> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT id, bucket, key, owner, attrs, created_ms, crypt, checksum, max_size FROM uploads WHERE id = ?1",
            )?
            .query_row([id], upload_from_row)
            .optional()?)
    }

    /// Uploads whose data key (or DSSE-KMS outer key, `outer`) is sealed by a version of
    /// the KMS key `kms_key` older than `newest`.
    pub fn uploads_sealed_before(&self, kms_key: &str, newest: u32) -> Result<Vec<Upload>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, bucket, key, owner, attrs, created_ms, crypt, checksum, max_size FROM uploads
             WHERE crypt IS NOT NULL
               AND ((json_extract(crypt, '$.sealed.kmsKey') = ?1
                     AND json_extract(crypt, '$.sealed.kmsVersion') < ?2)
                 OR (json_extract(crypt, '$.outer.kmsKey') = ?1
                     AND json_extract(crypt, '$.outer.kmsVersion') < ?2))
             ORDER BY id",
        )?;
        let rows = stmt.query_map(params![kms_key, newest], upload_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Replaces an upload's encryption record if it's still `old`; whether it was.
    pub fn replace_upload_crypt(&self, id: &str, old: &str, new: &str) -> Result<bool> {
        let changed = self
            .conn
            .prepare_cached("UPDATE uploads SET crypt = ?3 WHERE id = ?1 AND crypt = ?2")?
            .execute(params![id, old, new])?;
        Ok(changed == 1)
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
            "SELECT id, bucket, key, owner, attrs, created_ms, crypt, checksum, max_size FROM uploads
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

    /// Remembers what completing upload `id` answered, and forgets completions older than
    /// `expire_before_ms`.
    pub fn record_completed(
        &self,
        id: &str,
        completed: &CompletedUpload,
        now_ms: i64,
        expire_before_ms: i64,
    ) -> Result<()> {
        self.expire_completed(expire_before_ms)?;
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO completed_uploads (id, bucket, key, result, completed_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![
                id,
                completed.bucket,
                completed.key,
                completed.result,
                now_ms
            ])?;
        Ok(())
    }

    /// Forgets completed uploads' answers older than `before_ms`.
    pub fn expire_completed(&self, before_ms: i64) -> Result<usize> {
        Ok(self
            .conn
            .prepare_cached("DELETE FROM completed_uploads WHERE completed_ms < ?1")?
            .execute([before_ms])?)
    }

    /// Ids of uploads started before `before_ms`, oldest first, at most `limit`.
    pub fn stale_uploads(&self, before_ms: i64, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id FROM uploads WHERE created_ms < ?1 ORDER BY created_ms LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![before_ms, i64::try_from(limit).unwrap_or(i64::MAX)],
            |r| r.get(0),
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// What completing upload `id` answered, if it completed recently.
    pub fn completed_upload(&self, id: &str) -> Result<Option<CompletedUpload>> {
        Ok(self
            .conn
            .prepare_cached("SELECT bucket, key, result FROM completed_uploads WHERE id = ?1")?
            .query_row([id], |r| {
                Ok(CompletedUpload {
                    bucket: r.get(0)?,
                    key: r.get(1)?,
                    result: r.get(2)?,
                })
            })
            .optional()?)
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
        self.conn
            .prepare_cached(
                "INSERT INTO parts (upload_id, part, size, etag, checksums, modified_ms, salt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (upload_id, part) DO UPDATE SET
               size = excluded.size, etag = excluded.etag, checksums = excluded.checksums,
               modified_ms = excluded.modified_ms, salt = excluded.salt",
            )?
            .execute(params![
                upload_id,
                part.number,
                to_db(part.size),
                part.etag,
                serde_json::to_string(&part.checksums).expect("checksums serialize"),
                part.modified_ms,
                part.salt,
            ])?;
        Ok(())
    }

    /// The size of an upload's parts, all but part `except` (0 for all of them).
    pub fn parts_size(&self, upload_id: &str, except: u32) -> Result<u64> {
        let size: i64 = self
            .conn
            .prepare_cached(
                "SELECT COALESCE(SUM(size), 0) FROM parts WHERE upload_id = ?1 AND part != ?2",
            )?
            .query_row(params![upload_id, except], |r| r.get(0))?;
        Ok(from_db(size))
    }

    /// Parts of an upload with numbers above `after`, in order.
    pub fn list_parts(&self, upload_id: &str, after: u32, limit: usize) -> Result<Vec<Part>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT part, size, etag, checksums, modified_ms, salt FROM parts
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
                    salt: r.get(5)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_of_a_folder_bucket_seek_to_their_first_key() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        for sql in [ROWS_BETWEEN, KEYS_BETWEEN, KEYS_AFTER] {
            let mut stmt = index
                .conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            let values = vec!["k"; stmt.parameter_count()];
            let plan: Vec<String> = stmt
                .query_map(rusqlite::params_from_iter(values), |r| r.get(3))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert!(
                plan.iter().any(|step| step.contains("key>?")),
                "{sql} reads from the bucket's first key: {plan:?}"
            );
        }
    }

    #[test]
    fn pages_of_a_folder_bucket_hold_the_keys_between_their_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        let row = Row {
            stamp: Stamp {
                size: 1,
                mtime_ns: 1,
                ino: 1,
            },
            etag: "e".into(),
            attrs: ObjectAttrs::default(),
            parts: None,
            version_id: None,
        };
        for key in ["a", "b", "b/", "c", "d"] {
            index.put("f", key, &row).unwrap();
        }
        index.put("other", "a", &row).unwrap();
        let rows = |after, upto| -> Vec<String> {
            index
                .rows_between("f", after, upto)
                .unwrap()
                .into_iter()
                .map(|(key, _)| key)
                .collect()
        };
        assert_eq!(rows(None, "b/"), ["a", "b", "b/"]);
        assert_eq!(rows(Some("b"), "d"), ["b/", "c", "d"]);
        let keys = |after, upto, limit| index.keys_between("f", after, upto, limit).unwrap();
        assert_eq!(keys(None, None, 10), ["a", "b", "b/", "c", "d"]);
        assert_eq!(keys(None, Some("b"), 10), ["a", "b"]);
        assert_eq!(keys(Some("b"), None, 2), ["b/", "c"]);
        assert_eq!(keys(Some("c"), Some("d"), 10), ["d"]);
        assert!(keys(Some("d"), None, 10).is_empty());
    }

    #[test]
    fn the_sync_level_can_be_relaxed() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        let level = |index: &Index| -> i64 {
            index
                .conn
                .pragma_query_value(None, "synchronous", |r| r.get(0))
                .unwrap()
        };
        assert_eq!(level(&index), 2, "FULL by default");
        index.set_synchronous("NORMAL").unwrap();
        assert_eq!(level(&index), 1);
        index.set_synchronous("OFF").unwrap();
        assert_eq!(level(&index), 0);
    }

    #[test]
    fn batches_nest_and_a_failed_one_undoes_only_its_own_writes() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        let done = |key: &str| CompletedUpload {
            bucket: "b".into(),
            key: key.into(),
            result: "{}".into(),
        };
        let failed = || -> crate::MetaError { rusqlite::Error::InvalidQuery.into() };
        index
            .batch(|index| {
                index.record_completed("outer", &done("k1"), 1_000, 0)?;
                let inner = index.batch(|index| {
                    index.record_completed("inner", &done("k2"), 1_000, 0)?;
                    Err::<(), _>(failed())
                });
                assert!(inner.is_err());
                index.batch(|index| index.record_completed("kept", &done("k3"), 1_000, 0))
            })
            .unwrap();
        assert!(index.completed_upload("outer").unwrap().is_some());
        assert_eq!(index.completed_upload("inner").unwrap(), None);
        assert!(index.completed_upload("kept").unwrap().is_some());
        // A failed outer batch undoes everything in it, nested batches included.
        let outer = index.batch(|index| {
            index.batch(|index| index.record_completed("nested", &done("k4"), 1_000, 0))?;
            Err::<(), _>(failed())
        });
        assert!(outer.is_err());
        assert_eq!(index.completed_upload("nested").unwrap(), None);
        // And the connection is back outside any transaction.
        assert!(index.conn.is_autocommit());
    }

    #[test]
    fn a_commit_that_fails_leaves_no_transaction_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.db");
        let index = Index::open(&path).unwrap();
        // A deferred foreign key fails the commit and, as an I/O error or a full disk
        // can, leaves SQLite's transaction open.
        index
            .conn
            .execute_batch(
                "CREATE TEMP TABLE parent (id INTEGER PRIMARY KEY);
                 CREATE TEMP TABLE child (
                    parent INTEGER REFERENCES parent (id) DEFERRABLE INITIALLY DEFERRED
                 );",
            )
            .unwrap();
        let failed = index.batch(|index| {
            index.conn.execute("INSERT INTO child VALUES (1)", [])?;
            Ok(())
        });
        assert!(failed.is_err());
        assert!(index.conn.is_autocommit());
        // So what follows is committed, not left inside the failed transaction.
        let done = CompletedUpload {
            bucket: "b".into(),
            key: "k".into(),
            result: "{}".into(),
        };
        index
            .batch(|index| index.record_completed("after", &done, 1_000, 0))
            .unwrap();
        let other = Index::open_reader(&path).unwrap();
        assert!(other.completed_upload("after").unwrap().is_some());
    }

    #[test]
    fn completed_uploads_are_remembered_then_expire() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        let done = |key: &str| CompletedUpload {
            bucket: "b".into(),
            key: key.into(),
            result: "{}".into(),
        };
        index
            .record_completed("old", &done("k1"), 1_000, 0)
            .unwrap();
        assert_eq!(index.completed_upload("old").unwrap(), Some(done("k1")));
        assert_eq!(index.completed_upload("other").unwrap(), None);
        // Recording another forgets those older than the cutoff.
        index
            .record_completed("new", &done("k2"), 5_000, 2_000)
            .unwrap();
        assert_eq!(index.completed_upload("old").unwrap(), None);
        assert_eq!(index.completed_upload("new").unwrap(), Some(done("k2")));
    }

    #[test]
    fn uploads_sealed_by_older_key_versions_are_found_and_resealed_once() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        let sealed =
            |version: u32| format!(r#"{{"sealed":{{"kmsKey":"k","kmsVersion":{version}}}}}"#);
        for (id, crypt) in [
            ("old", Some(sealed(1))),
            ("new", Some(sealed(2))),
            ("plain", None),
            (
                "dual",
                Some(
                    r#"{"sealed":{"kmsKey":"j","kmsVersion":1},"outer":{"kmsKey":"k","kmsVersion":1}}"#
                        .to_owned(),
                ),
            ),
        ] {
            index
                .insert_upload(&Upload {
                    id: id.into(),
                    bucket: "b".into(),
                    key: "k".into(),
                    owner: None,
                    attrs: ObjectAttrs::default(),
                    created_ms: 1,
                    crypt,
                    checksum: None,
                    max_size: None,
                })
                .unwrap();
        }
        let ids = |uploads: Vec<Upload>| uploads.into_iter().map(|u| u.id).collect::<Vec<_>>();
        assert_eq!(
            ids(index.uploads_sealed_before("k", 2).unwrap()),
            ["dual", "old"]
        );
        assert_eq!(ids(index.uploads_sealed_before("j", 2).unwrap()), ["dual"]);
        assert!(
            !index
                .replace_upload_crypt("old", &sealed(2), &sealed(3))
                .unwrap()
        );
        assert!(
            index
                .replace_upload_crypt("old", &sealed(1), &sealed(2))
                .unwrap()
        );
        assert_eq!(ids(index.uploads_sealed_before("k", 2).unwrap()), ["dual"]);
        assert_eq!(
            index.get_upload("old").unwrap().unwrap().crypt,
            Some(sealed(2))
        );
    }

    #[test]
    fn an_uploads_cap_and_its_parts_sizes_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        let upload = |id: &str, max_size| Upload {
            id: id.into(),
            bucket: "b".into(),
            key: "k".into(),
            owner: None,
            attrs: ObjectAttrs::default(),
            created_ms: 1,
            crypt: None,
            checksum: None,
            max_size,
        };
        index
            .insert_upload(&upload("capped", Some(u64::MAX)))
            .unwrap();
        index.insert_upload(&upload("open", None)).unwrap();
        let max = |id| index.get_upload(id).unwrap().unwrap().max_size;
        assert_eq!(max("capped"), Some(u64::MAX));
        assert_eq!(max("open"), None);
        assert_eq!(index.parts_size("capped", 0).unwrap(), 0);
        for (number, size) in [(1, 5), (2, 7), (3, 11)] {
            let part = Part {
                number,
                size,
                etag: String::new(),
                checksums: std::collections::BTreeMap::new(),
                modified_ms: 1,
                salt: (number == 2).then(|| "00ff".to_owned()),
            };
            index.put_part("capped", &part).unwrap();
        }
        let salts: Vec<_> = index
            .list_parts("capped", 0, 10)
            .unwrap()
            .into_iter()
            .map(|p| p.salt)
            .collect();
        assert_eq!(salts, [None, Some("00ff".to_owned()), None]);
        assert_eq!(index.parts_size("capped", 0).unwrap(), 23);
        assert_eq!(index.parts_size("capped", 2).unwrap(), 16);
        assert_eq!(index.parts_size("open", 0).unwrap(), 0);
    }
}
