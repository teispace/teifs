//! Object versions in object buckets: one row per version, authoritative. Until a bucket
//! has versioning, each key has one version, `null`. A key's versions are ordered by
//! `seq` (newer is higher); exactly one is `latest` while the key has any.

use rusqlite::{OptionalExtension, Row as SqlRow, params};
use teifs_types::ObjectAttrs;

use crate::{
    Index, Result,
    index::{attrs_from_json, attrs_to_json, from_db, to_db},
};

/// Where a listing starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionsFrom<'a> {
    /// At the first key.
    Start,
    /// After every version of this key.
    AfterKey(&'a str),
    /// After this version of this key (by its `seq`): its older versions follow.
    AfterVersion(&'a str, i64),
    /// After every key that starts with this (a common prefix already listed).
    AfterAll(&'a str),
}

/// The version id of an object written without versioning.
pub const NULL_VERSION: &str = "null";

/// One version of an object in an object bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRow {
    /// The bucket's id.
    pub bucket_id: String,
    /// The object's key.
    pub key: String,
    /// The version id (`null` without versioning).
    pub version_id: String,
    /// Whether this version is a delete marker.
    pub delete_marker: bool,
    /// The data file's id, when the bytes are in a file.
    pub object_id: Option<String>,
    /// The object's size in bytes.
    pub size: u64,
    /// Its ETag, without quotes.
    pub etag: String,
    /// When it was written, in milliseconds since the Unix epoch.
    pub modified_ms: i64,
    /// Its attributes.
    pub attrs: ObjectAttrs,
    /// How it's encrypted (JSON the store owns), if it is.
    pub crypt: Option<String>,
    /// Its parts (JSON the store owns), for multipart objects.
    pub parts: Option<String>,
    /// The bytes themselves, for small objects kept in the index.
    pub inline: Option<Vec<u8>>,
    /// Its place among the key's versions (higher is newer). Read only: a write decides
    /// it.
    pub seq: i64,
    /// Whether it's the key's current version. Read only: a write decides it.
    pub latest: bool,
}

/// The columns a write sets (`seq` and `latest` are decided by the write).
const COLUMNS: &str = "bucket_id, key, version_id, delete_marker, object_id, size, etag, \
                       modified_ms, attrs, crypt, parts, data";
/// The columns [`from_row`] reads.
const READ: &str = "bucket_id, key, version_id, delete_marker, object_id, size, etag, \
                    modified_ms, attrs, crypt, parts, data, seq, latest";
/// The same, without an inline object's bytes: for listings, which describe objects and
/// would otherwise read every listed object's bytes.
const LISTED: &str = "bucket_id, key, version_id, delete_marker, object_id, size, etag, \
                      modified_ms, attrs, crypt, parts, NULL, seq, latest";

fn from_row(r: &SqlRow<'_>) -> rusqlite::Result<VersionRow> {
    let key: Vec<u8> = r.get(1)?;
    Ok(VersionRow {
        bucket_id: r.get(0)?,
        // Keys are written from Rust strings, so they're UTF-8.
        key: String::from_utf8(key).unwrap_or_default(),
        version_id: r.get(2)?,
        delete_marker: r.get(3)?,
        object_id: r.get(4)?,
        size: from_db(r.get(5)?),
        etag: r.get(6)?,
        modified_ms: r.get(7)?,
        attrs: attrs_from_json(&r.get::<_, String>(8)?),
        crypt: r.get(9)?,
        parts: r.get(10)?,
        inline: r.get(11)?,
        seq: r.get(12)?,
        latest: r.get(13)?,
    })
}

/// The smallest byte string greater than every string starting with `prefix`, or `None`
/// when there's none (an empty prefix, or all `0xFF`).
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

impl Index {
    /// The current version of `key`, if it has one (delete markers included).
    pub fn latest_version(&self, bucket_id: &str, key: &str) -> Result<Option<VersionRow>> {
        Ok(self
            .conn
            .prepare_cached(&format!(
                "SELECT {READ} FROM object_versions
                 WHERE bucket_id = ?1 AND key = ?2 AND latest = 1"
            ))?
            .query_row(params![bucket_id, key.as_bytes()], from_row)
            .optional()?)
    }

    /// A version of `key` by its id, delete markers included.
    pub fn version(
        &self,
        bucket_id: &str,
        key: &str,
        version_id: &str,
    ) -> Result<Option<VersionRow>> {
        Ok(self
            .conn
            .prepare_cached(&format!(
                "SELECT {READ} FROM object_versions
                 WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3"
            ))?
            .query_row(params![bucket_id, key.as_bytes(), version_id], from_row)
            .optional()?)
    }

    /// Makes `row` the current version of its key, replacing a version with the same id
    /// (only `null` can be written twice), in one transaction. Data files of replaced
    /// versions are queued as garbage; their ids are returned so the caller can remove
    /// them right away.
    pub fn put_version(&self, row: &VersionRow, now_ms: i64) -> Result<Vec<String>> {
        self.insert_version(row, now_ms, true)
    }

    /// Adds `row` as the newest of its key's versions without making it current (a
    /// folder bucket's current version is its file), replacing a version with the same
    /// id as [`Index::put_version`] does. No version of the key stays current.
    pub fn put_noncurrent(&self, row: &VersionRow, now_ms: i64) -> Result<Vec<String>> {
        self.insert_version(row, now_ms, false)
    }

    fn insert_version(&self, row: &VersionRow, now_ms: i64, latest: bool) -> Result<Vec<String>> {
        let tx = self.begin()?;
        let key = row.key.as_bytes();
        let replaced = files_of(&tx, &row.bucket_id, key, &row.version_id)?;
        tx.execute(
            "DELETE FROM object_versions WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3",
            params![row.bucket_id, key, row.version_id],
        )?;
        tx.execute(
            "UPDATE object_versions SET latest = 0 WHERE bucket_id = ?1 AND key = ?2",
            params![row.bucket_id, key],
        )?;
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM object_versions
             WHERE bucket_id = ?1 AND key = ?2",
            params![row.bucket_id, key],
            |r| r.get(0),
        )?;
        tx.execute(
            &format!(
                "INSERT INTO object_versions ({COLUMNS}, seq, latest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"
            ),
            params![
                row.bucket_id,
                key,
                row.version_id,
                row.delete_marker,
                row.object_id,
                to_db(row.size),
                row.etag,
                row.modified_ms,
                attrs_to_json(&row.attrs),
                row.crypt,
                row.parts,
                row.inline,
                seq,
                latest,
            ],
        )?;
        queue_garbage(&tx, &row.bucket_id, &replaced, now_ms)?;
        tx.commit()?;
        Ok(replaced)
    }

    /// Makes no version of `key` current (its current version is somewhere else: a
    /// folder bucket's file).
    pub fn demote_versions(&self, bucket_id: &str, key: &str) -> Result<()> {
        self.conn
            .prepare_cached(
                "UPDATE object_versions SET latest = 0
                 WHERE bucket_id = ?1 AND key = ?2 AND latest = 1",
            )?
            .execute(params![bucket_id, key.as_bytes()])?;
        Ok(())
    }

    /// The newest version of `key`, current or not, delete markers included.
    pub fn newest_version(&self, bucket_id: &str, key: &str) -> Result<Option<VersionRow>> {
        Ok(self
            .conn
            .prepare_cached(&format!(
                "SELECT {READ} FROM object_versions
                 WHERE bucket_id = ?1 AND key = ?2 ORDER BY seq DESC LIMIT 1"
            ))?
            .query_row(params![bucket_id, key.as_bytes()], from_row)
            .optional()?)
    }

    /// Makes the version `version_id` of `key` its current one, and no other.
    pub fn set_latest(&self, bucket_id: &str, key: &str, version_id: &str) -> Result<()> {
        self.conn
            .prepare_cached(
                "UPDATE object_versions SET latest = (version_id = ?3)
                 WHERE bucket_id = ?1 AND key = ?2",
            )?
            .execute(params![bucket_id, key.as_bytes(), version_id])?;
        Ok(())
    }

    /// Renames the current `null` version of `from` to `to` (same bucket), replacing
    /// `to`'s `null` version, whose data file is queued as garbage (returned). The data
    /// stays where it is: files are named by object id, not key.
    pub fn rename_null_version(
        &self,
        bucket_id: &str,
        from: &str,
        to: &str,
        now_ms: i64,
    ) -> Result<Vec<String>> {
        let tx = self.begin()?;
        let replaced = files_of(&tx, bucket_id, to.as_bytes(), NULL_VERSION)?;
        tx.execute(
            "DELETE FROM object_versions WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3",
            params![bucket_id, to.as_bytes(), NULL_VERSION],
        )?;
        tx.execute(
            "UPDATE object_versions SET latest = 0 WHERE bucket_id = ?1 AND key = ?2",
            params![bucket_id, to.as_bytes()],
        )?;
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM object_versions
             WHERE bucket_id = ?1 AND key = ?2",
            params![bucket_id, to.as_bytes()],
            |r| r.get(0),
        )?;
        let moved = tx.execute(
            "UPDATE object_versions SET key = ?3, seq = ?4, latest = 1
             WHERE bucket_id = ?1 AND key = ?2 AND version_id = 'null'",
            params![bucket_id, from.as_bytes(), to.as_bytes(), seq],
        )?;
        if moved == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows.into());
        }
        queue_garbage(&tx, bucket_id, &replaced, now_ms)?;
        tx.commit()?;
        Ok(replaced)
    }

    /// Removes the `null` version of `key`, queuing its data file as garbage (returned).
    pub fn delete_null_version(
        &self,
        bucket_id: &str,
        key: &str,
        now_ms: i64,
    ) -> Result<Vec<String>> {
        Ok(self
            .delete_version(bucket_id, key, NULL_VERSION, now_ms)?
            .map(|(_, files)| files)
            .unwrap_or_default())
    }

    /// Removes a version of `key` for good, queuing its data file as garbage. When it was
    /// the current version, the newest one left becomes current. The removed version and
    /// its data files, or `None` when there's no such version.
    pub fn delete_version(
        &self,
        bucket_id: &str,
        key: &str,
        version_id: &str,
        now_ms: i64,
    ) -> Result<Option<(VersionRow, Vec<String>)>> {
        let tx = self.begin()?;
        let key = key.as_bytes();
        let removed = tx
            .prepare_cached(&format!(
                "DELETE FROM object_versions
                 WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3
                 RETURNING {READ}"
            ))?
            .query_row(params![bucket_id, key, version_id], from_row)
            .optional()?;
        let Some(removed) = removed else {
            return Ok(None);
        };
        if removed.latest {
            tx.execute(
                "UPDATE object_versions SET latest = 1
                 WHERE bucket_id = ?1 AND key = ?2 AND seq =
                   (SELECT MAX(seq) FROM object_versions WHERE bucket_id = ?1 AND key = ?2)",
                params![bucket_id, key],
            )?;
        }
        let files: Vec<String> = removed.object_id.iter().cloned().collect();
        queue_garbage(&tx, bucket_id, &files, now_ms)?;
        tx.commit()?;
        Ok(Some((removed, files)))
    }

    /// Replaces the attributes of a version of `key`; with `modified_ms`, also when it
    /// was last modified (a copy onto itself does, as in S3; tagging doesn't).
    pub fn set_version_attrs(
        &self,
        bucket_id: &str,
        key: &str,
        version_id: &str,
        attrs: &ObjectAttrs,
        modified_ms: Option<i64>,
    ) -> Result<()> {
        self.conn
            .prepare_cached(
                "UPDATE object_versions SET attrs = ?4, modified_ms = COALESCE(?5, modified_ms)
                 WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3",
            )?
            .execute(params![
                bucket_id,
                key.as_bytes(),
                version_id,
                attrs_to_json(attrs),
                modified_ms
            ])?;
        Ok(())
    }

    /// Replaces a version's encryption record, attributes and parts if its record is
    /// still `old_crypt` (a write since changes it); whether it was.
    pub fn replace_version_crypt(
        &self,
        bucket_id: &str,
        key: &str,
        version_id: &str,
        old_crypt: &str,
        new: (&str, &ObjectAttrs, Option<&str>),
    ) -> Result<bool> {
        let (crypt, attrs, parts) = new;
        let changed = self
            .conn
            .prepare_cached(
                "UPDATE object_versions SET crypt = ?5, attrs = ?6, parts = ?7
                 WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3 AND crypt = ?4",
            )?
            .execute(params![
                bucket_id,
                key.as_bytes(),
                version_id,
                old_crypt,
                crypt,
                attrs_to_json(attrs),
                parts
            ])?;
        Ok(changed == 1)
    }

    /// Versions (of every bucket) whose data key (or DSSE-KMS outer key, `outer`) is
    /// sealed by a version of the KMS key `kms_key` older than `newest`, after `after` (a bucket id, key and `seq`), in that
    /// order; at most `limit`.
    pub fn sealed_before(
        &self,
        kms_key: &str,
        newest: u32,
        after: Option<(&str, &str, i64)>,
        limit: usize,
    ) -> Result<Vec<VersionRow>> {
        let (bucket_id, key, seq) = after.unwrap_or(("", "", i64::MIN));
        let sql = format!(
            "SELECT {LISTED} FROM object_versions
             WHERE crypt IS NOT NULL
               AND ((json_extract(crypt, '$.sealed.kmsKey') = ?1
                     AND json_extract(crypt, '$.sealed.kmsVersion') < ?2)
                 OR (json_extract(crypt, '$.outer.kmsKey') = ?1
                     AND json_extract(crypt, '$.outer.kmsVersion') < ?2))
               AND (bucket_id, key, seq) > (?3, ?4, ?5)
             ORDER BY bucket_id, key, seq LIMIT ?6"
        );
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(
            params![
                kms_key,
                newest,
                bucket_id,
                key.as_bytes(),
                seq,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Forgets every version in a bucket (it's being deleted and has none left that
    /// matter), queuing their data files.
    pub fn forget_bucket_versions(&self, bucket_id: &str, now_ms: i64) -> Result<Vec<String>> {
        let tx = self.begin()?;
        let ids: Vec<String> = {
            let mut stmt = tx.prepare_cached(
                "SELECT object_id FROM object_versions
                 WHERE bucket_id = ?1 AND object_id IS NOT NULL",
            )?;
            stmt.query_map([bucket_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        tx.execute(
            "DELETE FROM object_versions WHERE bucket_id = ?1",
            [bucket_id],
        )?;
        tx.execute(
            "DELETE FROM replicated_deletes WHERE bucket_id = ?1",
            [bucket_id],
        )?;
        tx.execute(
            "DELETE FROM replication_resyncs WHERE bucket_id = ?1",
            [bucket_id],
        )?;
        queue_garbage(&tx, bucket_id, &ids, now_ms)?;
        tx.commit()?;
        Ok(ids)
    }

    /// Current, non-deleted objects whose keys start with `prefix`, after `from`, in key
    /// order, among the next `limit` current versions: delete markers are skipped after
    /// the scan, so a page can come back short, even empty. Also the last key scanned,
    /// `None` when the scan reached the end: callers continue after it.
    pub fn list_latest(
        &self,
        bucket_id: &str,
        prefix: &str,
        from: VersionsFrom<'_>,
        limit: usize,
    ) -> Result<(Vec<VersionRow>, Option<String>)> {
        let prefix = prefix.as_bytes();
        // Past any version of a key is past its current one.
        let from = match from {
            VersionsFrom::AfterVersion(key, _) => VersionsFrom::AfterKey(key),
            other => other,
        };
        let Some((start, inclusive)) = lower_bound(prefix, from) else {
            return Ok((Vec::new(), None));
        };
        let end = prefix_end(prefix);
        // Plain range bounds, so SQLite walks the partial index in order.
        let sql = format!(
            "SELECT {LISTED} FROM object_versions
             WHERE bucket_id = ?1 AND latest = 1 AND key {} ?2 {}
             ORDER BY key LIMIT ?4",
            if inclusive { ">=" } else { ">" },
            if end.is_some() {
                "AND key < ?3"
            } else {
                "AND ?3 IS NULL"
            },
        );
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows: Vec<VersionRow> = stmt
            .query_map(
                params![
                    bucket_id,
                    start,
                    end,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                from_row,
            )?
            .collect::<rusqlite::Result<_>>()?;
        let last = (rows.len() == limit)
            .then(|| rows.last().map(|r| r.key.clone()))
            .flatten();
        Ok((
            rows.into_iter().filter(|v| !v.delete_marker).collect(),
            last,
        ))
    }

    /// Every version whose key starts with `prefix`, delete markers included, from
    /// `from` on: keys in byte order, each key's versions newest first; at most `limit`.
    pub fn list_versions(
        &self,
        bucket_id: &str,
        prefix: &str,
        from: VersionsFrom<'_>,
        limit: usize,
    ) -> Result<Vec<VersionRow>> {
        let prefix = prefix.as_bytes();
        let Some((start, inclusive)) = lower_bound(prefix, from) else {
            return Ok(Vec::new());
        };
        let end = prefix_end(prefix);
        // Past a version of the lower bound's key: only its older versions.
        let before_seq = match from {
            VersionsFrom::AfterVersion(key, seq) if key.as_bytes() == start.as_slice() => Some(seq),
            _ => None,
        };
        let sql = format!(
            "SELECT {LISTED} FROM object_versions
             WHERE bucket_id = ?1 AND key {} ?2 {} {}
             ORDER BY key, seq DESC LIMIT ?5",
            if inclusive { ">=" } else { ">" },
            if end.is_some() {
                "AND key < ?3"
            } else {
                "AND ?3 IS NULL"
            },
            if before_seq.is_some() {
                "AND (key > ?2 OR seq < ?4)"
            } else {
                "AND ?4 IS NULL"
            },
        );
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(
            params![
                bucket_id,
                start,
                end,
                before_seq,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Whether a bucket has any object version left.
    pub fn bucket_has_versions(&self, bucket_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("SELECT 1 FROM object_versions WHERE bucket_id = ?1 LIMIT 1")?
            .query_row([bucket_id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// Whether some version still uses the data file `object_id`.
    pub fn object_in_use(&self, object_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("SELECT 1 FROM object_versions WHERE object_id = ?1 LIMIT 1")?
            .query_row([object_id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// Whether some version of the bucket `bucket_id` uses the data file `object_id`.
    pub fn bucket_uses_object(&self, bucket_id: &str, object_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT 1 FROM object_versions WHERE object_id = ?1 AND bucket_id = ?2 LIMIT 1",
            )?
            .query_row([object_id, bucket_id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// Whether the data file `object_id` is queued to be removed.
    pub fn is_garbage(&self, object_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("SELECT 1 FROM garbage WHERE object_id = ?1")?
            .query_row([object_id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// A page of a bucket's versions that have a data file, in key and `seq` order, after
    /// `after` (a key and a `seq`).
    pub fn versions_with_files(
        &self,
        bucket_id: &str,
        after: Option<(&str, i64)>,
        limit: usize,
    ) -> Result<Vec<VersionRow>> {
        let (key, seq) = after.map_or((&[][..], i64::MIN), |(k, s)| (k.as_bytes(), s));
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT {READ} FROM object_versions
             WHERE bucket_id = ?1 AND object_id IS NOT NULL AND (key, seq) > (?2, ?3)
             ORDER BY key, seq LIMIT ?4"
        ))?;
        let rows = stmt.query_map(
            params![
                bucket_id,
                key,
                seq,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Adds `row`, a version found without a row of its own, among its key's versions by
    /// when it was written (`modified_ms`); with `current`, the newest of them becomes
    /// the current one. Nothing is replaced: `false` when the key already has a version
    /// with its id.
    pub fn adopt_version(&self, row: &VersionRow, current: bool) -> Result<bool> {
        let tx = self.begin()?;
        let key = row.key.as_bytes();
        let taken = tx
            .prepare_cached(
                "SELECT 1 FROM object_versions
                 WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3",
            )?
            .query_row(params![row.bucket_id, key, row.version_id], |_| Ok(()))
            .optional()?
            .is_some();
        if taken {
            return Ok(false);
        }
        // Its place: before the first version written after it.
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(
                (SELECT MIN(seq) FROM object_versions
                 WHERE bucket_id = ?1 AND key = ?2 AND modified_ms > ?3),
                (SELECT COALESCE(MAX(seq), 0) + 1 FROM object_versions
                 WHERE bucket_id = ?1 AND key = ?2))",
            params![row.bucket_id, key, row.modified_ms],
            |r| r.get(0),
        )?;
        // Those after it move up one, through negative numbers so no two ever meet.
        tx.execute(
            "UPDATE object_versions SET seq = -(seq + 1)
             WHERE bucket_id = ?1 AND key = ?2 AND seq >= ?3",
            params![row.bucket_id, key, seq],
        )?;
        tx.execute(
            "UPDATE object_versions SET seq = -seq WHERE bucket_id = ?1 AND key = ?2 AND seq < 0",
            params![row.bucket_id, key],
        )?;
        tx.execute(
            &format!(
                "INSERT INTO object_versions ({COLUMNS}, seq, latest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0)"
            ),
            params![
                row.bucket_id,
                key,
                row.version_id,
                row.delete_marker,
                row.object_id,
                to_db(row.size),
                row.etag,
                row.modified_ms,
                attrs_to_json(&row.attrs),
                row.crypt,
                row.parts,
                row.inline,
                seq,
            ],
        )?;
        if current {
            tx.execute(
                "UPDATE object_versions SET latest = (seq =
                   (SELECT MAX(seq) FROM object_versions WHERE bucket_id = ?1 AND key = ?2))
                 WHERE bucket_id = ?1 AND key = ?2",
                params![row.bucket_id, key],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Data files waiting to be removed: `(bucket id, object id)`, oldest first.
    pub fn garbage(&self, limit: usize) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT bucket_id, object_id FROM garbage ORDER BY queued_ms LIMIT ?1",
        )?;
        let rows = stmt.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Forgets a garbage entry once its file is gone.
    pub fn drop_garbage(&self, object_id: &str) -> Result<()> {
        self.conn
            .prepare_cached("DELETE FROM garbage WHERE object_id = ?1")?
            .execute([object_id])?;
        Ok(())
    }
}

/// Where a listing's keys start (inclusive or not) within `prefix`, or `None` when no
/// key can follow.
fn lower_bound(prefix: &[u8], from: VersionsFrom<'_>) -> Option<(Vec<u8>, bool)> {
    Some(match from {
        VersionsFrom::AfterKey(key) if key.as_bytes() >= prefix => (key.as_bytes().to_vec(), false),
        VersionsFrom::AfterVersion(key, _) if key.as_bytes() >= prefix => {
            (key.as_bytes().to_vec(), true)
        }
        VersionsFrom::Start | VersionsFrom::AfterKey(_) | VersionsFrom::AfterVersion(..) => {
            (prefix.to_vec(), true)
        }
        VersionsFrom::AfterAll(common) => match prefix_end(common.as_bytes()) {
            None => return None,
            Some(end) if end.as_slice() >= prefix => (end, true),
            Some(_) => (prefix.to_vec(), true),
        },
    })
}

/// The data file of a version of `key`, if it has one.
fn files_of(
    tx: &rusqlite::Connection,
    bucket_id: &str,
    key: &[u8],
    version_id: &str,
) -> Result<Vec<String>> {
    let mut stmt = tx.prepare_cached(
        "SELECT object_id FROM object_versions
         WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3 AND object_id IS NOT NULL",
    )?;
    let ids = stmt.query_map(params![bucket_id, key, version_id], |r| r.get(0))?;
    Ok(ids.collect::<rusqlite::Result<_>>()?)
}

fn queue_garbage(
    tx: &rusqlite::Connection,
    bucket_id: &str,
    object_ids: &[String],
    now_ms: i64,
) -> Result<()> {
    let mut stmt = tx.prepare_cached(
        "INSERT OR IGNORE INTO garbage (object_id, bucket_id, queued_ms) VALUES (?1, ?2, ?3)",
    )?;
    for id in object_ids {
        stmt.execute(params![id, bucket_id, now_ms])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> (tempfile::TempDir, Index) {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        (dir, index)
    }

    fn row(key: &str, object_id: &str) -> VersionRow {
        VersionRow {
            bucket_id: "b1".into(),
            key: key.into(),
            version_id: NULL_VERSION.into(),
            delete_marker: false,
            object_id: Some(object_id.into()),
            size: 3,
            etag: "e".into(),
            modified_ms: 1,
            attrs: ObjectAttrs::default(),
            crypt: None,
            parts: None,
            inline: None,
            seq: 0,
            latest: false,
        }
    }

    fn written(key: &str, id: &str, at: i64) -> VersionRow {
        VersionRow {
            version_id: id.into(),
            modified_ms: at,
            ..row(key, &format!("o-{id}"))
        }
    }

    /// `key`'s versions, oldest first, with the current one marked.
    fn order(index: &Index, key: &str) -> Vec<String> {
        let mut rows = index.versions_with_files("b1", None, 100).unwrap();
        rows.retain(|r| r.key == key);
        rows.iter()
            .map(|r| format!("{}{}", r.version_id, if r.latest { "*" } else { "" }))
            .collect()
    }

    #[test]
    fn listings_leave_out_inline_bytes_and_lookups_keep_them() {
        let (_dir, index) = index();
        let inline = VersionRow {
            object_id: None,
            inline: Some(b"abc".to_vec()),
            ..row("k", "unused")
        };
        index.put_version(&inline, 1).unwrap();
        let (listed, _) = index
            .list_latest("b1", "", VersionsFrom::Start, 10)
            .unwrap();
        assert_eq!(listed[0].inline, None);
        let versions = index
            .list_versions("b1", "", VersionsFrom::Start, 10)
            .unwrap();
        assert_eq!(versions[0].inline, None);
        let found = index.latest_version("b1", "k").unwrap().unwrap();
        assert_eq!(found.inline.as_deref(), Some(&b"abc"[..]));
        let found = index.version("b1", "k", NULL_VERSION).unwrap().unwrap();
        assert_eq!(found.inline.as_deref(), Some(&b"abc"[..]));
    }

    #[test]
    fn adopted_versions_take_their_place_by_time() {
        let (_dir, index) = index();
        index.put_version(&written("k", "v1", 10), 10).unwrap();
        index.put_version(&written("k", "v3", 30), 30).unwrap();
        assert!(index.adopt_version(&written("k", "v2", 20), true).unwrap());
        assert_eq!(order(&index, "k"), ["v1", "v2", "v3*"]);
        assert!(index.adopt_version(&written("k", "v0", 5), true).unwrap());
        assert!(index.adopt_version(&written("k", "v4", 40), true).unwrap());
        assert_eq!(order(&index, "k"), ["v0", "v1", "v2", "v3", "v4*"]);
        // A version id already there is left alone.
        assert!(!index.adopt_version(&written("k", "v2", 99), true).unwrap());
        assert_eq!(order(&index, "k"), ["v0", "v1", "v2", "v3", "v4*"]);
        // Not made current where the current version lives elsewhere (a folder).
        assert!(index.adopt_version(&written("f", "old", 1), false).unwrap());
        assert_eq!(order(&index, "f"), ["old"]);
        // Paged by key and position.
        let first = index.versions_with_files("b1", None, 2).unwrap();
        let next = index
            .versions_with_files("b1", Some((&first[1].key, first[1].seq)), 100)
            .unwrap();
        assert_eq!(first.len() + next.len(), 6);
        assert_eq!(
            (first[0].key.as_str(), next[0].version_id.as_str()),
            ("f", "v1")
        );
        assert!(!index.is_garbage("o-v1").unwrap());
        assert!(index.bucket_uses_object("b1", "o-v1").unwrap());
        assert!(!index.bucket_uses_object("b2", "o-v1").unwrap());
        assert!(!index.bucket_uses_object("b1", "o-v9").unwrap());
    }

    #[test]
    fn replacing_a_version_queues_the_old_file() {
        let (_dir, index) = index();
        assert!(index.put_version(&row("a", "o1"), 1).unwrap().is_empty());
        assert_eq!(index.put_version(&row("a", "o2"), 2).unwrap(), ["o1"]);
        let latest = index.latest_version("b1", "a").unwrap().unwrap();
        assert_eq!(latest.object_id.as_deref(), Some("o2"));
        assert_eq!(
            index.garbage(10).unwrap(),
            [("b1".to_owned(), "o1".to_owned())]
        );
        assert!(!index.object_in_use("o1").unwrap());
        index.drop_garbage("o1").unwrap();
        assert!(index.garbage(10).unwrap().is_empty());

        index.put_version(&row("b", "o3"), 3).unwrap();
        assert_eq!(
            index.rename_null_version("b1", "a", "b", 4).unwrap(),
            ["o3"]
        );
        assert!(index.latest_version("b1", "a").unwrap().is_none());
        let renamed = index.latest_version("b1", "b").unwrap().unwrap();
        assert_eq!(renamed.object_id.as_deref(), Some("o2"));
        assert!(index.rename_null_version("b1", "missing", "c", 5).is_err());
        assert_eq!(index.delete_null_version("b1", "b", 3).unwrap(), ["o2"]);
        assert!(index.latest_version("b1", "b").unwrap().is_none());
        index.drop_garbage("o3").unwrap();
        assert!(!index.bucket_has_versions("b1").unwrap());
    }

    #[test]
    fn encryption_is_replaced_only_if_unchanged() {
        let (_dir, index) = index();
        let sealed = VersionRow {
            crypt: Some("old".into()),
            ..row("a", "o1")
        };
        index.put_version(&sealed, 1).unwrap();
        let attrs = ObjectAttrs {
            content_type: Some("text/plain".into()),
            ..ObjectAttrs::default()
        };
        let new = ("new", &attrs, Some("[]"));
        assert!(
            !index
                .replace_version_crypt("b1", "a", NULL_VERSION, "other", new)
                .unwrap()
        );
        assert!(
            index
                .replace_version_crypt("b1", "a", NULL_VERSION, "old", new)
                .unwrap()
        );
        let got = index.latest_version("b1", "a").unwrap().unwrap();
        assert_eq!(
            (
                got.crypt.as_deref(),
                got.parts.as_deref(),
                got.attrs.content_type.as_deref()
            ),
            (Some("new"), Some("[]"), Some("text/plain"))
        );
        // Done once: the old record is gone.
        assert!(
            !index
                .replace_version_crypt("b1", "a", NULL_VERSION, "old", new)
                .unwrap()
        );
    }

    #[test]
    fn versions_sealed_by_older_key_versions_are_found_in_pages() {
        let (_dir, index) = index();
        let sealed = |key: &str, version: u32| {
            Some(format!(
                r#"{{"mode":"s3","sealed":{{"kmsKey":"{key}","kmsVersion":{version}}}}}"#
            ))
        };
        for (name, crypt) in [
            ("a", sealed("k", 1)),
            ("b", sealed("k", 2)),
            ("c", sealed("k", 1)),
            ("d", sealed("other", 1)),
            ("e", None),
            // DSSE-KMS: found by its outer key's seal too.
            (
                "f",
                Some(
                    r#"{"mode":"dsse","sealed":{"kmsKey":"other","kmsVersion":1},"outer":{"kmsKey":"k","kmsVersion":1}}"#
                        .to_owned(),
                ),
            ),
        ] {
            index
                .put_version(
                    &VersionRow {
                        crypt,
                        ..row(name, name)
                    },
                    1,
                )
                .unwrap();
        }
        let keys = |rows: Vec<VersionRow>| rows.into_iter().map(|r| r.key).collect::<Vec<_>>();
        assert_eq!(
            keys(index.sealed_before("k", 2, None, 10).unwrap()),
            ["a", "c", "f"]
        );
        assert_eq!(
            keys(index.sealed_before("k", 3, None, 10).unwrap()),
            ["a", "b", "c", "f"]
        );
        let first = index.sealed_before("k", 2, None, 1).unwrap();
        assert_eq!(keys(first.clone()), ["a"]);
        let after = (
            first[0].bucket_id.as_str(),
            first[0].key.as_str(),
            first[0].seq,
        );
        assert_eq!(
            keys(index.sealed_before("k", 2, Some(after), 10).unwrap()),
            ["c", "f"]
        );
        assert_eq!(
            keys(index.sealed_before("other", 2, None, 10).unwrap()),
            ["d", "f"]
        );
        assert!(index.sealed_before("k", 1, None, 10).unwrap().is_empty());
    }

    #[test]
    fn lists_in_byte_order_within_a_prefix() {
        use VersionsFrom::{AfterAll, AfterKey, Start};
        let (_dir, index) = index();
        for (i, key) in ["a", "a/b", "a/c", "a0", "b", "é", "a/", "a//x"]
            .iter()
            .enumerate()
        {
            index.put_version(&row(key, &format!("o{i}")), 1).unwrap();
        }
        let keys = |prefix: &str, from: VersionsFrom<'_>, limit| {
            index
                .list_latest("b1", prefix, from, limit)
                .unwrap()
                .0
                .into_iter()
                .map(|r| r.key)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            keys("", Start, 100),
            ["a", "a/", "a//x", "a/b", "a/c", "a0", "b", "é"]
        );
        assert_eq!(keys("a/", Start, 100), ["a/", "a//x", "a/b", "a/c"]);
        assert_eq!(keys("a/", AfterKey("a//x"), 100), ["a/b", "a/c"]);
        assert_eq!(keys("", AfterKey("a0"), 1), ["b"]);
        // A marker before the prefix starts at the prefix.
        assert_eq!(keys("b", AfterKey("a"), 100), ["b"]);
        assert_eq!(keys("zz", Start, 100), Vec::<String>::new());
        // Skipping everything under a common prefix.
        assert_eq!(keys("", AfterAll("a/"), 100), ["a0", "b", "é"]);
        assert_eq!(keys("a", AfterAll("a/"), 100), ["a0"]);
    }

    fn version(key: &str, version_id: &str, object_id: Option<&str>) -> VersionRow {
        VersionRow {
            version_id: version_id.into(),
            delete_marker: object_id.is_none(),
            object_id: object_id.map(Into::into),
            ..row(key, "")
        }
    }

    /// `(version id, latest)` of every version of `key`, newest first.
    fn stack(index: &Index, key: &str) -> Vec<(String, bool)> {
        index
            .list_versions("b1", key, VersionsFrom::Start, 100)
            .unwrap()
            .into_iter()
            .filter(|r| r.key == key)
            .map(|r| (r.version_id, r.latest))
            .collect()
    }

    #[test]
    fn versions_stack_and_the_newest_left_is_current() {
        let (_dir, index) = index();
        let owned = |v: &[(&str, bool)]| {
            v.iter()
                .map(|(id, latest)| ((*id).to_owned(), *latest))
                .collect::<Vec<_>>()
        };
        index
            .put_version(&version("k", NULL_VERSION, Some("o0")), 1)
            .unwrap();
        index
            .put_version(&version("k", "v1", Some("o1")), 2)
            .unwrap();
        index
            .put_version(&version("k", "v2", Some("o2")), 3)
            .unwrap();
        // Markers stack like versions.
        index.put_version(&version("k", "m1", None), 4).unwrap();
        index.put_version(&version("k", "m2", None), 5).unwrap();
        assert_eq!(
            stack(&index, "k"),
            owned(&[
                ("m2", true),
                ("m1", false),
                ("v2", false),
                ("v1", false),
                ("null", false)
            ])
        );
        assert!(
            index
                .latest_version("b1", "k")
                .unwrap()
                .unwrap()
                .delete_marker
        );
        let v1 = index.version("b1", "k", "v1").unwrap().unwrap();
        assert_eq!((v1.object_id.as_deref(), v1.latest), (Some("o1"), false));
        assert!(index.version("b1", "k", "v9").unwrap().is_none());

        // Removing the current version makes the newest left current.
        let (removed, files) = index.delete_version("b1", "k", "m2", 6).unwrap().unwrap();
        assert!(removed.delete_marker && removed.latest && files.is_empty());
        let (removed, files) = index.delete_version("b1", "k", "m1", 7).unwrap().unwrap();
        assert!(removed.delete_marker && files.is_empty());
        assert_eq!(
            index.latest_version("b1", "k").unwrap().unwrap().version_id,
            "v2"
        );
        // Removing an older one leaves the current one.
        assert_eq!(
            index.delete_version("b1", "k", "v1", 8).unwrap().unwrap().1,
            ["o1"]
        );
        assert_eq!(stack(&index, "k"), owned(&[("v2", true), ("null", false)]));
        assert!(index.delete_version("b1", "k", "v1", 9).unwrap().is_none());

        // A new `null` version replaces the old one, wherever it is, and is current.
        let replaced = index
            .put_version(&version("k", NULL_VERSION, Some("o3")), 10)
            .unwrap();
        assert_eq!(replaced, ["o0"]);
        assert_eq!(stack(&index, "k"), owned(&[("null", true), ("v2", false)]));
        // Suspended deletes: the `null` version becomes a marker.
        let replaced = index
            .put_version(&version("k", NULL_VERSION, None), 11)
            .unwrap();
        assert_eq!(replaced, ["o3"]);
        assert_eq!(stack(&index, "k"), owned(&[("null", true), ("v2", false)]));
        assert!(
            index
                .latest_version("b1", "k")
                .unwrap()
                .unwrap()
                .delete_marker
        );
        index
            .delete_version("b1", "k", "null", 12)
            .unwrap()
            .unwrap();
        index.delete_version("b1", "k", "v2", 13).unwrap().unwrap();
        assert!(index.latest_version("b1", "k").unwrap().is_none());
        assert!(!index.bucket_has_versions("b1").unwrap());
    }

    #[test]
    fn a_folder_buckets_versions_can_all_be_noncurrent() {
        let (_dir, index) = index();
        index.put_version(&version("k", "m1", None), 1).unwrap();
        index
            .put_noncurrent(&version("k", "v1", Some("o1")), 2)
            .unwrap();
        // The newest is noncurrent, and so is every other.
        assert!(index.latest_version("b1", "k").unwrap().is_none());
        let newest = index.newest_version("b1", "k").unwrap().unwrap();
        assert_eq!((newest.version_id.as_str(), newest.latest), ("v1", false));
        index.set_latest("b1", "k", "m1").unwrap();
        assert_eq!(
            index.latest_version("b1", "k").unwrap().unwrap().version_id,
            "m1"
        );
        index.demote_versions("b1", "k").unwrap();
        assert!(index.latest_version("b1", "k").unwrap().is_none());
        assert!(index.newest_version("b1", "nothing").unwrap().is_none());
    }

    #[test]
    fn versions_list_newest_first_and_resume_anywhere() {
        use VersionsFrom::{AfterAll, AfterKey, AfterVersion, Start};
        let (_dir, index) = index();
        for (key, id) in [
            ("a", "a1"),
            ("a", "a2"),
            ("b/x", "x1"),
            ("b/y", "y1"),
            ("c", "c1"),
        ] {
            index.put_version(&version(key, id, Some(id)), 1).unwrap();
        }
        index.put_version(&version("a", "a3", None), 2).unwrap();
        let ids = |prefix: &str, from, limit| {
            index
                .list_versions("b1", prefix, from, limit)
                .unwrap()
                .into_iter()
                .map(|r| r.version_id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids("", Start, 100), ["a3", "a2", "a1", "x1", "y1", "c1"]);
        assert_eq!(ids("", Start, 2), ["a3", "a2"]);
        let a2 = index.version("b1", "a", "a2").unwrap().unwrap().seq;
        assert_eq!(
            ids("", AfterVersion("a", a2), 100),
            ["a1", "x1", "y1", "c1"]
        );
        assert_eq!(ids("", AfterKey("a"), 100), ["x1", "y1", "c1"]);
        assert_eq!(ids("", AfterAll("b/"), 100), ["c1"]);
        assert_eq!(ids("b/", Start, 100), ["x1", "y1"]);
        // A marker before the prefix starts at the prefix.
        assert_eq!(ids("b/", AfterVersion("a", a2), 100), ["x1", "y1"]);
        assert_eq!(ids("b/", AfterKey("b/x"), 100), ["y1"]);
    }

    #[test]
    fn a_page_of_delete_markers_says_where_to_go_on() {
        let (_dir, index) = index();
        for key in ["a", "b", "c"] {
            index.put_version(&version(key, "m", None), 1).unwrap();
        }
        index.put_version(&version("d", "v", Some("o")), 1).unwrap();
        let (rows, last) = index.list_latest("b1", "", VersionsFrom::Start, 2).unwrap();
        assert!(rows.is_empty());
        assert_eq!(last.as_deref(), Some("b"));
        let (rows, last) = index
            .list_latest("b1", "", VersionsFrom::AfterKey("b"), 2)
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(),
            ["d"]
        );
        assert_eq!(last.as_deref(), Some("d"));
        let (rows, last) = index
            .list_latest("b1", "", VersionsFrom::AfterKey("d"), 2)
            .unwrap();
        assert!(rows.is_empty() && last.is_none());
    }

    #[test]
    fn prefix_ends() {
        assert_eq!(prefix_end(b"a/"), Some(b"a0".to_vec()));
        assert_eq!(prefix_end(b""), None);
        assert_eq!(prefix_end(&[b'a', 0xFF]), Some(b"b".to_vec()));
        assert_eq!(prefix_end(&[0xFF]), None);
    }
}
