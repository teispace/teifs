//! Object versions in object buckets: one row per version, authoritative. Until a bucket
//! has versioning, each key has one version, `null`.

use rusqlite::{OptionalExtension, Row as SqlRow, params};
use teifs_types::ObjectAttrs;

use crate::{
    Index, Result,
    index::{attrs_from_json, attrs_to_json, from_db, to_db},
};

/// Where a listing starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFrom<'a> {
    /// At the first key.
    Start,
    /// After this key.
    AfterKey(&'a str),
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
}

const COLUMNS: &str = "bucket_id, key, version_id, delete_marker, object_id, size, etag, \
                       modified_ms, attrs, crypt, parts, data";

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
                "SELECT {COLUMNS} FROM object_versions
                 WHERE bucket_id = ?1 AND key = ?2 AND latest = 1"
            ))?
            .query_row(params![bucket_id, key.as_bytes()], from_row)
            .optional()?)
    }

    /// Makes `row` the `null` version of its key, replacing any `null` version, in one
    /// transaction. Data files of replaced versions are queued as garbage; their ids are
    /// returned so the caller can remove them right away.
    pub fn put_null_version(&self, row: &VersionRow, now_ms: i64) -> Result<Vec<String>> {
        let tx = self.conn.unchecked_transaction()?;
        let key = row.key.as_bytes();
        let replaced = replaced_files(&tx, &row.bucket_id, key)?;
        tx.execute(
            "DELETE FROM object_versions WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3",
            params![row.bucket_id, key, NULL_VERSION],
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
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1)"
            ),
            params![
                row.bucket_id,
                key,
                NULL_VERSION,
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
        queue_garbage(&tx, &row.bucket_id, &replaced, now_ms)?;
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
        let tx = self.conn.unchecked_transaction()?;
        let replaced = replaced_files(&tx, bucket_id, key.as_bytes())?;
        tx.execute(
            "DELETE FROM object_versions WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3",
            params![bucket_id, key.as_bytes(), NULL_VERSION],
        )?;
        queue_garbage(&tx, bucket_id, &replaced, now_ms)?;
        tx.commit()?;
        Ok(replaced)
    }

    /// Replaces the attributes of the current version of `key` and marks it modified now
    /// (a copy onto itself, as S3 does).
    pub fn set_version_attrs(
        &self,
        bucket_id: &str,
        key: &str,
        attrs: &ObjectAttrs,
        now_ms: i64,
    ) -> Result<()> {
        self.conn
            .prepare_cached(
                "UPDATE object_versions SET attrs = ?3, modified_ms = ?4
                 WHERE bucket_id = ?1 AND key = ?2 AND latest = 1",
            )?
            .execute(params![
                bucket_id,
                key.as_bytes(),
                attrs_to_json(attrs),
                now_ms
            ])?;
        Ok(())
    }

    /// Forgets every version in a bucket (it's being deleted and has none left that
    /// matter), queuing their data files.
    pub fn forget_bucket_versions(&self, bucket_id: &str, now_ms: i64) -> Result<Vec<String>> {
        let tx = self.conn.unchecked_transaction()?;
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
        queue_garbage(&tx, bucket_id, &ids, now_ms)?;
        tx.commit()?;
        Ok(ids)
    }

    /// Current, non-deleted objects whose keys start with `prefix`, from `from` on, in key
    /// order, at most `limit`. Delete markers are skipped after the scan, so a page can
    /// come back short; callers continue from the last key they saw.
    pub fn list_latest(
        &self,
        bucket_id: &str,
        prefix: &str,
        from: ListFrom<'_>,
        limit: usize,
    ) -> Result<Vec<VersionRow>> {
        let prefix = prefix.as_bytes();
        // The lower bound, and whether it's included.
        let (start, inclusive): (Vec<u8>, bool) = match from {
            ListFrom::AfterKey(key) if key.as_bytes() >= prefix => (key.as_bytes().to_vec(), false),
            ListFrom::Start | ListFrom::AfterKey(_) => (prefix.to_vec(), true),
            ListFrom::AfterAll(common) => match prefix_end(common.as_bytes()) {
                None => return Ok(Vec::new()),
                Some(end) if end.as_slice() >= prefix => (end, true),
                Some(_) => (prefix.to_vec(), true),
            },
        };
        let end = prefix_end(prefix);
        // Plain range bounds, so SQLite walks the partial index in order.
        let sql = format!(
            "SELECT {COLUMNS} FROM object_versions
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
        let rows = stmt.query_map(
            params![
                bucket_id,
                start,
                end,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            from_row,
        )?;
        Ok(rows
            .filter(|r| r.as_ref().map_or(true, |v| !v.delete_marker))
            .collect::<rusqlite::Result<_>>()?)
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

/// The data files of `key`'s `null` versions.
fn replaced_files(
    tx: &rusqlite::Transaction<'_>,
    bucket_id: &str,
    key: &[u8],
) -> Result<Vec<String>> {
    let mut stmt = tx.prepare_cached(
        "SELECT object_id FROM object_versions
         WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3 AND object_id IS NOT NULL",
    )?;
    let ids = stmt.query_map(params![bucket_id, key, NULL_VERSION], |r| r.get(0))?;
    Ok(ids.collect::<rusqlite::Result<_>>()?)
}

fn queue_garbage(
    tx: &rusqlite::Transaction<'_>,
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
        }
    }

    #[test]
    fn replacing_a_version_queues_the_old_file() {
        let (_dir, index) = index();
        assert!(
            index
                .put_null_version(&row("a", "o1"), 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(index.put_null_version(&row("a", "o2"), 2).unwrap(), ["o1"]);
        let latest = index.latest_version("b1", "a").unwrap().unwrap();
        assert_eq!(latest.object_id.as_deref(), Some("o2"));
        assert_eq!(
            index.garbage(10).unwrap(),
            [("b1".to_owned(), "o1".to_owned())]
        );
        assert!(!index.object_in_use("o1").unwrap());
        index.drop_garbage("o1").unwrap();
        assert!(index.garbage(10).unwrap().is_empty());

        assert_eq!(index.delete_null_version("b1", "a", 3).unwrap(), ["o2"]);
        assert!(index.latest_version("b1", "a").unwrap().is_none());
        assert!(!index.bucket_has_versions("b1").unwrap());
    }

    #[test]
    fn lists_in_byte_order_within_a_prefix() {
        use ListFrom::{AfterAll, AfterKey, Start};
        let (_dir, index) = index();
        for (i, key) in ["a", "a/b", "a/c", "a0", "b", "é", "a/", "a//x"]
            .iter()
            .enumerate()
        {
            index
                .put_null_version(&row(key, &format!("o{i}")), 1)
                .unwrap();
        }
        let keys = |prefix: &str, from: ListFrom<'_>, limit| {
            index
                .list_latest("b1", prefix, from, limit)
                .unwrap()
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

    #[test]
    fn prefix_ends() {
        assert_eq!(prefix_end(b"a/"), Some(b"a0".to_vec()));
        assert_eq!(prefix_end(b""), None);
        assert_eq!(prefix_end(&[b'a', 0xFF]), Some(b"b".to_vec()));
        assert_eq!(prefix_end(&[0xFF]), None);
    }
}
