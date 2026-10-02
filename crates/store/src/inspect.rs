//! What the store keeps about objects, as it keeps it, for `MinIO`'s `inspect-data`
//! (`mc support inspect`): each key's index rows, the way `MinIO` hands over a drive's
//! `xl.meta`. Small objects' bytes kept in the index are left out, only their length
//! said: the records describe objects, they don't copy them.

use serde_json::{Value, json};
use teifs_meta::{Index, Row, VersionRow, VersionsFrom};

use crate::{Bucket, Inner, Store, error::Result, format, objects::ObjectBucket};

/// The most versions read for one key.
const MAX_VERSIONS: usize = 10_000;

impl Store {
    /// The records of `key` in `bucket`: for an object bucket its versions' rows, for a
    /// folder bucket its file's row and its older versions' rows. `None` when there are
    /// none.
    ///
    /// # Errors
    ///
    /// A bucket that doesn't exist, or the index failing.
    pub async fn inspect_records(&self, bucket: &str, key: &str) -> Result<Option<Value>> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        self.blocking(move |inner| records(inner, &bucket, &key))
            .await
    }

    /// The drive's `format.json`, as written.
    ///
    /// # Errors
    ///
    /// The file can't be read.
    pub fn format_file(&self) -> Result<Vec<u8>> {
        Ok(std::fs::read(
            self.inner.system_dir().join(format::FORMAT_FILE),
        )?)
    }
}

fn records(inner: &Inner, bucket: &str, key: &str) -> Result<Option<Value>> {
    let conn = inner.lock();
    let (layout, row, versions) = match inner.bucket(bucket)? {
        Bucket::Object(store) => ("object", None, versions(&conn, Some(&store), key)?),
        Bucket::Folder(folder) => {
            let row = conn.get(&folder.name, key)?;
            (
                "folder",
                row,
                versions(&conn, folder.versions.as_ref(), key)?,
            )
        }
    };
    if row.is_none() && versions.is_empty() {
        return Ok(None);
    }
    Ok(Some(json!({
        "bucket": bucket,
        "key": key,
        "layout": layout,
        "file": row.as_ref().map(file_json),
        "versions": versions.iter().map(version_json).collect::<Vec<_>>(),
    })))
}

/// The versions of exactly `key` in a version store, newest first.
fn versions(conn: &Index, store: Option<&ObjectBucket>, key: &str) -> Result<Vec<VersionRow>> {
    let Some(store) = store else {
        return Ok(Vec::new());
    };
    let mut rows = conn.list_versions(&store.id, key, VersionsFrom::Start, MAX_VERSIONS)?;
    rows.retain(|r| r.key == key);
    Ok(rows)
}

fn file_json(row: &Row) -> Value {
    json!({
        "size": row.stamp.size,
        "mtime_ns": row.stamp.mtime_ns,
        "ino": row.stamp.ino,
        "etag": row.etag,
        "attrs": row.attrs,
        "parts": stored_json(row.parts.as_deref()),
        "version_id": row.version_id,
    })
}

fn version_json(row: &VersionRow) -> Value {
    json!({
        "bucket_id": row.bucket_id,
        "version_id": row.version_id,
        "delete_marker": row.delete_marker,
        "object_id": row.object_id,
        "size": row.size,
        "etag": row.etag,
        "modified_ms": row.modified_ms,
        "attrs": row.attrs,
        "crypt": stored_json(row.crypt.as_deref()),
        "parts": stored_json(row.parts.as_deref()),
        "inline_bytes": row.inline.as_ref().map(Vec::len),
        "seq": row.seq,
        "latest": row.latest,
    })
}

/// JSON the store keeps as text, parsed so it reads as part of the record (as text when
/// it doesn't parse).
fn stored_json(text: Option<&str>) -> Value {
    text.map_or(Value::Null, |text| {
        serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
    })
}
