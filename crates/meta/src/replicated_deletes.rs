//! Deletes of versions waiting to be replicated (`MinIO`'s `DeleteReplication`, and the
//! removal of delete markers that were replicated): the version is gone, so what's left
//! to send is queued here, in the delete's own transaction.

use rusqlite::params;

use crate::{Index, Result};

pub(crate) const MIGRATION: &str = "CREATE TABLE replicated_deletes (
        bucket_id     TEXT    NOT NULL,
        key           BLOB    NOT NULL,
        version_id    TEXT    NOT NULL,
        delete_marker INTEGER NOT NULL,
        destinations  TEXT    NOT NULL,
        queued_ms     INTEGER NOT NULL,
        PRIMARY KEY (bucket_id, key, version_id)
     ) WITHOUT ROWID;";

/// A removed version whose removal is still to reach some destinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedDelete {
    /// The object's key.
    pub key: String,
    /// The removed version's id.
    pub version_id: String,
    /// Whether the removed version was a delete marker.
    pub delete_marker: bool,
    /// The destinations (ARNs) it's still to reach.
    pub destinations: Vec<String>,
}

impl Index {
    /// Queues the removal of `key`'s version `version_id` for `destinations` (nothing
    /// when there are none).
    pub fn queue_replicated_delete(
        &self,
        bucket_id: &str,
        delete: &QueuedDelete,
        now_ms: i64,
    ) -> Result<()> {
        if delete.destinations.is_empty() {
            return Ok(());
        }
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO replicated_deletes
                 (bucket_id, key, version_id, delete_marker, destinations, queued_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute(params![
                bucket_id,
                delete.key.as_bytes(),
                delete.version_id,
                delete.delete_marker,
                destinations_to_json(&delete.destinations),
                now_ms
            ])?;
        Ok(())
    }

    /// The bucket's queued removals, oldest first, at most `limit`.
    pub fn replicated_deletes(&self, bucket_id: &str, limit: usize) -> Result<Vec<QueuedDelete>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT key, version_id, delete_marker, destinations FROM replicated_deletes
             WHERE bucket_id = ?1 ORDER BY queued_ms, key, version_id LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![bucket_id, i64::try_from(limit).unwrap_or(i64::MAX)],
            |r| {
                let key: Vec<u8> = r.get(0)?;
                let destinations: String = r.get(3)?;
                Ok(QueuedDelete {
                    key: String::from_utf8_lossy(&key).into_owned(),
                    version_id: r.get(1)?,
                    delete_marker: r.get(2)?,
                    destinations: serde_json::from_str(&destinations).unwrap_or_default(),
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Records the destinations a queued removal is still to reach; with none left, it
    /// leaves the queue.
    pub fn set_replicated_delete(
        &self,
        bucket_id: &str,
        key: &str,
        version_id: &str,
        destinations: &[String],
    ) -> Result<()> {
        if destinations.is_empty() {
            self.conn
                .prepare_cached(
                    "DELETE FROM replicated_deletes
                     WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3",
                )?
                .execute(params![bucket_id, key.as_bytes(), version_id])?;
        } else {
            self.conn
                .prepare_cached(
                    "UPDATE replicated_deletes SET destinations = ?4
                     WHERE bucket_id = ?1 AND key = ?2 AND version_id = ?3",
                )?
                .execute(params![
                    bucket_id,
                    key.as_bytes(),
                    version_id,
                    destinations_to_json(destinations)
                ])?;
        }
        Ok(())
    }
}

fn destinations_to_json(destinations: &[String]) -> String {
    serde_json::to_string(destinations).expect("strings serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued(key: &str, version_id: &str, destinations: &[&str]) -> QueuedDelete {
        QueuedDelete {
            key: key.into(),
            version_id: version_id.into(),
            delete_marker: false,
            destinations: destinations.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    #[test]
    fn removals_wait_until_every_destination_has_them() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        let first = queued("a", "v1", &["arn:1", "arn:2"]);
        index.queue_replicated_delete("b1", &first, 1).unwrap();
        index
            .queue_replicated_delete("b1", &queued("b", "v2", &["arn:1"]), 2)
            .unwrap();
        index
            .queue_replicated_delete("b1", &queued("c", "v3", &[]), 3)
            .unwrap();
        index
            .queue_replicated_delete("b2", &queued("a", "v4", &["arn:9"]), 0)
            .unwrap();
        assert_eq!(
            index.replicated_deletes("b1", 10).unwrap(),
            [first.clone(), queued("b", "v2", &["arn:1"])]
        );
        assert_eq!(index.replicated_deletes("b1", 1).unwrap(), [first]);

        index
            .set_replicated_delete("b1", "a", "v1", &["arn:2".to_owned()])
            .unwrap();
        index.set_replicated_delete("b1", "b", "v2", &[]).unwrap();
        assert_eq!(
            index.replicated_deletes("b1", 10).unwrap(),
            [queued("a", "v1", &["arn:2"])]
        );

        index.forget_bucket_versions("b1", 5).unwrap();
        assert!(index.replicated_deletes("b1", 10).unwrap().is_empty());
        assert_eq!(index.replicated_deletes("b2", 10).unwrap().len(), 1);
    }
}
