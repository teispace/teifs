//! Resyncs of replication destinations (`MinIO`'s `mc replicate resync`): where each
//! stands, by bucket and destination, kept so a restart goes on where it was.

use rusqlite::{OptionalExtension as _, params};
use teifs_types::replication::ReplicationResync;

use crate::{Index, Result};

pub(crate) const MIGRATION: &str = "CREATE TABLE replication_resyncs (
        bucket_id TEXT NOT NULL,
        arn       TEXT NOT NULL,
        state     TEXT NOT NULL,
        PRIMARY KEY (bucket_id, arn)
     ) WITHOUT ROWID;";

impl Index {
    /// The bucket's resync of the destination `arn`, if it had one.
    pub fn replication_resync(
        &self,
        bucket_id: &str,
        arn: &str,
    ) -> Result<Option<ReplicationResync>> {
        let state: Option<String> = self
            .conn
            .prepare_cached(
                "SELECT state FROM replication_resyncs WHERE bucket_id = ?1 AND arn = ?2",
            )?
            .query_row(params![bucket_id, arn], |r| r.get(0))
            .optional()?;
        Ok(state.and_then(|state| serde_json::from_str(&state).ok()))
    }

    /// The bucket's resyncs, by destination.
    pub fn replication_resyncs(&self, bucket_id: &str) -> Result<Vec<(String, ReplicationResync)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT arn, state FROM replication_resyncs WHERE bucket_id = ?1 ORDER BY arn",
        )?;
        let rows = stmt.query_map(params![bucket_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut found = Vec::new();
        for row in rows {
            let (arn, state) = row?;
            if let Ok(state) = serde_json::from_str(&state) {
                found.push((arn, state));
            }
        }
        Ok(found)
    }

    /// Records where the bucket's resync of `arn` stands.
    pub fn set_replication_resync(
        &self,
        bucket_id: &str,
        arn: &str,
        state: &ReplicationResync,
    ) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO replication_resyncs (bucket_id, arn, state)
                 VALUES (?1, ?2, ?3)",
            )?
            .execute(params![
                bucket_id,
                arn,
                serde_json::to_string(state).expect("a resync serializes")
            ])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use teifs_types::replication::ResyncStatus;

    use super::*;

    fn resync(id: &str) -> ReplicationResync {
        ReplicationResync {
            id: id.to_owned(),
            before_ms: 10,
            started_ms: 10,
            updated_ms: 10,
            status: ResyncStatus::Ongoing,
            marked: false,
            next: Some(("a".to_owned(), Some("v1".to_owned()))),
            replicated: (1, 5),
            failed: (0, 0),
            last_key: Some("a".to_owned()),
        }
    }

    #[test]
    fn resyncs_are_kept_by_bucket_and_destination() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        assert_eq!(index.replication_resync("b1", "arn:1").unwrap(), None);
        index
            .set_replication_resync("b1", "arn:1", &resync("one"))
            .unwrap();
        index
            .set_replication_resync("b1", "arn:2", &resync("two"))
            .unwrap();
        index
            .set_replication_resync("b2", "arn:1", &resync("other"))
            .unwrap();
        let mut done = resync("one");
        done.status = ResyncStatus::Completed;
        index.set_replication_resync("b1", "arn:1", &done).unwrap();
        assert_eq!(
            index.replication_resync("b1", "arn:1").unwrap(),
            Some(done.clone())
        );
        assert_eq!(
            index.replication_resyncs("b1").unwrap(),
            [
                ("arn:1".to_owned(), done),
                ("arn:2".to_owned(), resync("two"))
            ]
        );

        index.forget_bucket_versions("b1", 5).unwrap();
        assert!(index.replication_resyncs("b1").unwrap().is_empty());
        assert_eq!(index.replication_resyncs("b2").unwrap().len(), 1);
    }
}
