//! A drive set's heal queue: data files a drive missed while the set served (a shard
//! that couldn't be written, or removed), kept with the change that missed it so a
//! restart doesn't forget them, and retried until every drive holds what it should.

use rusqlite::params;

use crate::{Index, Result};

pub(crate) const MIGRATION: &str = "CREATE TABLE heal_queue (
        object_id TEXT    PRIMARY KEY,
        bucket_id TEXT    NOT NULL,
        queued_ms INTEGER NOT NULL,
        tries     INTEGER NOT NULL,
        next_ms   INTEGER NOT NULL
     ) WITHOUT ROWID;
     CREATE INDEX heal_queue_due ON heal_queue (next_ms);";

/// When a queued heal waits for a drive that's down: tried again once it's back.
pub const PARKED: i64 = i64::MAX;

/// A data file waiting to be healed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedHeal {
    /// Its bucket's id.
    pub bucket_id: String,
    /// Its object id.
    pub object_id: String,
    /// How many times healing it failed.
    pub tries: u32,
}

impl Index {
    /// Queues data file `object_id` of bucket `bucket_id` to be healed now (one already
    /// queued is tried again now).
    pub fn queue_heal(&self, bucket_id: &str, object_id: &str, now_ms: i64) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO heal_queue (object_id, bucket_id, queued_ms, tries, next_ms)
                 VALUES (?1, ?2, ?3, 0, ?3)
                 ON CONFLICT (object_id) DO UPDATE SET next_ms = MIN(next_ms, excluded.next_ms)",
            )?
            .execute(params![object_id, bucket_id, now_ms])?;
        Ok(())
    }

    /// The queued heals due at `now_ms`, those due longest first, at most `limit`.
    pub fn due_heals(&self, now_ms: i64, limit: usize) -> Result<Vec<QueuedHeal>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT bucket_id, object_id, tries FROM heal_queue
             WHERE next_ms <= ?1 ORDER BY next_ms, object_id LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![now_ms, i64::try_from(limit).unwrap_or(i64::MAX)],
            |r| {
                Ok(QueuedHeal {
                    bucket_id: r.get(0)?,
                    object_id: r.get(1)?,
                    tries: r.get(2)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Puts off a queued heal that failed until `next_ms` ([`PARKED`]: until the
    /// drives are back), counting the try.
    pub fn retry_heal(&self, object_id: &str, next_ms: i64) -> Result<()> {
        self.conn
            .prepare_cached(
                "UPDATE heal_queue SET tries = tries + 1, next_ms = ?2 WHERE object_id = ?1",
            )?
            .execute(params![object_id, next_ms])?;
        Ok(())
    }

    /// Takes a healed data file off the queue.
    pub fn drop_heal(&self, object_id: &str) -> Result<()> {
        self.conn
            .prepare_cached("DELETE FROM heal_queue WHERE object_id = ?1")?
            .execute([object_id])?;
        Ok(())
    }

    /// Makes every queued heal due at `now_ms` (the drives are back, or a heal was
    /// asked for); how many were waiting.
    pub fn wake_heals(&self, now_ms: i64) -> Result<usize> {
        Ok(self
            .conn
            .prepare_cached("UPDATE heal_queue SET next_ms = ?1 WHERE next_ms > ?1")?
            .execute([now_ms])?)
    }

    /// How many data files are queued, and of them how many wait for a drive that's down.
    pub fn heal_queue_len(&self) -> Result<(u64, u64)> {
        let (all, parked): (i64, i64) = self
            .conn
            .prepare_cached("SELECT COUNT(*), COALESCE(SUM(next_ms = ?1), 0) FROM heal_queue")?
            .query_row([PARKED], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok((crate::index::from_db(all), crate::index::from_db(parked)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn heals_queue_once_back_off_and_wake() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        index.queue_heal("b1", "o1", 100).unwrap();
        index.queue_heal("b1", "o2", 200).unwrap();
        // Queued again: once, and due at the earlier time.
        index.queue_heal("b1", "o1", 300).unwrap();
        let due = index.due_heals(150, 10).unwrap();
        assert_eq!(
            due,
            [QueuedHeal {
                bucket_id: "b1".into(),
                object_id: "o1".into(),
                tries: 0,
            }]
        );
        index.retry_heal("o1", 1_000).unwrap();
        index.retry_heal("o2", PARKED).unwrap();
        assert!(index.due_heals(999, 10).unwrap().is_empty());
        assert_eq!(index.heal_queue_len().unwrap(), (2, 1));
        assert_eq!(index.due_heals(1_000, 10).unwrap()[0].tries, 1);
        // A failed write queues it again: due now, tries kept.
        index.queue_heal("b1", "o2", 500).unwrap();
        assert_eq!(index.due_heals(500, 10).unwrap()[0].object_id, "o2");
        index.retry_heal("o2", PARKED).unwrap();
        assert_eq!(index.wake_heals(600).unwrap(), 2);
        assert_eq!(index.due_heals(600, 10).unwrap().len(), 2);
        index.drop_heal("o1").unwrap();
        assert_eq!(index.heal_queue_len().unwrap(), (1, 0));
    }
}
