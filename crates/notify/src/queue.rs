//! The events waiting to be sent, kept on the drive (`events.db`) so a restart or a
//! target that's down loses none: each target's in the order they happened.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use rusqlite::{Connection, params};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    body BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_target ON events (target, seq);
";

/// One event waiting: its place in the queue, and what's sent.
pub(crate) type Queued = (i64, Vec<u8>);

/// The queue, shared by the request that add to it and the targets' senders.
#[derive(Debug, Clone)]
pub(crate) struct Queue {
    db: Arc<Mutex<Connection>>,
}

impl Queue {
    /// Opens (or makes) the queue at `path`.
    pub(crate) fn open(path: &Path) -> rusqlite::Result<Self> {
        let db = Connection::open(path)?;
        // Waiting events survive the process ending; the last ones may not survive
        // the power going, which a notification may miss anyway.
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
        })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many events wait for each target.
    pub(crate) fn counts(&self) -> rusqlite::Result<HashMap<String, u64>> {
        let db = self.db();
        let mut select = db.prepare("SELECT target, COUNT(*) FROM events GROUP BY target")?;
        let rows = select.query_map([], |row| {
            let count: i64 = row.get(1)?;
            Ok((row.get(0)?, u64::try_from(count).unwrap_or(0)))
        })?;
        rows.collect()
    }

    /// Adds events, each for its target, in one step.
    pub(crate) fn push(&self, events: &[(String, Vec<u8>)]) -> rusqlite::Result<()> {
        let mut db = self.db();
        let tx = db.transaction()?;
        {
            let mut insert =
                tx.prepare_cached("INSERT INTO events (target, body) VALUES (?, ?)")?;
            for (target, body) in events {
                insert.execute(params![target, body])?;
            }
        }
        tx.commit()
    }

    /// The first `limit` events waiting for `target`.
    pub(crate) fn peek(&self, target: &str, limit: usize) -> rusqlite::Result<Vec<Queued>> {
        let db = self.db();
        let mut select = db
            .prepare_cached("SELECT seq, body FROM events WHERE target = ? ORDER BY seq LIMIT ?")?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows =
            select.query_map(params![target, limit], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// Removes `target`'s events up to and including `seq`: they've been sent.
    pub(crate) fn remove_through(&self, target: &str, seq: i64) -> rusqlite::Result<u64> {
        let removed = self.db().execute(
            "DELETE FROM events WHERE target = ? AND seq <= ?",
            params![target, seq],
        )?;
        Ok(removed as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_wait_in_order_across_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.db");
        let queue = Queue::open(&path).unwrap();
        let event = |target: &str, n: u8| (target.to_owned(), vec![n]);
        queue
            .push(&[event("a", 1), event("b", 2), event("a", 3)])
            .unwrap();
        queue.push(&[event("a", 4)]).unwrap();
        drop(queue);
        let queue = Queue::open(&path).unwrap();
        assert_eq!(
            queue.counts().unwrap(),
            HashMap::from([("a".into(), 3), ("b".into(), 1)])
        );
        let first = queue.peek("a", 2).unwrap();
        let bodies: Vec<_> = first.iter().map(|(_, body)| body[0]).collect();
        assert_eq!(bodies, [1, 3]);
        assert_eq!(queue.remove_through("a", first[1].0).unwrap(), 2);
        let rest = queue.peek("a", 10).unwrap();
        assert_eq!(rest.iter().map(|(_, b)| b[0]).collect::<Vec<_>>(), [4]);
        assert_eq!(
            queue.peek("b", 10).unwrap().len(),
            1,
            "another target's stay"
        );
    }
}
