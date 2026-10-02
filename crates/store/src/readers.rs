//! Reads of the index that don't wait for the commit lock. The index is in WAL mode, so
//! a connection that only reads sees the last commit while a write is being recorded on
//! the main one: an object bucket's reads, heads and listings don't queue behind writes
//! (and their syncs). Each read runs in one transaction, so it sees one snapshot.

use std::{
    path::PathBuf,
    sync::{Mutex, PoisonError},
};

use teifs_meta::Index;

use crate::{Inner, error::Result};

/// How many idle connections are kept for the next reads: opening one costs far more
/// than a read, so enough for every read the blocking pool usually runs at once.
const IDLE: usize = 128;

/// Read-only connections to the index, opened as reads need them.
#[derive(Debug)]
pub(crate) struct Readers {
    path: PathBuf,
    idle: Mutex<Vec<Index>>,
}

impl Readers {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            idle: Mutex::new(Vec::new()),
        }
    }

    fn take(&self) -> Option<Index> {
        let idle = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        idle.or_else(|| Index::open_reader(&self.path).ok())
    }

    fn put_back(&self, reader: Index) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < IDLE {
            idle.push(reader);
        }
    }
}

impl Inner {
    /// Runs `read` on a snapshot of the index, without the commit lock (with it if no
    /// reading connection can be opened).
    pub(crate) fn read_index<T>(&self, read: impl FnOnce(&Index) -> Result<T>) -> Result<T> {
        let Some(reader) = self.readers.take() else {
            return read(&self.lock());
        };
        let out = reader.try_batch(read);
        self.readers.put_back(reader);
        out
    }
}
