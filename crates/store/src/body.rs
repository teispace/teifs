//! An object's bytes, as a reader of exactly those bytes (never an object bucket's
//! footer), whole or a range.

use std::io::SeekFrom;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};

use crate::error::Result;

/// The bytes of an object being read. The file stays the one the object's description
/// was read with, even if the object is replaced meanwhile.
#[derive(Debug)]
pub struct ObjectBody {
    file: tokio::fs::File,
    size: u64,
}

impl ObjectBody {
    pub(crate) fn new(file: std::fs::File, size: u64) -> Self {
        Self {
            file: tokio::fs::File::from_std(file),
            size,
        }
    }

    /// The object's size.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// A reader of `len` bytes from `start` (clamped to the object).
    pub async fn range(
        mut self,
        start: u64,
        len: u64,
    ) -> Result<impl AsyncRead + Send + Unpin + 'static> {
        let start = start.min(self.size);
        let len = len.min(self.size - start);
        self.file.seek(SeekFrom::Start(start)).await?;
        Ok(self.file.take(len))
    }

    /// A reader of the whole object.
    pub async fn all(self) -> Result<impl AsyncRead + Send + Unpin + 'static> {
        let size = self.size;
        self.range(0, size).await
    }
}
