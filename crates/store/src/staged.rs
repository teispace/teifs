//! Bytes on their way into the drive: written to `.teidrive/tmp`, hashed as they arrive,
//! flushed to disk, and only then renamed into place, so a crash or a failed upload never
//! leaves a half-written file where an object should be.

use std::path::{Path, PathBuf};

use md5::{Digest, Md5};
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::error::Result;

const BUFFER: usize = 256 * 1024;

/// An upload being written. Dropped without being committed, its file is removed.
#[derive(Debug)]
pub struct Staged {
    path: PathBuf,
    file: Option<BufWriter<tokio::fs::File>>,
    md5: Md5,
    size: u64,
    kept: bool,
}

impl Staged {
    pub(crate) async fn create(dir: &Path) -> Result<Self> {
        let path = dir.join(uuid::Uuid::new_v4().to_string());
        let file = tokio::fs::File::create(&path).await?;
        Ok(Self {
            path,
            file: Some(BufWriter::with_capacity(BUFFER, file)),
            md5: Md5::new(),
            size: 0,
            kept: false,
        })
    }

    /// Appends bytes.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.md5.update(bytes);
        self.size += bytes.len() as u64;
        self.file
            .as_mut()
            .expect("written after finishing")
            .write_all(bytes)
            .await?;
        Ok(())
    }

    /// How many bytes were written.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The MD5 of what was written.
    pub fn md5(&self) -> [u8; 16] {
        self.md5.clone().finalize().into()
    }

    /// Flushes and syncs the file; nothing more can be written.
    pub(crate) async fn finish(&mut self) -> Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
            file.into_inner().sync_all().await?;
        }
        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The file now belongs somewhere else (it was renamed into place).
    pub(crate) fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.kept {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Syncs a folder so a rename into it survives a crash.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Windows has no folder sync; renames are journaled by NTFS.
#[cfg(not(unix))]
pub(crate) fn sync_dir(_: &Path) -> std::io::Result<()> {
    Ok(())
}

/// A temporary file written without streaming (copies, joined parts), removed unless kept.
#[derive(Debug)]
pub(crate) struct TmpFile {
    pub path: PathBuf,
    kept: bool,
}

impl TmpFile {
    pub fn new(dir: &Path) -> Self {
        Self {
            path: dir.join(uuid::Uuid::new_v4().to_string()),
            kept: false,
        }
    }

    pub fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for TmpFile {
    fn drop(&mut self) {
        if !self.kept {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
