//! Bytes on their way into the drive: written to `.teifs/tmp`, hashed as they arrive,
//! flushed to disk, and only then renamed into place, so a crash or a failed upload never
//! leaves a half-written file where an object should be.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

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

    /// Flushes the file; nothing more can be written. The commit syncs it (once, after
    /// anything it appends).
    pub(crate) async fn finish(&mut self) -> Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
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

/// How a finished file is put in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Publish {
    /// Replaces whatever is there.
    Replace,
    /// Only if nothing is there (`If-None-Match: *`). The file system decides, so a file
    /// another program creates at the same moment is never overwritten.
    CreateNew,
}

/// Puts the finished file `from` in place as `to`, in one atomic step.
///
/// `Replace` renames; `CreateNew` hard-links, which fails if `to` exists, then removes
/// `from`. When `to` is on another disk than `from` (a bucket that's a link to a folder
/// elsewhere), the file is first copied into the bucket's own staging folder
/// (`bucket_dir/.teifs-tmp`), so the last step is still atomic on the destination's disk.
/// Returns `AlreadyExists` when `CreateNew` finds something at `to`.
pub(crate) fn publish(from: &Path, to: &Path, bucket_dir: &Path, how: Publish) -> io::Result<()> {
    match put(from, to, how) {
        Err(err) if err.kind() == io::ErrorKind::CrossesDevices => {
            let staging = bucket_dir.join(teifs_types::BUCKET_STAGING);
            fs::create_dir_all(&staging)?;
            // Never stage through a link someone put there.
            if !fs::symlink_metadata(&staging)?.is_dir() {
                return Err(io::Error::other(
                    "the bucket's .teifs-tmp folder is a link or a file",
                ));
            }
            let near = TmpFile::new(&staging);
            fs::copy(from, &near.path)?;
            // Flushing needs write access on Windows.
            fs::OpenOptions::new()
                .write(true)
                .open(&near.path)?
                .sync_all()?;
            put(&near.path, to, how)?;
            near.keep();
            let _ = fs::remove_file(from);
            Ok(())
        }
        other => other,
    }
}

fn put(from: &Path, to: &Path, how: Publish) -> io::Result<()> {
    match how {
        Publish::Replace => fs::rename(from, to),
        Publish::CreateNew => match fs::hard_link(from, to) {
            Ok(()) => {
                fs::remove_file(from)?;
                Ok(())
            }
            // A file system without hard links (FAT, exFAT, some network shares): the
            // caller's check under the commit lock is the only guard left.
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::Unsupported | io::ErrorKind::PermissionDenied
                ) && !to.exists() =>
            {
                fs::rename(from, to)
            }
            Err(err) => Err(err),
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let (from, to) = (dir.path().join("from"), dir.path().join("to"));
        fs::write(&from, b"new").unwrap();
        fs::write(&to, b"someone else's").unwrap();
        let err = publish(&from, &to, dir.path(), Publish::CreateNew).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&to).unwrap(), b"someone else's");

        fs::remove_file(&to).unwrap();
        publish(&from, &to, dir.path(), Publish::CreateNew).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"new");
        assert!(!from.exists());
    }

    #[test]
    fn replace_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let (from, to) = (dir.path().join("from"), dir.path().join("to"));
        fs::write(&from, b"new").unwrap();
        fs::write(&to, b"old").unwrap();
        publish(&from, &to, dir.path(), Publish::Replace).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"new");
    }

    /// A bucket on another disk: Linux runners have a tmpfs at /dev/shm.
    #[cfg(target_os = "linux")]
    #[test]
    fn publishes_across_disks() {
        use std::os::unix::fs::MetadataExt;
        let Ok(other) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        if fs::metadata(dir.path()).unwrap().dev() == fs::metadata(other.path()).unwrap().dev() {
            return;
        }
        for how in [Publish::Replace, Publish::CreateNew] {
            let from = dir.path().join("from");
            let to = other.path().join("to");
            let _ = fs::remove_file(&to);
            fs::write(&from, b"bytes").unwrap();
            publish(&from, &to, other.path(), how).unwrap();
            assert_eq!(fs::read(&to).unwrap(), b"bytes");
            assert!(!from.exists());
            let staging = other.path().join(teifs_types::BUCKET_STAGING);
            assert_eq!(fs::read_dir(staging).unwrap().count(), 0);
        }
    }
}
