//! Bytes on their way into the drive: written to `.teifs/tmp`, hashed as they arrive,
//! flushed to disk, and only then renamed into place, so a crash or a failed upload never
//! leaves a half-written file where an object should be.
//!
//! Bytes are gathered into batches; each batch is hashed, encrypted and written on a
//! blocking thread while the next one arrives, so the network, the hashing and the disk
//! overlap. At most one batch is in flight per upload, and none holds a thread while it
//! waits for the client.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use md5::{Digest, Md5};
use tokio::task::JoinHandle;

use teifs_crypto::{PartCipher, PartEncryptor, PartId};

use crate::{error::Result, sse::Keyed};

/// How many bytes are gathered before they're written.
const BATCH: usize = 256 * 1024;

/// An upload being written. Dropped without being committed, its file is removed. When
/// it's encrypted, what reaches the file is ciphertext; the MD5 and size are of the
/// plaintext.
#[derive(Debug)]
pub struct Staged {
    path: PathBuf,
    state: State,
    /// The bytes not yet sent to be written.
    batch: Vec<u8>,
    /// The last batch's buffer, back from being written, for the next one.
    spare: Vec<u8>,
    size: u64,
    kept: bool,
    sealing: Option<Sealing>,
}

/// An encrypted upload's key.
#[derive(Debug)]
pub(crate) struct Sealing {
    pub keyed: Keyed,
    /// The object bucket the data key is bound to.
    pub bucket_id: String,
    /// The part the bytes are encrypted as (1 for a single-part object).
    pub part: PartId,
}

/// What batches are written with; it goes to the blocking thread with each batch.
#[derive(Debug)]
struct Sink {
    file: fs::File,
    md5: Md5,
    encryptor: Option<PartEncryptor>,
    scratch: Vec<u8>,
}

impl Sink {
    fn write(&mut self, batch: &[u8]) -> io::Result<()> {
        self.md5.update(batch);
        match self.encryptor.as_mut() {
            Some(encryptor) => {
                self.scratch.clear();
                encryptor.update(batch, &mut self.scratch);
                self.file.write_all(&self.scratch)
            }
            None => self.file.write_all(batch),
        }
    }

    /// Writes the last of the ciphertext; the plaintext's MD5.
    fn finish(mut self: Box<Self>) -> io::Result<[u8; 16]> {
        if let Some(encryptor) = self.encryptor.take() {
            self.scratch.clear();
            encryptor.finish(&mut self.scratch);
            self.file.write_all(&self.scratch)?;
        }
        Ok(self.md5.finalize().into())
    }
}

/// A batch being written: the sink and the batch's buffer come back with the outcome.
type Writing = JoinHandle<(Box<Sink>, Vec<u8>, io::Result<()>)>;

#[derive(Debug)]
enum State {
    /// Nothing in flight.
    Idle(Box<Sink>),
    /// A batch is being written.
    Writing(Writing),
    /// Every byte is written; the plaintext's MD5.
    Finished([u8; 16]),
    /// A write failed or was cancelled part way.
    Broken,
}

fn broken() -> io::Error {
    io::Error::other("the upload's file was left part written")
}

impl Staged {
    pub(crate) async fn create(dir: &Path) -> Result<Self> {
        Self::open(dir, None, None).await
    }

    /// A staged upload encrypted with `keyed`'s data key as part `part`.
    pub(crate) async fn create_sealed(
        dir: &Path,
        keyed: Keyed,
        bucket_id: String,
        part: PartId,
    ) -> Result<Self> {
        let encryptor =
            PartCipher::layered(&keyed.data_key, keyed.outer.as_ref(), part).encryptor();
        let sealing = Sealing {
            keyed,
            bucket_id,
            part,
        };
        Self::open(dir, Some(encryptor), Some(sealing)).await
    }

    async fn open(
        dir: &Path,
        encryptor: Option<PartEncryptor>,
        sealing: Option<Sealing>,
    ) -> Result<Self> {
        let path = dir.join(uuid::Uuid::new_v4().to_string());
        let file = tokio::fs::File::create(&path).await?.into_std().await;
        let scratch = if encryptor.is_some() {
            Vec::with_capacity(BATCH + BATCH / 4)
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            state: State::Idle(Box::new(Sink {
                file,
                md5: Md5::new(),
                encryptor,
                scratch,
            })),
            batch: Vec::with_capacity(BATCH),
            spare: Vec::new(),
            size: 0,
            kept: false,
            sealing,
        })
    }

    /// Appends bytes.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if matches!(self.state, State::Finished(_)) {
            return Err(io::Error::other("the upload was written after it was finished").into());
        }
        self.size += bytes.len() as u64;
        self.batch.extend_from_slice(bytes);
        if self.batch.len() >= BATCH {
            let mut sink = self.sink().await?;
            let mut batch = std::mem::take(&mut self.spare);
            batch.clear();
            std::mem::swap(&mut batch, &mut self.batch);
            self.state = State::Writing(tokio::task::spawn_blocking(move || {
                let result = sink.write(&batch);
                (sink, batch, result)
            }));
        }
        Ok(())
    }

    /// The sink, once the batch in flight (if any) is written. Until it's put back, the
    /// upload counts as broken: a write cancelled here leaves it so.
    async fn sink(&mut self) -> Result<Box<Sink>> {
        match std::mem::replace(&mut self.state, State::Broken) {
            State::Idle(sink) => Ok(sink),
            State::Writing(writing) => {
                let (sink, batch, result) = writing.await.map_err(io::Error::other)?;
                result?;
                self.spare = batch;
                Ok(sink)
            }
            State::Finished(_) | State::Broken => Err(broken().into()),
        }
    }

    /// The encryption this upload carries, if any.
    pub(crate) fn sealing(&self) -> Option<&Sealing> {
        self.sealing.as_ref()
    }

    /// Whether the bytes are encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.sealing.is_some()
    }

    /// How many bytes were written.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The MD5 of what was written, once [`Staged::finish`]ed.
    ///
    /// # Panics
    /// Before it's finished.
    #[must_use]
    pub fn md5(&self) -> [u8; 16] {
        match self.state {
            State::Finished(md5) => md5,
            _ => panic!("the MD5 of an upload is read before it's finished"),
        }
    }

    /// Writes what's left; nothing more can be written. The commit syncs the file (once,
    /// after anything it appends). Finishing again does nothing.
    pub async fn finish(&mut self) -> Result<()> {
        if matches!(self.state, State::Finished(_)) {
            return Ok(());
        }
        let mut sink = self.sink().await?;
        let batch = std::mem::take(&mut self.batch);
        let md5 = tokio::task::spawn_blocking(move || {
            sink.write(&batch)?;
            sink.finish()
        })
        .await
        .map_err(io::Error::other)??;
        self.state = State::Finished(md5);
        self.spare = Vec::new();
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

/// Syncs a written file's data. Flushing needs write access on Windows.
pub(crate) fn sync_file(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .sync_all()
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

    #[tokio::test]
    async fn batches_reach_the_file_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut staged = Staged::create(dir.path()).await.unwrap();
        let mut sent = Vec::new();
        // Pieces smaller and bigger than a batch.
        for (i, len) in [1, BATCH - 1, 3, 2 * BATCH + 5, 0, 77]
            .into_iter()
            .enumerate()
        {
            let piece = vec![u8::try_from(i).unwrap(); len];
            staged.write(&piece).await.unwrap();
            sent.extend_from_slice(&piece);
        }
        staged.finish().await.unwrap();
        assert_eq!(fs::read(staged.path()).unwrap(), sent);
        assert_eq!(staged.md5(), <[u8; 16]>::from(Md5::digest(&sent)));
        assert!(staged.write(b"late").await.is_err());
        let path = staged.path().to_owned();
        drop(staged);
        assert!(!path.exists());
    }

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
