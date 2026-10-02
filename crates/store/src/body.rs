//! An object's bytes, as a reader of exactly those bytes (never an object bucket's
//! footer), whole or a range. Encrypted objects are read and decrypted up to 16
//! packages at a time on the blocking pool, in place in one buffer handed on without
//! copying; a range reads and decrypts only the packages that hold it.

use std::io::{self, Read, SeekFrom};

use bytes::{Bytes, BytesMut};
use teifs_crypto::{
    DataKey, PACKAGE_SIZE, PartCipher, PartId, TAG_LEN, ciphertext_len, packages_for,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};

use crate::error::Result;

/// The bytes of an object being read. The file stays the one the object's description
/// was read with, even if the object is replaced meanwhile.
#[derive(Debug)]
pub struct ObjectBody {
    file: tokio::fs::File,
    size: u64,
    decrypt: Option<Decrypt>,
}

/// How to decrypt an encrypted object: its data key (and DSSE-KMS's second one) and its
/// parts, in order: each one's plaintext size and which key encrypts it.
#[derive(Debug)]
pub(crate) struct Decrypt {
    pub key: DataKey,
    pub outer: Option<DataKey>,
    pub parts: Vec<(u64, PartId)>,
}

/// A reader of an object's bytes.
pub type BodyReader = Box<dyn AsyncRead + Send + Sync + Unpin + 'static>;

/// On-disk size of a full package.
const SEALED_PACKAGE_LEN: usize = PACKAGE_SIZE + TAG_LEN;
const SEALED_PACKAGE: u64 = SEALED_PACKAGE_LEN as u64;

impl ObjectBody {
    pub(crate) fn new(file: std::fs::File, size: u64, decrypt: Option<Decrypt>) -> Self {
        Self {
            file: tokio::fs::File::from_std(file),
            size,
            decrypt,
        }
    }

    /// The object's size.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// A reader of `len` bytes from `start` (clamped to the object).
    pub async fn range(mut self, start: u64, len: u64) -> Result<BodyReader> {
        let start = start.min(self.size);
        let len = len.min(self.size - start);
        match self.decrypt.take() {
            None => {
                self.file.seek(SeekFrom::Start(start)).await?;
                Ok(Box::new(self.file.take(len)))
            }
            Some(decrypt) => decrypting(self.file, decrypt, start, len).await,
        }
    }

    /// A reader of the whole object.
    pub async fn all(self) -> Result<BodyReader> {
        let size = self.size;
        self.range(0, size).await
    }
}

/// Packages read and decrypted at a time (about 1 MiB): one trip to the blocking pool
/// and one buffer for all of them.
const BATCH: u64 = 16;

/// Where a decrypting read is: which part and package, and how much is still wanted.
struct Position {
    file: std::fs::File,
    decrypt: Decrypt,
    part: usize,
    package: u64,
    cipher: PartCipher,
    /// Bytes to drop from the start of the next package.
    skip: usize,
    remaining: u64,
}

async fn decrypting(
    mut file: tokio::fs::File,
    decrypt: Decrypt,
    start: u64,
    len: u64,
) -> Result<BodyReader> {
    // The part, then the package, holding `start`, and where its ciphertext begins.
    let (mut plain_before, mut cipher_before, mut part) = (0, 0, 0);
    while part + 1 < decrypt.parts.len() && start >= plain_before + decrypt.parts[part].0 {
        plain_before += decrypt.parts[part].0;
        cipher_before += ciphertext_len(decrypt.parts[part].0);
        part += 1;
    }
    let offset = start - plain_before;
    let package = offset / PACKAGE_SIZE as u64;
    file.seek(SeekFrom::Start(cipher_before + package * SEALED_PACKAGE))
        .await?;
    let position = Position {
        cipher: PartCipher::layered(&decrypt.key, decrypt.outer.as_ref(), decrypt.parts[part].1),
        file: file.into_std().await,
        decrypt,
        part,
        package,
        skip: usize::try_from(offset % PACKAGE_SIZE as u64).unwrap_or(0),
        remaining: len,
    };
    let stream = Box::pin(futures::stream::try_unfold(position, next_chunk));
    Ok(Box::new(tokio_util::io::StreamReader::new(stream)))
}

/// Reads, decrypts and trims the next packages, on the blocking pool.
async fn next_chunk(at: Position) -> io::Result<Option<(Bytes, Position)>> {
    if at.remaining == 0 {
        return Ok(None);
    }
    tokio::task::spawn_blocking(move || at.next_batch().map(Some))
        .await
        .map_err(io::Error::other)?
}

impl Position {
    /// Up to [`BATCH`] packages of the current part, decrypted in place, their
    /// plaintexts moved together, and trimmed to what's wanted.
    fn next_batch(mut self) -> io::Result<(Bytes, Self)> {
        let part_size = self.decrypt.parts[self.part].0;
        let packages = packages_for(part_size);
        let wanted = (self.skip as u64 + self.remaining).div_ceil(PACKAGE_SIZE as u64);
        let count = BATCH.min(packages - self.package).min(wanted.max(1));
        let first = self.package;
        let reaches_end = first + count == packages;
        let sealed_len = if reaches_end {
            ciphertext_len(part_size) - first * SEALED_PACKAGE
        } else {
            count * SEALED_PACKAGE
        };
        let mut buf = BytesMut::zeroed(usize::try_from(sealed_len).map_err(io::Error::other)?);
        self.file.read_exact(&mut buf)?;
        let mut plain_len = 0;
        for (i, at) in (0..buf.len()).step_by(SEALED_PACKAGE_LEN).enumerate() {
            let index = first + i as u64;
            let end = buf.len().min(at + SEALED_PACKAGE_LEN);
            let opened = self
                .cipher
                .open(index, index + 1 == packages, &mut buf[at..end])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .len();
            buf.copy_within(at..at + opened, plain_len);
            plain_len += opened;
        }
        let from = self.skip.min(plain_len);
        let take = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(plain_len - from);
        buf.truncate(from + take);
        let chunk = buf.freeze().slice(from..);
        self.remaining -= take as u64;
        self.skip = 0;
        self.package += count;
        if reaches_end && self.part + 1 < self.decrypt.parts.len() {
            self.part += 1;
            self.package = 0;
            let id = self.decrypt.parts[self.part].1;
            self.cipher = PartCipher::layered(&self.decrypt.key, self.decrypt.outer.as_ref(), id);
        }
        Ok((chunk, self))
    }
}
