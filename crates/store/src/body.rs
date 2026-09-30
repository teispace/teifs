//! An object's bytes, as a reader of exactly those bytes (never an object bucket's
//! footer), whole or a range. Encrypted objects are decrypted package by package; a
//! range reads and decrypts only the packages that hold it.

use std::io::{self, SeekFrom};

use bytes::Bytes;
use teifs_crypto::{DataKey, PACKAGE_SIZE, PartCipher, TAG_LEN, ciphertext_len, packages_for};
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
/// parts' plaintext sizes (part numbers 1, 2, …).
#[derive(Debug)]
pub(crate) struct Decrypt {
    pub key: DataKey,
    pub outer: Option<DataKey>,
    pub parts: Vec<u64>,
}

/// A reader of an object's bytes.
pub type BodyReader = Box<dyn AsyncRead + Send + Sync + Unpin + 'static>;

/// On-disk size of a full package.
const SEALED_PACKAGE: u64 = (PACKAGE_SIZE + TAG_LEN) as u64;

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

/// Where a decrypting read is: which part and package, and how much is still wanted.
struct Position {
    file: tokio::fs::File,
    decrypt: Decrypt,
    part: usize,
    package: u64,
    cipher: PartCipher,
    /// Bytes to drop from the start of the next package.
    skip: usize,
    remaining: u64,
    buf: Vec<u8>,
}

async fn decrypting(
    mut file: tokio::fs::File,
    decrypt: Decrypt,
    start: u64,
    len: u64,
) -> Result<BodyReader> {
    // The part, then the package, holding `start`, and where its ciphertext begins.
    let (mut plain_before, mut cipher_before, mut part) = (0, 0, 0);
    while part + 1 < decrypt.parts.len() && start >= plain_before + decrypt.parts[part] {
        plain_before += decrypt.parts[part];
        cipher_before += ciphertext_len(decrypt.parts[part]);
        part += 1;
    }
    let offset = start - plain_before;
    let package = offset / PACKAGE_SIZE as u64;
    file.seek(SeekFrom::Start(cipher_before + package * SEALED_PACKAGE))
        .await?;
    let number = u32::try_from(part + 1).map_err(io::Error::other)?;
    let position = Position {
        cipher: PartCipher::layered(&decrypt.key, decrypt.outer.as_ref(), number),
        file,
        decrypt,
        part,
        package,
        skip: usize::try_from(offset % PACKAGE_SIZE as u64).unwrap_or(0),
        remaining: len,
        buf: vec![0; PACKAGE_SIZE + TAG_LEN],
    };
    let stream = Box::pin(futures::stream::try_unfold(position, next_chunk));
    Ok(Box::new(tokio_util::io::StreamReader::new(stream)))
}

/// Reads, decrypts and trims the next package.
async fn next_chunk(mut at: Position) -> io::Result<Option<(Bytes, Position)>> {
    if at.remaining == 0 {
        return Ok(None);
    }
    let part_size = at.decrypt.parts[at.part];
    let last = at.package + 1 == packages_for(part_size);
    let sealed_len = if last {
        ciphertext_len(part_size) - at.package * SEALED_PACKAGE
    } else {
        SEALED_PACKAGE
    };
    let buf = &mut at.buf[..usize::try_from(sealed_len).map_err(io::Error::other)?];
    at.file.read_exact(buf).await?;
    let plain = at
        .cipher
        .open(at.package, last, buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let from = at.skip.min(plain.len());
    let take = usize::try_from(at.remaining)
        .unwrap_or(usize::MAX)
        .min(plain.len() - from);
    let chunk = Bytes::copy_from_slice(&plain[from..from + take]);
    at.remaining -= take as u64;
    at.skip = 0;
    at.package += 1;
    if last && at.part + 1 < at.decrypt.parts.len() {
        at.part += 1;
        at.package = 0;
        let number = u32::try_from(at.part + 1).map_err(io::Error::other)?;
        at.cipher = PartCipher::layered(&at.decrypt.key, at.decrypt.outer.as_ref(), number);
    }
    Ok(Some((chunk, at)))
}
