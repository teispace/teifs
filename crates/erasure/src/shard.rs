//! A shard file's header and the hash in front of each piece.

use xxhash_rust::xxh3::{xxh3_64, xxh3_128, xxh3_128_with_seed};

use crate::{Error, Geometry, Result};

/// Bytes of a shard file's header.
pub const HEADER_LEN: usize = 52;
/// Bytes of the hash in front of each piece.
pub const HASH_LEN: usize = 16;

const MAGIC: &[u8; 4] = b"TFSS";
const VERSION: u8 = 1;

/// What a shard file says about itself: which file (its id), which shard, how the file
/// was coded and how long it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The file's id (the store's object id).
    pub id: [u8; 16],
    /// Which shard this is, from 0 (`data` shards first).
    pub index: usize,
    /// How the file was coded.
    pub geometry: Geometry,
    /// The file's length.
    pub len: u64,
}

impl Header {
    /// The header's bytes: magic `TFSS`, version, shard index, data and parity counts,
    /// block size (4 bytes) and file length (8), all big-endian, the id, then the
    /// XXH3-128 of everything before it.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(MAGIC);
        out[4] = VERSION;
        out[5] = byte(self.index);
        out[6] = byte(self.geometry.data());
        out[7] = byte(self.geometry.parity());
        let block = u32::try_from(self.geometry.block()).expect("a block is at most 64 MiB");
        out[8..12].copy_from_slice(&block.to_be_bytes());
        out[12..20].copy_from_slice(&self.len.to_be_bytes());
        out[20..36].copy_from_slice(&self.id);
        let hash = xxh3_128(&out[..36]);
        out[36..].copy_from_slice(&hash.to_be_bytes());
        out
    }

    /// Reads a header, checking its magic, version, hash and geometry.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let Some(bytes) = bytes.get(..HEADER_LEN) else {
            return Err(Error::Shard("shorter than a header"));
        };
        if &bytes[..4] != MAGIC {
            return Err(Error::Shard("no TFSS magic"));
        }
        if bytes[4] != VERSION {
            return Err(Error::Shard("a shard version this release doesn't know"));
        }
        if xxh3_128(&bytes[..36]).to_be_bytes() != bytes[36..] {
            return Err(Error::Shard("the header's hash doesn't match"));
        }
        let block = u32::from_be_bytes(bytes[8..12].try_into().expect("4 bytes"));
        let geometry = Geometry::new(
            usize::from(bytes[6]),
            usize::from(bytes[7]),
            usize::try_from(block).map_err(|_| Error::Shard("block size"))?,
        )
        .map_err(|_| Error::Shard("an invalid geometry"))?;
        let index = usize::from(bytes[5]);
        if index >= geometry.shards() {
            return Err(Error::Shard("a shard index past the geometry's shards"));
        }
        Ok(Self {
            id: bytes[20..36].try_into().expect("16 bytes"),
            index,
            geometry,
            len: u64::from_be_bytes(bytes[12..20].try_into().expect("8 bytes")),
        })
    }

    /// The hash of piece `n` of this shard: XXH3-128 seeded with the file's id, the
    /// block number and the shard index, so a piece copied from elsewhere (another
    /// file, block or shard) doesn't pass.
    #[must_use]
    pub fn piece_hash(&self, n: u64, piece: &[u8]) -> [u8; HASH_LEN] {
        let seed = xxh3_64(&self.id) ^ (n << 8 | self.index as u64);
        xxh3_128_with_seed(piece, seed).to_be_bytes()
    }
}

/// A count or index that [`Geometry::new`] keeps within a byte.
fn byte(n: usize) -> u8 {
    u8::try_from(n).expect("shard counts and indexes fit in a byte")
}
