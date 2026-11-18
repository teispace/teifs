//! How a file is cut and coded: shards, block size, and the pieces' lengths.

use crate::{Error, Result};

/// The shape of an erasure code: `data` shards hold the file, `parity` more let it be
/// rebuilt from any `data` of them, and the file is coded `block` bytes at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Geometry {
    data: usize,
    parity: usize,
    block: usize,
}

impl Geometry {
    /// The most shards a code can have (a shard's index is one byte in its header).
    pub const MAX_SHARDS: usize = 256;
    /// The largest block (pieces are read whole, so this bounds a read's memory).
    pub const MAX_BLOCK: usize = 64 << 20;
    /// The block size drive sets use.
    pub const DEFAULT_BLOCK: usize = 1 << 20;

    /// A geometry of `data` and `parity` shards coding `block` bytes at a time.
    pub fn new(data: usize, parity: usize, block: usize) -> Result<Self> {
        if data == 0 {
            return Err(Error::Geometry("at least one data shard is needed"));
        }
        if parity == 0 {
            return Err(Error::Geometry("at least one parity shard is needed"));
        }
        if data + parity > Self::MAX_SHARDS {
            return Err(Error::Geometry("at most 256 shards"));
        }
        if block == 0 || block > Self::MAX_BLOCK {
            return Err(Error::Geometry("the block size must be 1 byte to 64 MiB"));
        }
        Ok(Self {
            data,
            parity,
            block,
        })
    }

    /// Shards holding the file's bytes: any this many give it back.
    #[must_use]
    pub fn data(&self) -> usize {
        self.data
    }

    /// Shards of redundancy: this many can be lost.
    #[must_use]
    pub fn parity(&self) -> usize {
        self.parity
    }

    /// All shards.
    #[must_use]
    pub fn shards(&self) -> usize {
        self.data + self.parity
    }

    /// Bytes of the file coded at a time.
    #[must_use]
    pub fn block(&self) -> usize {
        self.block
    }

    /// Bytes of each piece of a block of `block_len` bytes: a `data`-th of it, rounded
    /// up to an even length (the code works on 16-bit symbols).
    #[must_use]
    pub fn piece_len(&self, block_len: usize) -> usize {
        let len = block_len.div_ceil(self.data).max(1);
        len + (len & 1)
    }

    /// How many blocks a file of `len` bytes has.
    #[must_use]
    pub fn blocks(&self, len: u64) -> u64 {
        len.div_ceil(self.block as u64)
    }

    /// Bytes of block `n` of a file of `len` bytes (the last is shorter).
    #[must_use]
    pub fn block_len(&self, len: u64, n: u64) -> usize {
        let start = n.saturating_mul(self.block as u64);
        let left = len.saturating_sub(start);
        usize::try_from(left.min(self.block as u64)).unwrap_or(self.block)
    }

    /// Where block `n`'s hashed piece starts in a shard file.
    #[must_use]
    pub fn piece_offset(&self, n: u64) -> u64 {
        let full = (crate::HASH_LEN + self.piece_len(self.block)) as u64;
        crate::HEADER_LEN as u64 + n * full
    }

    /// The length of each shard file of a file of `len` bytes.
    #[must_use]
    pub fn shard_file_len(&self, len: u64) -> u64 {
        let blocks = self.blocks(len);
        if blocks == 0 {
            return crate::HEADER_LEN as u64;
        }
        let last = (crate::HASH_LEN + self.piece_len(self.block_len(len, blocks - 1))) as u64;
        self.piece_offset(blocks - 1) + last
    }

    /// Codes one block: its `data + parity` pieces, in shard order.
    pub fn encode(&self, block: &[u8]) -> Result<Vec<Vec<u8>>> {
        let len = self.piece_len(block.len());
        let mut pieces: Vec<Vec<u8>> = (0..self.data)
            .map(|i| {
                let start = (i * len).min(block.len());
                let end = ((i + 1) * len).min(block.len());
                let mut piece = Vec::with_capacity(len);
                piece.extend_from_slice(&block[start..end]);
                piece.resize(len, 0);
                piece
            })
            .collect();
        let parity = reed_solomon_simd::encode(self.data, self.parity, &pieces)
            .map_err(|e| Error::Codec(e.to_string()))?;
        pieces.extend(parity);
        Ok(pieces)
    }

    /// Fills in every missing piece of a block from the ones present (at least `data`
    /// of them, all `piece_len` long).
    pub fn rebuild(&self, pieces: &mut [Option<Vec<u8>>]) -> Result<()> {
        if pieces.len() != self.shards() {
            return Err(Error::Geometry("one slot per shard is needed"));
        }
        let found = pieces.iter().filter(|p| p.is_some()).count();
        if found < self.data {
            return Err(Error::NotEnoughShards {
                needed: self.data,
                found,
            });
        }
        if found == self.shards() {
            return Ok(());
        }
        if pieces[..self.data].iter().any(Option::is_none) {
            let (data, parity) = pieces.split_at(self.data);
            let restored = reed_solomon_simd::decode(
                self.data,
                self.parity,
                data.iter()
                    .enumerate()
                    .filter_map(|(i, p)| p.as_deref().map(|p| (i, p))),
                parity
                    .iter()
                    .enumerate()
                    .filter_map(|(i, p)| p.as_deref().map(|p| (i, p))),
            )
            .map_err(|e| Error::Codec(e.to_string()))?;
            for (i, piece) in restored {
                if let Some(slot) = pieces.get_mut(i) {
                    *slot = Some(piece);
                }
            }
        }
        if pieces[self.data..].iter().any(Option::is_none) {
            let data: Vec<&[u8]> = pieces[..self.data]
                .iter()
                .map(|p| {
                    p.as_deref()
                        .ok_or(Error::Codec("a data piece is missing".into()))
                })
                .collect::<Result<_>>()?;
            let parity = reed_solomon_simd::encode(self.data, self.parity, data)
                .map_err(|e| Error::Codec(e.to_string()))?;
            for (slot, piece) in pieces[self.data..].iter_mut().zip(parity) {
                if slot.is_none() {
                    *slot = Some(piece);
                }
            }
        }
        Ok(())
    }

    /// The block of `block_len` bytes back from its pieces (at least `data` present).
    pub fn decode(&self, mut pieces: Vec<Option<Vec<u8>>>, block_len: usize) -> Result<Vec<u8>> {
        if pieces[..self.data.min(pieces.len())]
            .iter()
            .any(Option::is_none)
        {
            self.rebuild(&mut pieces)?;
        }
        let mut block = Vec::with_capacity(block_len);
        for piece in pieces.into_iter().take(self.data).flatten() {
            let want = block_len - block.len();
            block.extend_from_slice(&piece[..want.min(piece.len())]);
        }
        if block.len() == block_len {
            Ok(block)
        } else {
            Err(Error::Codec("the pieces are shorter than the block".into()))
        }
    }
}
