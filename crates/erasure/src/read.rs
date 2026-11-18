//! Reading a file back from its shard files, rebuilding what's missing or damaged.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::{Error, Geometry, HASH_LEN, HEADER_LEN, Header, Result};

/// A reader of a file from its shard files: reads and seeks over the file's bytes,
/// using the data shards while they're good and the parity shards in place of any that
/// aren't. Every piece is checked against its hash before it's used; a shard that's
/// missing, isn't this file's, or has a damaged piece is set aside and listed by
/// [`Reader::damaged`], for the caller to heal.
#[derive(Debug)]
pub struct Reader<S> {
    geometry: Geometry,
    header: Header,
    /// One per shard, by index; `None` once missing or damaged.
    sources: Vec<Option<S>>,
    damaged: Vec<usize>,
    pos: u64,
    /// The block read last and its bytes.
    cached: Option<(u64, Vec<u8>)>,
}

impl<S: Read + Seek> Reader<S> {
    /// Opens file `id`, coded with `geometry`, from `sources` (its shard files, in any
    /// order, `None` for a drive that's down). Each shard's header says which shard it
    /// is; the file's length is the one most headers agree on, which at least `data` of
    /// them must.
    pub fn open(id: [u8; 16], geometry: Geometry, sources: Vec<Option<S>>) -> Result<Self> {
        let mut slots: Vec<Option<(Header, S)>> = (0..geometry.shards()).map(|_| None).collect();
        for mut source in sources.into_iter().flatten() {
            let Ok(header) = read_header(&mut source) else {
                continue;
            };
            if header.id != id || header.geometry != geometry {
                continue;
            }
            let slot = &mut slots[header.index];
            if slot.is_none() {
                *slot = Some((header, source));
            }
        }
        // The length most shards agree on (a shard left from an earlier write of the
        // same id can't outvote the others).
        let mut lens: Vec<(u64, usize)> = Vec::new();
        for (header, _) in slots.iter().flatten() {
            match lens.iter_mut().find(|(len, _)| *len == header.len) {
                Some((_, votes)) => *votes += 1,
                None => lens.push((header.len, 1)),
            }
        }
        let best = lens.iter().max_by_key(|(_, votes)| *votes).copied();
        let (len, votes) = best.unwrap_or((0, 0));
        if votes < geometry.data() {
            return Err(Error::NotEnoughShards {
                needed: geometry.data(),
                found: votes,
            });
        }
        let mut damaged = Vec::new();
        let sources = slots
            .into_iter()
            .enumerate()
            .map(|(i, slot)| match slot {
                Some((header, source)) if header.len == len => Some(source),
                _ => {
                    damaged.push(i);
                    None
                }
            })
            .collect();
        Ok(Self {
            geometry,
            header: Header {
                id,
                index: 0,
                geometry,
                len,
            },
            sources,
            damaged,
            pos: 0,
            cached: None,
        })
    }

    /// The file's length.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.header.len
    }

    /// Whether the file is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.header.len == 0
    }

    /// The shards found missing or damaged so far (by index, in the order found).
    #[must_use]
    pub fn damaged(&self) -> &[usize] {
        &self.damaged
    }

    /// Reads the pieces of block `n` until `data` good ones are in hand: the data
    /// shards first, parity in place of any that fail.
    fn pieces(&mut self, n: u64) -> Result<Vec<Option<Vec<u8>>>> {
        let block_len = self.geometry.block_len(self.header.len, n);
        let piece_len = self.geometry.piece_len(block_len);
        let mut pieces: Vec<Option<Vec<u8>>> = vec![None; self.geometry.shards()];
        let mut found = 0;
        #[allow(clippy::needless_range_loop)] // `sources` and `pieces` both
        for i in 0..self.geometry.shards() {
            if found == self.geometry.data() {
                break;
            }
            let Some(source) = self.sources[i].as_mut() else {
                continue;
            };
            let header = Header {
                index: i,
                ..self.header
            };
            if let Ok(piece) = read_piece(source, &header, n, piece_len) {
                pieces[i] = Some(piece);
                found += 1;
            } else {
                self.sources[i] = None;
                self.damaged.push(i);
            }
        }
        if found < self.geometry.data() {
            return Err(Error::NotEnoughShards {
                needed: self.geometry.data(),
                found,
            });
        }
        Ok(pieces)
    }

    /// Block `n`'s bytes.
    fn block(&mut self, n: u64) -> Result<&[u8]> {
        if self.cached.as_ref().is_none_or(|(at, _)| *at != n) {
            let block_len = self.geometry.block_len(self.header.len, n);
            let pieces = self.pieces(n)?;
            self.cached = Some((n, self.geometry.decode(pieces, block_len)?));
        }
        Ok(self.cached.as_ref().map_or(&[][..], |(_, bytes)| bytes))
    }

    /// Writes shard `index` whole (header and every piece, rebuilt from the others) to
    /// `sink`: how a missing or damaged shard is healed.
    pub fn write_shard<W: Write>(&mut self, index: usize, sink: &mut W) -> Result<()> {
        if index >= self.geometry.shards() {
            return Err(Error::Geometry("no such shard"));
        }
        let header = Header {
            index,
            ..self.header
        };
        sink.write_all(&header.encode())?;
        for n in 0..self.geometry.blocks(self.header.len) {
            let mut pieces = self.pieces(n)?;
            self.geometry.rebuild(&mut pieces)?;
            let piece = pieces[index]
                .as_deref()
                .ok_or(Error::Codec("a rebuilt piece is missing".into()))?;
            sink.write_all(&header.piece_hash(n, piece))?;
            sink.write_all(piece)?;
        }
        sink.flush()?;
        Ok(())
    }
}

impl<S: Read + Seek> Read for Reader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.header.len || buf.is_empty() {
            return Ok(0);
        }
        let block = self.geometry.block() as u64;
        let (n, within) = (self.pos / block, self.pos % block);
        let bytes = self.block(n)?;
        let within = usize::try_from(within).map_err(io::Error::other)?;
        let take = (bytes.len() - within).min(buf.len());
        buf[..take].copy_from_slice(&bytes[within..within + take]);
        self.pos += take as u64;
        Ok(take)
    }
}

impl<S: Read + Seek> Seek for Reader<S> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(by) => self.header.len.checked_add_signed(by),
            SeekFrom::Current(by) => self.pos.checked_add_signed(by),
        };
        let Some(pos) = pos else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the file",
            ));
        };
        self.pos = pos;
        Ok(pos)
    }
}

/// Checks one shard file whole: its header (which must be file `id`'s, coded with
/// `geometry`) and every piece's hash. Its header, or why it's damaged.
pub fn verify<S: Read + Seek>(id: [u8; 16], geometry: Geometry, source: &mut S) -> Result<Header> {
    let header = read_header(source)?;
    if header.id != id {
        return Err(Error::Shard("another file's shard"));
    }
    if header.geometry != geometry {
        return Err(Error::Shard("a shard coded with another geometry"));
    }
    for n in 0..geometry.blocks(header.len) {
        let piece_len = geometry.piece_len(geometry.block_len(header.len, n));
        read_piece(source, &header, n, piece_len)?;
    }
    let end = source.seek(SeekFrom::End(0))?;
    if end != geometry.shard_file_len(header.len) {
        return Err(Error::Shard("bytes after the last piece"));
    }
    Ok(header)
}

fn read_header<S: Read + Seek>(source: &mut S) -> Result<Header> {
    let mut bytes = [0u8; HEADER_LEN];
    source.seek(SeekFrom::Start(0))?;
    source.read_exact(&mut bytes)?;
    Header::decode(&bytes)
}

/// Piece `n` of a shard, checked against its hash.
fn read_piece<S: Read + Seek>(
    source: &mut S,
    header: &Header,
    n: u64,
    piece_len: usize,
) -> Result<Vec<u8>> {
    source.seek(SeekFrom::Start(header.geometry.piece_offset(n)))?;
    let mut buf = vec![0u8; HASH_LEN + piece_len];
    source.read_exact(&mut buf)?;
    let piece = buf.split_off(HASH_LEN);
    if header.piece_hash(n, &piece)[..] != buf[..] {
        return Err(Error::Shard("a piece's hash doesn't match"));
    }
    Ok(piece)
}
