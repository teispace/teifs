//! Coding a file into its shard files.

use std::io::{self, Read, Write};

use crate::{Error, Geometry, Header, Result};

/// Codes the `len` bytes `src` gives into one shard file per writer in `sinks` (shard
/// `i` to `sinks[i]`; there must be one per shard). A writer that fails is dropped
/// (`None` from then on) and its error kept; the others carry on, so the caller can
/// decide whether enough shards were written. Fails only when `src` does (or ends
/// early).
///
/// Writes only: syncing and putting the files in place is the caller's.
pub fn encode<R: Read, W: Write>(
    geometry: Geometry,
    id: [u8; 16],
    len: u64,
    src: &mut R,
    sinks: &mut [Option<W>],
) -> Result<Vec<Option<io::Error>>> {
    if sinks.len() != geometry.shards() {
        return Err(Error::Geometry("one writer per shard is needed"));
    }
    let mut errors: Vec<Option<io::Error>> = (0..sinks.len()).map(|_| None).collect();
    let headers: Vec<Header> = (0..geometry.shards())
        .map(|index| Header {
            id,
            index,
            geometry,
            len,
        })
        .collect();
    for (i, sink) in sinks.iter_mut().enumerate() {
        put(sink, &mut errors[i], &[&headers[i].encode()]);
    }
    let mut block = vec![
        0u8;
        geometry
            .block()
            .min(usize::try_from(len).unwrap_or(usize::MAX))
    ];
    for n in 0..geometry.blocks(len) {
        let block_len = geometry.block_len(len, n);
        let block = &mut block[..block_len];
        src.read_exact(block)?;
        let pieces = geometry.encode(block)?;
        for (i, (sink, piece)) in sinks.iter_mut().zip(&pieces).enumerate() {
            if sink.is_some() {
                let hash = headers[i].piece_hash(n, piece);
                put(sink, &mut errors[i], &[&hash, piece]);
            }
        }
        if sinks.iter().all(Option::is_none) {
            break;
        }
    }
    for (sink, error) in sinks.iter_mut().zip(&mut errors) {
        if let Some(w) = sink
            && let Err(err) = w.flush()
        {
            *error = Some(err);
            *sink = None;
        }
    }
    Ok(errors)
}

/// Writes `parts` to `sink`, dropping it on an error.
fn put<W: Write>(sink: &mut Option<W>, error: &mut Option<io::Error>, parts: &[&[u8]]) {
    let Some(w) = sink else { return };
    for part in parts {
        if let Err(err) = w.write_all(part) {
            *error = Some(err);
            *sink = None;
            return;
        }
    }
}
