//! Erasure coding for TeiFS's drive sets (`docs/ON_DISK_FORMAT.md`, "Shard files").
//!
//! A file is cut into blocks of [`Geometry::block`] bytes; each block is split into
//! `data` equal pieces (the last zero-padded) and Reed-Solomon coded into `parity` more
//! (GF(2^16), [`reed_solomon_simd`]). Piece `i` of every block goes to shard file `i`,
//! after a [`Header`], each piece after its XXH3-128 hash, so a damaged piece is found
//! before it's used. Any `data` of the `data + parity` shards give the file back.
//!
//! This crate only codes bytes: where shard files live, how they're synced and which
//! drives are up is the store's business.

mod geometry;
mod read;
mod shard;
mod write;

pub use geometry::Geometry;
pub use read::{Reader, verify};
pub use shard::{HASH_LEN, HEADER_LEN, Header};
pub use write::encode;

/// What erasure coding can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A geometry the code can't have.
    #[error("invalid erasure geometry: {0}")]
    Geometry(&'static str),
    /// A shard file that isn't one, or not of this file.
    #[error("not a shard of this file: {0}")]
    Shard(&'static str),
    /// Fewer good shards than the file needs.
    #[error("only {found} of the {needed} shards needed are readable")]
    NotEnoughShards {
        /// Shards needed (the geometry's `data`).
        needed: usize,
        /// Good shards found.
        found: usize,
    },
    /// Reed-Solomon refused the shards (a bug: they're checked first).
    #[error("erasure coding failed: {0}")]
    Codec(String),
    /// Reading or writing failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(err) => err,
            Error::Shard(_) => Self::new(std::io::ErrorKind::InvalidData, err),
            other => Self::other(other),
        }
    }
}

/// What this crate's functions return.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
