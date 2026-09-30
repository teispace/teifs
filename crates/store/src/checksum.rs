//! S3's additional checksums (CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, SHA-512, MD5,
//! XXHASH64, XXHASH3, XXHASH128), computed together in one pass: for requests that send
//! or ask for them, and to verify stored objects against the checksums kept with them.
//! Each digest is base64 of its bytes; integer digests (the CRCs and xxhashes) are
//! big-endian, as S3 sends them.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use md5::Digest as _;
use xxhash_rust::{xxh3::Xxh3, xxh64::Xxh64};

/// Every algorithm S3 names, as it names them.
pub const ALGORITHMS: [&str; 10] = [
    "CRC32",
    "CRC32C",
    "CRC64NVME",
    "SHA1",
    "SHA256",
    "SHA512",
    "MD5",
    "XXHASH64",
    "XXHASH3",
    "XXHASH128",
];

enum Digest {
    Crc32(crc_fast::Digest),
    Crc64(crc_fast::Digest),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Md5(md5::Md5),
    Xxh64(Xxh64),
    Xxh3(Box<Xxh3>),
    Xxh128(Box<Xxh3>),
}

impl Digest {
    fn new(algorithm: &str) -> Option<Self> {
        use crc_fast::CrcAlgorithm::{Crc32Iscsi, Crc32IsoHdlc, Crc64Nvme};
        Some(match algorithm {
            "CRC32" => Self::Crc32(crc_fast::Digest::new(Crc32IsoHdlc)),
            "CRC32C" => Self::Crc32(crc_fast::Digest::new(Crc32Iscsi)),
            "CRC64NVME" => Self::Crc64(crc_fast::Digest::new(Crc64Nvme)),
            "SHA1" => Self::Sha1(sha1::Sha1::new()),
            "SHA256" => Self::Sha256(sha2::Sha256::new()),
            "SHA512" => Self::Sha512(sha2::Sha512::new()),
            "MD5" => Self::Md5(md5::Md5::new()),
            "XXHASH64" => Self::Xxh64(Xxh64::new(0)),
            "XXHASH3" => Self::Xxh3(Box::default()),
            "XXHASH128" => Self::Xxh128(Box::default()),
            _ => return None,
        })
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Crc32(d) | Self::Crc64(d) => d.update(data),
            Self::Sha1(d) => d.update(data),
            Self::Sha256(d) => d.update(data),
            Self::Sha512(d) => d.update(data),
            Self::Md5(d) => d.update(data),
            Self::Xxh64(d) => d.update(data),
            Self::Xxh3(d) | Self::Xxh128(d) => d.update(data),
        }
    }

    fn finish(self) -> String {
        match self {
            Self::Crc32(d) => {
                let crc = u32::try_from(d.finalize() & u64::from(u32::MAX)).unwrap_or(0);
                STANDARD.encode(crc.to_be_bytes())
            }
            Self::Crc64(d) => STANDARD.encode(d.finalize().to_be_bytes()),
            Self::Sha1(d) => STANDARD.encode(d.finalize()),
            Self::Sha256(d) => STANDARD.encode(d.finalize()),
            Self::Sha512(d) => STANDARD.encode(d.finalize()),
            Self::Md5(d) => STANDARD.encode(d.finalize()),
            Self::Xxh64(d) => STANDARD.encode(d.digest().to_be_bytes()),
            Self::Xxh3(d) => STANDARD.encode(d.digest().to_be_bytes()),
            Self::Xxh128(d) => STANDARD.encode(d.digest128().to_be_bytes()),
        }
    }
}

/// Checksums of the same bytes under several algorithms at once.
#[derive(Default)]
pub struct Checksums(Vec<(&'static str, Digest)>);

impl std::fmt::Debug for Checksums {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name))
            .finish()
    }
}

impl Checksums {
    /// Whether S3 has an algorithm of this name.
    #[must_use]
    pub fn supports(algorithm: &str) -> bool {
        ALGORITHMS.contains(&algorithm)
    }

    /// Adds `algorithm` (once however often it's added); `false` if S3 has none of that
    /// name.
    pub fn add(&mut self, algorithm: &str) -> bool {
        let Some(name) = ALGORITHMS.iter().find(|&&a| a == algorithm) else {
            return false;
        };
        if !self.0.iter().any(|(n, _)| n == name) {
            let digest = Digest::new(name).expect("every listed algorithm has a digest");
            self.0.push((name, digest));
        }
        true
    }

    /// Whether no algorithm was added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Feeds bytes to every algorithm.
    pub fn update(&mut self, data: &[u8]) {
        for (_, digest) in &mut self.0 {
            digest.update(data);
        }
    }

    /// Each algorithm's checksum, base64, by name.
    #[must_use]
    pub fn finish(self) -> BTreeMap<String, String> {
        self.0
            .into_iter()
            .map(|(name, digest)| (name.to_owned(), digest.finish()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(algorithm: &str, data: &[u8]) -> String {
        let mut sums = Checksums::default();
        assert!(sums.add(algorithm));
        // In pieces, as a stream arrives.
        for piece in data.chunks(7) {
            sums.update(piece);
        }
        sums.finish().remove(algorithm).unwrap()
    }

    #[test]
    fn known_answers() {
        // Published check values ("123456789") and well-known digests.
        let check = b"123456789";
        let hex = |value: String| teifs_types::hex(&STANDARD.decode(value).unwrap());
        assert_eq!(hex(of("CRC32", check)), "cbf43926");
        assert_eq!(hex(of("CRC32C", check)), "e3069283");
        assert_eq!(hex(of("CRC64NVME", check)), "ae8b14860a799888");
        assert_eq!(
            hex(of("SHA1", b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(of("SHA256", b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(hex(of("SHA512", b"abc")).starts_with("ddaf35a193617aba"));
        assert_eq!(hex(of("MD5", b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(of("XXHASH64", b"")), "ef46db3751d8e999");
        assert_eq!(hex(of("XXHASH3", b"")), "2d06800538d394c2");
        assert_eq!(
            hex(of("XXHASH128", b"")),
            "99aa06d3014798d86001c324468d497f"
        );
    }

    #[test]
    fn several_at_once_and_unknown_names() {
        let mut sums = Checksums::default();
        assert!(sums.is_empty());
        assert!(sums.add("CRC32") && sums.add("SHA256") && sums.add("CRC32"));
        assert!(!sums.add("CRC99") && !sums.add("crc32"));
        assert!(Checksums::supports("XXHASH3") && !Checksums::supports("BLAKE3"));
        sums.update(b"abc");
        let done = sums.finish();
        assert_eq!(done.len(), 2);
        assert_eq!(done["SHA256"], of("SHA256", b"abc"));
        assert_eq!(done["CRC32"], of("CRC32", b"abc"));
    }
}
