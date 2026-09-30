//! A part's bytes as 64 KiB authenticated packages (`docs/ENCRYPTION_FORMAT.md`):
//! package `i` of part `p` is AES-256-GCM under the part key with nonce `i` and AAD
//! `"TFS1" ‖ p ‖ i ‖ final`, stored as ciphertext then tag. Under DSSE-KMS each stored
//! package (ciphertext and tag) is encrypted again with AES-256-CTR under a key from a
//! second, independent data key, so sizes and offsets don't change.

use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce},
    cipher::{AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey},
    iv::FixedLength,
};

use crate::{CryptoError, DataKey, Result, aead_key};

/// Plaintext bytes per package (the last package of a part may be shorter).
pub const PACKAGE_SIZE: usize = 64 * 1024;
/// Bytes of authentication tag after each package.
pub const TAG_LEN: usize = 16;
/// A full package on disk.
const SEALED_PACKAGE_LEN: usize = PACKAGE_SIZE + TAG_LEN;
const SEALED_PACKAGE: u64 = SEALED_PACKAGE_LEN as u64;

/// How many packages `plain_len` bytes take (an empty part is one empty package).
#[must_use]
pub fn packages_for(plain_len: u64) -> u64 {
    plain_len.div_ceil(PACKAGE_SIZE as u64).max(1)
}

/// The encrypted size of `plain_len` bytes.
#[must_use]
pub fn ciphertext_len(plain_len: u64) -> u64 {
    plain_len + packages_for(plain_len) * TAG_LEN as u64
}

/// The plaintext size of `cipher_len` encrypted bytes; fails for a length no part can
/// have.
pub fn plaintext_len(cipher_len: u64) -> Result<u64> {
    let packages = cipher_len.div_ceil(SEALED_PACKAGE).max(1);
    let last = cipher_len
        .checked_sub((packages - 1) * SEALED_PACKAGE)
        .ok_or(CryptoError::Authentication)?;
    // Only an empty part has a final package with nothing in it.
    if last < TAG_LEN as u64 || (last == TAG_LEN as u64 && packages > 1) {
        return Err(CryptoError::Authentication);
    }
    Ok(cipher_len - packages * TAG_LEN as u64)
}

/// The AAD binding a package to its part, position and finality.
fn aad(part: u32, index: u64, last: bool) -> [u8; 17] {
    let mut out = [0u8; 17];
    out[..4].copy_from_slice(b"TFS1");
    out[4..8].copy_from_slice(&part.to_be_bytes());
    out[8..16].copy_from_slice(&index.to_be_bytes());
    out[16] = u8::from(last);
    out
}

fn nonce(index: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&index.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

/// The initial counter block of package `index`'s outer layer: the index, then a 64-bit
/// block counter from zero (a package is far fewer than 2^64 blocks).
fn counter(index: u64) -> FixedLength<16> {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&index.to_be_bytes());
    FixedLength::from(block)
}

/// The cipher of one part: encrypts it as a stream, or decrypts single packages.
pub struct PartCipher {
    key: LessSafeKey,
    /// DSSE-KMS's outer layer.
    outer: Option<EncryptingKey>,
    part: u32,
}

impl std::fmt::Debug for PartCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartCipher")
            .field("part", &self.part)
            .field("layers", &(1 + u8::from(self.outer.is_some())))
            .finish_non_exhaustive()
    }
}

impl PartCipher {
    /// The cipher of part `part` (1 for a single-part object) of an object.
    #[must_use]
    pub fn new(data_key: &DataKey, part: u32) -> Self {
        Self::layered(data_key, None, part)
    }

    /// Like [`PartCipher::new`], with DSSE-KMS's second layer under `outer` when given.
    #[must_use]
    pub fn layered(data_key: &DataKey, outer: Option<&DataKey>, part: u32) -> Self {
        Self {
            key: aead_key(&data_key.part_key(part)),
            outer: outer.map(|outer| {
                let key = UnboundCipherKey::new(&AES_256, outer.outer_part_key(part).as_ref())
                    .expect("a 32-byte AES-256 key");
                EncryptingKey::ctr(key).expect("AES-256-CTR is supported")
            }),
            part,
        }
    }

    /// Adds or removes the outer layer of package `index` (CTR is its own inverse).
    fn outer_layer(&self, index: u64, package: &mut [u8]) {
        if let Some(outer) = &self.outer {
            outer
                .less_safe_encrypt(package, EncryptionContext::Iv128(counter(index)))
                .expect("CTR encrypts any length");
        }
    }

    /// Starts encrypting the part from its first byte.
    #[must_use]
    pub fn encryptor(self) -> PartEncryptor {
        PartEncryptor {
            cipher: self,
            index: 0,
            pending: Vec::with_capacity(2 * PACKAGE_SIZE),
        }
    }

    /// Decrypts package `index` in place (`sealed` is its ciphertext and tag) and returns
    /// its plaintext. `last` says whether it's the part's final package.
    pub fn open<'a>(&self, index: u64, last: bool, sealed: &'a mut [u8]) -> Result<&'a mut [u8]> {
        if sealed.len() < TAG_LEN || sealed.len() > PACKAGE_SIZE + TAG_LEN {
            return Err(CryptoError::Authentication);
        }
        self.outer_layer(index, sealed);
        self.key
            .open_in_place(nonce(index), Aad::from(aad(self.part, index, last)), sealed)
            .map_err(|_| CryptoError::Authentication)
    }

    fn seal_into(&self, index: u64, last: bool, plain: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(plain);
        let tag = self
            .key
            .seal_in_place_separate_tag(
                nonce(index),
                Aad::from(aad(self.part, index, last)),
                &mut out[start..],
            )
            .expect("sealing a buffer can't fail");
        out.extend_from_slice(tag.as_ref());
        self.outer_layer(index, &mut out[start..]);
    }
}

/// Encrypts a part as its bytes arrive. A full package is held back until more bytes
/// come, because the last package must be marked final.
#[derive(Debug)]
pub struct PartEncryptor {
    cipher: PartCipher,
    index: u64,
    pending: Vec<u8>,
}

impl PartEncryptor {
    /// Adds plaintext; appends the packages it completes to `out`.
    pub fn update(&mut self, plain: &[u8], out: &mut Vec<u8>) {
        self.pending.extend_from_slice(plain);
        let mut done = 0;
        while self.pending.len() - done > PACKAGE_SIZE {
            let package = &self.pending[done..done + PACKAGE_SIZE];
            self.cipher.seal_into(self.index, false, package, out);
            self.index += 1;
            done += PACKAGE_SIZE;
        }
        self.pending.drain(..done);
    }

    /// Ends the part: appends its final package to `out`.
    pub fn finish(self, out: &mut Vec<u8>) {
        self.cipher.seal_into(self.index, true, &self.pending, out);
    }
}

/// Decrypts a whole part in memory (small objects and tests).
pub fn decrypt_part(
    data_key: &DataKey,
    outer: Option<&DataKey>,
    part: u32,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let cipher = PartCipher::layered(data_key, outer, part);
    let plain_len = plaintext_len(sealed.len() as u64)?;
    let packages = packages_for(plain_len);
    let mut out = Vec::with_capacity(usize::try_from(plain_len).unwrap_or(0));
    for (index, chunk) in (0..).zip(sealed.chunks(SEALED_PACKAGE_LEN)) {
        let mut buf = chunk.to_vec();
        out.extend_from_slice(cipher.open(index, index + 1 == packages, &mut buf)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt(key: &DataKey, part: u32, data: &[u8], chunk: usize) -> Vec<u8> {
        encrypt_layered(key, None, part, data, chunk)
    }

    fn encrypt_layered(
        key: &DataKey,
        outer: Option<&DataKey>,
        part: u32,
        data: &[u8],
        chunk: usize,
    ) -> Vec<u8> {
        let mut enc = PartCipher::layered(key, outer, part).encryptor();
        let mut out = Vec::new();
        for piece in data.chunks(chunk.max(1)) {
            enc.update(piece, &mut out);
        }
        enc.finish(&mut out);
        out
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i * 31 % 251).unwrap())
            .collect()
    }

    #[test]
    fn round_trips_every_boundary_and_chunking() {
        let key = DataKey::generate();
        for len in [
            0,
            1,
            PACKAGE_SIZE - 1,
            PACKAGE_SIZE,
            PACKAGE_SIZE + 1,
            3 * PACKAGE_SIZE + 7,
        ] {
            let data = pattern(len);
            for chunk in [1, 1000, PACKAGE_SIZE, 1 << 20] {
                if chunk == 1 && len > PACKAGE_SIZE + 1 {
                    continue;
                }
                let sealed = encrypt(&key, 1, &data, chunk);
                assert_eq!(
                    sealed.len() as u64,
                    ciphertext_len(len as u64),
                    "{len}/{chunk}"
                );
                assert_eq!(plaintext_len(sealed.len() as u64).unwrap(), len as u64);
                assert_eq!(
                    decrypt_part(&key, None, 1, &sealed).unwrap(),
                    data,
                    "{len}/{chunk}"
                );
            }
        }
    }

    #[test]
    fn lengths_that_no_part_has_are_refused() {
        assert!(plaintext_len(0).is_err());
        assert!(plaintext_len(15).is_err());
        assert_eq!(plaintext_len(16).unwrap(), 0);
        // A full package followed by an empty final package is never written.
        assert!(plaintext_len(SEALED_PACKAGE + 16).is_err());
        assert_eq!(plaintext_len(SEALED_PACKAGE).unwrap(), PACKAGE_SIZE as u64);
    }

    #[test]
    fn tampering_reordering_truncation_and_splicing_fail() {
        let key = DataKey::generate();
        let data = pattern(3 * PACKAGE_SIZE);
        let sealed = encrypt(&key, 1, &data, 4096);
        let p = SEALED_PACKAGE_LEN;

        let mut flipped = sealed.clone();
        flipped[100] ^= 1;
        assert!(decrypt_part(&key, None, 1, &flipped).is_err());

        let mut swapped = sealed.clone();
        swapped[..p].copy_from_slice(&sealed[p..2 * p]);
        swapped[p..2 * p].copy_from_slice(&sealed[..p]);
        assert!(decrypt_part(&key, None, 1, &swapped).is_err());

        // Dropping the final package: what's left isn't a complete part.
        assert!(decrypt_part(&key, None, 1, &sealed[..2 * p]).is_err());

        // The same bytes under another part number or key.
        assert!(decrypt_part(&key, None, 2, &sealed).is_err());
        assert!(decrypt_part(&DataKey::generate(), None, 1, &sealed).is_err());

        // A package moved from another part with the same key.
        let other = encrypt(&key, 2, &data, 4096);
        let mut spliced = sealed.clone();
        spliced[p..2 * p].copy_from_slice(&other[p..2 * p]);
        assert!(decrypt_part(&key, None, 1, &spliced).is_err());
    }

    #[test]
    fn single_packages_open_for_range_reads() {
        let key = DataKey::generate();
        let data = pattern(2 * PACKAGE_SIZE + 10);
        let sealed = encrypt(&key, 1, &data, 777);
        let cipher = PartCipher::new(&key, 1);
        let p = SEALED_PACKAGE_LEN;
        let mut second = sealed[p..2 * p].to_vec();
        assert_eq!(
            cipher.open(1, false, &mut second).unwrap(),
            &data[PACKAGE_SIZE..2 * PACKAGE_SIZE]
        );
        let mut last = sealed[2 * p..].to_vec();
        assert_eq!(
            cipher.open(2, true, &mut last).unwrap(),
            &data[2 * PACKAGE_SIZE..]
        );
        // The wrong finality fails.
        let mut last = sealed[2 * p..].to_vec();
        assert!(cipher.open(2, false, &mut last).is_err());
    }

    #[test]
    fn dsse_adds_a_second_layer_that_needs_its_own_key() {
        let (key, outer) = (DataKey::generate(), DataKey::generate());
        let data = pattern(2 * PACKAGE_SIZE + 10);
        let single = encrypt(&key, 1, &data, 5000);
        let dual = encrypt_layered(&key, Some(&outer), 1, &data, 5000);
        let p = SEALED_PACKAGE_LEN;
        assert_eq!(dual.len(), single.len());
        assert_eq!(decrypt_part(&key, Some(&outer), 1, &dual).unwrap(), data);
        // The inner layer isn't visible: no stored package matches the single layer's.
        for (a, b) in single.chunks(p).zip(dual.chunks(p)) {
            assert_ne!(a, b);
        }
        // Each package, and each part, has a keystream of its own.
        let stream = |a: &[u8], b: &[u8]| a.iter().zip(b).map(|(x, y)| x ^ y).collect::<Vec<_>>();
        let same = vec![9u8; 2 * PACKAGE_SIZE];
        let (plain1, dual1) = (
            encrypt(&key, 1, &same, 5000),
            encrypt_layered(&key, Some(&outer), 1, &same, 5000),
        );
        let (plain2, dual2) = (
            encrypt(&key, 2, &same, 5000),
            encrypt_layered(&key, Some(&outer), 2, &same, 5000),
        );
        let first = stream(&plain1[..p], &dual1[..p]);
        assert_ne!(first, stream(&plain1[p..2 * p], &dual1[p..2 * p]));
        assert_ne!(first, stream(&plain2[..p], &dual2[..p]));
        // Either key alone, the layers swapped, or another outer key fails.
        assert!(decrypt_part(&key, None, 1, &dual).is_err());
        assert!(decrypt_part(&outer, None, 1, &dual).is_err());
        assert!(decrypt_part(&outer, Some(&key), 1, &dual).is_err());
        assert!(decrypt_part(&key, Some(&DataKey::generate()), 1, &dual).is_err());
        assert!(decrypt_part(&key, Some(&outer), 2, &dual).is_err());
        // Packages keep their places, and open one at a time for range reads.
        let mut swapped = dual.clone();
        swapped[..p].copy_from_slice(&dual[p..2 * p]);
        swapped[p..2 * p].copy_from_slice(&dual[..p]);
        assert!(decrypt_part(&key, Some(&outer), 1, &swapped).is_err());
        let cipher = PartCipher::layered(&key, Some(&outer), 1);
        let mut second = dual[p..2 * p].to_vec();
        assert_eq!(
            cipher.open(1, false, &mut second).unwrap(),
            &data[PACKAGE_SIZE..2 * PACKAGE_SIZE]
        );
        let mut last = dual[2 * p..].to_vec();
        assert_eq!(
            cipher.open(2, true, &mut last).unwrap(),
            &data[2 * PACKAGE_SIZE..]
        );
    }

    #[test]
    fn ciphertext_never_contains_the_plaintext() {
        let key = DataKey::generate();
        let data = b"a secret sentence that must not appear on disk".repeat(4000);
        let sealed = encrypt(&key, 1, &data, 8192);
        assert!(!sealed.windows(24).any(|w| w == &data[..24]));
    }
}

#[cfg(test)]
mod bench {
    use super::*;

    /// `cargo test --release -p teifs-crypto -- --ignored --nocapture throughput`
    #[test]
    #[ignore = "a measurement, not a check"]
    fn throughput() {
        let key = DataKey::generate();
        let chunk = vec![5u8; 1 << 20];
        let total = 2u64 << 30;
        let mut enc = PartCipher::new(&key, 1).encryptor();
        let mut out = Vec::with_capacity(2 << 20);
        let start = std::time::Instant::now();
        for _ in 0..total >> 20 {
            enc.update(&chunk, &mut out);
            out.clear();
        }
        enc.finish(&mut out);
        let secs = start.elapsed().as_secs_f64();
        #[allow(clippy::cast_precision_loss, reason = "a report")]
        let mib = total as f64 / 1_048_576.0;
        println!("encrypt: {:.0} MiB/s", mib / secs);
    }
}
