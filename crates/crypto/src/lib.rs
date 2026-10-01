//! TeiFS's encryption at rest, as specified in `docs/ENCRYPTION_FORMAT.md`:
//!
//! - a random [`DataKey`] per object, from which each part's key is derived;
//! - [`seal`] / [`unseal`], which wrap a data key under a key-encryption key and bind it
//!   to a [`Context`];
//! - [`PartCipher`], which turns a part's bytes into 64 KiB authenticated packages
//!   ([`PartEncryptor`]) and opens single packages for range reads;
//! - [`CustomerKey`] for SSE-C, and the [`Kms`] trait with a [`LocalKms`] keyring.
//!
//! All primitives come from aws-lc-rs.

mod aws_kms;
mod context;
mod customer;
mod error;
mod kes;
mod key;
mod kms;
mod package;
mod private;
mod seal;
mod tls;
mod transit;

pub use aws_kms::{AWS_KMS, AwsKms};
pub use context::Context;
pub use customer::CustomerKey;
pub use error::CryptoError;
pub use kes::{KES, KesAuth, KesKms};
pub use key::DataKey;
pub use kms::{DEFAULT_KEY, DefaultKeyNamed, KeyInfo, Kms, LocalKms};
pub use package::{
    PACKAGE_SIZE, PartCipher, PartEncryptor, PartId, TAG_LEN, ciphertext_len, decrypt_part,
    packages_for, plaintext_len,
};
pub use private::{create_private, replace_private};
pub use seal::{SealedKey, seal, unseal};
pub use tls::tls_config;
pub use transit::{TRANSIT, TransitKms};

/// A crypto result.
pub type Result<T, E = CryptoError> = std::result::Result<T, E>;

/// 32 random bytes from the operating system (salts).
#[must_use]
pub fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    random(&mut salt);
    salt
}

/// Fills `out` with random bytes from the operating system.
pub(crate) fn random(out: &mut [u8]) {
    aws_lc_rs::rand::fill(out).expect("the operating system provides randomness");
}

/// HKDF-SHA256 into a 32-byte key.
pub(crate) fn hkdf(ikm: &[u8], salt: &[u8], info: &[&[u8]]) -> zeroize::Zeroizing<[u8; 32]> {
    use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
    struct Len32;
    impl KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    Salt::new(HKDF_SHA256, salt)
        .extract(ikm)
        .expand(info, Len32)
        .and_then(|okm| okm.fill(out.as_mut()))
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// An AES-256-GCM key.
pub(crate) fn aead_key(key: &[u8; 32]) -> aws_lc_rs::aead::LessSafeKey {
    use aws_lc_rs::aead::{AES_256_GCM, LessSafeKey, UnboundKey};
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte AES-256 key"))
}
