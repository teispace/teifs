//! SSE-C: keys the client sends with every request and TeiFS never stores.

use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result, hkdf};

/// A customer-provided 256-bit key. Wiped when dropped; never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CustomerKey([u8; 32]);

impl std::fmt::Debug for CustomerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustomerKey(…)")
    }
}

impl CustomerKey {
    /// Reads the SSE-C headers: the algorithm must be `AES256`, the key a base64 256-bit
    /// key, and the key MD5 its base64 MD5.
    pub fn parse(algorithm: &str, key: &str, key_md5: &str) -> Result<Self> {
        if algorithm != "AES256" {
            return Err(CryptoError::InvalidCustomerKey(
                "the algorithm must be AES256",
            ));
        }
        let bytes = zeroize::Zeroizing::new(
            STANDARD
                .decode(key)
                .map_err(|_| CryptoError::InvalidCustomerKey("the key isn't base64"))?,
        );
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidCustomerKey("the key must be 256 bits"))?;
        let key = Self(bytes);
        if STANDARD.decode(key_md5).ok().as_deref() != Some(key.md5().as_slice()) {
            return Err(CryptoError::InvalidCustomerKey(
                "the key MD5 doesn't match the key",
            ));
        }
        Ok(key)
    }

    fn md5(&self) -> [u8; 16] {
        Md5::digest(self.0).into()
    }

    /// The key's MD5 in base64, as S3 returns it.
    #[must_use]
    pub fn md5_base64(&self) -> String {
        STANDARD.encode(self.md5())
    }

    /// What's stored to recognize the key later: HMAC-SHA256 under a random salt.
    #[must_use]
    pub fn check(&self, salt: &[u8; 32]) -> [u8; 32] {
        use aws_lc_rs::hmac;
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, salt), &self.0);
        tag.as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
    }

    /// Fails unless this is the key whose check value was stored (constant time).
    pub fn verify(&self, salt: &[u8; 32], stored: &[u8]) -> Result<()> {
        use aws_lc_rs::hmac;
        hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, salt), &self.0, stored)
            .map_err(|_| CryptoError::WrongCustomerKey)
    }

    /// The key-encryption key that seals the object's data key.
    #[must_use]
    pub fn kek(&self, salt: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
        hkdf(&self.0, salt, &[b"teifs sse-c v1"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(key: &[u8; 32]) -> (String, String) {
        (STANDARD.encode(key), STANDARD.encode(Md5::digest(key)))
    }

    #[test]
    fn parses_valid_headers_only() {
        let (key, md5) = headers(&[7; 32]);
        let parsed = CustomerKey::parse("AES256", &key, &md5).unwrap();
        assert_eq!(parsed.md5_base64(), md5);
        assert_eq!(format!("{parsed:?}"), "CustomerKey(…)");

        assert!(CustomerKey::parse("aws:kms", &key, &md5).is_err());
        assert!(CustomerKey::parse("AES256", "!!", &md5).is_err());
        let (short, short_md5) = (
            STANDARD.encode([1; 16]),
            STANDARD.encode(Md5::digest([1; 16])),
        );
        assert!(CustomerKey::parse("AES256", &short, &short_md5).is_err());
        let (_, other_md5) = headers(&[8; 32]);
        assert!(CustomerKey::parse("AES256", &key, &other_md5).is_err());
    }

    #[test]
    fn verifies_the_same_key_only() {
        let (a, a_md5) = headers(&[7; 32]);
        let (b, b_md5) = headers(&[8; 32]);
        let a = CustomerKey::parse("AES256", &a, &a_md5).unwrap();
        let b = CustomerKey::parse("AES256", &b, &b_md5).unwrap();
        let salt = [9; 32];
        let stored = a.check(&salt);
        assert!(a.verify(&salt, &stored).is_ok());
        assert!(matches!(
            b.verify(&salt, &stored),
            Err(CryptoError::WrongCustomerKey)
        ));
        assert_ne!(*a.kek(&salt), *b.kek(&salt));
    }
}
