//! Sealing a data key under a key-encryption key, bound to a context. Each seal derives
//! a one-time key from the key-encryption key and a random salt, so the zero nonce is
//! never reused under one key and there's no limit on how many keys one KEK seals.

use aws_lc_rs::aead::{Aad, Nonce};
use serde::{Deserialize, Serialize};

use crate::{Context, CryptoError, DataKey, Result, aead_key, hkdf, random};

/// The sealed-key format this build writes.
const VERSION: u8 = 1;

/// A data key sealed under a key-encryption key, as stored with the object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedKey {
    /// The sealed-key format version.
    pub version: u8,
    /// Who sealed it: empty for TeiFS itself (a local keyring, or an SSE-C key),
    /// `transit` for a Vault or OpenBao transit engine.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider: String,
    /// The KMS key that sealed it (empty for SSE-C).
    pub kms_key: String,
    /// That key's version.
    pub kms_version: u32,
    /// The random salt of the one-time sealing key.
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    /// The sealed data key and its tag.
    #[serde(with = "b64")]
    pub sealed: Vec<u8>,
}

/// Seals `data_key` under `kek`, bound to `context`.
#[must_use]
pub fn seal(
    kek: &[u8; 32],
    context: &Context,
    data_key: &DataKey,
    kms_key: &str,
    kms_version: u32,
) -> SealedKey {
    let mut salt = [0u8; 32];
    random(&mut salt);
    let canonical = context.canonical();
    let key = aead_key(&hkdf(kek, &salt, &[b"teifs seal v1", &canonical]));
    let mut sealed = data_key.bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::from(canonical.as_slice()),
        &mut sealed,
    )
    .expect("sealing a buffer can't fail");
    SealedKey {
        version: VERSION,
        provider: String::new(),
        kms_key: kms_key.to_owned(),
        kms_version,
        salt: salt.to_vec(),
        sealed,
    }
}

/// Unseals a data key; fails unless `kek` and `context` are the ones it was sealed with.
pub fn unseal(kek: &[u8; 32], context: &Context, sealed: &SealedKey) -> Result<DataKey> {
    if sealed.version != VERSION {
        return Err(CryptoError::UnknownVersion(sealed.version));
    }
    if !sealed.provider.is_empty() {
        return Err(CryptoError::Kms(format!(
            "the key was sealed by {}, not by TeiFS",
            sealed.provider
        )));
    }
    let canonical = context.canonical();
    let key = aead_key(&hkdf(kek, &sealed.salt, &[b"teifs seal v1", &canonical]));
    let mut buf = zeroize::Zeroizing::new(sealed.sealed.clone());
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key([0; 12]),
            Aad::from(canonical.as_slice()),
            &mut buf,
        )
        .map_err(|_| CryptoError::Authentication)?;
    let bytes: [u8; 32] = plain.try_into().map_err(|_| CryptoError::Authentication)?;
    Ok(DataKey::from_bytes(bytes))
}

/// Serde for byte fields as base64.
mod b64 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn round_trips_only_with_the_same_key_and_context() {
        let ctx = Context::object("drive", "bucket", "object");
        let data = DataKey::generate();
        let sealed = seal(&kek(1), &ctx, &data, "teifs-default", 1);
        assert_eq!(unseal(&kek(1), &ctx, &sealed).unwrap(), data);

        assert!(unseal(&kek(2), &ctx, &sealed).is_err());
        let other = Context::object("drive", "bucket", "another");
        assert!(unseal(&kek(1), &other, &sealed).is_err());
        let extra = ctx.clone().with("app", "x");
        assert!(unseal(&kek(1), &extra, &sealed).is_err());
    }

    #[test]
    fn every_seal_is_different_and_tampering_fails() {
        let ctx = Context::object("d", "b", "o");
        let data = DataKey::generate();
        let a = seal(&kek(1), &ctx, &data, "k", 1);
        let b = seal(&kek(1), &ctx, &data, "k", 1);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.sealed, b.sealed);

        let mut bad = a.clone();
        bad.sealed[0] ^= 1;
        assert!(unseal(&kek(1), &ctx, &bad).is_err());
        let mut bad = a.clone();
        bad.salt[0] ^= 1;
        assert!(unseal(&kek(1), &ctx, &bad).is_err());
        let mut bad = a;
        bad.version = 9;
        assert!(matches!(
            unseal(&kek(1), &ctx, &bad),
            Err(CryptoError::UnknownVersion(9))
        ));
    }

    #[test]
    fn serializes_as_json_with_base64() {
        let sealed = seal(&kek(1), &Context::default(), &DataKey::generate(), "k", 3);
        let json = serde_json::to_string(&sealed).unwrap();
        assert!(json.contains("\"kmsVersion\":3"));
        let back: SealedKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sealed);
    }
}
