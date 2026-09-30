//! NATS's user keys: a seed (`SU…`) signs the server's nonce with Ed25519, alone or with
//! a user JWT from a `.creds` file, as `nsc` writes them.

use std::fmt;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use zeroize::Zeroizing;

/// The type byte of an encoded seed.
const SEED: u8 = 18 << 3;
/// The type byte of an encoded user key.
const USER: u8 = 20 << 3;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A NATS user's key, and the JWT it goes with, if any.
pub struct UserKey {
    pair: Ed25519KeyPair,
    /// The public key, `U…`.
    pub public: String,
    /// The user JWT from a `.creds` file; none for a key alone.
    pub jwt: Option<String>,
}

impl UserKey {
    /// The key in `text`: a `.creds` file (a user JWT then its seed, each between
    /// `-----` lines) or a file holding a user seed.
    ///
    /// # Errors
    ///
    /// When it holds no user seed, the seed is damaged, or the JWT is for another user.
    pub fn parse(text: &str) -> Result<Self, String> {
        let blocks = blocks(text);
        let (jwt, seed) = match blocks.as_slice() {
            [jwt, seed, ..] => (Some(*jwt), *seed),
            _ => (
                None,
                text.lines()
                    .map(str::trim)
                    .find(|line| line.starts_with('S'))
                    .ok_or("it holds no NATS seed")?,
            ),
        };
        let key = Self::from_seed(seed)?;
        let Some(jwt) = jwt else {
            return Ok(key);
        };
        let payload = jwt
            .split('.')
            .nth(1)
            .and_then(|p| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(p)
                    .ok()
            })
            .and_then(|p| serde_json::from_slice::<serde_json::Value>(&p).ok())
            .ok_or("its JWT isn't a NATS user JWT")?;
        if payload["sub"].as_str() != Some(key.public.as_str()) {
            return Err("its JWT is for another user than its seed".to_owned());
        }
        Ok(Self {
            jwt: Some(jwt.to_owned()),
            ..key
        })
    }

    /// The key of a user seed, `SU…`.
    fn from_seed(seed: &str) -> Result<Self, String> {
        let raw = Zeroizing::new(decode(seed).ok_or("its seed is damaged")?);
        let kind = ((raw[0] & 7) << 5) | ((raw[1] & 0xf8) >> 3);
        if raw[0] & 0xf8 != SEED || raw.len() != 34 {
            return Err("its seed is damaged".to_owned());
        }
        if kind != USER {
            return Err("its seed isn't a user's (`SU…`)".to_owned());
        }
        let pair = Ed25519KeyPair::from_seed_unchecked(&raw[2..])
            .map_err(|_| "its seed is damaged".to_owned())?;
        let public = encode(USER, pair.public_key().as_ref());
        Ok(Self {
            pair,
            public,
            jwt: None,
        })
    }

    /// The signature of the server's `nonce`, as `CONNECT`'s `sig`.
    #[must_use]
    pub fn sign(&self, nonce: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.pair.sign(nonce.as_bytes()).as_ref())
    }
}

impl fmt::Debug for UserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserKey")
            .field("public", &self.public)
            .field("jwt", &self.jwt.is_some())
            .finish_non_exhaustive()
    }
}

/// Whether `sig` is the user key `public`'s signature of `nonce`, as a server checks.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn verifies(public: &str, nonce: &str, sig: &str) -> bool {
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
    let Some(raw) = decode(public) else {
        return false;
    };
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig)
        .unwrap_or_default();
    raw.first() == Some(&USER)
        && UnparsedPublicKey::new(&ED25519, &raw[1..])
            .verify(nonce.as_bytes(), &sig)
            .is_ok()
}

/// The lines each alone between two `---` lines.
fn blocks(text: &str) -> Vec<&str> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let fence = |line: &str| line.len() >= 6 && line.starts_with("---") && line.ends_with("---");
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < lines.len() {
        if fence(lines[i]) && !fence(lines[i + 1]) && fence(lines[i + 2]) {
            out.push(lines[i + 1]);
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

/// `bytes` with the type byte `prefix` and a checksum, in base32.
fn encode(prefix: u8, bytes: &[u8]) -> String {
    let mut raw = Vec::with_capacity(bytes.len() + 3);
    raw.push(prefix);
    raw.extend_from_slice(bytes);
    raw.extend_from_slice(&crc16(&raw).to_le_bytes());
    let mut out = String::with_capacity(raw.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in raw {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The bytes of a base32 key or seed, its checksum checked and removed.
fn decode(text: &str) -> Option<Vec<u8>> {
    let mut raw = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c)?;
        buffer = ((buffer << 5) | u32::try_from(value).ok()?) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    if raw.len() < 4 {
        return None;
    }
    let checksum = raw.split_off(raw.len() - 2);
    (crc16(&raw).to_le_bytes() == checksum[..]).then_some(raw)
}

/// CRC-16/XMODEM, as NATS's keys carry.
fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |crc, &byte| {
        (0..8).fold(crc ^ (u16::from(byte) << 8), |crc, _| {
            if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x1021
            }
        })
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testing::{NKEY_JWT as JWT, NKEY_PUBLIC as PUBLIC, NKEY_SEED as SEED, creds};

    #[test]
    fn a_seed_gives_its_public_key_and_signs() {
        let key = UserKey::parse(SEED).unwrap();
        assert_eq!(key.public, PUBLIC);
        assert!(key.jwt.is_none());
        let sig = key.sign("nonce-from-the-server");
        assert!(verifies(PUBLIC, "nonce-from-the-server", &sig));
        assert!(!verifies(PUBLIC, "another nonce", &sig));
        assert!(!format!("{key:?}").contains(SEED));
    }

    #[test]
    fn a_creds_file_gives_its_jwt_and_key() {
        let key = UserKey::parse(&creds()).unwrap();
        assert_eq!(
            (key.jwt.as_deref(), key.public.as_str()),
            (Some(JWT), PUBLIC)
        );
    }

    #[test]
    fn damaged_or_foreign_keys_are_refused() {
        let mut damaged = SEED.to_owned();
        damaged.replace_range(10..11, if &SEED[10..11] == "A" { "B" } else { "A" });
        let other_user = encode_seed(USER, &[7; 32]);
        let account = encode_seed(0, &[7; 32]);
        for (bad, why) in [
            ("", "no NATS seed"),
            ("hello", "no NATS seed"),
            (damaged.as_str(), "damaged"),
            (&SEED[..40], "damaged"),
            ("S1AB", "damaged"),
            (account.as_str(), "isn't a user's"),
        ] {
            let err = UserKey::parse(bad).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
        let foreign = creds().replace(SEED, &other_user);
        assert!(
            UserKey::parse(&foreign)
                .unwrap_err()
                .contains("another user")
        );
        let broken = creds().replace(JWT, "not-a-jwt");
        assert!(
            UserKey::parse(&broken)
                .unwrap_err()
                .contains("isn't a NATS user JWT")
        );
    }

    #[test]
    fn keys_encode_as_nats_does() {
        assert_eq!(crc16(b"123456789"), 0x31c3, "CRC-16/XMODEM's check value");
        let public = encode(USER, &[0; 32]);
        assert!(public.starts_with('U') && public.len() == 56, "{public}");
        assert_eq!(decode(&public).unwrap()[1..], [0; 32]);
        assert!(encode_seed(USER, &[1; 32]).starts_with("SU"));
    }

    /// A seed for `kind`'s key, as `nkeys` encodes one.
    pub(crate) fn encode_seed(kind: u8, seed: &[u8; 32]) -> String {
        let mut raw = vec![SEED_BYTE | (kind >> 5), (kind & 31) << 3];
        raw.extend_from_slice(seed);
        encode(raw[0], &raw[1..])
    }

    const SEED_BYTE: u8 = super::SEED;
    pub(crate) const USER_BYTE: u8 = USER;
}
