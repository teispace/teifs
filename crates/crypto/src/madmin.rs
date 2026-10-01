//! The encryption MinIO's admin API puts around secrets in request and response bodies
//! (madmin-go's `EncryptData` and `DecryptData`), with the caller's secret key as the
//! password: a 32-byte salt, an algorithm id, an 8-byte nonce, then the data as sio-go's
//! stream of 16 KiB fragments, each sealed on its own.
//!
//! The key is Argon2id of the password (1 pass, 64 MiB, 4 lanes; ids 0 for AES-256-GCM
//! and 1 for ChaCha20-Poly1305) or, in MinIO's FIPS builds, PBKDF2-HMAC-SHA256 with 8192
//! rounds (id 2, AES-256-GCM). Each fragment's nonce is the 8-byte nonce and its sequence
//! number (from 1, little endian); its associated data is a flag (`0x80` on the last
//! fragment, else `0`) and the tag of nothing sealed under sequence number 0, which binds
//! the fragments to the stream.

use std::{num::NonZeroU32, sync::Mutex};

use aws_lc_rs::aead::{AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::CryptoError;

const SALT: usize = 32;
const NONCE: usize = 8;
const TAG: usize = 16;
/// The plaintext of every fragment but the last.
const FRAGMENT: usize = 1 << 14;

const ARGON2ID_AES_GCM: u8 = 0;
const ARGON2ID_CHACHA20_POLY1305: u8 = 1;
const PBKDF2_AES_GCM: u8 = 2;

/// Argon2id takes 64 MiB at a time: one derivation runs at once, as in madmin-go, so
/// concurrent admin calls can't add up to much memory.
static ARGON2: Mutex<()> = Mutex::new(());

/// Whether `data` starts as encrypted data does (it's longer than a salt, and the
/// algorithm id after the salt is one of madmin's).
#[must_use]
pub fn is_encrypted(data: &[u8]) -> bool {
    data.get(SALT).is_some_and(|id| {
        matches!(
            *id,
            ARGON2ID_AES_GCM | ARGON2ID_CHACHA20_POLY1305 | PBKDF2_AES_GCM
        )
    })
}

/// `data` encrypted for `password` (Argon2id and AES-256-GCM, as madmin-go encrypts on
/// machines with AES instructions).
#[must_use]
pub fn encrypt(password: &str, data: &[u8]) -> Vec<u8> {
    let salt = crate::random_salt();
    let mut nonce = [0; NONCE];
    crate::random(&mut nonce);
    let cipher = cipher(ARGON2ID_AES_GCM, password, &salt)
        .expect("Argon2id and AES-256-GCM take a 32-byte key");
    let fragments = data.len().div_ceil(FRAGMENT).max(1);
    let mut out = Vec::with_capacity(SALT + 1 + NONCE + data.len() + fragments * TAG);
    out.extend_from_slice(&salt);
    out.push(ARGON2ID_AES_GCM);
    out.extend_from_slice(&nonce);
    let mut ad = associated_data(&cipher, nonce);
    // Empty data is still one (empty) last fragment.
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[]]
    } else {
        data.chunks(FRAGMENT).collect()
    };
    let last = chunks.len() - 1;
    for (seq, (i, chunk)) in (1..).zip(chunks.iter().enumerate()) {
        if i == last {
            ad[0] = 0x80;
        }
        let mut fragment = chunk.to_vec();
        cipher
            .seal_in_place_append_tag(fragment_nonce(nonce, seq), Aad::from(&ad), &mut fragment)
            .expect("a fragment is far shorter than AES-GCM's limit");
        out.extend_from_slice(&fragment);
    }
    out
}

/// The data `encrypted` holds, if `password` opens it: any other password, a changed,
/// reordered or shortened stream, or an unknown algorithm is
/// [`CryptoError::Authentication`].
pub fn decrypt(password: &str, encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if encrypted.len() < SALT + 1 + NONCE + TAG {
        return Err(CryptoError::Authentication);
    }
    let (salt, rest) = encrypted.split_at(SALT);
    let (id, rest) = rest.split_at(1);
    let (nonce, mut rest) = rest.split_at(NONCE);
    let nonce: [u8; NONCE] = nonce.try_into().expect("split at the nonce's length");
    let cipher = cipher(id[0], password, salt)?;
    let mut ad = associated_data(&cipher, nonce);
    let mut out = Zeroizing::new(Vec::with_capacity(rest.len()));
    let mut seq = 1;
    loop {
        // A fragment is the last when nothing follows it, even a full one.
        let last = rest.len() <= FRAGMENT + TAG;
        let (fragment, after) = rest.split_at(if last { rest.len() } else { FRAGMENT + TAG });
        if last {
            ad[0] = 0x80;
        }
        let mut fragment = Zeroizing::new(fragment.to_vec());
        let plain = cipher
            .open_in_place(fragment_nonce(nonce, seq), Aad::from(&ad), &mut fragment)
            .map_err(|_| CryptoError::Authentication)?;
        out.extend_from_slice(plain);
        if last {
            return Ok(out);
        }
        rest = after;
        seq += 1;
    }
}

/// The cipher of algorithm `id`, keyed from `password` and `salt`.
fn cipher(id: u8, password: &str, salt: &[u8]) -> Result<LessSafeKey, CryptoError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let algorithm = match id {
        ARGON2ID_AES_GCM | ARGON2ID_CHACHA20_POLY1305 => {
            let params = argon2::Params::new(64 * 1024, 1, 4, Some(key.len()))
                .expect("madmin's Argon2id parameters are valid");
            let argon2 =
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let _one = ARGON2
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            argon2
                .hash_password_into(password.as_bytes(), salt, key.as_mut())
                .map_err(|_| CryptoError::Authentication)?;
            if id == ARGON2ID_AES_GCM {
                &AES_256_GCM
            } else {
                &CHACHA20_POLY1305
            }
        }
        PBKDF2_AES_GCM => {
            aws_lc_rs::pbkdf2::derive(
                aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
                NonZeroU32::new(8192).expect("not zero"),
                salt,
                password.as_bytes(),
                key.as_mut(),
            );
            &AES_256_GCM
        }
        _ => return Err(CryptoError::Authentication),
    };
    let key = UnboundKey::new(algorithm, key.as_ref()).map_err(|_| CryptoError::Authentication)?;
    Ok(LessSafeKey::new(key))
}

/// The nonce of fragment `seq`: the stream's nonce, then `seq` in little endian.
fn fragment_nonce(nonce: [u8; NONCE], seq: u32) -> Nonce {
    let mut bytes = [0; 12];
    bytes[..NONCE].copy_from_slice(&nonce);
    bytes[NONCE..].copy_from_slice(&seq.to_le_bytes());
    Nonce::assume_unique_for_key(bytes)
}

/// The fragments' associated data: a flag byte, then the tag of nothing sealed under
/// sequence number 0.
fn associated_data(cipher: &LessSafeKey, nonce: [u8; NONCE]) -> [u8; 1 + TAG] {
    let tag = cipher
        .seal_in_place_separate_tag(fragment_nonce(nonce, 0), Aad::empty(), &mut [])
        .expect("nothing is shorter than AES-GCM's limit");
    let mut ad = [0; 1 + TAG];
    ad[1..].copy_from_slice(tag.as_ref());
    ad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// madmin-go's own vectors (`encrypt_test.go`, Apache-2.0): each opens with its
    /// password.
    #[test]
    fn madmin_go_vectors_decrypt() {
        let vectors = [
            (
                "",
                "828aa81599df0651c0461adb82283e8b89956baee9f6e719947ef9cddc849028001dc9d3ac0938f66b07bacc9751437e1985f8a9763c240e81",
            ),
            (
                r#"xPl.8/rhR"Q_1xLt"#,
                "b5c016e93b84b473fc8a37af94936563630c36d6df1841d23a86ee51ca161f9e00ac19116b32f643ff6a56a212b265d8c56195bb0d12ce199e13dfdc5272f80c1564da2c6fc2fa18da91d8062de02af5cdafea491c6f3cae1f",
            ),
        ];
        for (password, data) in vectors {
            let data = hex(data);
            assert!(is_encrypted(&data));
            let plain = decrypt(password, &data).unwrap();
            assert_eq!(plain.len(), data.len() - SALT - 1 - NONCE - TAG);
            assert!(plain.iter().all(|b| *b == 0), "madmin-go encrypts zeros");
            assert!(matches!(
                decrypt("other", &data),
                Err(CryptoError::Authentication)
            ));
        }
    }

    #[test]
    fn round_trips_across_fragments_and_refuses_changes() {
        for len in [0, 1, FRAGMENT - 1, FRAGMENT, FRAGMENT + 1, 3 * FRAGMENT] {
            let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let encrypted = encrypt("secret", &data);
            assert_eq!(
                encrypted.len(),
                SALT + 1 + NONCE + len + len.div_ceil(FRAGMENT).max(1) * TAG
            );
            assert_eq!(*decrypt("secret", &encrypted).unwrap(), data, "{len}");
            assert!(decrypt("Secret", &encrypted).is_err());
            let mut changed = encrypted.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(decrypt("secret", &changed).is_err(), "{len}");
            if len > FRAGMENT {
                // Dropping the last fragment makes a full one the last: refused.
                let cut = SALT + 1 + NONCE + FRAGMENT + TAG;
                assert!(decrypt("secret", &encrypted[..cut]).is_err(), "{len}");
            }
        }
        assert!(decrypt("secret", &[0; SALT + 1 + NONCE + TAG - 1]).is_err());
        let mut unknown = encrypt("secret", b"x");
        unknown[SALT] = 3;
        assert!(!is_encrypted(&unknown));
        assert!(decrypt("secret", &unknown).is_err());
    }

    #[test]
    fn chacha_and_pbkdf2_streams_open() {
        // Made as madmin-go makes them without AES instructions, or in FIPS mode.
        for id in [ARGON2ID_CHACHA20_POLY1305, PBKDF2_AES_GCM] {
            let salt = [7; SALT];
            let nonce = [9; NONCE];
            let cipher = cipher(id, "pw", &salt).unwrap();
            let mut ad = associated_data(&cipher, nonce);
            ad[0] = 0x80;
            let mut body = b"hello".to_vec();
            cipher
                .seal_in_place_append_tag(fragment_nonce(nonce, 1), Aad::from(&ad), &mut body)
                .unwrap();
            let mut data = salt.to_vec();
            data.push(id);
            data.extend_from_slice(&nonce);
            data.extend_from_slice(&body);
            assert!(is_encrypted(&data));
            assert_eq!(*decrypt("pw", &data).unwrap(), b"hello");
        }
    }
}
