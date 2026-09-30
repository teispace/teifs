//! An object's data key, and what's derived from it.

use aws_lc_rs::aead::{Aad, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result, aead_key, hkdf, random};

/// An object's random 256-bit data key. Wiped from memory when dropped; never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; 32]);

/// Compares in constant time.
impl PartialEq for DataKey {
    fn eq(&self, other: &Self) -> bool {
        aws_lc_rs::constant_time::verify_slices_are_equal(&self.0, &other.0).is_ok()
    }
}

impl Eq for DataKey {}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(…)")
    }
}

impl DataKey {
    /// A new random key.
    #[must_use]
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        random(&mut key);
        Self(key)
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key that encrypts part `part` (1 for a single-part object).
    pub(crate) fn part_key(&self, part: u32) -> zeroize::Zeroizing<[u8; 32]> {
        hkdf(&self.0, &[], &[b"teifs data v1", &part.to_be_bytes()])
    }

    /// The key of DSSE-KMS's outer layer over part `part`, when this is the object's
    /// second data key.
    pub(crate) fn outer_part_key(&self, part: u32) -> zeroize::Zeroizing<[u8; 32]> {
        hkdf(&self.0, &[], &[b"teifs dsse v1", &part.to_be_bytes()])
    }

    /// The ETag of an SSE-C or SSE-KMS object: a keyed hash of its MD5, so it's stable
    /// but doesn't reveal the plaintext's MD5 to anyone without the key.
    #[must_use]
    pub fn etag_for(&self, md5: &[u8; 16]) -> [u8; 16] {
        use aws_lc_rs::hmac;
        let tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &self.0),
            &[b"teifs etag v1".as_slice(), md5].concat(),
        );
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag.as_ref()[..16]);
        out
    }

    /// Encrypts small metadata (checksums) with this key: a random nonce in front.
    #[must_use]
    pub fn seal_metadata(&self, plaintext: &[u8]) -> Vec<u8> {
        self.seal_labeled(META, &[], plaintext)
    }

    /// Decrypts what [`DataKey::seal_metadata`] produced.
    pub fn open_metadata(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        self.open_labeled(META, &[], sealed)
    }

    /// Encrypts a secret (an access key's secret key) bound to `owner` (its access key
    /// id): opening it under any other owner fails, so sealed secrets can't be swapped.
    #[must_use]
    pub fn seal_secret(&self, owner: &[u8], secret: &[u8]) -> Vec<u8> {
        self.seal_labeled(SECRET, owner, secret)
    }

    /// Decrypts what [`DataKey::seal_secret`] produced for the same `owner`.
    pub fn open_secret(&self, owner: &[u8], sealed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.open_labeled(SECRET, owner, sealed)
            .map(zeroize::Zeroizing::new)
    }

    /// Seals a session token's claims bound to `owner` (the session's access key id):
    /// opening it under any other owner fails, so a token works only with its own key.
    /// Each owner's tokens get a key of their own, so however many are issued, random
    /// nonces never approach AES-GCM's limit for one key.
    #[must_use]
    pub fn seal_token(&self, owner: &[u8], claims: &[u8]) -> Vec<u8> {
        seal(
            &aead_key(&hkdf(&self.0, &[], &[TOKEN, owner])),
            owner,
            claims,
        )
    }

    /// Opens what [`DataKey::seal_token`] sealed for the same `owner`.
    pub fn open_token(&self, owner: &[u8], sealed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        open(
            &aead_key(&hkdf(&self.0, &[], &[TOKEN, owner])),
            owner,
            sealed,
        )
        .map(zeroize::Zeroizing::new)
    }

    /// The secret of the temporary access key `id`: an HMAC of the id under a key
    /// derived for session secrets, so it's never stored and is the same wherever this
    /// key is (every request can find it again from the id alone).
    #[must_use]
    pub fn session_secret(&self, id: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
        use aws_lc_rs::hmac;
        let key = hkdf(&self.0, &[], &[SESSION_SECRET]);
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()), id);
        let mut out = zeroize::Zeroizing::new([0u8; 32]);
        out.copy_from_slice(tag.as_ref());
        out
    }

    /// AES-256-GCM under a key derived for `label`, with a random nonce in front.
    fn seal_labeled(&self, label: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        seal(&aead_key(&hkdf(&self.0, &[], &[label])), aad, plaintext)
    }

    fn open_labeled(&self, label: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        open(&aead_key(&hkdf(&self.0, &[], &[label])), aad, sealed)
    }
}

/// AES-256-GCM under `key`, with a random nonce in front.
fn seal(key: &aws_lc_rs::aead::LessSafeKey, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    random(&mut nonce);
    let mut out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut out,
    )
    .expect("sealing a buffer can't fail");
    [nonce.as_slice(), &out].concat()
}

/// Opens what [`seal`] sealed under the same `key` and `aad`.
fn open(key: &aws_lc_rs::aead::LessSafeKey, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let (nonce, body) = sealed
        .split_at_checked(12)
        .ok_or(CryptoError::Authentication)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::Authentication)?;
    let mut body = body.to_vec();
    let plain = key
        .open_in_place(nonce, Aad::from(aad), &mut body)
        .map_err(|_| CryptoError::Authentication)?;
    let len = plain.len();
    body.truncate(len);
    Ok(body)
}

/// The derivation labels: each use of a data key gets its own AEAD key.
const META: &[u8] = b"teifs meta v1";
const SECRET: &[u8] = b"teifs secret v1";
const TOKEN: &[u8] = b"teifs session token v1";
const SESSION_SECRET: &[u8] = b"teifs session secret v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_random_and_parts_differ() {
        let key = DataKey::generate();
        assert_ne!(key, DataKey::generate());
        assert_ne!(*key.part_key(1), *key.part_key(2));
        assert_eq!(*key.part_key(1), *key.part_key(1));
        assert_eq!(format!("{key:?}"), "DataKey(…)");
    }

    #[test]
    fn etags_are_keyed() {
        let md5 = [3u8; 16];
        let a = DataKey::generate();
        assert_eq!(a.etag_for(&md5), a.etag_for(&md5));
        assert_ne!(a.etag_for(&md5), DataKey::generate().etag_for(&md5));
        assert_ne!(a.etag_for(&md5), md5);
    }

    #[test]
    fn metadata_round_trips_and_detects_tampering() {
        let key = DataKey::generate();
        let sealed = key.seal_metadata(b"{\"CRC32\":\"abc\"}");
        assert_eq!(key.open_metadata(&sealed).unwrap(), b"{\"CRC32\":\"abc\"}");
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(key.open_metadata(&bad).is_err());
        assert!(DataKey::generate().open_metadata(&sealed).is_err());
        assert!(key.open_metadata(&sealed[..5]).is_err());
    }

    #[test]
    fn tokens_are_bound_to_their_key_and_apart_from_secrets() {
        let key = DataKey::generate();
        let sealed = key.seal_token(b"TSIAEXAMPLE", b"{\"v\":1}");
        assert_eq!(
            &*key.open_token(b"TSIAEXAMPLE", &sealed).unwrap(),
            b"{\"v\":1}"
        );
        assert!(key.open_token(b"TSIAOTHER", &sealed).is_err());
        assert!(key.open_secret(b"TSIAEXAMPLE", &sealed).is_err());
        assert!(
            key.open_token(b"TSIAEXAMPLE", &key.seal_secret(b"TSIAEXAMPLE", b"x"))
                .is_err()
        );
        assert!(
            DataKey::generate()
                .open_token(b"TSIAEXAMPLE", &sealed)
                .is_err()
        );
        let mut bad = sealed;
        bad[20] ^= 1;
        assert!(key.open_token(b"TSIAEXAMPLE", &bad).is_err());

        let secret = key.session_secret(b"TSIAEXAMPLE");
        assert_eq!(*secret, *key.session_secret(b"TSIAEXAMPLE"), "found again");
        assert_ne!(*secret, *key.session_secret(b"TSIAOTHER"));
        assert_ne!(*secret, *DataKey::generate().session_secret(b"TSIAEXAMPLE"));
    }

    #[test]
    fn secrets_are_bound_to_their_owner_and_apart_from_metadata() {
        let key = DataKey::generate();
        let sealed = key.seal_secret(b"TKIAEXAMPLE", b"s3cret");
        assert_eq!(
            &*key.open_secret(b"TKIAEXAMPLE", &sealed).unwrap(),
            b"s3cret"
        );
        assert!(key.open_secret(b"TKIAOTHER", &sealed).is_err());
        assert!(key.open_metadata(&sealed).is_err());
        assert!(
            key.open_secret(b"", &key.seal_metadata(b"x")).is_err(),
            "metadata and secrets use different keys"
        );
        assert_ne!(
            sealed,
            key.seal_secret(b"TKIAEXAMPLE", b"s3cret"),
            "random nonces"
        );
    }
}
