//! The encryption around `MinIO`'s `inspect-data` download (`mc support inspect`), as
//! madmin-go reads it.
//!
//! Without the caller's public key (format 1): a byte `1`, a random 32-byte key, then
//! the data as sio-go's AES-256-GCM stream under that key and a zero nonce. Anyone who
//! has the download can open it; the key is there to be told to support.
//!
//! With the caller's RSA public key (format 2), madmin-go's `estream` 2.1: two bytes
//! `2, 1`, then blocks, each a `MessagePack` int8 id, a uint32 length and that many
//! bytes of `MessagePack` values. An encrypted-key block (the public key as PKCS #1 DER,
//! then the random stream key under RSA-OAEP with SHA-512), an encrypted-stream block
//! (its name, empty extra data, checksum type 1 for xxHash64, the 8-byte nonce: a
//! little-endian counter from 0), the sio-go stream in data blocks, an end-of-stream
//! block with the xxHash64 of those blocks' bytes (big endian), and an end-of-file block.
//! Only the private key's holder opens it.

use aws_lc_rs::rsa::{OAEP_SHA512_MGF1SHA512, OaepPublicEncryptingKey, PublicEncryptingKey};
use zeroize::Zeroizing;

use crate::{
    CryptoError,
    madmin::{NONCE, aes_256_gcm, open_stream, seal_stream},
};

/// The format byte of a download sealed with a key that comes with it.
pub const WITH_KEY: u8 = 1;

/// The `rsaEncryption` algorithm of a `SubjectPublicKeyInfo`, with its NULL parameters.
const RSA_ALGORITHM: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];
/// sio-go's plaintext per fragment: each goes in a data block of its own.
const FRAGMENT: usize = 1 << 14;
const TAG: usize = 16;

/// estream's blocks.
const ENCRYPTED_KEY: u8 = 2;
const ENCRYPTED_STREAM: u8 = 3;
const DATA: u8 = 5;
const END_OF_STREAM: u8 = 6;
const END_OF_FILE: u8 = 7;
const ERROR: u8 = 8;
/// estream's checksum type for xxHash64.
const XXHASH: u8 = 1;

/// A caller's RSA public key, as `mc support inspect` sends it.
pub struct InspectKey {
    /// As PKCS #1 DER, which the download repeats so the caller finds its key.
    pkcs1: Vec<u8>,
    key: OaepPublicEncryptingKey,
}

impl std::fmt::Debug for InspectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectKey")
            .field("bits", &self.key.key_size_bits())
            .finish_non_exhaustive()
    }
}

impl InspectKey {
    /// An RSA public key as PKCS #1 DER, or PEM holding it, as `MinIO` takes it.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidPublicKey`] for anything else.
    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        let pkcs1 = match x509_parser::pem::parse_x509_pem(bytes) {
            Ok((_, pem)) => pem.contents,
            Err(_) => bytes.to_vec(),
        };
        let spki = der(0x30, &[&RSA_ALGORITHM, &der(0x03, &[&[0], &pkcs1])]);
        let key = PublicEncryptingKey::from_der(&spki)
            .ok()
            .and_then(|key| OaepPublicEncryptingKey::new(key).ok())
            .ok_or(CryptoError::InvalidPublicKey)?;
        Ok(Self { pkcs1, key })
    }

    /// `data`, named `name`, as an estream only this key's private key opens; `error`,
    /// when there's one, follows the data, as the reader's error.
    #[must_use]
    pub fn seal(&self, name: &str, data: &[u8], error: Option<&str>) -> Vec<u8> {
        let mut stream_key = Zeroizing::new([0u8; 32]);
        crate::random(stream_key.as_mut());
        let mut sealed_key = vec![0; self.key.ciphertext_size()];
        let sealed_key = self
            .key
            .encrypt(
                &OAEP_SHA512_MGF1SHA512,
                stream_key.as_ref(),
                &mut sealed_key,
                None,
            )
            .expect("a 32-byte key fits any RSA key aws-lc-rs takes");

        let mut out = vec![2, 1];
        let mut body = Vec::new();
        bin(&mut body, &self.pkcs1);
        bin(&mut body, sealed_key);
        block(&mut out, ENCRYPTED_KEY, &body);

        let nonce = [0; NONCE];
        body.clear();
        str(&mut body, name);
        bin(&mut body, &[]);
        body.push(XXHASH);
        bin(&mut body, &nonce);
        block(&mut out, ENCRYPTED_STREAM, &body);

        let mut sealed = Vec::with_capacity(data.len() + data.len().div_ceil(FRAGMENT) * TAG);
        seal_stream(&aes_256_gcm(&stream_key), nonce, data, &mut sealed);
        for fragment in sealed.chunks(FRAGMENT + TAG) {
            body.clear();
            bin(&mut body, fragment);
            block(&mut out, DATA, &body);
        }
        body.clear();
        bin(
            &mut body,
            &xxhash_rust::xxh64::xxh64(&sealed, 0).to_be_bytes(),
        );
        block(&mut out, END_OF_STREAM, &body);
        if let Some(error) = error {
            body.clear();
            str(&mut body, error);
            block(&mut out, ERROR, &body);
        }
        block(&mut out, END_OF_FILE, &[]);
        out
    }
}

/// `data` sealed under a random key that comes first: format 1.
#[must_use]
pub fn seal_with_key(data: &[u8]) -> Vec<u8> {
    let mut key = Zeroizing::new([0u8; 32]);
    crate::random(key.as_mut());
    let mut out = Vec::with_capacity(1 + 32 + data.len() + data.len() / FRAGMENT * TAG + TAG);
    out.push(WITH_KEY);
    out.extend_from_slice(key.as_ref());
    seal_stream(&aes_256_gcm(&key), [0; NONCE], data, &mut out);
    out
}

/// What a download sealed by [`seal_with_key`] holds, with the key that comes with it.
///
/// # Errors
///
/// Another format, or data that was changed or cut short:
/// [`CryptoError::Authentication`].
pub fn open_with_key(download: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match download {
        [WITH_KEY, rest @ ..] if rest.len() >= 32 => {
            let (key, sealed) = rest.split_at(32);
            let key: &[u8; 32] = key.try_into().expect("split at 32");
            open_stream(&aes_256_gcm(key), [0; NONCE], sealed)
        }
        _ => Err(CryptoError::Authentication),
    }
}

/// A DER value: `tag`, its length, then `parts`.
fn der(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).expect("under 0x80"));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | u8::try_from(bytes.len() - skip).expect("at most 8"));
        out.extend_from_slice(&bytes[skip..]);
    }
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// A block: its id, its length as `MessagePack`'s smallest unsigned integer, its body.
fn block(out: &mut Vec<u8>, id: u8, body: &[u8]) {
    out.push(id);
    let len = u32::try_from(body.len()).expect("a block is under 4 GiB");
    match len {
        0..=0x7f => out.push(u8::try_from(len).expect("in range")),
        0x80..=0xff => {
            out.push(0xcc);
            out.push(u8::try_from(len).expect("in range"));
        }
        0x100..=0xffff => {
            out.push(0xcd);
            out.extend_from_slice(&u16::try_from(len).expect("in range").to_be_bytes());
        }
        _ => {
            out.push(0xce);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
    out.extend_from_slice(body);
}

/// `MessagePack` bin.
fn bin(out: &mut Vec<u8>, bytes: &[u8]) {
    header(out, bytes.len(), None, [0xc4, 0xc5, 0xc6]);
    out.extend_from_slice(bytes);
}

/// `MessagePack` str.
fn str(out: &mut Vec<u8>, text: &str) {
    header(out, text.len(), Some(0xa0), [0xd9, 0xda, 0xdb]);
    out.extend_from_slice(text.as_bytes());
}

/// The header of a bin or str of `len` bytes: the fix form under 32 when there's one,
/// else the 8-, 16- or 32-bit length form.
fn header(out: &mut Vec<u8>, len: usize, fix: Option<u8>, forms: [u8; 3]) {
    let len = u32::try_from(len).expect("a value is under 4 GiB");
    match (fix, len) {
        (Some(fix), 0..=31) => out.push(fix | u8::try_from(len).expect("in range")),
        (_, 0..=0xff) => {
            out.push(forms[0]);
            out.push(u8::try_from(len).expect("in range"));
        }
        (_, 0x100..=0xffff) => {
            out.push(forms[1]);
            out.extend_from_slice(&u16::try_from(len).expect("in range").to_be_bytes());
        }
        _ => {
            out.push(forms[2]);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
}

/// The PKCS #1 DER of a public key aws-lc-rs made, for tests.
#[cfg(test)]
fn pkcs1_of(key: &PublicEncryptingKey) -> Vec<u8> {
    use aws_lc_rs::encoding::AsDer as _;
    use x509_parser::prelude::FromDer as _;
    let spki = key.as_der().expect("serializes");
    let (_, info) =
        x509_parser::x509::SubjectPublicKeyInfo::from_der(spki.as_ref()).expect("parses");
    info.subject_public_key.data.to_vec()
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rsa::{KeySize, OaepPrivateDecryptingKey, PrivateDecryptingKey};

    use super::*;

    /// A test reader of what [`InspectKey::seal`] writes.
    struct Reader<'a>(&'a [u8]);

    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> &'a [u8] {
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            head
        }
        fn byte(&mut self) -> u8 {
            self.take(1)[0]
        }
        fn uint(&mut self, marker: u8) -> usize {
            match marker {
                0xcc | 0xc4 | 0xd9 => usize::from(self.byte()),
                0xcd | 0xc5 | 0xda => {
                    usize::from(u16::from_be_bytes(self.take(2).try_into().unwrap()))
                }
                0xce | 0xc6 | 0xdb => u32::from_be_bytes(self.take(4).try_into().unwrap()) as usize,
                fix if fix & 0xe0 == 0xa0 => usize::from(fix & 0x1f),
                fix => usize::from(fix),
            }
        }
        fn bytes(&mut self) -> &'a [u8] {
            let marker = self.byte();
            let n = self.uint(marker);
            self.take(n)
        }
        /// A block's id and body.
        fn block(&mut self) -> (u8, Reader<'a>) {
            let id = self.byte();
            let marker = self.byte();
            let n = self.uint(marker);
            (id, Reader(self.take(n)))
        }
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[test]
    fn format_1_carries_its_key() {
        for len in [0, 10, FRAGMENT, 3 * FRAGMENT + 5] {
            let plain = data(len);
            let sealed = seal_with_key(&plain);
            assert_eq!(sealed[0], WITH_KEY);
            assert_eq!(*open_with_key(&sealed).unwrap(), plain);
            let mut changed = sealed.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(open_with_key(&changed).is_err());
        }
    }

    #[test]
    fn format_2_opens_with_the_private_key_alone() {
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let pkcs1 = pkcs1_of(&private.public_key());
        let plain = data(2 * FRAGMENT + 100);
        let key = InspectKey::parse(&pkcs1).unwrap();
        let sealed = key.seal("inspect.zip", &plain, Some("nothing matched"));

        let mut r = Reader(&sealed);
        assert_eq!(r.take(2), [2, 1]);
        let (id, mut body) = r.block();
        assert_eq!(id, ENCRYPTED_KEY);
        assert_eq!(body.bytes(), pkcs1);
        let decrypting = OaepPrivateDecryptingKey::new(private).unwrap();
        let mut out = [0; 256];
        let stream_key: [u8; 32] = decrypting
            .decrypt(&OAEP_SHA512_MGF1SHA512, body.bytes(), &mut out, None)
            .unwrap()
            .try_into()
            .unwrap();
        let (id, mut body) = r.block();
        assert_eq!(id, ENCRYPTED_STREAM);
        assert_eq!(body.bytes(), b"inspect.zip");
        assert!(body.bytes().is_empty());
        assert_eq!(body.byte(), XXHASH);
        assert_eq!(body.bytes(), [0; NONCE]);
        let mut stream = Vec::new();
        let sum = loop {
            match r.block() {
                (DATA, mut body) => stream.extend_from_slice(body.bytes()),
                (END_OF_STREAM, mut body) => break body.bytes().to_vec(),
                (id, _) => panic!("block {id}"),
            }
        };
        assert_eq!(sum, xxhash_rust::xxh64::xxh64(&stream, 0).to_be_bytes());
        let (id, mut body) = r.block();
        assert_eq!((id, body.bytes()), (ERROR, &b"nothing matched"[..]));
        assert_eq!(r.block().0, END_OF_FILE);
        assert!(r.0.is_empty());
        let opened = open_stream(&aes_256_gcm(&stream_key), [0; NONCE], &stream).unwrap();
        assert_eq!(*opened, plain);
    }

    #[test]
    fn a_pem_key_is_taken_and_anything_else_refused() {
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let pkcs1 = pkcs1_of(&private.public_key());
        let pem = format!(
            "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pkcs1)
        );
        let key = InspectKey::parse(pem.as_bytes()).unwrap();
        assert_eq!(key.pkcs1, pkcs1);
        assert!(format!("{key:?}").contains("2048"));
        for bad in [&b"not a key"[..], &[], &pkcs1[..pkcs1.len() - 1]] {
            assert!(matches!(
                InspectKey::parse(bad),
                Err(CryptoError::InvalidPublicKey)
            ));
        }
    }

    #[test]
    fn long_lengths_take_the_longer_forms() {
        let mut out = Vec::new();
        str(&mut out, &"a".repeat(40));
        assert_eq!(&out[..2], [0xd9, 40]);
        out.clear();
        bin(&mut out, &[0; 300]);
        assert_eq!(&out[..3], [0xc5, 1, 44]);
        out.clear();
        block(&mut out, DATA, &[0; 200]);
        assert_eq!(&out[..3], [DATA, 0xcc, 200]);
        assert_eq!(der(0x04, &[&[0; 300]])[..4], [0x04, 0x82, 1, 44]);
    }
}
