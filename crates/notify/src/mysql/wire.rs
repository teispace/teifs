//! MySQL's client/server protocol: packets, length-encoded values, capabilities, `ERR`
//! packets, and the ways a password is proved or sent.

use aws_lc_rs::{
    digest::{self, SHA1_FOR_LEGACY_USE_ONLY, SHA256},
    rsa::{OAEP_SHA1_MGF1SHA1, OaepPublicEncryptingKey, PublicEncryptingKey},
};
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

/// The largest packet's payload; a larger one is split.
pub(crate) const MAX_PAYLOAD: usize = 0xff_ffff;
/// What an answer that can't be read is.
pub(crate) const GARBLED: &str = "it answered with something that isn't MySQL";

/// Capability flags.
pub(crate) mod capability {
    pub const LONG_PASSWORD: u32 = 1;
    pub const CONNECT_WITH_DB: u32 = 8;
    pub const PROTOCOL_41: u32 = 0x200;
    pub const SSL: u32 = 0x800;
    pub const TRANSACTIONS: u32 = 0x2000;
    pub const SECURE_CONNECTION: u32 = 0x8000;
    pub const PLUGIN_AUTH: u32 = 0x8_0000;
    pub const PLUGIN_AUTH_LENENC_DATA: u32 = 0x20_0000;
}

/// Commands.
pub(crate) mod command {
    #[cfg(any(test, feature = "testing"))]
    pub const QUIT: u8 = 0x01;
    pub const QUERY: u8 = 0x03;
    pub const STMT_PREPARE: u8 = 0x16;
    pub const STMT_EXECUTE: u8 = 0x17;
}

/// `utf8mb4_general_ci`, which every MySQL and `MariaDB` since 5.5 knows.
pub(crate) const UTF8MB4: u8 = 45;
/// A string parameter's type.
pub(crate) const TYPE_STRING: u8 = 0xfe;

/// Reads one packet's payload and sequence number, joining a payload split over several.
pub(crate) async fn read_packet<R: AsyncRead + Unpin>(
    stream: &mut R,
    max: usize,
) -> Result<(u8, Vec<u8>), String> {
    let lost = |e: std::io::Error| format!("the connection failed: {e}");
    let mut payload = Vec::new();
    loop {
        let mut head = [0; 4];
        stream.read_exact(&mut head).await.map_err(lost)?;
        let size = usize::from(head[0]) | usize::from(head[1]) << 8 | usize::from(head[2]) << 16;
        if payload.len() + size > max {
            return Err("it sent a packet larger than TeiFS takes".to_owned());
        }
        let start = payload.len();
        payload.resize(start + size, 0);
        stream
            .read_exact(&mut payload[start..])
            .await
            .map_err(lost)?;
        if size < MAX_PAYLOAD {
            return Ok((head[3], payload));
        }
    }
}

/// A packet with `payload` and sequence number `seq`, ready to write.
pub(crate) fn packet(seq: u8, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if payload.len() >= MAX_PAYLOAD {
        return Err("larger than a MySQL packet TeiFS sends".to_owned());
    }
    let size = u32::try_from(payload.len()).map_err(|_| "too large")?;
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    out.extend_from_slice(&size.to_le_bytes()[..3]);
    out.push(seq);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Appends a length-encoded integer.
pub(crate) fn lenenc(out: &mut Vec<u8>, n: usize) {
    let bytes = u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes();
    match n {
        0..=250 => out.push(bytes[0]),
        251..=0xffff => {
            out.push(0xfc);
            out.extend_from_slice(&bytes[..2]);
        }
        0x1_0000..=0xff_ffff => {
            out.push(0xfd);
            out.extend_from_slice(&bytes[..3]);
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&bytes);
        }
    }
}

/// Appends a length-encoded string.
pub(crate) fn lenenc_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    lenenc(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// A payload's fields, read in order.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let (head, rest) = self.bytes.split_at_checked(n).ok_or(GARBLED)?;
        self.bytes = rest;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length-encoded integer.
    pub(crate) fn lenenc(&mut self) -> Result<usize, String> {
        let n = match self.u8()? {
            n @ 0..=250 => u64::from(n),
            0xfc => u64::from(self.u16()?),
            0xfd => {
                let b = self.take(3)?;
                u64::from(u32::from_le_bytes([b[0], b[1], b[2], 0]))
            }
            0xfe => {
                let mut n = [0; 8];
                n.copy_from_slice(self.take(8)?);
                u64::from_le_bytes(n)
            }
            _ => return Err(GARBLED.to_owned()),
        };
        usize::try_from(n).map_err(|_| GARBLED.to_owned())
    }

    /// A length-encoded string.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn lenenc_bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.lenenc()?;
        self.take(n)
    }

    /// Up to a NUL, or to the end when there's none.
    pub(crate) fn cstring(&mut self) -> &'a [u8] {
        let end = self.bytes.iter().position(|b| *b == 0);
        let (text, rest) = self.bytes.split_at(end.unwrap_or(self.bytes.len()));
        self.bytes = rest.get(1..).unwrap_or_default();
        text
    }

    /// What's left.
    pub(crate) const fn rest(&self) -> &'a [u8] {
        self.bytes
    }
}

/// An `ERR` packet: its error number, SQL state and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerError {
    pub code: u16,
    pub message: String,
}

impl ServerError {
    /// Reads `payload`, an `ERR` packet (`0xff` first).
    pub(crate) fn read(payload: &[u8]) -> Self {
        let mut reader = Reader::new(payload.get(1..).unwrap_or_default());
        let code = reader.u16().unwrap_or(0);
        let rest = reader.rest();
        let (state, text) = match rest.strip_prefix(b"#") {
            Some(marked) if marked.len() >= 5 => marked.split_at(5),
            _ => (&b""[..], rest),
        };
        let state = String::from_utf8_lossy(state);
        let text = String::from_utf8_lossy(text);
        let message = if state.is_empty() {
            format!("it answered {code}: {text}")
        } else {
            format!("it answered {code} ({state}): {text}")
        };
        Self { code, message }
    }
}

/// An `ERR` packet with `code`, `state` and `text`, as a server writes one.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn err_packet(code: u16, state: &str, text: &str) -> Vec<u8> {
    let mut out = vec![0xff];
    out.extend_from_slice(&code.to_le_bytes());
    out.push(b'#');
    out.extend_from_slice(state.as_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    let mut context = digest::Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    for part in parts {
        context.update(part);
    }
    context.finish().as_ref().to_vec()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut context = digest::Context::new(&SHA256);
    for part in parts {
        context.update(part);
    }
    context.finish().as_ref().to_vec()
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(a, b)| a ^ b).collect()
}

/// `mysql_native_password`'s proof: `SHA1(password) XOR SHA1(nonce, SHA1(SHA1(password)))`;
/// nothing for no password.
pub(crate) fn native_proof(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let hashed = Zeroizing::new(sha1(&[password.as_bytes()]));
    xor(&hashed, &sha1(&[nonce, &sha1(&[&hashed])]))
}

/// `caching_sha2_password`'s proof: `SHA256(password) XOR SHA256(SHA256(SHA256(password)),
/// nonce)`; nothing for no password.
pub(crate) fn sha2_proof(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let hashed = Zeroizing::new(sha256(&[password.as_bytes()]));
    xor(&hashed, &sha256(&[&sha256(&[&hashed]), nonce]))
}

/// The password, with its NUL, `XOR`ed with the nonce and encrypted with the server's RSA
/// key (`SubjectPublicKeyInfo` DER), as `caching_sha2_password` and `sha256_password`
/// send it without TLS.
pub(crate) fn rsa_password(password: &str, nonce: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let refused = || "the server's RSA key can't be used".to_owned();
    if nonce.is_empty() {
        return Err(GARBLED.to_owned());
    }
    let key = PublicEncryptingKey::from_der(key).map_err(|_| refused())?;
    let key = OaepPublicEncryptingKey::new(key).map_err(|_| refused())?;
    let mut plain = Zeroizing::new(password.as_bytes().to_vec());
    plain.push(0);
    for (i, byte) in plain.iter_mut().enumerate() {
        *byte ^= nonce[i % nonce.len()];
    }
    let mut out = vec![0; key.ciphertext_size()];
    let size = key
        .encrypt(&OAEP_SHA1_MGF1SHA1, &plain, &mut out, None)
        .map_err(|_| "the password is too long for the server's RSA key".to_owned())?
        .len();
    out.truncate(size);
    Ok(out)
}

/// A `PUBLIC KEY` PEM's DER, checked to be an RSA key.
pub(crate) fn rsa_key_from_pem(pem: &[u8]) -> Result<Vec<u8>, String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let text = std::str::from_utf8(pem).map_err(|_| "not a PEM file")?;
    let body = text
        .split("-----BEGIN PUBLIC KEY-----")
        .nth(1)
        .and_then(|rest| rest.split("-----END PUBLIC KEY-----").next())
        .ok_or("no `PUBLIC KEY` in it")?;
    let der = BASE64
        .decode(body.split_whitespace().collect::<String>())
        .map_err(|_| "its `PUBLIC KEY` isn't base64")?;
    PublicEncryptingKey::from_der(&der).map_err(|_| "its `PUBLIC KEY` isn't an RSA key")?;
    Ok(der)
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rsa::{KeySize, OaepPrivateDecryptingKey, PrivateDecryptingKey};

    use super::*;

    #[tokio::test]
    async fn packets_are_read_as_written_and_joined() {
        let written = packet(3, b"hello").unwrap();
        assert_eq!(&written[..], [5, 0, 0, 3, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(
            read_packet(&mut &written[..], 16).await,
            Ok((3, b"hello".to_vec()))
        );
        assert!(read_packet(&mut &written[..], 4).await.is_err());
        let mut split = vec![0xff, 0xff, 0xff, 0];
        split.extend(vec![7; MAX_PAYLOAD]);
        split.extend_from_slice(&[1, 0, 0, 1, 8]);
        let (seq, joined) = read_packet(&mut &split[..], 1 << 25).await.unwrap();
        assert_eq!(
            (seq, joined.len(), joined[MAX_PAYLOAD]),
            (1, MAX_PAYLOAD + 1, 8)
        );
        assert!(packet(0, &vec![0; MAX_PAYLOAD]).is_err());
    }

    #[test]
    fn lengths_are_encoded_as_mysql_reads_them() {
        for (n, encoded) in [
            (250, vec![250]),
            (251, vec![0xfc, 251, 0]),
            (0x1_0000, vec![0xfd, 0, 0, 1]),
            (0x100_0000, vec![0xfe, 0, 0, 0, 1, 0, 0, 0, 0]),
        ] {
            let mut out = Vec::new();
            lenenc(&mut out, n);
            assert_eq!(out, encoded, "{n}");
            assert_eq!(Reader::new(&out).lenenc(), Ok(n));
        }
        assert!(Reader::new(&[0xff]).lenenc().is_err());
        let mut reader = Reader::new(b"abc\0de");
        assert_eq!(
            (reader.cstring(), reader.cstring()),
            (&b"abc"[..], &b"de"[..])
        );
    }

    #[test]
    fn errors_are_named_with_their_state() {
        let error = ServerError::read(&err_packet(1146, "42S02", "Table 's3.t' doesn't exist"));
        assert_eq!(error.code, 1146);
        assert_eq!(
            error.message,
            "it answered 1146 (42S02): Table 's3.t' doesn't exist"
        );
        let bare = ServerError::read(&[0xff, 0x15, 0x04, b'n', b'o']);
        assert_eq!(bare.message, "it answered 1045: no");
    }

    /// The proofs, checked the way a server checks them from what it stores.
    #[test]
    fn proofs_are_what_servers_check() {
        let nonce = b"0123456789abcdefghij";
        let proof = native_proof("pw", nonce);
        let stored = sha1(&[&sha1(&[b"pw"])]);
        let hashed = xor(&proof, &sha1(&[nonce, &stored]));
        assert_eq!(sha1(&[&hashed]), stored);
        let proof = sha2_proof("pw", nonce);
        let stored = sha256(&[&sha256(&[b"pw"])]);
        let hashed = xor(&proof, &sha256(&[&stored, nonce]));
        assert_eq!(sha256(&[&hashed]), stored);
        assert!(native_proof("", nonce).is_empty() && sha2_proof("", nonce).is_empty());
        assert_ne!(
            native_proof("pw", b"another-nonce-000000"),
            native_proof("pw", nonce)
        );
    }

    #[test]
    fn passwords_are_encrypted_with_the_servers_key() {
        use aws_lc_rs::encoding::AsDer as _;
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let public = private.public_key().as_der().unwrap();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public.as_ref())
        );
        let der = rsa_key_from_pem(pem.as_bytes()).unwrap();
        let sealed = rsa_password("pw", b"nonce", &der).unwrap();
        let private = OaepPrivateDecryptingKey::new(private).unwrap();
        let mut out = vec![0; private.min_output_size()];
        let plain = private
            .decrypt(&OAEP_SHA1_MGF1SHA1, &sealed, &mut out, None)
            .unwrap();
        assert_eq!(plain, xor(b"pw\0", b"non"));
        assert!(
            rsa_key_from_pem(b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")
                .is_err()
        );
        assert!(rsa_key_from_pem(b"nothing").is_err());
    }
}
