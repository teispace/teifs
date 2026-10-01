//! The private keys that decrypt a SAML provider's encrypted assertions: PEM, PKCS#8 or
//! PKCS#1 RSA keys, as AWS takes them. They're kept as PKCS#8, sealed under IAM's key.

use aws_lc_rs::rsa::PrivateDecryptingKey;
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use zeroize::Zeroizing;

/// AWS's message for a key that can't be used, and why.
fn invalid<T>(why: &str) -> Result<T, String> {
    Err(format!("Invalid private key: {why}"))
}

/// The PKCS#8 form of `pem`, if it's an RSA private key that can decrypt.
pub(crate) fn pkcs8(pem: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if pem.contains("ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED") {
        return invalid("Key is encrypted.");
    }
    let unrecognized = "Key format is not recognized. Private key file must be a .pem file.";
    let Ok(key) = PrivateKeyDer::from_pem_slice(pem.as_bytes()) else {
        return invalid(unrecognized);
    };
    let der = Zeroizing::new(match key {
        PrivateKeyDer::Pkcs8(key) => key.secret_pkcs8_der().to_vec(),
        PrivateKeyDer::Pkcs1(key) => wrap_pkcs1(key.secret_pkcs1_der()),
        _ => return invalid(unrecognized),
    });
    if PrivateDecryptingKey::from_pkcs8(&der).is_err() {
        return invalid("Key isn't an RSA key of 2048 to 8192 bits.");
    }
    Ok(der)
}

/// A PKCS#8 key as PEM.
pub(crate) fn pem(pkcs8: &[u8]) -> String {
    let body = STANDARD.encode(pkcs8);
    let mut pem = "-----BEGIN PRIVATE KEY-----\n".to_owned();
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// A PKCS#1 `RSAPrivateKey` wrapped as PKCS#8 (RFC 5208): version 0, the
/// `rsaEncryption` algorithm with NULL parameters, the key in an OCTET STRING.
fn wrap_pkcs1(pkcs1: &[u8]) -> Vec<u8> {
    const ALGORITHM: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend_from_slice(&ALGORITHM);
    body.push(0x04);
    push_length(&mut body, pkcs1.len());
    body.extend_from_slice(pkcs1);
    let mut der = vec![0x30];
    push_length(&mut der, body.len());
    der.extend_from_slice(&body);
    der
}

/// A DER length.
fn push_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(u8::try_from(length).unwrap_or_default());
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    out.push(0x80 | u8::try_from(bytes.len() - first).unwrap_or_default());
    out.extend_from_slice(&bytes[first..]);
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use aws_lc_rs::{encoding::AsDer, rsa::KeySize};

    use super::*;

    /// A new RSA key, as PEM (PKCS#8).
    pub(crate) fn new_pem() -> String {
        let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        pem(key.as_der().unwrap().as_ref())
    }

    fn armor(label: &str, der: &[u8]) -> String {
        let body = STANDARD.encode(der);
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    }

    #[test]
    fn pkcs8_and_pkcs1_keys_are_taken_and_others_refused() {
        let pem = new_pem();
        let der = pkcs8(&pem).unwrap();
        assert_eq!(super::pem(&der), pem);
        assert!(PrivateDecryptingKey::from_pkcs8(&der).is_ok());

        // The same key as PKCS#1: the RSAPrivateKey inside the PKCS#8 document, whose
        // header (version, algorithm, OCTET STRING with a two-byte long length) is 26
        // bytes for a 2048-bit key.
        let pkcs1 = &der[26..];
        assert_eq!(pkcs1[0], 0x30);
        let again = pkcs8(&armor("RSA PRIVATE KEY", pkcs1)).unwrap();
        assert_eq!(*again, *der);

        for (pem, why) in [
            (armor("ENCRYPTED PRIVATE KEY", b"x"), "Key is encrypted."),
            (
                armor("RSA PRIVATE KEY", b"x").replacen(
                    "-----\n",
                    "-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n",
                    1,
                ),
                "Key is encrypted.",
            ),
            ("not a key".to_owned(), "Key format is not recognized."),
            (armor("PRIVATE KEY", b"not der"), "isn't an RSA key"),
        ] {
            let err = pkcs8(&pem).unwrap_err();
            assert!(err.starts_with("Invalid private key: "), "{err}");
            assert!(err.contains(why), "{err}");
        }
        let mut short = Vec::new();
        push_length(&mut short, 5);
        assert_eq!(short, [5]);
        let mut long = Vec::new();
        push_length(&mut long, 0x1234);
        assert_eq!(long, [0x82, 0x12, 0x34]);
        let mut one = Vec::new();
        push_length(&mut one, 0x80);
        assert_eq!(one, [0x81, 0x80]);
    }
}
