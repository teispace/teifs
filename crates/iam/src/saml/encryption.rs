//! Encrypted assertions (XML Encryption, <https://www.w3.org/TR/xmlenc-core1/>) as AWS
//! takes them: an `EncryptedAssertion` whose content key is encrypted with RSA-OAEP for
//! one of the SAML provider's private keys, and whose assertion is encrypted with
//! AES-CBC or AES-GCM under that key.
//!
//! Every failure says the same thing, so that an answer tells nothing about which part
//! of a forged ciphertext was wrong.

use aws_lc_rs::{
    aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    cipher::{AES_128, AES_256, DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey},
    rsa::{
        OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
        OaepAlgorithm, OaepPrivateDecryptingKey, PrivateDecryptingKey,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

use super::{metadata::DS, xml::Element};

/// XML Encryption's namespaces.
pub(crate) const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";

/// What every failure to decrypt says.
const UNDECRYPTABLE: &str =
    "The encrypted assertion can't be decrypted with the SAML provider's private keys";

/// How the assertion itself is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Content {
    Cbc(usize),
    Gcm(usize),
}

impl Content {
    fn find(uri: &str) -> Option<Self> {
        Some(match uri {
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => Self::Cbc(16),
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => Self::Cbc(32),
            "http://www.w3.org/2009/xmlenc11#aes128-gcm" => Self::Gcm(16),
            "http://www.w3.org/2009/xmlenc11#aes256-gcm" => Self::Gcm(32),
            _ => return None,
        })
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Cbc(n) | Self::Gcm(n) => n,
        }
    }

    /// `data` (the IV, then the ciphertext and, for GCM, its tag) decrypted with `key`.
    fn decrypt(self, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Cbc(len) => {
                let algorithm = if len == 16 { &AES_128 } else { &AES_256 };
                // aws-lc refuses a ciphertext that isn't whole padded blocks.
                let (iv, ciphertext) = data.split_at_checked(16)?;
                let key = UnboundCipherKey::new(algorithm, key).ok()?;
                let key = PaddedBlockDecryptingKey::cbc_iso10126(key).ok()?;
                let iv: [u8; 16] = iv.try_into().ok()?;
                let mut buffer = ciphertext.to_vec();
                let plain = key
                    .decrypt(&mut buffer, DecryptionContext::Iv128(iv.into()))
                    .ok()?;
                Some(plain.to_vec())
            }
            Self::Gcm(len) => {
                let algorithm = if len == 16 {
                    &AES_128_GCM
                } else {
                    &AES_256_GCM
                };
                // aws-lc refuses a ciphertext shorter than its tag.
                let (nonce, sealed) = data.split_at_checked(12)?;
                let key = LessSafeKey::new(UnboundKey::new(algorithm, key).ok()?);
                let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
                let mut buffer = sealed.to_vec();
                let plain = key.open_in_place(nonce, Aad::empty(), &mut buffer).ok()?;
                Some(plain.to_vec())
            }
        }
    }
}

/// The digest a URI names, for OAEP: SHA-1, SHA-256, SHA-384 or SHA-512.
fn oaep_hash(uri: &str) -> Option<u16> {
    Some(match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1" => 1,
        "http://www.w3.org/2001/04/xmlenc#sha256" => 256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => 384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => 512,
        _ => return None,
    })
}

/// The MGF1 hash an `xenc11:MGF` names.
fn mgf_hash(uri: &str) -> Option<u16> {
    Some(match uri {
        "http://www.w3.org/2009/xmlenc11#mgf1sha1" => 1,
        "http://www.w3.org/2009/xmlenc11#mgf1sha256" => 256,
        "http://www.w3.org/2009/xmlenc11#mgf1sha384" => 384,
        "http://www.w3.org/2009/xmlenc11#mgf1sha512" => 512,
        _ => return None,
    })
}

/// The OAEP an `EncryptedKey`'s `EncryptionMethod` names, when aws-lc has it (the
/// digest and the mask's hash the same), and its label (`OAEPparams`).
fn oaep(method: &Element) -> Option<(&'static OaepAlgorithm, Vec<u8>)> {
    let digest = match method.one(DS, "DigestMethod").ok()? {
        Some(d) => oaep_hash(d.attr("Algorithm")?)?,
        None => 1,
    };
    let mgf = match method.attr("Algorithm")? {
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => 1,
        "http://www.w3.org/2009/xmlenc11#rsa-oaep" => match method.one(XENC11, "MGF").ok()? {
            Some(m) => mgf_hash(m.attr("Algorithm")?)?,
            None => 1,
        },
        _ => return None,
    };
    let algorithm = match (digest, mgf) {
        (1, 1) => &OAEP_SHA1_MGF1SHA1,
        (256, 256) => &OAEP_SHA256_MGF1SHA256,
        (384, 384) => &OAEP_SHA384_MGF1SHA384,
        (512, 512) => &OAEP_SHA512_MGF1SHA512,
        _ => return None,
    };
    let label = match method.one(XENC, "OAEPparams").ok()? {
        Some(params) => base64(params)?,
        None => Vec::new(),
    };
    Some((algorithm, label))
}

fn base64(element: &Element) -> Option<Vec<u8>> {
    let text: String = element.text().ok()?.split_ascii_whitespace().collect();
    STANDARD.decode(text).ok()
}

/// The `CipherValue` of an element's `CipherData`.
fn cipher_value(element: &Element) -> Option<Vec<u8>> {
    let data = element.one(XENC, "CipherData").ok()??;
    base64(data.one(XENC, "CipherValue").ok()??)
}

/// The content key, from one of `encrypted_keys`, with one of `private_keys` (PKCS#8,
/// tried in order).
fn content_key(
    encrypted_keys: &[&Element],
    private_keys: &[Zeroizing<Vec<u8>>],
    len: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    for private in private_keys {
        let Ok(private) = PrivateDecryptingKey::from_pkcs8(private) else {
            continue;
        };
        let Ok(private) = OaepPrivateDecryptingKey::new(private) else {
            continue;
        };
        for encrypted in encrypted_keys {
            let Some((algorithm, label)) = encrypted
                .one(XENC, "EncryptionMethod")
                .ok()
                .flatten()
                .and_then(oaep)
            else {
                continue;
            };
            let Some(ciphertext) = cipher_value(encrypted) else {
                continue;
            };
            let mut out = Zeroizing::new(vec![0; private.min_output_size()]);
            let label = (!label.is_empty()).then_some(label.as_slice());
            if let Ok(key) = private.decrypt(algorithm, &ciphertext, &mut out, label)
                && key.len() == len
            {
                return Some(Zeroizing::new(key.to_vec()));
            }
        }
    }
    None
}

/// The text of the assertion `encrypted` (an `EncryptedAssertion`) holds, decrypted
/// with one of `private_keys` (PKCS#8, newest first).
pub(crate) fn decrypt(
    encrypted: &Element,
    private_keys: &[Zeroizing<Vec<u8>>],
) -> Result<String, String> {
    let fail = || UNDECRYPTABLE.to_owned();
    let data = encrypted
        .one(XENC, "EncryptedData")
        .ok()
        .flatten()
        .ok_or_else(fail)?;
    if data
        .attr("Type")
        .is_some_and(|t| t != "http://www.w3.org/2001/04/xmlenc#Element")
    {
        return Err(fail());
    }
    let content = data
        .one(XENC, "EncryptionMethod")
        .ok()
        .flatten()
        .and_then(|m| m.attr("Algorithm"))
        .and_then(Content::find)
        .ok_or_else(fail)?;
    // The content key is in the data's KeyInfo, or beside the data.
    let mut encrypted_keys: Vec<&Element> = Vec::new();
    if let Ok(Some(info)) = data.one(DS, "KeyInfo") {
        encrypted_keys.extend(info.all(XENC, "EncryptedKey"));
    }
    encrypted_keys.extend(encrypted.all(XENC, "EncryptedKey"));
    let key = content_key(&encrypted_keys, private_keys, content.key_len()).ok_or_else(fail)?;
    let ciphertext = cipher_value(data).ok_or_else(fail)?;
    let plain = content.decrypt(&key, &ciphertext).ok_or_else(fail)?;
    String::from_utf8(plain).map_err(|_| fail())
}

#[cfg(test)]
pub(crate) mod tests {
    //! Assertions encrypted as an identity provider encrypts them.

    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use aws_lc_rs::{
        cipher::PaddedBlockEncryptingKey,
        rand::{SecureRandom, SystemRandom},
        rsa::OaepPublicEncryptingKey,
    };

    use super::*;
    use crate::saml::private_key::{pkcs8, tests::new_pem};

    /// How a test assertion is encrypted: the key transport's URI and its digest and
    /// mask URIs, and the content's algorithm URI.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Scheme {
        pub(crate) transport: &'static str,
        pub(crate) digest: Option<&'static str>,
        pub(crate) mgf: Option<&'static str>,
        pub(crate) content: &'static str,
        /// The OAEP label (`OAEPparams`), if there's one.
        pub(crate) label: Option<&'static [u8]>,
        /// Whether the encrypted key is beside the data rather than in its `KeyInfo`.
        pub(crate) beside: bool,
    }

    pub(crate) const MGF1P_AES256_CBC: Scheme = Scheme {
        transport: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        digest: Some("http://www.w3.org/2000/09/xmldsig#sha1"),
        mgf: None,
        content: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
        label: None,
        beside: false,
    };

    pub(crate) const OAEP256_AES128_GCM: Scheme = Scheme {
        transport: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        digest: Some("http://www.w3.org/2001/04/xmlenc#sha256"),
        mgf: Some("http://www.w3.org/2009/xmlenc11#mgf1sha256"),
        content: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        label: None,
        beside: false,
    };

    /// `assertion` (its XML) encrypted for the PKCS#8 key `private` as an
    /// `EncryptedAssertion` whose `saml`, `xenc` and `ds` prefixes are declared on it.
    pub(crate) fn encrypt(assertion: &str, private: &[u8], scheme: Scheme) -> String {
        let rng = SystemRandom::new();
        let content = Content::find(scheme.content).unwrap();
        let mut key = vec![0; content.key_len()];
        rng.fill(&mut key).unwrap();
        let public = PrivateDecryptingKey::from_pkcs8(private)
            .unwrap()
            .public_key();
        let public = OaepPublicEncryptingKey::new(public).unwrap();
        let digest = scheme.digest.map_or(1, |d| oaep_hash(d).unwrap());
        let algorithm = match digest {
            256 => &OAEP_SHA256_MGF1SHA256,
            384 => &OAEP_SHA384_MGF1SHA384,
            512 => &OAEP_SHA512_MGF1SHA512,
            _ => &OAEP_SHA1_MGF1SHA1,
        };
        let mut wrapped = vec![0; public.ciphertext_size()];
        let wrapped = public
            .encrypt(algorithm, &key, &mut wrapped, scheme.label)
            .unwrap();
        let data = match content {
            Content::Cbc(len) => {
                let algorithm = if len == 16 { &AES_128 } else { &AES_256 };
                let cbc = PaddedBlockEncryptingKey::cbc_pkcs7(
                    UnboundCipherKey::new(algorithm, &key).unwrap(),
                )
                .unwrap();
                let mut buffer = assertion.as_bytes().to_vec();
                let made = cbc.encrypt(&mut buffer).unwrap();
                let DecryptionContext::Iv128(iv) = made else {
                    unreachable!()
                };
                let iv: &[u8] = iv.as_ref();
                [iv, buffer.as_slice()].concat()
            }
            Content::Gcm(len) => {
                let algorithm = if len == 16 {
                    &AES_128_GCM
                } else {
                    &AES_256_GCM
                };
                let key = LessSafeKey::new(UnboundKey::new(algorithm, &key).unwrap());
                let mut nonce = [0; 12];
                rng.fill(&mut nonce).unwrap();
                let mut buffer = assertion.as_bytes().to_vec();
                key.seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    &mut buffer,
                )
                .unwrap();
                [&nonce[..], &buffer].concat()
            }
        };
        let digest = scheme
            .digest
            .map(|d| format!("<ds:DigestMethod Algorithm=\"{d}\"/>"))
            .unwrap_or_default();
        let label = scheme
            .label
            .map(|l| format!("<xenc:OAEPparams>{}</xenc:OAEPparams>", STANDARD.encode(l)))
            .unwrap_or_default();
        let mgf = scheme
            .mgf
            .map(|m| format!("<xenc11:MGF xmlns:xenc11=\"{XENC11}\" Algorithm=\"{m}\"/>"))
            .unwrap_or_default();
        let encrypted_key = format!(
            "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{transport}\">\
             {digest}{mgf}{label}</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>\
             {wrapped}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>",
            transport = scheme.transport,
            wrapped = STANDARD.encode(wrapped),
        );
        let (inside, beside) = if scheme.beside {
            (String::new(), encrypted_key)
        } else {
            (
                format!("<ds:KeyInfo>{encrypted_key}</ds:KeyInfo>"),
                String::new(),
            )
        };
        format!(
            "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
             xmlns:xenc=\"{XENC}\" xmlns:ds=\"{DS}\"><xenc:EncryptedData \
             Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod \
             Algorithm=\"{content}\"/>{inside}<xenc:CipherData><xenc:CipherValue>{data}\
             </xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>{beside}\
             </saml:EncryptedAssertion>",
            content = scheme.content,
            data = STANDARD.encode(data),
        )
    }

    fn decrypted(xml: &str, keys: &[Zeroizing<Vec<u8>>]) -> Result<String, String> {
        decrypt(&crate::saml::xml::parse(xml).unwrap(), keys)
    }

    #[test]
    fn assertions_are_decrypted_with_any_of_the_keys() {
        let assertion = "<saml:Assertion xmlns:saml=\"urn:x\">é &amp; more</saml:Assertion>";
        let ours = pkcs8(&new_pem()).unwrap();
        let other = pkcs8(&new_pem()).unwrap();
        for scheme in [
            MGF1P_AES256_CBC,
            OAEP256_AES128_GCM,
            Scheme {
                digest: None,
                content: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                ..MGF1P_AES256_CBC
            },
            Scheme {
                label: Some(b"label"),
                beside: true,
                ..MGF1P_AES256_CBC
            },
            // XML Encryption 1.1's OAEP masks with SHA-1 unless it says otherwise.
            Scheme {
                digest: Some("http://www.w3.org/2000/09/xmldsig#sha1"),
                mgf: None,
                ..OAEP256_AES128_GCM
            },
            Scheme {
                digest: Some("http://www.w3.org/2001/04/xmldsig-more#sha384"),
                mgf: Some("http://www.w3.org/2009/xmlenc11#mgf1sha384"),
                content: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
                ..OAEP256_AES128_GCM
            },
        ] {
            let xml = encrypt(assertion, &ours, scheme);
            // The newest key first, or not: either decrypts.
            for keys in [[other.clone(), ours.clone()], [ours.clone(), other.clone()]] {
                assert_eq!(
                    decrypted(&xml, &keys).as_deref(),
                    Ok(assertion),
                    "{scheme:?}"
                );
            }
            assert_eq!(
                decrypted(&xml, std::slice::from_ref(&other)),
                Err(UNDECRYPTABLE.to_owned())
            );
        }
    }

    #[test]
    fn anything_else_is_refused_alike() {
        let key = pkcs8(&new_pem()).unwrap();
        let keys = [key.clone()];
        let gcm = encrypt("<a/>", &key, OAEP256_AES128_GCM);
        let cbc = encrypt("<a/>", &key, MGF1P_AES256_CBC);
        let labeled = encrypt(
            "<a/>",
            &key,
            Scheme {
                label: Some(b"label"),
                ..OAEP256_AES128_GCM
            },
        );
        let end = "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>";
        for (xml, from, to) in [
            // Algorithms aws-lc has, or AWS takes, only.
            (
                &gcm,
                "aes128-gcm\"/><ds:KeyInfo>",
                "aes192-gcm\"/><ds:KeyInfo>",
            ),
            (&gcm, "#mgf1sha256", "#mgf1sha1"),
            (&gcm, "xmlenc11#rsa-oaep\"", "xmlenc#rsa-1_5\""),
            (&gcm, "#Element\"", "#Content\""),
            (&labeled, "<xenc:OAEPparams>", "<xenc:OAEPparams>AAAA"),
            // Ciphertexts that don't decrypt.
            (&gcm, "<xenc:CipherValue>", "<xenc:CipherValue>AAAA"),
            (&cbc, end, &format!("AAAAAAAAAAAAAAAAAAAAAA=={end}")),
            (&gcm, end, &format!("AAAA{end}")),
            // No data.
            (&gcm, "<xenc:EncryptedData ", "<xenc:Other "),
        ] {
            let xml = xml
                .replacen(from, to, 1)
                .replace("</xenc:EncryptedData>", "</xenc:Other>");
            let xml = if xml.contains("<xenc:Other ") {
                xml
            } else {
                xml.replace("</xenc:Other>", "</xenc:EncryptedData>")
            };
            assert_eq!(
                decrypted(&xml, &keys),
                Err(UNDECRYPTABLE.to_owned()),
                "{from}"
            );
        }
        assert!(decrypted(&gcm, &keys).is_ok());
        assert!(decrypted(&cbc, &keys).is_ok());
        assert!(decrypted(&labeled, &keys).is_ok());
        // A key of the wrong size for the content is passed over for the next one.
        let key_of = |xml: &str| {
            let from = xml.find("<xenc:EncryptedKey>").unwrap();
            let to = xml.find("</xenc:EncryptedKey>").unwrap() + "</xenc:EncryptedKey>".len();
            xml[from..to].to_owned()
        };
        let two = gcm.replacen(
            "<xenc:EncryptedKey>",
            &format!("{}<xenc:EncryptedKey>", key_of(&cbc)),
            1,
        );
        assert_eq!(decrypted(&two, &keys).as_deref(), Ok("<a/>"));
    }
}
