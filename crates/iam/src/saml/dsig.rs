//! XML signatures (<https://www.w3.org/TR/xmldsig-core1/>) as SAML uses them: an
//! enveloped signature on the element it signs, with one reference to that element's
//! `ID`, made by one of the keys the provider's metadata names.
//!
//! Only what SAML's profile allows is accepted, which is also what keeps signature
//! wrapping out: the `Signature` is a child of the element it signs, its only
//! `Reference` names that element's own `ID`, no other element of the document has
//! that `ID`, and the transforms are the enveloped signature and exclusive
//! canonicalization, in that order. Keys in the signature's `KeyInfo` are ignored: only
//! the metadata's are trusted. A caller reads only the element that was verified.

use aws_lc_rs::{
    digest,
    signature::{self, RsaPublicKeyComponents, UnparsedPublicKey, VerificationAlgorithm},
};
use base64::{Engine, engine::general_purpose::STANDARD};

use super::{
    c14n::{self, Options},
    metadata::DS,
    xml::Element,
};
use crate::oidc::jwt::{Curve, PublicKey};

/// Exclusive canonicalization's namespace, which is also its algorithm's URI.
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Why a signature isn't accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub(crate) struct BadSignature(pub(crate) String);

fn bad<T>(why: impl Into<String>) -> Result<T, BadSignature> {
    Err(BadSignature(why.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn digest(uri: &str) -> Option<Self> {
        Some(match uri {
            "http://www.w3.org/2000/09/xmldsig#sha1" => Self::Sha1,
            "http://www.w3.org/2001/04/xmlenc#sha256" => Self::Sha256,
            "http://www.w3.org/2001/04/xmldsig-more#sha384" => Self::Sha384,
            "http://www.w3.org/2001/04/xmlenc#sha512" => Self::Sha512,
            _ => return None,
        })
    }

    fn algorithm(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
            Self::Sha512 => &digest::SHA512,
        }
    }
}

/// A signature method: RSA (PKCS#1 v1.5) or ECDSA, with a hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Rsa(Hash),
    Ecdsa(Hash),
}

impl Method {
    fn find(uri: &str) -> Option<Self> {
        const MORE: &str = "http://www.w3.org/2001/04/xmldsig-more#";
        if uri == "http://www.w3.org/2000/09/xmldsig#rsa-sha1" {
            return Some(Self::Rsa(Hash::Sha1));
        }
        let name = uri.strip_prefix(MORE)?;
        let (kind, hash) = name.split_once('-')?;
        let hash = match hash {
            "sha1" => Hash::Sha1,
            "sha256" => Hash::Sha256,
            "sha384" => Hash::Sha384,
            "sha512" => Hash::Sha512,
            _ => return None,
        };
        match kind {
            "rsa" if hash != Hash::Sha1 => Some(Self::Rsa(hash)),
            "ecdsa" => Some(Self::Ecdsa(hash)),
            _ => None,
        }
    }

    /// Whether `key` made `signature` over `message` this way.
    fn verify(self, key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
        match (self, key) {
            (Self::Rsa(hash), PublicKey::Rsa { n, e }) => {
                let params = match hash {
                    Hash::Sha1 => &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                    Hash::Sha256 => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                    // aws-lc-rs takes SHA-384 only with keys of 2048 bits or more.
                    Hash::Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    Hash::Sha512 => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                };
                RsaPublicKeyComponents { n, e }
                    .verify(params, message, signature)
                    .is_ok()
            }
            (Self::Ecdsa(hash), PublicKey::Ec { curve, point }) => {
                let Some(algorithm) = ecdsa(*curve, hash) else {
                    return false;
                };
                let Some(der) = ecdsa_der(signature, curve_size(*curve)) else {
                    return false;
                };
                UnparsedPublicKey::new(algorithm, point)
                    .verify(message, &der)
                    .is_ok()
            }
            _ => false,
        }
    }
}

/// The ECDSA verification for a curve and hash, when there's one.
fn ecdsa(curve: Curve, hash: Hash) -> Option<&'static dyn VerificationAlgorithm> {
    Some(match (curve, hash) {
        (Curve::P256, Hash::Sha1) => &signature::ECDSA_P256_SHA1_ASN1,
        (Curve::P256, Hash::Sha256) => &signature::ECDSA_P256_SHA256_ASN1,
        (Curve::P256, Hash::Sha384) => &signature::ECDSA_P256_SHA384_ASN1,
        (Curve::P256, Hash::Sha512) => &signature::ECDSA_P256_SHA512_ASN1,
        (Curve::P384, Hash::Sha256) => &signature::ECDSA_P384_SHA256_ASN1,
        (Curve::P384, Hash::Sha384) => &signature::ECDSA_P384_SHA384_ASN1,
        (Curve::P384, Hash::Sha512) => &signature::ECDSA_P384_SHA512_ASN1,
        (Curve::P521, Hash::Sha1) => &signature::ECDSA_P521_SHA1_ASN1,
        (Curve::P521, Hash::Sha256) => &signature::ECDSA_P521_SHA256_ASN1,
        (Curve::P521, Hash::Sha384) => &signature::ECDSA_P521_SHA384_ASN1,
        (Curve::P521, Hash::Sha512) => &signature::ECDSA_P521_SHA512_ASN1,
        (Curve::P384, Hash::Sha1) => return None,
    })
}

const fn curve_size(curve: Curve) -> usize {
    match curve {
        Curve::P256 => 32,
        Curve::P384 => 48,
        Curve::P521 => 66,
    }
}

/// An XML signature's ECDSA value (`r` then `s`, each the curve's size) as DER.
fn ecdsa_der(fixed: &[u8], size: usize) -> Option<Vec<u8>> {
    if fixed.len() != 2 * size {
        return None;
    }
    let mut body = Vec::new();
    for half in fixed.chunks(size) {
        let mut int = half;
        while let [0, rest @ ..] = int {
            int = rest;
        }
        body.push(0x02);
        let pad = int.first().is_none_or(|b| b & 0x80 != 0);
        let len = int.len() + usize::from(pad);
        push_length(&mut body, len);
        if pad {
            body.push(0);
        }
        body.extend_from_slice(int);
    }
    let mut der = vec![0x30];
    push_length(&mut der, body.len());
    der.extend_from_slice(&body);
    Some(der)
}

fn push_length(out: &mut Vec<u8>, len: usize) {
    // An ECDSA signature's parts are at most 67 bytes, so two length bytes suffice.
    if let Ok(short) = u8::try_from(len)
        && short < 0x80
    {
        out.push(short);
    } else {
        out.push(0x81);
        out.push(u8::try_from(len).unwrap_or(u8::MAX));
    }
}

/// The only child element of `parent` that's `name` in `ns`.
fn one<'a>(parent: &'a Element, ns: &str, name: &str) -> Result<&'a Element, BadSignature> {
    match parent.one(ns, name) {
        Ok(Some(e)) => Ok(e),
        Ok(None) => bad(format!("<{name}> is missing")),
        Err(e) => Err(BadSignature(e.to_string())),
    }
}

fn algorithm(element: &Element) -> Result<&str, BadSignature> {
    match element.attr("Algorithm") {
        Some(uri) => Ok(uri),
        None => bad(format!("<{}> has no Algorithm", element.name)),
    }
}

fn base64(element: &Element) -> Result<Vec<u8>, BadSignature> {
    let text = element.text().map_err(|e| BadSignature(e.to_string()))?;
    let text: String = text.split_ascii_whitespace().collect();
    STANDARD
        .decode(text)
        .or_else(|_| bad(format!("<{}> isn't base64", element.name)))
}

/// How a canonicalization element (`CanonicalizationMethod`, or a `Transform`) says
/// to canonicalize: with comments or not, and its inclusive prefixes.
fn canonicalization(element: &Element) -> Result<Option<(bool, Vec<String>)>, BadSignature> {
    let comments = match algorithm(element)? {
        EXC_C14N => false,
        EXC_C14N_COMMENTS => true,
        _ => return Ok(None),
    };
    let mut prefixes = Vec::new();
    for inclusive in element.all(EXC_C14N, "InclusiveNamespaces") {
        for prefix in inclusive
            .attr("PrefixList")
            .unwrap_or("")
            .split_ascii_whitespace()
        {
            prefixes.push(if prefix == "#default" { "" } else { prefix }.to_owned());
        }
    }
    Ok(Some((comments, prefixes)))
}

/// Every `ID` attribute value in `roots` (a document, and any element decrypted from
/// it), which must each be unique.
pub(crate) fn unique_ids(roots: &[&Element]) -> Result<(), BadSignature> {
    let mut seen = std::collections::BTreeSet::new();
    for element in roots.iter().flat_map(|root| root.descendants()) {
        if let Some(id) = element.attr("ID")
            && !seen.insert(id)
        {
            return bad(format!("the ID {id} appears more than once"));
        }
    }
    Ok(())
}

/// Whether `element` is signed, and if it is, that the signature is good and made by
/// one of `keys`. Its document's IDs must have been checked with [`unique_ids`].
pub(crate) fn verify(element: &Element, keys: &[PublicKey]) -> Result<bool, BadSignature> {
    let mut signatures = element.all(DS, "Signature");
    let Some(signature) = signatures.next() else {
        return Ok(false);
    };
    if signatures.next().is_some() {
        return bad("the element has more than one signature");
    }
    let signed_info = one(signature, DS, "SignedInfo")?;
    let Some((comments, inclusive)) =
        canonicalization(one(signed_info, DS, "CanonicalizationMethod")?)?
    else {
        return bad("SignedInfo isn't canonicalized with exclusive canonicalization");
    };
    let method = algorithm(one(signed_info, DS, "SignatureMethod")?)?;
    let Some(method) = Method::find(method) else {
        return bad(format!("the signature method {method} isn't supported"));
    };
    let reference = one(signed_info, DS, "Reference")?;
    let Some(id) = element.attr("ID") else {
        return bad("the signed element has no ID");
    };
    if reference.attr("URI").and_then(|u| u.strip_prefix('#')) != Some(id) {
        return bad("the signature's reference isn't to the element it's in");
    }
    let transforms: Vec<&Element> = one(reference, DS, "Transforms")?
        .all(DS, "Transform")
        .collect();
    let [enveloped, exclusive] = transforms.as_slice() else {
        return bad(
            "the reference's transforms aren't the enveloped signature and exclusive canonicalization",
        );
    };
    if algorithm(enveloped)? != ENVELOPED {
        return bad("the reference's first transform isn't the enveloped signature");
    }
    // A bare-name reference (`#ID`) leaves comments out, whatever the transform says.
    let Some((_, reference_inclusive)) = canonicalization(exclusive)? else {
        return bad("the reference's second transform isn't exclusive canonicalization");
    };
    let digest_uri = algorithm(one(reference, DS, "DigestMethod")?)?;
    let Some(hash) = Hash::digest(digest_uri) else {
        return bad(format!("the digest method {digest_uri} isn't supported"));
    };
    let content = c14n::canonicalize(
        element,
        &Options {
            comments: false,
            inclusive: &reference_inclusive,
            without: Some(signature),
        },
    );
    let digest = digest::digest(hash.algorithm(), &content);
    if digest.as_ref() != base64(one(reference, DS, "DigestValue")?)?.as_slice() {
        return bad("the signed element's digest doesn't match");
    }
    let signed = c14n::canonicalize(
        signed_info,
        &Options {
            comments,
            inclusive: &inclusive,
            without: None,
        },
    );
    let value = base64(one(signature, DS, "SignatureValue")?)?;
    if keys.iter().any(|key| method.verify(key, &signed, &value)) {
        Ok(true)
    } else {
        bad("no key of the provider made the signature")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use rustls::pki_types::{CertificateDer, pem::PemObject};

    use super::*;
    use crate::{
        oidc::jwt::tests::Signer,
        saml::{metadata, xml},
    };

    /// `document` with the empty `DigestValue` and `SignatureValue` of the signature in
    /// the element whose ID is `id` filled in: signed by `signer` with `method` (a JOSE
    /// algorithm name, `RS256` or `ES256`), as an identity provider signs.
    pub(crate) fn sign(document: &str, id: &str, signer: &Signer, method: &str) -> String {
        let element_of = |root: &Element| -> Element {
            root.descendants()
                .into_iter()
                .find(|e| e.attr("ID") == Some(id))
                .unwrap()
                .clone()
        };
        let root = xml::parse(document).unwrap();
        let element = element_of(&root);
        let signature = element.one(DS, "Signature").unwrap().unwrap();
        let reference = one(one(signature, DS, "SignedInfo").unwrap(), DS, "Reference").unwrap();
        let transform = one(reference, DS, "Transforms")
            .unwrap()
            .all(DS, "Transform")
            .nth(1);
        let inclusive = transform
            .and_then(|t| canonicalization(t).unwrap())
            .map(|(_, p)| p)
            .unwrap_or_default();
        let hash =
            Hash::digest(algorithm(one(reference, DS, "DigestMethod").unwrap()).unwrap()).unwrap();
        let content = c14n::canonicalize(
            &element,
            &Options {
                inclusive: &inclusive,
                without: Some(signature),
                ..Options::default()
            },
        );
        let digest = STANDARD.encode(digest::digest(hash.algorithm(), &content));
        let digested = fill(
            document,
            id,
            "<ds:DigestValue/>",
            &format!("<ds:DigestValue>{digest}</ds:DigestValue>"),
        );
        let root = xml::parse(&digested).unwrap();
        let element = element_of(&root);
        let signed_info = one(
            element.one(DS, "Signature").unwrap().unwrap(),
            DS,
            "SignedInfo",
        )
        .unwrap();
        let (comments, inclusive) =
            canonicalization(one(signed_info, DS, "CanonicalizationMethod").unwrap())
                .unwrap()
                .unwrap();
        let canonical = c14n::canonicalize(
            signed_info,
            &Options {
                comments,
                inclusive: &inclusive,
                without: None,
            },
        );
        let value = STANDARD.encode(signer.sign(method, &canonical));
        fill(
            &digested,
            id,
            "<ds:SignatureValue/>",
            &format!("<ds:SignatureValue>{value}</ds:SignatureValue>"),
        )
    }

    /// `document` with the first `empty` after the element whose ID is `id` starts
    /// replaced by `full`.
    fn fill(document: &str, id: &str, empty: &str, full: &str) -> String {
        let start = document.find(&format!("ID=\"{id}\"")).unwrap();
        let at = start + document[start..].find(empty).unwrap();
        format!("{}{full}{}", &document[..at], &document[at + empty.len()..])
    }

    /// The key of a PEM certificate, as metadata would name it.
    fn key(pem: &str) -> PublicKey {
        let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        metadata::key(&der).unwrap()
    }

    const RSA_CERT: &str = include_str!("testdata/rsa.crt");
    const EC_CERT: &str = include_str!("testdata/ec.crt");
    /// Responses whose assertion xmlsec1 signed, by signature method.
    const SIGNED: [(&str, &str, &str); 4] = [
        (
            "rsa-sha1",
            RSA_CERT,
            include_str!("testdata/signed-rsa-sha1.xml"),
        ),
        (
            "rsa-sha256",
            RSA_CERT,
            include_str!("testdata/signed-rsa-sha256.xml"),
        ),
        (
            "rsa-sha512",
            RSA_CERT,
            include_str!("testdata/signed-rsa-sha512.xml"),
        ),
        (
            "ecdsa-sha256",
            EC_CERT,
            include_str!("testdata/signed-ecdsa-sha256.xml"),
        ),
    ];

    fn check(document: &str, keys: &[PublicKey]) -> Result<bool, BadSignature> {
        let root = xml::parse(document).map_err(|e| BadSignature(e.to_string()))?;
        unique_ids(&[&root])?;
        let assertion = root
            .descendants()
            .into_iter()
            .find(|e| e.name == "Assertion")
            .unwrap();
        // The response itself isn't signed.
        assert_eq!(verify(&root, keys), Ok(false));
        verify(assertion, keys)
    }

    #[test]
    fn the_default_namespace_is_named_by_a_hash() {
        let transform = xml::parse(&format!(
            r##"<t Algorithm="{EXC_C14N}"><e:InclusiveNamespaces xmlns:e="{EXC_C14N}" PrefixList="#default xs"/></t>"##
        ))
        .unwrap();
        assert_eq!(
            canonicalization(&transform),
            Ok(Some((false, vec![String::new(), "xs".to_owned()])))
        );
    }

    #[test]
    fn signatures_xmlsec_made_are_verified() {
        for (method, cert, document) in SIGNED {
            assert_eq!(check(document, &[key(cert)]), Ok(true), "{method}");
            // Line ends written as Windows writes them read the same.
            let crlf = document.replace('\n', "\r\n");
            assert_eq!(check(&crlf, &[key(cert)]), Ok(true), "{method}");
            // Only a key of the provider will do.
            let other = if cert == RSA_CERT { EC_CERT } else { RSA_CERT };
            let err = check(document, &[key(other)]).unwrap_err();
            assert!(err.0.contains("no key of the provider"), "{method}: {err}");
        }
    }

    #[test]
    fn any_change_to_what_was_signed_is_found() {
        let (_, cert, document) = SIGNED[1];
        let keys = [key(cert)];
        // Comments and white space between attributes aren't signed; the rest is.
        let commented = document.replace("<saml:Subject>", "<!-- new --><saml:Subject >");
        assert_eq!(check(&commented, &keys), Ok(true));
        for (from, to, why) in [
            ("alice &amp; co", "bob &amp; co", "digest doesn't match"),
            (
                "NotOnOrAfter=\"2026-10-01T12:05",
                "NotOnOrAfter=\"2027-10-01T12:05",
                "digest",
            ),
            (
                "<ds:SignatureValue>",
                "<ds:SignatureValue>AAAA",
                "no key of the provider",
            ),
            (
                "URI=\"#_a1\"",
                "URI=\"#_r1\"",
                "isn't to the element it's in",
            ),
            ("URI=\"#_a1\"", "URI=\"\"", "isn't to the element it's in"),
            ("ID=\"_r1\"", "ID=\"_a1\"", "appears more than once"),
            (
                "xml-exc-c14n#\"/>",
                "xml-c14n-20010315\"/>",
                "exclusive canonicalization",
            ),
            ("#enveloped-signature\"/>", "#base64\"/>", "first transform"),
            ("rsa-sha256", "hmac-sha256", "isn't supported"),
            ("xmlenc#sha256", "xmlenc#sha224", "isn't supported"),
            ("<ds:DigestValue>", "<ds:DigestValue>!", "isn't base64"),
            (
                "</ds:SignedInfo>",
                "</ds:SignedInfo><ds:SignedInfo/>",
                "more than once",
            ),
            (
                "<ds:SignatureValue>",
                "<ds:SignatureValu>",
                "isn't well-formed",
            ),
        ] {
            assert_eq!(document.matches(from).count(), 1, "{from}");
            let changed = document.replacen(from, to, 1);
            let err = check(&changed, &keys).unwrap_err();
            assert!(err.0.contains(why), "{from} → {to}: {err}");
        }
        // A second signature, and transforms out of order.
        let (start, end) = (
            document.find("<ds:Signature ").unwrap(),
            document.find("</ds:Signature>").unwrap() + "</ds:Signature>".len(),
        );
        let twice = document.replacen(
            "<saml:Subject>",
            &format!("{}<saml:Subject>", &document[start..end]),
            1,
        );
        assert!(
            check(&twice, &keys)
                .unwrap_err()
                .0
                .contains("more than one signature")
        );
    }

    #[test]
    fn every_method_verifies_and_ecdsa_values_become_der() {
        const MORE: &str = "http://www.w3.org/2001/04/xmldsig-more#";
        let template = |method: &str, digest: &str| {
            format!(
                "<r:Response xmlns:r=\"urn:r\" ID=\"_x\"><ds:Signature xmlns:ds=\"{DS}\">\
                 <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{EXC_C14N_COMMENTS}\"/>\
                 <ds:SignatureMethod Algorithm=\"{method}\"/><ds:Reference URI=\"#_x\">\
                 <ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"/>\
                 <ds:Transform Algorithm=\"{EXC_C14N_COMMENTS}\"/></ds:Transforms>\
                 <ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue/></ds:Reference>\
                 </ds:SignedInfo><ds:SignatureValue/></ds:Signature><!--c--><r:x>1</r:x>\
                 </r:Response>"
            )
        };
        let rsa = Signer::rsa();
        for (signer, method, jose) in [
            (&rsa, "rsa-sha256", "RS256"),
            (&rsa, "rsa-sha384", "RS384"),
            (&rsa, "rsa-sha512", "RS512"),
            (&Signer::ec(Curve::P256), "ecdsa-sha256", "ES256"),
            (&Signer::ec(Curve::P384), "ecdsa-sha384", "ES384"),
            (&Signer::ec(Curve::P521), "ecdsa-sha512", "ES512"),
        ] {
            for digest in [
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2001/04/xmldsig-more#sha384",
                "http://www.w3.org/2001/04/xmlenc#sha512",
            ] {
                let document = sign(
                    &template(&format!("{MORE}{method}"), digest),
                    "_x",
                    signer,
                    jose,
                );
                let root = xml::parse(&document).unwrap();
                assert_eq!(
                    verify(&root, &[signer.public()]),
                    Ok(true),
                    "{method} {digest}"
                );
            }
        }
        // rsa-sha1 is the 2000 namespace's, not xmldsig-more's.
        assert_eq!(Method::find(&format!("{MORE}rsa-sha1")), None);
        assert_eq!(
            Method::find("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
            Some(Method::Rsa(Hash::Sha1))
        );
        assert!(ecdsa(Curve::P384, Hash::Sha1).is_none());
        // DER integers are positive and minimal.
        let mut fixed = vec![0; 64];
        fixed[31] = 0x7f;
        fixed[32] = 0x80;
        assert_eq!(
            ecdsa_der(&fixed, 32).unwrap()[..7],
            [0x30, 0x26, 0x02, 0x01, 0x7f, 0x02, 0x21]
        );
        assert_eq!(ecdsa_der(&fixed[..63], 32), None);
        let mut zero = Vec::new();
        push_length(&mut zero, 0x85);
        assert_eq!(zero, [0x81, 0x85]);
    }
}
