//! A SAML provider's metadata document: the identity provider's entity id (the issuer
//! its responses name) and the certificates whose keys sign them.
//!
//! As on AWS, a certificate's key must have at least 1024 bits and no extension may
//! appear twice, and its dates aren't checked: responses are trusted for as long as
//! the metadata names the key.

use base64::{Engine, engine::general_purpose::STANDARD};
use x509_parser::{
    oid_registry::{OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521},
    prelude::{FromDer, X509Certificate},
    public_key::PublicKey as Parsed,
};

use super::xml::{self, Element};
use crate::oidc::jwt::{Curve, PublicKey};

/// SAML 2.0 metadata's namespace.
pub(crate) const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// XML Signature's namespace.
pub(crate) const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The protocol an identity provider must support.
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// The fewest bits an RSA key may have, as on AWS.
const MIN_RSA_BITS: usize = 1024;

/// What a metadata document says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Metadata {
    /// The identity provider's entity id: the issuer its responses name.
    pub(crate) entity_id: String,
    /// The keys that may sign its responses.
    pub(crate) keys: Vec<PublicKey>,
}

/// Why a metadata document can't be used, in AWS's words and then ours.
fn bad<T>(why: impl std::fmt::Display) -> Result<T, String> {
    Err(format!("Could not parse metadata: {why}."))
}

/// Reads a metadata document: an `EntityDescriptor`, or an `EntitiesDescriptor` with
/// one identity provider in it.
pub(crate) fn parse(document: &str) -> Result<Metadata, String> {
    let root = match xml::parse(document) {
        Ok(root) => root,
        Err(err) => return bad(err),
    };
    let entity = if root.is(MD, "EntityDescriptor") {
        &root
    } else if root.is(MD, "EntitiesDescriptor") {
        let mut providers = root
            .descendants()
            .into_iter()
            .filter(|e| e.is(MD, "EntityDescriptor") && idps(e).next().is_some());
        match (providers.next(), providers.next()) {
            (Some(one), None) => one,
            (None, _) => return bad("it describes no identity provider"),
            (Some(_), Some(_)) => return bad("it describes more than one identity provider"),
        }
    } else {
        return bad("its root isn't a SAML 2.0 EntityDescriptor");
    };
    let entity_id = match entity.attr("entityID").map(str::trim) {
        Some(id) if !id.is_empty() && id.len() <= 1024 => id.to_owned(),
        _ => return bad("its EntityDescriptor has no entityID"),
    };
    let mut keys = Vec::new();
    let mut found = false;
    for idp in idps(entity) {
        found = true;
        for descriptor in idp.all(MD, "KeyDescriptor") {
            if !matches!(descriptor.attr("use"), None | Some("signing")) {
                continue;
            }
            for certificate in certificates(descriptor) {
                let key = key(&certificate?)?;
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
    }
    if !found {
        return bad("it has no IDPSSODescriptor for SAML 2.0");
    }
    if keys.is_empty() {
        return bad("it has no signing certificate");
    }
    Ok(Metadata { entity_id, keys })
}

/// The SAML 2.0 identity provider descriptors of `entity`.
fn idps(entity: &Element) -> impl Iterator<Item = &Element> {
    entity.all(MD, "IDPSSODescriptor").filter(|idp| {
        idp.attr("protocolSupportEnumeration")
            .is_some_and(|p| p.split_ascii_whitespace().any(|p| p == PROTOCOL))
    })
}

/// The DER certificates of a `KeyDescriptor`'s `KeyInfo`.
fn certificates(descriptor: &Element) -> impl Iterator<Item = Result<Vec<u8>, String>> + '_ {
    descriptor
        .all(DS, "KeyInfo")
        .flat_map(|info| info.all(DS, "X509Data"))
        .flat_map(|data| data.all(DS, "X509Certificate"))
        .map(|certificate| {
            let text = certificate.text().or_else(bad)?;
            let text: String = text.split_ascii_whitespace().collect();
            STANDARD
                .decode(text)
                .or_else(|_| bad("a certificate isn't base64"))
        })
}

/// The public key of a certificate, if AWS would take it.
pub(crate) fn key(der: &[u8]) -> Result<PublicKey, String> {
    let Ok((rest, certificate)) = X509Certificate::from_der(der) else {
        return bad("a certificate isn't an X.509 certificate");
    };
    if !rest.is_empty() {
        return bad("a certificate has data after it");
    }
    if certificate.extensions_map().is_err() {
        return bad("a certificate has an extension more than once");
    }
    let spki = certificate.public_key();
    match spki.parsed() {
        Ok(Parsed::RSA(rsa)) if rsa.key_size() >= MIN_RSA_BITS => Ok(PublicKey::Rsa {
            n: strip(rsa.modulus).to_vec(),
            e: strip(rsa.exponent).to_vec(),
        }),
        Ok(Parsed::RSA(_)) => bad(format!(
            "a certificate's RSA key has fewer than {MIN_RSA_BITS} bits"
        )),
        Ok(Parsed::EC(point)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok());
            let curve = match curve {
                Some(oid) if oid == OID_EC_P256 => Curve::P256,
                Some(oid) if oid == OID_NIST_EC_P384 => Curve::P384,
                Some(oid) if oid == OID_NIST_EC_P521 => Curve::P521,
                _ => return bad("a certificate's elliptic curve isn't P-256, P-384 or P-521"),
            };
            Ok(PublicKey::Ec {
                curve,
                point: point.data().to_vec(),
            })
        }
        _ => bad("a certificate's key isn't an RSA or elliptic curve key"),
    }
}

/// A big-endian integer without its leading zero bytes.
fn strip(mut bytes: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use rcgen::{
        CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256,
        PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256, RsaKeySize,
    };

    use std::fmt::Write as _;

    use super::*;

    /// A self-signed certificate (DER) and its key pair.
    pub(crate) fn certificate(rsa: bool) -> (Vec<u8>, KeyPair) {
        let key = if rsa {
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap()
        } else {
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
        };
        let cert = CertificateParams::new(vec!["idp.example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.der().to_vec(), key)
    }

    /// A metadata document for `entity_id` with these signing certificates.
    pub(crate) fn document(entity_id: &str, certificates: &[&[u8]]) -> String {
        let mut keys = String::new();
        for der in certificates {
            let _ = write!(
                keys,
                "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data>\
                 <ds:X509Certificate>\n{}\n</ds:X509Certificate></ds:X509Data>\
                 </ds:KeyInfo></md:KeyDescriptor>",
                STANDARD.encode(der)
            );
        }
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor \
             xmlns:md=\"{MD}\" xmlns:ds=\"{DS}\" entityID=\"{entity_id}\">\
             <md:IDPSSODescriptor protocolSupportEnumeration=\"{PROTOCOL}\">{keys}\
             <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
             Location=\"https://idp.example.com/sso\"/></md:IDPSSODescriptor>\
             </md:EntityDescriptor>"
        )
    }

    #[test]
    fn the_entity_id_and_signing_keys_are_read() {
        let (rsa, _) = certificate(true);
        let (ec, _) = certificate(false);
        let doc = document("https://idp.example.com/saml", &[&rsa, &ec, &rsa]);
        let read = parse(&doc).unwrap();
        assert_eq!(read.entity_id, "https://idp.example.com/saml");
        assert_eq!(read.keys.len(), 2);
        assert!(matches!(read.keys[0], PublicKey::Rsa { ref n, .. } if n.len() == 256));
        assert!(matches!(
            read.keys[1],
            PublicKey::Ec { curve: Curve::P256, ref point } if point.len() == 65
        ));
        let p384 = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let p384 = CertificateParams::new(vec!["idp.example.com".into()])
            .unwrap()
            .self_signed(&p384)
            .unwrap();
        let read = parse(&document("x", &[p384.der()])).unwrap();
        assert!(matches!(
            read.keys[0],
            PublicKey::Ec { curve: Curve::P384, ref point } if point.len() == 97
        ));
        assert_eq!(
            parse(&document(&"i".repeat(1024), &[&rsa]))
                .unwrap()
                .entity_id
                .len(),
            1024
        );

        // An encryption key isn't a signing key; one without `use` is both.
        let encryption = doc.replacen("use=\"signing\"", "use=\"encryption\"", 1);
        assert_eq!(parse(&encryption).unwrap().keys.len(), 2);
        let both = doc.replace(" use=\"signing\"", "");
        assert_eq!(parse(&both).unwrap().keys.len(), 2);

        // An EntitiesDescriptor with one identity provider in it.
        let wrapped = format!(
            "<md:EntitiesDescriptor xmlns:md=\"{MD}\">\
             <md:EntityDescriptor entityID=\"sp\"><md:SPSSODescriptor/></md:EntityDescriptor>{}\
             </md:EntitiesDescriptor>",
            doc.split_once("?>\n").unwrap().1
        );
        assert_eq!(
            parse(&wrapped).unwrap().entity_id,
            "https://idp.example.com/saml"
        );
    }

    /// A self-signed certificate with a 1000-bit RSA key (made with OpenSSL).
    const SMALL_RSA: &str = "MIIB9DCCAWGgAwIBAgIUDjoJXHrnZFQVrIBr+TthQP6Y8wAwDQYJKoZIhvcNAQELBQAwEDEOMAwGA1UEAwwFc21hbGwwHhcNMjYxMDAxMTEyMzM5WhcNMzYwOTI4MTEyMzM5WjAQMQ4wDAYDVQQDDAVzbWFsbDCBmzANBgkqhkiG9w0BAQEFAAOBiQAwgYUCfgC1k0lCxT1evcgNp6MkRTyZMZnV9JQZdq353cGcq+gunZ5XQxYRFv0gyCE/slmRUl2BDA308KMD89i2BejRqjjO9B1AkzsJiSpwBypjx1nf8FKFQLBsj8P4smRZVTxEXcckae7gnc49T8gguGfSXNdNFHuB8dVnzlJkyMxQrwIDAQABo1MwUTAdBgNVHQ4EFgQU077rYj5+2jV325YK0X1TeV6TYX4wHwYDVR0jBBgwFoAU077rYj5+2jV325YK0X1TeV6TYX4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAN+AIE0zDQoADT5ad2IjAcx1s3OABC/XvN9s17GDybU4hTSh3mHEFpzKoBgZdRtnAq6xD4opFKIQwMo88XLrJtXJFlW2o/yooWztjnnDKIexnYtvpEAiM7IRjQnPpAzdfr2weBw1/I2PwhCaDP3SmPrNoCXvSff1EZHXXQS1ixr";

    #[test]
    fn metadata_aws_wouldnt_take_is_refused() {
        let (rsa, _) = certificate(true);
        let good = document("https://idp.example.com/saml", &[&rsa]);
        let small = STANDARD.decode(SMALL_RSA).unwrap();
        let mut twice = CertificateParams::new(vec!["idp.example.com".into()]).unwrap();
        let extension = CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]);
        twice.custom_extensions = vec![extension.clone(), extension];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let twice = twice.self_signed(&key).unwrap().der().to_vec();
        let encryption_only = good.replace("use=\"signing\"", "use=\"encryption\"");
        let saml1 = good.replace(PROTOCOL, "urn:oasis:names:tc:SAML:1.1:protocol");
        let no_id = good.replace("entityID=\"https://idp.example.com/saml\"", "");
        let blank_id = good.replace(
            "entityID=\"https://idp.example.com/saml\"",
            "entityID=\" \"",
        );
        let long_id = document(&"i".repeat(1025), &[&rsa]);
        let mut trailing = rsa.clone();
        trailing.push(0);
        let two = format!(
            "<md:EntitiesDescriptor xmlns:md=\"{MD}\">{}{}</md:EntitiesDescriptor>",
            good.split_once("?>\n").unwrap().1,
            good.split_once("?>\n").unwrap().1,
        );
        for (doc, why) in [
            ("<a/>".to_owned(), "isn't a SAML 2.0 EntityDescriptor"),
            (
                "not xml".to_owned(),
                "Could not parse metadata: it has text outside",
            ),
            (no_id, "has no entityID"),
            (blank_id, "has no entityID"),
            (long_id, "has no entityID"),
            (document("x", &[&trailing]), "data after it"),
            (saml1, "no IDPSSODescriptor for SAML 2.0"),
            (encryption_only, "no signing certificate"),
            (
                document("x", &[b"not a certificate"]),
                "isn't an X.509 certificate",
            ),
            (document("x", &[&twice]), "an extension more than once"),
            (document("x", &[&small]), "fewer than 1024 bits"),
            (
                good.replace("<ds:X509Certificate>\n", "<ds:X509Certificate>!"),
                "isn't base64",
            ),
            (two, "more than one identity provider"),
            (
                format!("<md:EntitiesDescriptor xmlns:md=\"{MD}\"/>"),
                "no identity provider",
            ),
        ] {
            let err = parse(&doc).unwrap_err();
            assert!(err.contains(why), "{err}");
            assert!(err.starts_with("Could not parse metadata: "), "{err}");
        }
    }
}
