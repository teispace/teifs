//! A SAML identity provider's responses, for other crates' tests: what `AssumeRoleWithSAML`
//! takes from a browser that signed in, signed as identity providers sign.

#![allow(
    clippy::unwrap_used,
    reason = "a test double: a bad key or clock fails the test"
)]

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::response::{ASSERTION, PROTOCOL};

/// An enveloped signature to fill in (RSA-SHA256 over exclusive canonicalization, a
/// SHA-256 digest) for the element whose ID is `ID`.
pub(crate) const SIGNATURE: &str = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
    <ds:SignedInfo><ds:CanonicalizationMethod \
    Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod \
    Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\
    <ds:Reference URI=\"#ID\"><ds:Transforms><ds:Transform \
    Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform \
    Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>\
    <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
    <ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>";

/// What a response says.
#[derive(Debug, Clone, Copy)]
pub struct Response<'a> {
    /// The identity provider: its metadata's `entityID`.
    pub issuer: &'a str,
    /// Who signed in (a persistent `NameID`).
    pub subject: &'a str,
    /// The `Role` attribute: `role ARN,provider ARN` pairs.
    pub roles: &'a [&'a str],
    /// The `RoleSessionName` attribute.
    pub session_name: &'a str,
}

/// `response` as `AssumeRoleWithSAML` takes it: the base64 of a SAML 2.0 response for
/// AWS's sign-in endpoint and audience, good for five minutes, whose assertion is signed
/// with `key` (an RSA key, PKCS#8).
#[must_use]
pub fn response(response: &Response<'_>, key: &[u8]) -> String {
    let at = |offset: i64| {
        (OffsetDateTime::now_utc() + Duration::seconds(offset))
            .format(&Rfc3339)
            .unwrap()
    };
    let (now, ends) = (at(0), at(300));
    let escape = |text: &str| {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('"', "&quot;")
    };
    let attribute = |name: &str, values: &[&str]| {
        let values: String = values
            .iter()
            .flat_map(|v| {
                [
                    "<saml:AttributeValue>",
                    &escape(v),
                    "</saml:AttributeValue>",
                ]
                .map(str::to_owned)
            })
            .collect();
        format!(
            "<saml:Attribute Name=\"https://aws.amazon.com/SAML/Attributes/{name}\">{values}\
             </saml:Attribute>"
        )
    };
    let (issuer, recipient) = (
        escape(response.issuer),
        "https://signin.aws.amazon.com/saml",
    );
    let document = format!(
        "<samlp:Response xmlns:samlp=\"{PROTOCOL}\" xmlns:saml=\"{ASSERTION}\" \
         ID=\"_response\" Version=\"2.0\" IssueInstant=\"{now}\" Destination=\"{recipient}\">\
         <saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode \
         Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>\
         <saml:Assertion ID=\"_assertion\" Version=\"2.0\" IssueInstant=\"{now}\">\
         <saml:Issuer>{issuer}</saml:Issuer>{signature}<saml:Subject><saml:NameID \
         Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{subject}\
         </saml:NameID><saml:SubjectConfirmation \
         Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData \
         NotOnOrAfter=\"{ends}\" Recipient=\"{recipient}\"/></saml:SubjectConfirmation>\
         </saml:Subject><saml:Conditions NotBefore=\"{now}\" NotOnOrAfter=\"{ends}\">\
         <saml:AudienceRestriction><saml:Audience>urn:amazon:webservices</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement \
         AuthnInstant=\"{now}\"/><saml:AttributeStatement>{roles}{name}\
         </saml:AttributeStatement></saml:Assertion></samlp:Response>",
        signature = SIGNATURE.replace("#ID", "#_assertion"),
        subject = escape(response.subject),
        roles = attribute("Role", response.roles),
        name = attribute("RoleSessionName", &[response.session_name]),
    );
    let key = RsaKeyPair::from_pkcs8(key).unwrap();
    let signed = super::dsig::sign(&document, "_assertion", |canonical| {
        let mut signature = vec![0; key.public_modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            canonical,
            &mut signature,
        )
        .unwrap();
        signature
    });
    STANDARD.encode(signed)
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256, RsaKeySize};

    use super::*;
    use crate::saml::{
        metadata::{self, tests::document},
        response::{Provider, read},
    };

    #[test]
    fn its_responses_are_taken() {
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let cert = CertificateParams::new(vec!["idp.example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let issuer = "https://idp.example.com/saml";
        let metadata = metadata::parse(&document(issuer, &[cert.der()])).unwrap();
        let encoded = response(
            &Response {
                issuer,
                subject: "a&b",
                roles: &["role,provider"],
                session_name: "alice",
            },
            &key.serialize_der(),
        );
        let provider = Provider {
            metadata: &metadata,
            uuid: "",
            private_keys: &[],
            encrypted_only: false,
        };
        let read = read(&encoded, &provider, crate::sessions::now_seconds()).unwrap();
        assert_eq!(read.subject, "a&b");
        assert_eq!(
            read.attribute("https://aws.amazon.com/SAML/Attributes/Role"),
            Some(&["role,provider".to_owned()][..])
        );
    }
}
