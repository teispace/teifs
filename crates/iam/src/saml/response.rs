//! A SAML 2.0 response as `AssumeRoleWithSAML` takes it (AWS's checks): from the
//! account's provider, successful, signed by a key its metadata names (the response,
//! its assertion or both), for AWS's sign-in endpoint, within its times, and saying who
//! the user is and what they may assume.
//!
//! What's read comes only from a signed element: the assertion is read when it, or the
//! response it's in, is the element a signature verified. An encrypted assertion is
//! decrypted with the provider's private keys first; the response's signature then
//! covers its ciphertext.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use super::{
    dsig, encryption,
    metadata::Metadata,
    xml::{self, Element},
};

/// SAML 2.0's protocol and assertion namespaces.
pub(crate) const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub(crate) const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
/// The `NameID` format a SAML 2.0 `NameID` without one has.
const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
/// The prefix AWS takes off a `NameID` format for `SubjectType`.
const FORMAT_PREFIX: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:";
/// How far a provider's clock may be from TeiFS's, in seconds.
pub(crate) const CLOCK_SKEW: i64 = 300;
/// The longest response accepted, as AWS's `SAMLAssertion` (base64).
pub(crate) const MAX_ENCODED: usize = 100_000;

/// Why a response isn't accepted, as AWS answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    /// `InvalidIdentityToken`.
    Invalid(String),
    /// `ExpiredTokenException`.
    Expired(String),
    /// `IDPRejectedClaim`: the provider says the sign-in failed.
    Rejected(String),
    /// `AccessDenied`.
    Denied(String),
}

fn invalid<T>(why: impl Into<String>) -> Result<T, Refused> {
    Err(Refused::Invalid(why.into()))
}

/// An attribute of the assertion: its `Name`, `FriendlyName` and values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attribute {
    pub(crate) name: String,
    pub(crate) friendly_name: Option<String>,
    pub(crate) values: Vec<String>,
}

/// What a verified response says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Assertion {
    /// The provider's entity id (`Issuer`).
    pub(crate) issuer: String,
    /// The `NameID`.
    pub(crate) subject: String,
    /// The `NameID`'s format, without AWS's usual prefix (`persistent`).
    pub(crate) subject_type: String,
    /// The bearer confirmation's `Recipient`: AWS's sign-in endpoint.
    pub(crate) recipient: String,
    /// When the provider's session ends (`SessionNotOnOrAfter`), in seconds.
    pub(crate) session_ends: Option<i64>,
    pub(crate) attributes: Vec<Attribute>,
}

impl Assertion {
    /// The values of the attribute `name`, if it's there.
    pub(crate) fn attribute(&self, name: &str) -> Option<&[String]> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.values.as_slice())
    }
}

/// The SAML provider a response is checked against.
pub(crate) struct Provider<'a> {
    pub(crate) metadata: &'a Metadata,
    /// Its `SAMLProviderUUID`, which a sign-in endpoint for it may end in.
    pub(crate) uuid: &'a str,
    /// Its private keys (PKCS#8), newest first, which decrypt encrypted assertions.
    pub(crate) private_keys: &'a [Zeroizing<Vec<u8>>],
    /// Whether its assertions must be encrypted (`AssertionEncryptionMode` `Required`).
    pub(crate) encrypted_only: bool,
}

/// A `xs:dateTime` attribute, in seconds since the Unix epoch.
fn time_of(element: &Element, name: &str) -> Result<Option<i64>, Refused> {
    let Some(text) = element.attr(name) else {
        return Ok(None);
    };
    match OffsetDateTime::parse(text.trim(), &Rfc3339) {
        Ok(t) => Ok(Some(t.unix_timestamp())),
        Err(_) => invalid(format!("{name} {text} isn't a date and time")),
    }
}

/// The text of the child `name` of `parent`, if it has one.
fn child_text(parent: &Element, ns: &str, name: &str) -> Result<Option<String>, Refused> {
    let child = parent.one(ns, name).or_else(|e| invalid(e.to_string()))?;
    child
        .map(|c| c.text().map(|t| t.trim().to_owned()))
        .transpose()
        .or_else(|e| invalid(e.to_string()))
}

/// Whether `url` is an AWS sign-in endpoint for SAML:
/// `https://signin.aws.amazon.com/saml`, a region's
/// (`https://us-east-1.signin.aws.amazon.com/saml`), China's or the US government
/// regions', or one of those followed by `/acs/` and the provider's UUID.
fn sign_in_endpoint(url: &str, uuid: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let regional = |base: &str| {
        host == base
            || host
                .strip_suffix(base)
                .and_then(|h| h.strip_suffix('.'))
                .is_some_and(|region| {
                    !region.is_empty()
                        && region
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
    };
    let host_ok = [
        "signin.aws.amazon.com",
        "signin.amazonaws.cn",
        "signin.amazonaws-us-gov.com",
    ]
    .iter()
    .any(|base| regional(base));
    host_ok
        && (path == "saml"
            || path
                .strip_prefix("saml/acs/")
                .is_some_and(|id| id.eq_ignore_ascii_case(uuid)))
}

/// Whether `audience` is one AWS takes: its service provider's name, or a sign-in
/// endpoint.
fn aws_audience(audience: &str, uuid: &str) -> bool {
    audience == "urn:amazon:webservices" || sign_in_endpoint(audience, uuid)
}

/// Reads and checks `encoded`, a base64 `samlp:Response`, at `now` (seconds).
pub(crate) fn read(encoded: &str, provider: &Provider<'_>, now: i64) -> Result<Assertion, Refused> {
    let compact: String = encoded.split_ascii_whitespace().collect();
    let Ok(bytes) = STANDARD.decode(compact) else {
        return invalid("The SAML response isn't base64");
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return invalid("The SAML response isn't UTF-8 text");
    };
    let root =
        xml::parse(&text).or_else(|e| invalid(format!("The SAML response is malformed: {e}")))?;
    if !root.is(PROTOCOL, "Response") {
        return invalid("The SAML response isn't a SAML 2.0 Response");
    }
    if root.attr("Version") != Some("2.0") {
        return invalid("The SAML response isn't SAML 2.0");
    }
    let status = root
        .one(PROTOCOL, "Status")
        .ok()
        .flatten()
        .and_then(|s| s.one(PROTOCOL, "StatusCode").ok().flatten())
        .and_then(|c| c.attr("Value"));
    if status != Some(SUCCESS) {
        return Err(Refused::Rejected(format!(
            "The identity provider didn't sign the user in (status {}).",
            status.unwrap_or("missing")
        )));
    }
    let issuer = &provider.metadata.entity_id;
    if let Some(named) = child_text(&root, ASSERTION, "Issuer")?
        && named != *issuer
    {
        return invalid("Issuer not present in specified provider");
    }
    let plain: Vec<&Element> = root.all(ASSERTION, "Assertion").collect();
    let encrypted: Vec<&Element> = root.all(ASSERTION, "EncryptedAssertion").collect();
    let unique = |roots: &[&Element]| {
        dsig::unique_ids(roots).or_else(|e| invalid(format!("Response signature invalid: {e}")))
    };
    let decrypted;
    let assertion = match (plain.as_slice(), encrypted.as_slice()) {
        ([_], []) if provider.encrypted_only => {
            return invalid(
                "The SAML provider requires encrypted assertions, and the response's \
                 assertion isn't encrypted",
            );
        }
        ([assertion], []) => {
            unique(&[&root])?;
            *assertion
        }
        ([], [encrypted]) => {
            let text = encryption::decrypt(encrypted, provider.private_keys).or_else(invalid)?;
            decrypted = xml::parse_in(&text, &encrypted.scope)
                .or_else(|e| invalid(format!("The encrypted assertion is malformed: {e}")))?;
            if !decrypted.is(ASSERTION, "Assertion") {
                return invalid("The encrypted assertion isn't an Assertion");
            }
            unique(&[&root, &decrypted])?;
            &decrypted
        }
        _ => return invalid("The SAML response must have exactly one assertion"),
    };
    let keys = &provider.metadata.keys;
    let signature =
        |e: dsig::BadSignature| Refused::Invalid(format!("Response signature invalid: {e}"));
    let response_signed = dsig::verify(&root, keys).map_err(signature)?;
    let assertion_signed = dsig::verify(assertion, keys).map_err(signature)?;
    if !response_signed && !assertion_signed {
        return invalid(
            "Response signature invalid: neither the response nor its assertion is signed",
        );
    }
    read_assertion(assertion, provider, now)
}

/// Reads a verified assertion.
fn read_assertion(
    assertion: &Element,
    provider: &Provider<'_>,
    now: i64,
) -> Result<Assertion, Refused> {
    let issuer = &provider.metadata.entity_id;
    if assertion.attr("Version") != Some("2.0") {
        return invalid("The assertion isn't SAML 2.0");
    }
    if child_text(assertion, ASSERTION, "Issuer")?.as_ref() != Some(issuer) {
        return invalid("Issuer not present in specified provider");
    }
    check_conditions(assertion, provider, now)?;
    let (subject, subject_type, recipient) = read_subject(assertion, provider, now)?;
    let mut session_ends = None;
    for statement in assertion.all(ASSERTION, "AuthnStatement") {
        if let Some(t) = time_of(statement, "SessionNotOnOrAfter")? {
            session_ends = Some(session_ends.map_or(t, |s: i64| s.min(t)));
        }
    }
    Ok(Assertion {
        issuer: issuer.clone(),
        subject,
        subject_type,
        recipient,
        session_ends,
        attributes: read_attributes(assertion)?,
    })
}

fn expired(what: &str) -> Refused {
    Refused::Expired(format!("The SAML assertion's {what} has passed."))
}

fn early(what: &str) -> Refused {
    Refused::Invalid(format!("The SAML assertion's {what} hasn't come yet."))
}

/// The assertion's `Conditions`: its times, and audiences AWS takes.
fn check_conditions(assertion: &Element, provider: &Provider<'_>, now: i64) -> Result<(), Refused> {
    let no_audience = "Response does not contain the required audience.";
    let Some(conditions) = assertion
        .one(ASSERTION, "Conditions")
        .or_else(|e| invalid(e.to_string()))?
    else {
        return invalid(no_audience);
    };
    if time_of(conditions, "NotBefore")?.is_some_and(|t| t > now + CLOCK_SKEW) {
        return Err(early("NotBefore"));
    }
    if time_of(conditions, "NotOnOrAfter")?.is_some_and(|t| t + CLOCK_SKEW <= now) {
        return Err(expired("NotOnOrAfter"));
    }
    let mut restrictions = conditions.all(ASSERTION, "AudienceRestriction").peekable();
    if restrictions.peek().is_none() {
        return invalid(no_audience);
    }
    // Every restriction must be met, each by one of its audiences.
    for restriction in restrictions {
        let mut met = false;
        for audience in restriction.all(ASSERTION, "Audience") {
            let text = audience.text().or_else(|e| invalid(e.to_string()))?;
            met |= aws_audience(text.trim(), provider.uuid);
        }
        if !met {
            return invalid(no_audience);
        }
    }
    Ok(())
}

/// The assertion's `Subject`: its `NameID`, the format AWS calls `SubjectType`, and
/// its one bearer confirmation's `Recipient`, an AWS sign-in endpoint.
fn read_subject(
    assertion: &Element,
    provider: &Provider<'_>,
    now: i64,
) -> Result<(String, String, String), Refused> {
    let subject = assertion
        .one(ASSERTION, "Subject")
        .or_else(|e| invalid(e.to_string()))?
        .ok_or_else(|| Refused::Denied("The SAML assertion has no Subject.".into()))?;
    let name_id = subject
        .one(ASSERTION, "NameID")
        .or_else(|e| invalid(e.to_string()))?
        .ok_or_else(|| Refused::Denied("The SAML assertion's Subject has no NameID.".into()))?;
    let name = name_id
        .text()
        .or_else(|e| invalid(e.to_string()))?
        .trim()
        .to_owned();
    if name.is_empty() {
        return Err(Refused::Denied(
            "The SAML assertion's NameID is empty.".into(),
        ));
    }
    let format = name_id.attr("Format").unwrap_or(UNSPECIFIED);
    let subject_type = format
        .strip_prefix(FORMAT_PREFIX)
        .unwrap_or(format)
        .to_owned();
    let mut bearers = subject
        .all(ASSERTION, "SubjectConfirmation")
        .filter(|c| c.attr("Method") == Some(BEARER));
    let (Some(bearer), None) = (bearers.next(), bearers.next()) else {
        return invalid("The SAML assertion must have exactly one bearer SubjectConfirmation.");
    };
    let data = bearer
        .one(ASSERTION, "SubjectConfirmationData")
        .or_else(|e| invalid(e.to_string()))?
        .ok_or_else(|| {
            Refused::Invalid(
                "The bearer SubjectConfirmation has no SubjectConfirmationData.".into(),
            )
        })?;
    match time_of(data, "NotOnOrAfter")? {
        None => return invalid("The SubjectConfirmationData has no NotOnOrAfter."),
        Some(t) if t + CLOCK_SKEW <= now => {
            return Err(expired("SubjectConfirmationData NotOnOrAfter"));
        }
        Some(_) => {}
    }
    if time_of(data, "NotBefore")?.is_some_and(|t| t > now + CLOCK_SKEW) {
        return Err(early("SubjectConfirmationData NotBefore"));
    }
    let recipient = data.attr("Recipient").unwrap_or_default().to_owned();
    // AWS asks for the provider's own endpoint when its assertions must be encrypted.
    if provider.encrypted_only && !recipient.contains("/saml/acs/") {
        return invalid(format!(
            "The SubjectConfirmationData Recipient {recipient:?} must be the SAML provider's \
             own sign-in endpoint (https://signin.aws.amazon.com/saml/acs/{}), as its \
             assertions are encrypted.",
            provider.uuid
        ));
    }
    if !sign_in_endpoint(&recipient, provider.uuid) {
        return invalid(format!(
            "The SubjectConfirmationData Recipient {recipient:?} isn't an AWS sign-in endpoint \
             (https://signin.aws.amazon.com/saml)."
        ));
    }
    Ok((name, subject_type, recipient))
}

/// The assertion's attributes, by name, the values of one named twice together.
fn read_attributes(assertion: &Element) -> Result<Vec<Attribute>, Refused> {
    let mut attributes: BTreeMap<String, Attribute> = BTreeMap::new();
    for statement in assertion.all(ASSERTION, "AttributeStatement") {
        for attribute in statement.all(ASSERTION, "Attribute") {
            let Some(name) = attribute.attr("Name") else {
                return invalid("An Attribute has no Name.");
            };
            let entry = attributes
                .entry(name.to_owned())
                .or_insert_with(|| Attribute {
                    name: name.to_owned(),
                    friendly_name: attribute.attr("FriendlyName").map(str::to_owned),
                    values: Vec::new(),
                });
            for value in attribute.all(ASSERTION, "AttributeValue") {
                let text = value.text().or_else(|e| invalid(e.to_string()))?;
                entry.values.push(text.trim().to_owned());
            }
        }
    }
    Ok(attributes.into_values().collect())
}

#[cfg(test)]
pub(crate) mod tests {
    //! A SAML identity provider for tests: its metadata, and the responses it signs.

    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use aws_lc_rs::signature::RsaKeyPair;
    use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
    use time::format_description::well_known::Rfc3339;

    use super::*;
    use crate::{
        oidc::jwt::tests::Signer,
        saml::{
            dsig::tests::sign,
            encryption::tests::{MGF1P_AES256_CBC, OAEP256_AES128_GCM, Scheme, encrypt},
            metadata::tests::document,
            private_key::{pkcs8, tests::new_pem},
        },
        sessions::now_seconds,
    };

    pub(crate) const ENTITY_ID: &str = "https://idp.example.com/saml";
    pub(crate) const SIGN_IN: &str = "https://signin.aws.amazon.com/saml";

    /// What's signed: the response, its assertion, both or neither.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Signed {
        Response,
        Assertion,
        Both,
        Neither,
    }

    /// What a response says. [`Saml::default`] is a good one with no attributes.
    #[derive(Debug, Clone)]
    pub(crate) struct Saml {
        pub(crate) issuer: String,
        pub(crate) subject: String,
        pub(crate) format: Option<String>,
        pub(crate) recipient: String,
        pub(crate) audience: String,
        /// The response's SAML version.
        pub(crate) version: String,
        /// The subject confirmation's method.
        pub(crate) method: String,
        /// Seconds from now that the confirmation and conditions end.
        pub(crate) expires_in: i64,
        /// Seconds from now that the conditions end, if not when the confirmation does.
        pub(crate) conditions_end_in: Option<i64>,
        /// Seconds from now that the conditions begin.
        pub(crate) begins_in: i64,
        /// Each authentication statement's `SessionNotOnOrAfter`, seconds from now.
        pub(crate) session_ends_in: Vec<Option<i64>>,
        pub(crate) status: String,
        pub(crate) attributes: Vec<(String, Vec<String>)>,
        pub(crate) signed: Signed,
        /// How the assertion is encrypted for the provider's private key, if it is.
        pub(crate) encrypted: Option<Scheme>,
    }

    impl Default for Saml {
        fn default() -> Self {
            Self {
                issuer: ENTITY_ID.into(),
                subject: "alice@example.com".into(),
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()),
                recipient: SIGN_IN.into(),
                audience: "urn:amazon:webservices".into(),
                version: "2.0".into(),
                method: BEARER.into(),
                expires_in: 300,
                conditions_end_in: None,
                begins_in: -60,
                session_ends_in: vec![None],
                status: "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
                attributes: Vec::new(),
                signed: Signed::Assertion,
                encrypted: None,
            }
        }
    }

    impl Saml {
        /// With AWS's attribute `name` (`RoleSessionName`) set to `values`.
        pub(crate) fn with(mut self, name: &str, values: &[&str]) -> Self {
            self.attributes.push((
                format!("https://aws.amazon.com/SAML/Attributes/{name}"),
                values.iter().map(|v| (*v).to_owned()).collect(),
            ));
            self
        }
    }

    fn at(seconds_from_now: i64) -> String {
        OffsetDateTime::from_unix_timestamp(now_seconds() + seconds_from_now)
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    }

    const SIGNATURE: &str = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
        <ds:SignedInfo><ds:CanonicalizationMethod \
        Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod \
        Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\
        <ds:Reference URI=\"#ID\"><ds:Transforms><ds:Transform \
        Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform \
        Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>\
        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
        <ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>";

    fn attributes_xml(attributes: &[(String, Vec<String>)]) -> String {
        use std::fmt::Write as _;
        let mut xml = String::new();
        for (name, values) in attributes {
            let _ = write!(xml, "<saml:Attribute Name=\"{name}\">");
            for value in values {
                let _ = write!(xml, "<saml:AttributeValue>{value}</saml:AttributeValue>");
            }
            xml.push_str("</saml:Attribute>");
        }
        xml
    }

    /// A SAML identity provider that signs with an RSA key its metadata names, and
    /// encrypts for the private key it gave the SAML provider.
    pub(crate) struct Idp {
        pub(crate) metadata: String,
        signer: Signer,
        /// The SAML provider's private key, as `AddPrivateKey` takes it.
        pub(crate) private_key_pem: String,
    }

    impl Idp {
        pub(crate) fn new() -> Self {
            let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
            let cert = CertificateParams::new(vec!["idp.example.com".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            Self {
                metadata: document(ENTITY_ID, &[cert.der()]),
                signer: Signer::Rsa(RsaKeyPair::from_pkcs8(&key.serialize_der()).unwrap()),
                private_key_pem: new_pem(),
            }
        }

        /// The response `saml` describes, as XML.
        pub(crate) fn xml(&self, saml: &Saml) -> String {
            use std::fmt::Write as _;

            let signature = |id: &str, signed: bool| {
                if signed {
                    SIGNATURE.replace("#ID", &format!("#{id}"))
                } else {
                    String::new()
                }
            };
            let (response_signed, assertion_signed) = match saml.signed {
                Signed::Response => (true, false),
                Signed::Assertion => (false, true),
                Signed::Both => (true, true),
                Signed::Neither => (false, false),
            };
            let format = saml
                .format
                .as_ref()
                .map(|f| format!(" Format=\"{f}\""))
                .unwrap_or_default();
            let mut statements = String::new();
            for ends in &saml.session_ends_in {
                let ends = ends
                    .map(|s| format!(" SessionNotOnOrAfter=\"{}\"", at(s)))
                    .unwrap_or_default();
                let begins = at(saml.begins_in);
                write!(
                    statements,
                    "<saml:AuthnStatement AuthnInstant=\"{begins}\"{ends}/>"
                )
                .unwrap();
            }
            let attributes = attributes_xml(&saml.attributes);
            let (issuer, ends, begins) = (&saml.issuer, at(saml.expires_in), at(saml.begins_in));
            let conditions_end = at(saml.conditions_end_in.unwrap_or(saml.expires_in));
            let document = format!(
                "<samlp:Response xmlns:samlp=\"{PROTOCOL}\" xmlns:saml=\"{ASSERTION}\" \
                 ID=\"_response\" Version=\"{version}\" IssueInstant=\"{begins}\" \
                 Destination=\"{recipient}\"><saml:Issuer>{issuer}</saml:Issuer>{response_sig}\
                 <samlp:Status><samlp:StatusCode Value=\"{status}\"/></samlp:Status>\
                 <saml:Assertion ID=\"_assertion\" Version=\"2.0\" IssueInstant=\"{begins}\">\
                 <saml:Issuer>{issuer}</saml:Issuer>{assertion_sig}<saml:Subject>\
                 <saml:NameID{format}>{subject}</saml:NameID><saml:SubjectConfirmation \
                 Method=\"{method}\"><saml:SubjectConfirmationData NotOnOrAfter=\"{ends}\" \
                 Recipient=\"{recipient}\"/></saml:SubjectConfirmation></saml:Subject>\
                 <saml:Conditions NotBefore=\"{begins}\" NotOnOrAfter=\"{conditions_end}\">\
                 <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>\
                 </saml:AudienceRestriction></saml:Conditions>{statements}\
                 <saml:AttributeStatement>{attributes}\
                 </saml:AttributeStatement></saml:Assertion></samlp:Response>",
                version = saml.version,
                method = saml.method,
                recipient = saml.recipient,
                response_sig = signature("_response", response_signed),
                status = saml.status,
                assertion_sig = signature("_assertion", assertion_signed),
                subject = saml.subject,
                audience = saml.audience,
            );
            let document = if assertion_signed {
                sign(&document, "_assertion", &self.signer, "RS256")
            } else {
                document
            };
            let document = match saml.encrypted {
                Some(scheme) => self.encrypted(&document, scheme, str::to_owned),
                None => document,
            };
            if response_signed {
                sign(&document, "_response", &self.signer, "RS256")
            } else {
                document
            }
        }

        /// `document` with its assertion, changed by `change`, encrypted with `scheme`.
        pub(crate) fn encrypted(
            &self,
            document: &str,
            scheme: Scheme,
            change: impl FnOnce(&str) -> String,
        ) -> String {
            let start = document.find("<saml:Assertion").unwrap();
            let end = document.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
            let key = pkcs8(&self.private_key_pem).unwrap();
            let encrypted = encrypt(&change(&document[start..end]), &key, scheme);
            format!("{}{encrypted}{}", &document[..start], &document[end..])
        }

        /// The response `saml` describes, as `SAMLAssertion` takes it (base64).
        pub(crate) fn response(&self, saml: &Saml) -> String {
            STANDARD.encode(self.xml(saml))
        }
    }

    fn checked(idp: &Idp, xml: &str) -> Result<Assertion, Refused> {
        read_by(idp, xml, false)
    }

    /// `xml` read by a provider with `idp`'s metadata and private key, which requires
    /// encrypted assertions if `encrypted_only`.
    fn read_by(idp: &Idp, xml: &str, encrypted_only: bool) -> Result<Assertion, Refused> {
        let metadata = crate::saml::metadata::parse(&idp.metadata).unwrap();
        let other = pkcs8(&new_pem()).unwrap();
        read(
            &STANDARD.encode(xml),
            &Provider {
                metadata: &metadata,
                uuid: "SAMLUUID",
                private_keys: &[other, pkcs8(&idp.private_key_pem).unwrap()],
                encrypted_only,
            },
            now_seconds(),
        )
    }

    #[test]
    fn signed_responses_are_read() {
        let idp = Idp::new();
        for signed in [Signed::Response, Signed::Assertion, Signed::Both] {
            let saml = Saml {
                signed,
                session_ends_in: vec![Some(7200), None, Some(9000)],
                ..Saml::default()
            }
            .with("RoleSessionName", &["alice"])
            .with("Role", &["a,b", "c,d"]);
            let read = checked(&idp, &idp.xml(&saml)).unwrap();
            assert_eq!(read.issuer, ENTITY_ID);
            assert_eq!(read.subject, "alice@example.com");
            assert_eq!(read.subject_type, "persistent");
            assert_eq!(read.recipient, SIGN_IN);
            // The soonest of the statements' sessions.
            assert!(
                read.session_ends
                    .is_some_and(|t| (7190..=7200).contains(&(t - now_seconds())))
            );
            assert_eq!(
                read.attribute("https://aws.amazon.com/SAML/Attributes/Role"),
                Some(&["a,b".to_owned(), "c,d".to_owned()][..])
            );
        }
        // Without a format, SAML's default; another format is kept whole.
        let unspecified = Saml {
            format: None,
            ..Saml::default()
        };
        assert_eq!(
            checked(&idp, &idp.xml(&unspecified)).unwrap().subject_type,
            UNSPECIFIED
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "every refusal, one after another")]
    fn responses_aws_would_refuse_are_refused() {
        let idp = Idp::new();
        let good = Saml::default();
        let invalid = |saml: Saml, why: &str| {
            let err = checked(&idp, &idp.xml(&saml)).unwrap_err();
            assert!(
                matches!(&err, Refused::Invalid(m) if m.contains(why)),
                "{why}: {err:?}"
            );
        };
        invalid(
            Saml {
                signed: Signed::Neither,
                ..good.clone()
            },
            "neither the response nor its assertion is signed",
        );
        invalid(
            Saml {
                issuer: "https://other.example.com".into(),
                ..good.clone()
            },
            "Issuer not present in specified provider",
        );
        invalid(
            Saml {
                audience: "https://teifs.example.com".into(),
                ..good.clone()
            },
            "Response does not contain the required audience.",
        );
        invalid(
            Saml {
                recipient: "https://teifs.example.com/saml".into(),
                ..good.clone()
            },
            "isn't an AWS sign-in endpoint",
        );
        invalid(
            Saml {
                begins_in: 600,
                ..good.clone()
            },
            "hasn't come yet",
        );
        invalid(
            Saml {
                version: "1.0".into(),
                ..good.clone()
            },
            "isn't SAML 2.0",
        );
        invalid(
            Saml {
                method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key".into(),
                ..good.clone()
            },
            "exactly one bearer SubjectConfirmation",
        );
        for expired in [
            Saml {
                expires_in: -400,
                ..good.clone()
            },
            Saml {
                conditions_end_in: Some(-400),
                ..good.clone()
            },
        ] {
            assert!(matches!(
                checked(&idp, &idp.xml(&expired)),
                Err(Refused::Expired(_))
            ));
        }
        let failed = Saml {
            status: "urn:oasis:names:tc:SAML:2.0:status:Responder".into(),
            ..good.clone()
        };
        assert!(matches!(
            checked(&idp, &idp.xml(&failed)),
            Err(Refused::Rejected(m)) if m.contains("status:Responder")
        ));
        let nameless = Saml {
            subject: String::new(),
            ..good.clone()
        };
        assert!(matches!(
            checked(&idp, &idp.xml(&nameless)),
            Err(Refused::Denied(_))
        ));
        // IDs are unique.
        let twice = idp
            .xml(&good)
            .replace("ID=\"_assertion\"", "ID=\"_response\"");
        assert!(matches!(
            checked(&idp, &twice),
            Err(Refused::Invalid(m)) if m.contains("the ID _response appears more than once")
        ));
        // Changed after signing.
        let xml = idp
            .xml(&good)
            .replace("alice@example.com", "mallory@example.com");
        assert!(matches!(checked(&idp, &xml), Err(Refused::Invalid(m)) if m.contains("digest")),);
        // A signed assertion moved into a response with another one: two assertions.
        let signed = idp.xml(&good);
        let assertion = &signed[signed.find("<saml:Assertion").unwrap()
            ..signed.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len()];
        let forged = assertion
            .replace("ID=\"_assertion\"", "ID=\"_forged\"")
            .replace("alice@", "mallory@");
        let wrapped = signed.replacen("<saml:Assertion", &format!("{forged}<saml:Assertion"), 1);
        assert!(matches!(
            checked(&idp, &wrapped),
            Err(Refused::Invalid(m)) if m.contains("exactly one assertion")
        ));
        // Endpoints AWS signs in at.
        for (url, ok) in [
            ("https://signin.aws.amazon.com/saml", true),
            ("https://us-east-1.signin.aws.amazon.com/saml", true),
            ("https://signin.amazonaws.cn/saml", true),
            (
                "https://us-gov-west-1.signin.amazonaws-us-gov.com/saml",
                true,
            ),
            ("https://signin.aws.amazon.com/saml/acs/samluuid", true),
            ("https://signin.aws.amazon.com/saml/acs/OTHER", false),
            ("http://signin.aws.amazon.com/saml", false),
            ("https://evil.example.com/signin.aws.amazon.com/saml", false),
            ("https://.signin.aws.amazon.com/saml", false),
            ("https://x.y.signin.aws.amazon.com/saml", false),
            ("https://signin.aws.amazon.com/other", false),
        ] {
            assert_eq!(sign_in_endpoint(url, "SAMLUUID"), ok, "{url}");
        }
        assert!(
            read(
                "!!",
                &Provider {
                    metadata: &crate::saml::metadata::parse(&idp.metadata).unwrap(),
                    uuid: "",
                    private_keys: &[],
                    encrypted_only: false,
                },
                0
            )
            .is_err()
        );
    }

    #[test]
    fn encrypted_assertions_are_decrypted_then_read() {
        let idp = Idp::new();
        for signed in [Signed::Response, Signed::Assertion, Signed::Both] {
            for scheme in [MGF1P_AES256_CBC, OAEP256_AES128_GCM] {
                let saml = Saml {
                    signed,
                    encrypted: Some(scheme),
                    ..Saml::default()
                }
                .with("RoleSessionName", &["alice"]);
                let read = checked(&idp, &idp.xml(&saml)).unwrap();
                assert_eq!(read.subject, "alice@example.com", "{signed:?} {scheme:?}");
                assert_eq!(
                    read.attribute("https://aws.amazon.com/SAML/Attributes/RoleSessionName"),
                    Some(&["alice".to_owned()][..])
                );
            }
        }
        // A provider that requires encryption takes only encrypted assertions, sent
        // to its own sign-in endpoint.
        let own = Saml {
            recipient: format!("{SIGN_IN}/acs/samluuid"),
            encrypted: Some(OAEP256_AES128_GCM),
            ..Saml::default()
        };
        assert!(read_by(&idp, &idp.xml(&own), true).is_ok());
        let refused = |saml: &Saml, why: &str| {
            let err = read_by(&idp, &idp.xml(saml), true).unwrap_err();
            assert!(
                matches!(&err, Refused::Invalid(m) if m.contains(why)),
                "{why}: {err:?}"
            );
        };
        refused(
            &Saml {
                encrypted: None,
                ..own.clone()
            },
            "requires encrypted assertions",
        );
        refused(
            &Saml {
                recipient: SIGN_IN.into(),
                ..own.clone()
            },
            "own sign-in endpoint (https://signin.aws.amazon.com/saml/acs/SAMLUUID)",
        );
    }

    #[test]
    fn encrypted_assertions_get_no_trust_of_their_own() {
        let idp = Idp::new();
        let invalid = |xml: &str, why: &str| {
            let err = checked(&idp, xml).unwrap_err();
            assert!(
                matches!(&err, Refused::Invalid(m) if m.contains(why)),
                "{why}: {err:?}"
            );
        };
        let encrypted = |signed| Saml {
            signed,
            encrypted: Some(OAEP256_AES128_GCM),
            ..Saml::default()
        };
        // Encryption isn't a signature.
        invalid(
            &idp.xml(&encrypted(Signed::Neither)),
            "neither the response nor its assertion is signed",
        );
        let plain = idp.xml(&Saml {
            signed: Signed::Neither,
            ..Saml::default()
        });
        let scheme = MGF1P_AES256_CBC;
        // Only the provider's keys decrypt.
        let start = plain.find("<saml:Assertion").unwrap();
        let end = plain.find("</samlp:Response>").unwrap();
        let elsewhere = encrypt(&plain[start..end], &pkcs8(&new_pem()).unwrap(), scheme);
        invalid(
            &format!("{}{elsewhere}{}", &plain[..start], &plain[end..]),
            "can't be decrypted with the SAML provider's private keys",
        );
        // What's decrypted must be one well-formed assertion, whose IDs are the
        // document's own.
        invalid(
            &idp.encrypted(&plain, scheme, |_| "<saml:Subject/>".into()),
            "isn't an Assertion",
        );
        invalid(
            &idp.encrypted(&plain, scheme, |_| "<saml:Assertion>".into()),
            "The encrypted assertion is malformed",
        );
        invalid(
            &idp.encrypted(&plain, scheme, |a| {
                a.replace("ID=\"_assertion\"", "ID=\"_response\"")
            }),
            "the ID _response appears more than once",
        );
        // One assertion, encrypted or not.
        let both = idp.encrypted(&plain, scheme, |a| format!("{a}{a}"));
        invalid(&both, "more than one root element");
        let assertion = &plain[start..end];
        let extra = idp.encrypted(&plain, scheme, str::to_owned);
        let extra = extra.replace(
            "</samlp:Response>",
            &format!("{assertion}</samlp:Response>"),
        );
        invalid(&extra, "exactly one assertion");
        // The response's signature covers the ciphertext: another can't be put in.
        let signed = idp.xml(&encrypted(Signed::Response));
        let forged = idp.encrypted(&plain, scheme, |a| a.replace("alice@", "mallory@"));
        let (from, to) = (
            signed.find("<saml:EncryptedAssertion").unwrap(),
            signed.find("</saml:EncryptedAssertion>").unwrap() + "</saml:EncryptedAssertion>".len(),
        );
        let (forged_from, forged_to) = (
            forged.find("<saml:EncryptedAssertion").unwrap(),
            forged.find("</saml:EncryptedAssertion>").unwrap() + "</saml:EncryptedAssertion>".len(),
        );
        let swapped = format!(
            "{}{}{}",
            &signed[..from],
            &forged[forged_from..forged_to],
            &signed[to..]
        );
        invalid(&swapped, "digest");
    }
}
