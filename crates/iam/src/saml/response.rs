//! A SAML 2.0 response as `AssumeRoleWithSAML` takes it (AWS's checks): from the
//! account's provider, successful, signed by a key its metadata names (the response,
//! its assertion or both), for AWS's sign-in endpoint, within its times, and saying who
//! the user is and what they may assume.
//!
//! What's read comes only from a signed element: the assertion is read when it, or the
//! response it's in, is the element a signature verified.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    dsig,
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
    dsig::unique_ids(&root).or_else(|e| invalid(format!("Response signature invalid: {e}")))?;
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
    let mut assertions = root.all(ASSERTION, "Assertion");
    let (Some(assertion), None) = (assertions.next(), assertions.next()) else {
        return invalid("The SAML response must have exactly one assertion");
    };
    if root
        .one(ASSERTION, "EncryptedAssertion")
        .ok()
        .flatten()
        .is_some()
    {
        return invalid("The SAML response must have exactly one assertion");
    }
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
        saml::{dsig::tests::sign, metadata::tests::document},
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

    /// A SAML identity provider that signs with an RSA key its metadata names.
    pub(crate) struct Idp {
        pub(crate) metadata: String,
        signer: Signer,
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
            if response_signed {
                sign(&document, "_response", &self.signer, "RS256")
            } else {
                document
            }
        }

        /// The response `saml` describes, as `SAMLAssertion` takes it (base64).
        pub(crate) fn response(&self, saml: &Saml) -> String {
            STANDARD.encode(self.xml(saml))
        }
    }

    fn checked(idp: &Idp, xml: &str) -> Result<Assertion, Refused> {
        let metadata = crate::saml::metadata::parse(&idp.metadata).unwrap();
        read(
            &STANDARD.encode(xml),
            &Provider {
                metadata: &metadata,
                uuid: "SAMLUUID",
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
                    uuid: ""
                },
                0
            )
            .is_err()
        );
    }
}
