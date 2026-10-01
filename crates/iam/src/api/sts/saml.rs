//! `AssumeRoleWithSAML`: a role's session for someone a SAML provider of the account
//! vouches for, as AWS gives it. The response must check out against the provider
//! (`crate::saml::response`); its `Role` attribute must name the role with the
//! provider; then the role's trust policy decides, with the `saml:` keys.

use std::sync::Arc;

use aws_lc_rs::digest;
use base64::{Engine, engine::general_purpose::STANDARD};
use teifs_policy::{Context, Principal, StsKey};
use zeroize::Zeroizing;

use super::{
    ARN_CHARS, ARN_PATTERN, ApiError, NAME_CHARS, Out, ROLE_LONGEST, Run, SHORTEST, answer, claims,
    credentials, duration, min_token_size, role_duration, session_policies, text,
};
use crate::{
    Identity,
    api::{On, with_request_tags, with_resource_tags},
    rules,
    saml::response::{self, Assertion, Provider, Refused},
    sessions::{SamlClaims, Who, now_seconds},
    state::{Encryption, Role, SamlProvider},
};

/// The action that exchanges a SAML response for a role's session.
pub(in crate::api) const SAML: &str = "AssumeRoleWithSAML";

/// The attributes AWS reads, by `Name`.
const ATTRIBUTES: &str = "https://aws.amazon.com/SAML/Attributes/";

/// The trust policy keys AWS makes of the eduPerson and eduOrg attributes, and `cn`, by
/// the attribute's `Name` (an OID URN).
const OID_KEYS: &[(&str, &str)] = &[
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
        "saml:edupersonaffiliation",
    ),
    ("urn:oid:1.3.6.1.4.1.5923.1.1.1.2", "saml:edupersonnickname"),
    ("urn:oid:1.3.6.1.4.1.5923.1.1.1.3", "saml:edupersonorgdn"),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.4",
        "saml:edupersonorgunitdn",
    ),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.5",
        "saml:edupersonprimaryaffiliation",
    ),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
        "saml:edupersonprincipalname",
    ),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
        "saml:edupersonentitlement",
    ),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.8",
        "saml:edupersonprimaryorgunitdn",
    ),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
        "saml:edupersonscopedaffiliation",
    ),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
        "saml:edupersontargetedid",
    ),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.11",
        "saml:edupersonassurance",
    ),
    ("urn:oid:1.3.6.1.4.1.5923.1.2.1.2", "saml:eduorghomepageuri"),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.2.1.3",
        "saml:eduorgidentityauthnpolicyuri",
    ),
    ("urn:oid:1.3.6.1.4.1.5923.1.2.1.4", "saml:eduorglegalname"),
    ("urn:oid:1.3.6.1.4.1.5923.1.2.1.5", "saml:eduorgsuperioruri"),
    (
        "urn:oid:1.3.6.1.4.1.5923.1.2.1.6",
        "saml:eduorgwhitepagesuri",
    ),
    ("urn:oid:2.5.4.3", "saml:cn"),
];

fn refused(err: Refused) -> ApiError {
    match err {
        Refused::Invalid(message) => super::invalid_token(message),
        Refused::Expired(message) => super::refused(crate::oidc::Refused::Expired(message)),
        Refused::Rejected(message) => ApiError {
            status: 403,
            code: "IDPRejectedClaim",
            message,
        },
        Refused::Denied(message) => ApiError::access_denied(message),
    }
}

/// The values of AWS's attribute `name`.
fn attribute<'a>(assertion: &'a Assertion, name: &str) -> Option<&'a [String]> {
    assertion.attribute(&format!("{ATTRIBUTES}{name}"))
}

/// AWS's attribute `name`, which may have only one value.
fn single<'a>(assertion: &'a Assertion, name: &str) -> Result<Option<&'a str>, ApiError> {
    match attribute(assertion, name) {
        None => Ok(None),
        Some([value]) => Ok(Some(value)),
        Some(_) => Err(super::invalid_token(format!(
            "The {name} attribute must have exactly one value."
        ))),
    }
}

/// Whether a `Role` attribute's value pairs `role` with `provider`, in either order.
fn names(value: &str, role: &str, provider: &str) -> bool {
    match value.split_once(',') {
        Some((a, b)) => (a == role && b == provider) || (a == provider && b == role),
        None => false,
    }
}

/// `RoleSessionName`: required, 2 to 64 of AWS's name characters.
fn session_name(assertion: &Assertion) -> Result<&str, ApiError> {
    let Some(name) = single(assertion, "RoleSessionName")? else {
        return Err(super::invalid_token(
            "RoleSessionName is required in AuthnResponse".into(),
        ));
    };
    let ok = (2..=64).contains(&name.chars().count())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || NAME_CHARS.contains(&b));
    if !ok {
        return Err(super::invalid_token(
            "RoleSessionName in AuthnResponse must match [a-zA-Z_0-9+=,.@-]{2,64}".into(),
        ));
    }
    Ok(name)
}

/// `SourceIdentity`, if the response sets it.
fn source_identity(assertion: &Assertion) -> Result<Option<&str>, ApiError> {
    let Some(source) = single(assertion, "SourceIdentity")? else {
        return Ok(None);
    };
    // Its characters have no ':', so it can't begin with "aws:".
    let ok = (2..=64).contains(&source.chars().count())
        && source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || NAME_CHARS.contains(&b));
    if !ok {
        return Err(super::invalid_token(
            "Source Identity must match [a-zA-Z_0-9+=,.@-]{2,64} and not begin with \"aws:\""
                .into(),
        ));
    }
    Ok(Some(source))
}

/// `SessionDuration`, in seconds, if the response sets it.
fn session_duration(assertion: &Assertion) -> Result<Option<u32>, ApiError> {
    let Some(text) = single(assertion, "SessionDuration")? else {
        return Ok(None);
    };
    match text.parse::<u32>() {
        Ok(seconds) if (SHORTEST..=ROLE_LONGEST).contains(&seconds) => Ok(Some(seconds)),
        _ => Err(super::invalid_token(format!(
            "SessionDuration in AuthnResponse must be a number of seconds from {SHORTEST} to \
             {ROLE_LONGEST}"
        ))),
    }
}

/// The session tags (`PrincipalTag:<key>`, one value each) and the keys of those that
/// are transitive (`TransitiveTagKeys`).
fn tags(assertion: &Assertion) -> Result<super::SessionTags, ApiError> {
    let prefix = format!("{ATTRIBUTES}PrincipalTag:");
    let mut tags: Vec<(String, String)> = Vec::new();
    for attribute in &assertion.attributes {
        let Some(key) = attribute.name.strip_prefix(&prefix) else {
            continue;
        };
        let [value] = attribute.values.as_slice() else {
            return Err(super::invalid_token(format!(
                "The PrincipalTag:{key} attribute must have exactly one value."
            )));
        };
        rules::tag(key, value).map_err(|err| super::invalid_token(err.to_string()))?;
        if tags.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)) {
            return Err(super::invalid_token(format!(
                "The tag {key} is set more than once in AuthnResponse"
            )));
        }
        tags.push((key.to_owned(), value.clone()));
    }
    if tags.len() > rules::MAX_TAGS {
        return Err(super::invalid_token(format!(
            "A session has at most {} tags.",
            rules::MAX_TAGS
        )));
    }
    let transitive = attribute(assertion, "TransitiveTagKeys")
        .unwrap_or_default()
        .to_vec();
    if let Some(key) = transitive
        .iter()
        .find(|key| !tags.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)))
    {
        return Err(super::invalid_token(format!(
            "The transitive tag key {key} isn't one of the session's tags."
        )));
    }
    Ok((tags, transitive))
}

/// AWS's `NameQualifier`: base64 of the SHA-1 of the issuer, the account id, `/` and the
/// provider's name.
fn name_qualifier(issuer: &str, account: &str, provider_name: &str) -> String {
    let text = format!("{issuer}{account}/{provider_name}");
    STANDARD.encode(digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        text.as_bytes(),
    ))
}

/// The provider's ARN, as IAM writes it.
fn provider_arn(r: &Run<'_>, provider: &SamlProvider) -> String {
    format!("arn:aws:iam::{}:saml-provider/{}", r.account, provider.name)
}

/// What a response asks for its session, from AWS's attributes.
struct Asked<'a> {
    name: &'a str,
    source: Option<&'a str>,
    /// `SessionDuration`.
    limit: Option<u32>,
    tags: Vec<(String, String)>,
    transitive: Vec<String>,
}

impl<'a> Asked<'a> {
    fn of(assertion: &'a Assertion) -> Result<Self, ApiError> {
        let (tags, transitive) = tags(assertion)?;
        Ok(Self {
            name: session_name(assertion)?,
            source: source_identity(assertion)?,
            limit: session_duration(assertion)?,
            tags,
            transitive,
        })
    }
}

/// What the trust policy may test: the `saml:` keys of the response, and what the
/// session asks for.
fn trust_context(
    r: &Run<'_>,
    role: &Role,
    provider: &SamlProvider,
    assertion: &Assertion,
    asked: &Asked<'_>,
    qualifier: &str,
) -> Context {
    let principal = Principal::web_identity(&provider_arn(r, provider), &assertion.subject);
    let mut context = r
        .base
        .clone()
        .with_principal(principal)
        .with_claim("saml:aud", assertion.recipient.as_str())
        .with_claim("saml:iss", assertion.issuer.as_str())
        .with_claim("saml:sub", assertion.subject.as_str())
        .with_claim("saml:sub_type", assertion.subject_type.as_str())
        .with_claim("saml:namequalifier", qualifier)
        .with_claim("saml:doc", format!("{}/{}", r.account, provider.name));
    for a in &assertion.attributes {
        if let Some((_, key)) = OID_KEYS.iter().find(|(oid, _)| *oid == a.name) {
            context = context.with_claim(key, a.values.clone());
        }
    }
    context = with_request_tags(context, &asked.tags).with_sts(StsKey::RoleSessionName, asked.name);
    if let Some(source) = asked.source {
        context = context.with_sts(StsKey::SourceIdentity, source);
    }
    if !asked.transitive.is_empty() {
        context = context.with_sts(StsKey::TransitiveTagKeys, asked.transitive.clone());
    }
    with_resource_tags(context, On::Role, &role.tags)
}

/// How long the session lasts: the shortest of what's asked (an hour if nothing is),
/// the role's longest, `SessionDuration` and what's left of the provider's session,
/// which must be at least 15 minutes.
fn session_seconds(
    requested: Option<u32>,
    role: &Role,
    asked: &Asked<'_>,
    assertion: &Assertion,
    now: i64,
) -> Result<u32, ApiError> {
    let mut seconds = role_duration(requested, false, role.max_session)?;
    if let Some(limit) = asked.limit {
        seconds = seconds.min(limit);
    }
    if let Some(ends) = assertion.session_ends {
        let left = u32::try_from((ends - now).max(0)).unwrap_or(u32::MAX);
        if left < SHORTEST {
            return Err(refused(Refused::Expired(
                "The SAML assertion's SessionNotOnOrAfter is less than 15 minutes away.".into(),
            )));
        }
        seconds = seconds.min(left);
    }
    Ok(seconds)
}

/// `SAMLAssertion`: the response, base64, 4 to 100 000 characters.
fn saml_assertion<'p>(r: &'p Run<'_>) -> Result<&'p str, ApiError> {
    let encoded =
        r.p.optional("SAMLAssertion")
            .ok_or_else(|| ApiError::missing("SAMLAssertion"))?;
    if !(4..=response::MAX_ENCODED).contains(&encoded.len()) {
        return Err(ApiError::validation(format!(
            "1 validation error detected: Value at 'sAMLAssertion' failed to satisfy \
             constraint: Member must have length between 4 and {}",
            response::MAX_ENCODED
        )));
    }
    Ok(encoded)
}

/// The SAML provider `provider_arn`, and what its response `encoded` says.
fn read_response(
    r: &Run<'_>,
    provider_arn: &str,
    encoded: &str,
    now: i64,
) -> Result<(Arc<SamlProvider>, Assertion), ApiError> {
    let Ok(provider) = r
        .iam
        .read(|s| s.saml_provider_by_arn(provider_arn).cloned())
    else {
        return Err(super::invalid_token(format!(
            "The SAML provider {provider_arn} doesn't exist."
        )));
    };
    let private_keys = private_keys(r, &provider);
    let assertion = response::read(
        encoded,
        &Provider {
            metadata: &provider.parsed,
            uuid: &provider.uuid,
            private_keys: &private_keys,
            encrypted_only: provider.encryption == Some(Encryption::Required),
        },
        now,
    )
    .map_err(refused)?;
    Ok((provider, assertion))
}

/// The provider's private keys, unsealed, newest first, as AWS tries them (any of them
/// decrypts; the newest likely does).
fn private_keys(r: &Run<'_>, provider: &SamlProvider) -> Vec<Zeroizing<Vec<u8>>> {
    provider
        .keys
        .iter()
        .rev()
        .filter_map(|k| r.iam.tokens.open_secret(k.id.as_bytes(), &k.sealed).ok())
        .collect()
}

pub(in crate::api) fn assume_role_with_saml(r: &Run<'_>) -> Out {
    let min_token = min_token_size(r)?;
    let arn = text(r, "RoleArn", 20..=2048, ARN_CHARS, ARN_PATTERN)?
        .ok_or_else(|| ApiError::missing("RoleArn"))?;
    let provider_arn = text(r, "PrincipalArn", 20..=2048, ARN_CHARS, ARN_PATTERN)?
        .ok_or_else(|| ApiError::missing("PrincipalArn"))?;
    let encoded = saml_assertion(r)?;
    let requested = duration(r, SHORTEST..=ROLE_LONGEST)?;
    let policies = session_policies(r)?;
    let now = now_seconds();
    let (provider, assertion) = read_response(r, provider_arn, encoded, now)?;
    let not_authorized = || super::not_authorized(SAML);
    if !attribute(&assertion, "Role")
        .unwrap_or_default()
        .iter()
        .any(|value| names(value, arn, provider_arn))
    {
        return Err(not_authorized());
    }
    let asked = Asked::of(&assertion)?;
    let Some(role) = r
        .iam
        .read(|s| Ok(s.id_of(arn).and_then(|id| s.roles.get(id)).cloned()))?
    else {
        return Err(not_authorized());
    };
    let qualifier = name_qualifier(&assertion.issuer, &r.account, &provider.name);
    let context = trust_context(r, &role, &provider, &assertion, &asked, &qualifier);
    // The request's signer, if any, has no part: only the trust policy can allow it.
    let anyone = Identity::anonymous();
    let needs = [
        ("sts:AssumeRoleWithSAML", true),
        ("sts:TagSession", !asked.tags.is_empty()),
        ("sts:SetSourceIdentity", asked.source.is_some()),
    ];
    for (action, needed) in needs {
        if needed && !anyone.allows_with(&context, action, arn, Some(&role.trust.policy)) {
            return Err(super::not_authorized(action));
        }
    }

    let seconds = session_seconds(requested, &role, &asked, &assertion, now)?;
    let name = asked.name;
    let mut claims = claims(
        Who::Role {
            role: role.id.clone(),
            name: name.to_owned(),
            chained: false,
        },
        seconds,
    );
    claims.policies = policies;
    claims.source = asked.source.map(str::to_owned);
    claims.tags = asked.tags;
    claims.transitive = asked.transitive;
    claims.saml = Some(SamlClaims {
        provider: self::provider_arn(r, &provider),
        sub: assertion.subject.clone(),
        sub_type: assertion.subject_type.clone(),
        namequalifier: qualifier.clone(),
    });
    let issued = r.iam.issue_at_least(&claims, min_token)?;
    let packed = !claims.policies.is_empty() || !claims.tags.is_empty();
    answer(|x| {
        credentials(x, &issued);
        x.el("AssumedRoleUser", |x| {
            x.text("AssumedRoleId", &format!("{}:{name}", role.id))
                .text(
                    "Arn",
                    &format!(
                        "arn:aws:sts::{}:assumed-role/{}/{name}",
                        r.account, role.name
                    ),
                );
        });
        if packed {
            x.number("PackedPolicySize", issued.utilization);
        }
        x.text("Subject", &assertion.subject)
            .text("SubjectType", &assertion.subject_type)
            .text("Issuer", &assertion.issuer)
            .text("Audience", &assertion.recipient)
            .text("NameQualifier", &qualifier)
            .maybe("SourceIdentity", claims.source.as_deref());
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_qualifiers_are_aws_s() {
        // base64(SHA-1("https://idp.example.com/saml" + "123456789012/Okta")).
        assert_eq!(
            name_qualifier("https://idp.example.com/saml", "123456789012", "Okta"),
            STANDARD.encode(digest::digest(
                &digest::SHA1_FOR_LEGACY_USE_ONLY,
                b"https://idp.example.com/saml123456789012/Okta"
            ))
        );
        assert!(names("arn:r,arn:p", "arn:r", "arn:p"));
        assert!(names("arn:p,arn:r", "arn:r", "arn:p"));
        assert!(!names("arn:p, arn:r", "arn:r", "arn:p"));
        assert!(!names("arn:r", "arn:r", "arn:p"));
    }
}
