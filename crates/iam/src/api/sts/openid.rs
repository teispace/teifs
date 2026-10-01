//! MinIO's sessions for an OpenID Connect token, without an IAM role: the managed
//! policies the token's policy claim names (a provider tagged
//! [`oidc::POLICY_CLAIM_TAG`]), or a provider's role policies for the role of one of
//! its clients ([`oidc::ROLE_POLICY_TAG`], [`crate::openid_role_arn`]). Both answer
//! `AssumeRoleWithWebIdentity` and MinIO's older `AssumeRoleWithClientGrants`, whose
//! token is `Token`.

use teifs_policy::Json;

use super::{
    ApiError, MINIO_LONGEST, NAME_CHARS, NAME_PATTERN, Out, Run, SHORTEST, answer, claims,
    credentials, duration, managed_policy, min_token_size, text, web_claims, web_identity,
};
use crate::{
    oidc,
    sessions::{Who, now_seconds},
};

/// MinIO's action that exchanges an OAuth 2.0 token (a JWT) for a session.
pub(in crate::api) const CLIENT_GRANTS: &str = "AssumeRoleWithClientGrants";

/// Which action asks: the parameter its token is in, and how its answer names the
/// token's subject.
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Web,
    ClientGrants,
}

impl Kind {
    const fn token(self) -> &'static str {
        match self {
            Self::Web => "WebIdentityToken",
            Self::ClientGrants => "Token",
        }
    }
}

/// `AssumeRoleWithClientGrants`: MinIO's sessions for a token, as for a web identity.
pub(in crate::api) fn assume_role_with_client_grants(r: &Run<'_>) -> Out {
    let min_token = min_token_size(r)?;
    minio_session(r, Kind::ClientGrants, r.p.optional("RoleArn"), min_token)
}

/// MinIO's session for `kind`'s token: the role policies of the role `arn` names, or
/// without one (or, as MinIO has it, with one that isn't a role, when the token's
/// provider names policies in a claim) the policies the token's claim names.
pub(super) fn minio_session(r: &Run<'_>, kind: Kind, arn: Option<&str>, min_token: usize) -> Out {
    let role = match arn {
        Some(arn) => r.iam.read(|s| Ok(s.oidc_role(arn)))?,
        None => None,
    };
    match (role, arn) {
        (Some(role), _) => role_policy_session(r, kind, role, min_token),
        (None, _) if names_policies(r, kind)? => claim_session(r, kind, min_token),
        (None, None) => Err(ApiError::missing("RoleArn")),
        (None, Some(arn)) if arn.starts_with("arn:minio:") => Err(ApiError::invalid_parameter(
            format!("Error processing RoleArn parameter: Role {arn} does not exist"),
        )),
        (None, Some(arn)) => Err(ApiError::invalid_parameter(format!(
            "{arn} isn't an IAM role ARN or a MinIO role of an OpenID Connect provider's \
             client (`teifs admin oidc ls` shows them)."
        ))),
    }
}

/// Whether the token's issuer is a provider whose tokens may name policies: for any
/// other, `RoleArn` is required as on AWS. The token is checked afterwards.
fn names_policies(r: &Run<'_>, kind: Kind) -> Result<bool, ApiError> {
    let Some((iss, _)) = r.p.optional(kind.token()).and_then(oidc::issuer) else {
        return Ok(false);
    };
    Ok(r.iam.read(|s| {
        Ok(s.oidc_provider_by_issuer(&iss)
            .is_some_and(|p| oidc::policy_claim(p).is_some()))
    })?)
}

/// The session for a role policy: the token must be the provider's, for the role's
/// client (its `aud` or `azp`), and the role's policies that exist are the session's.
fn role_policy_session(
    r: &Run<'_>,
    kind: Kind,
    (provider, client, names): (String, String, Vec<String>),
    min_token: usize,
) -> Out {
    text(r, "RoleSessionName", 2..=64, NAME_CHARS, NAME_PATTERN)?;
    let requested = duration(r, SHORTEST..=MINIO_LONGEST)?;
    let (web, session) = web_identity(r, kind.token())?;
    if web.id != provider || !for_client(&web.claims, &client) {
        return Err(ApiError::invalid_parameter(
            "STS JWT Token has `aud`/`azp` claim invalid, must match configured OpenID \
             Client ID"
                .into(),
        ));
    }
    let ids = existing(r, &names)?;
    issue(r, kind, &web, ids, session, requested, min_token)
}

/// MinIO's session for a token's policy claim: the managed policies it names (a list,
/// or text separated by commas; names or ARNs), narrowed by the session policies. Only
/// a provider tagged [`oidc::POLICY_CLAIM_TAG`] may name policies; without one, a role
/// is needed as on AWS. Unless asked, the session ends when the token does.
fn claim_session(r: &Run<'_>, kind: Kind, min_token: usize) -> Out {
    text(r, "RoleSessionName", 2..=64, NAME_CHARS, NAME_PATTERN)?;
    let requested = duration(r, SHORTEST..=MINIO_LONGEST)?;
    let (web, session) = web_identity(r, kind.token())?;
    let Some(claim) = &web.policy_claim else {
        return Err(ApiError::missing("RoleArn"));
    };
    let ids = existing(r, &policy_names(&web, claim)?)?;
    issue(r, kind, &web, ids, session, requested, min_token)
}

/// Whether a token is for `client`: its `azp`, or one of its audiences.
fn for_client(claims: &Json, client: &str) -> bool {
    claims.get("azp").and_then(Json::as_str) == Some(client)
        || oidc::strings(claims.get("aud")).is_some_and(|aud| aud.iter().any(|a| a == client))
}

/// The unique ids of the managed policies `names` names that exist; refused, as MinIO
/// refuses it, when none does.
fn existing(r: &Run<'_>, names: &[String]) -> Result<Vec<String>, ApiError> {
    let ids: Vec<String> = r.iam.read(|s| {
        Ok(names
            .iter()
            .filter_map(|name| managed_policy(s, name))
            .collect())
    })?;
    if ids.is_empty() {
        return Err(ApiError::invalid_parameter(format!(
            "None of the given policies (`{}`) are defined, credentials will not be generated",
            names.join(",")
        )));
    }
    Ok(ids)
}

/// Issues the session with the managed policies `ids`, for `requested` seconds or
/// until the token expires.
fn issue(
    r: &Run<'_>,
    kind: Kind,
    web: &oidc::WebIdentity,
    ids: Vec<String>,
    session: Vec<String>,
    requested: Option<u32>,
    min_token: usize,
) -> Out {
    let seconds = requested.unwrap_or_else(|| {
        let left = web.expires - now_seconds();
        u32::try_from(left.clamp(1, i64::from(MINIO_LONGEST))).unwrap_or(MINIO_LONGEST)
    });
    let who = Who::Web {
        provider: web.id.clone(),
        sub: web.subject.clone(),
        policies: ids,
    };
    let mut claims = claims(who, seconds);
    claims.policies = session;
    claims.web = Some(web_claims(web));
    let issued = r.iam.issue_at_least(&claims, min_token)?;
    answer(|x| {
        credentials(x, &issued);
        match kind {
            Kind::Web => {
                x.text("SubjectFromWebIdentityToken", &web.subject)
                    .text("Provider", &web.provider)
                    .text("Audience", &web.audience);
            }
            Kind::ClientGrants => {
                x.text("SubjectFromToken", &web.subject);
            }
        }
    })
}

/// The policies a token's policy `claim` names, as MinIO reads it: a list, or text
/// separated by commas.
fn policy_names(web: &oidc::WebIdentity, claim: &str) -> Result<Vec<String>, ApiError> {
    let Some(value) = web.claims.get(claim) else {
        return Err(ApiError::invalid_parameter(format!(
            "{claim} claim missing from the JWT token, credentials will not be generated"
        )));
    };
    let Some(items) = oidc::strings(Some(value)) else {
        return Err(ApiError::invalid_parameter(format!(
            "The token's {claim} claim isn't text or a list of text."
        )));
    };
    Ok(items
        .iter()
        .flat_map(|item| item.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect())
}
