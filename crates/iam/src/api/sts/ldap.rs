//! MinIO's `AssumeRoleWithLDAPIdentity`: temporary credentials for a directory user who
//! signs in with its name and password. Unsigned, like `AssumeRoleWithWebIdentity`: the
//! password is the proof. The directory is asked before the action runs
//! ([`crate::Iam::serve_self_proving`]); the action checks the request, then issues the
//! session with what the directory said.

use super::{
    ApiError, Out, Run, answer, credentials, duration, min_token_size, revoke_type,
    session_policies,
};
use crate::{
    api::Proved,
    ldap::LdapError,
    ops::LdapSignIn,
    sessions::{Claims, Who},
};

/// The action's name.
pub(in crate::api) const LDAP_IDENTITY: &str = "AssumeRoleWithLDAPIdentity";

/// MinIO's session lengths: an hour unless asked, 15 minutes to a year.
const DEFAULT_SECONDS: u32 = 3600;
const SHORTEST: u32 = 900;
const LONGEST: u32 = 31_536_000;

/// What a request asks for, checked before the directory is asked.
pub(in crate::api) struct LdapRequest<'p> {
    pub(in crate::api) username: &'p str,
    pub(in crate::api) password: &'p str,
    seconds: u32,
    policies: Vec<String>,
    min_token: usize,
}

/// Checks a request as MinIO does before it asks the directory: a name and a password,
/// a session policy that parses, a duration it allows.
pub(in crate::api) fn request<'p>(r: &'p Run<'_>) -> Result<LdapRequest<'p>, ApiError> {
    let username = r.p.optional("LDAPUsername").unwrap_or_default();
    let password = r.p.optional("LDAPPassword").unwrap_or_default();
    if username.is_empty() || password.is_empty() {
        return Err(ApiError {
            status: 400,
            code: "MissingParameter",
            message: "LDAPUsername and LDAPPassword cannot be empty".into(),
        });
    }
    let policies = session_policies(r)?;
    let seconds = duration(r, SHORTEST..=LONGEST)?.unwrap_or(DEFAULT_SECONDS);
    Ok(LdapRequest {
        username,
        password,
        seconds,
        policies,
        min_token: min_token_size(r)?,
    })
}

/// The action: a session with the managed policies mapped to the user's DN and its
/// groups' DNs, as the directory said, narrowed by the session policy. Refused when
/// none is mapped.
pub(in crate::api) fn assume_role_with_ldap_identity(r: &Run<'_>) -> Out {
    let request = request(r)?;
    let signed_in = match r.proved {
        Some(Proved::Ldap(Ok(signed_in))) => signed_in,
        Some(Proved::Ldap(Err(err))) => return Err(refused(err)),
        // Only [`crate::Iam::serve_self_proving`] asks the directory.
        _ => {
            return Err(refused(&LdapError::Failed(
                "the directory wasn't asked".into(),
            )));
        }
    };
    let mapped = r.iam.read(|s| {
        Ok(std::iter::once(&signed_in.dn)
            .chain(&signed_in.groups)
            .any(|dn| s.ldap_policies.contains_key(dn)))
    })?;
    if !mapped {
        return Err(ApiError::invalid_parameter(format!(
            "expecting a policy to be set for user `{}` or one of their groups: `{}` - \
             rejecting this request",
            signed_in.actual_dn,
            signed_in.groups.join("`,`")
        )));
    }
    let issued_ms = crate::now_ms();
    let now = issued_ms.div_euclid(1000);
    let expires = now + i64::from(request.seconds);
    let generation = r.iam.record_ldap_sign_in(&LdapSignIn {
        dn: &signed_in.dn,
        username: &signed_in.username,
        groups: &signed_in.groups,
        expires_ms: expires.saturating_mul(1000),
    })?;
    let who = Who::Ldap {
        dn: signed_in.dn.clone(),
        username: signed_in.username.clone(),
        generation,
    };
    let mut claims = Claims::new(who, now, expires);
    claims.iat_ms = Some(issued_ms);
    claims.policies = request.policies;
    claims.revoke_type = revoke_type(r);
    let issued = r.iam.issue_at_least(&claims, request.min_token)?;
    tracing::info!(dn = %signed_in.dn, "an LDAP user signed in");
    answer(|x| {
        credentials(x, &issued);
    })
}

/// The directory's refusal, as MinIO answers it.
fn refused(err: &LdapError) -> ApiError {
    if !matches!(err, LdapError::Refused) {
        tracing::warn!(error = %err, "LDAP sign-in failed");
    }
    ApiError::invalid_parameter(format!("LDAP server error: {err}"))
}
