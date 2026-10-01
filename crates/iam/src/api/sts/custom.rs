//! MinIO's `AssumeRoleWithCustomToken`: temporary credentials for whoever an identity
//! plugin ([`crate::plugin`]) vouches for, given an opaque token. Unsigned: the token is
//! the proof. The request is checked first, then the plugin asked
//! ([`crate::Iam::serve_self_proving`]); the session has the plugin role's policies and
//! lasts as long as the plugin allows, or less if asked.

use super::{
    ApiError, MINIO_LONGEST, Out, Run, SHORTEST, answer, credentials, duration, managed_policy,
    min_token_size, session_policies,
};
use crate::{
    api::Proved,
    plugin::{PluginError, PluginUser},
    sessions::{Claims, Who, now_seconds},
};

/// The action's name.
pub(in crate::api) const CUSTOM_TOKEN: &str = "AssumeRoleWithCustomToken";

/// What a request asks for, checked before the plugin is asked.
pub(in crate::api) struct CustomRequest<'p> {
    pub(in crate::api) token: &'p str,
    seconds: Option<u32>,
    /// The role's managed policies that exist, by unique id.
    policies: Vec<String>,
    session: Vec<String>,
    min_token: usize,
}

/// Checks a request as MinIO does before it asks the plugin: the server has one, a
/// token, the plugin's role, a duration it allows, and policies that exist.
pub(in crate::api) fn request<'p>(r: &'p Run<'_>) -> Result<CustomRequest<'p>, ApiError> {
    let Some(plugin) = r.iam.identity_plugin() else {
        return Err(ApiError {
            status: 503,
            code: "STSNotInitialized",
            message: format!("STS API '{CUSTOM_TOKEN}' is disabled"),
        });
    };
    let token = r.p.optional("Token").unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::invalid_parameter(
            "Invalid empty `Token` parameter provided".into(),
        ));
    }
    let seconds = duration(r, SHORTEST..=MINIO_LONGEST)?;
    let role = r.p.optional("RoleArn").unwrap_or_default();
    if role != plugin.role_arn() {
        return Err(ApiError::invalid_parameter(format!(
            "Error processing parameter RoleArn: RoleARN {role} is not defined."
        )));
    }
    let names = plugin.role_policies();
    let policies: Vec<String> = r.iam.read(|s| {
        Ok(names
            .iter()
            .filter_map(|name| managed_policy(s, name))
            .collect())
    })?;
    if policies.is_empty() {
        return Err(ApiError::invalid_parameter(format!(
            "None of the given policies (`{}`) are defined, credentials will not be generated",
            names.join(",")
        )));
    }
    Ok(CustomRequest {
        token,
        seconds,
        policies,
        session: session_policies(r)?,
        min_token: min_token_size(r)?,
    })
}

/// The action: a session for the user the plugin vouched for.
pub(in crate::api) fn assume_role_with_custom_token(r: &Run<'_>) -> Out {
    let request = request(r)?;
    let user: &PluginUser = match r.proved {
        Some(Proved::Plugin(Ok(user))) => user,
        Some(Proved::Plugin(Err(err))) => return Err(refused(err)),
        // Only [`crate::Iam::serve_self_proving`] asks the plugin.
        _ => {
            return Err(refused(&PluginError::Failed(
                "the plugin wasn't asked".into(),
            )));
        }
    };
    let seconds = request
        .seconds
        .map_or(user.max_seconds, |asked| asked.min(user.max_seconds));
    let now = now_seconds();
    let who = Who::Custom {
        user: user.user.clone(),
        policies: request.policies,
    };
    let mut claims = Claims::new(who, now, now + i64::from(seconds));
    claims.policies = request.session;
    let issued = r.iam.issue_at_least(&claims, request.min_token)?;
    tracing::info!(user = %user.user, "an identity plugin's user signed in");
    answer(|x| {
        credentials(x, &issued);
        x.text("AssumedUser", &format!("custom:{}", user.user));
    })
}

/// The plugin's refusal: its reason as it gave it.
fn refused(err: &PluginError) -> ApiError {
    match err {
        PluginError::Denied(reason) => ApiError {
            status: 403,
            code: "AccessDenied",
            message: reason.clone(),
        },
        PluginError::NoUser => {
            tracing::warn!("the identity plugin vouched for no user");
            ApiError {
                status: 500,
                code: "InternalError",
                message: err.to_string(),
            }
        }
        PluginError::Failed(_) | PluginError::NotSetUp => {
            tracing::warn!(error = %err, "the identity plugin couldn't be asked");
            ApiError::invalid_parameter(err.to_string())
        }
    }
}
