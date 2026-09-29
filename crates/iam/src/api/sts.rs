//! STS as AWS has it: temporary credentials for a role (`AssumeRole`), for a user's own
//! permissions (`GetSessionToken`) or for a federated user (`GetFederationToken`), and
//! who is calling (`GetCallerIdentity`, `GetAccessKeyInfo`); and a role's session for
//! someone an OpenID Connect provider vouches for (`AssumeRoleWithWebIdentity`).
//!
//! `AssumeRole` without an AWS role ARN is MinIO's: credentials with the calling user's
//! own permissions, narrowed by a session policy, for up to a year.

use std::ops::RangeInclusive;

use teifs_policy::{Context, Decision, Json, Kind as PolicyKind, Policy, Principal, StsKey};

use super::{
    Action, ApiError, On, Out, Run, answer, with_request_tags, with_resource_tags, xml::Xml,
};
use crate::{
    IamError, Identity, Issued, Session, SessionKind,
    oidc::{self, jwt},
    rules,
    sessions::{Claims, WebClaims, Who, now_seconds},
    state::Role,
};

/// The condition keys `AssumeRole` sets. AWS's reference also lists the keys of web
/// identity and SAML providers, which a request signed with IAM credentials never has.
const ASSUME_ROLE: &[&str] = &[
    "aws:RequestTag/${TagKey}",
    "aws:TagKeys",
    "iam:ResourceTag/${TagKey}",
    "sts:ExternalId",
    "sts:RoleSessionName",
    "sts:SourceIdentity",
    "sts:TransitiveTagKeys",
];

/// The action that exchanges a web identity token for a role's session.
pub(super) const WEB_IDENTITY: &str = "AssumeRoleWithWebIdentity";

/// The condition keys `AssumeRoleWithWebIdentity` sets besides the provider's own
/// (`idp.example.com:sub`), which [`crate::oidc::WebIdentity::with_keys`] sets.
const ASSUME_ROLE_WITH_WEB_IDENTITY: &[&str] = &[
    "aws:RequestTag/${TagKey}",
    "aws:TagKeys",
    "sts:RoleAuthorizedByIdp",
    "sts:RoleSessionName",
    "sts:SourceIdentity",
    "sts:TransitiveTagKeys",
];

pub(super) const ACTIONS: &[Action] = &[
    Action {
        name: "AssumeRole",
        on: On::Role,
        keys: ASSUME_ROLE,
        run: assume_role,
    },
    Action {
        name: WEB_IDENTITY,
        on: On::Role,
        keys: ASSUME_ROLE_WITH_WEB_IDENTITY,
        run: assume_role_with_web_identity,
    },
    Action {
        name: "GetSessionToken",
        on: On::Any,
        keys: &[],
        run: session_token,
    },
    Action {
        name: "GetFederationToken",
        on: On::FederatedUser,
        keys: super::TAGGING,
        run: federation_token,
    },
    Action {
        name: "GetCallerIdentity",
        on: On::Any,
        keys: &[],
        run: caller_identity,
    },
    Action {
        name: "GetAccessKeyInfo",
        on: On::Any,
        keys: &[],
        run: access_key_info,
    },
];

/// The STS actions a session made in some way may call, as on AWS: a role's any but
/// `GetSessionToken` and `GetFederationToken`; `GetSessionToken`'s only `AssumeRole`
/// and `GetCallerIdentity`; a federated user's only `GetCallerIdentity`. Anyone may
/// call `AssumeRoleWithWebIdentity`, whose token says who is asking.
pub(super) fn permitted(kind: SessionKind, action: &str) -> bool {
    if action == WEB_IDENTITY {
        return true;
    }
    match kind {
        SessionKind::Role { .. } | SessionKind::User => {
            !matches!(action, "GetSessionToken" | "GetFederationToken")
        }
        SessionKind::SessionToken => matches!(action, "AssumeRole" | "GetCallerIdentity"),
        SessionKind::Federated => action == "GetCallerIdentity",
    }
}

/// The shortest session of any kind, in seconds.
const SHORTEST: u32 = 900;
/// The longest `AssumeRole` asks for (a role may allow up to 12 hours).
const ROLE_LONGEST: u32 = 43_200;
/// The longest a role chain's sessions last, and the root user's.
const ONE_HOUR: u32 = 3600;
/// The longest `GetSessionToken` and `GetFederationToken` session (36 hours), and the
/// default (12 hours).
const USER_LONGEST: u32 = 129_600;
const USER_DEFAULT: u32 = 43_200;
/// The longest session MinIO's `AssumeRole` gives (365 days).
const MINIO_LONGEST: u32 = 31_536_000;
/// The most characters of an inline session policy, and managed session policies.
const SESSION_POLICY: usize = 2048;
const SESSION_POLICY_ARNS: usize = 10;

/// Names: `RoleSessionName`, `Name`, `SourceIdentity`.
const NAME_CHARS: &[u8] = b"_+=,.@-";
const NAME_PATTERN: &str = r"[\w+=,.@-]*";
const EXTERNAL_ID_CHARS: &[u8] = b"_+=,.@:/-";
const EXTERNAL_ID_PATTERN: &str = r"[\w+=,./@:-]*";
/// ARNs, as `RoleArn` takes them.
const ARN_CHARS: &[u8] = b"+=,.@:/_-";
const ARN_PATTERN: &str = r"[\w+=/:,.@-]*";

fn assume_role(r: &Run<'_>) -> Out {
    let arn = match r.p.optional("RoleArn") {
        Some(arn) if arn.starts_with("arn:aws:") => arn,
        _ => return assume_as_user(r),
    };
    no_mfa(r)?;
    let name = text(r, "RoleSessionName", 2..=64, NAME_CHARS, NAME_PATTERN)?
        .ok_or_else(|| ApiError::missing("RoleSessionName"))?;
    let requested = duration(r, SHORTEST..=ROLE_LONGEST)?;
    let external = text(
        r,
        "ExternalId",
        2..=1224,
        EXTERNAL_ID_CHARS,
        EXTERNAL_ID_PATTERN,
    )?;
    let given_source = source_identity(r)?;
    let tags = session_tags(r)?;
    let transitive = transitive_keys(r, &tags)?;
    let policies = session_policies(r)?;
    if r.identity.is_root() {
        return Err(ApiError::access_denied(
            "Roles may not be assumed by root accounts.".into(),
        ));
    }
    let Some(role) = r
        .iam
        .read(|s| Ok(s.id_of(arn).and_then(|id| s.roles.get(id)).cloned()))?
    else {
        return Err(ApiError::denied(r.identity, "sts:AssumeRole", arn));
    };

    let caller = r.identity.session();
    let chained = matches!(caller.map(Session::kind), Some(SessionKind::Role { .. }));
    let Inherited {
        tags: inherited,
        source,
    } = inherit(caller, &tags, given_source)?;
    let context = assume_context(r, &role, name, external, source, &tags, &transitive);
    let needs = [
        ("sts:AssumeRole", true),
        ("sts:TagSession", !tags.is_empty()),
        ("sts:SetSourceIdentity", source.is_some()),
    ];
    for (action, needed) in needs {
        if needed
            && !r
                .identity
                .allows_with(&context, action, arn, Some(&role.trust.policy))
        {
            return Err(ApiError::denied(r.identity, action, arn));
        }
    }

    let seconds = role_duration(requested, chained, role.max_session)?;
    let who = Who::Role {
        role: role.id.clone(),
        name: name.to_owned(),
        chained,
    };
    let mut claims = claims(who, seconds);
    claims.policies = policies;
    claims.tags = inherited.iter().chain(&tags).cloned().collect();
    claims.transitive = inherited
        .iter()
        .map(|(key, _)| key.clone())
        .chain(transitive)
        .collect();
    claims.source = source.map(str::to_owned);
    let issued = r.iam.issue(&claims)?;
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
        x.maybe("SourceIdentity", claims.source.as_deref());
    })
}

/// A role's session for someone an OpenID Connect provider vouches for, as AWS gives
/// it: the token must be the provider's (its signature, issuer, audience and expiry),
/// and then the role's trust policy decides, with the provider's keys
/// (`idp.example.com:sub`), `sts:RoleAuthorizedByIdp`, and the session tags and source
/// identity the token carries. Nothing about who signed the request counts.
fn assume_role_with_web_identity(r: &Run<'_>) -> Out {
    let arn = text(r, "RoleArn", 20..=2048, ARN_CHARS, ARN_PATTERN)?
        .ok_or_else(|| ApiError::missing("RoleArn"))?;
    let name = text(r, "RoleSessionName", 2..=64, NAME_CHARS, NAME_PATTERN)?
        .ok_or_else(|| ApiError::missing("RoleSessionName"))?;
    let token =
        r.p.optional("WebIdentityToken")
            .ok_or_else(|| ApiError::missing("WebIdentityToken"))?;
    if !(4..=jwt::MAX_TOKEN).contains(&token.len()) {
        return Err(ApiError::validation(format!(
            "1 validation error detected: Value at 'webIdentityToken' failed to satisfy \
             constraint: Member must have length between 4 and {}",
            jwt::MAX_TOKEN
        )));
    }
    if r.p.optional("ProviderId").is_some() {
        return Err(ApiError::validation(
            "ProviderId is for OAuth 2.0 access tokens; TeiFS takes OpenID Connect ID \
             tokens, whose issuer names their provider."
                .into(),
        ));
    }
    let requested = duration(r, SHORTEST..=ROLE_LONGEST)?;
    let policies = session_policies(r)?;
    let web = r
        .iam
        .read(|s| Ok(oidc::verify(s, &r.iam.web_keys, token, now_seconds())))?
        .map_err(refused)?;
    let authorized = authorized_by_idp(&web, arn)?;
    let (tags, transitive) = web_tags(&web)?;
    let source = web_source(&web)?;
    let Some(role) = r
        .iam
        .read(|s| Ok(s.id_of(arn).and_then(|id| s.roles.get(id)).cloned()))?
    else {
        return Err(not_authorized(WEB_IDENTITY));
    };

    let principal = Principal::web_identity(&web.provider, &web.subject);
    let mut context = with_request_tags(
        web.with_keys(r.base.clone().with_principal(principal)),
        &tags,
    )
    .with_sts(StsKey::RoleSessionName, name)
    .with_sts(StsKey::RoleAuthorizedByIdp, authorized);
    if let Some(source) = source {
        context = context.with_sts(StsKey::SourceIdentity, source);
    }
    if !transitive.is_empty() {
        context = context.with_sts(StsKey::TransitiveTagKeys, transitive.clone());
    }
    let context = with_resource_tags(context, On::Role, &role.tags);
    // The request's signer, if any, has no part: only the trust policy can allow it.
    let anyone = Identity::anonymous();
    let needs = [
        ("sts:AssumeRoleWithWebIdentity", true),
        ("sts:TagSession", !tags.is_empty()),
        ("sts:SetSourceIdentity", source.is_some()),
    ];
    for (action, needed) in needs {
        if needed && !anyone.allows_with(&context, action, arn, Some(&role.trust.policy)) {
            return Err(not_authorized(action));
        }
    }

    let seconds = role_duration(requested, false, role.max_session)?;
    let who = Who::Role {
        role: role.id.clone(),
        name: name.to_owned(),
        chained: false,
    };
    let mut claims = claims(who, seconds);
    claims.policies = policies;
    claims.tags = tags;
    claims.transitive = transitive;
    claims.source = source.map(str::to_owned);
    claims.web = Some(WebClaims {
        provider: web.provider.clone(),
        aud: web.audience.clone(),
        sub: web.subject.clone(),
        amr: web.amr(),
    });
    let issued = r.iam.issue(&claims)?;
    let packed = !claims.policies.is_empty() || !claims.tags.is_empty();
    answer(|x| {
        credentials(x, &issued);
        x.text("SubjectFromWebIdentityToken", &web.subject);
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
        x.text("Provider", &web.provider)
            .text("Audience", &web.audience)
            .maybe("SourceIdentity", claims.source.as_deref());
    })
}

/// A token that isn't accepted, as AWS answers it.
fn refused(err: oidc::Refused) -> ApiError {
    let (code, message) = match err {
        oidc::Refused::Invalid(message) => ("InvalidIdentityToken", message),
        oidc::Refused::Expired(message) => ("ExpiredTokenException", message),
        oidc::Refused::Unreachable(message) => ("IDPCommunicationError", message),
    };
    ApiError {
        status: 400,
        code,
        message,
    }
}

fn invalid_token(message: String) -> ApiError {
    refused(oidc::Refused::Invalid(message))
}

/// AWS's refusal of a web identity the trust policy doesn't allow.
fn not_authorized(action: &str) -> ApiError {
    let action = action.strip_prefix("sts:").unwrap_or(action);
    ApiError::access_denied(format!("Not authorized to perform sts:{action}"))
}

/// `sts:RoleAuthorizedByIdp`: whether the token's roles claim names the role. A token
/// with a roles claim that doesn't name it isn't for this role at all.
fn authorized_by_idp(web: &oidc::WebIdentity, arn: &str) -> Result<bool, ApiError> {
    let roles = match web.claims.get(oidc::ROLES_CLAIM) {
        None => return Ok(false),
        Some(Json::String(list)) => list.split(';').map(str::trim).map(str::to_owned).collect(),
        claim => oidc::strings(claim).ok_or_else(|| {
            invalid_token(format!(
                "The token's {} claim isn't a list of role ARNs.",
                oidc::ROLES_CLAIM
            ))
        })?,
    };
    if roles.iter().any(|role| role == arn) {
        Ok(true)
    } else {
        Err(invalid_token(format!(
            "The token's {} claim doesn't name the role {arn}.",
            oidc::ROLES_CLAIM
        )))
    }
}

/// Session tags, and the keys of those that are transitive.
type SessionTags = (Vec<(String, String)>, Vec<String>);

/// The session tags the token carries (`https://aws.amazon.com/tags`): its
/// `principal_tags`, each a list of one value, and its `transitive_tag_keys`.
fn web_tags(web: &oidc::WebIdentity) -> Result<SessionTags, ApiError> {
    let Some(claim) = web.claims.get(oidc::TAGS_CLAIM) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let bad = |why: &str| invalid_token(format!("The token's {} claim {why}.", oidc::TAGS_CLAIM));
    if !matches!(claim, Json::Object(_)) {
        return Err(bad("isn't an object"));
    }
    let mut tags: Vec<(String, String)> = Vec::new();
    match claim.get("principal_tags") {
        None => {}
        Some(Json::Object(members)) => {
            for (key, value) in members {
                let value = match value {
                    Json::Array(values) if values.len() == 1 => values[0].as_str(),
                    _ => None,
                }
                .ok_or_else(|| bad(&format!("gives the tag {key} other than one text value")))?;
                rules::tag(key, value)
                    .map_err(|err| bad(&format!("has a tag AWS refuses: {err}")))?;
                if tags.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)) {
                    return Err(bad(&format!("names the tag {key} twice")));
                }
                tags.push((key.clone(), value.to_owned()));
            }
        }
        Some(_) => return Err(bad("has principal_tags that aren't an object")),
    }
    if tags.len() > rules::MAX_TAGS {
        return Err(bad(&format!("has more than {} tags", rules::MAX_TAGS)));
    }
    let transitive = match claim.get("transitive_tag_keys") {
        None => Vec::new(),
        keys => {
            oidc::strings(keys).ok_or_else(|| bad("has transitive_tag_keys that aren't text"))?
        }
    };
    if let Some(key) = transitive
        .iter()
        .find(|key| !tags.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)))
    {
        return Err(bad(&format!(
            "makes {key} transitive, which isn't one of its tags"
        )));
    }
    Ok((tags, transitive))
}

/// The source identity the token carries (`https://aws.amazon.com/source_identity`),
/// with `SourceIdentity`'s rules (its characters leave out the `:` of `aws:`, which it
/// may not start with).
fn web_source(web: &oidc::WebIdentity) -> Result<Option<&str>, ApiError> {
    let Some(claim) = web.claims.get(oidc::SOURCE_IDENTITY_CLAIM) else {
        return Ok(None);
    };
    let source = claim.as_str().filter(|source| {
        (2..=64).contains(&source.chars().count())
            && source
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || NAME_CHARS.contains(&b))
    });
    source.map(Some).ok_or_else(|| {
        invalid_token(format!(
            "The token's {} claim must be 2 to 64 letters, digits or {}.",
            oidc::SOURCE_IDENTITY_CLAIM,
            std::str::from_utf8(NAME_CHARS).unwrap_or_default()
        ))
    })
}

/// What a calling session passes on to the role session it starts.
struct Inherited<'a> {
    /// Its transitive tags.
    tags: &'a [(String, String)],
    /// Its source identity, or else the one given.
    source: Option<&'a str>,
}

/// What `caller` passes on: its transitive tags, which `tags` can't set again, and its
/// source identity, which `given` can't change.
fn inherit<'a>(
    caller: Option<&'a Session>,
    tags: &[(String, String)],
    given: Option<&'a str>,
) -> Result<Inherited<'a>, ApiError> {
    let inherited = caller.map_or(&[][..], Session::transitive_tags);
    if let Some((key, _)) = tags
        .iter()
        .find(|(key, _)| inherited.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)))
    {
        return Err(ApiError::validation(format!(
            "The tag {key} is a transitive tag of the calling session and can't be set again."
        )));
    }
    let source = match (caller.and_then(Session::source_identity), given) {
        (Some(kept), Some(given)) if kept != given => {
            return Err(ApiError::validation(format!(
                "The calling session's source identity {kept} can't be changed."
            )));
        }
        (Some(kept), _) => Some(kept),
        (None, given) => given,
    };
    Ok(Inherited {
        tags: inherited,
        source,
    })
}

/// How long a role session lasts: an hour unless `requested`, and no longer than the
/// role allows, or an hour when a role's session starts it.
fn role_duration(requested: Option<u32>, chained: bool, max_session: u32) -> Result<u32, ApiError> {
    let limit = if chained { ONE_HOUR } else { max_session };
    let seconds = requested.unwrap_or(ONE_HOUR);
    if seconds <= limit {
        return Ok(seconds);
    }
    Err(ApiError::validation(
        if chained {
            "The requested DurationSeconds exceeds the 1 hour session limit for roles assumed \
             by role chaining."
        } else {
            "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."
        }
        .into(),
    ))
}

/// What the trust policy and the caller's policies may test about `AssumeRole`. A caller
/// the trust policy names by an ARN that meant someone else when it was set (a user or
/// role deleted and made again) isn't the one it trusts.
fn assume_context(
    r: &Run<'_>,
    role: &Role,
    name: &str,
    external: Option<&str>,
    source: Option<&str>,
    tags: &[(String, String)],
    transitive: &[String],
) -> Context {
    let mut context = r.context();
    if let Some((arn, id)) = r.identity.entity()
        && role.principals.get(arn).is_some_and(|bound| bound != id)
    {
        let principal = context.principal().clone().unbound();
        context = context.with_principal(principal);
    }
    context = with_request_tags(context, tags).with_sts(StsKey::RoleSessionName, name);
    if let Some(external) = external {
        context = context.with_sts(StsKey::ExternalId, external);
    }
    if let Some(source) = source {
        context = context.with_sts(StsKey::SourceIdentity, source);
    }
    if !transitive.is_empty() {
        context = context.with_sts(StsKey::TransitiveTagKeys, transitive.to_vec());
    }
    with_resource_tags(context, On::Role, &role.tags)
}

/// MinIO's `AssumeRole`: the calling user's own permissions, narrowed by the session
/// policy if there is one. Only a user's own access key may ask, and any user may unless
/// a policy denies them `sts:AssumeRole`.
fn assume_as_user(r: &Run<'_>) -> Out {
    let Some((arn, user)) = r
        .identity
        .entity()
        .filter(|_| r.identity.session().is_none())
    else {
        return Err(ApiError::access_denied(
            "AssumeRole without a role ARN gives temporary credentials for a user's own \
             permissions, so it needs that user's own access key."
                .into(),
        ));
    };
    let seconds = duration(r, SHORTEST..=MINIO_LONGEST)?.unwrap_or(ONE_HOUR);
    let policies = session_policies(r)?;
    if r.identity.decide(&r.context(), "sts:AssumeRole", arn, None) == Decision::ExplicitDeny {
        return Err(ApiError::denied(r.identity, "sts:AssumeRole", arn));
    }
    let mut claims = claims(
        Who::User {
            user: user.to_owned(),
        },
        seconds,
    );
    claims.policies = policies;
    let issued = r.iam.issue(&claims)?;
    answer(|x| credentials(x, &issued))
}

/// Credentials for the caller's own permissions: a user's, or the root user's for at
/// most an hour.
fn session_token(r: &Run<'_>) -> Out {
    no_mfa(r)?;
    let seconds = user_duration(r)?;
    let who = Who::SessionToken {
        user: caller_user(r),
    };
    let issued = r.iam.issue(&claims(who, seconds))?;
    answer(|x| credentials(x, &issued))
}

/// Credentials for a federated user `Name`: the caller's permissions, as far as the
/// session policies allow (none allow nothing).
fn federation_token(r: &Run<'_>) -> Out {
    let name = text(r, "Name", 2..=32, NAME_CHARS, NAME_PATTERN)?
        .ok_or_else(|| ApiError::missing("Name"))?;
    let seconds = user_duration(r)?;
    let tags = session_tags(r)?;
    let policies = session_policies(r)?;
    let arn = format!("arn:aws:sts::{}:federated-user/{name}", r.account);
    let context = with_request_tags(r.context(), &tags);
    if !r.identity.allows(&context, "sts:GetFederationToken", &arn) {
        return Err(ApiError::denied(r.identity, "sts:GetFederationToken", &arn));
    }
    let who = Who::Federated {
        user: caller_user(r),
        name: name.to_owned(),
    };
    let mut claims = claims(who, seconds);
    claims.policies = policies;
    claims.tags = tags;
    let issued = r.iam.issue(&claims)?;
    let packed = !claims.policies.is_empty() || !claims.tags.is_empty();
    answer(|x| {
        credentials(x, &issued);
        x.el("FederatedUser", |x| {
            x.text("FederatedUserId", &format!("{}:{name}", r.account))
                .text("Arn", &arn);
        });
        if packed {
            x.number("PackedPolicySize", issued.utilization);
        }
    })
}

/// Who signed the request; anyone signed may ask, whatever their policies say.
fn caller_identity(r: &Run<'_>) -> Out {
    let principal = r.identity.principal();
    answer(|x| {
        x.maybe("Arn", principal.arn())
            .text("UserId", principal.user_id())
            .maybe("Account", principal.account());
    })
}

/// The account an access key id belongs to: this one, the only one there is.
fn access_key_info(r: &Run<'_>) -> Out {
    text(r, "AccessKeyId", 16..=128, b"_", r"[\w]*")?
        .ok_or_else(|| ApiError::missing("AccessKeyId"))?;
    if !r.identity.allows(&r.context(), "sts:GetAccessKeyInfo", "*") {
        return Err(ApiError::denied(r.identity, "sts:GetAccessKeyInfo", "*"));
    }
    answer(|x| {
        x.text("Account", &r.account);
    })
}

fn claims(who: Who, seconds: u32) -> Claims {
    let now = now_seconds();
    Claims::new(who, now, now + i64::from(seconds))
}

/// The credentials, and how large their token is (in bytes, and as a share of the
/// largest), as every answer that issues credentials says.
fn credentials(x: &mut Xml, issued: &Issued) {
    x.el("Credentials", |x| {
        x.text("AccessKeyId", &issued.access_key)
            .text("SecretAccessKey", &issued.secret)
            .text("SessionToken", &issued.token)
            .date("Expiration", issued.expires.saturating_mul(1000));
    })
    .number("SessionTokenUtilization", issued.utilization)
    .number("SessionTokenSize", issued.token.len());
}

/// The calling user's unique id; none for the root user.
fn caller_user(r: &Run<'_>) -> Option<String> {
    r.identity.entity().map(|(_, id)| id.to_owned())
}

/// MFA: TeiFS has no MFA devices, so a request that gives a code is refused rather than
/// its code ignored.
fn no_mfa(r: &Run<'_>) -> Result<(), ApiError> {
    if r.p.optional("SerialNumber").is_some() || r.p.optional("TokenCode").is_some() {
        return Err(ApiError::access_denied(
            "MultiFactorAuthentication failed: TeiFS has no MFA devices.".into(),
        ));
    }
    Ok(())
}

/// A text parameter of `length` characters, each a letter, digit or one of `extra`.
fn text<'p>(
    r: &'p Run<'_>,
    name: &str,
    length: RangeInclusive<usize>,
    extra: &[u8],
    pattern: &str,
) -> Result<Option<&'p str>, ApiError> {
    let Some(value) = r.p.optional(name) else {
        return Ok(None);
    };
    let count = value.chars().count();
    if count < *length.start() {
        return Err(ApiError::constraint(
            name,
            value,
            &format!(
                "Member must have length greater than or equal to {}",
                length.start()
            ),
        ));
    }
    if count > *length.end() {
        return Err(ApiError::constraint(
            name,
            value,
            &format!(
                "Member must have length less than or equal to {}",
                length.end()
            ),
        ));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
    {
        return Err(ApiError::constraint(
            name,
            value,
            &format!("Member must satisfy regular expression pattern: {pattern}"),
        ));
    }
    Ok(Some(value))
}

/// `DurationSeconds`, if given, within `range`.
fn duration(r: &Run<'_>, range: RangeInclusive<u32>) -> Result<Option<u32>, ApiError> {
    let Some(text) = r.p.optional("DurationSeconds") else {
        return Ok(None);
    };
    let seconds: u32 = text
        .parse()
        .map_err(|_| ApiError::invalid_value("DurationSeconds", text))?;
    let constraint = if seconds < *range.start() {
        format!(
            "Member must have value greater than or equal to {}",
            range.start()
        )
    } else if seconds > *range.end() {
        format!(
            "Member must have value less than or equal to {}",
            range.end()
        )
    } else {
        return Ok(Some(seconds));
    };
    Err(ApiError::constraint("DurationSeconds", text, &constraint))
}

/// `GetSessionToken`'s and `GetFederationToken`'s duration: 12 hours unless asked, up to
/// 36; the root user's is at most an hour, however long it asks for.
fn user_duration(r: &Run<'_>) -> Result<u32, ApiError> {
    let seconds = duration(r, SHORTEST..=USER_LONGEST)?.unwrap_or(USER_DEFAULT);
    Ok(if r.identity.is_root() {
        seconds.min(ONE_HOUR)
    } else {
        seconds
    })
}

/// `SourceIdentity`: a name, which can't start with `aws:`.
fn source_identity<'p>(r: &'p Run<'_>) -> Result<Option<&'p str>, ApiError> {
    let source = text(r, "SourceIdentity", 2..=64, NAME_CHARS, NAME_PATTERN)?;
    if let Some(source) = source
        && source
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("aws:"))
    {
        return Err(ApiError::validation(
            "SourceIdentity can't start with aws:.".into(),
        ));
    }
    Ok(source)
}

/// `Tags`: at most 50, valid, their keys unique in any case.
fn session_tags(r: &Run<'_>) -> Result<Vec<(String, String)>, ApiError> {
    let tags = r.p.tags()?;
    if tags.len() > rules::MAX_TAGS {
        return Err(ApiError::validation(format!(
            "A session has at most {} tags.",
            rules::MAX_TAGS
        )));
    }
    for (i, (key, value)) in tags.iter().enumerate() {
        rules::tag(key, value).map_err(|err| ApiError::validation(err.to_string()))?;
        if tags[..i].iter().any(|(k, _)| k.eq_ignore_ascii_case(key)) {
            return Err(ApiError::validation(
                "Duplicate tag keys found. Please note that Tag keys are case insensitive.".into(),
            ));
        }
    }
    Ok(tags)
}

/// `TransitiveTagKeys`: keys of the session's own `tags`.
fn transitive_keys(r: &Run<'_>, tags: &[(String, String)]) -> Result<Vec<String>, ApiError> {
    let keys = r.p.list("TransitiveTagKeys")?;
    if let Some(key) = keys
        .iter()
        .find(|key| !tags.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)))
    {
        return Err(ApiError::validation(format!(
            "The transitive tag key {key} isn't one of the session's tags."
        )));
    }
    Ok(keys.into_iter().map(str::to_owned).collect())
}

/// The session policies' documents: `Policy`, and the managed policies `PolicyArns`
/// names as they are now.
fn session_policies(r: &Run<'_>) -> Result<Vec<String>, ApiError> {
    let mut documents = Vec::new();
    if let Some(text) = r.p.optional("Policy") {
        if text.chars().count() > SESSION_POLICY {
            return Err(ApiError::validation(format!(
                "A session policy is at most {SESSION_POLICY} characters."
            )));
        }
        rules::document(text)?;
        Policy::parse(text, PolicyKind::Identity)
            .map_err(|err| IamError::MalformedPolicyDocument(err.to_string()))?;
        documents.push(text.to_owned());
    }
    let arns = r.p.members("PolicyArns", "arn")?;
    if arns.len() > SESSION_POLICY_ARNS {
        return Err(ApiError::validation(format!(
            "A session has at most {SESSION_POLICY_ARNS} managed session policies."
        )));
    }
    for arn in arns {
        let document = r
            .iam
            .read(|s| {
                Ok(s.policy_by_arn(arn)
                    .ok()
                    .map(|p| p.default_document().text.to_string()))
            })?
            .ok_or_else(|| {
                IamError::MalformedPolicyDocument(format!(
                    "Policy {arn} does not exist or is not attachable."
                ))
            })?;
        documents.push(document);
    }
    Ok(documents)
}
