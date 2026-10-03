//! `MinIO`'s admin API for users, groups and policies (`mc admin user`, `group`,
//! `policy`), over TeiFS's IAM: a `MinIO` user is the IAM user named as its access key,
//! which signs with a key of that id, and a canned policy is a managed policy by name.
//!
//! Secrets travel in bodies encrypted with the caller's secret key, as madmin does it
//! ([`teifs_crypto::madmin`]): `add-user` and `change-my-password` send one, and
//! `list-users`, the policy attach and detach calls and `policy-entities` answer
//! encrypted. [`crate::routes`] decides who may call each.

use std::collections::BTreeMap;

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::{Deserialize, Serialize};
use teifs_iam::{
    GroupPolicies, Iam, Identity, LdapEntity, MinioError, MinioGroup, MinioUser, MinioUserChange,
    Owner, PolicyEntities, Session, SessionParent,
};
use teifs_policy::Context;
use teifs_store::{RetentionPeriod, Store, Versioning};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    access::allows,
    admin,
    errors::StoreResultExt,
    routes::{Routes, s3_refusal, signed_body},
};

/// The largest body read: a policy document, or an encrypted request.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// A user's or group's status, as `MinIO` spells it.
const ENABLED: &str = "enabled";
const DISABLED: &str = "disabled";

/// A `MinIO` admin error, with its code and status.
pub(crate) fn minio_error(err: MinioError) -> S3Error {
    let status = StatusCode::from_u16(err.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status.is_server_error() {
        tracing::error!(error = %err, "a MinIO admin request failed in IAM");
        return S3Error::internal_error(err);
    }
    admin::error(status, err.code(), err.to_string())
}

pub(crate) fn invalid(message: impl Into<String>) -> S3Error {
    admin::error(
        StatusCode::BAD_REQUEST,
        "XMinioAdminInvalidArgument",
        message,
    )
}

/// The query's parameters.
pub(crate) fn query(req: &S3Request<Body>) -> Vec<(String, String)> {
    form_urlencoded::parse(req.uri.query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

/// The value of query parameter `name`, which must be there and not be empty.
pub(crate) fn required(req: &S3Request<Body>, name: &str) -> S3Result<String> {
    query(req)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid(format!("The query needs {name}=…")))
}

/// Whether query parameter `name` is `true`.
pub(crate) fn flag(req: &S3Request<Body>, name: &str) -> bool {
    query(req).iter().any(|(n, v)| n == name && v == "true")
}

/// The access key of `req`'s caller, whom [`crate::routes`] has authenticated.
pub(crate) fn caller_key(req: &S3Request<Body>) -> Option<&str> {
    req.credentials.as_ref().map(|c| c.access_key.as_str())
}

/// The caller's secret key: the password of the bodies it sends and reads.
pub(crate) fn caller_secret(req: &S3Request<Body>) -> S3Result<Zeroizing<String>> {
    req.credentials
        .as_ref()
        .map(|c| Zeroizing::new(c.secret_key.expose().to_owned()))
        .ok_or_else(|| s3s::s3_error!(AccessDenied, "Access Denied"))
}

/// The request's body, signed.
async fn body(req: &mut S3Request<Body>) -> S3Result<bytes::Bytes> {
    signed_body(req, MAX_BODY_BYTES).await.map_err(s3_refusal)
}

/// The request's body, decrypted with the caller's secret key and read as JSON.
pub(crate) async fn decrypted<T: for<'de> Deserialize<'de>>(
    req: &mut S3Request<Body>,
) -> S3Result<T> {
    let secret = caller_secret(req)?;
    let body = body(req).await?;
    // Argon2id takes a while and 64 MiB: off the async workers.
    let plain = tokio::task::spawn_blocking(move || teifs_crypto::madmin::decrypt(&secret, &body))
        .await
        .map_err(S3Error::internal_error)?
        .map_err(|_| {
            invalid(
                "The body isn't encrypted with the secret key of the access key that signed it.",
            )
        })?;
    serde_json::from_slice(&plain).map_err(|_| invalid("The body isn't the JSON this call takes."))
}

/// An answer of `value` as JSON, encrypted with the caller's secret key.
pub(crate) async fn encrypted(
    req: &S3Request<Body>,
    value: &impl Serialize,
) -> S3Result<S3Response<Body>> {
    let plain = Zeroizing::new(serde_json::to_vec(value).map_err(S3Error::internal_error)?);
    encrypted_bytes(req, plain).await
}

/// An answer of `plain`, encrypted with the caller's secret key.
pub(crate) async fn encrypted_bytes(
    req: &S3Request<Body>,
    plain: Zeroizing<Vec<u8>>,
) -> S3Result<S3Response<Body>> {
    let secret = caller_secret(req)?;
    let data = tokio::task::spawn_blocking(move || teifs_crypto::madmin::encrypt(&secret, &plain))
        .await
        .map_err(S3Error::internal_error)?;
    Ok(raw(data, "application/octet-stream"))
}

/// An answer with this body.
fn raw(bytes: impl Into<bytes::Bytes>, content_type: &'static str) -> S3Response<Body> {
    let mut response = S3Response::new(crate::routes::unlogged(bytes));
    response.headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    response
}

/// An answer with nothing to say.
fn empty() -> S3Response<Body> {
    S3Response::new(Body::empty())
}

/// A time in milliseconds since the Unix epoch, as Go's JSON writes it.
pub(crate) fn time(ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub(crate) const fn status(enabled: bool) -> &'static str {
    if enabled { ENABLED } else { DISABLED }
}

/// A status as `MinIO` sends it: `enabled`, `disabled`, or none.
fn parse_status(status: &str) -> S3Result<Option<bool>> {
    match status {
        "" => Ok(None),
        ENABLED => Ok(Some(true)),
        DISABLED => Ok(Some(false)),
        _ => Err(invalid("A status is enabled or disabled.")),
    }
}

/// `madmin.AddOrUpdateUserReq`.
#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct UserRequest {
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    status: String,
}

/// `madmin.UserInfo`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserInfo {
    #[serde(skip_serializing_if = "String::is_empty")]
    policy_name: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    member_of: Vec<String>,
    updated_at: String,
}

impl From<MinioUser> for UserInfo {
    fn from(user: MinioUser) -> Self {
        Self {
            policy_name: user.policies.join(","),
            status: status(user.enabled),
            member_of: user.groups,
            updated_at: time(user.created_ms),
        }
    }
}

/// `PUT add-user?accessKey=…`: makes a user or changes its secret and status. The
/// body's `policy` is ignored, as `MinIO` ignores it: policies are attached by their own
/// calls, which need their own permission.
pub(crate) async fn add_user(iam: &Iam, mut req: S3Request<Body>) -> S3Result<S3Response<Body>> {
    let access_key = required(&req, "accessKey")?;
    let request: UserRequest = decrypted(&mut req).await?;
    let secret = Some(request.secret_key.as_str()).filter(|s| !s.is_empty());
    let enabled = parse_status(&request.status)?;
    iam.minio_set_user(
        &access_key,
        MinioUserChange {
            secret,
            enabled,
            policies: None,
        },
    )
    .map_err(minio_error)?;
    Ok(empty())
}

/// `POST change-my-password`: a new secret for the key that signed the request.
pub(crate) async fn change_my_password(
    iam: &Iam,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let key = caller_key(&req).unwrap_or_default().to_owned();
    let request: UserRequest = decrypted(&mut req).await?;
    iam.minio_change_secret(&key, &request.secret_key)
        .map_err(minio_error)?;
    Ok(empty())
}

/// `DELETE remove-user?accessKey=…`.
pub(crate) fn remove_user(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let name = required(req, "accessKey")?;
    if caller_key(req) == Some(name.as_str()) {
        return Err(invalid("A user can't remove itself."));
    }
    iam.minio_remove_user(&name).map_err(minio_error)?;
    Ok(empty())
}

/// `GET user-info?accessKey=…`.
pub(crate) fn user_info(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let name = required(req, "accessKey")?;
    let user = iam.minio_user(&name).map_err(minio_error)?;
    Ok(admin::json(&UserInfo::from(user)))
}

/// `GET list-users`: every user by name, encrypted.
pub(crate) async fn list_users(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let users: BTreeMap<String, UserInfo> = iam
        .minio_users()
        .into_iter()
        .map(|u| (u.name.clone(), UserInfo::from(u)))
        .collect();
    encrypted(req, &users).await
}

/// `PUT set-user-status?accessKey=…&status=enabled|disabled`.
pub(crate) fn set_user_status(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let name = required(req, "accessKey")?;
    let enabled = parse_status(&required(req, "status")?)?.expect("not empty");
    if caller_key(req) == Some(name.as_str()) {
        return Err(invalid("A user can't change its own status."));
    }
    iam.minio_set_user_enabled(&name, enabled)
        .map_err(minio_error)?;
    Ok(empty())
}

/// `madmin.GroupAddRemove`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupChange {
    group: String,
    #[serde(default)]
    members: Option<Vec<String>>,
    #[serde(default)]
    group_status: String,
    #[serde(default)]
    is_remove: bool,
}

/// `PUT update-group-members`.
pub(crate) async fn update_group_members(
    iam: &Iam,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let body = body(&mut req).await?;
    let change: GroupChange = serde_json::from_slice(&body)
        .map_err(|_| invalid("The body isn't a group's members (GroupAddRemove)."))?;
    if change.group.is_empty() {
        return Err(invalid("A group is needed."));
    }
    let enabled = parse_status(&change.group_status)?;
    iam.minio_update_group(
        &change.group,
        &change.members.unwrap_or_default(),
        change.is_remove,
        enabled,
    )
    .map_err(minio_error)?;
    Ok(empty())
}

/// `madmin.GroupDesc`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupDesc {
    name: String,
    status: &'static str,
    members: Vec<String>,
    policy: String,
    updated_at: String,
}

impl From<MinioGroup> for GroupDesc {
    fn from(group: MinioGroup) -> Self {
        Self {
            name: group.name,
            status: status(group.enabled),
            members: group.members,
            policy: group.policies.join(","),
            updated_at: time(group.created_ms),
        }
    }
}

/// `GET group?group=…`.
pub(crate) fn group(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let name = required(req, "group")?;
    let group = iam.minio_group(&name).map_err(minio_error)?;
    Ok(admin::json(&GroupDesc::from(group)))
}

/// `GET groups`.
pub(crate) fn groups(iam: &Iam) -> S3Response<Body> {
    admin::json(&iam.minio_groups())
}

/// `PUT set-group-status?group=…&status=enabled|disabled`.
pub(crate) fn set_group_status(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let name = required(req, "group")?;
    let enabled = parse_status(&required(req, "status")?)?.expect("not empty");
    iam.minio_set_group_enabled(&name, enabled)
        .map_err(minio_error)?;
    Ok(empty())
}

/// `PUT add-canned-policy?name=…`, the body the policy's document; a built-in policy's
/// name only with `overrideBuiltin=true`, and `resetBuiltin=true` removes the override.
pub(crate) async fn add_canned_policy(
    iam: &Iam,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let name = required(&req, "name")?;
    if flag(&req, "resetBuiltin") {
        return match iam.minio_remove_policy(&name) {
            // Nothing overrides it: it's the built-in policy already.
            Ok(()) | Err(MinioError::InvalidArgument(_)) => Ok(empty()),
            Err(err) => Err(minio_error(err)),
        };
    }
    let over_builtin = flag(&req, "overrideBuiltin");
    let body = body(&mut req).await?;
    let document = std::str::from_utf8(&body).map_err(|_| {
        admin::error(
            StatusCode::BAD_REQUEST,
            "XMinioMalformedIAMPolicy",
            "A policy's document is UTF-8 JSON.",
        )
    })?;
    iam.minio_put_policy(&name, document, over_builtin)
        .map_err(minio_error)?;
    Ok(empty())
}

/// A policy's document as JSON in an answer.
fn document(text: &str) -> S3Result<serde_json::Value> {
    serde_json::from_str(text).map_err(S3Error::internal_error)
}

/// `madmin.PolicyInfo`.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct PolicyInfo {
    policy_name: String,
    policy: serde_json::Value,
    create_date: String,
    update_date: String,
}

/// `GET info-canned-policy?name=…`: the document, or with `v=2` a `PolicyInfo`.
pub(crate) fn info_canned_policy(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let name = required(req, "name")?;
    let policy = iam.minio_policy(&name).map_err(minio_error)?;
    if query(req).iter().any(|(n, v)| n == "v" && v == "2") {
        Ok(admin::json(&PolicyInfo {
            policy_name: policy.name,
            policy: document(&policy.document)?,
            create_date: time(policy.created_ms),
            update_date: time(policy.updated_ms),
        }))
    } else {
        Ok(raw(policy.document, "application/json"))
    }
}

/// `GET list-canned-policies`: every policy's document, by name.
pub(crate) fn list_canned_policies(iam: &Iam) -> S3Result<S3Response<Body>> {
    let policies = iam
        .minio_policies()
        .into_iter()
        .map(|p| Ok((p.name, document(&p.document)?)))
        .collect::<S3Result<BTreeMap<_, _>>>()?;
    Ok(admin::json(&policies))
}

/// `DELETE remove-canned-policy?name=…`.
pub(crate) fn remove_canned_policy(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let name = required(req, "name")?;
    iam.minio_remove_policy(&name).map_err(minio_error)?;
    Ok(empty())
}

/// `madmin.PolicyAssociationReq`.
#[derive(Deserialize)]
pub(crate) struct Association {
    #[serde(default)]
    pub(crate) policies: Vec<String>,
    #[serde(default)]
    pub(crate) user: String,
    #[serde(default)]
    pub(crate) group: String,
    #[serde(default, rename = "configName")]
    pub(crate) config_name: String,
}

/// `PUT set-user-or-group-policy?policyName=…&userOrGroup=…&isGroup=true|false`:
/// `MinIO`'s older call, which maps exactly the policies named (comma-separated; none:
/// no policy) to a user or group of the built-in provider's, or else of the LDAP
/// directory's.
pub(crate) async fn set_user_or_group_policy(
    iam: &Iam,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let entity = required(req, "userOrGroup")?;
    let params = query(req);
    let param = |name: &str| {
        params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    let is_group = match param("isGroup") {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(invalid("The query needs isGroup=true or isGroup=false")),
    };
    let policies: Vec<String> = param("policyName")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    let (owner, entity_kind, missing) = if is_group {
        (
            Owner::Group(&entity),
            LdapEntity::Group,
            MinioError::NoSuchGroup,
        )
    } else {
        if iam.root_access_key().as_deref() == Some(entity.as_str()) {
            return Err(minio_error(MinioError::ActionNotAllowed(
                "The root user has every permission already.".into(),
            )));
        }
        (
            Owner::User(&entity),
            LdapEntity::User,
            MinioError::NoSuchUser,
        )
    };
    let built_in = if is_group {
        iam.minio_group(&entity).is_ok()
    } else {
        iam.minio_user(&entity).is_ok()
    };
    if built_in {
        iam.minio_set_policies(owner, &policies)
            .map_err(minio_error)?;
    } else if iam.ldap().is_some() {
        let dn = if is_group {
            entity.clone()
        } else {
            match iam.find_ldap_user(&entity).await {
                Ok(Some(dn)) => dn,
                Ok(None) => return Err(minio_error(missing)),
                Err(err) => return Err(minio_error(err.into())),
            }
        };
        iam.set_ldap_policies(&dn, entity_kind, &policies)
            .await
            .map_err(|err| match err {
                MinioError::Iam(teifs_iam::IamError::NoSuchEntity(_)) => minio_error(missing),
                err => minio_error(err),
            })?;
    } else {
        return Err(minio_error(missing));
    }
    Ok(S3Response::new(Body::empty()))
}

/// `POST revoke-tokens/{userProvider}?user=&tokenRevokeType=&fullRevoke=`: ends a
/// user's temporary credentials before they expire (`mc admin user revoke`, `mc idp
/// ldap revoke`), as `MinIO` does: all of them (`fullRevoke=true`) or those issued with
/// one token revoke type. A caller without `admin:RemoveServiceAccount`, or naming no
/// user, ends its own; a session that names neither ends those of its own type.
pub(crate) async fn revoke_tokens(
    iam: &Iam,
    identity: &Identity,
    privileged: bool,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let provider = req.uri.path().rsplit('/').next().unwrap_or_default();
    let params = query(req);
    let param = |name: &str| {
        params
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, v)| v.as_str())
    };
    let user = param("user");
    let mut revoke_type = param("tokenRevokeType");
    let full = param("fullRevoke") == "true";
    let named = if user.is_empty() {
        None
    } else {
        Some(session_parent(iam, provider, user).await?)
    };
    if (named.is_some() && revoke_type.is_empty() && !full) || (!revoke_type.is_empty() && full) {
        return Err(admin::error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Name a token revoke type (tokenRevokeType) or ask for all of them (fullRevoke=true), \
             not both.",
        ));
    }
    let parent = match named {
        Some(named) if privileged => named,
        named => {
            let own = iam.session_parent(identity);
            match (own, named) {
                (Some(own), None) => own,
                (Some(own), Some(named)) if same_parent(&own, &named) => own,
                _ => return Err(s3s::s3_error!(AccessDenied, "Access Denied")),
            }
        }
    };
    if user.is_empty() && revoke_type.is_empty() && !full {
        revoke_type = identity
            .session()
            .and_then(Session::revoke_type)
            .unwrap_or_default();
        if revoke_type.is_empty() {
            return Err(admin::error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "No token revoke type specified and one could not be inferred from the request",
            ));
        }
    }
    let revoke_type = (!revoke_type.is_empty()).then_some(revoke_type);
    iam.revoke_sessions(&parent, revoke_type)
        .map_err(minio_error)?;
    let mut response = S3Response::new(Body::empty());
    response.status = Some(StatusCode::NO_CONTENT);
    Ok(response)
}

/// The user `revoke-tokens` names: a built-in one (or the root user) by access key, or
/// a directory user by name or DN. Other providers' tokens aren't revoked by user, as on
/// `MinIO`.
async fn session_parent(iam: &Iam, provider: &str, user: &str) -> S3Result<SessionParent> {
    match provider {
        "builtin" if iam.root_access_key().as_deref() == Some(user) => Ok(SessionParent::Root),
        "builtin" => Ok(SessionParent::User(user.to_owned())),
        "ldap" if iam.ldap().is_some() => match iam.find_ldap_user(user).await {
            Ok(Some(dn)) => Ok(SessionParent::Ldap(dn)),
            _ if teifs_iam::ldap::is_dn(user) => teifs_iam::ldap::normalize(user)
                .map(SessionParent::Ldap)
                .map_err(|_| minio_error(MinioError::NoSuchUser)),
            Ok(None) => Err(minio_error(MinioError::NoSuchUser)),
            Err(err) => Err(minio_error(err.into())),
        },
        "ldap" => Err(minio_error(MinioError::ActionNotAllowed(
            "LDAP isn't configured.".into(),
        ))),
        _ => Err(minio_error(MinioError::ActionNotAllowed(format!(
            "The tokens of {provider:?} users can't be revoked by user."
        )))),
    }
}

/// Whether two parents are the same user (names compare without case, as IAM's do).
fn same_parent(a: &SessionParent, b: &SessionParent) -> bool {
    match (a, b) {
        (SessionParent::User(a), SessionParent::User(b)) => a.eq_ignore_ascii_case(b),
        (a, b) => a == b,
    }
}

/// `madmin.PolicyAssociationResp`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssociationResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policies_attached: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policies_detached: Vec<String>,
    updated_at: String,
}

/// `POST idp/builtin/policy/attach` and `detach`: both encrypted.
pub(crate) async fn associate(
    iam: &Iam,
    mut req: S3Request<Body>,
    attach: bool,
) -> S3Result<S3Response<Body>> {
    let request: Association = decrypted(&mut req).await?;
    let owner = match (request.user.as_str(), request.group.as_str()) {
        (user, "") if !user.is_empty() => Owner::User(user),
        ("", group) if !group.is_empty() => Owner::Group(group),
        _ => return Err(invalid("Exactly one of user and group is needed.")),
    };
    if !request.config_name.is_empty() {
        return Err(invalid(
            "The built-in identity provider has no configurations.",
        ));
    }
    let changed = iam
        .minio_associate(owner, &request.policies, attach)
        .map_err(minio_error)?;
    encrypted(&req, &AssociationResult::new(changed, attach)).await
}

impl AssociationResult {
    /// What attaching (or detaching) changed, now.
    pub(crate) fn new(changed: Vec<String>, attach: bool) -> Self {
        let now = time(admin::millis(std::time::SystemTime::now()));
        if attach {
            Self {
                policies_attached: changed,
                policies_detached: Vec::new(),
                updated_at: now,
            }
        } else {
            Self {
                policies_attached: Vec::new(),
                policies_detached: changed,
                updated_at: now,
            }
        }
    }
}

/// `madmin.PolicyEntitiesResult`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntitiesResult {
    timestamp: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_mappings: Vec<UserMapping>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    group_mappings: Vec<GroupMapping>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_mappings: Vec<PolicyMapping>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserMapping {
    user: String,
    policies: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    member_of_mappings: Vec<GroupMapping>,
}

#[derive(Serialize)]
struct GroupMapping {
    group: String,
    policies: Vec<String>,
}

impl From<GroupPolicies> for GroupMapping {
    fn from(group: GroupPolicies) -> Self {
        Self {
            group: group.group,
            policies: group.policies,
        }
    }
}

#[derive(Serialize)]
struct PolicyMapping {
    policy: String,
    users: Vec<String>,
    groups: Vec<String>,
}

/// `GET idp/builtin/policy-entities?user=…&group=…&policy=…` (each repeated, or none
/// for all): encrypted.
pub(crate) async fn policy_entities(
    iam: &Iam,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let (mut users, mut groups, mut policies) = (Vec::new(), Vec::new(), Vec::new());
    for (name, value) in query(req) {
        match name.as_str() {
            "user" => users.push(value),
            "group" => groups.push(value),
            "policy" => policies.push(value),
            _ => {}
        }
    }
    let entities = iam.minio_policy_entities(&users, &groups, &policies);
    encrypted(req, &EntitiesResult::from(entities)).await
}

impl From<PolicyEntities> for EntitiesResult {
    fn from(entities: PolicyEntities) -> Self {
        Self {
            timestamp: time(admin::millis(std::time::SystemTime::now())),
            user_mappings: entities
                .users
                .into_iter()
                .map(|u| UserMapping {
                    user: u.user,
                    policies: u.policies,
                    member_of_mappings: u.groups.into_iter().map(GroupMapping::from).collect(),
                })
                .collect(),
            group_mappings: entities
                .groups
                .into_iter()
                .map(GroupMapping::from)
                .collect(),
            policy_mappings: entities
                .policies
                .into_iter()
                .map(|p| PolicyMapping {
                    policy: p.policy,
                    users: p.users,
                    groups: p.groups,
                })
                .collect(),
        }
    }
}

/// `madmin.AccountInfo`: Go's field names, as madmin reads them.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AccountInfo {
    account_name: String,
    server: BackendInfo,
    policy: serde_json::Value,
    buckets: Vec<BucketAccessInfo>,
}

/// `madmin.BackendInfo`: one drive, which MinIO calls a filesystem backend.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct BackendInfo {
    #[serde(rename = "Type")]
    kind: u8,
}

/// MinIO's `madmin.FS`.
const FS_BACKEND: u8 = 1;

/// `madmin.BucketAccessInfo`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BucketAccessInfo {
    name: String,
    size: u64,
    objects: u64,
    versions: u64,
    delete_markers: u64,
    details: BucketDetails,
    created: String,
    access: Access,
}

/// `madmin.BucketDetails`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "madmin's fields, each a feature turned on or off"
)]
struct BucketDetails {
    versioning: bool,
    versioning_suspended: bool,
    locking: bool,
    replication: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retention: Option<serde_json::Value>,
}

/// `madmin.AccountAccess`.
#[derive(Serialize)]
struct Access {
    read: bool,
    write: bool,
}

/// `GET accountinfo`: the caller's name and policy, and the buckets it may read or
/// write (`s3:ListBucket`, `s3:PutObject`), with what each holds.
pub(crate) async fn account_info(
    routes: &Routes,
    identity: &Identity,
    context: &Context,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let (iam, store, rules) = (&routes.iam, &routes.store, &routes.rules);
    let account = iam.minio_account(identity, caller_key(req).unwrap_or_default());
    let usage = store.usage().await.s3()?;
    let mut buckets = Vec::new();
    for bucket in store.list_buckets().await.s3()? {
        let name = &bucket.name;
        // A bucket removed meanwhile is left out.
        let Ok(bucket_rules) = rules.of(name).await else {
            continue;
        };
        let access = Access {
            read: allows(
                identity,
                context,
                "s3:ListBucket",
                &teifs_policy::bucket_arn(name),
                Some(&bucket_rules),
            ),
            write: allows(
                identity,
                context,
                "s3:PutObject",
                &teifs_policy::object_arn(name, ""),
                Some(&bucket_rules),
            ),
        };
        if !(access.read || access.write) {
            continue;
        }
        let Ok(details) = details(store, name).await else {
            continue;
        };
        let held = usage
            .iter()
            .find(|u| u.name == *name)
            .map(|u| u.usage)
            .unwrap_or_default();
        buckets.push(BucketAccessInfo {
            name: name.clone(),
            size: held.bytes,
            objects: held.objects,
            versions: held.versions,
            delete_markers: held.delete_markers,
            details,
            created: time(admin::millis(bucket.created)),
            access,
        });
    }
    Ok(admin::json(&AccountInfo {
        account_name: account.name,
        server: BackendInfo { kind: FS_BACKEND },
        policy: document(&account.policy)?,
        buckets,
    }))
}

/// What's turned on in a bucket.
async fn details(store: &Store, bucket: &str) -> teifs_store::Result<BucketDetails> {
    let versioning = store.bucket_versioning(bucket).await?;
    let lock = store.bucket_object_lock(bucket).await?;
    let quota = store.bucket_quota(bucket).await?;
    Ok(BucketDetails {
        versioning: versioning == Versioning::Enabled,
        versioning_suspended: versioning == Versioning::Suspended,
        locking: lock.is_some(),
        replication: false,
        quota: quota.map(|bytes| {
            serde_json::json!({"quota": bytes, "size": bytes, "rate": 0, "requests": 0, "quotatype": "hard"})
        }),
        retention: lock.and_then(|l| l.default_retention).map(|r| match r.period {
            RetentionPeriod::Days(days) => {
                serde_json::json!({"mode": r.mode.as_str(), "days": days})
            }
            RetentionPeriod::Years(years) => {
                serde_json::json!({"mode": r.mode.as_str(), "years": years})
            }
        }),
    })
}
