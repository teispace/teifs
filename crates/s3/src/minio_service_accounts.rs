//! `MinIO`'s service accounts (`mc admin user svcacct`, `mc admin accesskey`): access
//! keys a user (or the root user) makes for itself, which act as it, narrowed by their
//! own policy when they have one, until they expire.
//!
//! A caller manages its own without the admin action, unless a policy denies it; anyone
//! else's needs the action, as `MinIO` decides it. "Its own" are those of the `MinIO` user
//! the caller acts as ([`Iam::minio_parent`]). Requests and answers holding a secret,
//! and lists, are encrypted with the caller's secret key.

use std::collections::BTreeMap;

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::{Deserialize, Serialize};
use teifs_iam::{
    Iam, Identity, MinioError, MinioServiceAccount, NewServiceAccount, ServiceAccountChange,
};
use teifs_policy::{Context, Decision};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    admin,
    minio_iam::{
        caller_key, decrypted, encrypted, invalid, minio_error, query, required, status, time,
    },
};

/// The expiry `MinIO` writes for a service account that never expires: the epoch.
const NEVER_MS: i64 = 0;

/// `madmin.AddServiceAccountReq`.
#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct AddRequest {
    #[serde(default)]
    #[zeroize(skip)]
    policy: Option<serde_json::Value>,
    #[serde(default)]
    target_user: String,
    #[serde(default)]
    access_key: String,
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    expiration: Option<String>,
}

/// `madmin.UpdateServiceAccountReq`.
#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
struct UpdateRequest {
    #[serde(default, rename = "newPolicy")]
    #[zeroize(skip)]
    policy: Option<serde_json::Value>,
    #[serde(default, rename = "newSecretKey")]
    secret_key: String,
    #[serde(default, rename = "newStatus")]
    status: String,
    #[serde(default, rename = "newName")]
    name: String,
    #[serde(default, rename = "newDescription")]
    description: String,
    #[serde(default, rename = "newExpiration")]
    expiration: Option<String>,
}

/// `madmin.Credentials`, in `madmin.AddServiceAccountResp`.
#[derive(Serialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct Credentials {
    access_key: String,
    secret_key: String,
    expiration: String,
}

#[derive(Serialize)]
struct Added {
    credentials: Credentials,
}

/// `madmin.InfoServiceAccountResp`, and the fields `madmin.InfoAccessKeyResp` shares.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Info {
    parent_user: String,
    account_status: &'static str,
    implied_policy: bool,
    policy: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<String>,
}

impl From<MinioServiceAccount> for Info {
    fn from(account: MinioServiceAccount) -> Self {
        Self {
            parent_user: account.parent,
            account_status: status(account.enabled),
            implied_policy: account.implied,
            policy: account.policy,
            name: account.name,
            description: account.description,
            expiration: account.expires_ms.map(time),
        }
    }
}

/// `madmin.InfoAccessKeyResp`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessKeyInfo {
    #[serde(rename = "AccessKey")]
    access_key: String,
    #[serde(flatten)]
    info: Info,
    user_type: &'static str,
    user_provider: &'static str,
}

/// `madmin.ServiceAccountInfo`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Listed {
    parent_user: String,
    account_status: &'static str,
    implied_policy: bool,
    access_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    expiration: String,
}

impl From<MinioServiceAccount> for Listed {
    fn from(account: MinioServiceAccount) -> Self {
        Self {
            parent_user: account.parent,
            account_status: status(account.enabled),
            implied_policy: account.implied,
            access_key: account.access_key,
            name: account.name,
            description: account.description,
            expiration: time(account.expires_ms.unwrap_or(NEVER_MS)),
        }
    }
}

/// `madmin.ListServiceAccountsResp`.
#[derive(Serialize)]
struct List {
    accounts: Vec<Listed>,
}

/// `madmin.ListAccessKeysResp`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessKeys {
    service_accounts: Vec<Listed>,
    sts_keys: Vec<Listed>,
}

/// A policy as `madmin` sends it: an empty document (no `Version`, no `Statement`) is
/// none, as `MinIO` takes it.
fn policy_text(policy: Option<&serde_json::Value>) -> Option<String> {
    let policy = policy.filter(|p| !p.is_null())?;
    let empty = policy.as_object().is_some_and(|o| {
        o.get("Version").is_none_or(|v| v.as_str() == Some(""))
            && o.get("Statement")
                .is_none_or(|s| s.as_array().is_some_and(Vec::is_empty))
    });
    (!empty).then(|| policy.to_string())
}

/// An expiry as `madmin` sends it, in milliseconds: `None` for never (Go's zero time or
/// the epoch).
fn expiry(text: &str) -> S3Result<Option<i64>> {
    let at = OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|_| invalid("An expiration is an RFC 3339 time."))?;
    if at.year() <= 1 || at == OffsetDateTime::UNIX_EPOCH {
        return Ok(None);
    }
    let ms = at.unix_timestamp_nanos() / 1_000_000;
    Ok(Some(
        i64::try_from(ms).map_err(|_| invalid("The expiration is out of range."))?,
    ))
}

/// The `MinIO` user whose service accounts are the caller's own, or its access key when
/// it acts as none.
fn own(iam: &Iam, identity: &Identity, req: &S3Request<Body>) -> String {
    iam.minio_parent(identity)
        .unwrap_or_else(|| caller_key(req).unwrap_or_default().to_owned())
}

/// Whether `user` names the caller: its own `MinIO` user or the key that signed.
fn is_own(iam: &Iam, identity: &Identity, req: &S3Request<Body>, user: &str) -> bool {
    caller_key(req) == Some(user) || iam.minio_parent(identity).as_deref() == Some(user)
}

/// `204 No Content`, which `madmin` expects of an update or a delete.
fn no_content() -> S3Response<Body> {
    let mut response = S3Response::new(Body::empty());
    response.status = Some(StatusCode::NO_CONTENT);
    response
}

fn denied() -> S3Error {
    s3s::s3_error!(AccessDenied, "Access Denied")
}

/// `PUT add-service-account`: makes a service account for the body's `targetUser`, or
/// the caller's own user; answers its credentials, encrypted.
pub(crate) async fn add(
    iam: &Iam,
    identity: &Identity,
    privileged: bool,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let request: AddRequest = decrypted(&mut req).await?;
    let mine = request.target_user.is_empty() || is_own(iam, identity, &req, &request.target_user);
    if !mine && !privileged {
        return Err(denied());
    }
    let parent = if mine {
        iam.minio_parent(identity).ok_or_else(|| {
            invalid("Service accounts are made for users: this caller acts as none.")
        })?
    } else {
        request.target_user.clone()
    };
    let policy = policy_text(request.policy.as_ref());
    let expires_ms = request
        .expiration
        .as_deref()
        .map(expiry)
        .transpose()?
        .flatten();
    let added = iam
        .minio_add_service_account(
            &parent,
            NewServiceAccount {
                access_key: Some(request.access_key.as_str()).filter(|k| !k.is_empty()),
                secret: Some(request.secret_key.as_str()).filter(|s| !s.is_empty()),
                policy: policy.as_deref(),
                name: &request.name,
                description: &request.description,
                expires_ms,
            },
        )
        .map_err(|err| match err {
            MinioError::NoSuchUser => admin::error(
                StatusCode::from_u16(err.status()).unwrap_or(StatusCode::NOT_FOUND),
                err.code(),
                format!("Specified target user {parent} does not exist"),
            ),
            err => minio_error(err),
        })?;
    let answer = Added {
        credentials: Credentials {
            access_key: added.access_key.clone(),
            secret_key: added.secret.to_string(),
            expiration: time(added.expires_ms.unwrap_or(NEVER_MS)),
        },
    };
    encrypted(&req, &answer).await
}

/// A status as `MinIO` takes it for a service account: `on`, `off`, `enabled`,
/// `disabled`, or none.
fn parse_status(text: &str) -> S3Result<Option<bool>> {
    match text {
        "" => Ok(None),
        "on" | "enabled" => Ok(Some(true)),
        "off" | "disabled" => Ok(Some(false)),
        _ => Err(invalid("A status is on, off, enabled or disabled.")),
    }
}

/// `POST update-service-account?accessKey=…`: changes what the body names; what it
/// leaves out stays.
pub(crate) async fn update(iam: &Iam, mut req: S3Request<Body>) -> S3Result<S3Response<Body>> {
    let access_key = required(&req, "accessKey")?;
    let request: UpdateRequest = decrypted(&mut req).await?;
    let policy = request.policy.as_ref().map(|p| policy_text(Some(p)));
    let expires_ms = request.expiration.as_deref().map(expiry).transpose()?;
    iam.minio_update_service_account(
        &access_key,
        ServiceAccountChange {
            secret: Some(request.secret_key.as_str()).filter(|s| !s.is_empty()),
            enabled: parse_status(&request.status)?,
            policy: policy.as_ref().map(Option::as_deref),
            name: Some(request.name.as_str()).filter(|n| !n.is_empty()),
            description: Some(request.description.as_str()).filter(|d| !d.is_empty()),
            expires_ms,
        },
    )
    .map_err(minio_error)?;
    Ok(no_content())
}

/// `GET info-service-account?accessKey=…`, encrypted.
pub(crate) async fn info(
    iam: &Iam,
    identity: &Identity,
    privileged: bool,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let access_key = required(req, "accessKey")?;
    let account = iam.minio_service_account(&access_key);
    if !privileged
        && !account
            .as_ref()
            .is_ok_and(|a| is_own(iam, identity, req, &a.parent))
    {
        return Err(denied());
    }
    encrypted(req, &Info::from(account.map_err(minio_error)?)).await
}

/// `GET list-service-accounts[?user=…]`: the user's service accounts (the caller's own
/// by default), encrypted.
pub(crate) async fn list(
    iam: &Iam,
    identity: &Identity,
    privileged: bool,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let user = query(req)
        .into_iter()
        .find(|(n, v)| n == "user" && !v.is_empty())
        .map_or_else(|| own(iam, identity, req), |(_, v)| v);
    if !privileged && !is_own(iam, identity, req, &user) {
        return Err(denied());
    }
    let accounts = iam
        .minio_service_accounts(&user)
        .into_iter()
        .map(Listed::from)
        .collect();
    encrypted(req, &List { accounts }).await
}

/// `DELETE delete-service-account?accessKey=…`: anyone else's is as missing as one that
/// isn't there, to a caller without the action.
pub(crate) fn delete(
    iam: &Iam,
    identity: &Identity,
    privileged: bool,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let access_key = required(req, "accessKey")?;
    if !privileged {
        let account = iam
            .minio_service_account(&access_key)
            .map_err(minio_error)?;
        if !is_own(iam, identity, req, &account.parent) {
            return Err(minio_error(MinioError::NoSuchServiceAccount));
        }
    }
    iam.minio_remove_service_account(&access_key)
        .map_err(minio_error)?;
    Ok(no_content())
}

/// `GET info-access-key?accessKey=…`: a service account, as `mc admin accesskey info`
/// shows it, encrypted. Temporary credentials keep nothing to show.
pub(crate) async fn info_access_key(
    iam: &Iam,
    identity: &Identity,
    privileged: bool,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let access_key = query(req)
        .into_iter()
        .find(|(n, v)| n == "accessKey" && !v.is_empty())
        .map_or_else(
            || caller_key(req).unwrap_or_default().to_owned(),
            |(_, v)| v,
        );
    let account = iam.minio_service_account(&access_key);
    if !privileged
        && !account
            .as_ref()
            .is_ok_and(|a| is_own(iam, identity, req, &a.parent))
    {
        return Err(denied());
    }
    let account = account.map_err(|_| minio_error(MinioError::NoSuchAccessKey))?;
    let answer = AccessKeyInfo {
        access_key,
        info: Info::from(account),
        user_type: "Service Account",
        user_provider: "builtin",
    };
    encrypted(req, &answer).await
}

/// `GET temporary-account-info?accessKey=…`: nothing about a session is kept, so there's
/// none to describe.
pub(crate) fn temporary_account_info(req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    required(req, "accessKey").map_err(|_| invalid_request("The query needs accessKey=…"))?;
    Err(minio_error(MinioError::NoSuchAccessKey))
}

fn invalid_request(message: &str) -> S3Error {
    admin::error(StatusCode::BAD_REQUEST, "InvalidRequest", message)
}

/// `GET list-access-keys-bulk?listType=…[&users=…][&all=true]`: each user's service
/// accounts (and temporary keys, of which none are kept), encrypted. `all` needs
/// `admin:ListUsers`; anyone but the caller needs `admin:ListServiceAccounts`.
pub(crate) async fn list_bulk(
    iam: &Iam,
    (identity, context): (&Identity, &Context),
    privileged: bool,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let params = query(req);
    let mut users: Vec<String> = params
        .iter()
        .filter(|(n, _)| n == "users")
        .map(|(_, v)| v.clone())
        .collect();
    let all = params.iter().any(|(n, v)| n == "all" && v == "true");
    if all && !users.is_empty() {
        return Err(invalid_request("Name users or ask for all, not both."));
    }
    if all && identity.decide(context, "admin:ListUsers", "*", None) != Decision::Allow {
        return Err(denied());
    }
    let mine =
        !all && (users.is_empty() || (users.len() == 1 && is_own(iam, identity, req, &users[0])));
    if !mine && !privileged {
        return Err(denied());
    }
    let (sts, service_accounts) = match params
        .iter()
        .find(|(n, _)| n == "listType")
        .map_or("", |(_, v)| v.as_str())
    {
        "users-only" => (false, false),
        "sts-only" => (true, false),
        "svcacc-only" => (false, true),
        "all" => (true, true),
        _ => {
            return Err(invalid_request(
                "listType is users-only, sts-only, svcacc-only or all.",
            ));
        }
    };
    let root = iam.root_access_key();
    if all {
        users = iam.minio_users().into_iter().map(|u| u.name).collect();
        users.extend(root.clone());
    } else if users.is_empty() {
        users.push(own(iam, identity, req));
    }
    let mut answer = BTreeMap::new();
    for user in users {
        let known = root.as_deref() == Some(user.as_str()) || iam.minio_user(&user).is_ok();
        if !known {
            continue;
        }
        let accounts: Vec<Listed> = if service_accounts {
            iam.minio_service_accounts(&user)
                .into_iter()
                .map(Listed::from)
                .collect()
        } else {
            Vec::new()
        };
        // Only one kind asked for: users with none of it are left out.
        if (sts && !service_accounts) || (service_accounts && !sts && accounts.is_empty()) {
            continue;
        }
        answer.insert(
            user,
            AccessKeys {
                service_accounts: accounts,
                sts_keys: Vec::new(),
            },
        );
    }
    encrypted(req, &answer).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policies_are_none() {
        let none = [
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!({"Version": "", "Statement": []}),
        ];
        for policy in none {
            assert_eq!(policy_text(Some(&policy)), None, "{policy}");
        }
        assert_eq!(policy_text(None), None);
        let some = serde_json::json!({"Version": "2012-10-17", "Statement": []});
        assert_eq!(policy_text(Some(&some)), Some(some.to_string()));
        let statements = serde_json::json!({"Statement": [{"Effect": "Allow"}]});
        assert!(policy_text(Some(&statements)).is_some());
    }

    #[test]
    fn expiries_read_go_times_and_never() {
        assert_eq!(expiry("0001-01-01T00:00:00Z").unwrap(), None);
        assert_eq!(expiry("1970-01-01T00:00:00Z").unwrap(), None);
        assert_eq!(
            expiry("2030-01-01T00:00:00.5Z").unwrap(),
            Some(1_893_456_000_500)
        );
        assert!(expiry("tomorrow").is_err());
    }

    #[test]
    fn statuses_are_minio_s() {
        assert_eq!(parse_status("").unwrap(), None);
        assert_eq!(parse_status("on").unwrap(), Some(true));
        assert_eq!(parse_status("enabled").unwrap(), Some(true));
        assert_eq!(parse_status("off").unwrap(), Some(false));
        assert_eq!(parse_status("disabled").unwrap(), Some(false));
        assert!(parse_status("yes").is_err());
    }
}
