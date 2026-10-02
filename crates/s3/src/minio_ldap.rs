//! `MinIO`'s LDAP admin calls (`mc idp ldap policy`, `mc idp ldap accesskey`): the
//! policies mapped to directory users' and groups' DNs, and directory users' service
//! accounts. And `mc idp openid accesskey ls`, whose users own no access keys here.
//!
//! Answers, and the requests that hold a secret, are encrypted with the caller's secret
//! key, as `madmin` sends and reads them.

use std::collections::BTreeMap;

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::Serialize;
use teifs_iam::{Iam, IamError, Identity, LdapEntity, LdapUser, MinioError, Session};
use teifs_policy::{Context, Decision};

use crate::{
    admin,
    minio_iam::{
        Association, AssociationResult, EntitiesResult, decrypted, encrypted, minio_error, query,
    },
    minio_service_accounts::{
        AccessKeys, AddRequest, Listed, Owner, create, denied, invalid_request, is_own, list_type,
        narrowed,
    },
    routes::Routes,
};

/// Which of the calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `POST idp/ldap/policy/attach`.
    Attach,
    /// `POST idp/ldap/policy/detach`.
    Detach,
    /// `GET idp/ldap/policy-entities`.
    Entities,
    /// `PUT idp/ldap/add-service-account`.
    AddServiceAccount,
    /// `GET idp/ldap/list-access-keys`.
    ListAccessKeys,
    /// `GET idp/ldap/list-access-keys-bulk`.
    ListAccessKeysBulk,
    /// `GET idp/openid/list-access-keys-bulk`.
    OpenIdListAccessKeysBulk,
}

impl Call {
    /// The call's name, as the audit log and traces name it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Attach | Self::Detach => "AttachDetachPolicyLDAP",
            Self::Entities => "ListLDAPPolicyMappingEntities",
            Self::AddServiceAccount => "AddServiceAccountLDAP",
            Self::ListAccessKeys => "ListAccessKeysLDAP",
            Self::ListAccessKeysBulk => "ListAccessKeysLDAPBulk",
            Self::OpenIdListAccessKeysBulk => "ListAccessKeysOpenIDBulk",
        }
    }

    /// Calls it, for a caller who may: `privileged` when it has the admin action itself,
    /// beyond its own service accounts.
    pub(crate) async fn call(
        self,
        routes: &Routes,
        req: S3Request<Body>,
        (identity, context): (&Identity, &Context),
        privileged: bool,
    ) -> S3Result<S3Response<Body>> {
        let iam = &routes.iam;
        if self == Self::OpenIdListAccessKeysBulk {
            return openid_bulk(iam, &req, (identity, context), privileged).await;
        }
        if iam.ldap().is_none() {
            return Err(admin::error(
                StatusCode::NOT_IMPLEMENTED,
                "XMinioLDAPNotEnabled",
                "LDAP is not enabled. LDAP must be enabled to make LDAP requests.",
            ));
        }
        match self {
            Self::Attach => associate(iam, req, true).await,
            Self::Detach => associate(iam, req, false).await,
            Self::Entities => entities(iam, &req).await,
            Self::AddServiceAccount => add(iam, identity, privileged, req).await,
            Self::ListAccessKeys => list(iam, identity, privileged, &req).await,
            Self::ListAccessKeysBulk => list_bulk(iam, (identity, context), privileged, &req).await,
            Self::OpenIdListAccessKeysBulk => unreachable!("answered above"),
        }
    }
}

/// An IAM failure as `MinIO` answers it.
fn iam_error(err: IamError) -> S3Error {
    minio_error(MinioError::from(err))
}

/// `MinIO`'s answer for a directory user it doesn't have.
fn no_such_user(message: &str) -> S3Error {
    admin::error(StatusCode::NOT_FOUND, "XMinioAdminNoSuchUser", message)
}

/// `POST idp/ldap/policy/attach` and `detach`: an encrypted `PolicyAssociationReq`
/// naming a user (by name or DN) or a group (by DN); answers what changed, encrypted.
async fn associate(
    iam: &Iam,
    mut req: S3Request<Body>,
    attach: bool,
) -> S3Result<S3Response<Body>> {
    let request: Association = decrypted(&mut req).await?;
    for policy in &request.policies {
        iam.minio_policy(policy).map_err(minio_error)?;
    }
    let (dn, entity) = match (request.user.as_str(), request.group.as_str()) {
        (user, "") if !user.is_empty() => {
            let dn = match iam.find_ldap_user(user).await.map_err(iam_error)? {
                Some(dn) => dn,
                // A DN the directory no longer has can still have its policies detached.
                None if !attach && teifs_iam::ldap::is_dn(user) => user.to_owned(),
                None => return Err(minio_error(MinioError::NoSuchUser)),
            };
            (dn, LdapEntity::User)
        }
        ("", group) if !group.is_empty() => (group.to_owned(), LdapEntity::Group),
        _ => {
            return Err(minio_error(MinioError::InvalidArgument(
                "Exactly one of user and group is needed.".into(),
            )));
        }
    };
    let change = iam
        .change_ldap_policies(&dn, entity, &request.policies, attach)
        .await
        .map_err(|err| match (err, entity) {
            (IamError::NoSuchEntity(_), LdapEntity::User) => minio_error(MinioError::NoSuchUser),
            (IamError::NoSuchEntity(_), LdapEntity::Group) => minio_error(MinioError::NoSuchGroup),
            (err, _) => iam_error(err),
        })?;
    if change.changed.is_empty() {
        return Err(minio_error(MinioError::AlreadyApplied));
    }
    tracing::info!(
        dn = change.dn,
        entity = change.entity.as_str(),
        changed = ?change.changed,
        attach,
        "an LDAP user's or group's policies changed"
    );
    encrypted(&req, &AssociationResult::new(change.changed, attach)).await
}

/// `GET idp/ldap/policy-entities?user=…&group=…&policy=…` (each repeated, or none for
/// all): encrypted.
async fn entities(iam: &Iam, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let (mut users, mut groups, mut policies) = (Vec::new(), Vec::new(), Vec::new());
    for (name, value) in query(req) {
        match name.as_str() {
            "user" => users.push(value),
            "group" => groups.push(value),
            "policy" => policies.push(value),
            _ => {}
        }
    }
    let entities = iam
        .ldap_policy_entities(&users, &groups, &policies)
        .await
        .map_err(iam_error)?;
    encrypted(req, &EntitiesResult::from(entities)).await
}

/// `PUT idp/ldap/add-service-account`: makes a service account for the encrypted
/// request's `targetUser`, a directory user's name, or for the caller's own directory
/// user; answers its credentials, encrypted.
async fn add(
    iam: &Iam,
    identity: &Identity,
    privileged: bool,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let request: AddRequest = decrypted(&mut req).await?;
    let caller = identity.session().and_then(Session::ldap_user);
    let target = request.target_user.as_str();
    let mine = target.is_empty()
        || caller.is_some_and(|c| target == c.username || target.eq_ignore_ascii_case(c.dn));
    if mine {
        let Some(caller) = caller else {
            return Err(no_such_user("Specified user does not exist on LDAP server"));
        };
        if !privileged && narrowed(identity) {
            return Err(denied());
        }
        return create(iam, &req, &request, Owner::Ldap(caller)).await;
    }
    if !privileged {
        return Err(denied());
    }
    if teifs_iam::ldap::is_dn(target) {
        return Err(admin::error(
            StatusCode::BAD_REQUEST,
            "XMinioLDAPExpectedLoginName",
            "Expected LDAP short username but was given full DN.",
        ));
    }
    let directory = iam.ldap().expect("checked LDAP is set up");
    let found = directory
        .user(target)
        .await
        .map_err(|e| iam_error(IamError::Directory(e.to_string())))?
        .ok_or_else(|| no_such_user("Specified user does not exist on LDAP server"))?;
    let mapped = iam.ldap_policies(None).map_err(iam_error)?;
    let has_policy = mapped
        .iter()
        .any(|m| m.dn == found.dn || found.groups.contains(&m.dn));
    if !has_policy {
        return Err(no_such_user(&format!(
            "No policy set for user `{}` or any of their groups: `{}`",
            found.actual_dn,
            found.groups.join("`,`")
        )));
    }
    let user = LdapUser {
        dn: &found.dn,
        username: &found.username,
        groups: &found.groups,
    };
    create(iam, &req, &request, Owner::Ldap(user)).await
}

/// The directory user a name (or DN) names, written in one form.
async fn user_dn(iam: &Iam, name: &str) -> S3Result<String> {
    iam.find_ldap_user(name)
        .await
        .map_err(iam_error)?
        .ok_or_else(|| minio_error(MinioError::NoSuchUser))
}

/// `GET idp/ldap/list-access-keys?userDN=…&listType=…`: a directory user's service
/// accounts (the caller's own by default), encrypted.
async fn list(
    iam: &Iam,
    identity: &Identity,
    privileged: bool,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let params = query(req);
    let asked = params
        .iter()
        .find(|(n, v)| n == "userDN" && !v.is_empty())
        .map(|(_, v)| v.as_str());
    let own = iam.minio_parent(identity);
    let dn = match asked {
        Some(name) => {
            let dn = user_dn(iam, name).await?;
            if !privileged && !is_own(iam, identity, &dn) {
                return Err(denied());
            }
            dn
        }
        None => user_dn(iam, own.as_deref().unwrap_or_default()).await?,
    };
    let service_accounts = params
        .iter()
        .find(|(n, _)| n == "listType")
        .is_none_or(|(_, v)| v != "sts-only");
    encrypted(req, &AccessKeys::of(iam, &dn, service_accounts)).await
}

/// `GET idp/ldap/list-access-keys-bulk?listType=…[&userDNs=…][&all=true]`: each
/// directory user's service accounts (and temporary keys, of which none are kept), by
/// DN, encrypted. `all` needs `admin:ListUsers`; anyone but the caller needs
/// `admin:ListServiceAccounts`.
async fn list_bulk(
    iam: &Iam,
    (identity, context): (&Identity, &Context),
    privileged: bool,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let params = query(req);
    let names: Vec<&str> = params
        .iter()
        .filter(|(n, _)| n == "userDNs")
        .map(|(_, v)| v.as_str())
        .collect();
    let all = params.iter().any(|(n, v)| n == "all" && v == "true");
    if all && !names.is_empty() {
        return Err(invalid_request("Name users or ask for all, not both."));
    }
    if all && identity.decide(context, "admin:ListUsers", "*", None) != Decision::Allow {
        return Err(denied());
    }
    let mut dns = Vec::new();
    if all {
        dns = iam.ldap_users().map_err(iam_error)?;
    } else if names.is_empty() {
        dns.push(user_dn(iam, &iam.minio_parent(identity).unwrap_or_default()).await?);
    } else {
        for name in &names {
            if let Some(dn) = iam.find_ldap_user(name).await.map_err(iam_error)? {
                dns.push(dn);
            }
        }
    }
    let mine = !all && dns.len() <= 1 && dns.iter().all(|dn| is_own(iam, identity, dn));
    if !mine && !privileged {
        return Err(denied());
    }
    let (sts, service_accounts) = list_type(&params)?;
    let mut answer = BTreeMap::new();
    for dn in dns {
        let keys = AccessKeys::of(iam, &dn, service_accounts);
        // Only one kind asked for: users with none of it are left out.
        if (sts && !service_accounts)
            || (service_accounts && !sts && keys.service_accounts.is_empty())
        {
            continue;
        }
        answer.insert(dn, keys);
    }
    encrypted(req, &answer).await
}

/// `madmin.ListAccessKeysOpenIDResp`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenIdAccessKeys {
    config_name: &'static str,
    users: Vec<OpenIdUserKeys>,
}

/// `madmin.OpenIDUserAccessKeys`.
#[derive(Serialize)]
struct OpenIdUserKeys {
    #[serde(rename = "minioAccessKey")]
    minio_access_key: String,
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "readableName")]
    readable_name: String,
    #[serde(rename = "serviceAccounts")]
    service_accounts: Vec<Listed>,
    #[serde(rename = "stsKeys")]
    sts_keys: Vec<Listed>,
}

/// The name `MinIO` gives the OpenID Connect configuration that has none.
const DEFAULT_CONFIG: &str = "_";

/// `GET idp/openid/list-access-keys-bulk`: OpenID Connect users' service accounts, by
/// configuration (one, `MinIO`'s default, for every provider), each user by `MinIO`'s
/// name for it with its `sub` as its id. Their sessions' keys aren't kept. A user is
/// named by either; the caller is its own by default.
async fn openid_bulk(
    iam: &Iam,
    req: &S3Request<Body>,
    (identity, context): (&Identity, &Context),
    privileged: bool,
) -> S3Result<S3Response<Body>> {
    if iam.oidc_providers().map_err(iam_error)?.is_empty() {
        return Err(admin::error(
            StatusCode::BAD_REQUEST,
            "OpenIDNotEnabled",
            "No enabled OpenID Connect identity providers",
        ));
    }
    let params = query(req);
    let value = |name: &str| {
        params
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, v)| v.as_str())
    };
    let users: Vec<&str> = params
        .iter()
        .filter(|(n, _)| n == "users")
        .map(|(_, v)| v.as_str())
        .collect();
    let all = value("all") == "true";
    if all && !users.is_empty() {
        return Err(invalid_request("Name users or ask for all, not both."));
    }
    if all && identity.decide(context, "admin:ListUsers", "*", None) != Decision::Allow {
        return Err(denied());
    }
    let own = iam.minio_parent(identity);
    let mine = !all && (users.is_empty() || (users.len() == 1 && own.as_deref() == Some(users[0])));
    if !mine && !privileged {
        return Err(denied());
    }
    let (_, service_accounts) = list_type(&params)?;
    let config = value("configName");
    if value("allConfigs") != "true" && !config.is_empty() && config != DEFAULT_CONFIG {
        return Err(admin::error(
            StatusCode::BAD_REQUEST,
            "XMinioAdminNoSuchConfigTarget",
            "No such named configuration target exists",
        ));
    }
    let named = |user: &str, sub: &str| {
        if all {
            return true;
        }
        if users.is_empty() {
            return own.as_deref() == Some(user);
        }
        users.iter().any(|u| *u == user || *u == sub)
    };
    let mut listed: Vec<OpenIdUserKeys> = Vec::new();
    if service_accounts {
        for found in iam.minio_openid_service_accounts() {
            if !named(&found.user, &found.sub) {
                continue;
            }
            let account = Listed::from(found.account);
            match listed.last_mut() {
                Some(last) if last.minio_access_key == found.user => {
                    last.service_accounts.push(account);
                }
                _ => listed.push(OpenIdUserKeys {
                    minio_access_key: found.user,
                    id: found.sub,
                    readable_name: String::new(),
                    service_accounts: vec![account],
                    sts_keys: Vec::new(),
                }),
            }
        }
    }
    encrypted(
        req,
        &[OpenIdAccessKeys {
            config_name: DEFAULT_CONFIG,
            users: listed,
        }],
    )
    .await
}
