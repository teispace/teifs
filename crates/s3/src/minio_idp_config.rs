//! `MinIO`'s identity provider configurations (`mc admin idp ldap|openid add|update|
//! remove|info|list`): the `identity_ldap` and `identity_openid` targets of the drive's
//! key-value configuration ([`crate::minio_config`]), one target per call. Like `MinIO`'s,
//! they take effect when the server starts again, and the answers say so.
//!
//! Every call needs `admin:ConfigUpdate`. Configurations travel encrypted with the
//! caller's secret key, as madmin sends them.

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::Serialize;
use teifs_types::config_kv::{ConfigKv, DEFAULT_TARGET};

use crate::{
    admin,
    minio_config::{config_error, configs, decrypted, keep, variable},
    minio_iam::encrypted,
    routes::Routes,
};

/// An identity provider configuration call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `PUT idp-config/{type}/{name}`: a configuration that isn't there yet.
    Add,
    /// `POST idp-config/{type}/{name}`: changes one that is.
    Update,
    /// `GET idp-config/{type}`.
    List,
    /// `GET idp-config/{type}/{name}`.
    Get,
    /// `DELETE idp-config/{type}/{name}`.
    Delete,
}

impl Call {
    /// The call's name, in metrics and the audit log (`MinIO`'s).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Add => "AddIdentityProviderCfg",
            Self::Update => "UpdateIdentityProviderCfg",
            Self::List => "ListIdentityProviderCfg",
            Self::Get => "GetIdentityProviderCfg",
            Self::Delete => "DeleteIdentityProviderCfg",
        }
    }

    pub(crate) async fn call(
        self,
        routes: &Routes,
        mut req: S3Request<Body>,
    ) -> S3Result<S3Response<Body>> {
        let configs = configs(routes)?;
        let path = req.uri.path().to_owned();
        let (kind, name) = asked(&path)?;
        let files = &configs.settings.files;
        match self {
            Self::List => {
                let config = files.load().map_err(S3Error::internal_error)?;
                let list = available(&config, kind)?
                    .into_iter()
                    .map(|name| listed(&config, kind, name))
                    .collect::<S3Result<Vec<_>>>()?;
                encrypted(&req, &list).await
            }
            Self::Get => {
                let config = files.load().map_err(S3Error::internal_error)?;
                let name = existing(&config, kind, name)?;
                encrypted(&req, &info(&config, kind, &name)?).await
            }
            Self::Add | Self::Update => {
                let opaque = req
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .is_some_and(|v| v == "application/octet-stream");
                if !opaque {
                    return Err(admin::error(
                        StatusCode::BAD_REQUEST,
                        "BadRequest",
                        "400 BadRequest",
                    ));
                }
                let text = decrypted(&mut req).await?;
                let name = name.unwrap_or(DEFAULT_TARGET);
                if kind == Kind::Ldap && name != DEFAULT_TARGET {
                    return Err(admin::error(
                        StatusCode::BAD_REQUEST,
                        "XMinioAdminConfigLDAPNonDefaultConfigName",
                        "Only a single LDAP configuration is supported - config name must be \
                         empty or `_`",
                    ));
                }
                let _changing = configs.changing.lock().await;
                let mut config = files.load().map_err(S3Error::internal_error)?;
                let exists = if name == DEFAULT_TARGET {
                    !config
                        .resolved(kind.subsystem(), name, &variable)
                        .map_err(config_error)?
                        .is_empty()
                } else {
                    find(&config, kind, name)?.is_some()
                };
                if exists && self == Self::Add {
                    return Err(bad(
                        "XMinioAdminConfigIDPCfgNameAlreadyExists",
                        "An IDP configuration with the given name already exists",
                    ));
                }
                if !exists && self == Self::Update {
                    return Err(bad(
                        "XMinioAdminConfigIDPCfgNameDoesNotExist",
                        "No such IDP configuration exists",
                    ));
                }
                let line = format!("{} {}", target(kind, name), text.as_str());
                config.set(&line).map_err(config_error)?;
                keep(configs, &config)?;
                files.record(&line).map_err(S3Error::internal_error)?;
                Ok(S3Response::new(Body::empty()))
            }
            Self::Delete => {
                let _changing = configs.changing.lock().await;
                let mut config = files.load().map_err(S3Error::internal_error)?;
                let name = existing(&config, kind, name)?;
                let resolved = config
                    .resolved(kind.subsystem(), &name, &variable)
                    .map_err(config_error)?;
                if resolved.iter().any(|r| r.from_env) {
                    return Err(bad(
                        "XMinioAdminConfigEnvOverridden",
                        "Unable to update config via Admin API due to environment variable \
                         override",
                    ));
                }
                if config.target_names(kind.subsystem()).contains(&name) {
                    config.delete(&target(kind, &name)).map_err(config_error)?;
                    keep(configs, &config)?;
                }
                Ok(S3Response::new(Body::empty()))
            }
        }
    }
}

/// The kinds of identity provider `MinIO` configures this way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    OpenId,
    Ldap,
}

impl Kind {
    const fn subsystem(self) -> &'static str {
        match self {
            Self::OpenId => "identity_openid",
            Self::Ldap => "identity_ldap",
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::OpenId => "openid",
            Self::Ldap => "ldap",
        }
    }
}

/// The kind and name a path asks for: `…/idp-config/{type}[/{name}]`.
fn asked(path: &str) -> S3Result<(Kind, Option<&str>)> {
    let rest = path.split_once("/idp-config/").map_or("", |(_, rest)| rest);
    let (kind, name) = match rest.split_once('/') {
        Some((kind, name)) => (kind, Some(name)),
        None => (rest, None),
    };
    let kind = match kind {
        "openid" => Kind::OpenId,
        "ldap" => Kind::Ldap,
        _ => {
            return Err(bad(
                "XMinioAdminConfigInvalidIDPType",
                "Invalid IDP configuration type - must be one of [ldap openid]",
            ));
        }
    };
    Ok((kind, name))
}

/// The configuration's target line for a name: `identity_openid:dex`, or the sub-system
/// alone for the default.
fn target(kind: Kind, name: &str) -> String {
    if name == DEFAULT_TARGET {
        kind.subsystem().to_owned()
    } else {
        format!("{}:{name}", kind.subsystem())
    }
}

/// The names of a kind's configurations: those set and those `MinIO`'s variables name.
fn available(config: &ConfigKv, kind: Kind) -> S3Result<Vec<String>> {
    let variables: Vec<String> = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .collect();
    config
        .available_targets(kind.subsystem(), variables.iter().map(String::as_str))
        .map_err(config_error)
}

/// The configuration named `name` as it's spelled, if there is one.
fn find(config: &ConfigKv, kind: Kind, name: &str) -> S3Result<Option<String>> {
    Ok(available(config, kind)?
        .into_iter()
        .find(|n| n.eq_ignore_ascii_case(name)))
}

/// The configuration a call names, which must be there.
fn existing(config: &ConfigKv, kind: Kind, name: Option<&str>) -> S3Result<String> {
    let name = name.unwrap_or(DEFAULT_TARGET);
    let found = if kind == Kind::Ldap {
        (name == DEFAULT_TARGET).then(|| name.to_owned())
    } else {
        find(config, kind, name)?
    };
    found.ok_or_else(|| {
        bad(
            "XMinioAdminNoSuchConfigTarget",
            "No such named configuration target exists",
        )
    })
}

/// madmin's `IDPListItem`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListItem {
    #[serde(rename = "type")]
    kind: &'static str,
    name: String,
    enabled: bool,
    #[serde(rename = "roleARN", skip_serializing_if = "Option::is_none")]
    role_arn: Option<String>,
}

fn listed(config: &ConfigKv, kind: Kind, name: String) -> S3Result<ListItem> {
    let (enabled, role_arn) = state(config, kind, &name)?;
    Ok(ListItem {
        kind: kind.name(),
        name,
        enabled,
        role_arn,
    })
}

/// Whether a configuration is on, and the role ARN an OpenID one with role policies
/// gives its tokens.
fn state(config: &ConfigKv, kind: Kind, name: &str) -> S3Result<(bool, Option<String>)> {
    let (on, values) = config
        .resolved_on(kind.subsystem(), name, &variable)
        .map_err(config_error)?;
    let role_arn = (on && kind == Kind::OpenId)
        .then(|| {
            let has_roles = values.get("role_policy").is_some_and(|p| !p.is_empty());
            let client_id = values.get("client_id")?;
            has_roles.then(|| teifs_iam::openid_role_arn(client_id))
        })
        .flatten();
    Ok((on, role_arn))
}

/// madmin's `IDPConfig`.
#[derive(Debug, Serialize)]
struct IdpConfig {
    #[serde(rename = "type")]
    kind: &'static str,
    name: String,
    info: Vec<InfoItem>,
}

/// madmin's `IDPCfgInfo`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoItem {
    key: String,
    value: String,
    is_cfg: bool,
    is_env: bool,
}

fn info(config: &ConfigKv, kind: Kind, name: &str) -> S3Result<IdpConfig> {
    let mut info: Vec<InfoItem> = config
        .resolved(kind.subsystem(), name, &variable)
        .map_err(config_error)?
        .into_iter()
        .map(|r| InfoItem {
            key: r.key,
            value: r.value,
            is_cfg: true,
            is_env: r.from_env,
        })
        .collect();
    if let (_, Some(role_arn)) = state(config, kind, name)? {
        info.push(InfoItem {
            key: "roleARN".to_owned(),
            value: role_arn,
            is_cfg: false,
            is_env: false,
        });
    }
    info.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(IdpConfig {
        kind: kind.name(),
        name: name.to_owned(),
        info,
    })
}

fn bad(code: &str, message: &str) -> S3Error {
    admin::error(StatusCode::BAD_REQUEST, code, message)
}
