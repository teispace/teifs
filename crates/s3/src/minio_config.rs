//! `MinIO`'s configuration calls (`mc admin config get|set|reset|history|restore|export|
//! import`), on the drive's key-value configuration ([`teifs_types::config_kv`]). What
//! they set takes effect when the server starts again (`mc admin service restart`), as
//! `MinIO`'s settings that aren't dynamic do: the answers never say it was applied.
//!
//! Every call needs `admin:ConfigUpdate`. Configurations travel encrypted with the
//! caller's secret key, as madmin sends them; the help doesn't.

use std::{sync::Arc, time::SystemTime};

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::Serialize;
use teifs_store::{ConfigChange, ConfigFiles};
use teifs_types::config_kv::{self, ConfigError, ConfigKv};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    admin,
    minio_iam::{caller_secret, encrypted, encrypted_bytes, query},
    routes::{Routes, s3_refusal, signed_body},
};

/// The largest configuration a call takes, as `MinIO`'s `maxEConfigJSONSize`.
const MAX_BODY_BYTES: usize = 262_272;

/// Checks a configuration as the server's next start would read it.
pub type CheckConfig = dyn Fn(&ConfigKv) -> Result<(), String> + Send + Sync;

/// Where `mc admin config` keeps what it sets, and how a change is checked before it's
/// kept: a change the next start would refuse is refused now.
#[derive(Clone)]
pub struct ConfigSettings {
    /// The drive's configuration files.
    pub files: ConfigFiles,
    /// The check `teifs serve` makes of the settings it starts with.
    pub check: Arc<CheckConfig>,
}

impl std::fmt::Debug for ConfigSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigSettings")
            .field("files", &self.files)
            .finish_non_exhaustive()
    }
}

/// The configuration settings with the lock that keeps changes one at a time.
#[derive(Debug)]
pub(crate) struct Configs {
    settings: ConfigSettings,
    changing: tokio::sync::Mutex<()>,
}

impl Configs {
    pub(crate) fn new(settings: ConfigSettings) -> Self {
        Self {
            settings,
            changing: tokio::sync::Mutex::new(()),
        }
    }
}

/// A configuration call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// A sub-system's targets, without secrets (`?key=subsys[:target]`).
    Get,
    /// Sets the lines of the body.
    Set,
    /// Resets the targets or keys of the body.
    Delete,
    /// Help for `?subSys=` and `?key=`.
    Help,
    /// The newest `?count=` changes.
    History,
    /// Forgets the change `?restoreId=` (`all` for every one).
    ClearHistory,
    /// Sets a change's lines again (`?restoreId=`).
    RestoreHistory,
    /// The whole configuration, secrets included.
    Export,
    /// Replaces the whole configuration.
    Import,
}

impl Call {
    /// The call's name, in metrics and the audit log (`MinIO`'s).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Get => "GetConfigKV",
            Self::Set => "SetConfigKV",
            Self::Delete => "DelConfigKV",
            Self::Help => "HelpConfigKV",
            Self::History => "ListConfigHistoryKV",
            Self::ClearHistory => "ClearConfigHistoryKV",
            Self::RestoreHistory => "RestoreConfigHistoryKV",
            Self::Export => "GetConfig",
            Self::Import => "SetConfig",
        }
    }

    /// Calls it.
    pub(crate) async fn call(
        self,
        routes: &Routes,
        mut req: S3Request<Body>,
    ) -> S3Result<S3Response<Body>> {
        if self == Self::Help {
            let help = config_kv::help(
                &param(&req, "subSys").unwrap_or_default(),
                &param(&req, "key").unwrap_or_default(),
                param(&req, "env").is_some(),
            )
            .map_err(config_error)?;
            return Ok(admin::json(&help));
        }
        let configs = routes.configs.as_deref().ok_or_else(|| {
            admin::error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                "This server's settings aren't kept on its drive.",
            )
        })?;
        let files = &configs.settings.files;
        match self {
            Self::Get => {
                let config = files.load().map_err(S3Error::internal_error)?;
                let text = config
                    .get(&param(&req, "key").unwrap_or_default(), &variable)
                    .map_err(config_error)?;
                encrypted_bytes(&req, Zeroizing::new(text.into_bytes())).await
            }
            Self::Export => {
                let config = files.load().map_err(S3Error::internal_error)?;
                let text = Zeroizing::new(config.export(&variable).into_bytes());
                encrypted_bytes(&req, text).await
            }
            Self::History => {
                let count = param(&req, "count")
                    .and_then(|c| c.parse::<usize>().ok())
                    .ok_or_else(|| {
                        crate::minio_iam::invalid("Say how many changes: ?count=N (0 for all).")
                    })?;
                let changes = files
                    .changes((count > 0).then_some(count))
                    .map_err(S3Error::internal_error)?;
                let entries: Vec<HistoryEntry> = changes.into_iter().map(Into::into).collect();
                encrypted(&req, &entries).await
            }
            Self::ClearHistory => {
                let id = restore_id(&req)?;
                let _changing = configs.changing.lock().await;
                if id == "all" {
                    for change in files.changes(None).map_err(S3Error::internal_error)? {
                        files.forget(&change.id).map_err(S3Error::internal_error)?;
                    }
                } else if !files.forget(&id).map_err(S3Error::internal_error)? {
                    return Err(no_change(&id));
                }
                Ok(S3Response::new(Body::empty()))
            }
            Self::RestoreHistory => {
                let id = restore_id(&req)?;
                let _changing = configs.changing.lock().await;
                let change = files
                    .read(&id)
                    .map_err(S3Error::internal_error)?
                    .ok_or_else(|| no_change(&id))?;
                let mut config = files.load().map_err(S3Error::internal_error)?;
                config.set(&change.text).map_err(config_error)?;
                keep(configs, &config)?;
                files.forget(&id).map_err(S3Error::internal_error)?;
                Ok(S3Response::new(Body::empty()))
            }
            Self::Set | Self::Delete | Self::Import => {
                let text = decrypted(&mut req).await?;
                let _changing = configs.changing.lock().await;
                let config = if self == Self::Import {
                    ConfigKv::parse(&text)
                } else {
                    let mut config = files.load().map_err(S3Error::internal_error)?;
                    if self == Self::Set {
                        config.set(&text)
                    } else {
                        config.delete(&text)
                    }
                    .map(|()| config)
                }
                .map_err(config_error)?;
                keep(configs, &config)?;
                if self != Self::Delete {
                    files.record(&text).map_err(S3Error::internal_error)?;
                }
                Ok(S3Response::new(Body::empty()))
            }
            Self::Help => unreachable!("answered above"),
        }
    }
}

/// Checks `config` as the next start would read it, then keeps it.
fn keep(configs: &Configs, config: &ConfigKv) -> S3Result<()> {
    (configs.settings.check)(config).map_err(|message| {
        admin::error(StatusCode::BAD_REQUEST, "XMinioAdminConfigBadJSON", message)
    })?;
    configs
        .settings
        .files
        .save(config)
        .map_err(S3Error::internal_error)
}

/// The value of query parameter `name`, if it's there.
fn param(req: &S3Request<Body>, name: &str) -> Option<String> {
    query(req)
        .into_iter()
        .find_map(|(n, v)| (n == name).then_some(v))
}

/// The change `?restoreId=` names.
fn restore_id(req: &S3Request<Body>) -> S3Result<String> {
    param(req, "restoreId")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            admin::error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Name the change with ?restoreId=.",
            )
        })
}

fn no_change(id: &str) -> S3Error {
    admin::error(
        StatusCode::NOT_FOUND,
        "XMinioConfigNotFoundError",
        format!("There's no change {id} to put back."),
    )
}

/// The value of a `MinIO` variable this server was started with, which `get` and
/// `export` list as comments.
fn variable(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// `MinIO`'s answer to a configuration TeiFS can't take.
fn config_error(err: ConfigError) -> S3Error {
    match err {
        ConfigError::NotFound(message) => {
            admin::error(StatusCode::NOT_FOUND, "XMinioConfigNotFoundError", message)
        }
        ConfigError::Invalid(message) => {
            admin::error(StatusCode::BAD_REQUEST, "XMinioConfigError", message)
        }
    }
}

/// The request's configuration text, decrypted with the caller's secret key.
async fn decrypted(req: &mut S3Request<Body>) -> S3Result<Zeroizing<String>> {
    let too_large = || {
        admin::error(
            StatusCode::BAD_REQUEST,
            "XMinioAdminConfigTooLarge",
            format!("A configuration is at most {MAX_BODY_BYTES} bytes, encrypted."),
        )
    };
    let length = req
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if length.is_none_or(|length| length > MAX_BODY_BYTES) {
        return Err(too_large());
    }
    let secret = caller_secret(req)?;
    let body = signed_body(req, MAX_BODY_BYTES).await.map_err(s3_refusal)?;
    let bad = || {
        admin::error(
            StatusCode::BAD_REQUEST,
            "XMinioAdminConfigBadJSON",
            "The configuration isn't encrypted with the secret key of the access key that \
             signed it.",
        )
    };
    // Argon2id takes a while and 64 MiB: off the async workers.
    let plain = tokio::task::spawn_blocking(move || teifs_crypto::madmin::decrypt(&secret, &body))
        .await
        .map_err(S3Error::internal_error)?
        .map_err(|_| bad())?;
    std::str::from_utf8(&plain)
        .map(|text| Zeroizing::new(text.to_owned()))
        .map_err(|_| bad())
}

/// A change, as madmin's `ConfigHistoryEntry`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryEntry {
    restore_id: String,
    create_time: String,
    data: String,
}

impl From<ConfigChange> for HistoryEntry {
    fn from(change: ConfigChange) -> Self {
        Self {
            restore_id: change.id,
            create_time: rfc3339(change.created),
            data: change.text,
        }
    }
}

fn rfc3339(at: SystemTime) -> String {
    OffsetDateTime::from(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}
