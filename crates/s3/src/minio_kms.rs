//! `MinIO`'s KMS API (`/minio/kms/v1/…`: `mc admin kms key create|list|status`) and
//! the KMS calls of its admin API (`/minio/admin/v3/kms/…`, which older clients use),
//! on the server's KMS.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::Serialize;
use teifs_crypto::{Context, CryptoError, DEFAULT_KEY, Kms, LATENCY_BUCKETS};
use teifs_iam::Identity;
use teifs_types::admin::{KmsConfig, ServerConfig};

use crate::{admin, minio_iam::query, routes::Routes};

/// How long the status waits for the KMS.
const CHECK: Duration = Duration::from_secs(10);

/// A call on the KMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// The KMS's endpoints and default key.
    Status,
    /// What its calls came to.
    Metrics,
    /// The calls TeiFS serves on it.
    Apis,
    /// Its version.
    Version,
    /// Creates `?key-id=`.
    CreateKey,
    /// Its keys whose names start with `?pattern=`.
    ListKeys,
    /// Whether `?key-id=` (the default key by default) seals and unseals.
    KeyStatus,
}

impl Call {
    /// The call's name, in metrics and the audit log (`MinIO`'s).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Status => "KMSStatus",
            Self::Metrics => "KMSMetrics",
            Self::Apis => "KMSAPIs",
            Self::Version => "KMSVersion",
            Self::CreateKey => "KMSCreateKey",
            Self::ListKeys => "KMSListKeys",
            Self::KeyStatus => "KMSKeyStatus",
        }
    }

    /// Calls it.
    pub(crate) async fn call(
        self,
        routes: &Routes,
        req: &S3Request<Body>,
        (identity, context): (&Identity, &teifs_policy::Context),
    ) -> S3Result<S3Response<Body>> {
        let kms = configured(routes.store.kms())?;
        match self {
            Self::Status => Ok(admin::json(&status(kms, routes.config.as_deref()).await)),
            Self::Metrics => Ok(admin::json(&metrics(routes))),
            Self::Apis => Ok(admin::json(&apis())),
            Self::Version => Ok(admin::json(&Version {
                version: env!("CARGO_PKG_VERSION"),
            })),
            Self::CreateKey => {
                let name = named_key(req, None)?;
                kms.create_key(&name)
                    .await
                    .map_err(|e| failed(&e, "kms:KeyCreationFailed"))?;
                Ok(S3Response::new(Body::empty()))
            }
            Self::ListKeys => {
                let pattern = query(req)
                    .into_iter()
                    .find_map(|(n, v)| (n == "pattern").then_some(v))
                    .unwrap_or_default();
                // As `MinIO`'s, `*` is every key, and anything else a prefix.
                let prefix = if pattern == "*" { "" } else { &pattern };
                let keys = kms
                    .keys()
                    .await
                    .map_err(|e| failed(&e, "kms:KeyListingFailed"))?;
                let listed: Vec<KeyInfo> = keys
                    .into_iter()
                    .filter(|key| key.name.starts_with(prefix))
                    .filter(|key| {
                        identity
                            .decide(
                                context,
                                "kms:ListKeys",
                                &teifs_policy::minio::kms_key_arn(&key.name),
                                None,
                            )
                            .is_allowed()
                    })
                    .map(|key| KeyInfo {
                        created_at: rfc3339(key.created_ms),
                        created_by: String::new(),
                        name: key.name,
                    })
                    .collect();
                Ok(admin::json(&listed))
            }
            Self::KeyStatus => {
                let name = named_key(req, Some(&default_key(routes.config.as_deref())))?;
                Ok(admin::json(&key_status(kms, name).await))
            }
        }
    }
}

/// The KMS, or `MinIO`'s answer when the server has none.
fn configured(kms: Option<&dyn Kms>) -> S3Result<&dyn Kms> {
    kms.ok_or_else(|| {
        admin::error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "The server has no KMS.",
        )
    })
}

/// The name of the server's default key.
pub(crate) fn default_key(config: Option<&ServerConfig>) -> String {
    config
        .and_then(|c| c.kms_default_key.clone())
        .unwrap_or_else(|| DEFAULT_KEY.to_owned())
}

/// The key `?key-id=` names; `default` when it names none, if there is one.
pub(crate) fn named_key(req: &S3Request<Body>, default: Option<&str>) -> S3Result<String> {
    let named = query(req)
        .into_iter()
        .find_map(|(n, v)| (n == "key-id" && !v.is_empty()).then_some(v));
    named.or_else(|| default.map(str::to_owned)).ok_or_else(|| {
        admin::error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Name the key with ?key-id=.",
        )
    })
}

/// `MinIO`'s error for what the KMS refused or failed: `failure` names a failure.
fn failed(err: &CryptoError, failure: &str) -> S3Error {
    let (status, code) = match err {
        CryptoError::NoSuchKey(_) => (StatusCode::NOT_FOUND, "kms:KeyNotFound"),
        CryptoError::KeyExists(_) => (StatusCode::CONFLICT, "kms:KeyAlreadyExists"),
        CryptoError::InvalidKeyName => (StatusCode::BAD_REQUEST, "kms:InvalidKeyName"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, failure),
    };
    admin::error(status, code, err.to_string())
}

/// `madmin.KMSStatus`.
#[derive(Serialize)]
struct Status {
    name: &'static str,
    #[serde(rename = "default-key-id")]
    default_key_id: String,
    /// Each endpoint's state: `online` or `offline`.
    endpoints: BTreeMap<String, &'static str>,
    state: State,
}

/// `madmin.KMSState`, which `MinIO` names by its Go fields.
#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct State {
    version: String,
    /// In nanoseconds, as Go's durations.
    key_store_latency: u64,
    key_store_reachable: bool,
    keystore_available: bool,
    #[serde(rename = "OS")]
    os: String,
    arch: String,
    up_time: u64,
    #[serde(rename = "CPUs")]
    cpus: u64,
    #[serde(rename = "UsableCPUs")]
    usable_cpus: u64,
    heap_alloc: u64,
    stack_alloc: u64,
}

/// What kind of KMS the server has, and where it answers.
pub(crate) fn kind(config: Option<&ServerConfig>) -> (&'static str, Vec<String>) {
    match config.map(|c| &c.kms) {
        Some(KmsConfig::Transit { address }) => ("Vault transit", vec![address.clone()]),
        Some(KmsConfig::Kes { endpoints, .. }) => ("KES", endpoints.clone()),
        Some(KmsConfig::AwsKms { region }) => {
            ("AWS KMS", vec![format!("kms.{region}.amazonaws.com")])
        }
        Some(KmsConfig::Keyring { .. }) | None => ("TeiFS keyring", vec!["local".to_owned()]),
    }
}

/// The KMS's state, with one check of whether it answers.
async fn status(kms: &dyn Kms, config: Option<&ServerConfig>) -> Status {
    let (name, endpoints) = kind(config);
    let started = Instant::now();
    let reachable = match tokio::time::timeout(CHECK, kms.keys()).await {
        Ok(Ok(_)) => true,
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "the KMS didn't answer");
            false
        }
        Err(_) => {
            tracing::warn!("the KMS didn't answer in time");
            false
        }
    };
    let latency = started.elapsed();
    let state = if reachable { "online" } else { "offline" };
    Status {
        name,
        default_key_id: default_key(config),
        endpoints: endpoints.into_iter().map(|e| (e, state)).collect(),
        state: State {
            key_store_latency: u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX),
            key_store_reachable: reachable,
            keystore_available: reachable,
            ..State::default()
        },
    }
}

/// `MinIO`'s KMS metrics.
#[derive(Serialize)]
struct Metrics {
    #[serde(rename = "kms_req_success")]
    succeeded: u64,
    #[serde(rename = "kms_req_error")]
    refused: u64,
    #[serde(rename = "kms_req_failure")]
    failed: u64,
    /// For each bucket's upper bound, in nanoseconds, the calls that took less.
    #[serde(rename = "kms_resp_time")]
    latency: BTreeMap<String, u64>,
}

fn metrics(routes: &Routes) -> Metrics {
    let counted = routes
        .store
        .kms_metrics()
        .unwrap_or(teifs_crypto::KmsMetrics {
            ok: 0,
            errors: 0,
            failures: 0,
            latency: [0; LATENCY_BUCKETS.len()],
        });
    Metrics {
        succeeded: counted.ok,
        refused: counted.errors,
        failed: counted.failures,
        latency: LATENCY_BUCKETS
            .iter()
            .zip(counted.latency)
            .map(|(bound, n)| (bound.as_nanos().to_string(), n))
            .collect(),
    }
}

/// `madmin.KMSAPI`, which `MinIO` names by its Go fields.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Api {
    method: &'static str,
    path: &'static str,
    max_body: u64,
    timeout: u64,
}

/// The KMS API's calls TeiFS serves.
fn apis() -> Vec<Api> {
    crate::routes::endpoints()
        .filter(|e| e.path.starts_with(crate::routes::MINIO_KMS))
        .map(|e| Api {
            method: e.method,
            path: e.path,
            max_body: 0,
            timeout: 0,
        })
        .collect()
}

#[derive(Serialize)]
struct Version {
    version: &'static str,
}

/// `madmin.KMSKeyInfo`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyInfo {
    created_at: String,
    created_by: String,
    name: String,
}

fn rfc3339(ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "0001-01-01T00:00:00Z".to_owned())
}

/// `madmin.KMSKeyStatus`.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct KeyStatus {
    #[serde(rename = "key-id")]
    key_id: String,
    #[serde(rename = "encryption-error", skip_serializing_if = "Option::is_none")]
    encryption_error: Option<String>,
    #[serde(rename = "decryption-error", skip_serializing_if = "Option::is_none")]
    decryption_error: Option<String>,
}

/// Whether `name` seals a new data key and opens the seal again, as `MinIO` checks a
/// key: what fails is in the answer, not an error.
async fn key_status(kms: &dyn Kms, name: String) -> KeyStatus {
    let context = Context::default().with("MinIO admin API", "KMSKeyStatusHandler");
    let mut status = KeyStatus {
        key_id: name,
        encryption_error: None,
        decryption_error: None,
    };
    match kms.generate(Some(&status.key_id), &context).await {
        Err(err) => status.encryption_error = Some(err.to_string()),
        Ok((data_key, sealed)) => match kms.unseal(&sealed, &context).await {
            Err(err) => status.decryption_error = Some(err.to_string()),
            Ok(opened) if opened != data_key => {
                status.decryption_error =
                    Some("the data key that was sealed isn't the one unsealed".to_owned());
            }
            Ok(_) => {}
        },
    }
    status
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn a_server_without_a_kms_says_so() {
        let err = configured(None).unwrap_err();
        assert_eq!(err.code().as_str(), "NotImplemented");
        assert_eq!(err.status_code(), Some(StatusCode::NOT_IMPLEMENTED));
    }

    #[test]
    fn errors_are_minio_s() {
        for (err, status, code) in [
            (
                CryptoError::NoSuchKey("k".to_owned()),
                StatusCode::NOT_FOUND,
                "kms:KeyNotFound",
            ),
            (
                CryptoError::KeyExists("k".to_owned()),
                StatusCode::CONFLICT,
                "kms:KeyAlreadyExists",
            ),
            (
                CryptoError::InvalidKeyName,
                StatusCode::BAD_REQUEST,
                "kms:InvalidKeyName",
            ),
            (
                CryptoError::Kms("down".to_owned()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "kms:Failed",
            ),
        ] {
            let failed = failed(&err, "kms:Failed");
            assert_eq!(failed.status_code(), Some(status));
            assert_eq!(failed.code().as_str(), code);
            assert_eq!(failed.message(), Some(err.to_string().as_str()));
        }
    }

    /// A KMS whose seals don't open.
    #[derive(Debug)]
    struct Broken(teifs_crypto::LocalKms);

    #[async_trait::async_trait]
    impl Kms for Broken {
        async fn seal(
            &self,
            key: Option<&str>,
            context: &Context,
            data_key: &teifs_crypto::DataKey,
        ) -> teifs_crypto::Result<teifs_crypto::SealedKey> {
            self.0.seal(key, context, data_key).await
        }
        async fn unseal(
            &self,
            sealed: &teifs_crypto::SealedKey,
            _: &Context,
        ) -> teifs_crypto::Result<teifs_crypto::DataKey> {
            self.0.unseal(sealed, &Context::default()).await
        }
        async fn keys(&self) -> teifs_crypto::Result<Vec<teifs_crypto::KeyInfo>> {
            self.0.keys().await
        }
        async fn create_key(&self, name: &str) -> teifs_crypto::Result<teifs_crypto::KeyInfo> {
            self.0.create_key(name).await
        }
        async fn rotate_key(&self, name: &str) -> teifs_crypto::Result<teifs_crypto::KeyInfo> {
            self.0.rotate_key(name).await
        }
    }

    #[tokio::test]
    async fn a_key_s_status_says_what_failed() {
        let dir = tempfile::tempdir().unwrap();
        let keys = || teifs_crypto::LocalKms::open(dir.path().join("keys")).unwrap();
        let kms: Arc<dyn Kms> = Arc::new(keys());
        let ok = key_status(kms.as_ref(), DEFAULT_KEY.to_owned()).await;
        assert_eq!((ok.encryption_error, ok.decryption_error), (None, None));
        let missing = key_status(kms.as_ref(), "missing".to_owned()).await;
        assert!(missing.encryption_error.unwrap().contains("missing"));
        assert_eq!(missing.decryption_error, None);
        let broken = key_status(&Broken(keys()), DEFAULT_KEY.to_owned()).await;
        assert_eq!(broken.encryption_error, None);
        assert!(broken.decryption_error.is_some());
    }

    #[test]
    fn the_status_names_the_kms_and_where_it_answers() {
        assert_eq!(kind(None), ("TeiFS keyring", vec!["local".to_owned()]));
        assert_eq!(default_key(None), DEFAULT_KEY);
    }
}
