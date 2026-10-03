//! `MinIO`'s bucket replication calls. Its resync (`mc replicate resync
//! start|status|cancel`): `?replication-reset` (`PUT`), `?replication-reset-status`
//! (`GET`) and `?replication-reset-cancel` (`PUT`), decided with
//! `s3:ResetBucketReplicationState`. A resync sends every version from before it that the
//! rules send to one destination there again ([`Store::start_resync`]), as when a target
//! lost what it had. And its replication metrics (`mc replicate status`):
//! `?replication-metrics` (`GET`; `=2` for the second version,
//! [`crate::minio_replication_metrics`]), decided with `s3:GetReplicationConfiguration`.

use std::time::Duration;

use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use s3s::{Body, S3Error, S3ErrorCode, S3Response, S3Result};
use serde::Serialize;
use teifs_store::Store;
use teifs_types::replication::ReplicationResync;
use tokio::sync::Notify;

use crate::{
    errors::StoreResultExt,
    minio_kms::rfc3339,
    replication,
    replicator::{Stats, Unready},
};

/// What Go writes for a time never set.
const NEVER: &str = "0001-01-01T00:00:00Z";

/// One of the resync calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// Starts a resync.
    Start,
    /// Where resyncs stand.
    Status,
    /// Cancels the resync going on.
    Cancel,
    /// What replication did (`true`: the second version).
    Metrics(bool),
    /// Whether replication can work (`MinIO`'s `ValidateBucketReplicationCreds`).
    Check,
}

impl Call {
    /// The call a request is, and the bucket it's on; `None` for any other request.
    pub(crate) fn of(
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        domains: &[String],
    ) -> Option<(Self, String)> {
        let query = uri.query()?;
        let call = form_urlencoded::parse(query.as_bytes()).find_map(|(name, value)| {
            match (method, name.as_ref()) {
                (&Method::PUT, "replication-reset") => Some(Self::Start),
                (&Method::GET, "replication-reset-status") => Some(Self::Status),
                (&Method::PUT, "replication-reset-cancel") => Some(Self::Cancel),
                (&Method::GET, "replication-metrics") => Some(Self::Metrics(value == "2")),
                (&Method::GET, "replication-check") => Some(Self::Check),
                _ => None,
            }
        })?;
        let path = uri.path();
        if let Some(bucket) = crate::admin::virtual_bucket(headers, domains) {
            return (path == "/").then(|| (call, bucket.to_owned()));
        }
        let name = path.strip_prefix('/')?;
        let name = name.strip_suffix('/').unwrap_or(name);
        (!name.is_empty() && !name.contains('/')).then(|| (call, name.to_owned()))
    }

    /// Its name, in metrics and the audit log (`MinIO`'s).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Start => "ResetBucketReplicationStart",
            Self::Status => "ResetBucketReplicationStatus",
            Self::Cancel => "ResetBucketReplicationCancel",
            Self::Metrics(false) => "GetBucketReplicationMetrics",
            Self::Metrics(true) => "GetBucketReplicationMetricsV2",
            Self::Check => "ValidateBucketReplicationCreds",
        }
    }

    /// The action it needs on the bucket.
    pub(crate) const fn action(self) -> &'static str {
        match self {
            Self::Start | Self::Status | Self::Cancel => "s3:ResetBucketReplicationState",
            Self::Metrics(_) | Self::Check => "s3:GetReplicationConfiguration",
        }
    }
}

/// What the calls act on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Replication<'a> {
    pub(crate) store: &'a Store,
    /// Wakes the replication job (a resync started).
    pub(crate) wake: &'a Notify,
    /// What replication did.
    pub(crate) stats: &'a Stats,
    /// The server's name, as the request reached it.
    pub(crate) node: &'a str,
}

/// `MinIO`'s `ResyncTargetsInfo`.
#[derive(Debug, Serialize)]
struct Targets {
    #[serde(rename = "target", skip_serializing_if = "Vec::is_empty")]
    targets: Vec<Target>,
}

/// `MinIO`'s `ResyncTarget`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Target {
    arn: String,
    #[serde(rename = "resetid")]
    reset_id: String,
    start_time: String,
    end_time: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    resync_status: &'static str,
    #[serde(rename = "completedReplicationSize", skip_serializing_if = "is_zero")]
    replicated_size: u64,
    #[serde(rename = "failedReplicationSize", skip_serializing_if = "is_zero")]
    failed_size: u64,
    #[serde(rename = "failedReplicationCount", skip_serializing_if = "is_zero")]
    failed_count: u64,
    #[serde(rename = "replicationCount", skip_serializing_if = "is_zero")]
    replicated_count: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    bucket: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    object: String,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes a reference"
)]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Target {
    /// A resync just started, as `MinIO` answers its start.
    fn started(arn: String, reset_id: String) -> Self {
        Self {
            arn,
            reset_id,
            start_time: NEVER.to_owned(),
            end_time: NEVER.to_owned(),
            resync_status: "",
            replicated_size: 0,
            failed_size: 0,
            failed_count: 0,
            replicated_count: 0,
            bucket: String::new(),
            object: String::new(),
        }
    }

    fn of(bucket: &str, arn: String, resync: ReplicationResync) -> Self {
        Self {
            arn,
            reset_id: resync.id,
            start_time: rfc3339(resync.started_ms),
            end_time: rfc3339(resync.updated_ms),
            resync_status: resync.status.as_minio(),
            replicated_size: resync.replicated.1,
            failed_size: resync.failed.1,
            failed_count: resync.failed.0,
            replicated_count: resync.replicated.0,
            bucket: resync
                .last_key
                .as_ref()
                .map(|_| bucket.to_owned())
                .unwrap_or_default(),
            object: resync.last_key.unwrap_or_default(),
        }
    }
}

/// Answers `call` on `bucket` with the request's `query`.
pub(crate) async fn serve(
    replication: Replication<'_>,
    (call, bucket): (Call, &str),
    query: &str,
) -> S3Result<S3Response<Body>> {
    let Replication { store, wake, .. } = replication;
    let param = |name: &str| {
        form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
    };
    let config = async || {
        store
            .bucket_replication(bucket)
            .await
            .s3()?
            .ok_or_else(replication::not_found)
    };
    match call {
        Call::Start => {
            let config = config().await?;
            let arn = match param("arn") {
                Some(arn) => arn,
                None => only_destination(&config)?,
            };
            match config.resyncs(&arn) {
                None => return Err(no_target()),
                Some(false) => return Err(no_existing_objects()),
                Some(true) => {}
            }
            let older = match param("older-than") {
                Some(text) => teifs_types::config_kv::go_duration(&text)
                    .map_err(|message| invalid_argument(&message))?,
                None => Duration::ZERO,
            };
            let before_ms =
                now_ms().saturating_sub(i64::try_from(older.as_millis()).unwrap_or(i64::MAX));
            let id = param("reset-id").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let resync = store
                .start_resync(bucket, &arn, id, before_ms)
                .await
                .map_err(|err| match err {
                    teifs_store::StoreError::InvalidRequest(message) => bad_request(message),
                    err => crate::errors::from_store(err),
                })?;
            wake.notify_one();
            Ok(json(&Targets {
                targets: vec![Target::started(arn, resync.id)],
            }))
        }
        Call::Status => {
            config().await?;
            let arn = param("arn");
            let targets = store
                .resyncs(bucket)
                .await
                .s3()?
                .into_iter()
                .filter(|(of, _)| arn.as_ref().is_none_or(|arn| arn == of))
                .map(|(of, resync)| Target::of(bucket, of, resync))
                .collect();
            Ok(json(&Targets { targets }))
        }
        Call::Cancel => {
            let config = config().await?;
            let arn = match param("arn") {
                Some(arn) => arn,
                None => only_destination(&config)?,
            };
            let id = store
                .cancel_resync(bucket, &arn)
                .await
                .s3()?
                .ok_or_else(|| bad_request("no resync of this destination is going on"))?;
            Ok(S3Response::new(Body::from(id)))
        }
        Call::Metrics(v2) => {
            let config = config().await?;
            let metrics = crate::minio_replication_metrics::Metrics::of(
                replication.stats,
                bucket,
                &config,
                replication.node,
            );
            Ok(if v2 {
                json(&metrics)
            } else {
                json(&metrics.current)
            })
        }
        Call::Check => {
            crate::replicator::check(store, bucket)
                .await
                .map_err(unready)?;
            Ok(S3Response::new(Body::empty()))
        }
    }
}

/// What `MinIO` answers when replication can't work.
fn unready(why: Unready) -> S3Error {
    match why {
        Unready::NotVersioned => error(
            "InvalidRequest",
            "Versioning must be 'Enabled' on the bucket to apply a replication configuration",
            StatusCode::BAD_REQUEST,
        ),
        Unready::NoConfig => replication::not_found(),
        Unready::StaleTarget(rule) => error(
            "XMinioAdminRemoteTargetNotFoundError",
            &format!("replication config with rule ID {rule} has a stale target"),
            StatusCode::NOT_FOUND,
        ),
        Unready::TargetNotVersioned(bucket) => error(
            "RemoteTargetNotVersionedError",
            &format!("target bucket {bucket} is not versioned"),
            StatusCode::BAD_REQUEST,
        ),
        Unready::TargetUnlocked(bucket) => error(
            "ReplicationDestinationMissingLockError",
            &format!("target bucket {bucket} is not object lock enabled"),
            StatusCode::BAD_REQUEST,
        ),
        Unready::Invalid(why) => error("InvalidRequest", &why, StatusCode::BAD_REQUEST),
    }
}

/// The one destination of `config`'s rules, when no ARN is given.
fn only_destination(config: &teifs_types::replication::ReplicationConfig) -> S3Result<String> {
    let mut arns: Vec<&str> = config
        .rules
        .iter()
        .map(|rule| rule.destination.bucket.as_str())
        .collect();
    arns.dedup();
    match arns[..] {
        [arn] => Ok(arn.to_owned()),
        _ => Err(bad_request("ARN should be specified for replication reset")),
    }
}

fn json(value: &impl Serialize) -> S3Response<Body> {
    let mut response = S3Response::new(Body::from(
        serde_json::to_string(value).expect("a resync serializes"),
    ));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn error(code: &str, message: &str, status: StatusCode) -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom(code.to_owned().into()),
        message.to_owned(),
    );
    err.set_status_code(status);
    err
}

fn bad_request(message: &str) -> S3Error {
    error("BadRequest", message, StatusCode::BAD_REQUEST)
}

fn no_target() -> S3Error {
    error(
        "XMinioAdminRemoteTargetNotFoundError",
        "The remote target does not exist",
        StatusCode::NOT_FOUND,
    )
}

fn no_existing_objects() -> S3Error {
    error(
        "XMinioReplicationNoExistingObjects",
        "No matching ExistingObjects rule enabled",
        StatusCode::BAD_REQUEST,
    )
}

fn invalid_argument(message: &str) -> S3Error {
    let mut err = S3Error::with_message(S3ErrorCode::InvalidArgument, message.to_owned());
    err.set_status_code(StatusCode::BAD_REQUEST);
    err
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(text: &str) -> Uri {
        text.parse().unwrap()
    }

    #[test]
    fn calls_are_told_by_method_and_query() {
        let none = HeaderMap::new();
        let of = |method: Method, text: &str| Call::of(&method, &uri(text), &none, &[]);
        assert_eq!(
            of(Method::PUT, "/b?replication-reset&arn=x"),
            Some((Call::Start, "b".to_owned()))
        );
        assert_eq!(
            of(Method::GET, "/b/?replication-reset-status="),
            Some((Call::Status, "b".to_owned()))
        );
        assert_eq!(
            of(Method::PUT, "/b?replication-reset-cancel"),
            Some((Call::Cancel, "b".to_owned()))
        );
        // Not with another method, on an object, or on no bucket.
        assert_eq!(of(Method::GET, "/b?replication-reset"), None);
        assert_eq!(of(Method::PUT, "/b/key?replication-reset"), None);
        assert_eq!(of(Method::PUT, "/?replication-reset"), None);
        assert_eq!(of(Method::PUT, "/b?replication"), None);
        assert_eq!(
            of(Method::GET, "/b?replication-check"),
            Some((Call::Check, "b".to_owned()))
        );
        assert_eq!(of(Method::PUT, "/b?replication-check"), None);
    }

    #[test]
    fn started_targets_are_written_as_minio_writes_them() {
        let started = Targets {
            targets: vec![Target::started(
                "arn:minio:replication::x:copy".to_owned(),
                "r1".to_owned(),
            )],
        };
        assert_eq!(
            serde_json::to_string(&started).unwrap(),
            r#"{"target":[{"arn":"arn:minio:replication::x:copy","resetid":"r1","startTime":"0001-01-01T00:00:00Z","endTime":"0001-01-01T00:00:00Z"}]}"#
        );
        assert_eq!(
            serde_json::to_string(&Targets { targets: vec![] }).unwrap(),
            "{}"
        );
    }
}
