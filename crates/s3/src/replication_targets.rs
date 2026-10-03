//! Replication targets through `MinIO`'s admin API (madmin-go's `SetRemoteTarget`,
//! `ListRemoteTargets` and `RemoveRemoteTarget`, which `mc replicate` calls): other S3
//! services' buckets a bucket replicates to, whose ARNs its replication rules name. The secret keys come encrypted with the caller's, are kept sealed, and are
//! never answered.

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::{Deserialize, Serialize};
use teifs_store::{NewTarget, Store, StoreError, TargetSecrets};
use teifs_types::replication::RemoteTarget;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    admin,
    errors::{StoreResultExt, from_store},
    minio_iam::{decrypted, flag, invalid, query, required},
};

/// The only kind of target there is.
const REPLICATION: &str = "replication";

/// Nanoseconds in a second: `MinIO` sends durations as Go's, in nanoseconds.
const NANOS: u64 = 1_000_000_000;

/// A target as `MinIO`'s admin API takes and answers it (`madmin.BucketTarget`).
#[derive(Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "madmin's shape")]
struct BucketTarget {
    #[serde(default, rename = "sourcebucket")]
    source_bucket: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    credentials: Option<Credentials>,
    #[serde(default, rename = "targetbucket")]
    target_bucket: String,
    #[serde(default)]
    secure: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    arn: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    region: String,
    #[serde(default, rename = "bandwidthlimit", skip_serializing_if = "is_zero")]
    bandwidth_limit: i64,
    #[serde(default, rename = "replicationSync")]
    sync: bool,
    #[serde(
        default,
        rename = "storageclass",
        skip_serializing_if = "String::is_empty"
    )]
    storage_class: String,
    /// Nanoseconds.
    #[serde(
        default,
        rename = "healthCheckDuration",
        skip_serializing_if = "is_zero"
    )]
    health_check: i64,
    #[serde(default, rename = "disableProxy")]
    disable_proxy: bool,
    #[serde(default, rename = "insecureTLS")]
    insecure_tls: bool,
    #[serde(default)]
    edge: bool,
    /// Nanoseconds it's been unreachable in all.
    #[serde(default, rename = "totalDowntime")]
    total_downtime: u64,
    /// When it was last reached (Go's zero time if never).
    #[serde(default, rename = "lastOnline")]
    last_online: String,
    #[serde(default, rename = "isOnline")]
    online: bool,
    #[serde(default)]
    latency: Latency,
}

/// `madmin.LatencyStat`, in nanoseconds.
#[derive(Default, Serialize, Deserialize)]
struct Latency {
    #[serde(default)]
    curr: u64,
    #[serde(default)]
    avg: u64,
    #[serde(default)]
    max: u64,
}

impl BucketTarget {
    /// With how its replication went, from `stats`: online unless the last attempt
    /// couldn't reach it.
    fn with_health(mut self, stats: &crate::replicator::Stats) -> Self {
        let target = stats
            .bucket(&self.source_bucket)
            .targets
            .remove(&self.arn)
            .unwrap_or_default();
        let nanos = |d: std::time::Duration| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.online = target.online != Some(false);
        self.total_downtime = nanos(target.total_downtime(std::time::Instant::now()));
        self.last_online = target.last_online.map_or_else(
            || "0001-01-01T00:00:00Z".to_owned(),
            |at| crate::minio_kms::rfc3339(crate::admin::millis(at)),
        );
        let (curr, avg, max) = target.latency();
        self.latency = Latency {
            curr: nanos(curr),
            avg: nanos(avg),
            max: nanos(max),
        };
        self
    }
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// `madmin.Credentials`: the secrets only ever come in.
#[derive(Default, Serialize, Deserialize)]
struct Credentials {
    #[serde(default, rename = "accessKey")]
    access_key: String,
    #[serde(default, rename = "secretKey", skip_serializing)]
    secret_key: String,
    #[serde(default, rename = "sessionToken", skip_serializing)]
    session_token: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.secret_key.zeroize();
        self.session_token.zeroize();
    }
}

impl BucketTarget {
    fn from_target(target: RemoteTarget) -> Self {
        Self {
            source_bucket: target.source_bucket,
            endpoint: target.endpoint,
            credentials: Some(Credentials {
                access_key: target.access_key,
                secret_key: String::new(),
                session_token: String::new(),
            }),
            target_bucket: target.target_bucket,
            secure: target.secure,
            arn: target.arn,
            kind: REPLICATION.to_owned(),
            region: target.region,
            bandwidth_limit: i64::try_from(target.bandwidth_limit).unwrap_or(i64::MAX),
            sync: target.sync,
            storage_class: target.storage_class,
            health_check: i64::try_from(target.health_check_secs.saturating_mul(NANOS))
                .unwrap_or(i64::MAX),
            ..Self::default()
        }
    }
}

/// `MinIO`'s answer for a target that isn't there.
fn not_found() -> S3Error {
    admin::error(
        StatusCode::NOT_FOUND,
        "XMinioAdminRemoteTargetNotFoundError",
        "The remote target does not exist",
    )
}

/// What `mc` is told when the drive has no KMS to seal the secret key with.
fn store_error(err: StoreError) -> S3Error {
    match err {
        StoreError::NoKms => admin::error(
            StatusCode::NOT_IMPLEMENTED,
            "XMinioAdminNoKMS",
            "A replication target's secret key is kept sealed by the KMS, and none is \
             configured",
        ),
        err => from_store(err),
    }
}

/// `PUT set-remote-target?bucket=NAME`: adds a target to the bucket, or with
/// `&update=true` changes the one the body's `arn` names (its secret key only with
/// `&creds=true`), answering its ARN as a JSON string.
pub(crate) async fn set(
    store: &Store,
    bucket: &str,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    store.head_bucket(bucket).await.s3()?;
    let update = flag(&req, "update");
    let new_secret = !update || flag(&req, "creds");
    let given: BucketTarget = decrypted(&mut req).await?;
    let new = read(bucket, given, update, new_secret)?;
    let arn = store
        .add_replication_target(new)
        .await
        .map_err(|err| match err {
            StoreError::InvalidRequest("no such replication target") => not_found(),
            StoreError::InvalidRequest(why) => invalid(why),
            err => store_error(err),
        })?;
    Ok(admin::json(&arn))
}

/// The target a body describes, checked.
fn read(bucket: &str, given: BucketTarget, update: bool, new_secret: bool) -> S3Result<NewTarget> {
    if !given.kind.is_empty() && given.kind != REPLICATION {
        return Err(invalid(format!(
            "Only replication targets are kept, not {}",
            given.kind
        )));
    }
    if !given.source_bucket.is_empty() && given.source_bucket != bucket {
        return Err(invalid("The target's sourcebucket isn't the bucket named"));
    }
    if given.endpoint.is_empty() || given.endpoint.contains('/') {
        return Err(invalid(
            "A target's endpoint is its host and port, without a scheme or a path",
        ));
    }
    if given.target_bucket.is_empty() {
        return Err(invalid("A target needs its targetbucket"));
    }
    if given.insecure_tls {
        return Err(invalid(
            "Targets' certificates are always checked: insecureTLS isn't taken",
        ));
    }
    let arn = if update {
        if given.arn.is_empty() {
            return Err(invalid("A change of a target needs its arn"));
        }
        Some(given.arn)
    } else {
        None
    };
    let mut credentials = given.credentials.unwrap_or_default();
    if credentials.access_key.is_empty() {
        return Err(invalid("A target needs an access key"));
    }
    let secrets = if new_secret {
        if credentials.secret_key.is_empty() {
            return Err(invalid("A target needs a secret key"));
        }
        Some(TargetSecrets {
            session_token: (!credentials.session_token.is_empty())
                .then(|| Zeroizing::new(std::mem::take(&mut credentials.session_token))),
            secret_key: Zeroizing::new(std::mem::take(&mut credentials.secret_key)),
        })
    } else {
        None
    };
    let bandwidth_limit = u64::try_from(given.bandwidth_limit)
        .map_err(|_| invalid("A target's bandwidthlimit can't be below 0"))?;
    let health_check = u64::try_from(given.health_check)
        .map_err(|_| invalid("A target's healthCheckDuration can't be below 0"))?;
    Ok(NewTarget {
        arn,
        source_bucket: bucket.to_owned(),
        endpoint: given.endpoint,
        secure: given.secure,
        target_bucket: given.target_bucket,
        region: given.region,
        access_key: std::mem::take(&mut credentials.access_key),
        secrets,
        storage_class: given.storage_class,
        bandwidth_limit,
        sync: given.sync,
        health_check_secs: health_check / NANOS,
    })
}

/// `GET list-remote-targets?bucket=NAME[&type=replication]`: the bucket's targets, as
/// `MinIO` answers them, without their secret keys.
pub(crate) async fn list(
    (store, stats): (&Store, &crate::replicator::Stats),
    bucket: &str,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let kind = query(req)
        .into_iter()
        .find(|(n, _)| n == "type")
        .map(|(_, v)| v)
        .unwrap_or_default();
    let targets = store.replication_targets(Some(bucket)).await.s3()?;
    let answer: Vec<BucketTarget> = if kind.is_empty() || kind == REPLICATION {
        targets
            .into_iter()
            .map(|target| BucketTarget::from_target(target).with_health(stats))
            .collect()
    } else {
        Vec::new()
    };
    Ok(admin::json(&answer))
}

/// `DELETE remove-remote-target?bucket=NAME&arn=ARN`: removes the target, unless a
/// replication rule still names it.
pub(crate) async fn remove(
    store: &Store,
    bucket: &str,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let arn = required(req, "arn")?;
    let targets = store.replication_targets(Some(bucket)).await.s3()?;
    if !targets.iter().any(|t| t.arn == arn) {
        return Err(not_found());
    }
    store
        .remove_replication_target(bucket, &arn)
        .await
        .map_err(|err| match err {
            StoreError::InvalidRequest("no such replication target") => not_found(),
            StoreError::InvalidRequest(why) => admin::error(
                StatusCode::BAD_REQUEST,
                "XMinioAdminRemoteRemoveDisallowed",
                why,
            ),
            err => store_error(err),
        })?;
    let mut response = S3Response::new(Body::empty());
    response.status = Some(StatusCode::NO_CONTENT);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given(json: &str) -> BucketTarget {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_minio_target_is_read_as_mc_sends_it() {
        let target = given(
            r#"{"sourcebucket":"photos","endpoint":"backup.example.com:9000","credentials":{"accessKey":"replicator","secretKey":"dummy-secret"},"targetbucket":"photos-copy","secure":true,"type":"replication","region":"eu-west-1","bandwidthlimit":1048576,"replicationSync":true,"healthCheckDuration":30000000000,"disableProxy":false,"insecureTLS":false}"#,
        );
        let new = read("photos", target, false, true).unwrap();
        assert_eq!(new.endpoint, "backup.example.com:9000");
        assert_eq!(new.target_bucket, "photos-copy");
        assert_eq!(new.region, "eu-west-1");
        assert_eq!(new.bandwidth_limit, 1_048_576);
        assert!(new.sync && new.secure);
        assert_eq!(new.health_check_secs, 30);
        assert_eq!(new.secrets.unwrap().secret_key.as_str(), "dummy-secret");
        assert!(new.arn.is_none());
    }

    #[test]
    fn targets_that_cant_work_are_refused() {
        let base = r#""endpoint":"h:9000","targetbucket":"b","credentials":{"accessKey":"a","secretKey":"s"}"#;
        for (json, why) in [
            (format!(r#"{{{base},"type":"ilm"}}"#), "kind"),
            (format!(r#"{{{base},"sourcebucket":"other"}}"#), "source"),
            (format!(r#"{{{base},"insecureTLS":true}}"#), "tls"),
            (
                r#"{"endpoint":"https://h","targetbucket":"b","credentials":{"accessKey":"a","secretKey":"s"}}"#.to_owned(),
                "scheme",
            ),
            (
                r#"{"endpoint":"h","credentials":{"accessKey":"a","secretKey":"s"}}"#.to_owned(),
                "bucket",
            ),
            (
                r#"{"endpoint":"h","targetbucket":"b","credentials":{"accessKey":"a"}}"#.to_owned(),
                "secret",
            ),
            (format!(r#"{{{base},"bandwidthlimit":-1}}"#), "bandwidth"),
        ] {
            assert!(read("photos", given(&json), false, true).is_err(), "{why}");
        }
        // A change needs the ARN, and without new credentials keeps the old secret.
        let change = format!("{{{base}}}");
        assert!(read("photos", given(&change), true, false).is_err());
        let change = format!(r#"{{{base},"arn":"arn:minio:replication::id:b"}}"#);
        let new = read("photos", given(&change), true, false).unwrap();
        assert!(new.secrets.is_none());
        assert_eq!(new.arn.as_deref(), Some("arn:minio:replication::id:b"));
    }

    #[test]
    fn listed_targets_never_carry_secrets() {
        let target = RemoteTarget {
            arn: "arn:minio:replication::id:b".to_owned(),
            source_bucket: "photos".to_owned(),
            endpoint: "h:9000".to_owned(),
            secure: true,
            target_bucket: "b".to_owned(),
            region: String::new(),
            access_key: "replicator".to_owned(),
            storage_class: String::new(),
            bandwidth_limit: 0,
            sync: false,
            health_check_secs: 60,
            created_ms: 0,
        };
        let json = serde_json::to_string(&BucketTarget::from_target(target)).unwrap();
        assert!(!json.contains("secretKey") && !json.contains("sessionToken"));
        assert!(json.contains(r#""accessKey":"replicator""#));
        assert!(json.contains(r#""healthCheckDuration":60000000000"#));
        assert!(json.contains(r#""type":"replication""#));
    }
}
