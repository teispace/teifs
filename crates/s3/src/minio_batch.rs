//! `MinIO`'s batch jobs through its admin API (`mc batch`): `start-job` takes a job in
//! YAML, `list-jobs`, `status-job` and `describe-job` say what each is doing,
//! `cancel-job` stops one, and `list-supported-job-types` and `generate-job` tell a
//! client what it may start. The jobs run in the background ([`crate::batch_jobs`]), one
//! at a time, and survive a restart.
//!
//! The kinds TeiFS runs: `expire` (removes the objects and versions its rules match) and
//! `keyrotate` (seals encrypted versions' data keys again, under another KMS key).

use std::time::Duration;

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::{Deserialize, Serialize};
use teifs_iam::Identity;
use teifs_store::{Store, StoreError};
use teifs_types::{
    batch::{
        BatchJob, ExpireJob, ExpireKind, ExpireRule, JobNotify, JobProgress, JobRetry, JobSpec,
        JobStatus, KeyRotateJob, KeyValue, RotateFilter, RotateTo,
    },
    config_kv::go_duration,
};
use zeroize::Zeroizing;

use crate::{
    admin,
    errors::{StoreResultExt, from_store},
    minio_iam::{caller_key, invalid, query, required},
    minio_kms::rfc3339,
    routes::{Routes, s3_refusal, signed_body},
};

/// The largest job a client may send, as on `MinIO`.
const MAX_JOB_BYTES: usize = 4 << 20;

/// The most rules an `expire` job may have, as on `MinIO`.
const MAX_RULES: usize = 100;

/// What a job's secret is shown as.
const REDACTED: &str = "**REDACTED**";

/// The kinds of job TeiFS runs.
const KINDS: [&str; 2] = ["expire", "keyrotate"];

/// One of the batch calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// Starts a job.
    Start,
    /// The jobs.
    List,
    /// How far a job got.
    Status,
    /// A job's YAML, its secrets hidden.
    Describe,
    /// Cancels a job.
    Cancel,
    /// The kinds of job there are.
    Kinds,
    /// A kind's template.
    Generate,
}

impl Call {
    /// The call's name, in metrics and the audit log (`MinIO`'s).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Start => "StartBatchJob",
            Self::List => "ListBatchJobs",
            Self::Status => "BatchJobStatus",
            Self::Describe => "DescribeBatchJob",
            Self::Cancel => "CancelBatchJob",
            Self::Kinds => "ListSupportedBatchJobTypes",
            Self::Generate => "GenerateBatchJob",
        }
    }

    /// Calls it.
    pub(crate) async fn call(
        self,
        routes: &Routes,
        req: S3Request<Body>,
        identity: &Identity,
    ) -> S3Result<S3Response<Body>> {
        let store = &routes.store;
        match self {
            Self::Start => {
                // The user, or (as `MinIO` names the root user) the key that signed.
                let user = identity
                    .principal()
                    .username()
                    .or_else(|| caller_key(&req))
                    .unwrap_or_default()
                    .to_owned();
                let started = start(store, req, user).await?;
                routes.batch.notify_one();
                Ok(admin::json(&started))
            }
            Self::List => list(store, &req).await,
            Self::Status => {
                let job = job(store, &required(&req, "jobId")?).await?;
                Ok(admin::json(&Status {
                    last_metric: metric(&job),
                }))
            }
            Self::Describe => {
                let job = job(store, &required(&req, "jobId")?).await?;
                Ok(text(describe(&job)?))
            }
            Self::Cancel => {
                let id = required(&req, "id")?;
                let cancel = |job: &mut BatchJob| job.status = JobStatus::Cancelled;
                store
                    .update_batch_job(&id, cancel)
                    .await
                    .s3()?
                    .ok_or_else(no_such_job)?;
                let mut response = S3Response::new(Body::empty());
                response.status = Some(StatusCode::NO_CONTENT);
                Ok(response)
            }
            Self::Kinds => Ok(admin::json(&KINDS)),
            Self::Generate => {
                let kind = required(&req, "jobType")?;
                match kind.as_str() {
                    "expire" => Ok(text(EXPIRE_TEMPLATE.to_owned())),
                    "keyrotate" => Ok(text(KEYROTATE_TEMPLATE.to_owned())),
                    _ => Err(not_runnable(&kind)),
                }
            }
        }
    }
}

fn text(yaml: String) -> S3Response<Body> {
    let mut response = S3Response::new(Body::from(yaml));
    response.headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/yaml"),
    );
    response
}

fn no_such_job() -> S3Error {
    admin::error(
        StatusCode::NOT_FOUND,
        "XMinioAdminNoSuchJob",
        "The specified job does not exist.",
    )
}

fn not_runnable(kind: &str) -> S3Error {
    invalid(format!(
        "TeiFS doesn't run `{kind}` batch jobs; it runs: {}",
        KINDS.join(", ")
    ))
}

async fn job(store: &Store, id: &str) -> S3Result<BatchJob> {
    store.batch_job(id).await.s3()?.ok_or_else(no_such_job)
}

/// `POST start-job` with a job in YAML: records it to run, answering its id.
async fn start(store: &Store, mut req: S3Request<Body>, user: String) -> S3Result<JobResult> {
    let body = signed_body(&mut req, MAX_JOB_BYTES)
        .await
        .map_err(s3_refusal)?;
    let (spec, token) = read(&body)?;
    if let JobSpec::KeyRotate(rotate) = &spec {
        check_rotation(store, &rotate.encryption).await?;
    }
    match store.head_bucket(spec.bucket()).await {
        Err(StoreError::NoSuchBucket) => {
            return Err(admin::error(
                StatusCode::NOT_FOUND,
                "NoSuchSourceBucket",
                "The specified source bucket does not exist",
            ));
        }
        other => drop(other.s3()?),
    }
    let job = BatchJob {
        id: format!("{}-{}", spec.kind(), uuid::Uuid::new_v4().simple()),
        user,
        created_ms: crate::admin::millis(std::time::SystemTime::now()),
        priority: 0,
        status: JobStatus::Ready,
        spec,
        progress: JobProgress::default(),
        failures: Vec::new(),
    };
    store
        .add_batch_job(&job, token)
        .await
        .map_err(|err| match err {
            StoreError::NoKms => admin::error(
                StatusCode::NOT_IMPLEMENTED,
                "XMinioAdminNoKMS",
                "A job's notification token is kept sealed by the KMS, and none is configured",
            ),
            err => from_store(err),
        })?;
    Ok(JobResult::of(&job))
}

/// `GET list-jobs[?jobType=KIND][&bucket=NAME]`: the jobs, oldest first.
async fn list(store: &Store, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let given = query(req);
    let filter = |name: &str| {
        given
            .iter()
            .find(|(n, v)| n == name && !v.is_empty())
            .map(|(_, v)| v.clone())
    };
    let (kind, bucket) = (filter("jobType"), filter("bucket"));
    let jobs = store
        .batch_jobs()
        .await
        .s3()?
        .iter()
        .filter(|job| kind.as_ref().is_none_or(|k| k == job.spec.kind()))
        .filter(|job| bucket.as_ref().is_none_or(|b| b == job.spec.bucket()))
        .map(JobResult::of)
        .collect();
    Ok(admin::json(&Jobs { jobs }))
}

/// `madmin.BatchJobResult`.
#[derive(Debug, Serialize)]
pub(crate) struct JobResult {
    id: String,
    #[serde(rename = "type")]
    kind: &'static str,
    bucket: String,
    user: String,
    started: String,
    /// Nanoseconds since it started, as Go's `time.Duration`.
    #[serde(skip_serializing_if = "is_zero")]
    elapsed: u64,
    status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl JobResult {
    fn of(job: &BatchJob) -> Self {
        let started = job.progress.started_ms.unwrap_or(job.created_ms);
        let until = if job.status.finished() {
            job.progress.updated_ms.unwrap_or(started)
        } else {
            crate::admin::millis(std::time::SystemTime::now())
        };
        let elapsed = u64::try_from(until.saturating_sub(started)).unwrap_or(0);
        Self {
            id: job.id.clone(),
            kind: job.spec.kind(),
            bucket: job.spec.bucket().to_owned(),
            user: job.user.clone(),
            started: rfc3339(job.created_ms),
            elapsed: elapsed.saturating_mul(1_000_000),
            status: status_name(job.status),
            error: job.failures.first().cloned().unwrap_or_default(),
        }
    }
}

/// `madmin.ListBatchJobsResult`.
#[derive(Serialize)]
struct Jobs {
    jobs: Vec<JobResult>,
}

/// `madmin.BatchJobStatus`.
#[derive(Serialize)]
struct Status {
    #[serde(rename = "LastMetric")]
    last_metric: Metric,
}

/// `madmin.JobMetric`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Metric {
    #[serde(rename = "jobID")]
    job_id: String,
    job_type: &'static str,
    start_time: String,
    last_update: String,
    retry_attempts: u32,
    complete: bool,
    failed: bool,
    status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expired: Option<Counts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotation: Option<RotationCounts>,
}

/// `madmin.KeyRotationInfo`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RotationCounts {
    last_bucket: String,
    last_object: String,
    objects: u64,
    objects_failed: u64,
}

/// `madmin.ExpirationInfo`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Counts {
    last_bucket: String,
    last_object: String,
    objects: u64,
    objects_failed: u64,
    delete_markers: u64,
    delete_markers_failed: u64,
}

/// What a job did, as `MinIO` reports it.
pub(crate) fn metric(job: &BatchJob) -> Metric {
    let p = &job.progress;
    let never = "0001-01-01T00:00:00Z".to_owned();
    Metric {
        job_id: job.id.clone(),
        job_type: job.spec.kind(),
        start_time: p.started_ms.map_or_else(|| never.clone(), rfc3339),
        last_update: p.updated_ms.map_or(never, rfc3339),
        retry_attempts: p.retry_attempts,
        complete: job.status == JobStatus::Complete,
        failed: job.status == JobStatus::Failed,
        status: status_name(job.status),
        last_error: job.failures.last().cloned().unwrap_or_default(),
        expired: match &job.spec {
            JobSpec::Expire(expire) => Some(Counts {
                last_bucket: expire.bucket.clone(),
                last_object: p.last_key.clone().unwrap_or_default(),
                objects: p.objects,
                objects_failed: p.objects_failed,
                delete_markers: p.delete_markers,
                delete_markers_failed: p.delete_markers_failed,
            }),
            JobSpec::KeyRotate(_) => None,
        },
        rotation: match &job.spec {
            JobSpec::KeyRotate(rotate) => Some(RotationCounts {
                last_bucket: rotate.bucket.clone(),
                last_object: p.last_key.clone().unwrap_or_default(),
                objects: p.objects,
                objects_failed: p.objects_failed,
            }),
            JobSpec::Expire(_) => None,
        },
    }
}

/// What a job's result is sent as when it ends (`MinIO`'s `batchJobInfo`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Ended {
    #[serde(rename = "jobID")]
    job_id: String,
    job_type: &'static str,
    start_time: String,
    last_update: String,
    retry_attempts: u32,
    complete: bool,
    failed: bool,
    objects: u64,
    delete_markers: u64,
    objects_failed: u64,
    delete_markers_failed: u64,
    bytes_transferred: u64,
    bytes_failed: u64,
}

impl Ended {
    pub(crate) fn of(job: &BatchJob) -> Self {
        let metric = metric(job);
        let p = &job.progress;
        Self {
            job_id: metric.job_id,
            job_type: metric.job_type,
            start_time: metric.start_time,
            last_update: metric.last_update,
            retry_attempts: p.retry_attempts,
            complete: metric.complete,
            failed: metric.failed,
            objects: p.objects,
            delete_markers: p.delete_markers,
            objects_failed: p.objects_failed,
            delete_markers_failed: p.delete_markers_failed,
            bytes_transferred: p.bytes,
            bytes_failed: p.bytes_failed,
        }
    }
}

/// A status as madmin names it.
const fn status_name(status: JobStatus) -> &'static str {
    match status {
        JobStatus::Complete => "completed",
        JobStatus::Failed => "failed",
        JobStatus::Cancelled | JobStatus::Cancelling => "canceled",
        JobStatus::Active | JobStatus::Completing | JobStatus::Failing => "in-progress",
        JobStatus::New
        | JobStatus::Preparing
        | JobStatus::Suspended
        | JobStatus::Ready
        | JobStatus::Pausing
        | JobStatus::Paused => "waiting",
    }
}

/// A job as `MinIO` takes it in YAML: one kind, with what `describe-job` adds.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    started: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expire: Option<ExpireYaml>,
    #[serde(default, skip_serializing)]
    replicate: Option<serde::de::IgnoredAny>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keyrotate: Option<KeyRotateYaml>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpireYaml {
    #[serde(default)]
    api_version: String,
    #[serde(default)]
    bucket: String,
    #[serde(default, skip_serializing_if = "Prefixes::is_empty")]
    prefix: Prefixes,
    #[serde(default)]
    rules: Vec<RuleYaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notify: Option<NotifyYaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry: Option<RetryYaml>,
}

/// One prefix or several.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Prefixes {
    One(String),
    Many(Vec<String>),
}

impl Default for Prefixes {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl Prefixes {
    fn is_empty(&self) -> bool {
        match self {
            Self::One(one) => one.is_empty(),
            Self::Many(many) => many.is_empty(),
        }
    }

    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(one) if one.is_empty() => Vec::new(),
            Self::One(one) => vec![one],
            Self::Many(many) => many.into_iter().filter(|p| !p.is_empty()).collect(),
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleYaml {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    older_than: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_before: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<KeyValueYaml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    metadata: Vec<KeyValueYaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size: Option<SizeYaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purge: Option<PurgeYaml>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyValueYaml {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SizeYaml {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    less_than: Option<Size>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    greater_than: Option<Size>,
}

/// A size: bytes, or with a unit (`10MiB`, `1MB`).
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Size {
    Bytes(u64),
    Text(String),
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PurgeYaml {
    #[serde(default)]
    retain_versions: i64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotifyYaml {
    #[serde(default)]
    endpoint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    token: String,
}

impl Drop for NotifyYaml {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetryYaml {
    #[serde(default)]
    attempts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delay: Option<String>,
}

/// `MinIO`'s `keyrotate` job.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyRotateYaml {
    #[serde(default)]
    api_version: String,
    #[serde(default)]
    bucket: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    prefix: String,
    #[serde(default)]
    encryption: EncryptionYaml,
    #[serde(default)]
    flags: FlagsYaml,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptionYaml {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    key: String,
    /// Base64 of a JSON object.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    context: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlagsYaml {
    #[serde(default)]
    filter: FilterYaml,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notify: Option<NotifyYaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry: Option<RetryYaml>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FilterYaml {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    newer_than: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    older_than: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_before: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<KeyValueYaml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    metadata: Vec<KeyValueYaml>,
    #[serde(default, rename = "kmskeyid", skip_serializing_if = "String::is_empty")]
    kms_key: String,
}

/// A `keyrotate` job's retries when it gives none, as `MinIO`'s.
const ROTATE_RETRY: JobRetry = JobRetry {
    attempts: 3,
    delay_ms: 25,
};

/// A KMS key named directly, by `MinIO`'s `arn:aws:kms:NAME` or by AWS's key ARN.
fn kms_key(given: &str) -> String {
    crate::sse::kms_key_name(given.strip_prefix("arn:aws:kms:").unwrap_or(given))
}

fn read_keyrotate(mut given: KeyRotateYaml) -> S3Result<(JobSpec, Option<Zeroizing<String>>)> {
    if given.api_version != "v1" {
        return Err(invalid("Unsupported batch key rotation API version"));
    }
    if given.bucket.is_empty() {
        return Err(invalid("Bucket argument missing"));
    }
    let wrong = |why: String| invalid(format!("Invalid batch key rotation: {why}"));
    let encryption = &given.encryption;
    let to = match encryption.kind.as_str() {
        "sse-s3" if encryption.key.is_empty() && encryption.context.is_empty() => RotateTo::S3,
        "sse-s3" => return Err(wrong("sse-s3 takes no key or context".to_owned())),
        "sse-kms" => {
            if encryption.key.trim() != encryption.key {
                return Err(wrong("the key can't start or end with a space".to_owned()));
            }
            let context = if encryption.context.is_empty() {
                std::collections::BTreeMap::new()
            } else {
                base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &encryption.context,
                )
                .ok()
                .and_then(|json| serde_json::from_slice(&json).ok())
                .ok_or_else(|| {
                    wrong("the context is base64 of a JSON object of strings".to_owned())
                })?
            };
            let key = if encryption.key.is_empty() {
                teifs_crypto::DEFAULT_KEY.to_owned()
            } else {
                kms_key(&encryption.key)
            };
            RotateTo::Kms { key, context }
        }
        other => return Err(wrong(format!("the type `{other}` isn't sse-s3 or sse-kms"))),
    };
    let flags = std::mem::take(&mut given.flags);
    let filter = flags.filter;
    let seconds = |field: &str, text: Option<String>| {
        text.map(|text| minio_duration(&text).map(|d| d.as_secs()))
            .transpose()
            .map_err(|why| wrong(format!("{field}: {why}")))
    };
    let pairs = |given: Vec<KeyValueYaml>| {
        given
            .into_iter()
            .map(|kv| KeyValue {
                key: kv.key,
                value: kv.value,
            })
            .collect()
    };
    let filter = RotateFilter {
        newer_than_secs: seconds("newerThan", filter.newer_than)?,
        older_than_secs: seconds("olderThan", filter.older_than)?,
        created_after_ms: filter
            .created_after
            .map(|text| date("createdAfter", &text))
            .transpose()
            .map_err(wrong)?,
        created_before_ms: filter
            .created_before
            .map(|text| date("createdBefore", &text))
            .transpose()
            .map_err(wrong)?,
        tags: pairs(filter.tags),
        metadata: pairs(filter.metadata),
        kms_key: (!filter.kms_key.is_empty()).then(|| kms_key(&filter.kms_key)),
    };
    let (notify, token) = read_notify(flags.notify)?;
    let retry = read_retry(flags.retry, ROTATE_RETRY, "key rotation")?;
    let rotate = KeyRotateJob {
        bucket: std::mem::take(&mut given.bucket),
        prefix: std::mem::take(&mut given.prefix),
        encryption: to,
        filter,
        notify,
        retry,
    };
    Ok((JobSpec::KeyRotate(rotate), token))
}

/// Whether the drive can rotate keys to `to`: it has a KMS, and the key seals a data key
/// under the context.
async fn check_rotation(store: &Store, to: &RotateTo) -> S3Result<()> {
    let kms = store.kms().ok_or_else(|| {
        admin::error(
            StatusCode::NOT_IMPLEMENTED,
            "XMinioAdminNoKMS",
            "Rotating keys needs the KMS, and none is configured",
        )
    })?;
    if let RotateTo::Kms { key, context } = to {
        let mut test = teifs_crypto::Context::replication(&store.format().drive)
            .with("MinIO batch API", "batchrotate");
        for (name, value) in context {
            test = test.with(name.clone(), value.clone());
        }
        kms.generate(Some(key), &test).await.map_err(|err| {
            invalid(format!(
                "Invalid batch key rotation: the key `{key}` can't be used: {err}"
            ))
        })?;
    }
    Ok(())
}

/// The job a YAML body describes, checked, and the token its result is sent with.
fn read(body: &[u8]) -> S3Result<(JobSpec, Option<Zeroizing<String>>)> {
    let text = std::str::from_utf8(body).map_err(|_| invalid("A job is YAML, in UTF-8"))?;
    let request: Request = serde_saphyr::from_str(text)
        .map_err(|e| invalid(format!("The job isn't valid YAML: {e}")))?;
    match request {
        Request {
            expire: Some(expire),
            replicate: None,
            keyrotate: None,
            ..
        } => read_expire(expire),
        Request {
            replicate: Some(_),
            expire: None,
            keyrotate: None,
            ..
        } => Err(not_runnable("replicate")),
        Request {
            keyrotate: Some(rotate),
            expire: None,
            replicate: None,
            ..
        } => read_keyrotate(rotate),
        _ => Err(invalid(
            "A job has exactly one of expire, replicate or keyrotate",
        )),
    }
}

fn read_expire(mut given: ExpireYaml) -> S3Result<(JobSpec, Option<Zeroizing<String>>)> {
    if given.api_version != "v1" {
        return Err(invalid("Unsupported batch expire API version"));
    }
    if given.bucket.is_empty() {
        return Err(invalid("Bucket argument missing"));
    }
    if given.rules.len() > MAX_RULES {
        return Err(invalid(
            "Too many rules. Batch expire job can't have more than 100 rules",
        ));
    }
    let rules = given
        .rules
        .drain(..)
        .map(read_rule)
        .collect::<Result<_, _>>()
        .map_err(|why| invalid(format!("Invalid batch expire rule: {why}")))?;
    let (notify, token) = read_notify(given.notify.take())?;
    let retry = read_retry(given.retry.take(), JobRetry::default(), "expire")?;
    let expire = ExpireJob {
        bucket: std::mem::take(&mut given.bucket),
        prefixes: std::mem::take(&mut given.prefix).into_vec(),
        rules,
        notify,
        retry,
    };
    Ok((JobSpec::Expire(expire), token))
}

/// Where a job's result goes, and the token it's sent with.
fn read_notify(
    given: Option<NotifyYaml>,
) -> S3Result<(Option<JobNotify>, Option<Zeroizing<String>>)> {
    Ok(match given {
        Some(mut notify) if !notify.endpoint.is_empty() => {
            teifs_notify::Webhook::new(&notify.endpoint, None)
                .map_err(|why| invalid(format!("The notify endpoint: {why}")))?;
            if notify.token == REDACTED {
                return Err(invalid(
                    "The notify token was hidden when the job was described: give it again",
                ));
            }
            let token = (!notify.token.is_empty())
                .then(|| Zeroizing::new(std::mem::take(&mut notify.token)));
            let notify = JobNotify {
                endpoint: std::mem::take(&mut notify.endpoint),
                token: token.is_some(),
            };
            (Some(notify), token)
        }
        _ => (None, None),
    })
}

/// How often what fails is tried, `default` for what isn't given.
fn read_retry(given: Option<RetryYaml>, default: JobRetry, kind: &str) -> S3Result<JobRetry> {
    Ok(match given {
        None => default,
        Some(retry) => {
            let attempts = u32::try_from(retry.attempts).map_err(|_| {
                invalid(format!(
                    "Invalid batch {kind} retry configuration: attempts"
                ))
            })?;
            let delay = retry
                .delay
                .as_deref()
                .map(go_duration)
                .transpose()
                .map_err(|why| {
                    invalid(format!("Invalid batch {kind} retry configuration: {why}"))
                })?;
            JobRetry {
                attempts: if attempts == 0 {
                    default.attempts
                } else {
                    attempts
                },
                delay_ms: delay.map_or(default.delay_ms, |d| {
                    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
                }),
            }
        }
    })
}

fn read_rule(given: RuleYaml) -> Result<ExpireRule, String> {
    let kind = match given.kind.as_str() {
        "object" => ExpireKind::Object,
        "deleted" => ExpireKind::Deleted,
        other => return Err(format!("unknown type `{other}`: object or deleted")),
    };
    if kind == ExpireKind::Deleted && (!given.tags.is_empty() || !given.metadata.is_empty()) {
        return Err("delete type filter can't have tags or metadata".to_owned());
    }
    let older_than_secs = given
        .older_than
        .as_deref()
        .map(|text| minio_duration(text).map(|d| d.as_secs()))
        .transpose()?;
    let created_before_ms = given
        .created_before
        .as_deref()
        .map(|text| date("createdBefore", text))
        .transpose()?;
    let pairs = |given: Vec<KeyValueYaml>| -> Result<Vec<KeyValue>, String> {
        given
            .into_iter()
            .map(|kv| {
                if kv.key.is_empty() {
                    return Err("a tag or metadata needs a key".to_owned());
                }
                Ok(KeyValue {
                    key: kv.key,
                    value: kv.value,
                })
            })
            .collect()
    };
    let size = given.size.unwrap_or_default();
    let retain = given.purge.map_or(0, |p| p.retain_versions);
    Ok(ExpireRule {
        kind,
        name: given.name.filter(|n| !n.is_empty()),
        older_than_secs,
        created_before_ms,
        tags: pairs(given.tags)?,
        metadata: pairs(given.metadata)?,
        size_less_than: size.less_than.map(bytes).transpose()?,
        size_greater_than: size.greater_than.map(bytes).transpose()?,
        retain_versions: u32::try_from(retain)
            .map_err(|_| "retainVersions must be 0 or more".to_owned())?,
    })
}

/// A date in RFC 3339, as Unix milliseconds; `field` names it when it isn't one.
fn date(field: &str, text: &str) -> Result<i64, String> {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map(|t| i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX))
        .map_err(|_| format!("{field} `{text}` isn't a date like 2006-01-02T15:04:05Z"))
}

/// A duration as `MinIO`'s batch jobs take it: Go's (`10h`, `1h30m`), with days and
/// weeks before it (`7d10h31s`, `2w`).
fn minio_duration(text: &str) -> Result<Duration, String> {
    let wrong = || format!("`{text}` isn't a duration like 70h, 7d or 7d10h31s");
    let mut rest = text.trim();
    let mut total = Duration::ZERO;
    loop {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let unit = match rest[digits..].chars().next() {
            Some('d') => 86_400,
            Some('w') => 7 * 86_400,
            _ => break,
        };
        let number: u64 = rest[..digits].parse().map_err(|_| wrong())?;
        total = number
            .checked_mul(unit)
            .and_then(|secs| total.checked_add(Duration::from_secs(secs)))
            .ok_or_else(wrong)?;
        rest = &rest[digits + 1..];
    }
    if rest.is_empty() {
        return if total.is_zero() && text.trim().is_empty() {
            Err(wrong())
        } else {
            Ok(total)
        };
    }
    go_duration(rest)
        .ok()
        .and_then(|more| total.checked_add(more))
        .ok_or_else(wrong)
}

/// A size as `MinIO` takes one (go-humanize's `ParseBytes`): bytes, or a number with
/// `KB`/`K` (1000), `KiB` (1024) and the larger units.
fn bytes(size: Size) -> Result<u64, String> {
    let text = match size {
        Size::Bytes(bytes) => return Ok(bytes),
        Size::Text(text) => text,
    };
    let wrong = || format!("`{text}` isn't a size like 10MiB or 1MB");
    let trimmed = text.trim();
    let split = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(trimmed.len());
    let number: f64 = trimmed[..split].parse().map_err(|_| wrong())?;
    let unit = trimmed[split..].trim().to_ascii_lowercase();
    let power = |base: f64, exponent: i32| base.powi(exponent);
    let multiplier = match unit.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => power(1000.0, 1),
        "ki" | "kib" => power(1024.0, 1),
        "m" | "mb" => power(1000.0, 2),
        "mi" | "mib" => power(1024.0, 2),
        "g" | "gb" => power(1000.0, 3),
        "gi" | "gib" => power(1024.0, 3),
        "t" | "tb" => power(1000.0, 4),
        "ti" | "tib" => power(1024.0, 4),
        "p" | "pb" => power(1000.0, 5),
        "pi" | "pib" => power(1024.0, 5),
        _ => return Err(wrong()),
    };
    let value = number * multiplier;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "checked to be a whole number of bytes that fits"
    )]
    if (0.0..18_446_744_073_709_551_615.0).contains(&value) {
        Ok(value as u64)
    } else {
        Err(wrong())
    }
}

/// A job as `describe-job` answers it: `MinIO`'s YAML, its token hidden.
fn describe(job: &BatchJob) -> S3Result<String> {
    let mut request = Request {
        id: Some(job.id.clone()),
        user: Some(job.user.clone()),
        started: Some(rfc3339(job.created_ms)),
        ..Request::default()
    };
    match &job.spec {
        JobSpec::Expire(expire) => request.expire = Some(expire_yaml(expire)),
        JobSpec::KeyRotate(rotate) => request.keyrotate = Some(keyrotate_yaml(rotate)),
    }
    serde_saphyr::to_string(&request).map_err(S3Error::internal_error)
}

fn expire_yaml(expire: &ExpireJob) -> ExpireYaml {
    let pairs = |given: &[KeyValue]| {
        given
            .iter()
            .map(|kv| KeyValueYaml {
                key: kv.key.clone(),
                value: kv.value.clone(),
            })
            .collect()
    };
    let rules = expire
        .rules
        .iter()
        .map(|rule| RuleYaml {
            kind: match rule.kind {
                ExpireKind::Object => "object",
                ExpireKind::Deleted => "deleted",
            }
            .to_owned(),
            name: rule.name.clone(),
            older_than: rule.older_than_secs.map(|secs| format!("{secs}s")),
            created_before: rule.created_before_ms.map(rfc3339),
            tags: pairs(&rule.tags),
            metadata: pairs(&rule.metadata),
            size: (rule.size_less_than.is_some() || rule.size_greater_than.is_some()).then(|| {
                SizeYaml {
                    less_than: rule.size_less_than.map(Size::Bytes),
                    greater_than: rule.size_greater_than.map(Size::Bytes),
                }
            }),
            purge: Some(PurgeYaml {
                retain_versions: i64::from(rule.retain_versions),
            }),
        })
        .collect();
    ExpireYaml {
        api_version: "v1".to_owned(),
        bucket: expire.bucket.clone(),
        prefix: Prefixes::Many(expire.prefixes.clone()),
        rules,
        notify: notify_yaml(expire.notify.as_ref()),
        retry: Some(retry_yaml(expire.retry)),
    }
}

fn notify_yaml(notify: Option<&JobNotify>) -> Option<NotifyYaml> {
    notify.map(|notify| NotifyYaml {
        endpoint: notify.endpoint.clone(),
        token: if notify.token {
            REDACTED.to_owned()
        } else {
            String::new()
        },
    })
}

fn retry_yaml(retry: JobRetry) -> RetryYaml {
    RetryYaml {
        attempts: i64::from(retry.attempts),
        delay: Some(format!("{}ms", retry.delay_ms)),
    }
}

fn keyrotate_yaml(rotate: &KeyRotateJob) -> KeyRotateYaml {
    let encryption = match &rotate.encryption {
        RotateTo::S3 => EncryptionYaml {
            kind: "sse-s3".to_owned(),
            ..EncryptionYaml::default()
        },
        RotateTo::Kms { key, context } => EncryptionYaml {
            kind: "sse-kms".to_owned(),
            key: key.clone(),
            context: if context.is_empty() {
                String::new()
            } else {
                let json = serde_json::to_vec(context).expect("a context serializes");
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json)
            },
        },
    };
    let pairs = |given: &[KeyValue]| {
        given
            .iter()
            .map(|kv| KeyValueYaml {
                key: kv.key.clone(),
                value: kv.value.clone(),
            })
            .collect()
    };
    let f = &rotate.filter;
    KeyRotateYaml {
        api_version: "v1".to_owned(),
        bucket: rotate.bucket.clone(),
        prefix: rotate.prefix.clone(),
        encryption,
        flags: FlagsYaml {
            filter: FilterYaml {
                newer_than: f.newer_than_secs.map(|secs| format!("{secs}s")),
                older_than: f.older_than_secs.map(|secs| format!("{secs}s")),
                created_after: f.created_after_ms.map(rfc3339),
                created_before: f.created_before_ms.map(rfc3339),
                tags: pairs(&f.tags),
                metadata: pairs(&f.metadata),
                kms_key: f.kms_key.clone().unwrap_or_default(),
            },
            notify: notify_yaml(rotate.notify.as_ref()),
            retry: Some(retry_yaml(rotate.retry)),
        },
    }
}

/// What `generate-job?jobType=keyrotate` answers.
const KEYROTATE_TEMPLATE: &str = "\
keyrotate:
  apiVersion: v1
  bucket: mybucket          # the bucket whose encrypted versions get a new key
  prefix: myprefix          # (optional) only keys under it
  encryption:
    type: sse-kms           # sse-s3: the managed key's newest version; sse-kms: a KMS key
    key: my-key             # sse-kms only: the key (none: the managed key)
    context: eyJ0ZWFtIjoib3BzIn0= # (optional, sse-kms) base64 of a JSON object
  flags:
    filter:                 # (optional) every condition given must hold
      newerThan: 7d         # made less than this long ago (s, m, h, d, w)
      olderThan: 1d         # made at least this long ago
      createdAfter: \"2026-01-01T00:00:00Z\"
      createdBefore: \"2026-12-31T00:00:00Z\"
      tags:                 # with any one of these tags
        - key: team
          value: o*
      metadata:             # with any one of these headers or x-amz-meta-* metadata
        - key: content-type
          value: image/*
      kmskeyid: old-key     # SSE-KMS versions only when sealed by this key now
    notify:                 # (optional) where the result is POSTed when the job ends
      endpoint: https://example.com/batch
      token: Bearer TOKEN
    retry:                  # how often a version that fails is tried
      attempts: 3
      delay: 25ms
";

/// What `generate-job?jobType=expire` answers.
const EXPIRE_TEMPLATE: &str = "\
expire:
  apiVersion: v1
  bucket: mybucket          # the bucket to expire objects in
  prefix: myprefix          # (optional) only keys under it; a list of prefixes works too
  rules:
    # The first rule that matches an object's newest version decides.
    - type: object          # objects whose newest version is an object
      name: \"*.log\"         # (optional) keys matching it, with * and ?
      olderThan: 7d         # (optional) made longer ago than this (s, m, h, d, w)
      createdBefore: \"2026-01-01T00:00:00Z\" # (optional) made before then
      tags:                 # (optional) with every one of these tags
        - key: name
          value: pick*      # values with * and ?
      metadata:             # (optional) with these headers or x-amz-meta-* metadata
        - key: content-type
          value: image/*
      size:                 # (optional)
        lessThan: 10MiB
        greaterThan: 1KiB
      purge:
        retainVersions: 0   # 0 removes every version; N keeps the newest N
    - type: deleted         # objects whose newest version is a delete marker
      olderThan: 30d
      purge:
        retainVersions: 0
  notify:                   # (optional) where the result is POSTed when the job ends
    endpoint: https://example.com/batch
    token: Bearer TOKEN
  retry:                    # how often a removal that fails is tried
    attempts: 3
    delay: 500ms
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_template_is_a_job_this_server_runs() {
        let (spec, token) = read(EXPIRE_TEMPLATE.as_bytes()).unwrap();
        assert_eq!(token.as_deref().map(String::as_str), Some("Bearer TOKEN"));
        let JobSpec::Expire(expire) = spec else {
            panic!("an expire job: {spec:?}");
        };
        assert_eq!(expire.bucket, "mybucket");
        assert_eq!(expire.prefixes, ["myprefix"]);
        assert_eq!(expire.rules.len(), 2);
        let rule = &expire.rules[0];
        assert_eq!(rule.kind, ExpireKind::Object);
        assert_eq!(rule.name.as_deref(), Some("*.log"));
        assert_eq!(rule.older_than_secs, Some(7 * 86_400));
        assert_eq!(rule.created_before_ms, Some(1_767_225_600_000));
        assert_eq!(rule.tags[0].value, "pick*");
        assert_eq!(rule.metadata[0].key, "content-type");
        assert_eq!(rule.size_less_than, Some(10 << 20));
        assert_eq!(rule.size_greater_than, Some(1024));
        assert_eq!(expire.rules[1].kind, ExpireKind::Deleted);
        assert_eq!(
            expire.notify,
            Some(JobNotify {
                endpoint: "https://example.com/batch".to_owned(),
                token: true
            })
        );
        assert_eq!(
            expire.retry,
            JobRetry {
                attempts: 3,
                delay_ms: 500
            }
        );
    }

    #[test]
    fn the_keyrotate_template_is_a_job_this_server_runs_and_describes() {
        let (spec, token) = read(KEYROTATE_TEMPLATE.as_bytes()).unwrap();
        assert_eq!(token.as_deref().map(String::as_str), Some("Bearer TOKEN"));
        let JobSpec::KeyRotate(rotate) = &spec else {
            panic!("a keyrotate job: {spec:?}");
        };
        assert_eq!(
            (rotate.bucket.as_str(), rotate.prefix.as_str()),
            ("mybucket", "myprefix")
        );
        assert_eq!(
            rotate.encryption,
            RotateTo::Kms {
                key: "my-key".to_owned(),
                context: [("team".to_owned(), "ops".to_owned())].into()
            }
        );
        let f = &rotate.filter;
        assert_eq!(
            (f.newer_than_secs, f.older_than_secs),
            (Some(7 * 86_400), Some(86_400))
        );
        assert_eq!(f.created_after_ms, Some(1_767_225_600_000));
        assert_eq!(f.created_before_ms, Some(1_798_675_200_000));
        assert_eq!((f.tags.len(), f.metadata.len()), (1, 1));
        assert_eq!(f.kms_key.as_deref(), Some("old-key"));
        assert_eq!(
            rotate.retry,
            JobRetry {
                attempts: 3,
                delay_ms: 25
            }
        );
        let job = BatchJob {
            id: "keyrotate-1".to_owned(),
            user: "admin".to_owned(),
            created_ms: 0,
            priority: 0,
            status: JobStatus::Ready,
            spec: spec.clone(),
            progress: JobProgress::default(),
            failures: Vec::new(),
        };
        let yaml = describe(&job).unwrap().replace(REDACTED, "Bearer AGAIN");
        let (again, _) = read(yaml.as_bytes()).unwrap();
        assert_eq!(again, spec);
        // MinIO's and AWS's ARNs name keys too; no key is the managed one.
        for (given, name) in [
            ("arn:aws:kms:my-key", "my-key"),
            ("arn:aws:kms:us-east-1:123456789012:key/my-key", "my-key"),
            ("", teifs_crypto::DEFAULT_KEY),
        ] {
            let yaml = format!(
                "keyrotate:\n  apiVersion: v1\n  bucket: b\n  encryption:\n    type: sse-kms\n    key: \"{given}\"\n"
            );
            let (JobSpec::KeyRotate(rotate), _) = read(yaml.as_bytes()).unwrap() else {
                panic!("a keyrotate job");
            };
            assert_eq!(
                rotate.encryption,
                RotateTo::Kms {
                    key: name.to_owned(),
                    context: std::collections::BTreeMap::new()
                }
            );
        }
    }

    #[test]
    fn a_described_job_reads_back_the_same_without_its_token() {
        let (spec, _) = read(EXPIRE_TEMPLATE.as_bytes()).unwrap();
        let job = BatchJob {
            id: "expire-1".to_owned(),
            user: "admin".to_owned(),
            created_ms: 0,
            priority: 0,
            status: JobStatus::Ready,
            spec: spec.clone(),
            progress: JobProgress::default(),
            failures: Vec::new(),
        };
        let yaml = describe(&job).unwrap();
        assert!(yaml.contains(REDACTED), "{yaml}");
        assert!(!yaml.contains("Bearer TOKEN"), "{yaml}");
        assert!(yaml.contains("id: expire-1"), "{yaml}");
        let refused = read(yaml.as_bytes()).unwrap_err();
        assert!(refused.message().unwrap_or_default().contains("hidden"));
        let yaml = yaml.replace(REDACTED, "Bearer AGAIN");
        let (again, token) = read(yaml.as_bytes()).unwrap();
        assert_eq!(again, spec);
        assert_eq!(token.as_deref().map(String::as_str), Some("Bearer AGAIN"));
    }

    #[test]
    fn mistakes_are_refused_with_why() {
        let refused = |yaml: &str| {
            let err = read(yaml.as_bytes()).unwrap_err();
            err.message().unwrap_or_default().to_owned()
        };
        let job =
            |rules: &str| format!("expire:\n  apiVersion: v1\n  bucket: b\n  rules:\n{rules}");
        assert!(refused("expire:\n  apiVersion: v2\n  bucket: b\n").contains("API version"));
        assert!(refused("expire:\n  apiVersion: v1\n").contains("Bucket"));
        assert!(refused("replicate:\n  apiVersion: v1\n").contains("replicate"));
        let rotate = |encryption: &str| {
            format!("keyrotate:\n  apiVersion: v1\n  bucket: b\n  encryption:\n{encryption}")
        };
        assert!(refused("keyrotate:\n  apiVersion: v0\n").contains("API version"));
        assert!(refused(&rotate("    type: sse-c\n")).contains("sse-c"));
        assert!(refused(&rotate("    type: sse-s3\n    key: k\n")).contains("no key"));
        assert!(refused(&rotate("    type: sse-kms\n    key: \" k\"\n")).contains("space"));
        assert!(refused(&rotate("    type: sse-kms\n    context: '!!'\n")).contains("base64"));
        let filtered = rotate("    type: sse-s3\n  flags:\n    filter:\n      newerThan: soon\n");
        assert!(refused(&filtered).contains("newerThan"));
        assert!(refused("nothing: 1\n").contains("exactly one"));
        assert!(refused(": : :").contains("YAML"));
        assert!(refused(&job("    - type: gone\n")).contains("unknown type"));
        assert!(refused(&job("    - type: object\n      typo: 1\n")).contains("YAML"));
        assert!(
            refused(&job(
                "    - type: deleted\n      tags:\n        - key: a\n          value: b\n"
            ))
            .contains("tags or metadata")
        );
        assert!(refused(&job("    - type: object\n      olderThan: soon\n")).contains("duration"));
        assert!(
            refused(&job("    - type: object\n      createdBefore: yesterday\n"))
                .contains("createdBefore")
        );
        assert!(
            refused(&job(
                "    - type: object\n      size:\n        lessThan: lots\n"
            ))
            .contains("size")
        );
        assert!(
            refused(&job(
                "    - type: object\n      purge:\n        retainVersions: -1\n"
            ))
            .contains("retainVersions")
        );
        let many = "    - type: object\n".repeat(101);
        assert!(refused(&job(&many)).contains("100 rules"));
        assert!(
            refused("expire:\n  apiVersion: v1\n  bucket: b\n  notify:\n    endpoint: ftp://x\n")
                .contains("notify")
        );
        assert!(
            refused("expire:\n  apiVersion: v1\n  bucket: b\n  retry:\n    attempts: -2\n")
                .contains("retry")
        );
    }

    #[test]
    fn durations_take_days_and_weeks_before_gos() {
        assert_eq!(minio_duration("70h").unwrap(), Duration::from_hours(70));
        assert_eq!(minio_duration("7d").unwrap(), Duration::from_hours(7 * 24));
        assert_eq!(minio_duration("2w").unwrap(), Duration::from_hours(14 * 24));
        assert_eq!(
            minio_duration("7d10h31s").unwrap(),
            Duration::from_secs(7 * 86_400 + 10 * 3600 + 31)
        );
        assert_eq!(
            minio_duration("1w1d").unwrap(),
            Duration::from_hours(8 * 24)
        );
        for wrong in ["", "d", "7x", "h7", "7d-1h"] {
            assert!(minio_duration(wrong).is_err(), "{wrong}");
        }
    }

    #[test]
    fn sizes_take_si_and_binary_units() {
        let size = |text: &str| bytes(Size::Text(text.to_owned()));
        assert_eq!(size("10MiB").unwrap(), 10 << 20);
        assert_eq!(size("1MB").unwrap(), 1_000_000);
        assert_eq!(size("1.5 KiB").unwrap(), 1536);
        assert_eq!(size("42").unwrap(), 42);
        assert_eq!(size("2gi").unwrap(), 2 << 30);
        assert_eq!(bytes(Size::Bytes(7)).unwrap(), 7);
        for wrong in ["", "MiB", "1.2.3", "5 parsecs", "-1", "99999999PiB"] {
            assert!(size(wrong).is_err(), "{wrong}");
        }
    }

    #[test]
    fn statuses_are_madmins() {
        assert_eq!(status_name(JobStatus::Ready), "waiting");
        assert_eq!(status_name(JobStatus::Active), "in-progress");
        assert_eq!(status_name(JobStatus::Complete), "completed");
        assert_eq!(status_name(JobStatus::Failed), "failed");
        assert_eq!(status_name(JobStatus::Cancelled), "canceled");
    }
}
