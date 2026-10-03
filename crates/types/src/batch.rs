//! Batch jobs: one operation over many objects, run in the background with their
//! progress kept, as `MinIO`'s batch jobs (`mc batch`) and S3 Batch Operations run them.

use serde::{Deserialize, Serialize};

/// The most failure reasons a job keeps.
pub const MAX_FAILURES: usize = 20;

/// A job: what it does, where it stands, and how far it got.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchJob {
    /// Its id.
    pub id: String,
    /// Who started it (an access key's user).
    pub user: String,
    /// When it was made (Unix milliseconds).
    pub created_ms: i64,
    /// Which job runs first: higher first, then older.
    pub priority: i32,
    /// Where it stands.
    pub status: JobStatus,
    /// What it does.
    pub spec: JobSpec,
    /// How far it got.
    #[serde(default)]
    pub progress: JobProgress,
    /// Why tasks or the job failed, the first [`MAX_FAILURES`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
}

impl BatchJob {
    /// Records why something failed, keeping the first [`MAX_FAILURES`].
    pub fn failed_because(&mut self, why: impl Into<String>) {
        if self.failures.len() < MAX_FAILURES {
            self.failures.push(why.into());
        }
    }
}

/// Where a job stands, with S3 Batch Operations' names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    /// Made, waiting to be prepared.
    New,
    /// Its objects are being found.
    Preparing,
    /// Waiting for a person to confirm it.
    Suspended,
    /// Waiting to run.
    Ready,
    /// Running.
    Active,
    /// Stopping for a job that comes first.
    Pausing,
    /// Stopped for a job that comes first.
    Paused,
    /// Finishing.
    Completing,
    /// Done: each object's task succeeded or failed.
    Complete,
    /// Being cancelled.
    Cancelling,
    /// Cancelled.
    Cancelled,
    /// Failing.
    Failing,
    /// Failed as a whole.
    Failed,
}

impl JobStatus {
    /// Its name, as S3 Batch Operations says it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "New",
            Self::Preparing => "Preparing",
            Self::Suspended => "Suspended",
            Self::Ready => "Ready",
            Self::Active => "Active",
            Self::Pausing => "Pausing",
            Self::Paused => "Paused",
            Self::Completing => "Completing",
            Self::Complete => "Complete",
            Self::Cancelling => "Cancelling",
            Self::Cancelled => "Cancelled",
            Self::Failing => "Failing",
            Self::Failed => "Failed",
        }
    }

    /// Whether it's done for good: complete, cancelled or failed.
    #[must_use]
    pub const fn finished(self) -> bool {
        matches!(self, Self::Complete | Self::Cancelled | Self::Failed)
    }
}

/// What a job does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum JobSpec {
    /// Removes the objects and versions its rules match (`MinIO`'s `expire`).
    Expire(ExpireJob),
    /// Seals encrypted versions' data keys again, under another KMS key (`MinIO`'s
    /// `keyrotate`).
    KeyRotate(KeyRotateJob),
    /// Copies objects between a bucket here and one on another S3 service, either way
    /// (`MinIO`'s `replicate`).
    Replicate(ReplicateJob),
    /// One operation on each object a manifest lists, as an IAM role (S3 Batch
    /// Operations).
    Operation(OperationJob),
}

impl JobSpec {
    /// The kind, as `MinIO` names it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Expire(_) => "expire",
            Self::KeyRotate(_) => "keyrotate",
            Self::Replicate(_) => "replicate",
            Self::Operation(_) => "operation",
        }
    }

    /// Whether it's one of `MinIO`'s kinds, which `mc batch` lists; S3 Batch
    /// Operations' jobs are listed apart.
    #[must_use]
    pub const fn is_minio(&self) -> bool {
        !matches!(self, Self::Operation(_))
    }

    /// The bucket it works on: a `replicate` job's here, an operation's manifest's.
    #[must_use]
    pub fn bucket(&self) -> &str {
        match self {
            Self::Expire(job) => &job.bucket,
            Self::KeyRotate(job) => &job.bucket,
            Self::Replicate(job) => &job.here().bucket,
            Self::Operation(job) => &job.manifest.bucket,
        }
    }

    /// Where its result is sent, if anywhere.
    #[must_use]
    pub const fn notify(&self) -> Option<&JobNotify> {
        match self {
            Self::Expire(job) => job.notify.as_ref(),
            Self::KeyRotate(job) => job.notify.as_ref(),
            Self::Replicate(job) => job.notify.as_ref(),
            Self::Operation(_) => None,
        }
    }

    /// How often what fails is tried again.
    #[must_use]
    pub const fn retry(&self) -> JobRetry {
        match self {
            Self::Expire(job) => job.retry,
            Self::KeyRotate(job) => job.retry,
            Self::Replicate(job) => job.retry,
            Self::Operation(_) => JobRetry::DEFAULT,
        }
    }
}

/// `MinIO`'s `expire` job: for each object whose newest version (or delete marker) a
/// rule matches, removes it with all its versions, or its versions but the newest
/// `retain_versions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpireJob {
    /// The bucket.
    pub bucket: String,
    /// The prefixes it looks under (none: the whole bucket).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
    /// The rules, the first that matches an object deciding.
    pub rules: Vec<ExpireRule>,
    /// Where its result is sent, if anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<JobNotify>,
    /// How often it's tried again.
    #[serde(default)]
    pub retry: JobRetry,
}

/// Which objects a rule of an `expire` job takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExpireKind {
    /// Objects whose newest version is an object.
    Object,
    /// Objects whose newest version is a delete marker.
    Deleted,
}

/// A rule of an `expire` job; every condition given must hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpireRule {
    /// Which objects.
    pub kind: ExpireKind,
    /// Their keys match this, with `*` and `?`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// They were made more than this many seconds ago.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub older_than_secs: Option<u64>,
    /// They were made before this (Unix milliseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_before_ms: Option<i64>,
    /// They have each of these tags (values with `*` and `?`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<KeyValue>,
    /// They have each of these metadata (user metadata or standard headers, values
    /// with `*` and `?`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata: Vec<KeyValue>,
    /// They're smaller than this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_less_than: Option<u64>,
    /// They're larger than this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_greater_than: Option<u64>,
    /// How many of their newest versions stay (0: the object goes, every version).
    #[serde(default)]
    pub retain_versions: u32,
}

/// `MinIO`'s `keyrotate` job: seals the data key of each SSE-S3 or SSE-KMS version under
/// its prefix that the filter takes again, under the managed key's newest version or a
/// KMS key it names. The data isn't touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRotateJob {
    /// The bucket.
    pub bucket: String,
    /// The prefix it looks under (empty: the whole bucket).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// What seals the keys from now on.
    pub encryption: RotateTo,
    /// Which versions.
    #[serde(default)]
    pub filter: VersionFilter,
    /// Where its result is sent, if anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<JobNotify>,
    /// How often a version that fails is tried again.
    #[serde(default)]
    pub retry: JobRetry,
}

/// What seals a `keyrotate` job's keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RotateTo {
    /// The managed key (SSE-S3), its newest version; SSE-KMS versions can't go back to it.
    S3,
    /// A KMS key (SSE-KMS), with an encryption context of the client's.
    Kms {
        /// The key.
        key: String,
        /// The context.
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        context: std::collections::BTreeMap<String, String>,
    },
}

/// Which versions a `keyrotate` or `replicate` job takes; every condition given must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionFilter {
    /// Made less than this many seconds ago.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newer_than_secs: Option<u64>,
    /// Made at least this many seconds ago.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub older_than_secs: Option<u64>,
    /// Made after this (Unix milliseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_after_ms: Option<i64>,
    /// Made before this (Unix milliseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_before_ms: Option<i64>,
    /// With any of these tags (values with `*` and `?`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<KeyValue>,
    /// With any of these metadata (values with `*` and `?`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata: Vec<KeyValue>,
    /// Sealed by this KMS key now (`keyrotate` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key: Option<String>,
}

/// `MinIO`'s `replicate` job: copies each version under the source's prefixes that the
/// filter takes to the target, under its prefix. One end is a bucket here, the other a
/// bucket on another S3 service. Between two that keep versions (`MinIO`'s and TeiFS's
/// kind), every version and delete marker goes, keeping its id and time; when either is
/// plain S3, each key's current object, as a new version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicateJob {
    /// Where the objects are.
    pub source: ReplicateEnd,
    /// Where they go.
    pub target: ReplicateEnd,
    /// Which versions.
    #[serde(default)]
    pub filter: VersionFilter,
    /// Where its result is sent, if anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<JobNotify>,
    /// How often a version that fails is tried again.
    #[serde(default)]
    pub retry: JobRetry,
}

impl ReplicateJob {
    /// The end that's a bucket here.
    #[must_use]
    pub const fn here(&self) -> &ReplicateEnd {
        if self.source.remote.is_some() {
            &self.target
        } else {
            &self.source
        }
    }

    /// Whether versions go as they are, with their ids, times and delete markers: both
    /// ends keep them so.
    #[must_use]
    pub fn keeps_versions(&self) -> bool {
        self.source.kind == EndKind::Minio && self.target.kind == EndKind::Minio
    }
}

/// An end of a `replicate` job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicateEnd {
    /// What kind of service it is.
    pub kind: EndKind,
    /// The bucket.
    pub bucket: String,
    /// The source's prefixes (none: the whole bucket); the target's one, which the keys
    /// go under.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
    /// The service, when it isn't this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteEnd>,
}

/// What kind of service an end of a `replicate` job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EndKind {
    /// One that keeps versions' ids and times when told (`MinIO`, TeiFS).
    Minio,
    /// Plain S3.
    S3,
}

/// Another S3 service an end of a `replicate` job is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEnd {
    /// Its URL (`http[s]://HOST[:PORT]`).
    pub endpoint: String,
    /// The access key; its secret is kept sealed apart.
    pub access_key: String,
    /// Whether buckets are named in the path (`true`), the host (`false`), or as suits
    /// the service (`None`: in the host on AWS, else the path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_style: Option<bool>,
    /// Whether a session token goes with the keys; it's kept sealed apart.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub session_token: bool,
}

/// An S3 Batch Operations job: its operation, the manifest that lists its objects, and
/// the role its tasks run as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationJob {
    /// What it does to each object.
    pub operation: Operation,
    /// The objects.
    pub manifest: Manifest,
    /// The IAM role its tasks run as.
    pub role_arn: String,
    /// Its description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Whether it waits for a person to confirm it before it runs.
    #[serde(default)]
    pub confirmation_required: bool,
    /// The token that made it: the same request again makes no other.
    pub client_token: String,
    /// Its tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<KeyValue>,
    /// Where its completion report goes, if anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<JobReport>,
    /// Why its status last changed, when someone said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_reason: Option<String>,
}

/// What an S3 Batch Operations job does to each object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Operation {
    /// Replaces its tags (`S3PutObjectTagging`).
    PutObjectTagging {
        /// The tags.
        #[serde(default)]
        tags: Vec<KeyValue>,
    },
    /// Removes its tags (`S3DeleteObjectTagging`).
    DeleteObjectTagging,
    /// Puts a legal hold on it or takes it off (`S3PutObjectLegalHold`).
    PutObjectLegalHold {
        /// On or off.
        on: bool,
    },
    /// Sets its retention (`S3PutObjectRetention`); without a mode, takes it off.
    PutObjectRetention {
        /// `GOVERNANCE` or `COMPLIANCE`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
        /// Until when (Unix milliseconds).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retain_until_ms: Option<i64>,
        /// Whether governance-mode retention may be shortened or taken off.
        #[serde(default)]
        bypass_governance: bool,
    },
}

impl Operation {
    /// Its name in S3 Control (`ListJobs`' `Operation`).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PutObjectTagging { .. } => "S3PutObjectTagging",
            Self::DeleteObjectTagging => "S3DeleteObjectTagging",
            Self::PutObjectLegalHold { .. } => "S3PutObjectLegalHold",
            Self::PutObjectRetention { .. } => "S3PutObjectRetention",
        }
    }
}

/// The CSV object that lists an S3 Batch Operations job's objects
/// (`S3BatchOperations_CSV_20180820`), pinned to the version it was when the job was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// Its bucket.
    pub bucket: String,
    /// Its key.
    pub key: String,
    /// Its version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// Its `ETag`, quoted.
    pub etag: String,
    /// What each column is.
    pub fields: Vec<ManifestField>,
}

/// A column of a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestField {
    /// Skipped.
    Ignore,
    /// The object's bucket.
    Bucket,
    /// The object's key, URL-encoded.
    Key,
    /// The object's version.
    VersionId,
}

impl ManifestField {
    /// Its name in S3 Control.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ignore => "Ignore",
            Self::Bucket => "Bucket",
            Self::Key => "Key",
            Self::VersionId => "VersionId",
        }
    }
}

/// Where an S3 Batch Operations job's completion report goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobReport {
    /// The bucket.
    pub bucket: String,
    /// The prefix its files go under (`job-{id}/` follows).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// Whether it lists failed tasks only.
    #[serde(default)]
    pub failed_only: bool,
}

/// A key and a value a condition needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyValue {
    /// The key.
    pub key: String,
    /// The value, with `*` and `?`.
    pub value: String,
}

impl KeyValue {
    /// Whether `key` and `value` are this one's: the key the same but for case, the
    /// value matching.
    #[must_use]
    pub fn matches(&self, key: &str, value: &str) -> bool {
        self.key.eq_ignore_ascii_case(key) && wildcard(&self.value, value)
    }
}

/// Where a job's result is sent when it ends: `POST`ed as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobNotify {
    /// The URL.
    pub endpoint: String,
    /// Whether an `Authorization` token is sent; the token itself is kept sealed apart.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub token: bool,
}

/// How often a job is tried again when it fails as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobRetry {
    /// How many times it's run in all, at most.
    pub attempts: u32,
    /// How long it waits before running again, in milliseconds.
    pub delay_ms: u64,
}

impl JobRetry {
    /// Three runs, half a second apart.
    pub const DEFAULT: Self = Self {
        attempts: 3,
        delay_ms: 500,
    };
}

impl Default for JobRetry {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How far a job got.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobProgress {
    /// When it started running (Unix milliseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_ms: Option<i64>,
    /// When it last moved on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_ms: Option<i64>,
    /// The key it finished last: it goes on after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_key: Option<String>,
    /// With `last_key`, the version it finished last, where a listing goes on from a
    /// version (another service's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_version: Option<String>,
    /// The prefix it's working under (an index into the job's prefixes).
    #[serde(default)]
    pub prefix: usize,
    /// Objects (versions) whose task succeeded.
    #[serde(default)]
    pub objects: u64,
    /// Objects whose task failed.
    #[serde(default)]
    pub objects_failed: u64,
    /// Delete markers whose task succeeded.
    #[serde(default)]
    pub delete_markers: u64,
    /// Delete markers whose task failed.
    #[serde(default)]
    pub delete_markers_failed: u64,
    /// Bytes the succeeded tasks took.
    #[serde(default)]
    pub bytes: u64,
    /// Bytes of the failed ones.
    #[serde(default)]
    pub bytes_failed: u64,
    /// How many times it ran again after failing as a whole.
    #[serde(default)]
    pub retry_attempts: u32,
    /// How many tasks it has, once its manifest was read (an S3 Batch Operations job's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Where in its manifest it goes on, in bytes.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub offset: u64,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Whether `text` matches `pattern`, where `*` is any run of characters and `?` any one.
#[must_use]
pub fn wildcard(pattern: &str, text: &str) -> bool {
    let (pattern, text): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), text.chars().collect());
    let (mut p, mut t) = (0, 0);
    // Where the last `*` was, and the text position it was tried at.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == '?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((at, tried)) => {
                    p = at + 1;
                    t = tried + 1;
                    star = Some((at, tried + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_match_runs_and_single_characters() {
        assert!(wildcard("*", ""));
        assert!(wildcard("*", "anything"));
        assert!(wildcard("pick*", "pickles"));
        assert!(!wildcard("pick*", "apick"));
        assert!(wildcard("image/*", "image/png"));
        assert!(wildcard("a?c", "abc"));
        assert!(!wildcard("a?c", "ac"));
        assert!(wildcard("*.log", "logs/2026/app.log"));
        assert!(!wildcard("*.log", "app.log.gz"));
        assert!(wildcard("a*b*c", "axxbyyc"));
        assert!(!wildcard("a*b*c", "axxbyy"));
        assert!(wildcard("", ""));
        assert!(!wildcard("", "a"));
        assert!(wildcard("ü*", "über"));
    }

    #[test]
    fn keys_match_without_case_and_values_with_wildcards() {
        let kv = KeyValue {
            key: "Content-Type".to_owned(),
            value: "image/*".to_owned(),
        };
        assert!(kv.matches("content-type", "image/jpeg"));
        assert!(!kv.matches("content-type", "text/plain"));
        assert!(!kv.matches("content-length", "image/jpeg"));
    }

    #[test]
    fn finished_jobs_are_complete_cancelled_or_failed() {
        assert!(JobStatus::Complete.finished());
        assert!(JobStatus::Cancelled.finished());
        assert!(JobStatus::Failed.finished());
        assert!(!JobStatus::Active.finished());
        assert!(!JobStatus::Cancelling.finished());
        assert_eq!(JobStatus::Suspended.as_str(), "Suspended");
    }

    #[test]
    fn a_replicate_job_works_on_its_local_end_and_keeps_versions_between_minios() {
        let end = |bucket: &str, kind, remote: bool| ReplicateEnd {
            kind,
            bucket: bucket.to_owned(),
            prefixes: Vec::new(),
            remote: remote.then(|| RemoteEnd {
                endpoint: "https://backup.example.com".to_owned(),
                access_key: "AKIAEXAMPLE".to_owned(),
                path_style: None,
                session_token: false,
            }),
        };
        let job = |source, target| ReplicateJob {
            source,
            target,
            filter: VersionFilter::default(),
            notify: None,
            retry: JobRetry::default(),
        };
        let push = job(
            end("here", EndKind::Minio, false),
            end("there", EndKind::Minio, true),
        );
        assert_eq!(push.here().bucket, "here");
        assert!(push.keeps_versions());
        let pull = job(
            end("there", EndKind::Minio, true),
            end("here", EndKind::S3, false),
        );
        assert_eq!(pull.here().bucket, "here");
        assert!(!pull.keeps_versions());
        assert!(
            !job(
                end("here", EndKind::S3, false),
                end("there", EndKind::Minio, true)
            )
            .keeps_versions()
        );
        assert_eq!(JobSpec::Replicate(pull).bucket(), "here");
    }
}
