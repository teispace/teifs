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
}

impl JobSpec {
    /// The kind, as `MinIO` names it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Expire(_) => "expire",
        }
    }

    /// The bucket it works on.
    #[must_use]
    pub fn bucket(&self) -> &str {
        match self {
            Self::Expire(job) => &job.bucket,
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

impl Default for JobRetry {
    fn default() -> Self {
        Self {
            attempts: 3,
            delay_ms: 500,
        }
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
}
