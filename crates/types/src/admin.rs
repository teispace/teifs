//! The admin API's messages: JSON under `/.teifs/admin/v1/`, signed like S3 requests.
//! The server writes them and clients read them, so both use these types; values that
//! name a choice (a layout, a durability) are strings, so a client keeps working when
//! a later server adds one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Where the admin API is. A bucket name can't start with a dot, so no path-style
/// request for a bucket starts with this.
pub const ADMIN_PREFIX: &str = "/.teifs/admin/v1/";

/// `GET`: [`ServerInfo`].
pub const ADMIN_INFO: &str = "/.teifs/admin/v1/info";

/// `GET`: [`ServerConfig`].
pub const ADMIN_CONFIG: &str = "/.teifs/admin/v1/config";

/// What a server is and how it's doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    /// The TeiFS version it runs.
    pub version: String,
    /// The drive's id.
    pub drive: String,
    /// The drive's AWS account id: 12 digits.
    pub account: String,
    /// When it started, in milliseconds since the Unix epoch.
    pub started_ms: i64,
    /// How long it has been running.
    pub uptime_seconds: u64,
    /// What each background job has done since it started, by name.
    pub jobs: BTreeMap<String, JobInfo>,
}

/// What a background job has done.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobInfo {
    /// Steps run.
    pub steps: u64,
    /// Items handled (uploads expired, files swept, …).
    pub items: u64,
    /// When a step last handled something, in milliseconds since the Unix epoch.
    pub last_progress_ms: Option<i64>,
    /// The last step's error, if it failed.
    pub last_error: Option<String>,
}

/// How a server was started. Secrets are never part of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is a separate setting of the server"
)]
pub struct ServerConfig {
    /// The address it listens on.
    pub listen: String,
    /// Domains for virtual-hosted-style requests.
    pub domains: Vec<String>,
    /// The layout of buckets created without choosing one: `folder` or `object`.
    pub default_layout: String,
    /// How hard writes are made to survive a power cut: `strict`, `relaxed` or `none`.
    pub durability: String,
    /// Which names folder buckets may create: `portable` or `host`.
    pub key_names: String,
    /// Where the KMS keys are.
    pub kms: KmsConfig,
    /// Where the root user's key comes from: `drive` (generated, in the drive's
    /// `.teifs/credentials.json`) or `given` (the environment, flags or a file).
    pub root_credentials: String,
    /// Whether buckets without their own setting accept SSE-C.
    pub allow_sse_c: bool,
    /// Whether plain HTTP counts as a secure connection for SSE-C keys.
    pub plain_http_is_secure: bool,
    /// Whether Signature Version 2 is accepted.
    pub allow_sig_v2: bool,
    /// Whether new buckets start with ACLs enabled and no Block Public Access.
    pub legacy_bucket_defaults: bool,
    /// How long an unfinished multipart upload is kept; none for ever.
    pub upload_expiry_seconds: Option<u64>,
    /// The background jobs' pause after a busy step, as a multiple of its duration.
    pub job_pace: f64,
    /// How long a client has to send a request's headers.
    pub header_timeout_seconds: u64,
    /// How long a request body may stop arriving.
    pub body_timeout_seconds: u64,
    /// The most connections served at once.
    pub max_connections: usize,
}

/// Where a server's KMS keys are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum KmsConfig {
    /// A keyring file on the server's machine.
    Keyring {
        /// Its path.
        path: String,
    },
    /// A Vault or OpenBao transit engine.
    Transit {
        /// Its address.
        address: String,
    },
}

/// Why an admin request failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminError {
    /// What went wrong, as a code: `AccessDenied`, `NotFound`, ….
    pub code: String,
    /// What went wrong, for a person.
    pub message: String,
    /// The request's id, as the server logged it.
    pub request_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_under_the_prefix_and_never_a_bucket() {
        for path in [ADMIN_INFO, ADMIN_CONFIG] {
            assert!(path.starts_with(ADMIN_PREFIX), "{path}");
        }
        let first = ADMIN_PREFIX.trim_start_matches('/').split('/').next();
        assert!(crate::check_bucket(first.unwrap_or_default()).is_err());
    }

    #[test]
    fn messages_are_camel_case_json() {
        let info = ServerInfo {
            version: "1.0.0".into(),
            drive: "d".into(),
            account: "123456789012".into(),
            started_ms: 1,
            uptime_seconds: 2,
            jobs: BTreeMap::from([("housekeeping".into(), JobInfo::default())]),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["startedMs"], 1);
        assert_eq!(
            json["jobs"]["housekeeping"]["lastProgressMs"],
            serde_json::Value::Null
        );
        assert_eq!(serde_json::from_value::<ServerInfo>(json).unwrap(), info);
        let kms = serde_json::to_value(KmsConfig::Transit {
            address: "https://vault:8200".into(),
        })
        .unwrap();
        assert_eq!(
            kms,
            serde_json::json!({"kind": "transit", "address": "https://vault:8200"})
        );
    }
}
