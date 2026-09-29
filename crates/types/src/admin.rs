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

/// `GET`: the account's IAM as an [`IamExport`], access keys without their secrets.
/// `PUT`: imports an [`IamExport`] into an empty IAM (root user only), answering an
/// [`ImportReport`]; `?account=adopt` also takes the export's account id.
pub const ADMIN_IAM: &str = "/.teifs/admin/v1/iam";

/// `GET`: the account's IAM with access keys' secrets (root user only).
pub const ADMIN_IAM_SECRETS: &str = "/.teifs/admin/v1/iam/secrets";

/// `POST`: replaces the root user's access key and answers the new one, a
/// [`RootKeyRotated`] (root user only). Only for a key the drive generated: one given
/// through the environment, a flag or a file is changed there.
pub const ADMIN_ROOT_KEY: &str = "/.teifs/admin/v1/root-key";

/// The root user's new access key, shown only in this answer and the drive's
/// credentials file.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootKeyRotated {
    /// The access key id.
    pub access_key: String,
    /// The secret key.
    pub secret_key: String,
}

impl std::fmt::Debug for RootKeyRotated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootKeyRotated")
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

/// The format of an [`IamExport`]; a server refuses any other.
pub const IAM_FORMAT: &str = "teifs-iam/1";

/// An account's IAM: its managed policies, groups and users, which refer to each other
/// by name, so an export can be imported into another drive's account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IamExport {
    /// [`IAM_FORMAT`].
    pub format: String,
    /// The account it was exported from.
    pub account: String,
    /// Customer-managed policies.
    pub policies: Vec<ExportedPolicy>,
    /// Groups.
    pub groups: Vec<ExportedGroup>,
    /// Users.
    pub users: Vec<ExportedUser>,
    /// Roles.
    #[serde(default)]
    pub roles: Vec<ExportedRole>,
    /// OpenID Connect providers.
    #[serde(default)]
    pub oidc_providers: Vec<ExportedOidcProvider>,
}

/// A customer-managed policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportedPolicy {
    /// Its name.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its description.
    #[serde(default)]
    pub description: String,
    /// Its tags.
    #[serde(default)]
    pub tags: Vec<Tag>,
    /// Its versions, oldest first; one is the default. An import numbers them again from
    /// `v1`.
    pub versions: Vec<ExportedVersion>,
}

/// A version of a managed policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportedVersion {
    /// The document, as given.
    pub document: String,
    /// Whether it's the version in effect.
    #[serde(default)]
    pub is_default: bool,
}

/// A group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportedGroup {
    /// Its name.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its inline policies' documents, by name.
    #[serde(default)]
    pub inline: BTreeMap<String, String>,
    /// The names of the managed policies attached to it.
    #[serde(default)]
    pub attached: Vec<String>,
}

/// A user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportedUser {
    /// Its name.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its tags.
    #[serde(default)]
    pub tags: Vec<Tag>,
    /// The name of the managed policy that is its permissions boundary.
    #[serde(default)]
    pub boundary: Option<String>,
    /// The names of the groups it's in.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Its inline policies' documents, by name.
    #[serde(default)]
    pub inline: BTreeMap<String, String>,
    /// The names of the managed policies attached to it.
    #[serde(default)]
    pub attached: Vec<String>,
    /// Its access keys, oldest first.
    #[serde(default)]
    pub access_keys: Vec<ExportedKey>,
}

/// A role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportedRole {
    /// Its name.
    pub name: String,
    /// Its path.
    pub path: String,
    /// Its description.
    #[serde(default)]
    pub description: String,
    /// Its trust policy: who may assume it.
    pub trust_policy: String,
    /// The longest session it allows, in seconds.
    pub max_session_duration: u32,
    /// Its tags.
    #[serde(default)]
    pub tags: Vec<Tag>,
    /// The name of the managed policy that is its permissions boundary.
    #[serde(default)]
    pub boundary: Option<String>,
    /// Its inline policies' documents, by name.
    #[serde(default)]
    pub inline: BTreeMap<String, String>,
    /// The names of the managed policies attached to it.
    #[serde(default)]
    pub attached: Vec<String>,
}

/// An OpenID Connect identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportedOidcProvider {
    /// Its URL: the issuer its tokens name.
    pub url: String,
    /// The audiences its tokens may be for.
    #[serde(default)]
    pub client_ids: Vec<String>,
    /// The thumbprints of the certificates it's pinned to.
    #[serde(default)]
    pub thumbprints: Vec<String>,
    /// Its tags.
    #[serde(default)]
    pub tags: Vec<Tag>,
}

/// An access key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportedKey {
    /// The access key id.
    pub id: String,
    /// Whether requests signed with it are accepted.
    pub active: bool,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Its secret key: only in an export with secrets. An import skips a key without
    /// one (and reports it), since no one could sign with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl std::fmt::Debug for ExportedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportedKey")
            .field("id", &self.id)
            .field("active", &self.active)
            .field("created_ms", &self.created_ms)
            .field("secret", &self.secret.as_ref().map(|_| "…"))
            .finish()
    }
}

/// A tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tag {
    /// Its key.
    pub key: String,
    /// Its value.
    pub value: String,
}

/// What an import made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    /// The account's id after the import.
    pub account: String,
    /// Managed policies created.
    pub policies: usize,
    /// Groups created.
    pub groups: usize,
    /// Users created.
    pub users: usize,
    /// Roles created.
    #[serde(default)]
    pub roles: usize,
    /// OpenID Connect providers created.
    #[serde(default)]
    pub oidc_providers: usize,
    /// Access keys imported.
    pub access_keys: usize,
    /// Access keys skipped because the export has no secret for them.
    pub keys_without_secrets: Vec<String>,
}

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
        for path in [
            ADMIN_INFO,
            ADMIN_CONFIG,
            ADMIN_IAM,
            ADMIN_IAM_SECRETS,
            ADMIN_ROOT_KEY,
        ] {
            assert!(path.starts_with(ADMIN_PREFIX), "{path}");
        }
        let first = ADMIN_PREFIX.trim_start_matches('/').split('/').next();
        assert!(crate::check_bucket(first.unwrap_or_default()).is_err());
    }

    #[test]
    fn exported_secrets_never_show_in_debug_output() {
        let key = ExportedKey {
            id: "TKIAEXAMPLE".into(),
            active: true,
            created_ms: 1,
            secret: Some("do-not-print".into()),
        };
        assert!(!format!("{key:?}").contains("do-not-print"));
        let rotated = RootKeyRotated {
            access_key: "TFROOT".into(),
            secret_key: "do-not-print".into(),
        };
        assert!(!format!("{rotated:?}").contains("do-not-print"));
        let json = serde_json::to_value(ExportedKey {
            secret: None,
            ..key
        })
        .unwrap();
        assert!(json.get("secret").is_none(), "{json}");
    }

    #[test]
    fn an_export_with_unknown_fields_is_refused() {
        let export = serde_json::json!({
            "format": IAM_FORMAT, "account": "123456789012",
            "policies": [], "groups": [], "users": [{"name": "a", "path": "/", "admin": true}]
        });
        assert!(serde_json::from_value::<IamExport>(export).is_err());
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
