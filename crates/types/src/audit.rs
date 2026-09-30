//! The audit log: one JSON object per request, on a line of its own, with `MinIO`'s field
//! names (madmin-go's `audit.Entry`), so tools written for `MinIO`'s audit log read
//! TeiFS's. Secrets are never in it: signatures, session tokens and SSE-C keys are
//! removed from the headers and query before an entry is made.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The entries' format version.
pub const AUDIT_VERSION: &str = "1";

/// What a request asked and what it was answered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// [`AUDIT_VERSION`].
    pub version: String,
    /// The drive's id.
    #[serde(rename = "deploymentid")]
    pub deployment_id: String,
    /// When the request arrived: RFC 3339, UTC, with nanoseconds.
    pub time: String,
    /// Which API: `S3`, `Admin`, `IAM`, `STS` or `Control`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `incoming`: a client's request.
    pub trigger: String,
    /// The operation and its result.
    pub api: AuditApi,
    /// The client's address (a trusted proxy's client, behind one).
    #[serde(
        rename = "remotehost",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub remote_host: String,
    /// The request's id, as in its answer's `x-amz-request-id`.
    #[serde(rename = "requestID")]
    pub request_id: String,
    /// The client's `User-Agent`.
    #[serde(
        rename = "userAgent",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub user_agent: String,
    /// The request's path, as sent.
    #[serde(rename = "requestPath")]
    pub request_path: String,
    /// Its `Host`.
    #[serde(
        rename = "requestHost",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub request_host: String,
    /// Its query parameters, decoded.
    #[serde(
        rename = "requestQuery",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub request_query: BTreeMap<String, String>,
    /// Its headers, by lower-case name; repeated ones joined with commas.
    #[serde(
        rename = "requestHeader",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub request_header: BTreeMap<String, String>,
    /// The answer's headers.
    #[serde(
        rename = "responseHeader",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub response_header: BTreeMap<String, String>,
    /// The access key it was signed with; none when unsigned.
    #[serde(
        rename = "accessKey",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub access_key: String,
    /// The error code it was answered with, if any (`NoSuchKey`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// The operation a request was, and how it went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditApi {
    /// The operation (`PutObject`), or `unknown` for one refused before its signature
    /// was accepted.
    pub name: String,
    /// The bucket it's on.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bucket: String,
    /// The key it's on.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub object: String,
    /// The HTTP status's reason (`OK`, `Not Found`).
    pub status: String,
    /// The HTTP status.
    pub status_code: u16,
    /// Request body bytes read.
    pub rx: u64,
    /// Answer body bytes sent.
    pub tx: u64,
    /// Time until the answer's headers were ready: nanoseconds, then `ns`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub time_to_first_byte: String,
    /// Time until the answer's last byte was sent: nanoseconds, then `ns`.
    pub time_to_response: String,
    /// The same, as a number of nanoseconds.
    #[serde(rename = "timeToResponseInNS")]
    pub time_to_response_in_ns: String,
}
