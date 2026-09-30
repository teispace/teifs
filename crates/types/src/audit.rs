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

/// Which requests a live trace shows; each set field narrows it, and the default shows
/// every request. Sent as a query: `errors=true`, `api=NAME` (repeated), `bucket=NAME`,
/// `prefix=KEY`, `status=CODE` (repeated), `slowerThanMs=MS`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceFilter {
    /// Only errors: statuses from 400.
    pub errors: bool,
    /// Only these operations (`PutObject`).
    pub apis: Vec<String>,
    /// Only requests on this bucket.
    pub bucket: Option<String>,
    /// Only requests on keys starting with this.
    pub prefix: Option<String>,
    /// Only these HTTP statuses.
    pub statuses: Vec<u16>,
    /// Only requests that took at least this long, in milliseconds.
    pub slower_than_ms: Option<u64>,
}

impl TraceFilter {
    /// Whether `entry` is shown.
    #[must_use]
    pub fn matches(&self, entry: &AuditEntry) -> bool {
        let api = &entry.api;
        let took_ms = || api.time_to_response_in_ns.parse::<u64>().unwrap_or(0) / 1_000_000;
        (!self.errors || api.status_code >= 400)
            && (self.apis.is_empty() || self.apis.contains(&api.name))
            && self.bucket.as_ref().is_none_or(|b| *b == api.bucket)
            && self
                .prefix
                .as_ref()
                .is_none_or(|p| api.object.starts_with(p.as_str()))
            && (self.statuses.is_empty() || self.statuses.contains(&api.status_code))
            && self.slower_than_ms.is_none_or(|ms| took_ms() >= ms)
    }

    /// As a query string (empty for the default).
    #[must_use]
    pub fn to_query(&self) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        if self.errors {
            query.append_pair("errors", "true");
        }
        for api in &self.apis {
            query.append_pair("api", api);
        }
        if let Some(bucket) = &self.bucket {
            query.append_pair("bucket", bucket);
        }
        if let Some(prefix) = &self.prefix {
            query.append_pair("prefix", prefix);
        }
        for status in &self.statuses {
            query.append_pair("status", &status.to_string());
        }
        if let Some(ms) = self.slower_than_ms {
            query.append_pair("slowerThanMs", &ms.to_string());
        }
        query.finish()
    }

    /// Reads a query string.
    ///
    /// # Errors
    ///
    /// A parameter it doesn't know, or a value that isn't one.
    pub fn from_query(query: &str) -> Result<Self, String> {
        let mut filter = Self::default();
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            let number = |what: &str| format!("`{name}` needs {what}, not `{value}`");
            match &*name {
                "errors" => {
                    filter.errors = value.parse().map_err(|_| number("true or false"))?;
                }
                "api" => filter.apis.push(value.into_owned()),
                "bucket" => filter.bucket = Some(value.into_owned()),
                "prefix" => filter.prefix = Some(value.into_owned()),
                "status" => filter
                    .statuses
                    .push(value.parse().map_err(|_| number("an HTTP status"))?),
                "slowerThanMs" => {
                    filter.slower_than_ms =
                        Some(value.parse().map_err(|_| number("milliseconds"))?);
                }
                _ => return Err(format!("`{name}` isn't a trace filter")),
            }
        }
        Ok(filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, bucket: &str, object: &str, status: u16, ms: u64) -> AuditEntry {
        AuditEntry {
            api: AuditApi {
                name: name.into(),
                bucket: bucket.into(),
                object: object.into(),
                status_code: status,
                time_to_response_in_ns: (ms * 1_000_000).to_string(),
                ..AuditApi::default()
            },
            ..AuditEntry::default()
        }
    }

    #[test]
    fn filters_narrow_and_travel_as_a_query() {
        let put = entry("PutObject", "photos", "2026/a.jpg", 200, 5);
        let missing = entry("GetObject", "photos", "2025/b.jpg", 404, 1);
        let slow = entry("ListObjectsV2", "logs", "", 200, 1500);
        let all = TraceFilter::default();
        assert!([&put, &missing, &slow].iter().all(|e| all.matches(e)));
        assert_eq!(all.to_query(), "");
        let cases = [
            (
                TraceFilter {
                    errors: true,
                    ..TraceFilter::default()
                },
                [false, true, false],
            ),
            (
                TraceFilter {
                    apis: vec!["PutObject".into(), "ListObjectsV2".into()],
                    ..TraceFilter::default()
                },
                [true, false, true],
            ),
            (
                TraceFilter {
                    bucket: Some("photos".into()),
                    prefix: Some("2026/".into()),
                    ..TraceFilter::default()
                },
                [true, false, false],
            ),
            (
                TraceFilter {
                    statuses: vec![404],
                    ..TraceFilter::default()
                },
                [false, true, false],
            ),
            (
                TraceFilter {
                    slower_than_ms: Some(1000),
                    ..TraceFilter::default()
                },
                [false, false, true],
            ),
        ];
        for (filter, shown) in cases {
            let got = [&put, &missing, &slow].map(|e| filter.matches(e));
            assert_eq!(got, shown, "{filter:?}");
            assert_eq!(TraceFilter::from_query(&filter.to_query()), Ok(filter));
        }
        let odd = TraceFilter {
            prefix: Some("a b&c=d/é".into()),
            ..TraceFilter::default()
        };
        assert_eq!(TraceFilter::from_query(&odd.to_query()), Ok(odd));
        for bad in [
            "errors=maybe",
            "status=abc",
            "slowerThanMs=-1",
            "method=GET",
        ] {
            assert!(TraceFilter::from_query(bad).is_err(), "{bad}");
        }
    }
}
