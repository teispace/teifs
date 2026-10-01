//! The audit log's entries, made from what the observer saw of a request: who asked
//! what of which bucket and key, how it was answered, the bytes and the time. Where they
//! go is the server's business ([`AuditSink`]); what goes in them is decided here, and a
//! secret never does: signatures, session tokens, cookies and SSE-C keys are replaced by
//! [`REDACTED`] before an entry is made.

use std::{collections::BTreeMap, net::IpAddr, time::SystemTime};

use http::{HeaderMap, Request, StatusCode};
use teifs_types::audit::{AUDIT_VERSION, AuditApi, AuditEntry};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::observe::{Answer, Seen};

/// Where audit entries go: a file, standard output, a webhook.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Takes an entry, or refuses it (returns false) when it can't keep up, so a slow
    /// destination never slows requests down; refusals are counted in the metrics.
    fn log(&self, entry: AuditEntry) -> bool;
}

/// What a secret's value is replaced with.
pub const REDACTED: &str = "REDACTED";

/// Headers whose values are secrets, or enough to replay a request.
const SECRET_HEADERS: [&str; 6] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-amz-security-token",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-copy-source-server-side-encryption-customer-key",
];

/// Query parameters that are: a presigned link's signature is the link's whole power,
/// and MinIO's clients send STS's proofs in the query (a password, a token).
const SECRET_QUERY: [&str; 8] = [
    "x-amz-signature",
    "x-amz-security-token",
    "signature",
    "ldappassword",
    "webidentitytoken",
    "webidentityaccesstoken",
    "samlassertion",
    "token",
];

/// What a request asked, kept from its arrival only while an audit log is kept.
#[derive(Debug)]
pub(crate) struct Asked {
    time: SystemTime,
    path: String,
    host: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    remote: Option<IpAddr>,
}

impl Asked {
    pub(crate) fn of<B>(req: &Request<B>, remote: Option<IpAddr>) -> Self {
        let uri = req.uri();
        let host = uri
            .authority()
            .map(ToString::to_string)
            .or_else(|| {
                req.headers()
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        Self {
            time: SystemTime::now(),
            path: uri.path().to_owned(),
            host,
            query: query(uri.query()),
            headers: headers(req.headers()),
            remote,
        }
    }
}

/// A query's parameters, secrets redacted.
fn query(query: Option<&str>) -> BTreeMap<String, String> {
    form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .map(|(name, value)| {
            let secret = SECRET_QUERY.iter().any(|s| name.eq_ignore_ascii_case(s));
            let value = if secret {
                REDACTED.to_owned()
            } else {
                value.into_owned()
            };
            (name.into_owned(), value)
        })
        .collect()
}

/// Headers by name, repeated ones joined with commas, secrets redacted.
fn headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers {
        let value = if SECRET_HEADERS.contains(&name.as_str()) {
            REDACTED
        } else {
            value.to_str().unwrap_or("(not text)")
        };
        out.entry(name.as_str().to_owned())
            .and_modify(|joined| {
                joined.push(',');
                joined.push_str(value);
            })
            .or_insert_with(|| value.to_owned());
    }
    out
}

/// The entry for a request.
pub(crate) fn entry(
    drive: &str,
    asked: Asked,
    seen: &Seen,
    answer: &Answer,
    response_headers: &HeaderMap,
) -> AuditEntry {
    let (bucket, object) = seen.target().unwrap_or_default();
    let status = answer.status;
    let time = OffsetDateTime::from(asked.time)
        .format(&Rfc3339)
        .unwrap_or_default();
    AuditEntry {
        version: AUDIT_VERSION.to_owned(),
        deployment_id: drive.to_owned(),
        time,
        kind: seen.kind().to_owned(),
        trigger: "incoming".to_owned(),
        api: AuditApi {
            name: seen.operation().to_owned(),
            bucket,
            object,
            status: status
                .canonical_reason()
                .unwrap_or_else(|| reason(status))
                .to_owned(),
            status_code: status.as_u16(),
            rx: answer.received,
            tx: answer.sent,
            time_to_first_byte: answer
                .first_byte
                .map(|d| format!("{}ns", d.as_nanos()))
                .unwrap_or_default(),
            time_to_response: format!("{}ns", answer.duration.as_nanos()),
            time_to_response_in_ns: answer.duration.as_nanos().to_string(),
        },
        remote_host: asked.remote.map(|ip| ip.to_string()).unwrap_or_default(),
        request_id: seen.id.clone(),
        user_agent: asked.headers.get("user-agent").cloned().unwrap_or_default(),
        request_path: asked.path,
        request_host: asked.host,
        request_query: asked.query,
        request_header: asked.headers,
        response_header: headers(response_headers),
        access_key: seen.access_key().unwrap_or_default().to_owned(),
        error: answer.error.clone().unwrap_or_default(),
    }
}

/// The reason of a status HTTP names none for: the client's leaving (nginx's 499).
const fn reason(status: StatusCode) -> &'static str {
    if status.as_u16() == crate::observe::CLIENT_LEFT {
        "Client Closed Request"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_reach_an_entry() {
        let mut map = HeaderMap::new();
        for name in SECRET_HEADERS {
            map.insert(name, "secret".parse().unwrap());
        }
        map.append("x-amz-meta-a", "1".parse().unwrap());
        map.append("x-amz-meta-a", "2".parse().unwrap());
        map.insert(
            "x-amz-server-side-encryption-customer-key-md5",
            "digest".parse().unwrap(),
        );
        let kept = headers(&map);
        for name in SECRET_HEADERS {
            assert_eq!(kept[name], REDACTED, "{name}");
        }
        assert_eq!(kept["x-amz-meta-a"], "1,2");
        assert_eq!(
            kept["x-amz-server-side-encryption-customer-key-md5"],
            "digest"
        );

        let kept = query(Some(
            "X-Amz-Signature=abc&x-amz-security-token=t&Signature=v2&AWSAccessKeyId=AK&X-Amz-Credential=AK%2F20260930&prefix=a%20b\
             &LDAPUsername=ann&LDAPPassword=pw&WebIdentityToken=jwt&Token=custom&WebIdentityAccessToken=at&SAMLAssertion=PHNhbWw",
        ));
        for name in [
            "X-Amz-Signature",
            "x-amz-security-token",
            "Signature",
            "LDAPPassword",
            "WebIdentityToken",
            "WebIdentityAccessToken",
            "SAMLAssertion",
            "Token",
        ] {
            assert_eq!(kept[name], REDACTED, "{name}");
        }
        assert_eq!(kept["X-Amz-Credential"], "AK/20260930");
        assert_eq!(kept["AWSAccessKeyId"], "AK");
        assert_eq!(kept["prefix"], "a b");
        assert_eq!(kept["LDAPUsername"], "ann");
    }
}
