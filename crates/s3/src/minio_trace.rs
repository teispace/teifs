//! `MinIO`'s live trace (`GET /minio/admin/v3/trace`, `mc admin trace`): each request
//! the server answers, as the `madmin.TraceInfo` `MinIO` would send for it, one JSON
//! document after another, until the caller leaves.
//!
//! S3's requests are `MinIO`'s S3 trace type; the admin, IAM, STS and control APIs'
//! are its internal type, which `mc admin trace --all` (or `--call internal`) asks for.
//! Headers and queries are the audit entry's, so their secrets are already redacted.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use s3s::{Body, S3Response, S3Result};
use serde::Serialize;
use teifs_types::{audit::AuditEntry, config_kv::go_duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    admin::error,
    trace::{Traced, Tracers},
};

/// `madmin.TraceS3`.
const TRACE_S3: u64 = 1 << 2;
/// `madmin.TraceInternal`.
const TRACE_INTERNAL: u64 = 1 << 3;
/// How often a quiet trace sends a space, as `MinIO`'s does.
const KEEP_ALIVE: Duration = Duration::from_secs(1);

/// What a trace asks for (`madmin.ServiceTraceOpts`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Options {
    /// The trace types wanted, as `madmin.TraceType` bits.
    types: u64,
    /// Only answers with a status from 400 (`err=true`).
    only_errors: bool,
    /// Only requests that took at least this long (`threshold`).
    threshold: Duration,
}

impl Options {
    /// Reads the query as `madmin`'s `ParseParams` does: `types` when it's set and not
    /// zero, else the older `s3=true`, `internal=true`… (and `all=true`).
    fn parse(query: &str) -> Result<Self, String> {
        let pairs: BTreeMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let on = |name: &str| pairs.get(name).is_some_and(|v| v == "true");
        let threshold = match pairs.get("threshold").filter(|t| !t.is_empty()) {
            Some(text) => go_duration(text)?,
            None => Duration::ZERO,
        };
        if let Some(text) = pairs.get("threshold-ttfb").filter(|t| !t.is_empty()) {
            go_duration(text)?;
        }
        let types = match pairs.get("types").filter(|t| !t.is_empty()) {
            Some(text) => text
                .parse::<u64>()
                .map_err(|_| format!("`{text}` isn't a set of trace types"))?,
            None => 0,
        };
        let types = if types == 0 {
            let mut types = 0;
            if on("s3") || on("all") {
                types |= TRACE_S3;
            }
            if on("internal") || on("all") {
                types |= TRACE_INTERNAL;
            }
            types
        } else {
            types
        };
        Ok(Self {
            types,
            only_errors: on("err"),
            threshold,
        })
    }

    /// Whether `entry`, of `kind`, is shown, as `MinIO`'s `shouldTrace` decides.
    fn shows(self, entry: &AuditEntry, kind: u64) -> bool {
        self.types & kind != 0
            && took(entry) >= self.threshold
            && !(self.only_errors && entry.api.status_code < 400)
    }
}

/// How long the request took.
fn took(entry: &AuditEntry) -> Duration {
    Duration::from_nanos(entry.api.time_to_response_in_ns.parse().unwrap_or(0))
}

/// `madmin.TraceInfo`, for an HTTP request.
#[derive(Serialize)]
struct TraceInfo<'a> {
    #[serde(rename = "type")]
    kind: u64,
    nodename: &'a str,
    funcname: String,
    time: &'a str,
    path: &'a str,
    /// Nanoseconds, as Go writes a `time.Duration`.
    dur: u128,
    bytes: u64,
    #[serde(skip_serializing_if = "str::is_empty")]
    error: &'a str,
    http: Http<'a>,
}

#[derive(Serialize)]
struct Http<'a> {
    request: Request<'a>,
    response: Response<'a>,
    stats: Stats,
}

#[derive(Serialize)]
struct Request<'a> {
    time: &'a str,
    proto: &'static str,
    method: &'a str,
    path: &'a str,
    #[serde(skip_serializing_if = "String::is_empty")]
    rawquery: String,
    headers: BTreeMap<&'a str, [&'a str; 1]>,
    client: &'a str,
}

#[derive(Serialize)]
struct Response<'a> {
    time: String,
    headers: BTreeMap<&'a str, [&'a str; 1]>,
    statuscode: u16,
}

#[derive(Serialize)]
struct Stats {
    inputbytes: u64,
    outputbytes: u64,
    /// Nanoseconds.
    timetofirstbyte: u128,
}

/// The `TraceInfo` for `entry`, and its trace type.
fn trace_info<'a>(entry: &'a AuditEntry, method: &'a str) -> (u64, TraceInfo<'a>) {
    let kind = if entry.kind == "S3" {
        TRACE_S3
    } else {
        TRACE_INTERNAL
    };
    let prefix = match entry.kind.as_str() {
        "S3" => "s3",
        "STS" => "sts",
        _ => "admin",
    };
    let took = took(entry);
    let ended = OffsetDateTime::parse(&entry.time, &Rfc3339)
        .ok()
        .and_then(|started| started.checked_add(took.try_into().ok()?))
        .and_then(|ended| ended.format(&Rfc3339).ok())
        .unwrap_or_else(|| entry.time.clone());
    let first_byte = entry
        .api
        .time_to_first_byte
        .trim_end_matches("ns")
        .parse()
        .unwrap_or(0);
    let headers = |map: &'a BTreeMap<String, String>| {
        map.iter()
            .map(|(k, v)| (k.as_str(), [v.as_str()]))
            .collect()
    };
    let mut rawquery = form_urlencoded::Serializer::new(String::new());
    rawquery.extend_pairs(&entry.request_query);
    let nodename = entry
        .request_host
        .strip_suffix(":80")
        .or_else(|| entry.request_host.strip_suffix(":443"))
        .unwrap_or(&entry.request_host);
    let info = TraceInfo {
        kind,
        nodename,
        funcname: format!("{prefix}.{}", entry.api.name),
        time: &entry.time,
        path: &entry.request_path,
        dur: took.as_nanos(),
        bytes: entry.api.rx.saturating_add(entry.api.tx),
        error: &entry.error,
        http: Http {
            request: Request {
                time: &entry.time,
                proto: "HTTP/1.1",
                method,
                path: &entry.request_path,
                rawquery: rawquery.finish(),
                headers: headers(&entry.request_header),
                client: &entry.remote_host,
            },
            response: Response {
                time: ended,
                headers: headers(&entry.response_header),
                statuscode: entry.api.status_code,
            },
            stats: Stats {
                inputbytes: entry.api.rx,
                outputbytes: entry.api.tx,
                timetofirstbyte: first_byte,
            },
        },
    };
    (kind, info)
}

/// `GET /minio/admin/v3/trace`.
pub(crate) fn trace(tracers: &Tracers, query: Option<&str>) -> S3Result<S3Response<Body>> {
    let options = Options::parse(query.unwrap_or_default())
        .map_err(|message| error(StatusCode::BAD_REQUEST, "InvalidRequest", message))?;
    let body = tracers.follow_with((KEEP_ALIVE, b" "), move |traced: Arc<Traced>| {
        let (kind, info) = trace_info(&traced.entry, &traced.method);
        options.shows(&traced.entry, kind).then(|| {
            let mut line = serde_json::to_vec(&info).expect("a trace serializes");
            line.push(b'\n');
            Bytes::from(line)
        })
    });
    let mut response = S3Response::new(body);
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use teifs_types::audit::AuditApi;

    use super::*;

    fn entry(kind: &str, status: u16, nanos: u64) -> AuditEntry {
        AuditEntry {
            time: "2026-10-02T10:00:00.5Z".to_owned(),
            kind: kind.to_owned(),
            api: AuditApi {
                name: "GetObject".to_owned(),
                status_code: status,
                rx: 10,
                tx: 20,
                time_to_first_byte: "700ns".to_owned(),
                time_to_response_in_ns: nanos.to_string(),
                ..AuditApi::default()
            },
            remote_host: "192.0.2.1".to_owned(),
            request_path: "/b/k".to_owned(),
            request_host: "s3.example.com:443".to_owned(),
            request_query: BTreeMap::from([("versionId".to_owned(), "v 1".to_owned())]),
            request_header: BTreeMap::from([("authorization".to_owned(), "REDACTED".to_owned())]),
            ..AuditEntry::default()
        }
    }

    #[test]
    fn options_are_madmin_s() {
        let typed =
            Options::parse("err=true&threshold=1.5s&threshold-ttfb=0s&types=12&s3=false").unwrap();
        assert_eq!(
            typed,
            Options {
                types: TRACE_S3 | TRACE_INTERNAL,
                only_errors: true,
                threshold: Duration::from_millis(1500),
            }
        );
        // Older clients name the types one by one; `types=0` is as if absent.
        assert_eq!(Options::parse("types=0&s3=true").unwrap().types, TRACE_S3);
        assert_eq!(
            Options::parse("all=true").unwrap().types,
            TRACE_S3 | TRACE_INTERNAL
        );
        assert_eq!(Options::parse("").unwrap(), Options::default());
        for bad in ["threshold=soon", "threshold-ttfb=1d", "types=s3"] {
            assert!(Options::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn requests_are_shown_as_minio_shows_them() {
        let options = Options::parse("types=4&err=true&threshold=1ms").unwrap();
        let slow_error = entry("S3", 404, 2_000_000);
        assert!(options.shows(&slow_error, TRACE_S3));
        assert!(!options.shows(&slow_error, TRACE_INTERNAL));
        assert!(!options.shows(&entry("S3", 200, 2_000_000), TRACE_S3));
        assert!(!options.shows(&entry("S3", 500, 999_999), TRACE_S3));
    }

    #[test]
    fn a_request_is_a_trace_info() {
        let s3 = entry("S3", 200, 1_500_000_000);
        let (kind, info) = trace_info(&s3, "GET");
        assert_eq!(kind, TRACE_S3);
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": 4,
                "nodename": "s3.example.com",
                "funcname": "s3.GetObject",
                "time": "2026-10-02T10:00:00.5Z",
                "path": "/b/k",
                "dur": 1_500_000_000_u64,
                "bytes": 30,
                "http": {
                    "request": {
                        "time": "2026-10-02T10:00:00.5Z",
                        "proto": "HTTP/1.1",
                        "method": "GET",
                        "path": "/b/k",
                        "rawquery": "versionId=v+1",
                        "headers": {"authorization": ["REDACTED"]},
                        "client": "192.0.2.1",
                    },
                    "response": {
                        "time": "2026-10-02T10:00:02Z",
                        "headers": {},
                        "statuscode": 200,
                    },
                    "stats": {"inputbytes": 10, "outputbytes": 20, "timetofirstbyte": 700},
                },
            })
        );
        for (api, funcname) in [("STS", "sts.GetObject"), ("Admin", "admin.GetObject")] {
            let other = entry(api, 200, 1);
            let (kind, info) = trace_info(&other, "POST");
            assert_eq!((kind, info.funcname.as_str()), (TRACE_INTERNAL, funcname));
        }
    }
}
