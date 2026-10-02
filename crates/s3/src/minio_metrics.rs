//! `MinIO`'s live metrics and lock list: `GET /minio/admin/v3/metrics`
//! (`mc admin scanner status`, the console's realtime view) and
//! `GET /minio/admin/v3/top/locks` (`mc admin top locks`).
//!
//! The metrics are `madmin.RealtimeMetrics` documents, one every `interval`, `n` times.
//! A server is one node, so its figures are the aggregate. It reports `MinIO`'s API
//! metrics: S3's requests being served and those answered since it started. A request
//! holds no lock past its own answer, so the lock list is always empty.

use std::{collections::BTreeMap, time::Duration};

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use s3s::{Body, S3Request, S3Response, S3Result};
use serde::Serialize;
use teifs_types::config_kv::go_duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{admin::error, lines, metrics::SinceStart, minio_info, routes::Routes};

/// Which of the calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `GET trace`.
    Trace,
    /// `GET log`.
    Log,
    /// `GET metrics`.
    Metrics,
    /// `GET top/locks`.
    TopLocks,
    /// `POST force-unlock`.
    ForceUnlock,
}

impl Call {
    /// The call's name, as the audit log and traces name it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Trace => "Trace",
            Self::Log => "ConsoleLog",
            Self::Metrics => "Metrics",
            Self::TopLocks => "TopLocks",
            Self::ForceUnlock => "ForceUnlock",
        }
    }

    pub(crate) fn call(self, routes: &Routes, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
        match self {
            Self::Trace => crate::minio_trace::trace(&routes.tracers, req.uri.query()),
            Self::Log => Ok(crate::console_log::log(routes, req)),
            Self::Metrics => Ok(metrics(routes, req)),
            Self::TopLocks => top_locks(req.uri.query()),
            Self::ForceUnlock => Ok(force_unlock()),
        }
    }
}

/// `madmin.MetricsAPI`.
const METRICS_API: u64 = 1 << 10;
/// The shortest interval `MinIO` sends documents at, and its default.
const SHORTEST: Duration = Duration::from_secs(1);

/// What a metrics call asks for (`madmin.MetricsOptions`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    /// The metric types wanted, as `madmin.MetricType` bits; 0 is all of them.
    types: u64,
    /// How many documents; none is until the caller leaves.
    times: Option<u64>,
    interval: Duration,
    /// The hosts asked about; none is all.
    hosts: Vec<String>,
    by_host: bool,
}

impl Options {
    /// Reads the query as `MinIO`'s `MetricsHandler` does: a missing, unreadable or
    /// short interval is a second; a missing, unreadable or non-positive `n` is no end.
    fn parse(query: &str) -> Self {
        let pairs: BTreeMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let get = |name: &str| pairs.get(name).map_or("", String::as_str);
        let interval = go_duration(get("interval"))
            .ok()
            .filter(|interval| *interval >= SHORTEST)
            .unwrap_or(SHORTEST);
        Self {
            types: get("types").parse().unwrap_or(0),
            times: get("n").parse::<u64>().ok().filter(|n| *n > 0),
            interval,
            hosts: get("hosts")
                .split(',')
                .filter(|host| !host.is_empty())
                .map(str::to_owned)
                .collect(),
            by_host: get("by-host") == "true",
        }
    }

    fn wants(&self, kind: u64) -> bool {
        self.types == 0 || self.types & kind != 0
    }
}

/// `madmin.RealtimeMetrics`.
#[derive(Serialize)]
struct RealtimeMetrics<'a> {
    collected: &'a str,
    hosts: Vec<&'a str>,
    aggregated: Metrics<'a>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    by_host: BTreeMap<&'a str, Metrics<'a>>,
    #[serde(rename = "final")]
    last: bool,
}

/// `madmin.Metrics`.
#[derive(Clone, Default, Serialize)]
struct Metrics<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    api: Option<ApiMetrics<'a>>,
}

/// `madmin.APIMetrics`.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiMetrics<'a> {
    collected: &'a str,
    nodes: u32,
    #[serde(skip_serializing_if = "is_zero")]
    active_requests: i64,
    #[serde(rename = "since_start")]
    since_start: ApiStats<'a>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes a reference"
)]
const fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// `madmin.APIStats`.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiStats<'a> {
    nodes: u32,
    start_time: &'a str,
    end_time: &'a str,
    wall_time_secs: f64,
    requests: u64,
    incoming_bytes: u64,
    outgoing_bytes: u64,
    #[serde(rename = "errors_4xx")]
    errors_4xx: u64,
    #[serde(rename = "errors_5xx")]
    errors_5xx: u64,
    canceled: u64,
    request_time_secs: f64,
    resp_ttfb_secs: f64,
    request_time_secs_min: f64,
    request_time_secs_max: f64,
    resp_ttfb_secs_min: f64,
    resp_ttfb_secs_max: f64,
}

/// The server's figures at one moment.
struct Taken<'a> {
    since: SinceStart,
    /// Requests being served.
    active: i64,
    started: &'a str,
    now: &'a str,
    /// Since the server started.
    wall_time: Duration,
}

impl Taken<'_> {
    fn api(&self) -> ApiMetrics<'_> {
        let since = &self.since;
        ApiMetrics {
            collected: self.now,
            nodes: 1,
            active_requests: self.active,
            since_start: ApiStats {
                nodes: 1,
                start_time: self.started,
                end_time: self.now,
                wall_time_secs: self.wall_time.as_secs_f64(),
                requests: since.requests,
                incoming_bytes: since.received,
                outgoing_bytes: since.sent,
                errors_4xx: since.errors_4xx,
                errors_5xx: since.errors_5xx,
                canceled: since.canceled,
                request_time_secs: since.time,
                resp_ttfb_secs: since.first_byte,
                request_time_secs_min: since.time_min,
                request_time_secs_max: since.time_max,
                resp_ttfb_secs_min: since.first_byte_min,
                resp_ttfb_secs_max: since.first_byte_max,
            },
        }
    }
}

/// One metrics document; `last` when no other follows.
fn document(options: &Options, node: &str, taken: &Taken<'_>, last: bool) -> Bytes {
    let ours = options.hosts.is_empty() || options.hosts.iter().any(|host| host == node);
    let api = (ours && options.wants(METRICS_API)).then(|| taken.api());
    let metrics = Metrics { api };
    let by_host = if ours && options.by_host {
        BTreeMap::from([(node, metrics.clone())])
    } else {
        BTreeMap::new()
    };
    let document = RealtimeMetrics {
        collected: taken.now,
        hosts: if ours { vec![node] } else { Vec::new() },
        aggregated: metrics,
        by_host,
        last,
    };
    let mut line = serde_json::to_vec(&document).expect("metrics serialize");
    line.push(b'\n');
    Bytes::from(line)
}

/// A time as `MinIO` writes one.
fn rfc3339(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_default()
}

/// `GET /minio/admin/v3/metrics`.
fn metrics(routes: &Routes, req: &S3Request<Body>) -> S3Response<Body> {
    let options = Options::parse(req.uri.query().unwrap_or_default());
    let node = minio_info::endpoint(routes, req);
    let live = routes.live.clone();
    let started = rfc3339(OffsetDateTime::from(live.started));
    let body = lines::every(
        routes.tracers.stopping(),
        options.interval,
        options.times,
        move |last| {
            let wall_time = live.started.elapsed().unwrap_or_default();
            let now = rfc3339(OffsetDateTime::now_utc());
            let taken = Taken {
                since: live.since_start(),
                active: live.inflight(),
                started: &started,
                now: &now,
                wall_time,
            };
            document(&options, &node, &taken, last)
        },
    );
    let mut response = S3Response::new(body);
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /minio/admin/v3/top/locks`: the oldest locks held, none here.
fn top_locks(query: Option<&str>) -> S3Result<S3Response<Body>> {
    let count = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .find(|(name, _)| name == "count")
        .map(|(_, count)| count.into_owned())
        .filter(|count| !count.is_empty());
    if let Some(count) = count
        && count.parse::<i64>().is_err()
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            format!("`{count}` isn't a number of locks"),
        ));
    }
    let mut response = S3Response::new(Body::from("[]".to_owned()));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

/// `POST /minio/admin/v3/force-unlock`: releases the locks named, none being held.
fn force_unlock() -> S3Response<Body> {
    S3Response::new(Body::empty())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn options_are_minio_s() {
        let asked = Options::parse("types=1024&n=3&interval=2s&hosts=a:9000,b:9000&by-host=true");
        assert_eq!(
            asked,
            Options {
                types: METRICS_API,
                times: Some(3),
                interval: Duration::from_secs(2),
                hosts: vec!["a:9000".to_owned(), "b:9000".to_owned()],
                by_host: true,
            }
        );
        // As MinIO reads them: nothing usable is every type, a second, no end.
        for loose in [
            "",
            "types=all&n=-1&interval=10ms",
            "n=0&interval=soon&hosts=",
        ] {
            let read = Options::parse(loose);
            assert_eq!(
                (read.types, read.times, read.interval, read.hosts.len()),
                (0, None, SHORTEST, 0),
                "{loose}"
            );
        }
        assert!(Options::parse("types=0").wants(METRICS_API));
        assert!(!Options::parse("types=1").wants(METRICS_API));
    }

    fn taken() -> Taken<'static> {
        let since = SinceStart {
            requests: 3,
            received: 10,
            sent: 20,
            errors_4xx: 1,
            time: 0.5,
            time_min: 0.1,
            time_max: 0.3,
            ..SinceStart::default()
        };
        Taken {
            since,
            active: 0,
            started: "2026-10-02T10:00:00Z",
            now: "2026-10-02T10:01:00Z",
            wall_time: Duration::from_secs(60),
        }
    }

    #[test]
    fn a_document_is_realtime_metrics() {
        let node = "s3.example.com:9000";
        let line = document(&Options::parse("by-host=true"), node, &taken(), true);
        let json: serde_json::Value = serde_json::from_slice(&line).unwrap();
        let api = serde_json::json!({
            "collected": "2026-10-02T10:01:00Z",
            "nodes": 1,
            "since_start": {
                "nodes": 1,
                "startTime": "2026-10-02T10:00:00Z",
                "endTime": "2026-10-02T10:01:00Z",
                "wallTimeSecs": 60.0,
                "requests": 3,
                "incomingBytes": 10,
                "outgoingBytes": 20,
                "errors_4xx": 1,
                "errors_5xx": 0,
                "canceled": 0,
                "requestTimeSecs": 0.5,
                "respTtfbSecs": 0.0,
                "requestTimeSecsMin": 0.1,
                "requestTimeSecsMax": 0.3,
                "respTtfbSecsMin": 0.0,
                "respTtfbSecsMax": 0.0,
            },
        });
        assert_eq!(
            json,
            serde_json::json!({
                "collected": "2026-10-02T10:01:00Z",
                "hosts": ["s3.example.com:9000"],
                "aggregated": {"api": api},
                "by_host": {"s3.example.com:9000": {"api": api}},
                "final": true,
            })
        );
        assert!(line.ends_with(b"\n"));

        // Another host's figures, or other types, aren't this server's to give.
        for options in ["hosts=elsewhere:9000", "types=1"] {
            let line = document(&Options::parse(options), node, &taken(), false);
            let json: serde_json::Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(json["aggregated"], serde_json::json!({}), "{options}");
        }
    }

    #[test]
    fn there_are_no_locks_to_list() {
        for query in [None, Some("count=10&stale=false"), Some("count=")] {
            assert!(top_locks(query).is_ok(), "{query:?}");
        }
        assert!(top_locks(Some("count=ten")).is_err());
    }
}
