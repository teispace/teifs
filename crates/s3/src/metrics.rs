//! Prometheus metrics at `GET /.teifs/metrics`, in the `OpenMetrics` text format: every
//! request by operation and status, errors by S3 error code, latency, bytes moved, the
//! drive's space and what it holds, the background jobs' progress and what the scrub
//! found, and how each bucket notification target is doing. `?buckets=1` adds what
//! each bucket holds, labeled by bucket.
//!
//! Metrics name buckets, users' operations and the drive's size, so a scrape needs a
//! bearer token (`teifs admin prometheus generate`) whose key may `teifs:GetMetrics`,
//! unless the server is started with public metrics for a network only Prometheus
//! shares.

use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{Arc, atomic::AtomicI64},
    time::{SystemTime, UNIX_EPOCH},
};

use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use prometheus_client::{
    collector::Collector,
    encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric},
    metrics::{
        MetricType,
        counter::{ConstCounter, Counter},
        family::Family,
        gauge::{ConstGauge, Gauge},
        histogram::{Histogram, exponential_buckets},
    },
    registry::{Registry, Unit},
};
use s3s::{HttpResponse, S3Error, S3ErrorCode};
use teifs_iam::{AuthError, Iam};
use teifs_notify::{Notifier, TargetStats};
use teifs_store::{BucketUsage, Store, Usage};
use teifs_types::{
    admin::METRICS_PATH,
    verify::{ScrubPass, ScrubReport},
};

use crate::{access::Client, observe::Answer};

/// The action a scrape's key needs.
const ACTION: &str = "teifs:GetMetrics";
/// `OpenMetrics` text, which Prometheus, `VictoriaMetrics` and Grafana Agent read.
const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Api {
    api: &'static str,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ApiStatus {
    api: &'static str,
    code: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ApiError {
    api: &'static str,
    error: String,
}

/// Seconds: 1 ms to about a minute, doubling.
fn latency() -> Histogram {
    Histogram::new(exponential_buckets(0.001, 2.0, 17))
}

/// The server's metrics.
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
    requests: Family<ApiStatus, Counter>,
    errors: Family<ApiError, Counter>,
    canceled: Family<Api, Counter>,
    inflight: Gauge<i64, AtomicI64>,
    first_byte: Family<Api, Histogram, fn() -> Histogram>,
    duration: Family<Api, Histogram, fn() -> Histogram>,
    received: Family<Api, Counter>,
    sent: Family<Api, Counter>,
    audit_dropped: Counter,
    access_log: crate::access_log::Counters,
    store: Store,
}

impl Metrics {
    pub(crate) fn new(store: &Store, notifier: Arc<Notifier>) -> Self {
        let mut registry = Registry::with_prefix("teifs");
        let requests = Family::default();
        let errors = Family::default();
        let canceled = Family::default();
        let inflight = Gauge::default();
        let first_byte = Family::new_with_constructor(latency as fn() -> Histogram);
        let duration = Family::new_with_constructor(latency as fn() -> Histogram);
        let received = Family::default();
        let sent = Family::default();
        let audit_dropped = Counter::default();
        let access_log = crate::access_log::Counters::default();
        registry.register(
            "s3_requests",
            "Requests answered, by operation and HTTP status",
            requests.clone(),
        );
        registry.register(
            "s3_errors",
            "Error answers, by operation and S3 error code",
            errors.clone(),
        );
        registry.register(
            "s3_canceled",
            "Requests whose client left before the whole answer was sent",
            canceled.clone(),
        );
        registry.register(
            "s3_requests_inflight",
            "Requests being served",
            inflight.clone(),
        );
        registry.register_with_unit(
            "s3_ttfb",
            "Time until the answer's headers were ready, by operation",
            Unit::Seconds,
            first_byte.clone(),
        );
        registry.register_with_unit(
            "s3_duration",
            "Time until the answer's last byte was sent, by operation",
            Unit::Seconds,
            duration.clone(),
        );
        registry.register_with_unit(
            "s3_received",
            "Request body bytes read, by operation",
            Unit::Bytes,
            received.clone(),
        );
        registry.register_with_unit(
            "s3_sent",
            "Answer body bytes sent, by operation",
            Unit::Bytes,
            sent.clone(),
        );
        registry.register_with_unit(
            "store_stage",
            "Time in each stage of the store's reads and writes (key, lock, sync, commit; locate, key)",
            Unit::Seconds,
            store.stage_times(),
        );
        registry.register(
            "audit_dropped",
            "Audit entries lost because their destination couldn't keep up",
            audit_dropped.clone(),
        );
        registry.register(
            "access_log_records",
            "Server access log records kept for delivery",
            access_log.records.clone(),
        );
        registry.register(
            "access_log_objects",
            "Server access log objects delivered",
            access_log.objects.clone(),
        );
        registry.register(
            "access_log_dropped",
            "Server access log records lost: the queue was full, the spool couldn't be written, or the target refused them",
            access_log.dropped.clone(),
        );
        registry.register_collector(Box::new(Server {
            store: store.clone(),
            started: SystemTime::now(),
        }));
        registry.register_collector(Box::new(Notifications(notifier)));
        Self {
            registry,
            requests,
            errors,
            canceled,
            inflight,
            first_byte,
            duration,
            received,
            sent,
            audit_dropped,
            access_log,
            store: store.clone(),
        }
    }

    /// The access log's counters, which its records and deliveries move.
    pub(crate) fn access_log(&self) -> crate::access_log::Counters {
        self.access_log.clone()
    }

    pub(crate) fn begin(&self) {
        self.inflight.inc();
    }

    pub(crate) fn end(&self, api: &'static str, canceled: bool) {
        self.inflight.dec();
        if canceled {
            self.canceled.get_or_create(&Api { api }).inc();
        }
    }

    pub(crate) fn record(&self, api: &'static str, answer: &Answer) {
        let code = answer.status.as_u16();
        self.requests.get_or_create(&ApiStatus { api, code }).inc();
        if let Some(error) = &answer.error {
            self.errors
                .get_or_create(&ApiError {
                    api,
                    error: error.clone(),
                })
                .inc();
        }
        let labels = Api { api };
        if answer.canceled {
            self.canceled.get_or_create(&labels).inc();
        }
        if let Some(first_byte) = answer.first_byte {
            self.first_byte
                .get_or_create(&labels)
                .observe(first_byte.as_secs_f64());
        }
        self.duration
            .get_or_create(&labels)
            .observe(answer.duration.as_secs_f64());
        self.received.get_or_create(&labels).inc_by(answer.received);
        self.sent.get_or_create(&labels).inc_by(answer.sent);
    }

    /// Counts an audit entry its destination couldn't take.
    pub(crate) fn audit_dropped(&self) {
        self.audit_dropped.inc();
    }

    /// The requests' metrics and the server's, in the `OpenMetrics` text format.
    #[cfg(test)]
    pub(crate) fn text(&self) -> String {
        self.encode(None)
    }

    /// Everything, with what the drive holds and what its scrub found, read now; each
    /// bucket's usage too when `per_bucket`.
    async fn scraped(&self, per_bucket: bool) -> String {
        let usage = self.store.usage().await;
        let scrub = self.store.scrub_report().await;
        if let Err(err) = usage.as_ref().map(drop).and(scrub.as_ref().map(drop)) {
            tracing::warn!(error = %err, "a scrape left out what the drive holds");
        }
        self.encode(Some(Drive {
            usage: usage.ok(),
            per_bucket,
            scrub: scrub.ok(),
        }))
    }

    fn encode(&self, drive: Option<Drive>) -> String {
        use prometheus_client::encoding::text::{encode_eof, encode_registry};
        let mut text = String::new();
        encode_registry(&mut text, &self.registry).expect("writing to a String can't fail");
        if let Some(drive) = drive {
            let mut read = Registry::with_prefix("teifs");
            read.register_collector(Box::new(drive));
            encode_registry(&mut text, &read).expect("writing to a String can't fail");
        }
        encode_eof(&mut text).expect("writing to a String can't fail");
        text
    }
}

/// What a scrape read of the drive: what it holds and what its scrub found (`None`
/// when it couldn't be read).
#[derive(Debug)]
struct Drive {
    usage: Option<Vec<BucketUsage>>,
    per_bucket: bool,
    scrub: Option<ScrubReport>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BucketLabel {
    bucket: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PassLabel {
    pass: &'static str,
}

/// A usage figure: its name, help and unit, and how to read it.
type Figure = (&'static str, &'static str, Option<Unit>, fn(&Usage) -> u64);

const FIGURES: [Figure; 4] = [
    (
        "objects",
        "Objects: keys whose current version isn't a delete marker",
        None,
        |u| u.objects,
    ),
    (
        "versions",
        "Object versions kept, current ones included, delete markers not",
        None,
        |u| u.versions,
    ),
    ("delete_markers", "Delete markers", None, |u| {
        u.delete_markers
    }),
    (
        "stored",
        "The size of every version kept",
        Some(Unit::Bytes),
        |u| u.bytes,
    ),
];

/// A scrub figure: its name, help and unit, and how to read it.
type ScrubFigure = (
    &'static str,
    &'static str,
    Option<Unit>,
    fn(&ScrubPass) -> u64,
);

const SCRUB_FIGURES: [ScrubFigure; 4] = [
    (
        "scrub_checked_versions",
        "Versions the scrub read and checked, in the pass under way and the last finished",
        None,
        |p| p.versions,
    ),
    (
        "scrub_checked",
        "Bytes the scrub read, in the pass under way and the last finished",
        Some(Unit::Bytes),
        |p| p.bytes,
    ),
    (
        "scrub_damaged_versions",
        "Versions the scrub found damaged, in the pass under way and the last finished",
        None,
        |p| p.damaged,
    ),
    (
        "scrub_unverifiable_versions",
        "Versions the scrub couldn't check (an SSE-C key it doesn't have), by pass",
        None,
        |p| p.unverifiable,
    ),
];

impl Collector for Drive {
    fn encode(&self, mut encoder: DescriptorEncoder) -> std::fmt::Result {
        if let Some(buckets) = &self.usage {
            let total = buckets
                .iter()
                .fold(Usage::default(), |total, b| total + b.usage);
            ConstGauge::new(i64::try_from(buckets.len()).unwrap_or(i64::MAX)).encode(
                encoder.encode_descriptor("buckets", "Buckets", None, MetricType::Gauge)?,
            )?;
            for (name, help, unit, read) in FIGURES {
                ConstGauge::new(gauge(read(&total))).encode(encoder.encode_descriptor(
                    &format!("usage_{name}"),
                    help,
                    unit.as_ref(),
                    MetricType::Gauge,
                )?)?;
            }
            if self.per_bucket {
                for (name, help, unit, read) in FIGURES {
                    let (name, help) = (format!("bucket_{name}"), format!("{help}, by bucket"));
                    let mut family = encoder.encode_descriptor(
                        &name,
                        &help,
                        unit.as_ref(),
                        MetricType::Gauge,
                    )?;
                    for bucket in buckets {
                        let label = BucketLabel {
                            bucket: bucket.name.clone(),
                        };
                        ConstGauge::new(gauge(read(&bucket.usage)))
                            .encode(family.encode_family(&label)?)?;
                    }
                }
            }
        }
        if let Some(scrub) = &self.scrub {
            let passes = [("current", &scrub.current), ("last", &scrub.last)];
            for (name, help, unit, read) in SCRUB_FIGURES {
                let mut family =
                    encoder.encode_descriptor(name, help, unit.as_ref(), MetricType::Gauge)?;
                for (pass, found) in passes {
                    if let Some(found) = found {
                        ConstGauge::new(gauge(read(found)))
                            .encode(family.encode_family(&PassLabel { pass })?)?;
                    }
                }
            }
            if let Some(finished) = scrub.last.as_ref().and_then(|p| p.finished_ms) {
                #[expect(clippy::cast_precision_loss, reason = "a timestamp fits a gauge")]
                let seconds = finished as f64 / 1000.0;
                ConstGauge::new(seconds).encode(encoder.encode_descriptor(
                    "scrub_last_finished",
                    "When the last scrub pass finished, in seconds since the Unix epoch",
                    Some(&Unit::Seconds),
                    MetricType::Gauge,
                )?)?;
            }
        }
        Ok(())
    }
}

/// A count as a gauge's value.
fn gauge(count: u64) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// What's read at each scrape: the version, when the server started, the drive's
/// space and the background jobs' progress.
#[derive(Debug)]
struct Server {
    store: Store,
    started: SystemTime,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Job {
    job: &'static str,
}

impl Server {
    fn gauge(
        encoder: &mut DescriptorEncoder,
        name: &str,
        help: &str,
        unit: Option<&Unit>,
        value: f64,
    ) -> std::fmt::Result {
        ConstGauge::new(value).encode(encoder.encode_descriptor(
            name,
            help,
            unit,
            MetricType::Gauge,
        )?)
    }
}

impl Collector for Server {
    fn encode(&self, mut encoder: DescriptorEncoder) -> std::fmt::Result {
        let info = [("version", Cow::Borrowed(env!("CARGO_PKG_VERSION")))];
        ConstGauge::new(1).encode(
            encoder
                .encode_descriptor("build_info", "The TeiFS version", None, MetricType::Info)?
                .encode_family(&info)?,
        )?;
        let started = self
            .started
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        Self::gauge(
            &mut encoder,
            "start_time",
            "When the server started, in seconds since the Unix epoch",
            Some(&Unit::Seconds),
            started,
        )?;
        let root: PathBuf = self.store.root().to_owned();
        if let Ok(stats) = fs4::statvfs(&root) {
            #[expect(clippy::cast_precision_loss, reason = "disk sizes fit a gauge")]
            let (total, free) = (stats.total_space() as f64, stats.available_space() as f64);
            Self::gauge(
                &mut encoder,
                "drive_total",
                "The size of the disk the drive is on",
                Some(&Unit::Bytes),
                total,
            )?;
            Self::gauge(
                &mut encoder,
                "drive_free",
                "The space free on the disk the drive is on, for TeiFS",
                Some(&Unit::Bytes),
                free,
            )?;
        }
        let jobs = self.store.job_status();
        let mut steps = encoder.encode_descriptor(
            "job_steps",
            "Steps each background job has run since the server started",
            None,
            MetricType::Counter,
        )?;
        for (job, status) in &jobs {
            ConstCounter::new(status.steps).encode(steps.encode_family(&Job { job })?)?;
        }
        let mut items = encoder.encode_descriptor(
            "job_items",
            "Items each background job has handled since the server started",
            None,
            MetricType::Counter,
        )?;
        for (job, status) in &jobs {
            ConstCounter::new(status.items).encode(items.encode_family(&Job { job })?)?;
        }
        let mut failing = encoder.encode_descriptor(
            "job_failing",
            "Whether each background job's last step failed",
            None,
            MetricType::Gauge,
        )?;
        for (job, status) in &jobs {
            ConstGauge::new(i64::from(status.last_error.is_some()))
                .encode(failing.encode_family(&Job { job })?)?;
        }
        Ok(())
    }
}

/// How each bucket notification target is doing.
#[derive(Debug)]
struct Notifications(Arc<Notifier>);

/// Reads one figure of a target's.
type Read<T> = fn(&TargetStats) -> T;

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Target {
    target: String,
}

impl Collector for Notifications {
    fn encode(&self, mut encoder: DescriptorEncoder) -> std::fmt::Result {
        let stats = self.0.stats();
        if stats.is_empty() {
            return Ok(());
        }
        let label = |arn: &teifs_types::notify::TargetArn| Target {
            target: arn.to_string(),
        };
        let counters: [(&str, &str, Read<u64>); 3] = [
            ("notify_sent", "Events each notification target took", |s| {
                s.sent
            }),
            (
                "notify_failed",
                "Tries each notification target didn't take (each is tried again)",
                |s| s.failed,
            ),
            (
                "notify_dropped",
                "Events dropped because too many waited for the target",
                |s| s.dropped,
            ),
        ];
        for (name, help, read) in counters {
            let mut family = encoder.encode_descriptor(name, help, None, MetricType::Counter)?;
            for stat in &stats {
                ConstCounter::new(read(stat)).encode(family.encode_family(&label(&stat.arn))?)?;
            }
        }
        let gauges: [(&str, &str, Read<i64>); 2] = [
            (
                "notify_queued",
                "Events waiting on the drive for each notification target",
                |s| i64::try_from(s.queued).unwrap_or(i64::MAX),
            ),
            (
                "notify_online",
                "Whether each notification target took its last try",
                |s| i64::from(s.online),
            ),
        ];
        for (name, help, read) in gauges {
            let mut family = encoder.encode_descriptor(name, help, None, MetricType::Gauge)?;
            for stat in &stats {
                ConstGauge::new(read(stat)).encode(family.encode_family(&label(&stat.arn))?)?;
            }
        }
        Ok(())
    }
}

/// Whether a request (not on a virtual-hosted bucket's host) is a scrape.
pub(crate) fn is_scrape(method: &Method, path: &str) -> bool {
    path == METRICS_PATH && method == Method::GET
}

/// Who may scrape.
#[derive(Debug, Clone)]
pub(crate) enum Scrapers {
    /// Anyone who can reach the server.
    Anyone,
    /// A bearer token whose key may `teifs:GetMetrics`.
    Allowed(Arc<Iam>),
}

/// Answers a scrape.
pub(crate) async fn scrape(
    metrics: &Metrics,
    scrapers: &Scrapers,
    query: Option<&str>,
    headers: &HeaderMap,
    client: Client,
    request_id: &str,
) -> HttpResponse {
    if let Scrapers::Allowed(iam) = scrapers
        && let Err(err) = check(iam, headers, client)
    {
        let mut response = crate::admin::error_response(&err, request_id);
        if err.status_code() == Some(StatusCode::UNAUTHORIZED) {
            response
                .headers
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        let mut http = HttpResponse::new(response.output);
        *http.status_mut() = response.status.unwrap_or(StatusCode::FORBIDDEN);
        *http.headers_mut() = response.headers;
        return http;
    }
    let per_bucket = query.is_some_and(|query| {
        form_urlencoded::parse(query.as_bytes())
            .any(|(name, value)| name == "buckets" && matches!(&*value, "1" | "true"))
    });
    let mut response = HttpResponse::new(s3s::Body::from(metrics.scraped(per_bucket).await));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Refuses a scrape without a valid token (401) or whose key may not scrape (403).
fn check(iam: &Iam, headers: &HeaderMap, client: Client) -> Result<(), S3Error> {
    let unauthorized = |message: &str| {
        let mut err = S3Error::with_message(
            S3ErrorCode::Custom("Unauthorized".into()),
            message.to_owned(),
        );
        err.set_status_code(StatusCode::UNAUTHORIZED);
        err
    };
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            unauthorized(
                "Metrics need a bearer token: make one with `teifs admin prometheus generate`.",
            )
        })?;
    let identity = iam
        .identify_metrics_token(token.trim())
        .map_err(|err| match err {
            AuthError::ExpiredToken => unauthorized("The token has expired."),
            _ => unauthorized("The token is invalid, or its access key is gone."),
        })?;
    let context = crate::access::base_context(&identity, headers, client, &iam.account());
    if identity.decide(&context, ACTION, "*", None).is_allowed() {
        Ok(())
    } else {
        Err(s3s::s3_error!(AccessDenied, "Access Denied"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_passes_are_labeled_and_the_last_ones_end_is_a_time() {
        let pass = |versions, damaged, finished_ms| ScrubPass {
            started_ms: 1_000,
            finished_ms,
            versions,
            bytes: versions * 10,
            damaged,
            unverifiable: 1,
            findings: Vec::new(),
        };
        let drive = Drive {
            usage: None,
            per_bucket: false,
            scrub: Some(ScrubReport {
                current: Some(pass(4, 0, None)),
                last: Some(pass(9, 2, Some(1_790_000_000_500))),
            }),
        };
        let mut registry = Registry::with_prefix("teifs");
        registry.register_collector(Box::new(drive));
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
        for line in [
            "teifs_scrub_checked_versions{pass=\"current\"} 4",
            "teifs_scrub_checked_versions{pass=\"last\"} 9",
            "teifs_scrub_checked_bytes{pass=\"last\"} 90",
            "teifs_scrub_damaged_versions{pass=\"last\"} 2",
            "teifs_scrub_damaged_versions{pass=\"current\"} 0",
            "teifs_scrub_unverifiable_versions{pass=\"last\"} 1",
            "teifs_scrub_last_finished_seconds 1790000000.5",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} in {text}");
        }
        assert!(
            !text.contains("teifs_usage_"),
            "no usage when it wasn't read"
        );
    }
}
