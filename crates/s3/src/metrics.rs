//! Prometheus metrics at `GET /.teifs/metrics`, in the `OpenMetrics` text format: every
//! request by operation and status, errors by S3 error code, latency, bytes moved, the
//! drive's space and the background jobs' progress.
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
use teifs_store::Store;
use teifs_types::admin::METRICS_PATH;

use crate::{access::Client, observe::Outcome};

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
}

impl Metrics {
    pub(crate) fn new(store: &Store) -> Self {
        let mut registry = Registry::with_prefix("teifs");
        let requests = Family::default();
        let errors = Family::default();
        let canceled = Family::default();
        let inflight = Gauge::default();
        let first_byte = Family::new_with_constructor(latency as fn() -> Histogram);
        let duration = Family::new_with_constructor(latency as fn() -> Histogram);
        let received = Family::default();
        let sent = Family::default();
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
        registry.register_collector(Box::new(Server {
            store: store.clone(),
            started: SystemTime::now(),
        }));
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
        }
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

    pub(crate) fn record(&self, outcome: &Outcome) {
        let api = outcome.request.seen.operation();
        let code = outcome.status.as_u16();
        self.requests.get_or_create(&ApiStatus { api, code }).inc();
        if let Some(error) = &outcome.error {
            self.errors
                .get_or_create(&ApiError {
                    api,
                    error: error.clone(),
                })
                .inc();
        }
        let labels = Api { api };
        if outcome.canceled {
            self.canceled.get_or_create(&labels).inc();
        }
        self.first_byte
            .get_or_create(&labels)
            .observe(outcome.first_byte.as_secs_f64());
        self.duration
            .get_or_create(&labels)
            .observe(outcome.duration.as_secs_f64());
        self.received
            .get_or_create(&labels)
            .inc_by(outcome.received);
        self.sent.get_or_create(&labels).inc_by(outcome.sent);
    }

    /// Everything, in the `OpenMetrics` text format.
    fn text(&self) -> String {
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &self.registry)
            .expect("writing to a String can't fail");
        text
    }
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
pub(crate) fn scrape(
    metrics: &Metrics,
    scrapers: &Scrapers,
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
    let mut response = HttpResponse::new(s3s::Body::from(metrics.text()));
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
