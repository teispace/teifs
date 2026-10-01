//! S3's request metrics: what `CloudWatch` counts for each of a bucket's metrics
//! configurations, as Prometheus metrics labeled by `bucket` and `filter_id` (the
//! configuration's id).
//!
//! Requests are only watched once some bucket has a metrics configuration
//! ([`RequestMetrics::on`]). A request is queued without waiting once its answer is
//! done (a full queue drops it, counted), and the [`Worker`] counts it against each of
//! its bucket's configurations it matches: every request to the bucket for one without
//! a filter, and requests on objects whose key and tags match for one with a prefix or
//! tag filter (the tags as they are once the request is answered). Access point filters
//! match nothing: TeiFS has no access points. A configuration's series go within a
//! minute of it being deleted.

use std::{
    collections::{BTreeMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use http::Method;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, histogram::Histogram},
    registry::{Registry, Unit},
};
use teifs_store::{Store, StoreError};
use teifs_types::configs::MetricsConfig;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::observe::{Answer, CLIENT_LEFT, Seen};

/// How many requests may wait for the worker.
const QUEUE: usize = 16 * 1024;
/// How often the series of configurations that are gone are removed.
const PRUNE: Duration = Duration::from_mins(1);

/// Where answered requests go: shared by the observer (which queues them) and the drive
/// (which turns watching on).
#[derive(Debug)]
pub(crate) struct RequestMetrics {
    on: AtomicBool,
    queue: mpsc::Sender<Done>,
    series: Series,
}

impl RequestMetrics {
    /// Watching requests from the start when `on`, with what its worker takes them from.
    pub(crate) fn new(on: bool, series: Series) -> (Arc<Self>, mpsc::Receiver<Done>) {
        let (queue, done) = mpsc::channel(QUEUE);
        let metrics = Arc::new(Self {
            on: AtomicBool::new(on),
            queue,
            series,
        });
        (metrics, done)
    }

    /// Whether requests are watched: once some bucket has a metrics configuration,
    /// until the server stops.
    pub(crate) fn on(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    /// Starts watching requests: a bucket now has a metrics configuration.
    pub(crate) fn turn_on(&self) {
        self.on.store(true, Ordering::Relaxed);
    }

    /// Queues an answered S3 request on a bucket, while requests are watched.
    pub(crate) fn record(&self, seen: &Seen, answer: &Answer) {
        if !self.on() || seen.kind() != "S3" {
            return;
        }
        let Some((bucket, key)) = seen.target() else {
            return;
        };
        if bucket.is_empty() {
            return;
        }
        let done = Done {
            kind: kind(seen.method(), seen.operation(), !key.is_empty()),
            bucket,
            key,
            status: answer.status.as_u16(),
            sent: answer.sent,
            received: answer.received,
            first_byte: answer.first_byte,
            duration: answer.duration,
        };
        if self.queue.try_send(done).is_err() {
            self.series.dropped.inc();
        }
    }
}

/// An answered request, as its metrics need it.
#[derive(Debug)]
pub(crate) struct Done {
    bucket: String,
    /// Empty for a request on the bucket.
    key: String,
    kind: Option<Kind>,
    status: u16,
    sent: u64,
    received: u64,
    first_byte: Option<Duration>,
    duration: Duration,
}

/// The kinds of request `CloudWatch` counts apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Get,
    Put,
    Delete,
    Head,
    Post,
    List,
    Select,
}

/// `CloudWatch`'s counts: `GET`, `PUT` and `HEAD` on objects; `DELETE` on objects and
/// multi-deletes; `POST`s but those; listings of the bucket's objects, uploads or
/// versions; and `SelectObjectContent` alone.
fn kind(method: Option<&Method>, operation: &str, on_object: bool) -> Option<Kind> {
    match operation {
        "SelectObjectContent" => return Some(Kind::Select),
        "DeleteObjects" => return Some(Kind::Delete),
        "ListObjects" | "ListObjectsV2" | "ListObjectVersions" | "ListMultipartUploads" => {
            return Some(Kind::List);
        }
        _ => {}
    }
    match *method? {
        Method::POST => Some(Kind::Post),
        _ if !on_object => None,
        Method::GET => Some(Kind::Get),
        Method::PUT => Some(Kind::Put),
        Method::DELETE => Some(Kind::Delete),
        Method::HEAD => Some(Kind::Head),
        _ => None,
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Labels {
    bucket: String,
    filter_id: String,
}

type Counters = Family<Labels, Counter>;
type Latencies = Family<Labels, Histogram, fn() -> Histogram>;

/// The metrics' series, by bucket and configuration.
#[derive(Debug, Clone)]
pub(crate) struct Series {
    /// By [`Kind`], in its order, then every request.
    requests: [Counters; 8],
    downloaded: Counters,
    uploaded: Counters,
    client_errors: Counters,
    server_errors: Counters,
    first_byte: Latencies,
    total: Latencies,
    /// Requests lost because the worker couldn't keep up.
    dropped: Counter,
}

/// The request counters' names: `CloudWatch`'s, in [`Kind`]'s order, then `AllRequests`.
const REQUESTS: [(&str, &str); 8] = [
    (
        "request_metrics_get_requests",
        "GetRequests: GET requests on objects",
    ),
    (
        "request_metrics_put_requests",
        "PutRequests: PUT requests on objects",
    ),
    (
        "request_metrics_delete_requests",
        "DeleteRequests: DELETE requests on objects, and multi-object deletes",
    ),
    (
        "request_metrics_head_requests",
        "HeadRequests: HEAD requests on objects",
    ),
    (
        "request_metrics_post_requests",
        "PostRequests: POST requests, but multi-object deletes and selects",
    ),
    (
        "request_metrics_list_requests",
        "ListRequests: requests that list the bucket's objects, uploads or versions",
    ),
    (
        "request_metrics_select_object_content_requests",
        "SelectObjectContentRequests: SelectObjectContent requests",
    ),
    ("request_metrics_all_requests", "AllRequests: every request"),
];

impl Series {
    /// The series, registered with the server's metrics.
    pub(crate) fn register(registry: &mut Registry) -> Self {
        let series = Self {
            requests: Default::default(),
            downloaded: Family::default(),
            uploaded: Family::default(),
            client_errors: Family::default(),
            server_errors: Family::default(),
            first_byte: Family::new_with_constructor(crate::metrics::latency as fn() -> Histogram),
            total: Family::new_with_constructor(crate::metrics::latency as fn() -> Histogram),
            dropped: Counter::default(),
        };
        for ((name, help), family) in REQUESTS.iter().zip(&series.requests) {
            registry.register(*name, help.to_string() + REQUESTS_HELP, family.clone());
        }
        registry.register_with_unit(
            "request_metrics_downloaded",
            format!("BytesDownloaded: answer body bytes sent{REQUESTS_HELP}"),
            Unit::Bytes,
            series.downloaded.clone(),
        );
        registry.register_with_unit(
            "request_metrics_uploaded",
            format!("BytesUploaded: request body bytes read{REQUESTS_HELP}"),
            Unit::Bytes,
            series.uploaded.clone(),
        );
        registry.register(
            "request_metrics_4xx_errors",
            format!("4xxErrors: requests answered with a 4xx status{REQUESTS_HELP}"),
            series.client_errors.clone(),
        );
        registry.register(
            "request_metrics_5xx_errors",
            format!("5xxErrors: requests answered with a 5xx status{REQUESTS_HELP}"),
            series.server_errors.clone(),
        );
        registry.register_with_unit(
            "request_metrics_first_byte_latency",
            format!("FirstByteLatency: time until the answer's headers were ready{REQUESTS_HELP}"),
            Unit::Seconds,
            series.first_byte.clone(),
        );
        registry.register_with_unit(
            "request_metrics_total_request_latency",
            format!(
                "TotalRequestLatency: time until the answer's last byte was sent{REQUESTS_HELP}"
            ),
            Unit::Seconds,
            series.total.clone(),
        );
        registry.register(
            "request_metrics_dropped",
            "Requests left out of buckets' request metrics because their worker couldn't keep up",
            series.dropped.clone(),
        );
        series
    }

    fn count(&self, labels: &Labels, done: &Done) {
        if let Some(kind) = done.kind {
            self.requests[kind as usize].get_or_create(labels).inc();
        }
        self.requests[REQUESTS.len() - 1]
            .get_or_create(labels)
            .inc();
        self.downloaded.get_or_create(labels).inc_by(done.sent);
        self.uploaded.get_or_create(labels).inc_by(done.received);
        match done.status {
            CLIENT_LEFT => {}
            400..500 => {
                self.client_errors.get_or_create(labels).inc();
            }
            500..600 => {
                self.server_errors.get_or_create(labels).inc();
            }
            _ => {}
        }
        if let Some(first_byte) = done.first_byte {
            self.first_byte
                .get_or_create(labels)
                .observe(first_byte.as_secs_f64());
        }
        self.total
            .get_or_create(labels)
            .observe(done.duration.as_secs_f64());
    }

    fn remove(&self, labels: &Labels) {
        for family in self
            .requests
            .iter()
            .chain([&self.downloaded, &self.uploaded])
            .chain([&self.client_errors, &self.server_errors])
        {
            family.remove(labels);
        }
        self.first_byte.remove(labels);
        self.total.remove(labels);
    }
}

/// What each metric's help ends with.
const REQUESTS_HELP: &str = ", by bucket and metrics configuration";

/// Counts answered requests against their buckets' metrics configurations.
#[derive(Debug)]
pub(crate) struct Worker {
    done: mpsc::Receiver<Done>,
    metrics: Arc<RequestMetrics>,
    store: Store,
    /// The series made so far, by bucket and configuration id.
    shown: HashSet<(String, String)>,
    /// How often the series of configurations that are gone are removed.
    prune: Duration,
}

impl Worker {
    pub(crate) fn new(
        done: mpsc::Receiver<Done>,
        metrics: Arc<RequestMetrics>,
        store: Store,
    ) -> Self {
        Self {
            done,
            metrics,
            store,
            shown: HashSet::new(),
            prune: PRUNE,
        }
    }

    /// Counts requests until `stop`.
    pub(crate) async fn run(mut self, stop: CancellationToken) {
        let mut prune = tokio::time::interval(self.prune);
        prune.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                done = self.done.recv() => match done {
                    Some(done) => self.count(&done).await,
                    None => break,
                },
                _ = prune.tick() => self.prune().await,
            }
        }
    }

    async fn count(&mut self, done: &Done) {
        let Ok(configurations) = self.store.bucket_configurations(&done.bucket).await else {
            return;
        };
        let mut tags = None;
        for (id, config) in &configurations.metrics {
            if !self.matches(config, done, &mut tags).await {
                continue;
            }
            let labels = Labels {
                bucket: done.bucket.clone(),
                filter_id: id.clone(),
            };
            self.metrics.series.count(&labels, done);
            self.shown.insert((labels.bucket, labels.filter_id));
        }
    }

    /// Whether the request counts for the configuration; reads the object's tags into
    /// `tags` the first time a filter needs them.
    async fn matches(
        &self,
        config: &MetricsConfig,
        done: &Done,
        tags: &mut Option<BTreeMap<String, String>>,
    ) -> bool {
        let Some(filter) = &config.filter else {
            return true;
        };
        if done.key.is_empty() {
            return false;
        }
        if filter.needs_tags() && tags.is_none() {
            let found = self.store.head(&done.bucket, &done.key).await;
            *tags = Some(found.map(|info| info.attrs.tags).unwrap_or_default());
        }
        filter.matches(&done.key, tags.as_ref().unwrap_or(&BTreeMap::new()))
    }

    /// Removes the series of configurations (or buckets) that are gone.
    async fn prune(&mut self) {
        let mut gone = Vec::new();
        for (bucket, id) in &self.shown {
            let there = match self.store.bucket_configurations(bucket).await {
                Ok(configurations) => configurations.metrics.contains_key(id),
                Err(StoreError::NoSuchBucket) => false,
                Err(_) => true,
            };
            if !there {
                gone.push((bucket.clone(), id.clone()));
            }
        }
        for (bucket, filter_id) in gone {
            self.metrics.series.remove(&Labels {
                bucket: bucket.clone(),
                filter_id: filter_id.clone(),
            });
            self.shown.remove(&(bucket, filter_id));
        }
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use teifs_store::Layout;
    use teifs_types::{
        ObjectAttrs,
        configs::{Filter, TagFilter},
    };

    use super::*;

    #[test]
    fn requests_are_counted_by_cloudwatchs_kinds() {
        let get = Some(&Method::GET);
        let post = Some(&Method::POST);
        let cases = [
            (get, "GetObject", true, Some(Kind::Get)),
            (get, "GetBucketPolicy", false, None),
            (get, "ListParts", true, Some(Kind::Get)),
            (get, "ListObjectsV2", false, Some(Kind::List)),
            (get, "ListObjects", false, Some(Kind::List)),
            (get, "ListObjectVersions", false, Some(Kind::List)),
            (get, "ListMultipartUploads", false, Some(Kind::List)),
            (get, "ListBucketMetricsConfigurations", false, None),
            (Some(&Method::PUT), "PutObject", true, Some(Kind::Put)),
            (Some(&Method::PUT), "PutBucketTagging", false, None),
            (
                Some(&Method::DELETE),
                "DeleteObject",
                true,
                Some(Kind::Delete),
            ),
            (Some(&Method::DELETE), "DeleteBucketPolicy", false, None),
            (post, "DeleteObjects", false, Some(Kind::Delete)),
            (Some(&Method::HEAD), "HeadObject", true, Some(Kind::Head)),
            (Some(&Method::HEAD), "HeadBucket", false, None),
            (post, "CreateMultipartUpload", true, Some(Kind::Post)),
            (post, "PostObject", false, Some(Kind::Post)),
            (post, "SelectObjectContent", true, Some(Kind::Select)),
            (Some(&Method::OPTIONS), "Unknown", true, None),
            (None, "Unknown", true, None),
        ];
        for (method, operation, on_object, expected) in cases {
            assert_eq!(kind(method, operation, on_object), expected, "{operation}");
        }
    }

    fn done(key: &str, kind: Option<Kind>, status: u16) -> Done {
        Done {
            bucket: "bkt".to_owned(),
            key: key.to_owned(),
            kind,
            status,
            sent: 10,
            received: 3,
            first_byte: Some(Duration::from_millis(2)),
            duration: Duration::from_millis(5),
        }
    }

    async fn setup() -> (tempfile::TempDir, Worker, Registry) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.create_bucket("bkt", Layout::Object).await.unwrap();
        let mut attrs = ObjectAttrs::default();
        attrs.tags.insert("team".to_owned(), "red".to_owned());
        store
            .put_bytes("bkt", "logs/tagged", b"x", attrs)
            .await
            .unwrap();
        store
            .put_bytes("bkt", "logs/plain", b"x", ObjectAttrs::default())
            .await
            .unwrap();
        let mut registry = Registry::default();
        let series = Series::register(&mut registry);
        let (metrics, done) = RequestMetrics::new(false, series);
        (dir, Worker::new(done, metrics, store), registry)
    }

    async fn configure(store: &Store, configs: &[(&str, Option<Filter>)]) {
        let configs: Vec<_> = configs
            .iter()
            .map(|(id, filter)| {
                (
                    (*id).to_owned(),
                    MetricsConfig {
                        filter: filter.clone(),
                    },
                )
            })
            .collect();
        let configurations = teifs_types::configs::Configurations {
            metrics: configs.into_iter().collect(),
            ..Default::default()
        };
        store
            .set_bucket_configurations("bkt", configurations)
            .await
            .unwrap();
    }

    fn text(registry: &Registry) -> String {
        let mut text = String::new();
        prometheus_client::encoding::text::encode_registry(&mut text, registry).unwrap();
        text
    }

    fn value(text: &str, series: &str) -> Option<String> {
        text.lines().find_map(|line| {
            line.strip_prefix(series)?
                .strip_prefix(' ')
                .map(str::to_owned)
        })
    }

    #[tokio::test]
    async fn each_configuration_counts_the_requests_it_matches() {
        let (_dir, mut worker, registry) = setup().await;
        let tagged = Filter {
            tags: vec![TagFilter {
                key: "team".to_owned(),
                value: "red".to_owned(),
            }],
            ..Filter::default()
        };
        let prefix = Filter {
            prefix: Some("logs/".to_owned()),
            ..Filter::default()
        };
        configure(
            &worker.store,
            &[
                ("EntireBucket", None),
                ("logs", Some(prefix)),
                ("red", Some(tagged)),
                (
                    "keyed",
                    Some(Filter {
                        prefix: Some(String::new()),
                        ..Filter::default()
                    }),
                ),
            ],
        )
        .await;
        for done in [
            done("logs/tagged", Some(Kind::Get), 200),
            done("logs/plain", Some(Kind::Put), 404),
            done("other", Some(Kind::Head), 503),
            done("", Some(Kind::List), 499),
            done("", None, 200),
        ] {
            worker.count(&done).await;
        }
        let text = text(&registry);
        let labels = |id: &str| format!("{{bucket=\"bkt\",filter_id=\"{id}\"}}");
        for (metric, id, expected) in [
            ("all_requests_total", "EntireBucket", Some("5")),
            ("all_requests_total", "logs", Some("2")),
            ("all_requests_total", "red", Some("1")),
            ("all_requests_total", "keyed", Some("3")),
            ("get_requests_total", "red", Some("1")),
            ("put_requests_total", "red", None),
            ("put_requests_total", "logs", Some("1")),
            ("head_requests_total", "EntireBucket", Some("1")),
            ("list_requests_total", "EntireBucket", Some("1")),
            ("delete_requests_total", "EntireBucket", None),
            ("4xx_errors_total", "EntireBucket", Some("1")),
            ("4xx_errors_total", "logs", Some("1")),
            ("5xx_errors_total", "EntireBucket", Some("1")),
            ("5xx_errors_total", "logs", None),
            ("downloaded_bytes_total", "EntireBucket", Some("50")),
            ("uploaded_bytes_total", "logs", Some("6")),
            ("first_byte_latency_seconds_count", "red", Some("1")),
            (
                "total_request_latency_seconds_count",
                "EntireBucket",
                Some("5"),
            ),
        ] {
            assert_eq!(
                value(&text, &format!("request_metrics_{metric}{}", labels(id))).as_deref(),
                expected,
                "{metric} {id}"
            );
        }
    }

    #[tokio::test]
    async fn requests_are_only_queued_while_watched() {
        let (_dir, mut worker, _registry) = setup().await;
        let metrics = Arc::clone(&worker.metrics);
        let seen = Seen::new().with_method(Method::GET);
        seen.on("bkt", "k");
        let answer = Answer {
            status: StatusCode::OK,
            ..Answer::default()
        };
        metrics.record(&seen, &answer);
        assert!(worker.done.try_recv().is_err());
        metrics.turn_on();
        metrics.record(&seen, &answer);
        let done = worker.done.try_recv().unwrap();
        assert_eq!((done.key.as_str(), done.kind), ("k", Some(Kind::Get)));
        let elsewhere = Seen::new();
        elsewhere.api("Admin");
        elsewhere.on("bkt", "");
        metrics.record(&elsewhere, &answer);
        let bucketless = Seen::new();
        bucketless.on("", "");
        metrics.record(&bucketless, &answer);
        metrics.record(&Seen::new(), &answer);
        assert!(worker.done.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_full_queue_drops_requests_counted() {
        let mut registry = Registry::default();
        let (metrics, _done) = RequestMetrics::new(true, Series::register(&mut registry));
        let seen = Seen::new();
        seen.on("bkt", "k");
        for _ in 0..=QUEUE {
            metrics.record(&seen, &Answer::default());
        }
        assert_eq!(
            value(&text(&registry), "request_metrics_dropped_total").as_deref(),
            Some("1")
        );
    }

    #[tokio::test]
    async fn the_series_of_configurations_that_are_gone_are_removed() {
        let (_dir, mut worker, registry) = setup().await;
        assert!(!worker.store.any_bucket_metrics().await.unwrap());
        configure(&worker.store, &[("all", None), ("kept", None)]).await;
        assert!(worker.store.any_bucket_metrics().await.unwrap());
        worker.count(&done("k", Some(Kind::Get), 200)).await;
        configure(&worker.store, &[("kept", None)]).await;
        worker.prune().await;
        let shown = text(&registry);
        assert!(!shown.contains("filter_id=\"all\""), "{shown}");
        assert!(shown.contains("filter_id=\"kept\""), "{shown}");
        for key in ["logs/tagged", "logs/plain"] {
            worker.store.delete("bkt", key).await.unwrap();
        }
        worker.store.delete_bucket("bkt").await.unwrap();
        worker.prune().await;
        assert!(!text(&registry).contains("filter_id"));
    }

    #[tokio::test]
    async fn a_running_worker_counts_and_prunes() {
        let (_dir, mut worker, registry) = setup().await;
        worker.prune = Duration::from_millis(10);
        configure(&worker.store, &[("all", None)]).await;
        let metrics = Arc::clone(&worker.metrics);
        let store = worker.store.clone();
        let stop = CancellationToken::new();
        let running = tokio::spawn(worker.run(stop.clone()));
        metrics.turn_on();
        let seen = Seen::new().with_method(Method::GET);
        seen.on("bkt", "k");
        metrics.record(&seen, &Answer::default());
        let shown = |registry: &Registry| text(registry).contains("filter_id=\"all\"");
        for _ in 0..200 {
            if shown(&registry) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(shown(&registry), "the request was counted");
        configure(&store, &[]).await;
        for _ in 0..200 {
            if !shown(&registry) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(!shown(&registry), "the series went with its configuration");
        stop.cancel();
        running.await.unwrap();
    }
}
