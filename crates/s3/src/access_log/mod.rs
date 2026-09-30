//! Server access logging, as S3's: a record of every request on a bucket that logs,
//! delivered as log objects into the bucket's target by the logging service.
//!
//! Requests are only watched once some bucket logs ([`AccessLog::on`]). A request's
//! records are made once its answer is done and queued without waiting (a full queue
//! drops them, counted). The [`Worker`] keeps them in one spool file per source bucket
//! in the drive's system folder, flushed every second, and rolls a spool into a log
//! object every interval, at 1 MiB, or when the day changes. Spools survive restarts and
//! are delivered after the next start. A delivery the target refuses (it's gone, or
//! doesn't let the logging service in) drops the records, counted and warned about, as
//! S3's does; one that fails otherwise is tried again.

mod record;

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufWriter, Write as _},
    net::IpAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{HeaderMap, Request, header};
use prometheus_client::metrics::counter::Counter;
use s3s::{S3Error, S3ErrorCode};
use teifs_iam::Identity;
use teifs_policy::PrincipalKind;
use teifs_store::{Expirations, OWNER_ID, Store, StoreError};
use tokio::sync::mpsc;

pub(crate) use self::record::{Record, copy_source_operation};
use crate::{
    access::Client,
    drive::{Drive, REGION},
    events::Events,
    observe::{self, Answer, Seen},
};

/// How many records may wait for the worker.
const QUEUE: usize = 16 * 1024;
/// A spool this big is delivered.
const MAX_SPOOL: u64 = 1024 * 1024;
/// How often spools are flushed, and checked for rolling.
const FLUSH: Duration = Duration::from_secs(1);
/// How often spools that couldn't be delivered are tried again.
const RETRY: Duration = Duration::from_secs(60);
/// How often a spool is delivered by default.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);
/// Query parameters whose values are secrets, redacted in records.
const SECRET_QUERY: [&str; 3] = ["x-amz-signature", "x-amz-security-token", "signature"];

/// Where requests' records go: shared by the observer (which makes them) and the drive
/// (which turns logging on).
#[derive(Debug)]
pub(crate) struct AccessLog {
    on: AtomicBool,
    queue: mpsc::Sender<Record>,
    counters: Counters,
}

/// The access log's metrics.
#[derive(Debug, Clone, Default)]
pub(crate) struct Counters {
    /// Records kept.
    pub(crate) records: Counter,
    /// Log objects delivered.
    pub(crate) objects: Counter,
    /// Records lost: the queue was full, the spool couldn't be written, or the target
    /// refused them.
    pub(crate) dropped: Counter,
}

impl AccessLog {
    /// The access log, watching requests from the start when `on` (some bucket logs),
    /// and what its worker takes the records from.
    pub(crate) fn new(on: bool, counters: Counters) -> (Arc<Self>, mpsc::Receiver<Record>) {
        let (queue, records) = mpsc::channel(QUEUE);
        let log = Arc::new(Self {
            on: AtomicBool::new(on),
            queue,
            counters,
        });
        (log, records)
    }

    /// Whether requests are watched: once some bucket logs, until the server stops.
    pub(crate) fn on(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    /// Starts watching requests: a bucket now logs.
    pub(crate) fn turn_on(&self) {
        self.on.store(true, Ordering::Relaxed);
    }

    /// Queues a record, or drops it (counted) when the worker can't keep up.
    fn record(&self, record: Record) {
        if self.queue.try_send(record).is_err() {
            self.counters.dropped.inc();
        }
    }
}

/// What's kept of a request from its arrival, while requests are watched.
#[derive(Debug)]
pub(crate) struct Arrival {
    time: SystemTime,
    method: String,
    /// The path and query, secrets redacted.
    uri: String,
    query: Option<String>,
    http: &'static str,
    host: Option<String>,
    referer: Option<String>,
    user_agent: Option<String>,
    remote: Option<IpAddr>,
    tls: Option<&'static str>,
    /// The bucket its host or path names, for a request refused before it's known.
    bucket: Option<String>,
    version_id: Option<String>,
    /// Whether it copies (`x-amz-copy-source`), so its body isn't the object's.
    copies: bool,
}

impl Arrival {
    /// `bucket` is the bucket its host or path names.
    pub(crate) fn of<B>(req: &Request<B>, client: Client, bucket: Option<String>) -> Self {
        let header = |name: header::HeaderName| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let uri = req.uri();
        let query = uri.query().map(str::to_owned);
        let path = uri.path();
        let version_id = form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes())
            .find(|(name, _)| name == "versionId")
            .map(|(_, value)| value.into_owned());
        Self {
            time: SystemTime::now(),
            method: req.method().as_str().to_owned(),
            uri: match &query {
                Some(query) => format!("{path}?{}", redacted(query)),
                None => path.to_owned(),
            },
            query,
            http: http_version(req.version()),
            host: header(header::HOST).or_else(|| uri.authority().map(ToString::to_string)),
            referer: header(header::REFERER),
            user_agent: header(header::USER_AGENT),
            remote: client.ip,
            tls: client.tls.map(|version| match version {
                "1.3" => "TLSv1.3",
                _ => "TLSv1.2",
            }),
            bucket,
            version_id,
            copies: req.headers().contains_key("x-amz-copy-source"),
        }
    }

    /// The size of the object an answer is about, from its headers: a range's total, or
    /// the whole body of a read. A write's comes from what it received.
    pub(crate) fn object_size(&self, headers: &HeaderMap) -> Option<u64> {
        let number = |name| {
            headers
                .get(name)
                .and_then(|v: &http::HeaderValue| v.to_str().ok())
                .map(str::to_owned)
        };
        if let Some(range) = number(header::CONTENT_RANGE) {
            return range.rsplit('/').next()?.parse().ok();
        }
        matches!(self.method.as_str(), "GET" | "HEAD")
            .then(|| number(header::CONTENT_LENGTH)?.parse().ok())
            .flatten()
    }

    /// The request's records, once it's answered: its own, for the bucket it's on,
    /// and those it adds (a copy's source, each object a multi-delete removed).
    pub(crate) fn finish(self, seen: &Seen, answer: &Answer, log: &AccessLog) {
        if seen.kind() != "S3" {
            return;
        }
        let (bucket, key) = match seen.target() {
            Some((bucket, key)) => (bucket, (!key.is_empty()).then_some(key)),
            None => match self.bucket.clone() {
                Some(bucket) => (bucket, None),
                None => return,
            },
        };
        if bucket.is_empty() {
            return;
        }
        let operation = if seen.is_website() {
            format!("WEBSITE.{}.OBJECT", self.method)
        } else {
            record::operation(
                &self.method,
                seen.operation(),
                self.query.as_deref(),
                key.is_some(),
            )
        };
        let millis = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let (signature, auth) = seen.signature().unzip();
        let object_size = answer.object_size.or_else(|| {
            (self.method == "PUT" && key.is_some() && !self.copies && answer.status.is_success())
                .then_some(answer.received)
        });
        let main = Record {
            bucket,
            time: self.time,
            remote: self.remote,
            requester: seen.requester().map(str::to_owned),
            request_id: seen.id.clone(),
            operation,
            key,
            request_uri: format!("{} {} {}", self.method, self.uri, self.http),
            status: Some(answer.status.as_u16()),
            error: answer.error.clone(),
            sent: answer.sent,
            object_size,
            total_ms: millis(answer.duration),
            turnaround_ms: answer.first_byte.map(millis),
            referer: self.referer,
            user_agent: self.user_agent,
            version_id: self.version_id,
            signature,
            auth,
            host: self.host,
            tls: self.tls,
            acl_required: seen.acl_required(),
        };
        for also in seen.also() {
            log.record(Record {
                bucket: also.bucket,
                operation: also.operation.to_owned(),
                key: Some(also.key),
                version_id: also.version_id,
                status: also.status.or(main.status),
                sent: 0,
                object_size: None,
                ..main.clone()
            });
        }
        log.record(main);
    }
}

/// A record a request adds to its own: for another bucket or object than the one it's
/// on.
#[derive(Debug, Clone)]
pub(crate) struct Also {
    pub(crate) bucket: String,
    pub(crate) key: String,
    pub(crate) version_id: Option<String>,
    pub(crate) operation: &'static str,
    /// Its own status, when not the request's.
    pub(crate) status: Option<u16>,
}

/// What lifecycle rules remove, told to the events and, for a bucket that logs, to its
/// access log as S3 logs it: `S3.EXPIRE.OBJECT` or `S3.CREATE.DELETEMARKER`, by
/// `AmazonS3`.
#[derive(Debug)]
pub(crate) struct Expired {
    pub(crate) events: Events,
    pub(crate) log: Arc<AccessLog>,
}

impl Expirations for Expired {
    fn expired<'a>(
        &'a self,
        bucket: &'a str,
        key: &'a str,
        version_id: Option<String>,
        marker: bool,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if self.log.on() {
                let operation = if marker {
                    "S3.CREATE.DELETEMARKER"
                } else {
                    "S3.EXPIRE.OBJECT"
                };
                self.log.record(Record {
                    bucket: bucket.to_owned(),
                    time: SystemTime::now(),
                    remote: None,
                    requester: Some("AmazonS3".to_owned()),
                    request_id: observe::new_id(),
                    operation: operation.to_owned(),
                    key: Some(key.to_owned()),
                    request_uri: String::new(),
                    status: None,
                    error: None,
                    sent: 0,
                    object_size: None,
                    total_ms: 0,
                    turnaround_ms: None,
                    referer: None,
                    user_agent: None,
                    version_id: version_id.clone(),
                    signature: None,
                    auth: None,
                    host: None,
                    tls: None,
                    acl_required: false,
                });
            }
            self.events.expired(bucket, key, version_id, marker).await;
        })
    }
}

/// Who records name: an IAM ARN, the owner's canonical id for the root user, none for
/// an unsigned request.
pub(crate) fn requester(identity: &Identity) -> Option<String> {
    let principal = identity.principal();
    match principal.kind() {
        PrincipalKind::Anonymous => None,
        PrincipalKind::Account => Some(OWNER_ID.to_owned()),
        _ => principal.arn().map(str::to_owned),
    }
}

/// A query with its secrets' values replaced.
fn redacted(query: &str) -> String {
    query
        .split('&')
        .map(|pair| {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            let decoded: String = form_urlencoded::parse(name.as_bytes())
                .map(|(n, _)| n.into_owned())
                .collect();
            if SECRET_QUERY.iter().any(|s| decoded.eq_ignore_ascii_case(s)) {
                format!("{name}={}", crate::audit::REDACTED)
            } else {
                pair.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

const fn http_version(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

/// Why a log object wasn't delivered.
#[derive(Debug)]
pub(crate) enum Undelivered {
    /// The target won't take it: its records are dropped.
    Refused(String),
    /// It may yet: tried again later.
    Failed(String),
}

/// What an error writing the log object means for its records.
impl From<S3Error> for Undelivered {
    fn from(err: S3Error) -> Self {
        let why = err
            .message()
            .map_or_else(|| err.code().as_str().to_owned(), str::to_owned);
        match err.code() {
            S3ErrorCode::InternalError
            | S3ErrorCode::ServiceUnavailable
            | S3ErrorCode::SlowDown => Self::Failed(why),
            _ => Self::Refused(why),
        }
    }
}

/// One source bucket's spool being written.
#[derive(Debug)]
struct Spool {
    path: PathBuf,
    file: BufWriter<File>,
    day: i64,
    bytes: u64,
    opened: Instant,
}

impl Spool {
    /// Whether it's delivered before a record of `day` is added: records of one day
    /// go together, up to [`MAX_SPOOL`] bytes.
    const fn is_full(&self, day: i64) -> bool {
        self.day != day || self.bytes >= MAX_SPOOL
    }
}

/// Keeps the records in spools and delivers them; the server runs it.
#[derive(Debug)]
pub struct Worker {
    records: mpsc::Receiver<Record>,
    log: Arc<AccessLog>,
    drive: Drive,
    store: Store,
    dir: PathBuf,
    interval: Duration,
    spools: HashMap<String, Spool>,
}

impl Worker {
    pub(crate) fn new(
        records: mpsc::Receiver<Record>,
        log: Arc<AccessLog>,
        drive: Drive,
        store: Store,
        interval: Duration,
    ) -> Self {
        Self {
            records,
            log,
            drive,
            dir: store.access_log_dir(),
            store,
            interval,
            spools: HashMap::new(),
        }
    }

    /// Delivers what the last run left, then keeps and delivers records until `stop`;
    /// what's spooled then is delivered after the next start.
    pub async fn run(mut self, stop: impl Future<Output = ()> + Send) {
        let mut stop = std::pin::pin!(stop);
        self.deliver_waiting().await;
        let mut flush = tokio::time::interval(FLUSH);
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut retried = Instant::now();
        loop {
            tokio::select! {
                () = &mut stop => break,
                record = self.records.recv() => match record {
                    Some(record) => self.keep(record).await,
                    None => break,
                },
                _ = flush.tick() => {
                    self.flush();
                    self.roll_due().await;
                    if retried.elapsed() >= RETRY {
                        retried = Instant::now();
                        self.deliver_waiting().await;
                    }
                }
            }
        }
        // What the last requests queued is kept for the next start.
        while let Ok(record) = self.records.try_recv() {
            self.keep(record).await;
        }
        self.flush();
    }

    /// Adds a record to its bucket's spool, if the bucket still logs.
    async fn keep(&mut self, record: Record) {
        match self.store.bucket_logging(&record.bucket).await {
            Ok(Some(_)) => {}
            Ok(None) | Err(StoreError::NoSuchBucket) => return,
            Err(err) => {
                tracing::warn!(bucket = record.bucket, error = %err, "couldn't read the bucket's logging; its record was dropped");
                self.log.counters.dropped.inc();
                return;
            }
        }
        let day = record::day(record.time);
        let full = self
            .spools
            .get(&record.bucket)
            .is_some_and(|spool| spool.is_full(day));
        if full {
            self.roll(&record.bucket).await;
        }
        let line = record.line();
        match self.append(&record, day, &line) {
            Ok(()) => {
                self.log.counters.records.inc();
            }
            Err(err) => {
                tracing::warn!(bucket = record.bucket, error = %err, "couldn't spool an access log record");
                self.log.counters.dropped.inc();
            }
        }
    }

    fn append(&mut self, record: &Record, day: i64, line: &str) -> io::Result<()> {
        let spool = match self.spools.entry(record.bucket.clone()) {
            std::collections::hash_map::Entry::Occupied(spool) => spool.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let dir = self.dir.join(&record.bucket);
                fs::create_dir_all(&dir)?;
                let first = record
                    .time
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis());
                let unique = uuid::Uuid::new_v4().simple();
                let path = dir.join(format!("{first}-{unique}.log"));
                let file = File::options().create_new(true).append(true).open(&path)?;
                entry.insert(Spool {
                    path,
                    file: BufWriter::new(file),
                    day,
                    bytes: 0,
                    opened: Instant::now(),
                })
            }
        };
        spool.file.write_all(line.as_bytes())?;
        spool.file.write_all(b"\n")?;
        spool.bytes += line.len() as u64 + 1;
        Ok(())
    }

    fn flush(&mut self) {
        for (bucket, spool) in &mut self.spools {
            if let Err(err) = spool.file.flush() {
                tracing::warn!(bucket, error = %err, "couldn't flush an access log spool");
            }
        }
    }

    /// Delivers the spools open for an interval.
    async fn roll_due(&mut self) {
        let due: Vec<String> = self
            .spools
            .iter()
            .filter(|(_, spool)| spool.opened.elapsed() >= self.interval)
            .map(|(bucket, _)| bucket.clone())
            .collect();
        for bucket in due {
            self.roll(&bucket).await;
        }
    }

    /// Closes a bucket's spool and delivers it.
    async fn roll(&mut self, bucket: &str) {
        let Some(mut spool) = self.spools.remove(bucket) else {
            return;
        };
        if let Err(err) = spool.file.flush() {
            tracing::warn!(bucket, error = %err, "couldn't flush an access log spool");
        }
        drop(spool.file);
        self.deliver(bucket, &spool.path).await;
    }

    /// Delivers the spools no one writes to: left by the last run, or not delivered yet.
    async fn deliver_waiting(&mut self) {
        let Ok(buckets) = fs::read_dir(&self.dir) else {
            return;
        };
        let mut waiting = Vec::new();
        for bucket in buckets.flatten() {
            let name = bucket.file_name().to_string_lossy().into_owned();
            let open = self.spools.get(&name).map(|spool| spool.path.clone());
            let Ok(files) = fs::read_dir(bucket.path()) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                if Some(&path) != open.as_ref() {
                    waiting.push((name.clone(), path));
                }
            }
        }
        waiting.sort();
        for (bucket, path) in waiting {
            self.deliver(&bucket, &path).await;
        }
    }

    /// Writes a spool as a log object into its bucket's target, and removes it once
    /// that's done or refused.
    async fn deliver(&self, bucket: &str, path: &Path) {
        let mut data = match tokio::fs::read(path).await {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => {
                tracing::warn!(bucket, error = %err, "couldn't read an access log spool");
                return;
            }
        };
        // A line cut short (the server stopped as it was written) isn't a record.
        data.truncate(
            data.iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |end| end + 1),
        );
        #[expect(
            clippy::naive_bytecount,
            reason = "one pass over a spool of at most a few MiB isn't worth a dependency"
        )]
        let records = data.iter().filter(|&&b| b == b'\n').count() as u64;
        let dropped = |why: &str| {
            if records > 0 {
                tracing::warn!(bucket, records, why, "access log records were dropped");
                self.log.counters.dropped.inc_by(records);
            }
        };
        let config = match self.store.bucket_logging(bucket).await {
            Ok(Some(config)) => config,
            Ok(None) | Err(StoreError::NoSuchBucket) => {
                dropped("the bucket no longer logs");
                remove(path);
                return;
            }
            Err(err) => {
                tracing::warn!(bucket, error = %err, "couldn't read the bucket's logging; will try again");
                return;
            }
        };
        if records == 0 {
            remove(path);
            return;
        }
        let first = path
            .file_name()
            .and_then(|name| name.to_str()?.split('-').next()?.parse::<u64>().ok())
            .map_or_else(SystemTime::now, |ms| UNIX_EPOCH + Duration::from_millis(ms));
        let unique = uuid::Uuid::new_v4().simple().to_string()[..16].to_ascii_uppercase();
        let account = self.drive.account().unwrap_or(OWNER_ID);
        let key = record::object_key(
            &config,
            (account, REGION, bucket),
            first,
            SystemTime::now(),
            &unique,
        );
        match self
            .drive
            .deliver_log(bucket, &config, &key, Bytes::from(data))
            .await
        {
            Ok(_) => {
                self.log.counters.objects.inc();
                remove(path);
            }
            Err(Undelivered::Refused(why)) => {
                dropped(&why);
                remove(path);
            }
            Err(Undelivered::Failed(why)) => {
                tracing::warn!(
                    bucket,
                    why,
                    "couldn't deliver an access log object; will try again"
                );
            }
        }
    }
}

fn remove(path: &Path) {
    if let Err(err) = fs::remove_file(path)
        && err.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), error = %err, "couldn't remove an access log spool");
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use s3s::s3_error;

    use super::*;

    #[test]
    fn a_presigned_links_secrets_are_redacted() {
        assert_eq!(
            redacted(
                "X-Amz-Credential=AKIA%2F1&X-Amz-Signature=abc&x-amz-security-token=t&versionId=1"
            ),
            "X-Amz-Credential=AKIA%2F1&X-Amz-Signature=REDACTED&x-amz-security-token=REDACTED&versionId=1"
        );
        assert_eq!(
            redacted("AWSAccessKeyId=A&Signature=s%2B&Expires=1"),
            "AWSAccessKeyId=A&Signature=REDACTED&Expires=1"
        );
        assert_eq!(redacted("acl"), "acl");
        let req = Request::get("/app/k?X-Amz-Signature=abc&versionId=v1")
            .header("host", "s3.test")
            .body(())
            .unwrap();
        let arrival = Arrival::of(&req, Client::default(), Some("app".to_owned()));
        assert_eq!(arrival.uri, "/app/k?X-Amz-Signature=REDACTED&versionId=v1");
        assert_eq!(arrival.version_id.as_deref(), Some("v1"));
        assert_eq!(arrival.host.as_deref(), Some("s3.test"));
        assert_eq!(arrival.http, "HTTP/1.1");
    }

    #[test]
    fn object_sizes_come_from_the_answers_headers() {
        let arrival = |method: &str| {
            let req = Request::builder()
                .method(method)
                .uri("/b/k")
                .body(())
                .unwrap();
            Arrival::of(&req, Client::default(), None)
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "10".parse().unwrap());
        assert_eq!(arrival("GET").object_size(&headers), Some(10));
        assert_eq!(arrival("HEAD").object_size(&headers), Some(10));
        assert_eq!(arrival("PUT").object_size(&headers), None);
        headers.insert(header::CONTENT_RANGE, "bytes 0-9/100".parse().unwrap());
        assert_eq!(arrival("GET").object_size(&headers), Some(100));
        assert_eq!(arrival("GET").object_size(&HeaderMap::new()), None);
    }

    #[test]
    fn only_passing_failures_are_tried_again() {
        assert!(matches!(
            Undelivered::from(s3_error!(InternalError, "disk")),
            Undelivered::Failed(why) if why == "disk"
        ));
        assert!(matches!(
            Undelivered::from(s3_error!(SlowDown)),
            Undelivered::Failed(_)
        ));
        assert!(matches!(
            Undelivered::from(s3_error!(NoSuchBucket)),
            Undelivered::Refused(_)
        ));
        assert!(matches!(
            Undelivered::from(s3_error!(AccessDenied, "locked")),
            Undelivered::Refused(_)
        ));
    }

    #[test]
    fn a_spool_holds_one_days_records_up_to_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.log");
        let spool = |bytes| Spool {
            file: BufWriter::new(File::create(&path).unwrap()),
            path: path.clone(),
            day: 20_000,
            bytes,
            opened: Instant::now(),
        };
        assert!(!spool(0).is_full(20_000));
        assert!(!spool(MAX_SPOOL - 1).is_full(20_000));
        assert!(spool(MAX_SPOOL).is_full(20_000));
        assert!(spool(0).is_full(20_001), "a new day starts a new object");
    }

    #[test]
    fn a_full_queue_drops_records_and_counts_them() {
        let counters = Counters::default();
        let (log, mut records) = AccessLog::new(false, counters.clone());
        assert!(!log.on());
        log.turn_on();
        assert!(log.on());
        let record = |n: usize| Record {
            bucket: format!("b{n}"),
            time: SystemTime::UNIX_EPOCH,
            remote: None,
            requester: None,
            request_id: String::new(),
            operation: String::new(),
            key: None,
            request_uri: String::new(),
            status: None,
            error: None,
            sent: 0,
            object_size: None,
            total_ms: 0,
            turnaround_ms: None,
            referer: None,
            user_agent: None,
            version_id: None,
            signature: None,
            auth: None,
            host: None,
            tls: None,
            acl_required: false,
        };
        for n in 0..=QUEUE {
            log.record(record(n));
        }
        assert_eq!(counters.dropped.get(), 1);
        assert_eq!(records.try_recv().unwrap().bucket, "b0");
    }
}
