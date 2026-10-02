//! `MinIO`'s speed tests (`mc admin speedtest`): `POST /minio/admin/v3/speedtest`
//! (objects), `speedtest/drive` (the disks), `speedtest/net` and `speedtest/site`.
//!
//! The object test writes objects of `size` with `concurrent` writers for `duration`,
//! then reads them back for as long, and answers `madmin.SpeedTestResult`; with
//! `autotune` it goes on with more writers while reads keep getting faster. It runs in
//! the server, on the drive, so it measures the drive and the store, not the network.
//! S3's requests are held meanwhile, as `MinIO` holds them, and what it wrote is removed
//! afterwards unless `noclear` is asked.
//!
//! The drive test writes a file of `filesize` to each disk in blocks of `blocksize`,
//! syncs it, reads it back and removes it. A server is one node, so there's no network
//! between nodes or sites to measure.

use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use s3s::{Body, S3Request, S3Response, S3Result};
use serde::Serialize;
use teifs_iam::Identity;
use teifs_policy::Context;
use teifs_store::{Encryption, Layout, ObjectAttrs, Precondition, Store, StoreError};
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    access::allows, admin::error, errors::StoreResultExt, lines, minio_info,
    minio_service::Control, routes::Routes,
};

/// The bucket `MinIO`'s object test uses unless asked for another.
const PERF_BUCKET: &str = "minio-perf-test-tmp-bucket";
/// Where in the bucket its objects go.
const PREFIX: &str = "speedtest";
/// How often a running test answers its last result again (or an empty one).
const KEEP_ALIVE: Duration = Duration::from_millis(500);
/// Bytes read at a time.
const CHUNK: usize = 1 << 20;

/// Which of the calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `POST speedtest`, `speedtest/object`.
    Object,
    /// `POST speedtest/drive`.
    Drive,
    /// `POST speedtest/net`, `speedtest/site`: between nodes or sites.
    Network,
}

impl Call {
    /// The call's name, as the audit log and traces name it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Object => "Speedtest",
            Self::Drive => "DriveSpeedtest",
            Self::Network => "Netperf",
        }
    }

    pub(crate) async fn call(
        self,
        routes: &Routes,
        req: &S3Request<Body>,
        caller: (&Identity, &Context),
    ) -> S3Result<S3Response<Body>> {
        match self {
            Self::Object => object(routes, req, caller).await,
            Self::Drive => Ok(drive(routes, req).await),
            Self::Network => Err(error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                "A server is one node: there's no network between nodes or sites to measure.",
            )),
        }
    }
}

/// `madmin.Timings`, in nanoseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct Timings {
    avg: u64,
    p50: u64,
    p75: u64,
    p95: u64,
    p99: u64,
    p999: u64,
    l5p: u64,
    s5p: u64,
    max: u64,
    min: u64,
    sdev: u64,
    range: u64,
}

/// What `madmin`'s `TimeDurations.Measure` makes of `samples`.
#[expect(
    clippy::cast_precision_loss,
    reason = "a standard deviation, as Go computes it"
)]
fn measure(samples: &mut [Duration]) -> Timings {
    if samples.is_empty() {
        return Timings::default();
    }
    samples.sort_unstable();
    let nanos = |d: Duration| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
    let len = samples.len();
    let at = |p: f64| {
        let index = rounded(len, p).saturating_sub(1).min(len - 1);
        nanos(samples[index])
    };
    let mean = |set: &[Duration]| {
        let total: u128 = set.iter().map(Duration::as_nanos).sum();
        u64::try_from(total / set.len() as u128).unwrap_or(u64::MAX)
    };
    let avg = mean(samples);
    let variance = samples
        .iter()
        .map(|d| {
            let delta = avg as f64 - nanos(*d) as f64;
            delta * delta
        })
        .sum::<f64>()
        / len as f64;
    let longest = &samples[rounded(len, 0.95).min(len)..];
    let shortest = &samples[..rounded(len, 0.05).min(len)];
    let (min, max) = (nanos(samples[0]), nanos(samples[len - 1]));
    Timings {
        avg,
        p50: nanos(samples[len / 2]),
        p75: at(0.75),
        p95: at(0.95),
        p99: at(0.99),
        p999: at(0.999),
        l5p: if longest.len() <= 1 {
            max
        } else {
            mean(longest)
        },
        s5p: if shortest.len() <= 1 {
            min
        } else {
            mean(shortest)
        },
        max,
        min,
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a standard deviation is positive and far below u64::MAX nanoseconds"
        )]
        sdev: variance.sqrt() as u64,
        range: max - min,
    }
}

/// `len * share`, rounded as Go's `int(x + 0.5)`.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "Go's own arithmetic, on sample counts"
)]
fn rounded(len: usize, share: f64) -> usize {
    (len as f64 * share + 0.5) as usize
}

/// `madmin.SpeedTestStatServer`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerStats {
    endpoint: String,
    throughput_per_sec: u64,
    objects_per_sec: u64,
    err: String,
}

/// `madmin.SpeedTestStats`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Stats {
    throughput_per_sec: u64,
    objects_per_sec: u64,
    response_time: Timings,
    ttfb: Timings,
    servers: Vec<ServerStats>,
}

/// `madmin.SpeedTestResult`.
#[derive(Debug, Clone, Default, Serialize)]
struct SpeedTestResult {
    version: &'static str,
    servers: u32,
    disks: usize,
    size: u64,
    concurrent: usize,
    #[serde(rename = "PUTStats")]
    put: Stats,
    #[serde(rename = "GETStats")]
    get: Stats,
}

fn line(value: &impl Serialize) -> Bytes {
    let mut line = serde_json::to_vec(value).expect("a speed test result serializes");
    line.push(b'\n');
    Bytes::from(line)
}

/// What an object test asks for, read as `MinIO` reads it: what can't be read is the
/// default (64 MiB objects, 32 writers, 10 seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectOptions {
    size: u64,
    concurrent: usize,
    duration: Duration,
    bucket: Option<String>,
    autotune: bool,
    no_clear: bool,
}

impl ObjectOptions {
    fn parse(query: &str) -> Self {
        let pairs: std::collections::BTreeMap<String, String> =
            form_urlencoded::parse(query.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
        let get = |name: &str| pairs.get(name).map_or("", |v| v.trim());
        Self {
            size: get("size")
                .parse()
                .ok()
                .filter(|s| *s > 0)
                .unwrap_or(64 << 20),
            concurrent: get("concurrent")
                .parse()
                .ok()
                .filter(|c| *c > 0)
                .unwrap_or(32),
            duration: teifs_types::config_kv::go_duration(get("duration"))
                .ok()
                .filter(|d| !d.is_zero())
                .unwrap_or(Duration::from_secs(10)),
            bucket: Some(get("bucket"))
                .filter(|b| !b.is_empty())
                .map(str::to_owned),
            autotune: get("autotune") == "true",
            no_clear: get("noclear") == "true",
        }
    }
}

/// What one round of an object test did.
#[derive(Debug, Default)]
struct Round {
    uploaded: u64,
    downloaded: u64,
    upload_times: Vec<Duration>,
    download_times: Vec<Duration>,
    first_bytes: Vec<Duration>,
    error: Option<String>,
}

/// The keys an object test wrote, with their version ids.
type Written = Arc<std::sync::Mutex<Vec<(String, Option<String>)>>>;

/// An object test under way.
struct ObjectTest {
    store: Store,
    bucket: String,
    /// Where this test's objects go: `speedtest/<uuid>`.
    prefix: String,
    options: ObjectOptions,
    data: Bytes,
    node: String,
    disks: usize,
    stop: CancellationToken,
    /// Everything written, to remove afterwards: key and version id.
    written: Written,
}

impl ObjectTest {
    /// Writes for the test's duration, then reads what was written for as long.
    async fn round(&self, concurrency: usize) -> Round {
        let deadline = Instant::now() + self.options.duration;
        let uploaded = Arc::new(AtomicU64::new(0));
        let mut writers = tokio::task::JoinSet::new();
        for writer in 0..concurrency {
            let (store, bucket, data) =
                (self.store.clone(), self.bucket.clone(), self.data.clone());
            let (prefix, stop) = (self.prefix.clone(), self.stop.clone());
            let (written, uploaded) = (Arc::clone(&self.written), Arc::clone(&uploaded));
            writers.spawn(async move {
                let mut times = Vec::new();
                let mut count = 0_u64;
                while Instant::now() < deadline && !stop.is_cancelled() {
                    let key = format!("{prefix}/{writer}/{count}");
                    let started = Instant::now();
                    let info = put(&store, &bucket, &key, &data)
                        .await
                        .map_err(|e| e.to_string())?;
                    written
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((key, info.version_id));
                    count += 1;
                    if Instant::now() <= deadline {
                        times.push(started.elapsed());
                        uploaded.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                }
                Ok::<_, String>((writer, count, times))
            });
        }
        let mut round = Round::default();
        let mut counts = vec![0_u64; concurrency];
        while let Some(done) = writers.join_next().await {
            match done {
                Ok(Ok((writer, count, times))) => {
                    counts[writer] = count;
                    round.upload_times.extend(times);
                }
                Ok(Err(err)) => round.error = Some(err),
                Err(err) => round.error = Some(err.to_string()),
            }
        }
        round.uploaded = uploaded.load(Ordering::Relaxed);
        if round.error.is_some() {
            return round;
        }
        let deadline = Instant::now() + self.options.duration;
        let mut readers = tokio::task::JoinSet::new();
        for (reader, count) in counts.into_iter().enumerate().filter(|(_, n)| *n > 0) {
            let (store, bucket) = (self.store.clone(), self.bucket.clone());
            let (prefix, stop) = (self.prefix.clone(), self.stop.clone());
            readers.spawn(async move {
                let mut read = (0_u64, Vec::new(), Vec::new());
                let mut next = 0;
                while Instant::now() < deadline && !stop.is_cancelled() {
                    let key = format!("{prefix}/{reader}/{next}");
                    next = (next + 1) % count;
                    let started = Instant::now();
                    let (bytes, first_byte) = get(&store, &bucket, &key)
                        .await
                        .map_err(|e| e.to_string())?;
                    if Instant::now() <= deadline {
                        read.0 += bytes;
                        read.1.push(started.elapsed());
                        read.2.push(first_byte);
                    }
                }
                Ok::<_, String>(read)
            });
        }
        while let Some(done) = readers.join_next().await {
            match done {
                Ok(Ok((bytes, times, first_bytes))) => {
                    round.downloaded += bytes;
                    round.download_times.extend(times);
                    round.first_bytes.extend(first_bytes);
                }
                Ok(Err(err)) => round.error = Some(err),
                Err(err) => round.error = Some(err.to_string()),
            }
        }
        round
    }

    /// The result `MinIO` sends for a round run with `concurrency` writers.
    fn result(&self, round: &mut Round, concurrency: usize) -> SpeedTestResult {
        let seconds = self.options.duration.as_secs_f64();
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss,
            reason = "rates of bytes and objects a second"
        )]
        let per_second = |bytes: u64| (bytes as f64 / seconds) as u64;
        let size = self.options.size;
        let mut err = round.error.clone().unwrap_or_default();
        if err.is_empty() && (round.uploaded == 0 || round.downloaded == 0) {
            let what = if round.uploaded == 0 {
                "uploads"
            } else {
                "downloads"
            };
            err = format!(
                "no results for {what} upon first attempt, concurrency {concurrency} and \
                 duration {}s",
                self.options.duration.as_secs()
            );
        }
        let stats = |bytes: u64, times: &mut Vec<Duration>| Stats {
            throughput_per_sec: per_second(bytes),
            objects_per_sec: per_second(bytes) / size,
            response_time: measure(times),
            ttfb: Timings::default(),
            servers: vec![ServerStats {
                endpoint: self.node.clone(),
                throughput_per_sec: per_second(bytes),
                objects_per_sec: per_second(bytes) / size,
                err: err.clone(),
            }],
        };
        let put = stats(round.uploaded, &mut round.upload_times);
        let mut get = stats(round.downloaded, &mut round.download_times);
        get.ttfb = measure(&mut round.first_bytes);
        SpeedTestResult {
            version: env!("CARGO_PKG_VERSION"),
            servers: 1,
            disks: self.disks,
            size,
            concurrent: concurrency,
            put,
            get,
        }
    }

    /// Runs rounds as `MinIO`'s `objectSpeedTest` does, sending each result.
    async fn run(&self, results: &mpsc::Sender<Bytes>) {
        let mut concurrency = self.options.concurrent;
        if self.options.autotune {
            let cpus = std::thread::available_parallelism().map_or(4, usize::from);
            concurrency = concurrency.min(self.disks).max(4).min(cpus);
        }
        let mut best_get = 0;
        let mut best: Option<SpeedTestResult> = None;
        loop {
            if self.stop.is_cancelled() {
                return;
            }
            let mut round = self.round(concurrency).await;
            let result = self.result(&mut round, concurrency);
            if round.downloaded < best_get {
                // Reads got slower: the best earlier round is as far as it goes.
                if let Some(best) = &best {
                    let _ = results.send(line(best)).await;
                }
                return;
            }
            #[expect(clippy::cast_precision_loss, reason = "a growth rate")]
            let flat = ((round.downloaded - best_get) as f64) < 0.025 * round.downloaded as f64;
            best_get = round.downloaded;
            let failed = round.error.is_some();
            if results.send(line(&result)).await.is_err() {
                return;
            }
            best = Some(result);
            if flat || failed || !self.options.autotune {
                return;
            }
            concurrency += concurrency.div_ceil(2);
        }
    }

    /// Removes what the test wrote, and the bucket if the test made it.
    async fn clear(&self, made_bucket: bool) {
        let written = std::mem::take(
            &mut *self
                .written
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for (key, version) in written {
            let removed = self
                .store
                .delete_with(
                    &self.bucket,
                    &key,
                    version.as_deref(),
                    Precondition::default(),
                    false,
                )
                .await;
            if let Err(err) = removed {
                tracing::warn!(error = %err, key, "a speed test object wasn't removed");
            }
        }
        if made_bucket && let Err(err) = self.store.delete_bucket(&self.bucket).await {
            tracing::warn!(error = %err, bucket = %self.bucket, "the speed test bucket wasn't removed");
        }
    }
}

async fn put(
    store: &Store,
    bucket: &str,
    key: &str,
    data: &[u8],
) -> Result<teifs_store::ObjectInfo, StoreError> {
    let mut staged = store.stage_for(bucket, &Encryption::None).await?;
    staged.write(data).await?;
    store
        .commit(
            bucket,
            key,
            staged,
            ObjectAttrs::default(),
            Precondition::default(),
        )
        .await
}

/// Reads an object to its end: its size, and how long its first bytes took.
async fn get(store: &Store, bucket: &str, key: &str) -> Result<(u64, Duration), StoreError> {
    let started = Instant::now();
    let (info, body) = store.read(bucket, key).await?;
    let Some(body) = body else {
        return Ok((0, started.elapsed()));
    };
    let mut reader = body.range(0, info.size).await?;
    let mut buffer = vec![0; CHUNK];
    let mut read = 0;
    let mut first_byte = None;
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        first_byte.get_or_insert_with(|| started.elapsed());
        read += n as u64;
    }
    Ok((read, first_byte.unwrap_or_else(|| started.elapsed())))
}

/// Bytes that don't repeat, so nothing on the way can make them smaller.
fn noise(len: u64) -> Bytes {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    Bytes::from(bytes)
}

/// Holds S3's requests while it lives, as `MinIO` holds them during a speed test.
struct Frozen(Arc<Control>);

impl Frozen {
    fn new(control: &Arc<Control>) -> Self {
        control.freeze();
        Self(Arc::clone(control))
    }
}

impl Drop for Frozen {
    fn drop(&mut self) {
        self.0.unfreeze();
    }
}

/// A body of what `results` sends, with the last one (or an empty result) again every
/// half second meanwhile, as `MinIO` keeps a speed test's answer alive. `stop` is
/// cancelled when the caller leaves.
fn kept_alive(mut results: mpsc::Receiver<Bytes>, empty: Bytes, stop: CancellationToken) -> Body {
    let (lines, out) = mpsc::channel(4);
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval_at(tokio::time::Instant::now() + KEEP_ALIVE, KEEP_ALIVE);
        let mut last = empty;
        loop {
            let next = tokio::select! {
                () = lines.closed() => break,
                _ = tick.tick() => last.clone(),
                result = results.recv() => match result {
                    Some(result) => {
                        last = result.clone();
                        result
                    }
                    None => break,
                },
            };
            if lines.send(next).await.is_err() {
                break;
            }
        }
        stop.cancel();
    });
    lines::body(out)
}

fn streamed(body: Body) -> S3Response<Body> {
    let mut response = S3Response::new(body);
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// `POST /minio/admin/v3/speedtest`.
async fn object(
    routes: &Routes,
    req: &S3Request<Body>,
    (identity, context): (&Identity, &Context),
) -> S3Result<S3Response<Body>> {
    let options = ObjectOptions::parse(req.uri.query().unwrap_or_default());
    let store = &routes.store;
    let disks = minio_info::disks(routes).await;
    let room = store.disks().await.s3()?.first().map_or(0, |d| d.available);
    let needed = options.size.saturating_mul(options.concurrent as u64);
    if room < needed {
        return Err(error(
            StatusCode::INSUFFICIENT_STORAGE,
            "XMinioSpeedtestInsufficientCapacity",
            format!(
                "not enough usable space available to perform speedtest - expected {needed} \
                 bytes, got {room}"
            ),
        ));
    }
    let (bucket, made_bucket) = match &options.bucket {
        Some(bucket) => {
            let rules = routes.rules.of(bucket).await?;
            let on = teifs_policy::object_arn(bucket, &format!("{PREFIX}/"));
            let may = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
                .iter()
                .all(|action| allows(identity, context, action, &on, Some(&rules)));
            if !may {
                return Err(error(
                    StatusCode::FORBIDDEN,
                    "XMinioSpeedtestInsufficientPermissions",
                    format!("the caller does not have read and write access to '{bucket}' bucket"),
                ));
            }
            (bucket.clone(), false)
        }
        None => match store.create_bucket(PERF_BUCKET, Layout::Object).await {
            Ok(()) => (PERF_BUCKET.to_owned(), true),
            Err(StoreError::BucketExists) => (PERF_BUCKET.to_owned(), false),
            Err(err) => return Err(crate::errors::from_store(err)),
        },
    };
    let stop = CancellationToken::new();
    let test = ObjectTest {
        store: store.clone(),
        bucket,
        prefix: format!("{PREFIX}/{}", uuid::Uuid::new_v4()),
        data: noise(options.size),
        node: minio_info::endpoint(routes, req),
        disks: disks.len().max(1),
        stop: stop.clone(),
        written: Arc::default(),
        options,
    };
    let frozen = Frozen::new(&routes.control);
    let (results, received) = mpsc::channel(4);
    tokio::spawn(async move {
        let _frozen = frozen;
        test.run(&results).await;
        if !test.options.no_clear {
            test.clear(made_bucket).await;
        }
    });
    Ok(streamed(kept_alive(
        received,
        line(&SpeedTestResult::default()),
        stop,
    )))
}

/// `madmin.DrivePerf`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct DrivePerf {
    path: String,
    read_throughput: u64,
    write_throughput: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

/// `madmin.DriveSpeedTestResult`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct DriveSpeedTestResult {
    version: &'static str,
    endpoint: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    drive_perf: Vec<DrivePerf>,
}

/// What a drive test asks for, as `MinIO` reads it: 4 MiB blocks, 1 GiB files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DriveOptions {
    serial: bool,
    block_size: u64,
    file_size: u64,
}

impl DriveOptions {
    fn parse(query: &str) -> Self {
        let mut options = Self {
            serial: false,
            block_size: 4 << 20,
            file_size: 1 << 30,
        };
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            match &*name {
                "serial" => options.serial = value == "true",
                "blocksize" => {
                    if let Ok(size) = value.parse::<u64>().map(|s| s.min(1 << 30)) {
                        options.block_size = size.max(1);
                    }
                }
                "filesize" => {
                    if let Ok(size) = value.parse() {
                        options.file_size = size;
                    }
                }
                _ => {}
            }
        }
        options
    }
}

/// Writes a file of `file_size` in `dir` a block at a time, syncs it, reads it back and
/// removes it: its write and read rates, in bytes a second.
fn drive_perf(dir: &std::path::Path, options: DriveOptions) -> std::io::Result<(u64, u64)> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("speedtest-{}", uuid::Uuid::new_v4()));
    let block = noise(options.block_size);
    let measured = (|| -> std::io::Result<(Duration, Duration)> {
        let started = Instant::now();
        let mut file = std::fs::File::create(&path)?;
        let mut left = options.file_size;
        while left > 0 {
            let n = usize::try_from(left.min(block.len() as u64)).unwrap_or(block.len());
            file.write_all(&block[..n])?;
            left -= n as u64;
        }
        file.sync_all()?;
        let wrote = started.elapsed();
        let started = Instant::now();
        let mut file = std::fs::File::open(&path)?;
        let mut buffer = vec![0; block.len()];
        while file.read(&mut buffer)? > 0 {}
        Ok((wrote, started.elapsed()))
    })();
    let _ = std::fs::remove_file(&path);
    let (wrote, read) = measured?;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "rates of bytes a second"
    )]
    let rate = |took: Duration| (options.file_size as f64 / took.as_secs_f64().max(1e-9)) as u64;
    Ok((rate(wrote), rate(read)))
}

/// `POST /minio/admin/v3/speedtest/drive`.
async fn drive(routes: &Routes, req: &S3Request<Body>) -> S3Response<Body> {
    let options = DriveOptions::parse(req.uri.query().unwrap_or_default());
    let disks = routes
        .store
        .disks()
        .await
        .inspect_err(|err| tracing::error!(error = %err, "can't read the drive's disks"))
        .unwrap_or_default();
    let root = routes
        .store
        .root()
        .join(teifs_store::SYSTEM_DIR)
        .join("tmp");
    let node = minio_info::endpoint(routes, req);
    let stop = CancellationToken::new();
    let (results, received) = mpsc::channel(1);
    let testing = stop.clone();
    tokio::spawn(async move {
        let tests = disks.into_iter().enumerate().map(|(index, disk)| {
            // The drive's own temporary folder, or a bucket's on another disk.
            let dir: PathBuf = if index == 0 {
                root.clone()
            } else {
                disk.path.join(".teifs-tmp")
            };
            async move {
                let path = disk.path.display().to_string();
                if disk.available < options.file_size {
                    return DrivePerf {
                        path,
                        error: format!("not enough room: {} bytes free", disk.available),
                        ..DrivePerf::default()
                    };
                }
                match tokio::task::spawn_blocking(move || drive_perf(&dir, options)).await {
                    Ok(Ok((write, read))) => DrivePerf {
                        path,
                        read_throughput: read,
                        write_throughput: write,
                        error: String::new(),
                    },
                    Ok(Err(err)) => DrivePerf {
                        path,
                        error: err.to_string(),
                        ..DrivePerf::default()
                    },
                    Err(err) => DrivePerf {
                        path,
                        error: err.to_string(),
                        ..DrivePerf::default()
                    },
                }
            }
        });
        let drive_perf = if options.serial {
            let mut done = Vec::new();
            for test in tests {
                if testing.is_cancelled() {
                    return;
                }
                done.push(test.await);
            }
            done
        } else {
            futures::future::join_all(tests).await
        };
        let _ = results
            .send(line(&DriveSpeedTestResult {
                version: env!("CARGO_PKG_VERSION"),
                endpoint: node,
                drive_perf,
            }))
            .await;
    });
    streamed(kept_alive(
        received,
        line(&DriveSpeedTestResult::default()),
        stop,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn timings_are_madmin_s() {
        let mut samples: Vec<Duration> = (1..=100).rev().map(Duration::from_millis).collect();
        let timings = measure(&mut samples);
        let ms = 1_000_000;
        assert_eq!(timings.min, ms);
        assert_eq!(timings.max, 100 * ms);
        assert_eq!(timings.range, 99 * ms);
        assert_eq!(timings.p50, 51 * ms);
        assert_eq!(timings.p75, 75 * ms);
        assert_eq!(timings.p99, 99 * ms);
        assert_eq!(timings.avg, 50_500_000);
        // The longest 5% are 96..=100 ms, the shortest 1..=5 ms.
        assert_eq!(timings.l5p, 98 * ms);
        assert_eq!(timings.s5p, 3 * ms);
        assert_eq!(timings.sdev, 28_866_070);
        assert_eq!(measure(&mut []), Timings::default());
        let one = measure(&mut [Duration::from_secs(1)]);
        assert_eq!(
            (one.p999, one.l5p, one.s5p),
            (1_000_000_000, 1_000_000_000, 1_000_000_000)
        );
    }

    #[test]
    fn object_options_are_minio_s() {
        let asked = ObjectOptions::parse(
            "size=1048576&concurrent=4&duration=2s&bucket=perf&autotune=true&noclear=true",
        );
        assert_eq!(
            asked,
            ObjectOptions {
                size: 1 << 20,
                concurrent: 4,
                duration: Duration::from_secs(2),
                bucket: Some("perf".to_owned()),
                autotune: true,
                no_clear: true,
            }
        );
        let loose = ObjectOptions::parse("size=big&concurrent=-1&duration=soon&bucket=%20");
        assert_eq!(
            (loose.size, loose.concurrent, loose.duration, loose.bucket),
            (64 << 20, 32, Duration::from_secs(10), None)
        );
    }

    #[test]
    fn drive_options_are_minio_s() {
        assert_eq!(
            DriveOptions::parse("serial=true&blocksize=4096&filesize=65536"),
            DriveOptions {
                serial: true,
                block_size: 4096,
                file_size: 65536
            }
        );
        assert_eq!(
            DriveOptions::parse("blocksize=0&filesize=x"),
            DriveOptions {
                serial: false,
                block_size: 1,
                file_size: 1 << 30
            }
        );
    }

    #[test]
    fn a_drive_is_written_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let options = DriveOptions {
            serial: false,
            block_size: 4096,
            file_size: 1 << 20,
        };
        let (write, read) = drive_perf(dir.path(), options).unwrap();
        assert!(write > 0 && read > 0, "{write} {read}");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "the file is removed"
        );
    }

    #[test]
    fn noise_doesn_t_repeat() {
        let bytes = noise(1 << 16);
        assert_eq!(bytes.len(), 1 << 16);
        assert_ne!(bytes[..8], bytes[8..16]);
        assert_eq!(noise(5).len(), 5);
    }
}
