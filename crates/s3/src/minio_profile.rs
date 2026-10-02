//! `MinIO`'s profiling (`mc admin profile`, `mc support profile`): `POST profile` takes
//! profiles for a while and answers them in a zip, as `MinIO` does; `POST profiling/start`
//! and `GET profiling/download` are its older pair of calls that start them and collect
//! them later.
//!
//! The server takes CPU profiles (`cpu`), sampling 100 times a second as Go's profiler
//! does, in pprof's format, which `go tool pprof` and other pprof tools read. The other
//! types are a Go runtime's (heap, goroutines, blocking, mutexes, the execution tracer)
//! and are refused, as `MinIO` refuses a type it doesn't know.

use std::{collections::BTreeMap, io::Write as _, sync::Mutex, time::Duration};

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use s3s::{Body, S3Request, S3Response, S3Result};
use serde::Serialize;

use crate::{admin::error, minio_info, routes::Routes};

/// How long `POST profile` profiles when it isn't told.
const DEFAULT_DURATION: Duration = Duration::from_secs(60);
/// The longest it profiles: a profile's samples are kept in memory meanwhile.
const MAX_DURATION: Duration = Duration::from_hours(1);

/// Which of the calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `POST profile`.
    Profile,
    /// `POST profiling/start`.
    Start,
    /// `GET profiling/download`.
    Download,
}

impl Call {
    /// The call's name, as the audit log and traces name it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Profile => "Profile",
            Self::Start => "StartProfiling",
            Self::Download => "DownloadProfiling",
        }
    }

    pub(crate) async fn call(
        self,
        routes: &Routes,
        req: &S3Request<Body>,
    ) -> S3Result<S3Response<Body>> {
        match self {
            Self::Profile => profile(routes, req).await,
            Self::Start => Ok(start(routes, req)),
            Self::Download => download(routes, req).await,
        }
    }
}

/// A profile being taken.
enum Profiler {
    #[cfg(unix)]
    Cpu(pprof::ProfilerGuard<'static>),
}

impl Profiler {
    /// Starts profiling of `kind`.
    fn start(kind: &str) -> Result<Self, String> {
        match kind {
            "cpu" => Self::cpu(),
            "cpuio" | "mem" | "block" | "mutex" | "trace" | "threads" | "goroutines"
            | "runtime" | "metrics" => Err(format!(
                "{kind} profiles are a Go runtime's: this server takes cpu profiles"
            )),
            _ => Err("profiler type unknown".to_owned()),
        }
    }

    #[cfg(unix)]
    fn cpu() -> Result<Self, String> {
        pprof::ProfilerGuardBuilder::default()
            .frequency(100)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
            .map(Self::Cpu)
            .map_err(|err| err.to_string())
    }

    #[cfg(not(unix))]
    fn cpu() -> Result<Self, String> {
        Err("cpu profiles are taken on Linux and macOS only".to_owned())
    }

    /// Stops it: its file's name and bytes, gzipped as Go's profiles are.
    #[cfg(unix)]
    fn stop(self, kind: &str) -> Result<(String, Vec<u8>), String> {
        match self {
            Self::Cpu(guard) => {
                use pprof::protos::Message as _;
                let profile = guard
                    .report()
                    .build()
                    .and_then(|report| report.pprof())
                    .map_err(|err| err.to_string())?;
                let bytes = profile.write_to_bytes().map_err(|err| err.to_string())?;
                let mut gzipped =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                gzipped
                    .write_all(&bytes)
                    .and_then(|()| gzipped.finish())
                    .map(|file| (format!("{kind}.pprof"), file))
                    .map_err(|err| err.to_string())
            }
        }
    }

    #[cfg(not(unix))]
    fn stop(self, _: &str) -> Result<(String, Vec<u8>), String> {
        match self {}
    }
}

/// The profiles being taken, by type.
#[derive(Default)]
pub(crate) struct Profiles(Mutex<BTreeMap<String, Profiler>>);

impl Profiles {
    fn running(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Profiler>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Starts profiles of `kinds` (stopping any of those that run): each kind, and why
    /// it didn't start if it didn't.
    #[cfg_attr(
        not(unix),
        allow(unreachable_patterns, reason = "none starts on Windows")
    )]
    fn start(&self, kinds: &[&str], stop_others: bool) -> Vec<(String, Option<String>)> {
        let mut running = self.running();
        if stop_others {
            running.clear();
        }
        let mut started = Vec::new();
        for kind in kinds {
            // One CPU profiler runs at a time: the one running stops first.
            running.remove(*kind);
            match Profiler::start(kind) {
                Ok(profiler) => {
                    running.insert((*kind).to_owned(), profiler);
                    started.push(((*kind).to_owned(), None));
                }
                Err(err) => started.push(((*kind).to_owned(), Some(err))),
            }
        }
        started
    }

    /// Stops every profile: their files, by name. `None` when none was running.
    fn collect(&self) -> Option<BTreeMap<String, Vec<u8>>> {
        let running = std::mem::take(&mut *self.running());
        if running.is_empty() {
            return None;
        }
        let mut files = BTreeMap::new();
        for (kind, profiler) in running {
            match profiler.stop(&kind) {
                Ok((name, bytes)) => {
                    files.insert(name, bytes);
                }
                Err(err) => tracing::error!(error = %err, kind, "a profile couldn't be read"),
            }
        }
        Some(files)
    }

    /// Stops every profile, keeping nothing.
    fn clear(&self) {
        self.running().clear();
    }
}

/// Stops the profiles when the caller leaves before they're collected.
struct Abandoned<'a>(Option<&'a Profiles>);

impl Drop for Abandoned<'_> {
    fn drop(&mut self) {
        if let Some(profiles) = self.0 {
            profiles.clear();
        }
    }
}

/// `MinIO`'s answer when there's no profile to give.
fn not_enabled() -> s3s::S3Error {
    error(
        StatusCode::BAD_REQUEST,
        "XMinioAdminProfilerNotEnabled",
        "Unable to perform the requested operation because profiling is not enabled",
    )
}

/// The query's value for `name`.
fn query(req: &S3Request<Body>, name: &str) -> Option<String> {
    form_urlencoded::parse(req.uri.query().unwrap_or_default().as_bytes())
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.into_owned())
}

fn kinds(asked: &str) -> Vec<&str> {
    asked
        .split(',')
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .collect()
}

/// `POST profile?profilerType=&duration=`.
async fn profile(routes: &Routes, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let duration = match query(req, "duration").filter(|d| !d.is_empty()) {
        None => DEFAULT_DURATION,
        Some(asked) => teifs_types::config_kv::go_duration(&asked)
            .ok()
            .filter(|d| *d <= MAX_DURATION)
            .ok_or_else(|| {
                error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "Invalid Request: the duration isn't one, or is longer than an hour",
                )
            })?,
    };
    let asked = query(req, "profilerType").unwrap_or_default();
    let started = routes.profiles.start(&kinds(&asked), true);
    for (kind, err) in &started {
        if let Some(err) = err {
            tracing::warn!(kind, error = %err, "a profile wasn't started");
        }
    }
    if started.iter().all(|(_, err)| err.is_some()) {
        return Err(not_enabled());
    }
    let mut abandoned = Abandoned(Some(&routes.profiles));
    let stopping = routes.tracers.stopping();
    tokio::select! {
        () = tokio::time::sleep(duration) => {}
        () = stopping.cancelled() => {}
    }
    abandoned.0 = None;
    let files = routes.profiles.collect().ok_or_else(not_enabled)?;
    zipped(routes, req, files).await
}

/// `madmin.StartProfilingResult`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Started {
    node_name: String,
    success: bool,
    error: String,
}

/// `POST profiling/start?profilerType=`: one result for each type asked.
fn start(routes: &Routes, req: &S3Request<Body>) -> S3Response<Body> {
    let asked = query(req, "profilerType").unwrap_or_default();
    let node = minio_info::endpoint(routes, req);
    let results: Vec<Started> = routes
        .profiles
        .start(&kinds(&asked), false)
        .into_iter()
        .map(|(_, err)| Started {
            node_name: node.clone(),
            success: err.is_none(),
            error: err.unwrap_or_default(),
        })
        .collect();
    crate::admin::json(&results)
}

/// `GET profiling/download`: the profiles started, stopped and zipped.
async fn download(routes: &Routes, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let files = routes.profiles.collect().ok_or_else(not_enabled)?;
    zipped(routes, req, files).await
}

/// `madmin.ClusterRegistrationInfo`, as `MinIO` puts it in a profile's zip.
#[derive(Debug, Serialize)]
struct ClusterInfo {
    deployment_id: String,
    cluster_name: String,
    used_capacity: u64,
    info: ClusterCounts,
}

#[derive(Debug, Serialize)]
struct ClusterCounts {
    minio_version: &'static str,
    no_of_server_pools: u32,
    no_of_servers: u32,
    no_of_drives: usize,
    no_of_buckets: u64,
    no_of_objects: u64,
    total_drive_space: u64,
    used_drive_space: u64,
}

async fn cluster_info(routes: &Routes) -> ClusterInfo {
    let disks = routes.store.disks().await.unwrap_or_default();
    let usage = routes.store.usage().await.unwrap_or_default();
    let total = usage
        .iter()
        .fold(teifs_store::Usage::default(), |total, b| total + b.usage);
    let version = env!("CARGO_PKG_VERSION");
    ClusterInfo {
        deployment_id: routes.store.format().drive.clone(),
        cluster_name: format!("1-servers-{}-disks-{version}", disks.len()),
        used_capacity: total.bytes,
        info: ClusterCounts {
            minio_version: version,
            no_of_server_pools: 1,
            no_of_servers: 1,
            no_of_drives: disks.len(),
            no_of_buckets: u64::try_from(usage.len()).unwrap_or(u64::MAX),
            no_of_objects: total.objects,
            total_drive_space: disks.iter().map(|d| d.total).sum(),
            used_drive_space: disks
                .iter()
                .map(|d| d.total.saturating_sub(d.available))
                .sum(),
        },
    }
}

/// The zip `MinIO` answers: `cluster.info`, then `profile-<node>-<file>` for each profile.
async fn zipped(
    routes: &Routes,
    req: &S3Request<Body>,
    files: BTreeMap<String, Vec<u8>>,
) -> S3Result<S3Response<Body>> {
    let info = serde_json::to_vec(&cluster_info(routes).await).expect("the info serializes");
    let node = minio_info::endpoint(routes, req);
    let zip = archive(
        std::iter::once(("cluster.info".to_owned(), info)).chain(
            files
                .into_iter()
                .map(|(name, bytes)| (format!("profile-{node}-{name}"), bytes)),
        ),
    )
    .map_err(|err| {
        tracing::error!(error = %err, "the profiles couldn't be zipped");
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "The profiles couldn't be zipped.",
        )
    })?;
    let mut response = S3Response::new(Body::from(Bytes::from(zip)));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    Ok(response)
}

/// A zip of `files`, compressed, readable only by their owner once unpacked.
pub(crate) fn archive(
    files: impl Iterator<Item = (String, Vec<u8>)>,
) -> zip::result::ZipResult<Vec<u8>> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o600);
    for (name, bytes) in files {
        zip.start_file(name, options)?;
        zip.write_all(&bytes)?;
    }
    Ok(zip.finish()?.into_inner())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn go_s_profiles_are_refused_and_unknown_ones_too() {
        let profiles = Profiles::default();
        let started = profiles.start(&["mem", "goroutines", "nonsense"], true);
        assert_eq!(started.len(), 3);
        assert!(started[0].1.as_deref().unwrap().contains("Go runtime"));
        assert_eq!(started[2].1.as_deref(), Some("profiler type unknown"));
        assert!(profiles.collect().is_none(), "nothing runs");
    }

    #[test]
    fn kinds_are_split_on_commas() {
        assert_eq!(kinds("cpu, mem,,"), ["cpu", "mem"]);
        assert!(kinds("").is_empty());
    }

    #[test]
    fn the_archive_holds_each_file() {
        let zip = archive(
            [
                ("cluster.info".to_owned(), b"{}".to_vec()),
                ("profile-n-cpu.pprof".to_owned(), vec![1, 2, 3]),
            ]
            .into_iter(),
        )
        .unwrap();
        let mut read = zip::ZipArchive::new(std::io::Cursor::new(zip)).unwrap();
        assert_eq!(read.len(), 2);
        let mut cpu = read.by_name("profile-n-cpu.pprof").unwrap();
        assert_eq!(cpu.unix_mode(), Some(0o100_600));
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut cpu, &mut bytes).unwrap();
        assert_eq!(bytes, [1, 2, 3]);
    }

    #[cfg(unix)]
    #[test]
    fn a_cpu_profile_is_gzipped_pprof() {
        let profiles = Profiles::default();
        assert_eq!(profiles.start(&["cpu"], true)[0].1, None);
        // Something to sample.
        let until = std::time::Instant::now() + Duration::from_millis(300);
        let mut spin = 0_u64;
        while std::time::Instant::now() < until {
            spin = spin.wrapping_mul(31).wrapping_add(7);
        }
        std::hint::black_box(spin);
        let files = profiles.collect().unwrap();
        let cpu = &files["cpu.pprof"];
        assert_eq!(cpu[..2], [0x1f, 0x8b], "gzip");
        assert!(profiles.collect().is_none(), "collected once");
    }
}
