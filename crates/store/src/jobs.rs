//! Background jobs: work that keeps a long-running drive tidy without a restart.
//!
//! Every job does its work in bounded steps on the blocking pool. After a step that did
//! something, the job sleeps for the step's duration times the pace factor, so a job
//! never takes more than its share of a core however much there is to do; after a step
//! with nothing to do, it waits for its idle interval. Jobs stop at the end of their
//! current step when told to, and report what they've done.

use std::{
    collections::BTreeMap,
    fs, io,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{Inner, Store, error::Result};

mod lifecycle;
pub(crate) mod scrub;
#[cfg(test)]
pub(crate) use lifecycle::ApplyLifecycle;

/// How long an idle staged file may sit before it's swept (active writes keep touching it).
const STAGED_IDLE: Duration = Duration::from_hours(1);
/// How long answers kept for retries (client tokens, completed uploads) live.
const RETRY_WINDOW: Duration = Duration::from_hours(24);
/// The longest pause between two busy steps, whatever the pace.
const MAX_PAUSE: Duration = Duration::from_secs(5);
/// Uploads one step may expire, and garbage files one step may remove.
pub(crate) const BATCH: usize = 256;

/// How the background jobs run.
#[derive(Debug, Clone)]
pub struct JobOptions {
    /// How long a multipart upload may stay unfinished before it's aborted; `None` keeps
    /// uploads until they're completed or aborted.
    pub upload_expiry: Option<Duration>,
    /// Pause after a busy step, as a multiple of the step's duration: 1 lets a job use
    /// at most half a core, 0 runs it flat out.
    pub pace: f64,
    /// How often every stored version is read back and checked (a pass starts this
    /// long after the last one started); `None` never scrubs.
    pub scrub_every: Option<Duration>,
}

impl Default for JobOptions {
    fn default() -> Self {
        Self {
            upload_expiry: Some(Duration::from_hours(7 * 24)),
            pace: 1.0,
            scrub_every: Some(Duration::from_hours(30 * 24)),
        }
    }
}

/// What a job has done since the drive opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobStatus {
    /// Steps run.
    pub steps: u64,
    /// Items handled (uploads expired, files swept, …).
    pub items: u64,
    /// When a step last handled something.
    pub last_progress: Option<SystemTime>,
    /// The last step's error, if it failed.
    pub last_error: Option<String>,
}

/// What a step runs with.
pub(crate) struct Step {
    /// The time the step runs at.
    pub now: SystemTime,
    /// Set when the jobs are stopping: long work checks it and ends early.
    pub cancel: CancellationToken,
}

/// One kind of background work.
pub(crate) trait Job: Send + 'static {
    /// Its name, as `teifs status` shows it.
    fn name(&self) -> &'static str;
    /// Does one bounded piece of work; how many items it handled (0: there was nothing
    /// to do).
    fn step(&mut self, inner: &Inner, step: &Step) -> Result<usize>;
    /// How long to wait after a step with nothing to do.
    fn idle(&self) -> Duration;
}

/// Aborts multipart uploads left unfinished for too long.
pub(crate) struct ExpireUploads {
    pub after: Duration,
}

impl Job for ExpireUploads {
    fn name(&self) -> &'static str {
        "expire-uploads"
    }

    fn step(&mut self, inner: &Inner, step: &Step) -> Result<usize> {
        let before = millis(step.now) - millis_of(self.after);
        let stale = inner.lock().stale_uploads(before, BATCH)?;
        let mut done = 0;
        for id in stale {
            match inner.abort_upload(&id) {
                // Completed or aborted meanwhile: gone either way.
                Ok(()) | Err(crate::StoreError::NoSuchUpload) => done += 1,
                Err(err) => return Err(err),
            }
        }
        if done > 0 {
            tracing::info!(count = done, "aborted stale multipart uploads");
        }
        Ok(done)
    }

    fn idle(&self) -> Duration {
        Duration::from_hours(1)
    }
}

/// Removes staged files abandoned by writes that never finished (a crashed client,
/// a dropped connection that left something behind).
pub(crate) struct SweepStaging;

impl Job for SweepStaging {
    fn name(&self) -> &'static str {
        "sweep-staging"
    }

    fn step(&mut self, inner: &Inner, step: &Step) -> Result<usize> {
        let now = step.now;
        let mut swept = sweep_idle_files(&inner.tmp, now)?;
        // Buckets on other disks stage writes in their own folder.
        for entry in fs::read_dir(&inner.root)?.flatten() {
            let staging = entry.path().join(teifs_types::BUCKET_STAGING);
            if staging.is_dir() {
                swept += sweep_idle_files(&staging, now)?;
            }
        }
        if swept > 0 {
            tracing::info!(count = swept, "removed abandoned staged files");
        }
        Ok(swept)
    }

    fn idle(&self) -> Duration {
        Duration::from_mins(15)
    }
}

/// Removes the files in `dir` untouched for [`STAGED_IDLE`].
fn sweep_idle_files(dir: &Path, now: SystemTime) -> Result<usize> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err.into()),
    };
    let mut swept = 0;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let idle = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age > STAGED_IDLE);
        if meta.is_file() && idle && fs::remove_file(entry.path()).is_ok() {
            swept += 1;
        }
    }
    Ok(swept)
}

/// Retries the garbage queue and forgets answers kept for retries once they're too old.
pub(crate) struct Housekeeping;

impl Job for Housekeeping {
    fn name(&self) -> &'static str {
        "housekeeping"
    }

    fn step(&mut self, inner: &Inner, step: &Step) -> Result<usize> {
        let now = step.now;
        let conn = inner.lock();
        let removed = inner.sweep_garbage(&conn, BATCH)?;
        let before = millis(now) - millis_of(RETRY_WINDOW);
        conn.expire_client_tokens(before)?;
        let expired = conn.expire_completed(before)?;
        Ok(removed + expired)
    }

    fn idle(&self) -> Duration {
        Duration::from_mins(10)
    }
}

pub(crate) fn millis(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, millis_of)
}

pub(crate) fn millis_of(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

/// What each job has done, by name: kept with the drive, so anything holding the
/// [`Store`] can report it.
pub(crate) type StatusMap = Arc<Mutex<BTreeMap<&'static str, JobStatus>>>;

/// The running background jobs. Dropping this doesn't stop them; [`Jobs::stop`] does.
#[derive(Debug)]
pub struct Jobs {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    status: StatusMap,
}

impl Jobs {
    /// What each job has done, by name.
    #[must_use]
    pub fn status(&self) -> BTreeMap<&'static str, JobStatus> {
        lock(&self.status).clone()
    }

    /// Stops every job at the end of its current step and waits for them.
    pub async fn stop(self) {
        self.cancel.cancel();
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Store {
    /// What each background job has done since the drive opened, by name; empty until
    /// [`Store::start_jobs`].
    #[must_use]
    pub fn job_status(&self) -> BTreeMap<&'static str, JobStatus> {
        lock(&self.inner.jobs).clone()
    }

    /// Starts the background jobs. Call once, from within a Tokio runtime.
    #[must_use]
    pub fn start_jobs(&self, options: &JobOptions) -> Jobs {
        let mut jobs: Vec<Box<dyn Job>> = vec![
            Box::new(Housekeeping),
            Box::new(SweepStaging),
            Box::new(crate::reconcile::IndexFolders::default()),
            Box::new(lifecycle::ApplyLifecycle::new(self.clone())),
        ];
        if let Some(after) = options.upload_expiry {
            jobs.push(Box::new(ExpireUploads { after }));
        }
        if let Some(every) = options.scrub_every {
            jobs.push(Box::new(scrub::Scrub::new(self.clone(), every)));
        }
        let cancel = CancellationToken::new();
        let status = Arc::clone(&self.inner.jobs);
        let tasks = jobs
            .into_iter()
            .map(|job| {
                tokio::spawn(run(
                    job,
                    Arc::clone(&self.inner),
                    options.pace,
                    cancel.clone(),
                    Arc::clone(&status),
                ))
            })
            .collect();
        Jobs {
            cancel,
            tasks,
            status,
        }
    }
}

async fn run(
    mut job: Box<dyn Job>,
    inner: Arc<Inner>,
    pace: f64,
    cancel: CancellationToken,
    status: StatusMap,
) {
    let name = job.name();
    lock(&status).insert(name, JobStatus::default());
    while !cancel.is_cancelled() {
        let started = Instant::now();
        let inner = Arc::clone(&inner);
        let step = Step {
            now: SystemTime::now(),
            cancel: cancel.clone(),
        };
        let (returned, result) = match tokio::task::spawn_blocking(move || {
            let result = job.step(&inner, &step);
            (job, result)
        })
        .await
        {
            Ok(done) => done,
            Err(err) => {
                tracing::error!(job = name, error = %err, "a background job panicked; it stops");
                return;
            }
        };
        job = returned;
        let elapsed = started.elapsed();
        let wait = {
            let mut status = lock(&status);
            let entry = status.entry(name).or_default();
            entry.steps += 1;
            match &result {
                Ok(0) => {
                    entry.last_error = None;
                    job.idle()
                }
                Ok(n) => {
                    entry.last_error = None;
                    entry.items += *n as u64;
                    entry.last_progress = Some(SystemTime::now());
                    elapsed.mul_f64(pace.max(0.0)).min(MAX_PAUSE)
                }
                Err(err) => {
                    tracing::warn!(job = name, error = %err, "a background job failed; it retries later");
                    entry.last_error = Some(err.to_string());
                    job.idle()
                }
            }
        };
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests;
