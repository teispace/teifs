//! The batch worker: runs batch jobs ([`crate::minio_batch`], and S3 Batch Operations'
//! in [`crate::batch_operations`]) one at a time, a page of keys per step, keeping each one's progress with it so a restart picks it up where
//! it was. The job running goes on until it ends; then the one with the highest
//! priority, the oldest first. A job whose page fails as a whole (the drive, not one
//! object) is tried again as its retries say, then fails. When a job ends, its result
//! is sent where it asked.

use std::{collections::HashMap, sync::Arc, time::Duration};

use teifs_store::{Store, StoreError};
use teifs_types::batch::{BatchJob, JobSpec, JobStatus};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::{
    batch_operations::{self, Operations},
    minio_batch::Ended,
};

/// How long the worker waits for a job when none is waiting.
const IDLE: Duration = Duration::from_secs(30);

/// How long a finished job is kept for its status.
const KEPT: Duration = Duration::from_hours(7 * 24);

/// Runs the batch jobs.
#[derive(Debug)]
pub(crate) struct Worker {
    store: Store,
    /// Woken when a job starts.
    wake: Arc<Notify>,
    /// How many times in a row each job's pages failed.
    errors: std::sync::Mutex<HashMap<String, u32>>,
    /// What runs S3 Batch Operations' tasks, with IAM.
    operations: Option<Operations>,
}

impl Worker {
    pub(crate) fn new(store: Store, wake: Arc<Notify>) -> Self {
        Self {
            store,
            wake,
            errors: std::sync::Mutex::default(),
            operations: None,
        }
    }

    /// Runs S3 Batch Operations' jobs too.
    pub(crate) fn run_operations(&mut self, operations: Operations) {
        self.operations = Some(operations);
    }

    /// Runs jobs until `stopping`.
    pub(crate) async fn run(self, stopping: CancellationToken) {
        let client = teifs_notify::client().ok();
        while !stopping.is_cancelled() {
            match self.step(client.as_ref()).await {
                Some(pause) if pause.is_zero() => tokio::task::yield_now().await,
                pause => {
                    self.forget_old().await;
                    tokio::select! {
                        () = stopping.cancelled() => break,
                        () = self.wake.notified() => {}
                        () = tokio::time::sleep(pause.unwrap_or(IDLE)) => {}
                    }
                }
            }
        }
    }

    /// Runs the next page of the job whose turn it is; how long to wait before the
    /// next step, `None` when no job waits.
    pub(crate) async fn step(&self, client: Option<&reqwest::Client>) -> Option<Duration> {
        let jobs = match self.store.batch_jobs().await {
            Ok(jobs) => jobs,
            Err(err) => {
                tracing::warn!(error = %err, "couldn't read the batch jobs");
                return None;
            }
        };
        let mut job = jobs
            .into_iter()
            // A suspended job waits for a person to confirm it.
            .filter(|job| !job.status.finished() && job.status != JobStatus::Suspended)
            .max_by_key(|job| {
                (
                    job.status == JobStatus::Active,
                    job.priority,
                    std::cmp::Reverse(job.created_ms),
                )
            })?;
        let now = crate::admin::millis(std::time::SystemTime::now());
        if job.status != JobStatus::Active && !batch_operations::preparing(job.status) {
            job.status = JobStatus::Active;
            job.progress.started_ms = Some(now);
            tracing::info!(job = job.id, kind = job.spec.kind(), "a batch job started");
        }
        let result = Box::pin(self.page(&mut job)).await;
        let retry = job.spec.retry();
        let (attempts, delay) = (retry.attempts.max(1), retry.delay_ms);
        let pause = match result {
            Ok(done) => {
                self.errors_of(&job.id, false);
                if done {
                    let failed = job.progress.objects_failed + job.progress.delete_markers_failed;
                    // An S3 Batch Operations job completes with the tasks that failed.
                    job.status = if failed > 0 && job.spec.is_minio() {
                        JobStatus::Failed
                    } else {
                        JobStatus::Complete
                    };
                }
                Duration::ZERO
            }
            Err(err) => {
                let failures = self.errors_of(&job.id, true);
                tracing::warn!(job = job.id, error = %err, failures, "a batch job's page failed");
                if matches!(err, StoreError::NoSuchBucket) || failures >= attempts {
                    job.failed_because(err.to_string());
                    job.status = JobStatus::Failed;
                    Duration::ZERO
                } else {
                    job.progress.retry_attempts += 1;
                    Duration::from_millis(delay)
                }
            }
        };
        job.progress.updated_ms = Some(crate::admin::millis(std::time::SystemTime::now()));
        let (status, progress, failures) = (job.status, job.progress.clone(), job.failures.clone());
        let kept = self
            .store
            .update_batch_job(&job.id, move |kept| {
                kept.status = status;
                kept.progress = progress;
                kept.failures = failures;
            })
            .await;
        match kept {
            // Cancelled meanwhile: it stays so.
            Ok(Some(kept)) if kept.status != status => {}
            Ok(Some(kept)) if kept.status.finished() => {
                self.errors_of(&kept.id, false);
                tracing::info!(
                    job = kept.id,
                    status = kept.status.as_str(),
                    "a batch job ended"
                );
                if let Some(client) = client {
                    self.notify(client, &kept).await;
                }
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(job = job.id, error = %err, "couldn't keep a batch job's progress");
            }
        }
        Some(pause)
    }

    /// Runs a page of `job`; whether it's done.
    async fn page(&self, job: &mut BatchJob) -> Result<bool, StoreError> {
        match job.spec.clone() {
            JobSpec::Expire(expire) => self.store.expire_batch_page(job, &expire).await,
            JobSpec::KeyRotate(rotate) => self.store.rotate_batch_page(job, &rotate).await,
            JobSpec::Replicate(replicate) => {
                let secrets = self.store.batch_job_secrets(&job.id).await?;
                Box::pin(crate::batch_replicate::page(
                    &self.store,
                    job,
                    &replicate,
                    &secrets,
                ))
                .await
            }
            JobSpec::Operation(operation) => match &self.operations {
                Some(operations) => {
                    Box::pin(batch_operations::page(operations, job, &operation)).await
                }
                None => Err(StoreError::Io(std::io::Error::other(
                    "S3 Batch Operations' jobs run only with IAM",
                ))),
            },
        }
    }

    /// Counts a failed page of job `id` (`failed`), or forgets its failures; how many
    /// in a row there are.
    fn errors_of(&self, id: &str, failed: bool) -> u32 {
        let mut errors = self
            .errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failed {
            let count = errors.entry(id.to_owned()).or_default();
            *count += 1;
            *count
        } else {
            errors.remove(id);
            0
        }
    }

    /// Sends a job's result where it asked, once.
    async fn notify(&self, client: &reqwest::Client, job: &BatchJob) {
        let Some(notify) = job.spec.notify() else {
            return;
        };
        let token = if notify.token {
            match self.store.batch_job_secrets(&job.id).await {
                Ok(mut secrets) => secrets.notify_token.take(),
                Err(err) => {
                    tracing::warn!(job = job.id, error = %err, "couldn't open a batch job's notify token");
                    return;
                }
            }
        } else {
            None
        };
        let webhook = match teifs_notify::Webhook::new(&notify.endpoint, token) {
            Ok(webhook) => webhook,
            Err(why) => {
                tracing::warn!(job = job.id, why, "a batch job's notify endpoint is wrong");
                return;
            }
        };
        let body = serde_json::to_vec(&Ended::of(job)).expect("a job's result serializes");
        if let Err(why) = webhook.post(client, "application/json", body).await {
            tracing::warn!(
                job = job.id,
                endpoint = webhook.shown(),
                why,
                "couldn't send a batch job's result"
            );
        }
    }

    /// Forgets the jobs that ended long ago.
    async fn forget_old(&self) {
        let before = crate::admin::millis(std::time::SystemTime::now() - KEPT);
        if let Err(err) = self.store.forget_batch_jobs(before).await {
            tracing::warn!(error = %err, "couldn't forget old batch jobs");
        }
    }
}
