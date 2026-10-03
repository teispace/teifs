//! Batch jobs' records (their JSON, and their secrets sealed apart) and the work of the
//! jobs that only change this drive: `expire`, a page of keys at a time. The server's
//! batch worker decides which job runs and keeps its progress.

use std::time::Duration;

use teifs_types::{
    SseMode,
    batch::{
        BatchJob, ExpireJob, ExpireKind, ExpireRule, JobProgress, JobRetry, KeyRotateJob, KeyValue,
        RotateFilter,
    },
};
use zeroize::Zeroizing;

use crate::{
    Match, ObjectVersion, Precondition, Store, StoreError,
    error::Result,
    jobs::{BATCH, millis},
    objects::Marking,
    replication_targets::{open, seal},
};

/// What a sealed secret of job `id` is bound to.
fn bound(id: &str) -> String {
    format!("batch-job:{id}")
}

fn parse(json: &str) -> Result<BatchJob> {
    serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata)
}

fn json(job: &BatchJob) -> Result<String> {
    serde_json::to_string(job).map_err(|_| StoreError::CorruptMetadata)
}

impl Store {
    /// Records a new job, with the token its result is sent with, sealed.
    pub async fn add_batch_job(
        &self,
        job: &BatchJob,
        token: Option<Zeroizing<String>>,
    ) -> Result<()> {
        let sealed = match token {
            Some(token) => Some(seal(&self.targets_key().await?, &bound(&job.id), &token)),
            None => None,
        };
        let (id, created_ms, json) = (job.id.clone(), job.created_ms, json(job)?);
        self.blocking(move |inner| {
            Ok(inner
                .system()
                .add_batch_job(&id, created_ms, &json, sealed.as_deref())?)
        })
        .await
    }

    /// The job `id`.
    pub async fn batch_job(&self, id: &str) -> Result<Option<BatchJob>> {
        let id = id.to_owned();
        self.blocking(move |inner| {
            inner
                .system()
                .batch_job(&id)?
                .map(|(job, _)| parse(&job))
                .transpose()
        })
        .await
    }

    /// Every job, oldest first.
    pub async fn batch_jobs(&self) -> Result<Vec<BatchJob>> {
        self.blocking(|inner| {
            inner
                .system()
                .batch_jobs()?
                .iter()
                .map(|j| parse(j))
                .collect()
        })
        .await
    }

    /// Changes the job `id` with `change`, unless it's finished (cancelled meanwhile):
    /// the job as it's kept now, `None` when there's none.
    pub async fn update_batch_job(
        &self,
        id: &str,
        change: impl FnOnce(&mut BatchJob) + Send + 'static,
    ) -> Result<Option<BatchJob>> {
        let id = id.to_owned();
        self.blocking(move |inner| {
            let system = inner.system();
            let Some((kept, _)) = system.batch_job(&id)? else {
                return Ok(None);
            };
            let mut job = parse(&kept)?;
            if !job.status.finished() {
                change(&mut job);
                system.set_batch_job(&id, &json(&job)?)?;
            }
            Ok(Some(job))
        })
        .await
    }

    /// The token the result of job `id` is sent with, if it has one.
    pub async fn batch_job_token(&self, id: &str) -> Result<Option<Zeroizing<String>>> {
        let owned = id.to_owned();
        let sealed = self
            .blocking(move |inner| Ok(inner.system().batch_job(&owned)?.and_then(|(_, s)| s)))
            .await?;
        match sealed {
            Some(sealed) => Ok(Some(open(&self.targets_key().await?, &bound(id), &sealed)?)),
            None => Ok(None),
        }
    }

    /// Forgets the jobs that finished before `before_ms`; how many.
    pub async fn forget_batch_jobs(&self, before_ms: i64) -> Result<usize> {
        self.blocking(move |inner| {
            let system = inner.system();
            let mut forgotten = 0;
            for job in system.batch_jobs()? {
                let job = parse(&job)?;
                let last = job.progress.updated_ms.unwrap_or(job.created_ms);
                if job.status.finished() && last < before_ms && system.remove_batch_job(&job.id)? {
                    forgotten += 1;
                }
            }
            Ok(forgotten)
        })
        .await
    }

    /// Runs the next page of `job`, an `expire` job, from where its progress says,
    /// counting what it removed and what it couldn't in it; whether the job is done.
    pub async fn expire_batch_page(&self, job: &mut BatchJob, expire: &ExpireJob) -> Result<bool> {
        let everything = [String::new()];
        let prefixes = if expire.prefixes.is_empty() {
            &everything[..]
        } else {
            &expire.prefixes[..]
        };
        let Some(prefix) = prefixes.get(job.progress.prefix) else {
            return Ok(true);
        };
        let now = crate::now_ms();
        let (versions, more) = self
            .whole_keys(&expire.bucket, prefix, job.progress.last_key.clone(), BATCH)
            .await?;
        for key_versions in versions.chunk_by(|a, b| a.info.key == b.info.key) {
            self.expire_key(job, expire, key_versions, now).await;
            job.progress.last_key = Some(key_versions[0].info.key.clone());
        }
        if !more {
            job.progress.prefix += 1;
            job.progress.last_key = None;
        }
        job.progress.updated_ms = Some(now);
        Ok(job.progress.prefix >= prefixes.len())
    }

    /// Applies the first rule that matches the newest of a key's versions (newest
    /// first): removes them all, or all but the newest the rule keeps.
    async fn expire_key(
        &self,
        job: &mut BatchJob,
        expire: &ExpireJob,
        versions: &[ObjectVersion],
        now: i64,
    ) {
        let newest = &versions[0];
        if !newest.latest {
            return;
        }
        let Some(rule) = expire.rules.iter().find(|r| rule_matches(r, newest, now)) else {
            return;
        };
        let keep = usize::try_from(rule.retain_versions).unwrap_or(usize::MAX);
        for version in versions.iter().skip(keep) {
            self.expire_version(job, expire, version).await;
        }
    }

    /// Removes one version, tried again as the job says when it fails for a reason that
    /// may pass; counted either way.
    async fn expire_version(
        &self,
        job: &mut BatchJob,
        expire: &ExpireJob,
        version: &ObjectVersion,
    ) {
        // Only the version that was listed: one written again under its id (`null`)
        // meanwhile stays.
        let precondition = if version.delete_marker {
            Precondition::default()
        } else {
            Precondition {
                if_match: Some(Match::ETag(version.info.etag.clone())),
                if_modified_at: Some(version.info.modified),
                ..Precondition::default()
            }
        };
        let result = retried(expire.retry, &mut job.progress, || {
            self.delete_marking(
                &expire.bucket,
                &version.info.key,
                version.info.version_id.as_deref(),
                precondition.clone(),
                (false, Marking::Lifecycle),
            )
        })
        .await;
        let progress = &mut job.progress;
        match result {
            Ok(_) if version.delete_marker => progress.delete_markers += 1,
            Ok(_) => {
                progress.objects += 1;
                progress.bytes += version.info.size;
            }
            // Gone or changed meanwhile: nothing to remove.
            Err(
                StoreError::NoSuchKey | StoreError::NoSuchVersion | StoreError::PreconditionFailed,
            ) => {}
            Err(err) => {
                if version.delete_marker {
                    progress.delete_markers_failed += 1;
                } else {
                    progress.objects_failed += 1;
                    progress.bytes_failed += version.info.size;
                }
                let id = version.info.version_id.as_deref().unwrap_or("null");
                job.failed_because(format!("{} ({id}): {err}", version.info.key));
            }
        }
    }
}

impl Store {
    /// Runs the next page of `job`, a `keyrotate` job, from where its progress says:
    /// seals the data keys of the SSE-S3 and SSE-KMS versions the filter takes again,
    /// counting each; whether the job is done.
    pub async fn rotate_batch_page(
        &self,
        job: &mut BatchJob,
        rotate: &KeyRotateJob,
    ) -> Result<bool> {
        if job.progress.prefix > 0 {
            return Ok(true);
        }
        let now = crate::now_ms();
        let (versions, more) = self
            .whole_keys(
                &rotate.bucket,
                &rotate.prefix,
                job.progress.last_key.clone(),
                BATCH,
            )
            .await?;
        for key_versions in versions.chunk_by(|a, b| a.info.key == b.info.key) {
            for version in key_versions
                .iter()
                .filter(|v| rotates(&rotate.filter, v, now))
            {
                self.rotate_version(job, rotate, version).await;
            }
            job.progress.last_key = Some(key_versions[0].info.key.clone());
        }
        if !more {
            job.progress.prefix = 1;
            job.progress.last_key = None;
        }
        job.progress.updated_ms = Some(now);
        Ok(!more)
    }

    async fn rotate_version(
        &self,
        job: &mut BatchJob,
        rotate: &KeyRotateJob,
        version: &ObjectVersion,
    ) {
        let info = &version.info;
        let result = retried(rotate.retry, &mut job.progress, || {
            self.rotate_key(
                &rotate.bucket,
                &info.key,
                info.version_id.as_deref(),
                &rotate.encryption,
            )
        })
        .await;
        let progress = &mut job.progress;
        match result {
            Ok(()) => {
                progress.objects += 1;
                progress.bytes += info.size;
            }
            // Gone meanwhile: nothing to rotate.
            Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => {}
            Err(err) => {
                progress.objects_failed += 1;
                progress.bytes_failed += info.size;
                let id = info.version_id.as_deref().unwrap_or("null");
                job.failed_because(format!("{} ({id}): {err}", info.key));
            }
        }
    }
}

/// Whether a `keyrotate` job's `filter` takes `version` at `now`: an SSE-S3 or SSE-KMS
/// version (not a delete marker) of the age, tags (any one), metadata (any one) and KMS
/// key (for SSE-KMS versions) it gives.
fn rotates(filter: &RotateFilter, version: &ObjectVersion, now: i64) -> bool {
    let info = &version.info;
    let Some(sse) = info
        .sse
        .as_ref()
        .filter(|s| matches!(s.mode, SseMode::S3 | SseMode::Kms))
    else {
        return false;
    };
    let modified = millis(info.modified);
    let age = now.saturating_sub(modified);
    let secs = |s: u64| i64::try_from(s).unwrap_or(i64::MAX).saturating_mul(1000);
    let any = |wanted: &[KeyValue], mut given: Box<dyn Iterator<Item = (String, &str)> + '_>| {
        wanted.is_empty() || given.any(|(k, v)| wanted.iter().any(|kv| kv.matches(&k, v)))
    };
    let tags = info.attrs.tags.iter().map(|(k, v)| (k.clone(), v.as_str()));
    !version.delete_marker
        && filter.newer_than_secs.is_none_or(|s| age < secs(s))
        && filter.older_than_secs.is_none_or(|s| age >= secs(s))
        && filter.created_after_ms.is_none_or(|after| modified > after)
        && filter
            .created_before_ms
            .is_none_or(|before| modified < before)
        && any(&filter.tags, Box::new(tags))
        && any(&filter.metadata, Box::new(headers(version)))
        && filter
            .kms_key
            .as_ref()
            .is_none_or(|wanted| sse.mode != SseMode::Kms || sse.kms_key.as_ref() == Some(wanted))
}

/// Runs `attempt` until it succeeds, fails for a reason that won't pass, or has been tried
/// as often as `retry` says, counting the retries in `progress`.
async fn retried<T, F: Future<Output = Result<T>>>(
    retry: JobRetry,
    progress: &mut JobProgress,
    mut attempt: impl FnMut() -> F,
) -> Result<T> {
    let mut tried = 1;
    loop {
        match attempt().await {
            Err(err) if tried < retry.attempts.max(1) && passing(&err) => {
                progress.retry_attempts += 1;
                tried += 1;
                tokio::time::sleep(Duration::from_millis(retry.delay_ms)).await;
            }
            other => return other,
        }
    }
}

/// Whether a removal that failed so may succeed when tried again.
fn passing(err: &StoreError) -> bool {
    !matches!(
        err,
        StoreError::ObjectLocked
            | StoreError::NoSuchBucket
            | StoreError::NoSuchKey
            | StoreError::NoSuchVersion
            | StoreError::PreconditionFailed
            | StoreError::InvalidRequest(_)
    )
}

/// Whether `rule` takes the key whose newest version is `newest`, at `now`.
fn rule_matches(rule: &ExpireRule, newest: &ObjectVersion, now: i64) -> bool {
    let info = &newest.info;
    let modified = millis(info.modified);
    let kind = match rule.kind {
        ExpireKind::Object => !newest.delete_marker,
        ExpireKind::Deleted => newest.delete_marker,
    };
    let older = rule.older_than_secs.is_none_or(|secs| {
        let secs = i64::try_from(secs).unwrap_or(i64::MAX);
        now.saturating_sub(modified) > secs.saturating_mul(1000)
    });
    kind && older
        && rule
            .name
            .as_ref()
            .is_none_or(|name| teifs_types::batch::wildcard(name, &info.key))
        && rule
            .created_before_ms
            .is_none_or(|before| modified < before)
        && rule
            .tags
            .iter()
            .all(|kv| info.attrs.tags.iter().any(|(k, v)| kv.matches(k, v)))
        && rule
            .metadata
            .iter()
            .all(|kv| headers(newest).any(|(k, v)| kv.matches(&k, v)))
        && rule.size_less_than.is_none_or(|less| info.size < less)
        && rule
            .size_greater_than
            .is_none_or(|greater| info.size > greater)
}

/// The metadata an `expire` rule looks at: user metadata (as `x-amz-meta-NAME`) and the
/// standard headers.
fn headers(version: &ObjectVersion) -> impl Iterator<Item = (String, &str)> {
    let attrs = &version.info.attrs;
    let standard = [
        ("content-type", &attrs.content_type),
        ("content-encoding", &attrs.content_encoding),
        ("content-disposition", &attrs.content_disposition),
        ("content-language", &attrs.content_language),
        ("cache-control", &attrs.cache_control),
        ("expires", &attrs.expires),
        (
            "x-amz-website-redirect-location",
            &attrs.website_redirect_location,
        ),
    ];
    standard
        .into_iter()
        .filter_map(|(name, value)| value.as_deref().map(|v| (name.to_owned(), v)))
        .chain(
            attrs
                .user
                .iter()
                .map(|(k, v)| (format!("x-amz-meta-{k}"), v.as_str())),
        )
}

#[cfg(test)]
mod tests;
