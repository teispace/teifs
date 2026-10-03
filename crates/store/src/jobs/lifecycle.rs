//! The lifecycle job: applies buckets' lifecycle rules.
//!
//! A pass walks every bucket that has enabled rules, a page of versions at a time, and
//! does what S3 would: expires current versions (removed without versioning, hidden by
//! a delete marker with it), removes noncurrent versions and delete markers left alone,
//! and aborts old uploads. Every change goes through the same store operations a
//! request would, with the object's ETag, size and modification time as conditions, so
//! an object written again meanwhile is left alone, and Object Lock is honoured: a
//! protected version stays until it may go, and so does one replication still holds
//! (`PENDING` or `FAILED`), as on S3.
//!
//! The job keeps where it is between steps; a pass that ends waits for the job's idle
//! interval before the next one starts.

use std::{sync::Arc, time::Duration};

use teifs_types::replication::ReplicationStatus;

use super::{BATCH, Job, Step, millis};
use crate::{
    Inner, Lifecycle, Match, ObjectVersion, Precondition, Store, StoreError, error::Result,
};

/// What the lifecycle job removed, told to whoever wants to know (bucket notifications),
/// before the job goes on.
pub trait Expirations: Send + Sync + std::fmt::Debug {
    /// `key` in `bucket` expired: its version `version_id` was removed, or (`marker`) a
    /// delete marker `version_id` was made for it.
    fn expired<'a>(
        &'a self,
        bucket: &'a str,
        key: &'a str,
        version_id: Option<String>,
        marker: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

/// Where a pass is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cursor {
    /// The bucket being walked.
    bucket: String,
    /// Whether its uploads have been looked at.
    uploads_done: bool,
    /// The last key whose versions were all looked at.
    after_key: Option<String>,
    /// Whether the bucket is done: the pass goes on with the next one.
    finished: bool,
}

impl Cursor {
    fn start(bucket: String) -> Self {
        Self {
            bucket,
            uploads_done: false,
            after_key: None,
            finished: false,
        }
    }
}

/// Applies buckets' lifecycle rules.
pub(crate) struct ApplyLifecycle {
    store: Store,
    cursor: Option<Cursor>,
    idle: Duration,
}

impl ApplyLifecycle {
    pub(crate) fn new(store: Store) -> Self {
        // A pass an hour on a real day: rules take effect within the hour they're due.
        let idle_ms = (store.inner.day_ms / 24).clamp(50, 3_600_000);
        Self {
            store,
            cursor: None,
            idle: Duration::from_millis(u64::try_from(idle_ms).unwrap_or(3_600_000)),
        }
    }

    /// One bounded piece of a pass: how many versions and uploads it looked at, 0 when
    /// the pass ended.
    pub(crate) async fn run(&mut self, step: &Step) -> Result<usize> {
        let now = millis(step.now);
        let buckets = self.buckets_with_rules().await?;
        let next = match &self.cursor {
            None => buckets.first(),
            Some(c) if c.finished => buckets.iter().find(|(name, _)| *name > c.bucket),
            Some(c) => buckets.iter().find(|(name, _)| *name >= c.bucket),
        };
        let Some((name, lifecycle)) = next.cloned() else {
            // Every bucket is done (or none has rules): the pass is over.
            self.cursor = None;
            return Ok(0);
        };
        let mut cursor = match self.cursor.take() {
            Some(c) if c.bucket == name && !c.finished => c,
            _ => Cursor::start(name),
        };
        let result = if cursor.uploads_done {
            self.versions_page(&mut cursor, &lifecycle, now, step).await
        } else {
            let result = self.abort_uploads(&cursor.bucket, &lifecycle, now).await;
            cursor.uploads_done = true;
            result
        };
        let looked = match result {
            Ok(looked) => looked,
            // Deleted meanwhile: nothing left to do there.
            Err(StoreError::NoSuchBucket) => {
                cursor.finished = true;
                0
            }
            Err(err) => {
                // Next time, the same place again.
                self.cursor = Some(cursor);
                return Err(err);
            }
        };
        self.cursor = Some(cursor);
        // Even a bucket with nothing in it counts: the pass goes on.
        Ok(looked.max(1))
    }

    /// The buckets with enabled rules, by name.
    async fn buckets_with_rules(&self) -> Result<Vec<(String, Arc<Lifecycle>)>> {
        self.store
            .blocking(|inner: &Inner| {
                let mut found = Vec::new();
                for bucket in inner.buckets()? {
                    if let Some(lifecycle) = inner.lifecycle(&bucket.name)?
                        && lifecycle.enabled().next().is_some()
                    {
                        found.push((bucket.name, lifecycle));
                    }
                }
                Ok(found)
            })
            .await
    }

    /// Aborts a bucket's uploads that a rule says are too old; how many it looked at.
    async fn abort_uploads(&self, bucket: &str, lifecycle: &Lifecycle, now: i64) -> Result<usize> {
        if !lifecycle
            .enabled()
            .any(|rule| rule.abort_uploads_after_days.is_some())
        {
            return Ok(0);
        }
        let day_ms = self.store.inner.day_ms;
        let prefix = lifecycle.common_prefix();
        let mut after = None;
        let mut looked = 0;
        loop {
            let page = self.store.uploads(bucket, prefix, after, BATCH).await?;
            looked += page.len();
            for upload in &page {
                let due = lifecycle.upload_abort(&upload.key, upload.created_ms, day_ms);
                if due.is_some_and(|due| due.at_ms <= now) {
                    match self.store.abort(&upload.id).await {
                        Ok(()) | Err(StoreError::NoSuchUpload) => {}
                        Err(err) => return Err(err),
                    }
                }
            }
            if page.len() < BATCH {
                return Ok(looked);
            }
            after = page.last().map(|u| (u.key.clone(), u.id.clone()));
        }
    }

    /// Applies the rules to the next page of a bucket's versions; how many it looked at.
    async fn versions_page(
        &self,
        cursor: &mut Cursor,
        lifecycle: &Lifecycle,
        now: i64,
        step: &Step,
    ) -> Result<usize> {
        let prefix = lifecycle.common_prefix();
        let (versions, more) = self
            .store
            .whole_keys(&cursor.bucket, prefix, cursor.after_key.clone(), BATCH)
            .await?;
        let looked = versions.len();
        for key_versions in versions.chunk_by(|a, b| a.info.key == b.info.key) {
            if step.cancel.is_cancelled() {
                return Ok(looked);
            }
            self.apply(&cursor.bucket, lifecycle, key_versions, now)
                .await?;
            cursor.after_key = Some(key_versions[0].info.key.clone());
        }
        cursor.finished = !more;
        Ok(looked)
    }

    /// Applies the rules to one key's versions (newest first).
    pub(crate) async fn apply(
        &self,
        bucket: &str,
        lifecycle: &Lifecycle,
        versions: &[ObjectVersion],
        now: i64,
    ) -> Result<()> {
        let day_ms = self.store.inner.day_ms;
        let key = &versions[0].info.key;
        // When the version before (newer than) the one looked at was made: when that
        // one became noncurrent.
        let mut successor: Option<i64> = None;
        let mut newer = 0;
        let mut kept = 0;
        let mut marker = None;
        for version in versions {
            let made = millis(version.info.modified);
            if version.latest {
                if version.delete_marker {
                    marker = Some(version);
                } else if !held(version)
                    && lifecycle
                        .expiry(&version.info, day_ms)
                        .is_some_and(|expiry| expiry.at_ms <= now)
                {
                    // Only the object that was listed: one written since isn't due.
                    let precondition = Precondition {
                        if_match: Some(Match::ETag(version.info.etag.clone())),
                        if_size: Some(version.info.size),
                        if_modified_at: Some(version.info.modified),
                        ..Precondition::default()
                    };
                    // Its delete marker isn't replicated, as on S3.
                    let deleted = self
                        .store
                        .delete_marking(
                            bucket,
                            key,
                            None,
                            precondition,
                            (false, crate::objects::Marking::Lifecycle),
                        )
                        .await;
                    if let Ok(deleted) = &deleted {
                        self.store
                            .expired(
                                bucket,
                                key,
                                deleted.version_id.clone(),
                                deleted.delete_marker,
                            )
                            .await;
                    }
                    tolerate(deleted.map(drop))?;
                }
            } else {
                let since = successor.unwrap_or(made);
                let removed = !held(version)
                    && lifecycle.removes_noncurrent(&version.info, since, newer, now, day_ms)
                    && self.remove(bucket, version).await?;
                if !removed {
                    kept += 1;
                }
                newer += 1;
            }
            successor = Some(made);
        }
        if let Some(marker) = marker
            && kept == 0
            && !held(marker)
            && lifecycle.removes_marker(key, millis(marker.info.modified), now, day_ms)
        {
            self.remove(bucket, marker).await?;
        }
        Ok(())
    }

    /// Removes a version for good unless Object Lock protects it; whether it's gone. The
    /// removal isn't replicated, as `MinIO` decides.
    async fn remove(&self, bucket: &str, version: &ObjectVersion) -> Result<bool> {
        let result = self
            .store
            .delete_marking(
                bucket,
                &version.info.key,
                version.info.version_id.as_deref(),
                Precondition::default(),
                (false, crate::objects::Marking::Lifecycle),
            )
            .await;
        match result {
            Ok(_) => {
                let version_id = version.info.version_id.clone();
                self.store
                    .expired(bucket, &version.info.key, version_id, false)
                    .await;
                Ok(true)
            }
            Err(StoreError::ObjectLocked) => Ok(false),
            Err(err) => tolerate(Err(err)).map(|()| false),
        }
    }
}

/// Lets through what a change made meanwhile explains: the object was written again,
/// removed, or is protected.
/// Whether replication holds a version back from the rules, as on S3: one still to
/// reach a destination (`PENDING`), or that couldn't (`FAILED`), isn't expired until it
/// does or is deleted.
fn held(version: &ObjectVersion) -> bool {
    version
        .info
        .attrs
        .replication
        .as_ref()
        .is_some_and(|replication| {
            matches!(
                replication.status,
                ReplicationStatus::Pending | ReplicationStatus::Failed
            )
        })
}

fn tolerate(result: Result<()>) -> Result<()> {
    match result {
        Err(StoreError::PreconditionFailed | StoreError::NoSuchKey | StoreError::ObjectLocked) => {
            Ok(())
        }
        other => other,
    }
}

impl Job for ApplyLifecycle {
    fn name(&self) -> &'static str {
        "lifecycle"
    }

    fn step(&mut self, _inner: &Inner, step: &Step) -> Result<usize> {
        // Steps run on the blocking pool, where waiting on the store's work is allowed.
        tokio::runtime::Handle::current().block_on(self.run(step))
    }

    fn idle(&self) -> Duration {
        self.idle
    }
}
