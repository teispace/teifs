//! Resyncs of replication destinations (`MinIO`'s `mc replicate resync`): every version
//! from before one started that the rules send to its destination waits for it again.
//! The replication job marks them a page at a time ([`Store::mark_resyncs`]), sends them
//! as any other, counts them ([`Store::count_resync`]) and settles the resync once none
//! waits ([`Store::settle_resyncs`]).

use teifs_meta::NULL_VERSION;
use teifs_types::{
    SseMode,
    replication::{
        ReplicationConfig, ReplicationResync, ReplicationStatus, ResyncStatus, VersionReplication,
    },
};

use crate::{Store, StoreError, VersionsQuery, error::Result, jobs::millis, now_ms};

impl Store {
    /// Starts resyncing `bucket`'s destination `arn` as `id`: the versions last modified
    /// before `before_ms` are sent there again. Refused while one of `arn` goes on.
    pub async fn start_resync(
        &self,
        bucket: &str,
        arn: &str,
        id: String,
        before_ms: i64,
    ) -> Result<ReplicationResync> {
        let (bucket, arn) = (bucket.to_owned(), arn.to_owned());
        self.blocking(move |inner| {
            let found = inner.bucket(&bucket)?;
            let versions = found.versions().ok_or(StoreError::InvalidRequest(
                "a resync needs a bucket that keeps versions",
            ))?;
            let conn = inner.lock();
            if conn
                .replication_resync(&versions.id, &arn)?
                .is_some_and(|resync| resync.status == ResyncStatus::Ongoing)
            {
                return Err(StoreError::InvalidRequest(
                    "a resync of this destination is going on",
                ));
            }
            let now = now_ms();
            let resync = ReplicationResync {
                id,
                before_ms,
                started_ms: now,
                updated_ms: now,
                status: ResyncStatus::Ongoing,
                marked: false,
                next: None,
                replicated: (0, 0),
                failed: (0, 0),
                last_key: None,
            };
            conn.set_replication_resync(&versions.id, &arn, &resync)?;
            Ok(resync)
        })
        .await
    }

    /// `bucket`'s resyncs, by destination.
    pub async fn resyncs(&self, bucket: &str) -> Result<Vec<(String, ReplicationResync)>> {
        let bucket = bucket.to_owned();
        self.blocking(move |inner| {
            let found = inner.bucket(&bucket)?;
            let Some(versions) = found.versions() else {
                return Ok(Vec::new());
            };
            Ok(inner.lock().replication_resyncs(&versions.id)?)
        })
        .await
    }

    /// Cancels `bucket`'s resync of `arn`: its id, `None` when none goes on. Versions
    /// it marked already are still sent.
    pub async fn cancel_resync(&self, bucket: &str, arn: &str) -> Result<Option<String>> {
        let ongoing = self
            .resyncs(bucket)
            .await?
            .into_iter()
            .find(|(of, resync)| of == arn && resync.status == ResyncStatus::Ongoing);
        let Some((_, resync)) = ongoing else {
            return Ok(None);
        };
        self.change_resync(bucket, arn, &resync.id, |resync| {
            resync.status = ResyncStatus::Canceled;
        })
        .await?;
        Ok(Some(resync.id))
    }

    /// Marks the next `limit` versions each of `bucket`'s resyncs going on looks at as
    /// waiting for its destination, by `config`'s rules; whether any has more to look at.
    pub async fn mark_resyncs(
        &self,
        bucket: &str,
        config: &ReplicationConfig,
        limit: usize,
    ) -> Result<bool> {
        let mut more = false;
        for (arn, resync) in self.resyncs(bucket).await? {
            if resync.status != ResyncStatus::Ongoing || resync.marked {
                continue;
            }
            let mut query = VersionsQuery {
                max_keys: limit,
                ..VersionsQuery::default()
            };
            if let Some((key, version)) = resync.next.clone() {
                query.key_marker = Some(key);
                query.version_marker = version;
            }
            let page = self.list_versions(bucket, query).await?;
            for version in &page.versions {
                let info = &version.info;
                let Some(version_id) = info.version_id.as_deref() else {
                    continue;
                };
                let replica = info
                    .attrs
                    .replication
                    .as_ref()
                    .map(|replication| replication.status == ReplicationStatus::Replica);
                // Not replicas, versions without an id to keep, versions made since,
                // nor markers never replicated (lifecycle's, as S3 never sends them).
                if replica == Some(true)
                    || version_id == NULL_VERSION
                    || millis(info.modified) >= resync.before_ms
                    || (version.delete_marker && replica.is_none())
                {
                    continue;
                }
                let kms = info
                    .sse
                    .as_ref()
                    .is_some_and(|sse| matches!(sse.mode, SseMode::Kms | SseMode::Dsse));
                if !config.resends(
                    &arn,
                    &info.key,
                    (version.delete_marker, &info.attrs.tags, kms),
                ) {
                    continue;
                }
                let to = arn.clone();
                self.change_replication(bucket, &info.key, version_id, move |replication| {
                    VersionReplication::resent(replication, &to)
                })
                .await?;
            }
            let next = page.next.filter(|_| page.truncated);
            let marked = next.is_none();
            more |= !marked;
            self.change_resync(bucket, &arn, &resync.id, move |resync| {
                resync.next = next;
                resync.marked = marked;
            })
            .await?;
        }
        Ok(more)
    }

    /// Settles `bucket`'s resyncs that looked at every version, but those of the
    /// destinations `unsettled` (a version still waits for them): they're done. Nothing
    /// is settled from a `partial` look at what waits.
    pub async fn settle_resyncs(
        &self,
        bucket: &str,
        unsettled: &[String],
        partial: bool,
    ) -> Result<()> {
        if partial {
            return Ok(());
        }
        for (arn, resync) in self.resyncs(bucket).await? {
            if resync.status == ResyncStatus::Ongoing && resync.marked && !unsettled.contains(&arn)
            {
                self.change_resync(bucket, &arn, &resync.id, |resync| {
                    resync.status = ResyncStatus::Completed;
                })
                .await?;
            }
        }
        Ok(())
    }

    /// Counts `key`'s version, of `size` bytes, that the resync of `arn` sent
    /// (`COMPLETED`) or couldn't (`FAILED`).
    pub async fn count_resync(
        &self,
        bucket: &str,
        arn: &str,
        (key, size): (&str, u64),
        status: ReplicationStatus,
    ) -> Result<()> {
        let Some((_, resync)) = self
            .resyncs(bucket)
            .await?
            .into_iter()
            .find(|(of, resync)| of == arn && resync.status == ResyncStatus::Ongoing)
        else {
            return Ok(());
        };
        let key = key.to_owned();
        self.change_resync(bucket, arn, &resync.id, move |resync| {
            let count = if status == ReplicationStatus::Completed {
                &mut resync.replicated
            } else {
                &mut resync.failed
            };
            count.0 += 1;
            count.1 = count.1.saturating_add(size);
            resync.last_key = Some(key);
        })
        .await
    }

    /// Changes `bucket`'s resync `id` of `arn` with `change`, while it goes on.
    async fn change_resync(
        &self,
        bucket: &str,
        arn: &str,
        id: &str,
        change: impl FnOnce(&mut ReplicationResync) + Send + 'static,
    ) -> Result<()> {
        let (bucket, arn, id) = (bucket.to_owned(), arn.to_owned(), id.to_owned());
        self.blocking(move |inner| {
            let found = inner.bucket(&bucket)?;
            let Some(versions) = found.versions() else {
                return Ok(());
            };
            let conn = inner.lock();
            let Some(mut resync) = conn.replication_resync(&versions.id, &arn)? else {
                return Ok(());
            };
            if resync.id != id || resync.status != ResyncStatus::Ongoing {
                return Ok(());
            }
            change(&mut resync);
            resync.updated_ms = now_ms();
            conn.set_replication_resync(&versions.id, &arn, &resync)?;
            Ok(())
        })
        .await
    }
}
