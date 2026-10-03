//! Bucket replication: copies the versions buckets' replication rules wait for to their
//! destinations. Woken as objects are written, and every so often to find what a restart
//! or a failed attempt left waiting (each version keeps where it stands, so nothing is
//! lost). A version a destination can't take is marked `FAILED`; one that may get
//! through later stays `PENDING` and is tried again. Removals of versions the rules
//! replicate (`MinIO`'s `DeleteReplication`) wait in a queue of their own, since the
//! versions are gone.

mod check;
mod remote;
mod stats;

pub(crate) use check::{Unready, check};
pub(crate) use stats::{Bucket, Rates, Stats, Target, Timed};

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use teifs_store::{
    Encryption, ObjectBody, ObjectInfo, QueuedDelete, Replica, ReplicaMetadata, Store, StoreError,
    Waiting,
};
use teifs_types::{
    SseMode,
    replication::{LOCAL_ARN, ReplicationConfig, ReplicationStatus},
};
use tokio::{io::AsyncReadExt as _, sync::Notify};
use tokio_util::sync::CancellationToken;

/// How often waiting versions are looked for without being woken.
const EVERY: Duration = Duration::from_secs(60);
/// How many waiting versions of a bucket one pass takes.
const BATCH: usize = 1_000;
/// How much of a version is read at a time.
const CHUNK: usize = 256 * 1024;

/// Copies waiting versions to their destinations.
#[derive(Debug)]
pub(crate) struct Worker {
    store: Store,
    wake: Arc<Notify>,
    every: Duration,
    /// The targets on other S3 services this pass sends to.
    targets: Mutex<HashMap<String, Arc<remote::Target>>>,
    /// What it did, for the replication metrics.
    stats: Arc<Stats>,
}

/// Why a version didn't reach a destination.
#[derive(Debug)]
enum Missed {
    /// It never will as things are: the destination is missing or doesn't take replicas.
    Failed(String),
    /// It may later: tried again on the next pass.
    Later(String),
    /// The destination didn't answer at all: tried again on the next pass.
    Unreachable(String),
}

impl From<StoreError> for Missed {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::NoSuchBucket
            | StoreError::InvalidRequest(_)
            | StoreError::CustomerKeyRequired
            | StoreError::ObjectLocked
            | StoreError::NoKms => Self::Failed(err.to_string()),
            err => Self::Later(err.to_string()),
        }
    }
}

impl Worker {
    /// Replicates `store`'s buckets, woken by `wake`.
    pub(crate) fn new(store: Store, wake: Arc<Notify>) -> Self {
        Self {
            store,
            wake,
            every: EVERY,
            targets: Mutex::default(),
            stats: Arc::default(),
        }
    }

    /// Records what it does in `stats`.
    pub(crate) fn with_stats(mut self, stats: Arc<Stats>) -> Self {
        self.stats = stats;
        self
    }

    /// Replicates what's waiting, then what comes, until `stopping`.
    pub(crate) async fn run(self, stopping: CancellationToken) {
        loop {
            // Woken while a pass runs, the next pass starts at once.
            let woken = self.wake.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            while self.pass(&stopping).await {}
            tokio::select! {
                () = stopping.cancelled() => break,
                () = woken => {}
                () = tokio::time::sleep(self.every) => {}
            }
        }
    }

    /// One pass over every replicating bucket; whether a bucket had more waiting than
    /// it took and got some through (so another pass should follow).
    pub(crate) async fn pass(&self, stopping: &CancellationToken) -> bool {
        let buckets = match self.store.list_buckets().await {
            Ok(buckets) => buckets,
            Err(err) => {
                tracing::warn!(error = %err, "couldn't list the buckets to replicate");
                return false;
            }
        };
        // Targets are read again each pass, so changes to them count.
        lock(&self.targets).clear();
        let mut again = false;
        for bucket in buckets {
            if stopping.is_cancelled() {
                return false;
            }
            let config = match self.store.bucket_replication(&bucket.name).await {
                Ok(Some(config)) => config,
                Ok(None) | Err(StoreError::NoSuchBucket) => continue,
                Err(err) => {
                    tracing::warn!(bucket = %bucket.name, error = %err, "couldn't read the replication configuration");
                    continue;
                }
            };
            let marking = self
                .store
                .mark_resyncs(&bucket.name, &config, BATCH)
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!(bucket = %bucket.name, error = %err, "couldn't mark the versions a resync sends");
                    false
                });
            match self.bucket(&bucket.name, &config, stopping).await {
                Some(more) => again |= more || marking,
                None => return false,
            }
        }
        again
    }

    /// Sends what waits in `bucket`: `None` when stopping, else whether it had more
    /// waiting than it took and got some through (so another pass should follow).
    async fn bucket(
        &self,
        bucket: &str,
        config: &ReplicationConfig,
        stopping: &CancellationToken,
    ) -> Option<bool> {
        let waiting = match self.store.waiting_replication(bucket, BATCH).await {
            Ok(waiting) => waiting,
            Err(err) => {
                tracing::warn!(bucket, error = %err, "couldn't find the versions waiting to be replicated");
                return Some(false);
            }
        };
        let full = waiting.len() >= BATCH;
        self.queued(bucket, &waiting, false);
        // The versions a destination still waits for after this pass.
        let mut left = Vec::new();
        let mut through = false;
        // The destinations a resync still waits for, once this pass is over.
        let mut unsettled = Vec::new();
        // A key's versions go oldest first, so the destination's current version is
        // the source's; one held back holds back the newer ones too.
        for versions in waiting.chunk_by(|a, b| a.key == b.key) {
            let mut held = Vec::new();
            for version in versions.iter().rev() {
                if stopping.is_cancelled() {
                    return None;
                }
                through |= self.version(bucket, config, version, &mut held).await;
                unsettled.extend(
                    version
                        .resync
                        .iter()
                        .filter(|arn| held.contains(arn))
                        .cloned(),
                );
                if version.destinations.iter().any(|arn| held.contains(arn)) {
                    left.push(version);
                }
            }
        }
        self.queued(bucket, left, true);
        if let Err(err) = self.store.settle_resyncs(bucket, &unsettled, full).await {
            tracing::warn!(bucket, error = %err, "couldn't settle the bucket's resyncs");
        }
        let removals = match self.store.waiting_removals(bucket, BATCH).await {
            Ok(removals) => removals,
            Err(err) => {
                tracing::warn!(bucket, error = %err, "couldn't find the removals waiting to be replicated");
                Vec::new()
            }
        };
        let full = full || removals.len() >= BATCH;
        for removal in &removals {
            if stopping.is_cancelled() {
                return None;
            }
            through |= self.removal(bucket, removal).await;
        }
        Some(full && through)
    }

    /// Sends a version's removal to each destination it's still to reach; whether any
    /// was settled. One a destination can't take is given up on (and logged).
    async fn removal(&self, bucket: &str, removal: &QueuedDelete) -> bool {
        let mut left = Vec::new();
        for arn in &removal.destinations {
            let sent = if let Some(local) = arn.strip_prefix(LOCAL_ARN) {
                self.store
                    .delete_replicated_version(local, &removal.key, &removal.version_id)
                    .await
                    .map(drop)
                    .map_err(Missed::from)
            } else {
                match self.remote(arn).await {
                    Ok(target) => target.send_removal(&removal.key, &removal.version_id).await,
                    Err(missed) => Err(missed),
                }
            };
            match sent {
                Ok(()) => {}
                Err(Missed::Failed(err)) => {
                    tracing::warn!(bucket, key = %removal.key, destination = %arn, error = %err, "a version's removal can't be replicated");
                }
                Err(Missed::Later(err) | Missed::Unreachable(err)) => {
                    tracing::info!(bucket, key = %removal.key, destination = %arn, error = %err, "a version's removal will be replicated later");
                    left.push(arn.clone());
                }
            }
        }
        if left.len() == removal.destinations.len() {
            return false;
        }
        match self
            .store
            .set_removal_destinations(bucket, &removal.key, &removal.version_id, left)
            .await
        {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(bucket, key = %removal.key, error = %err, "couldn't record a removal's replication");
                false
            }
        }
    }

    /// Records what waits in `bucket`, in all and by destination: before a pass sends
    /// (a sample of the queue), or what's `left` after.
    fn queued<'a>(&self, bucket: &str, waiting: impl IntoIterator<Item = &'a Waiting>, left: bool) {
        let mut all = (0, 0);
        let mut by_target: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for version in waiting {
            all = (all.0 + 1, all.1 + version.size);
            for arn in &version.destinations {
                let pending = by_target.entry(arn.clone()).or_default();
                *pending = (pending.0 + 1, pending.1 + version.size);
            }
        }
        if left {
            self.stats.left(bucket, all, &by_target);
        } else {
            self.stats.waiting(bucket, all, &by_target);
        }
    }

    /// Sends one version to each destination it waits for, but those `held` back for
    /// its key (to which it adds those it couldn't reach); whether any was settled.
    async fn version(
        &self,
        bucket: &str,
        config: &ReplicationConfig,
        version: &Waiting,
        held: &mut Vec<String>,
    ) -> bool {
        let mut settled = false;
        for arn in &version.destinations {
            if held.contains(arn) {
                continue;
            }
            let started = Instant::now();
            let size = if version.delete_marker {
                0
            } else {
                version.size
            };
            let status = match self.send(bucket, config, version, arn).await {
                Ok(()) => {
                    self.stats.sent(bucket, arn, size, started.elapsed());
                    ReplicationStatus::Completed
                }
                Err(Missed::Failed(err)) => {
                    self.stats.failed(bucket, arn, size, false);
                    tracing::warn!(bucket, key = %version.key, destination = %arn, error = %err, "a version can't be replicated");
                    ReplicationStatus::Failed
                }
                Err(missed @ (Missed::Later(_) | Missed::Unreachable(_))) => {
                    let unreachable = matches!(missed, Missed::Unreachable(_));
                    self.stats.failed(bucket, arn, size, unreachable);
                    let (Missed::Later(err) | Missed::Unreachable(err) | Missed::Failed(err)) =
                        missed;
                    tracing::info!(bucket, key = %version.key, destination = %arn, error = %err, "a version will be replicated later");
                    held.push(arn.clone());
                    continue;
                }
            };
            match self
                .store
                .set_replication_status(bucket, &version.key, &version.version_id, arn, status)
                .await
            {
                Ok(()) => {
                    settled = true;
                    if version.resync.contains(arn)
                        && let Err(err) = self
                            .store
                            .count_resync(bucket, arn, (&version.key, version.size), status)
                            .await
                    {
                        tracing::warn!(bucket, key = %version.key, error = %err, "couldn't count a resync's version");
                    }
                }
                Err(err) => {
                    tracing::warn!(bucket, key = %version.key, error = %err, "couldn't record a version's replication");
                }
            }
        }
        settled
    }

    /// Copies a version to the destination `arn`; whether it was sent (or is gone).
    async fn send(
        &self,
        bucket: &str,
        config: &ReplicationConfig,
        version: &Waiting,
        arn: &str,
    ) -> Result<(), Missed> {
        if version.delete_marker {
            return self.send_marker(version, arn).await;
        }
        if version.metadata.iter().any(|m| m == arn)
            && self.send_metadata(bucket, version, arn).await?
        {
            return Ok(());
        }
        let (info, body) = match self
            .store
            .read_with(bucket, &version.key, Some(&version.version_id), None)
            .await
        {
            Ok(read) => read,
            // Removed meanwhile: there's nothing left to send.
            Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        if info
            .sse
            .as_ref()
            .is_some_and(|sse| sse.mode == SseMode::Customer)
        {
            return Err(Missed::Failed(
                "the server doesn't hold an SSE-C object's key".to_owned(),
            ));
        }
        let destination = config
            .rules
            .iter()
            .find(|rule| rule.destination.bucket == arn)
            .map(|rule| &rule.destination);
        let replica = Replica {
            version_id: version.version_id.clone(),
            modified_ms: millis(info.modified),
            etag: Some(info.etag.clone()),
        };
        let sending = Sending {
            store: &self.store,
            bucket,
            key: &version.key,
            info,
            body,
            replica,
            replica_key: destination
                .and_then(|d| d.encryption.as_ref())
                .and_then(|encryption| encryption.kms_key.clone()),
            storage_class: destination.and_then(|d| d.storage_class.clone()),
        };
        if let Some(local) = arn.strip_prefix(LOCAL_ARN) {
            self.local(local, sending).await?;
        } else {
            self.remote(arn).await?.send(sending).await?;
        }
        Ok(())
    }

    /// Sends what changed in a version's metadata to the destination `arn`, which had
    /// the version; whether it did (`false`: the destination hasn't it now, so it all
    /// goes).
    async fn send_metadata(
        &self,
        bucket: &str,
        version: &Waiting,
        arn: &str,
    ) -> Result<bool, Missed> {
        let info = match self
            .store
            .head_version(bucket, &version.key, Some(&version.version_id))
            .await
        {
            Ok(info) => info,
            // Removed meanwhile: there's nothing left to send.
            Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => return Ok(true),
            Err(err) => return Err(err.into()),
        };
        if let Some(local) = arn.strip_prefix(LOCAL_ARN) {
            let update = ReplicaMetadata {
                tags: Some(info.attrs.tags.clone()),
                retention: info.attrs.retention,
                legal_hold: info.attrs.legal_hold,
            };
            return match self
                .store
                .update_replica_metadata(local, &version.key, &version.version_id, update)
                .await
            {
                Ok(_) => Ok(true),
                Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => Ok(false),
                Err(err) => Err(err.into()),
            };
        }
        let replica = Replica {
            version_id: version.version_id.clone(),
            modified_ms: millis(info.modified),
            etag: Some(info.etag.clone()),
        };
        self.remote(arn)
            .await?
            .send_metadata(&version.key, &replica, &info.attrs)
            .await
    }

    /// Copies a delete marker to the destination `arn`: there too, the key's current
    /// version becomes a marker (with this one's id and time, where that's kept).
    async fn send_marker(&self, version: &Waiting, arn: &str) -> Result<(), Missed> {
        let replica = Replica {
            version_id: version.version_id.clone(),
            modified_ms: millis(version.modified),
            etag: None,
        };
        if let Some(local) = arn.strip_prefix(LOCAL_ARN) {
            self.store
                .commit_replica_marker(local, &version.key, replica)
                .await?;
        } else {
            self.remote(arn)
                .await?
                .send_marker(&version.key, &replica)
                .await?;
        }
        Ok(())
    }

    /// The target `arn` names, ready to send to (made once a pass).
    async fn remote(&self, arn: &str) -> Result<Arc<remote::Target>, Missed> {
        if let Some(target) = lock(&self.targets).get(arn) {
            return Ok(Arc::clone(target));
        }
        let target = Arc::new(remote::Target::of(&self.store, arn).await?);
        lock(&self.targets).insert(arn.to_owned(), Arc::clone(&target));
        Ok(target)
    }

    /// Writes a replica into `destination`, a bucket on this drive.
    async fn local(&self, destination: &str, sending: Sending<'_>) -> Result<(), Missed> {
        let encryption = match sending.info.sse.as_ref().map(|sse| sse.mode) {
            // The destination's default, as a write without encryption headers gets.
            None => {
                let default = self.store.bucket_encryption(destination).await?;
                crate::sse::for_write(crate::sse::WriteRequest::default(), default.as_ref())
                    .unwrap_or_default()
            }
            Some(SseMode::S3) => Encryption::S3,
            Some(SseMode::Kms) => Encryption::Kms {
                key: sending.replica_key,
                context: std::collections::BTreeMap::new(),
                bucket_key: false,
            },
            Some(SseMode::Dsse | SseMode::Customer) => Encryption::Dsse {
                key: sending.replica_key,
                context: std::collections::BTreeMap::new(),
            },
        };
        let mut staged = self.store.stage_for(destination, &encryption).await?;
        if let Some(body) = sending.body {
            let mut reader = body.all().await?;
            let mut chunk = vec![0; CHUNK];
            loop {
                let read = reader
                    .read(&mut chunk)
                    .await
                    .map_err(|err| Missed::Later(err.to_string()))?;
                if read == 0 {
                    break;
                }
                staged.write(&chunk[..read]).await?;
            }
        }
        let mut attrs = sending.info.attrs;
        attrs.replication = None;
        self.store
            .commit_replica(destination, sending.key, staged, attrs, sending.replica)
            .await?;
        Ok(())
    }
}

/// A version on its way to a destination.
struct Sending<'a> {
    store: &'a Store,
    bucket: &'a str,
    key: &'a str,
    info: ObjectInfo,
    body: Option<ObjectBody>,
    /// What the replica keeps of the version.
    replica: Replica,
    /// The KMS key the rule names for replicas of SSE-KMS versions.
    replica_key: Option<String>,
    /// The storage class the rule names for replicas.
    storage_class: Option<String>,
}

impl Sending<'_> {
    /// The version read again, for another pass over its bytes.
    async fn reread(&self) -> Result<(ObjectInfo, Option<ObjectBody>), Missed> {
        Ok(self
            .store
            .read_with(self.bucket, self.key, Some(&self.replica.version_id), None)
            .await?)
    }
}

/// A time as Unix milliseconds.
fn millis(time: std::time::SystemTime) -> i64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_millis()).ok())
        .unwrap_or_default()
}

/// The cache of targets, whatever a panic elsewhere left.
fn lock(
    targets: &Mutex<HashMap<String, Arc<remote::Target>>>,
) -> std::sync::MutexGuard<'_, HashMap<String, Arc<remote::Target>>> {
    targets
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use teifs_store::{Layout, ObjectAttrs, Precondition, Versioning};
    use teifs_types::replication::{
        ReplicationDestination, ReplicationFilter, ReplicationRule, ResyncStatus,
    };

    use super::*;

    /// Everything in a bucket to `to`.
    fn everything_to(to: &str) -> ReplicationConfig {
        ReplicationConfig {
            role: String::new(),
            rules: vec![ReplicationRule {
                id: "r".to_owned(),
                priority: Some(1),
                enabled: true,
                filter: ReplicationFilter::All,
                delete_markers: Some(true),
                delete_replication: None,
                existing_objects: None,
                sse_kms_objects: None,
                replica_modifications: None,
                destination: ReplicationDestination {
                    bucket: format!("{LOCAL_ARN}{to}"),
                    account: None,
                    storage_class: None,
                    owner_override: false,
                    encryption: None,
                    replication_time: None,
                    metrics: None,
                },
            }],
        }
    }

    /// A drive (with a KMS, as a server has) whose `source` replicates to `copy`.
    async fn replicating() -> (tempfile::TempDir, Store) {
        replicating_in(Layout::Object).await
    }

    /// As [`replicating`], with buckets of `layout`.
    async fn replicating_in(layout: Layout) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let kms = Arc::new(teifs_crypto::LocalKms::open(dir.path().join("keys.json")).unwrap());
        let drive = dir.path().join("drive");
        std::fs::create_dir(&drive).unwrap();
        let options = teifs_store::StoreOptions {
            kms: Some(kms),
            ..teifs_store::StoreOptions::default()
        };
        let store = Store::open_with(&drive, options).unwrap();
        for bucket in ["source", "copy"] {
            store.create_bucket(bucket, layout).await.unwrap();
            store
                .set_bucket_versioning(bucket, Versioning::Enabled)
                .await
                .unwrap();
        }
        store
            .set_bucket_replication("source", Some(everything_to("copy")))
            .await
            .unwrap();
        (dir, store)
    }

    async fn put(store: &Store, key: &str, bytes: &[u8]) -> String {
        store
            .put_bytes("source", key, bytes, ObjectAttrs::default())
            .await
            .unwrap()
            .version_id
            .unwrap()
    }

    #[tokio::test]
    async fn a_keys_versions_are_replicated_oldest_first() {
        let (_dir, store) = replicating().await;
        let first = put(&store, "a.txt", b"one").await;
        let second = put(&store, "a.txt", b"two").await;
        put(&store, "b.txt", b"other").await;
        // A key's versions are never split between passes.
        let waiting = store.waiting_replication("source", 1).await.unwrap();
        assert_eq!(waiting.len(), 2, "{waiting:?}");

        let worker = Worker::new(store.clone(), Arc::new(Notify::new()));
        let stopping = CancellationToken::new();
        while worker.pass(&stopping).await {}
        assert!(!worker.pass(&stopping).await);
        assert!(
            store
                .waiting_replication("source", BATCH)
                .await
                .unwrap()
                .is_empty()
        );

        // The destination's current version is the source's.
        let (current, _) = store.read("copy", "a.txt").await.unwrap();
        assert_eq!(current.version_id.as_deref(), Some(second.as_str()));
        let older = store
            .head_version("copy", "a.txt", Some(&first))
            .await
            .unwrap();
        assert_eq!(older.size, 3);
        for (key, id) in [("a.txt", &first), ("a.txt", &second)] {
            let source = store.head_version("source", key, Some(id)).await.unwrap();
            assert_eq!(
                source.attrs.replication.map(|r| r.status),
                Some(ReplicationStatus::Completed)
            );
        }
        assert!(store.head_version("copy", "b.txt", None).await.is_ok());
    }

    #[tokio::test]
    async fn a_resync_sends_what_a_destination_lost_again_in_either_layout() {
        for layout in [Layout::Object, Layout::Folder] {
            let (_dir, store) = replicating_in(layout).await;
            let first = put(&store, "a.txt", b"one").await;
            let second = put(&store, "b.txt", b"three").await;
            let worker = Worker::new(store.clone(), Arc::new(Notify::new()));
            let stopping = CancellationToken::new();
            while worker.pass(&stopping).await {}
            // The destination loses them.
            for (key, id) in [("a.txt", &first), ("b.txt", &second)] {
                store
                    .delete_if("copy", key, Some(id), Precondition::default())
                    .await
                    .unwrap();
            }
            let arn = format!("{LOCAL_ARN}copy");
            let mut config = everything_to("copy");
            config.rules[0].existing_objects = Some(true);
            store
                .set_bucket_replication("source", Some(config))
                .await
                .unwrap();
            store
                .start_resync("source", &arn, "again".to_owned(), now() + 1)
                .await
                .unwrap();
            // Made since: sent as new, not by the resync.
            tokio::time::sleep(Duration::from_millis(5)).await;
            put(&store, "c.txt", b"later").await;
            while worker.pass(&stopping).await {}
            worker.pass(&stopping).await;

            for (key, id) in [("a.txt", &first), ("b.txt", &second)] {
                let copy = store.head_version("copy", key, Some(id)).await;
                assert!(copy.is_ok(), "{layout:?} {key}");
            }
            let resyncs = store.resyncs("source").await.unwrap();
            assert_eq!(resyncs.len(), 1, "{layout:?}");
            let (of, resync) = &resyncs[0];
            assert_eq!(of, &arn);
            assert_eq!(
                (resync.status, resync.replicated, resync.failed),
                (ResyncStatus::Completed, (2, 8), (0, 0)),
                "{layout:?}"
            );
        }
    }

    fn now() -> i64 {
        millis(std::time::SystemTime::now())
    }

    #[tokio::test]
    async fn versions_removed_before_their_turn_are_settled() {
        let (_dir, store) = replicating().await;
        let id = put(&store, "a.txt", b"one").await;
        store
            .delete_if("source", "a.txt", Some(&id), Precondition::default())
            .await
            .unwrap();
        let worker = Worker::new(store.clone(), Arc::new(Notify::new()));
        worker.pass(&CancellationToken::new()).await;
        assert!(store.head_version("copy", "a.txt", None).await.is_err());
    }

    #[tokio::test]
    async fn delete_markers_are_sent_once_in_either_layout() {
        for layout in [Layout::Object, Layout::Folder] {
            let (_dir, store) = replicating_in(layout).await;
            put(&store, "a.txt", b"one").await;
            let worker = Worker::new(store.clone(), Arc::new(Notify::new()));
            let stopping = CancellationToken::new();
            worker.pass(&stopping).await;
            let marker = store
                .delete_with("source", "a.txt", None, Precondition::default(), false)
                .await
                .unwrap()
                .version_id
                .unwrap();
            let waiting = store.waiting_replication("source", BATCH).await.unwrap();
            assert_eq!(waiting.len(), 1, "{layout:?}");
            assert!(waiting[0].delete_marker);
            worker.pass(&stopping).await;
            // Sent, and recorded so: it waits no more.
            assert!(
                store
                    .waiting_replication("source", BATCH)
                    .await
                    .unwrap()
                    .is_empty(),
                "{layout:?}"
            );
            assert!(matches!(
                store.head_version("copy", "a.txt", Some(&marker)).await,
                Err(StoreError::DeleteMarker { .. })
            ));
        }
    }

    #[tokio::test]
    async fn a_destination_on_the_drive_is_checked_as_a_target_would_be() {
        let (_dir, store) = replicating().await;
        assert_eq!(check(&store, "source").await, Ok(()));
        // Object Lock on the source wants it on the destination too.
        store
            .set_bucket_object_lock("source", teifs_store::ObjectLock::default())
            .await
            .unwrap();
        assert_eq!(
            check(&store, "source").await,
            Err(Unready::TargetUnlocked("copy".to_owned()))
        );
        store
            .set_bucket_object_lock("copy", teifs_store::ObjectLock::default())
            .await
            .unwrap();
        assert_eq!(check(&store, "source").await, Ok(()));
        // A destination that stopped keeping versions, or is gone, can't take replicas.
        store
            .set_bucket_replication("source", Some(everything_to("plain")))
            .await
            .unwrap();
        assert!(matches!(
            check(&store, "source").await,
            Err(Unready::Invalid(why)) if why.contains("plain")
        ));
        store.create_bucket("plain", Layout::Object).await.unwrap();
        assert_eq!(
            check(&store, "source").await,
            Err(Unready::TargetNotVersioned("plain".to_owned()))
        );
        // Nor does a bucket without versions or rules replicate.
        assert_eq!(check(&store, "plain").await, Err(Unready::NotVersioned));
        store
            .set_bucket_versioning("plain", Versioning::Enabled)
            .await
            .unwrap();
        assert_eq!(check(&store, "plain").await, Err(Unready::NoConfig));
        // A rule naming a target that's gone is stale.
        store
            .set_bucket_replication(
                "source",
                Some(ReplicationConfig {
                    rules: everything_to("copy")
                        .rules
                        .into_iter()
                        .map(|mut rule| {
                            rule.destination.bucket = "arn:minio:replication::gone:copy".to_owned();
                            rule
                        })
                        .collect(),
                    ..everything_to("copy")
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            check(&store, "source").await,
            Err(Unready::StaleTarget("r".to_owned()))
        );
    }

    #[tokio::test]
    async fn removals_reach_the_destination_once_in_either_layout() {
        for layout in [Layout::Object, Layout::Folder] {
            let (_dir, store) = replicating_in(layout).await;
            let mut config = everything_to("copy");
            config.rules[0].delete_replication = Some(true);
            store
                .set_bucket_replication("source", Some(config))
                .await
                .unwrap();
            let older = put(&store, "a.txt", b"one").await;
            let current = put(&store, "a.txt", b"two").await;
            put(&store, "b.txt", b"kept").await;
            let worker = Worker::new(store.clone(), Arc::new(Notify::new()));
            let stopping = CancellationToken::new();
            worker.pass(&stopping).await;
            let marker = store
                .delete_with("source", "b.txt", None, Precondition::default(), false)
                .await
                .unwrap()
                .version_id
                .unwrap();
            worker.pass(&stopping).await;
            assert!(store.head_version("copy", "b.txt", None).await.is_err());

            // The current version goes, and the marker: what was under it is back.
            for (key, id) in [("a.txt", &current), ("b.txt", &marker)] {
                store
                    .delete_with("source", key, Some(id), Precondition::default(), false)
                    .await
                    .unwrap();
            }
            assert_eq!(
                store.waiting_removals("source", BATCH).await.unwrap().len(),
                2
            );
            worker.pass(&stopping).await;
            assert!(
                store
                    .waiting_removals("source", BATCH)
                    .await
                    .unwrap()
                    .is_empty(),
                "{layout:?}"
            );
            let (now, _) = store.read("copy", "a.txt").await.unwrap();
            assert_eq!(
                now.version_id.as_deref(),
                Some(older.as_str()),
                "{layout:?}"
            );
            assert!(
                store.head_version("copy", "b.txt", None).await.is_ok(),
                "{layout:?}"
            );
            // The destination doesn't send them on.
            assert!(
                store
                    .waiting_removals("copy", BATCH)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn changed_metadata_follows_the_version_in_either_layout() {
        for layout in [Layout::Object, Layout::Folder] {
            let (_dir, store) = replicating_in(layout).await;
            let id = put(&store, "a.txt", b"one").await;
            let other = put(&store, "b.txt", b"two").await;
            let worker = Worker::new(store.clone(), Arc::new(Notify::new()));
            let stopping = CancellationToken::new();
            worker.pass(&stopping).await;
            let tags = std::collections::BTreeMap::from([("team".to_owned(), "red".to_owned())]);
            for (key, version) in [("a.txt", &id), ("b.txt", &other)] {
                store
                    .set_tags("source", key, Some(version), tags.clone())
                    .await
                    .unwrap();
            }
            // One the destination lost goes again whole.
            store
                .delete_if("copy", "b.txt", Some(&other), Precondition::default())
                .await
                .unwrap();
            worker.pass(&stopping).await;
            assert!(
                store
                    .waiting_replication("source", BATCH)
                    .await
                    .unwrap()
                    .is_empty(),
                "{layout:?}"
            );
            for (key, version) in [("a.txt", &id), ("b.txt", &other)] {
                let replica = store
                    .head_version("copy", key, Some(version))
                    .await
                    .unwrap();
                assert_eq!(replica.attrs.tags, tags, "{layout:?} {key}");
            }
            // Changed in place: no new version.
            let versions = store
                .list_versions(
                    "copy",
                    teifs_store::VersionsQuery {
                        max_keys: 100,
                        ..teifs_store::VersionsQuery::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(versions.versions.len(), 2, "{layout:?}");
        }
    }
}
