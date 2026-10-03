//! Bucket replication: copies the versions buckets' replication rules wait for to their
//! destinations. Woken as objects are written, and every so often to find what a restart
//! or a failed attempt left waiting (each version keeps where it stands, so nothing is
//! lost). A version a destination can't take is marked `FAILED`; one that may get
//! through later stays `PENDING` and is tried again. Removals of versions the rules
//! replicate (`MinIO`'s `DeleteReplication`) wait in a queue of their own, since the
//! versions are gone.

mod remote;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use teifs_store::{
    Encryption, ObjectBody, ObjectInfo, QueuedDelete, Replica, Store, StoreError, Waiting,
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
}

/// Why a version didn't reach a destination.
#[derive(Debug)]
enum Missed {
    /// It never will as things are: the destination is missing or doesn't take replicas.
    Failed(String),
    /// It may later: tried again on the next pass.
    Later(String),
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
        }
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
            let waiting = match self.store.waiting_replication(&bucket.name, BATCH).await {
                Ok(waiting) => waiting,
                Err(err) => {
                    tracing::warn!(bucket = %bucket.name, error = %err, "couldn't find the versions waiting to be replicated");
                    continue;
                }
            };
            let full = waiting.len() >= BATCH;
            let mut through = false;
            // A key's versions go oldest first, so the destination's current version is
            // the source's; one held back holds back the newer ones too.
            for versions in waiting.chunk_by(|a, b| a.key == b.key) {
                let mut held = Vec::new();
                for version in versions.iter().rev() {
                    if stopping.is_cancelled() {
                        return false;
                    }
                    through |= self
                        .version(&bucket.name, &config, version, &mut held)
                        .await;
                }
            }
            let removals = match self.store.waiting_removals(&bucket.name, BATCH).await {
                Ok(removals) => removals,
                Err(err) => {
                    tracing::warn!(bucket = %bucket.name, error = %err, "couldn't find the removals waiting to be replicated");
                    Vec::new()
                }
            };
            let full = full || removals.len() >= BATCH;
            for removal in &removals {
                if stopping.is_cancelled() {
                    return false;
                }
                through |= self.removal(&bucket.name, removal).await;
            }
            again |= full && through;
        }
        again
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
                Err(Missed::Later(err)) => {
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
            let status = match self.send(bucket, config, version, arn).await {
                Ok(()) => ReplicationStatus::Completed,
                Err(Missed::Failed(err)) => {
                    tracing::warn!(bucket, key = %version.key, destination = %arn, error = %err, "a version can't be replicated");
                    ReplicationStatus::Failed
                }
                Err(Missed::Later(err)) => {
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
                Ok(()) => settled = true,
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
    use teifs_types::replication::{ReplicationDestination, ReplicationFilter, ReplicationRule};

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
}
