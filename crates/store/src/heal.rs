//! Healing a drive set: copies of the databases rebuilt where they failed, and objects'
//! shards checked on each drive that's up, those missing or damaged rebuilt from the
//! others. Runs while the set serves: an object removed meanwhile loses the shards
//! healed for it again.
//!
//! Two ways in:
//! - **The heal queue** ([`HealQueue`], a background job): data files a drive missed
//!   while the set served (a shard that couldn't be written or removed, kept in the
//!   index with the change that missed it), and those a read found a bad shard of.
//!   Each is healed at once, and tried again later (backing off) while a drive fails;
//!   one waiting only for a drive that's down waits until the set opens with it.
//! - **A full heal** ([`Store::heal_set`]): every object, when the set opens with a
//!   drive that missed writes (it was down, or is new), or when asked.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use serde::Serialize;
use teifs_meta::{CopyState, PARKED, QueuedHeal};

use crate::{
    BUCKETS_DIR, Inner, Store, StoreError,
    error::Result,
    jobs::{BATCH, Job, Step, millis, millis_of},
    objects,
    set::{DriveSet, Healed, ShardState},
};

/// Data files looked up at a time.
const PAGE: usize = 256;
/// How long a queued heal that failed waits first; each failure doubles it.
const FIRST_RETRY: Duration = Duration::from_secs(30);
/// The longest a queued heal waits between tries.
const MAX_RETRY: Duration = Duration::from_hours(1);
/// How long failed copies of the metadata wait before they're rebuilt again, at first.
const COPIES_FIRST: Duration = Duration::from_secs(30);
/// The longest they wait.
const COPIES_MAX: Duration = Duration::from_mins(10);

/// What a heal did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealReport {
    /// Objects (data files) checked.
    pub objects: u64,
    /// Of them, those given new shards.
    pub healed: u64,
    /// Shards written.
    pub shards: u64,
    /// Objects with too few sound shards left to rebuild from.
    pub unreadable: u64,
    /// Copies of the databases that still can't be used (on a drive that's failing).
    pub failed_copies: usize,
}

/// How a drive of a set is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DriveState {
    /// Up and current.
    Ok,
    /// Down since the set opened.
    Offline,
    /// Up, but its copy of the metadata failed: it's missing changes until healed.
    Failing,
    /// New in a lost drive's place, being healed.
    Healing,
}

/// One drive of a set, as [`HealStatus`] reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveHealth {
    /// Its place in the set.
    pub place: usize,
    /// Its folder; `None` when it's down.
    pub path: Option<PathBuf>,
    /// How it's doing.
    pub state: DriveState,
}

/// Where a drive set's healing stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealStatus {
    /// Data files in the heal queue.
    pub queued: u64,
    /// Of them, those waiting for a drive that's down.
    pub waiting: u64,
    /// Data files healed since the set opened.
    pub objects: u64,
    /// Shards written (or removed) by healing since the set opened.
    pub shards: u64,
    /// Bytes of shards written by healing since the set opened.
    pub bytes: u64,
    /// Whether a full heal (every object) is under way.
    pub running: bool,
    /// Each drive, by place.
    pub drives: Vec<DriveHealth>,
}

/// What healing has done, as cheap to read as a counter (for metrics): the heal
/// queue's length is as the heal job last saw it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HealProgress {
    /// Drives up.
    pub up: usize,
    /// Drives down.
    pub down: usize,
    /// Data files in the heal queue.
    pub queued: u64,
    /// Of them, those waiting for a drive that's down.
    pub waiting: u64,
    /// Data files healed since the set opened.
    pub objects: u64,
    /// Shards written or removed.
    pub shards: u64,
    /// Bytes of shards written.
    pub bytes: u64,
    /// Whether a full heal is under way.
    pub running: bool,
}

/// What healing one version did: each drive's shard before and after, by place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectHeal {
    /// Before.
    pub before: Vec<ShardState>,
    /// After.
    pub after: Vec<ShardState>,
}

/// How [`Store::heal_object`] heals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HealOptions {
    /// Read every piece of each shard and check its hash, rather than only its header
    /// and length.
    pub deep: bool,
    /// Only look: change nothing.
    pub dry_run: bool,
}

impl Store {
    /// Heals a drive set (nothing on a single drive): rebuilds the databases' failed
    /// copies, then checks every object's shards on the drives that are up and rebuilds
    /// those missing or damaged. Writes go on meanwhile.
    pub async fn heal_set(&self) -> Result<HealReport> {
        let Some(set) = self.inner.set.clone() else {
            return Ok(HealReport::default());
        };
        if set.healed.running.swap(true, Ordering::SeqCst) {
            return Err(StoreError::InvalidRequest(
                "a heal of the drive set is under way",
            ));
        }
        let healed = self.heal_everything(&set).await;
        set.healed.running.store(false, Ordering::SeqCst);
        healed
    }

    /// On a drive set, rebuilds the metadata's copies that failed; how many still fail.
    pub async fn heal_copies(&self) -> Result<usize> {
        self.blocking(Inner::heal_copies).await
    }

    async fn heal_everything(&self, set: &Arc<DriveSet>) -> Result<HealReport> {
        let failed_copies = self.blocking(Inner::heal_copies).await?;
        let mut report = HealReport {
            failed_copies,
            ..HealReport::default()
        };
        let mut after = String::new();
        loop {
            let from = after.clone();
            let page = self
                .blocking(move |inner| Ok(inner.lock().data_files_after(&from, PAGE)?))
                .await?;
            let Some((_, last)) = page.last() else {
                break;
            };
            after.clone_from(last);
            for (bucket_id, object_id) in page {
                report.objects += 1;
                let set = Arc::clone(set);
                let healed = self
                    .blocking(move |inner| Ok(inner.heal_data_file(&set, &bucket_id, &object_id)))
                    .await?;
                match healed {
                    Outcome::Healed(shards) if shards > 0 => {
                        report.healed += 1;
                        report.shards += shards as u64;
                    }
                    Outcome::Unreadable => report.unreadable += 1,
                    _ => {}
                }
            }
        }
        if report.healed > 0 || report.unreadable > 0 {
            tracing::info!(
                objects = report.objects,
                healed = report.healed,
                shards = report.shards,
                unreadable = report.unreadable,
                "the drive set was healed"
            );
        }
        Ok(report)
    }

    /// Checks version `version_id` (the latest when `None`) of `key` on each drive of a
    /// drive set, and unless `options.dry_run`, rebuilds the shards that are missing or
    /// damaged: each drive's shard before and after. `None` on a single drive.
    pub async fn heal_object(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        options: HealOptions,
    ) -> Result<Option<ObjectHeal>> {
        let Some(set) = self.inner.set.clone() else {
            return Ok(None);
        };
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        let version_id = version_id.map(str::to_owned);
        self.blocking(move |inner| {
            let crate::Bucket::Object(bucket) = inner.bucket(&bucket)? else {
                return Err(StoreError::NoSuchBucket);
            };
            let row = Inner::version_row(&inner.lock(), &bucket, &key, version_id.as_deref())?;
            let up: Vec<ShardState> = set
                .drives()
                .iter()
                .map(|d| {
                    if d.is_some() {
                        ShardState::Ok
                    } else {
                        ShardState::Offline
                    }
                })
                .collect();
            // Kept in its row (or a delete marker): as safe as the metadata's copies.
            let Some(object_id) = row.object_id else {
                return Ok(Some(ObjectHeal {
                    before: up.clone(),
                    after: up,
                }));
            };
            let path = bucket.data_path(&object_id);
            let healed = set.heal_file(&path, &object_id, options.deep, options.dry_run)?;
            set.count(&healed);
            let mut after = healed.before.clone();
            for place in &healed.places {
                after[*place] = ShardState::Ok;
            }
            Ok(Some(ObjectHeal {
                before: healed.before,
                after,
            }))
        })
        .await
    }

    /// What a drive set's healing has done, read without waiting on anything; `None` on
    /// a single drive.
    #[must_use]
    pub fn heal_progress(&self) -> Option<HealProgress> {
        let set = self.inner.set.as_ref()?;
        let up = set.drives().iter().flatten().count();
        let healed = &set.healed;
        Some(HealProgress {
            up,
            down: set.drives().len() - up,
            queued: healed.queued.load(Ordering::Relaxed),
            waiting: healed.waiting.load(Ordering::Relaxed),
            objects: healed.objects.load(Ordering::Relaxed),
            shards: healed.shards.load(Ordering::Relaxed),
            bytes: healed.bytes.load(Ordering::Relaxed),
            running: healed.running.load(Ordering::SeqCst),
        })
    }

    /// Where a drive set's healing stands; `None` on a single drive.
    pub async fn heal_status(&self) -> Result<Option<HealStatus>> {
        let Some(set) = self.inner.set.clone() else {
            return Ok(None);
        };
        self.blocking(move |inner| {
            let (queued, waiting) = inner.lock().heal_queue_len()?;
            set.healed.queued.store(queued, Ordering::Relaxed);
            set.healed.waiting.store(waiting, Ordering::Relaxed);
            let failing = inner.failed_copy_paths();
            let running = set.healed.running.load(Ordering::SeqCst);
            let drives = set
                .drives()
                .iter()
                .enumerate()
                .map(|(place, root)| {
                    let state = match root {
                        None => DriveState::Offline,
                        Some(root) if failing.iter().any(|f| f.starts_with(root)) => {
                            DriveState::Failing
                        }
                        Some(_) if running && set.replaced().contains(&place) => {
                            DriveState::Healing
                        }
                        Some(_) => DriveState::Ok,
                    };
                    DriveHealth {
                        place,
                        path: root.clone(),
                        state,
                    }
                })
                .collect();
            Ok(Some(HealStatus {
                queued,
                waiting,
                objects: set.healed.objects.load(Ordering::Relaxed),
                shards: set.healed.shards.load(Ordering::Relaxed),
                bytes: set.healed.bytes.load(Ordering::Relaxed),
                running,
                drives,
            }))
        })
        .await
    }
}

/// What healing a data file came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Every drive that's up holds what it should; the shards written or removed.
    Healed(usize),
    /// A drive that's up failed: try again later.
    Retry,
    /// Only a drive that's down is left to put right: once it's back.
    Wait,
    /// Too few sound shards to rebuild from.
    Unreadable,
}

impl DriveSet {
    /// Counts what healing a data file did.
    fn count(&self, healed: &Healed) {
        if healed.places.is_empty() {
            return;
        }
        self.healed.objects.fetch_add(1, Ordering::Relaxed);
        self.healed
            .shards
            .fetch_add(healed.places.len() as u64, Ordering::Relaxed);
        self.healed.bytes.fetch_add(healed.bytes, Ordering::Relaxed);
    }
}

impl Inner {
    /// Rebuilds the metadata's failed copies; how many still fail.
    fn heal_copies(&self) -> Result<usize> {
        let index = self.lock().heal_copies()?;
        let system = self.system().heal_copies()?;
        Ok(index
            .iter()
            .chain(&system)
            .filter(|(_, state)| *state != CopyState::Current)
            .count())
    }

    /// Where the metadata's copies that failed are.
    fn failed_copy_paths(&self) -> Vec<PathBuf> {
        let failed = |states: Vec<(PathBuf, CopyState)>| {
            states
                .into_iter()
                .filter(|(_, state)| *state != CopyState::Current)
                .map(|(path, _)| path)
                .collect::<Vec<_>>()
        };
        let mut paths = self
            .lock()
            .copies()
            .map(|c| failed(c.states()))
            .unwrap_or_default();
        if let Some(copies) = self.system().copies() {
            paths.extend(failed(copies.states()));
        }
        paths
    }

    /// Heals data file `object_id` of bucket `bucket_id`: rebuilds its bad shards while
    /// a version uses it, else removes whatever shards of it are left.
    fn heal_data_file(&self, set: &DriveSet, bucket_id: &str, object_id: &str) -> Outcome {
        let dir = self.system_dir.join(BUCKETS_DIR).join(bucket_id);
        let path = objects::data_file(&dir, object_id);
        match self.heal_in_use(set, &path, object_id) {
            Ok(Some(outcome)) => outcome,
            Ok(None) => remove_left(set, &path),
            Err(err) => {
                tracing::warn!(object = object_id, error = %err, "an object couldn't be healed");
                Outcome::Retry
            }
        }
    }

    /// Heals `object_id`'s shards while a version uses it; `None` when none does (any
    /// more).
    fn heal_in_use(&self, set: &DriveSet, path: &Path, object_id: &str) -> Result<Option<Outcome>> {
        if !self.lock().object_in_use(object_id)? {
            return Ok(None);
        }
        let healed = match set.heal_file(path, object_id, true, false) {
            Ok(healed) => healed,
            // Removed since (as a file removed while it's read).
            Err(StoreError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(StoreError::Quorum { found, needed }) => {
                tracing::error!(
                    object = object_id,
                    found,
                    needed,
                    "an object has too few sound shards left to be healed"
                );
                return Ok(Some(Outcome::Unreadable));
            }
            Err(err) => return Err(err),
        };
        // Removed while it was healed: its new shards go too.
        if !healed.places.is_empty() && !self.lock().object_in_use(object_id)? {
            return Ok(None);
        }
        set.count(&healed);
        Ok(Some(if healed.failed > 0 {
            Outcome::Retry
        } else {
            Outcome::Healed(healed.places.len())
        }))
    }
}

/// Removes the shards left of a data file no version uses.
fn remove_left(set: &DriveSet, path: &Path) -> Outcome {
    let removed = set.remove(path);
    if removed.shards > 0 {
        set.healed.objects.fetch_add(1, Ordering::Relaxed);
        set.healed
            .shards
            .fetch_add(removed.shards as u64, Ordering::Relaxed);
    }
    if removed.complete() {
        Outcome::Healed(removed.shards)
    } else if removed.gone() {
        Outcome::Wait
    } else {
        Outcome::Retry
    }
}

/// The heal queue's job, on a drive set: takes what reads noted into the queue,
/// rebuilds the metadata's failed copies now and then, and heals the data files due.
pub(crate) struct HealQueue {
    /// When failed copies of the metadata are next rebuilt.
    copies_due_ms: i64,
    /// How long they wait after that, if they fail again.
    copies_wait: Duration,
}

impl HealQueue {
    pub(crate) fn new() -> Self {
        Self {
            copies_due_ms: 0,
            copies_wait: COPIES_FIRST,
        }
    }
}

impl Job for HealQueue {
    fn name(&self) -> &'static str {
        "heal"
    }

    fn step(&mut self, inner: &Inner, step: &Step) -> Result<usize> {
        let Some(set) = inner.set.clone() else {
            return Ok(0);
        };
        let now = millis(step.now);
        let suspects = set.take_suspects();
        if !suspects.is_empty() {
            let conn = inner.lock();
            for (bucket_id, object_id) in &suspects {
                conn.queue_heal(bucket_id, object_id, now)?;
            }
        }
        if now >= self.copies_due_ms && !inner.failed_copy_paths().is_empty() {
            if inner.heal_copies()? == 0 {
                // The drive is back: what waited on it is due now.
                tracing::info!("the metadata's failed copies were rebuilt");
                self.copies_wait = COPIES_FIRST;
                inner.lock().wake_heals(now)?;
            } else {
                self.copies_wait = (self.copies_wait * 2).min(COPIES_MAX);
            }
            self.copies_due_ms = now.saturating_add(millis_of(self.copies_wait));
        }
        let due = inner.lock().due_heals(now, BATCH)?;
        let mut done = 0;
        for QueuedHeal {
            bucket_id,
            object_id,
            tries,
        } in due
        {
            if step.cancel.is_cancelled() {
                break;
            }
            let outcome = inner.heal_data_file(&set, &bucket_id, &object_id);
            let conn = inner.lock();
            match outcome {
                Outcome::Healed(_) | Outcome::Unreadable => conn.drop_heal(&object_id)?,
                Outcome::Wait => conn.retry_heal(&object_id, PARKED)?,
                Outcome::Retry => {
                    let wait = FIRST_RETRY
                        .saturating_mul(1 << tries.min(16))
                        .min(MAX_RETRY);
                    conn.retry_heal(&object_id, now.saturating_add(millis_of(wait)))?;
                }
            }
            done += 1;
        }
        let (queued, waiting) = inner.lock().heal_queue_len()?;
        set.healed.queued.store(queued, Ordering::Relaxed);
        set.healed.waiting.store(waiting, Ordering::Relaxed);
        Ok(done)
    }

    fn idle(&self) -> Duration {
        Duration::from_secs(5)
    }
}
