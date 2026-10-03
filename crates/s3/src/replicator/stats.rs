//! What replication did since the server started, by bucket and destination, kept in
//! memory as `MinIO` keeps it: for its replication metrics (`mc replicate status`,
//! [`crate::minio_replication`]) and the Prometheus metrics.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Mutex, PoisonError},
    time::{Duration, Instant, SystemTime},
};

/// How far back errors and transfers are kept: the last hour.
const HOUR: Duration = Duration::from_secs(3600);
/// The last minute.
const MINUTE: Duration = Duration::from_secs(60);

/// Replication's figures, by bucket.
#[derive(Debug)]
pub(crate) struct Stats {
    started: Instant,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            buckets: Mutex::default(),
        }
    }
}

/// One bucket's figures.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Bucket {
    /// Each destination's.
    pub(crate) targets: BTreeMap<String, Target>,
    /// Replicas other servers sent here: how many, and of how many bytes.
    pub(crate) received: (u64, u64),
    /// The versions waiting to be sent, as last seen, and their average and most.
    pub(crate) queued: Queue,
}

/// How many versions, and of how many bytes, wait: now, on average, and at most.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Queue {
    pub(crate) now: (u64, u64),
    pub(crate) average: (f64, f64),
    pub(crate) most: (u64, u64),
    samples: u64,
}

/// One destination's figures.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Target {
    /// Versions sent: how many, and of how many bytes.
    pub(crate) replicated: (u64, u64),
    /// Versions waiting for it, as last seen: how many, and of how many bytes.
    pub(crate) pending: (u64, u64),
    /// Attempts that didn't get through, since the server started.
    pub(crate) failed: (u64, u64),
    /// Their times and sizes in the last hour.
    failures: VecDeque<(Instant, u64)>,
    /// Transfers in the last hour: when they ended, their bytes and how long they took.
    transfers: VecDeque<(Instant, u64, Duration)>,
    /// All transfers' bytes and time, since the server started.
    transferred: (u64, Duration),
    /// The fastest transfer, in bytes a second.
    pub(crate) peak_rate: f64,
    /// Whether it was reached when last tried.
    pub(crate) online: Option<bool>,
    /// When it was last reached.
    pub(crate) last_online: Option<SystemTime>,
    /// When it was found unreachable, while it is.
    offline_since: Option<Instant>,
    /// How long it's been unreachable in all, but the current stretch.
    pub(crate) downtime: Duration,
    /// How often it became unreachable.
    pub(crate) offline_count: u64,
    /// How long transfers took: the last, the longest, and all together with how many.
    latency: (Duration, Duration, Duration, u32),
}

/// Counts and bytes over a minute, an hour and since the server started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Timed {
    pub(crate) last_minute: (u64, u64),
    pub(crate) last_hour: (u64, u64),
    pub(crate) totals: (u64, u64),
}

/// Transfer rates in bytes a second: over the last minute, on average, and the most.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Rates {
    pub(crate) now: f64,
    pub(crate) average: f64,
    pub(crate) peak: f64,
    pub(crate) transfers: u64,
}

/// A count or byte total as a float, for rates and averages (exact below 2⁵³).
#[expect(clippy::cast_precision_loss, reason = "rates and averages")]
const fn float(n: u64) -> f64 {
    n as f64
}

impl Target {
    /// Its failures over a minute, an hour and since the server started, as of `now`.
    pub(crate) fn failures(&self, now: Instant) -> Timed {
        let within = |span: Duration| {
            self.failures
                .iter()
                .filter(|(at, _)| now.duration_since(*at) <= span)
                .fold((0, 0), |(count, bytes), (_, size)| {
                    (count + 1, bytes + size)
                })
        };
        Timed {
            last_minute: within(MINUTE),
            last_hour: within(HOUR),
            totals: self.failed,
        }
    }

    /// Its transfer rates, as of `now`.
    pub(crate) fn rates(&self, now: Instant) -> Rates {
        let last_minute: u64 = self
            .transfers
            .iter()
            .filter(|(at, ..)| now.duration_since(*at) <= MINUTE)
            .map(|(_, bytes, _)| bytes)
            .sum();
        let (bytes, took) = self.transferred;
        Rates {
            now: float(last_minute) / MINUTE.as_secs_f64(),
            average: if took.is_zero() {
                0.0
            } else {
                float(bytes) / took.as_secs_f64()
            },
            peak: self.peak_rate,
            transfers: u64::try_from(self.transfers.len()).unwrap_or(u64::MAX),
        }
    }

    /// How long transfers took: the last, on average, and the longest.
    pub(crate) fn latency(&self) -> (Duration, Duration, Duration) {
        let (last, longest, all, count) = self.latency;
        (last, all.checked_div(count).unwrap_or_default(), longest)
    }

    /// How long it's been unreachable in all, as of `now`.
    pub(crate) fn total_downtime(&self, now: Instant) -> Duration {
        self.downtime
            + self
                .offline_since
                .map_or(Duration::ZERO, |since| now - since)
    }

    fn prune(&mut self, now: Instant) {
        while self
            .failures
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) > HOUR)
        {
            self.failures.pop_front();
        }
        while self
            .transfers
            .front()
            .is_some_and(|(at, ..)| now.duration_since(*at) > HOUR)
        {
            self.transfers.pop_front();
        }
    }

    fn reached(&mut self, now: Instant) {
        if let Some(since) = self.offline_since.take() {
            self.downtime += now - since;
        }
        self.online = Some(true);
        self.last_online = Some(SystemTime::now());
    }
}

impl Stats {
    /// How long the server has been running.
    pub(crate) fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// `bucket`'s figures (none yet: empty).
    pub(crate) fn bucket(&self, bucket: &str) -> Bucket {
        self.lock().get(bucket).cloned().unwrap_or_default()
    }

    /// Every bucket's figures, by name.
    pub(crate) fn buckets(&self) -> BTreeMap<String, Bucket> {
        self.lock()
            .iter()
            .map(|(name, bucket)| (name.clone(), bucket.clone()))
            .collect()
    }

    /// Records that a version of `size` bytes reached `arn` from `bucket` in `took`.
    pub(crate) fn sent(&self, bucket: &str, arn: &str, size: u64, took: Duration) {
        let now = Instant::now();
        self.target(bucket, arn, |target| {
            target.prune(now);
            target.reached(now);
            target.replicated.0 += 1;
            target.replicated.1 = target.replicated.1.saturating_add(size);
            target.transfers.push_back((now, size, took));
            target.transferred.0 = target.transferred.0.saturating_add(size);
            target.transferred.1 += took;
            if !took.is_zero() {
                target.peak_rate = target.peak_rate.max(float(size) / took.as_secs_f64());
            }
            let (_, longest, all, count) = target.latency;
            target.latency = (took, longest.max(took), all + took, count.saturating_add(1));
        });
    }

    /// Records that a version of `size` bytes didn't get from `bucket` to `arn`;
    /// `unreachable` when `arn` couldn't be reached at all.
    pub(crate) fn failed(&self, bucket: &str, arn: &str, size: u64, unreachable: bool) {
        let now = Instant::now();
        self.target(bucket, arn, |target| {
            target.prune(now);
            target.failed.0 += 1;
            target.failed.1 = target.failed.1.saturating_add(size);
            target.failures.push_back((now, size));
            if unreachable {
                if target.offline_since.is_none() {
                    target.offline_since = Some(now);
                    target.offline_count += 1;
                }
                target.online = Some(false);
            } else {
                target.reached(now);
            }
        });
    }

    /// Records what waits in `bucket`: `(count, bytes)` in all, and by destination.
    pub(crate) fn waiting(
        &self,
        bucket: &str,
        all: (u64, u64),
        by_target: &BTreeMap<String, (u64, u64)>,
    ) {
        let mut buckets = self.lock();
        let found = buckets.entry(bucket.to_owned()).or_default();
        let queue = &mut found.queued;
        queue.samples += 1;
        let n = float(queue.samples);
        queue.average.0 += (float(all.0) - queue.average.0) / n;
        queue.average.1 += (float(all.1) - queue.average.1) / n;
        queue.now = all;
        queue.most = (queue.most.0.max(all.0), queue.most.1.max(all.1));
        for (arn, target) in &mut found.targets {
            target.pending = by_target.get(arn).copied().unwrap_or_default();
        }
        for (arn, pending) in by_target {
            found.targets.entry(arn.clone()).or_default().pending = *pending;
        }
    }

    /// Records what still waits in `bucket` once a pass sent what it could: `(count,
    /// bytes)` in all, and by destination (not a sample of the queue's size).
    pub(crate) fn left(
        &self,
        bucket: &str,
        all: (u64, u64),
        by_target: &BTreeMap<String, (u64, u64)>,
    ) {
        let mut buckets = self.lock();
        let found = buckets.entry(bucket.to_owned()).or_default();
        found.queued.now = all;
        for (arn, target) in &mut found.targets {
            target.pending = by_target.get(arn).copied().unwrap_or_default();
        }
    }

    /// Records a replica of `size` bytes another server sent to `bucket`.
    pub(crate) fn received(&self, bucket: &str, size: u64) {
        let mut buckets = self.lock();
        let found = buckets.entry(bucket.to_owned()).or_default();
        found.received.0 += 1;
        found.received.1 = found.received.1.saturating_add(size);
    }

    fn target(&self, bucket: &str, arn: &str, change: impl FnOnce(&mut Target)) {
        let mut buckets = self.lock();
        let found = buckets.entry(bucket.to_owned()).or_default();
        change(found.targets.entry(arn.to_owned()).or_default());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Bucket>> {
        self.buckets.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn transfers_and_failures_are_counted_by_destination() {
        let stats = Stats::default();
        stats.sent("b", "arn:1", 100, Duration::from_millis(100));
        stats.sent("b", "arn:1", 300, Duration::from_millis(100));
        stats.failed("b", "arn:1", 50, false);
        stats.failed("b", "arn:2", 7, true);
        stats.received("b", 9);
        let bucket = stats.bucket("b");
        let one = &bucket.targets["arn:1"];
        assert_eq!(one.replicated, (2, 400));
        assert_eq!(one.failed, (1, 50));
        assert_eq!(one.online, Some(true));
        let now = Instant::now();
        let failures = one.failures(now);
        assert_eq!(failures.last_minute, (1, 50));
        assert_eq!(failures.last_hour, (1, 50));
        // Two hours on, only the totals remember them.
        let later = now + 2 * HOUR;
        assert_eq!(one.failures(later).last_hour, (0, 0));
        assert_eq!(one.failures(later).totals, (1, 50));
        let rates = one.rates(now);
        assert!((rates.average - 2000.0).abs() < 1e-6, "{rates:?}");
        assert!((rates.peak - 3000.0).abs() < 1e-6, "{rates:?}");
        assert!((rates.now - 400.0 / 60.0).abs() < 1e-6, "{rates:?}");
        assert_eq!(
            one.latency(),
            (
                Duration::from_millis(100),
                Duration::from_millis(100),
                Duration::from_millis(100)
            )
        );
        assert!(one.rates(later).now.abs() < f64::EPSILON);

        let two = &bucket.targets["arn:2"];
        assert_eq!((two.online, two.offline_count), (Some(false), 1));
        assert!(two.total_downtime(now + MINUTE) >= MINUTE);
        assert_eq!(bucket.received, (1, 9));
        // Reached again: online, the downtime kept.
        stats.sent("b", "arn:2", 1, Duration::ZERO);
        let two = &stats.bucket("b").targets["arn:2"];
        assert_eq!((two.online, two.offline_count), (Some(true), 1));
        assert!(two.last_online.is_some());
        assert!(stats.bucket("other").targets.is_empty());
    }

    #[test]
    fn the_queue_keeps_its_average_and_most() {
        let stats = Stats::default();
        let by = BTreeMap::from([("arn:1".to_owned(), (4, 40))]);
        stats.waiting("b", (4, 40), &by);
        stats.waiting("b", (2, 20), &BTreeMap::new());
        let bucket = stats.bucket("b");
        assert_eq!(bucket.queued.now, (2, 20));
        assert_eq!(bucket.queued.most, (4, 40));
        assert_eq!(bucket.queued.average, (3.0, 30.0));
        // A destination nothing waits for any more has none pending.
        assert_eq!(bucket.targets["arn:1"].pending, (0, 0));
        // What's left after a pass isn't a sample.
        stats.left("b", (1, 5), &BTreeMap::new());
        let bucket = stats.bucket("b");
        assert_eq!(bucket.queued.now, (1, 5));
        assert_eq!(bucket.queued.average, (3.0, 30.0));
    }
}
