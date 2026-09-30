//! How long each stage of a read or a write takes, as histograms the server's metrics
//! show (`teifs_store_stage_seconds`), so a slow disk, a slow KMS or a busy commit lock
//! can be told apart from a slow network.
//!
//! Writes: `key` (a new data key from the KMS, for encrypted objects), `lock` (waiting
//! for the commit lock), `sync` (the data made durable), `commit` (everything under the
//! lock: the sync, the rename and the index). Reads: `locate` (finding the version and
//! opening its file), `key` (its data key from the KMS).

use std::time::Instant;

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{
        family::Family,
        histogram::{Histogram, exponential_buckets},
    },
};

use crate::Store;

/// An operation's stage.
#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Stage {
    /// `write` or `read`.
    pub op: &'static str,
    /// The stage.
    pub stage: &'static str,
}

/// Each stage's times, in seconds.
pub type StageTimes = Family<Stage, Histogram, fn() -> Histogram>;

/// From 100 µs, doubling, to about 52 s.
fn histogram() -> Histogram {
    Histogram::new(exponential_buckets(0.000_1, 2.0, 20))
}

pub(crate) fn new() -> StageTimes {
    Family::new_with_constructor(histogram as fn() -> Histogram)
}

/// Counts the time since `since` for `op`'s `stage`.
pub(crate) fn record(times: &StageTimes, op: &'static str, stage: &'static str, since: Instant) {
    times
        .get_or_create(&Stage { op, stage })
        .observe(since.elapsed().as_secs_f64());
}

/// Runs `f`, counting its time for `op`'s `stage`.
pub(crate) fn time<T>(
    times: &StageTimes,
    op: &'static str,
    stage: &'static str,
    f: impl FnOnce() -> T,
) -> T {
    let since = Instant::now();
    let result = f();
    record(times, op, stage, since);
    result
}

impl Store {
    /// How long each stage of reads and writes has taken, to register with metrics.
    #[must_use]
    pub fn stage_times(&self) -> StageTimes {
        self.inner.stages.clone()
    }
}
