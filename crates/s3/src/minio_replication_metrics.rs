//! `MinIO`'s replication metrics as its server writes them (`BucketStats`, and its
//! `currStats` alone for the first version), which `mc replicate status` reads: what
//! replication did since the server started, by destination, what waits, the transfer
//! rates and whether each target was reachable.

use std::{collections::BTreeMap, time::Instant};

use serde::Serialize;
use teifs_types::replication::ReplicationConfig;

use crate::replicator::{Bucket, Rates, Stats, Target, Timed};

/// `MinIO`'s `BucketStats`.
#[derive(Debug, Serialize)]
pub(crate) struct Metrics {
    uptime: u64,
    #[serde(rename = "currStats")]
    pub(crate) current: Current,
    #[serde(rename = "queueStats")]
    queue: QueueStats,
    #[serde(rename = "proxyStats")]
    proxy: Proxy,
}

/// `MinIO`'s `BucketReplicationStats`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Current {
    #[serde(rename = "Stats", skip_serializing_if = "BTreeMap::is_empty")]
    stats: BTreeMap<String, TargetStats>,
    #[serde(rename = "completedReplicationSize")]
    replicated_size: u64,
    replica_size: u64,
    failed: TimedStats,
    #[serde(rename = "replicationCount")]
    replicated_count: u64,
    replica_count: u64,
    queued: Queued,
    #[serde(rename = "pendingReplicationSize")]
    pending_size: u64,
    #[serde(rename = "failedReplicationSize")]
    failed_size: u64,
    #[serde(rename = "pendingReplicationCount")]
    pending_count: u64,
    #[serde(rename = "failedReplicationCount")]
    failed_count: u64,
}

/// `MinIO`'s `BucketReplicationStat`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetStats {
    #[serde(rename = "completedReplicationSize")]
    replicated_size: u64,
    replica_size: u64,
    failed: TimedStats,
    #[serde(rename = "replicationCount")]
    replicated_count: u64,
    /// No bandwidth limit is set.
    limit_in_bits: u64,
    current_bandwidth: f64,
    #[serde(rename = "pendingReplicationSize")]
    pending_size: u64,
    #[serde(rename = "failedReplicationSize")]
    failed_size: u64,
    #[serde(rename = "pendingReplicationCount")]
    pending_count: u64,
    #[serde(rename = "failedReplicationCount")]
    failed_count: u64,
}

/// `madmin.TimedErrStats`.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct TimedStats {
    last_minute: Counted,
    last_hour: Counted,
    totals: Counted,
}

/// `madmin.RStat`.
#[derive(Debug, Default, Serialize)]
struct Counted {
    count: f64,
    bytes: u64,
}

/// `MinIO`'s `InQueueMetric`: its server writes the most as `max`, which minio-go (and so
/// `mc`) reads as `peak`, so both are written.
#[derive(Debug, Default, Serialize)]
struct Queued {
    curr: QueueStat,
    avg: QueueStat,
    max: QueueStat,
    peak: QueueStat,
}

/// `MinIO`'s `QStat`.
#[derive(Debug, Default, Serialize)]
struct QueueStat {
    count: f64,
    bytes: f64,
}

/// `MinIO`'s `ReplicationQueueStats`: one node, this server.
#[derive(Debug, Serialize)]
struct QueueStats {
    nodes: [Node; 1],
    uptime: u64,
}

/// `MinIO`'s `ReplQNodeStats`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    #[serde(rename = "nodeName")]
    name: String,
    uptime: u64,
    active_workers: Workers,
    #[serde(rename = "transferSummary")]
    transfers: BTreeMap<&'static str, Transfer>,
    #[serde(rename = "tgtTransferStats")]
    target_transfers: BTreeMap<String, BTreeMap<&'static str, Transfer>>,
    queue_stats: Queued,
    mrf_stats: Mrf,
}

/// `MinIO`'s `ActiveWorkerStat`: TeiFS replicates with one worker.
#[derive(Debug, Serialize)]
struct Workers {
    curr: u32,
    avg: f32,
    max: u32,
}

/// `MinIO`'s `XferStats`.
#[derive(Debug, Default, Clone, Copy, Serialize)]
struct Transfer {
    #[serde(rename = "currRate")]
    now: f64,
    #[serde(rename = "avgRate")]
    average: f64,
    #[serde(rename = "peakRate")]
    peak: f64,
    n: u64,
}

/// `MinIO`'s `ReplicationMRFStats`: TeiFS keeps what waits with each version, so
/// nothing is dropped.
#[derive(Debug, Default, Serialize)]
struct Mrf {
    #[serde(rename = "failedCount_last5min")]
    failed_last_5_minutes: u64,
    #[serde(rename = "droppedCount_since_uptime")]
    dropped_count: u64,
    #[serde(rename = "droppedBytes_since_uptime")]
    dropped_bytes: u64,
}

/// `MinIO`'s `ProxyMetric`: TeiFS doesn't proxy reads to targets.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Proxy {
    put_tagging_proxy_total: u64,
    get_tagging_proxy_total: u64,
    remove_tagging_proxy_total: u64,
    get_proxy_total: u64,
    head_proxy_total: u64,
    put_tagging_proxy_failed: u64,
    get_tagging_proxy_failed: u64,
    remove_tagging_proxy_failed: u64,
    get_proxy_failed: u64,
    head_proxy_failed: u64,
}

impl From<Timed> for TimedStats {
    fn from(timed: Timed) -> Self {
        let counted = |(count, bytes): (u64, u64)| Counted {
            count: float(count),
            bytes,
        };
        Self {
            last_minute: counted(timed.last_minute),
            last_hour: counted(timed.last_hour),
            totals: counted(timed.totals),
        }
    }
}

impl From<Rates> for Transfer {
    fn from(rates: Rates) -> Self {
        Self {
            now: rates.now,
            average: rates.average,
            peak: rates.peak,
            n: rates.transfers,
        }
    }
}

/// A count as `MinIO` writes it (a float).
#[expect(clippy::cast_precision_loss, reason = "MinIO's counts are floats")]
const fn float(n: u64) -> f64 {
    n as f64
}

impl Metrics {
    /// `bucket`'s, from `stats`, for each destination of `config`'s rules; `node` names
    /// the server.
    pub(crate) fn of(stats: &Stats, bucket: &str, config: &ReplicationConfig, node: &str) -> Self {
        let now = Instant::now();
        let found = stats.bucket(bucket);
        let mut targets: BTreeMap<String, Target> = config
            .rules
            .iter()
            .map(|rule| (rule.destination.bucket.clone(), Target::default()))
            .collect();
        for (arn, target) in &found.targets {
            if let Some(slot) = targets.get_mut(arn) {
                *slot = target.clone();
            }
        }
        let uptime = stats.uptime().as_secs();
        Self {
            uptime,
            current: Current::of(&found, &targets, now),
            queue: QueueStats {
                nodes: [Node::of(&found, &targets, (node, uptime), now)],
                uptime,
            },
            proxy: Proxy::default(),
        }
    }
}

impl Current {
    fn of(found: &Bucket, targets: &BTreeMap<String, Target>, now: Instant) -> Self {
        let mut failed = Timed::default();
        let mut current = Self {
            stats: BTreeMap::new(),
            replicated_size: 0,
            replica_size: found.received.1,
            failed: TimedStats::default(),
            replicated_count: 0,
            replica_count: found.received.0,
            queued: Queued::of(found),
            pending_size: found.queued.now.1,
            failed_size: 0,
            pending_count: found.queued.now.0,
            failed_count: 0,
        };
        for (arn, target) in targets {
            let failures = target.failures(now);
            let add = |sum: &mut (u64, u64), (count, bytes): (u64, u64)| {
                *sum = (sum.0 + count, sum.1.saturating_add(bytes));
            };
            add(&mut failed.last_minute, failures.last_minute);
            add(&mut failed.last_hour, failures.last_hour);
            add(&mut failed.totals, failures.totals);
            current.replicated_count += target.replicated.0;
            current.replicated_size = current.replicated_size.saturating_add(target.replicated.1);
            current.failed_count += target.failed.0;
            current.failed_size = current.failed_size.saturating_add(target.failed.1);
            current.stats.insert(
                arn.clone(),
                TargetStats {
                    replicated_size: target.replicated.1,
                    replica_size: 0,
                    failed: failures.into(),
                    replicated_count: target.replicated.0,
                    limit_in_bits: 0,
                    current_bandwidth: target.rates(now).now,
                    pending_size: target.pending.1,
                    failed_size: target.failed.1,
                    pending_count: target.pending.0,
                    failed_count: target.failed.0,
                },
            );
        }
        current.failed = failed.into();
        current
    }
}

impl Queued {
    fn of(found: &Bucket) -> Self {
        let queue = &found.queued;
        Self {
            curr: QueueStat {
                count: float(queue.now.0),
                bytes: float(queue.now.1),
            },
            avg: QueueStat {
                count: queue.average.0,
                bytes: queue.average.1,
            },
            max: QueueStat {
                count: float(queue.most.0),
                bytes: float(queue.most.1),
            },
            peak: QueueStat {
                count: float(queue.most.0),
                bytes: float(queue.most.1),
            },
        }
    }
}

impl Node {
    fn of(
        found: &Bucket,
        targets: &BTreeMap<String, Target>,
        (name, uptime): (&str, u64),
        now: Instant,
    ) -> Self {
        let mut total = Transfer::default();
        let mut target_transfers = BTreeMap::new();
        for (arn, target) in targets {
            let transfer = Transfer::from(target.rates(now));
            total.now += transfer.now;
            total.average += transfer.average;
            total.peak = total.peak.max(transfer.peak);
            total.n += transfer.n;
            target_transfers.insert(arn.clone(), BTreeMap::from([("Total", transfer)]));
        }
        Self {
            name: name.to_owned(),
            uptime,
            active_workers: Workers {
                curr: 1,
                avg: 1.0,
                max: 1,
            },
            transfers: BTreeMap::from([("Total", total)]),
            target_transfers,
            queue_stats: Queued::of(found),
            mrf_stats: Mrf::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use std::time::Duration;

    use teifs_types::replication::{ReplicationDestination, ReplicationFilter, ReplicationRule};

    use super::*;

    fn to(arn: &str) -> ReplicationConfig {
        ReplicationConfig {
            role: String::new(),
            rules: vec![ReplicationRule {
                id: "r".to_owned(),
                priority: Some(1),
                enabled: true,
                filter: ReplicationFilter::All,
                delete_markers: None,
                delete_replication: None,
                existing_objects: None,
                sse_kms_objects: None,
                replica_modifications: None,
                destination: ReplicationDestination {
                    bucket: arn.to_owned(),
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

    #[test]
    fn metrics_are_written_as_minio_writes_them() {
        let stats = Stats::default();
        stats.sent("b", "arn:1", 100, Duration::from_millis(50));
        stats.failed("b", "arn:1", 30, false);
        // A destination the rules no longer name isn't shown.
        stats.sent("b", "arn:gone", 5, Duration::ZERO);
        stats.received("b", 9);
        stats.waiting(
            "b",
            (2, 60),
            &BTreeMap::from([("arn:1".to_owned(), (2, 60))]),
        );
        let metrics = Metrics::of(&stats, "b", &to("arn:1"), "node:9000");
        let json = serde_json::to_value(&metrics).unwrap();
        let current = &json["currStats"];
        let one = &current["Stats"]["arn:1"];
        assert_eq!(one["completedReplicationSize"], 100);
        assert_eq!(one["replicationCount"], 1);
        assert_eq!(one["failed"]["totals"]["count"], 1.0);
        assert_eq!(one["failed"]["lastMinute"]["bytes"], 30);
        assert_eq!(one["pendingReplicationCount"], 2);
        assert!(current["Stats"].get("arn:gone").is_none());
        assert_eq!(current["completedReplicationSize"], 100);
        assert_eq!(current["replicaCount"], 1);
        assert_eq!(current["replicaSize"], 9);
        assert_eq!(current["queued"]["curr"]["count"], 2.0);
        assert_eq!(current["queued"]["max"]["bytes"], 60.0);
        assert_eq!(current["queued"]["peak"]["bytes"], 60.0);
        let node = &json["queueStats"]["nodes"][0];
        assert_eq!(node["nodeName"], "node:9000");
        assert_eq!(node["activeWorkers"]["curr"], 1);
        assert_eq!(
            node["tgtTransferStats"]["arn:1"]["Total"]["peakRate"],
            2000.0
        );
        assert_eq!(node["mrfStats"]["droppedCount_since_uptime"], 0);
        assert_eq!(json["proxyStats"]["getProxyTotal"], 0);

        // Nothing yet: each destination, with nothing done.
        let empty = serde_json::to_value(Metrics::of(&stats, "other", &to("arn:1"), "n")).unwrap();
        assert_eq!(empty["currStats"]["Stats"]["arn:1"]["replicationCount"], 0);
    }
}
