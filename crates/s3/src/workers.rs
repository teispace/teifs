//! The jobs the server runs beside the S3 service: delivering buckets' access logs,
//! making their inventory reports and counting their request metrics.

use std::{sync::Arc, time::Duration};

use teifs_store::Store;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    AccessLogWorker,
    access_log::{AccessLog, Record},
    drive::Drive,
    inventory,
    request_metrics::{self, Done, RequestMetrics},
};

/// The service's background jobs, for the server to run.
#[derive(Debug)]
pub struct Workers {
    pub(crate) access_log: AccessLogWorker,
    pub(crate) inventory: inventory::Worker,
    pub(crate) request_metrics: request_metrics::Worker,
}

impl Workers {
    /// The jobs of a drive: delivering what the access log queues (every `interval`)
    /// and counting the answered requests request metrics queue.
    pub(crate) fn new(
        (drive, store): (&Drive, &Store),
        (records, log, interval): (mpsc::Receiver<Record>, Arc<AccessLog>, Duration),
        (answered, metrics): (mpsc::Receiver<Done>, Arc<RequestMetrics>),
    ) -> Self {
        Self {
            access_log: AccessLogWorker::new(records, log, drive.clone(), store.clone(), interval),
            inventory: inventory::Worker::new(drive.clone(), store.clone()),
            request_metrics: request_metrics::Worker::new(answered, metrics, store.clone()),
        }
    }

    /// Runs every job until `stop`.
    pub async fn run(self, stop: impl Future<Output = ()> + Send) {
        let stopping = CancellationToken::new();
        let stopped = async {
            stop.await;
            stopping.cancel();
        };
        tokio::join!(
            stopped,
            self.access_log.run(stopping.cancelled()),
            self.inventory.run(stopping.clone()),
            self.request_metrics.run(stopping.clone()),
        );
    }
}
