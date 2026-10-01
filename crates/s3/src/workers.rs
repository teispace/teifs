//! The jobs the server runs beside the S3 service: delivering buckets' access logs and
//! making their inventory reports.

use tokio_util::sync::CancellationToken;

use crate::{AccessLogWorker, inventory};

/// The service's background jobs, for the server to run.
#[derive(Debug)]
pub struct Workers {
    pub(crate) access_log: AccessLogWorker,
    pub(crate) inventory: inventory::Worker,
}

impl Workers {
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
        );
    }
}
