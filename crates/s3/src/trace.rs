//! Live traces (`GET /.teifs/admin/v1/trace`, `teifs admin trace`): each request the
//! server answers, as the audit entry it makes, to whoever is watching, as it happens.
//! Entries are made only while an audit log is kept or someone watches, and each
//! watcher's filter is applied on the server, so a narrow trace costs little.
//!
//! A watcher reads JSON lines ([`crate::lines`]) and every trace ends when the server
//! stops.

use std::sync::Arc;

use bytes::Bytes;
use s3s::Body;
use teifs_types::audit::{AuditEntry, TraceFilter};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::lines;

/// How many entries wait for the slowest watcher before it skips some.
const BACKLOG: usize = 4096;

/// A request that was answered: its audit entry, and its method, which `MinIO`'s trace
/// tells and the entry doesn't.
#[derive(Debug)]
pub(crate) struct Traced {
    pub(crate) entry: AuditEntry,
    pub(crate) method: String,
}

/// Everyone watching the requests.
#[derive(Debug)]
pub(crate) struct Tracers {
    entries: broadcast::Sender<Arc<Traced>>,
    stopping: CancellationToken,
}

impl Tracers {
    pub(crate) fn new() -> Self {
        Self {
            entries: broadcast::channel(BACKLOG).0,
            stopping: CancellationToken::new(),
        }
    }

    /// Whether anyone is watching.
    pub(crate) fn watched(&self) -> bool {
        self.entries.receiver_count() > 0
    }

    /// Shows `entry` to whoever is watching.
    pub(crate) fn show(&self, entry: &AuditEntry, method: Option<&http::Method>) {
        if self.watched() {
            let _ = self.entries.send(Arc::new(Traced {
                entry: entry.clone(),
                method: method.map(ToString::to_string).unwrap_or_default(),
            }));
        }
    }

    /// Cancelled when the server stops, which ends every trace.
    pub(crate) fn stopping(&self) -> CancellationToken {
        self.stopping.clone()
    }

    /// A trace: the entries `filter` shows, as JSON lines, until the watcher leaves or
    /// the server stops.
    pub(crate) fn follow(&self, filter: TraceFilter) -> Body {
        self.follow_with((lines::HEARTBEAT, b"\n"), move |traced: Arc<Traced>| {
            filter.matches(&traced.entry).then(|| {
                let mut line =
                    serde_json::to_vec(&traced.entry).expect("an audit entry serializes");
                line.push(b'\n');
                Bytes::from(line)
            })
        })
    }

    /// A trace of the lines `line` makes (none: skipped), with `heartbeat` every so
    /// often, until the watcher leaves or the server stops.
    pub(crate) fn follow_with<F>(
        &self,
        heartbeat: (std::time::Duration, &'static [u8]),
        line: F,
    ) -> Body
    where
        F: FnMut(Arc<Traced>) -> Option<Bytes> + Send + 'static,
    {
        lines::follow(
            self.entries.subscribe(),
            self.stopping.clone(),
            heartbeat,
            line,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn filters_the_server_cant_read_are_refused() {
        let tracers = Tracers::new();
        let err = crate::admin::trace(&tracers, Some("method=GET")).unwrap_err();
        assert_eq!(err.status_code(), Some(http::StatusCode::BAD_REQUEST));
        assert!(!tracers.watched(), "nobody watches a refused trace");
    }

    #[tokio::test]
    async fn only_a_watched_server_makes_entries_for_the_trace() {
        let tracers = Tracers::new();
        assert!(!tracers.watched());
        let body = tracers.follow(TraceFilter::default());
        assert!(tracers.watched());
        drop(body);
        // The watcher's task notices it's gone and stops watching.
        for _ in 0..100 {
            if !tracers.watched() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("still watched after the trace was dropped");
    }
}
