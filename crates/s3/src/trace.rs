//! Live traces (`GET /.teifs/admin/v1/trace`, `teifs admin trace`): each request the
//! server answers, as the audit entry it makes, to whoever is watching, as it happens.
//! Entries are made only while an audit log is kept or someone watches, and each
//! watcher's filter is applied on the server, so a narrow trace costs little.
//!
//! A watcher reads JSON lines from a queue of its own: one that falls behind skips
//! entries rather than slow requests down. An empty line every few seconds keeps
//! proxies from closing a quiet trace, and every trace ends when the server stops.

use std::{
    convert::Infallible,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures::Stream;
use s3s::{Body, dto::StreamingBlob};
use teifs_types::audit::{AuditEntry, TraceFilter};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// How many entries wait for the slowest watcher before it skips some.
const BACKLOG: usize = 4096;
/// How often a quiet trace sends an empty line.
const HEARTBEAT: Duration = Duration::from_secs(10);

/// Everyone watching the requests.
#[derive(Debug)]
pub(crate) struct Tracers {
    entries: broadcast::Sender<Arc<AuditEntry>>,
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
    pub(crate) fn show(&self, entry: &AuditEntry) {
        if self.watched() {
            let _ = self.entries.send(Arc::new(entry.clone()));
        }
    }

    /// Cancelled when the server stops, which ends every trace.
    pub(crate) fn stopping(&self) -> CancellationToken {
        self.stopping.clone()
    }

    /// A trace: the entries `filter` shows, as JSON lines, until the watcher leaves or
    /// the server stops.
    pub(crate) fn follow(&self, filter: TraceFilter) -> Body {
        let mut entries = self.entries.subscribe();
        let stopping = self.stopping.clone();
        let (lines, out) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut beat =
                tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT, HEARTBEAT);
            loop {
                let line = tokio::select! {
                    () = stopping.cancelled() => break,
                    () = lines.closed() => break,
                    _ = beat.tick() => Bytes::from_static(b"\n"),
                    entry = entries.recv() => match entry {
                        Ok(entry) if filter.matches(&entry) => {
                            let mut line = serde_json::to_vec(&*entry)
                                .expect("an audit entry serializes");
                            line.push(b'\n');
                            Bytes::from(line)
                        }
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                };
                if lines.send(line).await.is_err() {
                    break;
                }
            }
        });
        Body::from(StreamingBlob::wrap(Lines(out)))
    }
}

/// A trace's lines, as a body.
struct Lines(mpsc::Receiver<Bytes>);

impl Stream for Lines {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|line| line.map(Ok))
    }
}

#[cfg(test)]
mod tests {
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
