//! Answers that last: lines sent as things happen (live traces, listened-to events),
//! until the client leaves or the server stops.
//!
//! Each client reads from a queue of its own: one that falls behind skips lines rather
//! than slow requests down. A heartbeat every so often keeps proxies from closing a
//! quiet answer.

use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures::Stream;
use s3s::{Body, dto::StreamingBlob};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// How often a quiet answer sends its heartbeat, unless it asks otherwise.
pub(crate) const HEARTBEAT: Duration = Duration::from_secs(10);

/// A body of the lines `line` makes of what `happenings` receives (none: skipped), with
/// `heartbeat` every `every` in between, until the client leaves or `stopping` is
/// cancelled.
pub(crate) fn follow<T, F>(
    happenings: broadcast::Receiver<T>,
    stopping: CancellationToken,
    heartbeat: (Duration, &'static [u8]),
    line: F,
) -> Body
where
    T: Clone + Send + 'static,
    F: FnMut(T) -> Option<Bytes> + Send + 'static,
{
    follow_after(Vec::new(), happenings, stopping, heartbeat, line)
}

/// [`follow`], sending `first` before anything that happens.
pub(crate) fn follow_after<T, F>(
    first: Vec<Bytes>,
    mut happenings: broadcast::Receiver<T>,
    stopping: CancellationToken,
    (every, heartbeat): (Duration, &'static [u8]),
    mut line: F,
) -> Body
where
    T: Clone + Send + 'static,
    F: FnMut(T) -> Option<Bytes> + Send + 'static,
{
    let (lines, out) = mpsc::channel(64);
    tokio::spawn(async move {
        for next in first {
            if lines.send(next).await.is_err() {
                return;
            }
        }
        let mut beat = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        loop {
            let next = tokio::select! {
                () = stopping.cancelled() => break,
                () = lines.closed() => break,
                _ = beat.tick() => Bytes::from_static(heartbeat),
                happened = happenings.recv() => match happened {
                    Ok(happened) => match line(happened) {
                        Some(next) => next,
                        None => continue,
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            };
            if lines.send(next).await.is_err() {
                break;
            }
        }
    });
    Body::from(StreamingBlob::wrap(Lines(out)))
}

/// The lines, as a body.
struct Lines(mpsc::Receiver<Bytes>);

impl Stream for Lines {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|line| line.map(Ok))
    }
}
