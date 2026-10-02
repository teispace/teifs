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

/// A body of the documents `document` makes, the first at once and then one every
/// `every`, `times` times (none: until the client leaves) or until `stopping` is
/// cancelled. `document` is told whether it makes the last one.
pub(crate) fn every<F>(
    stopping: CancellationToken,
    every: Duration,
    times: Option<u64>,
    mut document: F,
) -> Body
where
    F: FnMut(bool) -> Bytes + Send + 'static,
{
    let (lines, out) = mpsc::channel(4);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        let mut made = 0_u64;
        loop {
            tokio::select! {
                () = stopping.cancelled() => break,
                () = lines.closed() => break,
                _ = tick.tick() => {}
            }
            made += 1;
            let last = times.is_some_and(|times| made >= times);
            if lines.send(document(last)).await.is_err() || last {
                break;
            }
        }
    });
    Body::from(StreamingBlob::wrap(Lines(out)))
}

/// What `lines` receives, as a body.
pub(crate) fn body(lines: mpsc::Receiver<Bytes>) -> Body {
    Body::from(StreamingBlob::wrap(Lines(lines)))
}

/// The lines, as a body.
struct Lines(mpsc::Receiver<Bytes>);

impl Stream for Lines {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|line| line.map(Ok))
    }
}
