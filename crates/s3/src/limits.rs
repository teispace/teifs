//! Bounds on what one request can make the server hold: its headers' size, user
//! metadata as S3 limits it, and how long its body may stall.

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use http_body::{Body, Frame, SizeHint};
use s3s::{HttpResponse, StdError};
use tokio::time::{Instant, Sleep};

/// The most header bytes (names and values) a request may have; HTTP/2's default limit
/// in hyper, applied to HTTP/1 too.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// The most user metadata (`x-amz-meta-*` names without the prefix, and values) a
/// request may carry, as S3 counts it.
pub const MAX_USER_METADATA_BYTES: usize = 2 * 1024;
const USER_METADATA: &str = "x-amz-meta-";

/// The answer to a request whose headers or user metadata are too large, checked before
/// any of it is looked at; `None` when they're within bounds.
pub(crate) fn refusal(headers: &HeaderMap) -> Option<HttpResponse> {
    let mut total = 0;
    let mut metadata = 0;
    for (name, value) in headers {
        let name = name.as_str();
        total += name.len() + value.len();
        if let Some(key) = name.strip_prefix(USER_METADATA) {
            metadata += key.len() + value.len();
        }
    }
    if total > MAX_HEADER_BYTES {
        return Some(crate::cors::error(
            StatusCode::BAD_REQUEST,
            "RequestHeaderSectionTooLarge",
            "Your request header section exceeds the maximum allowed size.",
        ));
    }
    if metadata > MAX_USER_METADATA_BYTES {
        return Some(crate::cors::error(
            StatusCode::BAD_REQUEST,
            "MetadataTooLarge",
            "Your metadata headers exceed the maximum allowed metadata size.",
        ));
    }
    None
}

/// A request body that stopped arriving.
#[derive(Debug)]
pub(crate) struct BodyStalled(Duration);

impl fmt::Display for BodyStalled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the client sent no body for {:?}", self.0)
    }
}

impl std::error::Error for BodyStalled {}

/// Whether `err`, or anything it wraps, is a stalled body.
pub(crate) fn is_stalled(err: &(dyn std::error::Error + 'static)) -> bool {
    std::iter::successors(Some(err), |e| e.source()).any(<dyn std::error::Error>::is::<BodyStalled>)
}

/// A body that fails with [`BodyStalled`] once the server has waited `timeout` for its
/// next bytes. Only time spent waiting on the client counts: a server busy elsewhere
/// before reading on doesn't time the client out.
pub(crate) struct StallTimeout<B> {
    body: B,
    timeout: Duration,
    /// When waiting for the client runs out (made on the first wait).
    deadline: Option<Pin<Box<Sleep>>>,
    /// Whether the last poll found nothing: the deadline is running.
    waiting: bool,
}

impl<B> StallTimeout<B> {
    pub(crate) fn new(body: B, timeout: Duration) -> Self {
        Self {
            body,
            timeout,
            deadline: None,
            waiting: false,
        }
    }
}

impl<B> Body for StallTimeout<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<StdError>,
{
    type Data = Bytes;
    type Error = StdError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, StdError>>> {
        let this = &mut *self;
        if let Poll::Ready(frame) = Pin::new(&mut this.body).poll_frame(cx) {
            this.waiting = false;
            return Poll::Ready(frame.map(|frame| frame.map_err(Into::into)));
        }
        let deadline = Instant::now() + this.timeout;
        let sleep = match &mut this.deadline {
            Some(sleep) => {
                if !this.waiting {
                    sleep.as_mut().reset(deadline);
                }
                sleep
            }
            None => this
                .deadline
                .insert(Box::pin(tokio::time::sleep_until(deadline))),
        };
        this.waiting = true;
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Some(Err(Box::new(BodyStalled(this.timeout))))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use http_body_util::{BodyExt, StreamBody};

    fn headers(pairs: &[(&str, String)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn code(headers: &HeaderMap) -> Option<StatusCode> {
        refusal(headers).map(|r| r.status())
    }

    #[test]
    fn user_metadata_is_limited_to_2_kib_as_s3_counts_it() {
        // Key "k" (1 byte) + 2047-byte value: exactly 2 KiB.
        let at_limit = headers(&[("x-amz-meta-k", "v".repeat(2047))]);
        assert_eq!(code(&at_limit), None);
        let over = headers(&[("x-amz-meta-k", "v".repeat(2048))]);
        assert_eq!(code(&over), Some(StatusCode::BAD_REQUEST));
        // Spread over many keys, it still adds up.
        let many: Vec<_> = (0..30)
            .map(|i| (format!("x-amz-meta-key{i:02}"), "v".repeat(64)))
            .collect();
        let many: Vec<_> = many.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        assert!(code(&headers(&many)).is_some());
        // Other headers don't count as metadata.
        let other = headers(&[("x-amz-tagging", "t".repeat(4000))]);
        assert_eq!(code(&other), None);
    }

    #[test]
    fn header_sections_over_16_kib_are_refused() {
        let big = headers(&[("x-big", "b".repeat(MAX_HEADER_BYTES))]);
        assert_eq!(code(&big), Some(StatusCode::BAD_REQUEST));
        let fine = headers(&[("x-fine", "b".repeat(8000))]);
        assert_eq!(code(&fine), None);
    }

    type Chunk = Result<Frame<Bytes>, std::io::Error>;

    fn channel() -> (
        tokio::sync::mpsc::Sender<Chunk>,
        StallTimeout<StreamBody<chan::Receiver<Chunk>>>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let body = StreamBody::new(chan::Receiver(rx));
        (tx, StallTimeout::new(body, Duration::from_secs(10)))
    }

    /// A minimal stream over a Tokio channel.
    mod chan {
        use std::{
            pin::Pin,
            task::{Context, Poll},
        };

        pub struct Receiver<T>(pub tokio::sync::mpsc::Receiver<T>);

        impl<T> futures::Stream for Receiver<T> {
            type Item = T;
            fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
                self.0.poll_recv(cx)
            }
        }
    }

    fn data(bytes: &'static [u8]) -> Frame<Bytes> {
        Frame::data(Bytes::from_static(bytes))
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_keeps_coming_never_times_out() {
        let (tx, mut body) = channel();
        tokio::spawn(async move {
            for _ in 0..5 {
                tokio::time::sleep(Duration::from_secs(9)).await;
                tx.send(Ok(data(b"x"))).await.unwrap();
            }
        });
        let bytes = (&mut body).collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"xxxxx");
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_stops_fails_as_stalled() {
        let (tx, mut body) = channel();
        tx.send(Ok(data(b"start"))).await.unwrap();
        let first = body.frame().await.unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), "start");
        let started = Instant::now();
        let err = body.frame().await.unwrap().unwrap_err();
        assert!(is_stalled(&*err), "{err}");
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        drop(tx);
    }

    #[tokio::test(start_paused = true)]
    async fn time_the_server_spends_before_reading_isnt_the_clients() {
        let (tx, mut body) = channel();
        tx.send(Ok(data(b"ready"))).await.unwrap();
        // The server is busy for longer than the timeout before it reads.
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "ready"
        );
        drop(tx);
        assert!(body.frame().await.is_none());
    }
}
