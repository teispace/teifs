//! What each request did, seen from around the whole service: an id for it (in
//! `x-amz-request-id` and error bodies, as S3 answers), the operation it turned out to
//! be, the bytes it moved and how long it took. The metrics record it once its answer is
//! sent, or abandoned by the client.

use std::{
    collections::BTreeSet,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use s3s::{HttpResponse, StdError};

use crate::metrics::Metrics;

/// The operation of a request no hook saw: refused before its signature was accepted.
pub(crate) const UNKNOWN: &str = "unknown";

/// What's learnt about a request while it's served, shared through its extensions.
#[derive(Debug)]
pub(crate) struct Seen {
    /// Its id.
    pub(crate) id: String,
    operation: OnceLock<&'static str>,
    received: AtomicU64,
}

impl Seen {
    pub(crate) fn new() -> Self {
        Self {
            id: next_id(),
            operation: OnceLock::new(),
            received: AtomicU64::new(0),
        }
    }

    /// Names the operation; the first name given wins.
    pub(crate) fn name(&self, operation: &'static str) {
        let _ = self.operation.set(operation);
    }

    /// The operation: the first name given, else [`UNKNOWN`].
    pub(crate) fn operation(&self) -> &'static str {
        self.operation.get().copied().unwrap_or(UNKNOWN)
    }
}

/// Names the operation of the request with these extensions; the first name wins.
pub(crate) fn name(extensions: &http::Extensions, operation: &'static str) {
    if let Some(seen) = extensions.get::<Arc<Seen>>() {
        seen.name(operation);
    }
}

/// An S3 operation's name, kept for ever: s3s holds its names for ever too but lends
/// them out for less. Only s3s's own names come here, so the set is small and bounded.
pub(crate) fn intern(name: &str) -> &'static str {
    static NAMES: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());
    let mut names = NAMES.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(kept) = names.get(name) {
        return kept;
    }
    let kept: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.insert(kept);
    kept
}

/// The id of the request with these extensions: a new one for a request served without
/// the observer (in tests).
pub(crate) fn request_id(extensions: &http::Extensions) -> String {
    extensions
        .get::<Arc<Seen>>()
        .map_or_else(next_id, |seen| seen.id.clone())
}

/// A request id: 16 upper-case hex digits, as S3's, from the time in nanoseconds and
/// always greater than the last, so no two are the same.
fn next_id() -> String {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    let previous = LAST
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            Some(now.max(last.saturating_add(1)))
        })
        .unwrap_or_else(|last| last);
    format!("{:016X}", now.max(previous.saturating_add(1)))
}

/// A request body that counts the bytes read from it.
pub(crate) struct Received<B> {
    body: B,
    seen: Arc<Seen>,
}

impl<B> Received<B> {
    pub(crate) const fn new(body: B, seen: Arc<Seen>) -> Self {
        Self { body, seen }
    }
}

impl<B: Body<Data = Bytes> + Unpin> Body for Received<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let poll = Pin::new(&mut self.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll
            && let Some(data) = frame.data_ref()
        {
            self.seen
                .received
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// A request being served: counted in flight until it's dropped, and as canceled if
/// that's before its answer was done with.
#[derive(Debug)]
pub(crate) struct Request {
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) seen: Arc<Seen>,
    pub(crate) started: Instant,
    done: bool,
}

impl Request {
    pub(crate) fn new(metrics: Arc<Metrics>, seen: Arc<Seen>) -> Self {
        metrics.begin();
        Self {
            metrics,
            seen,
            started: Instant::now(),
            done: false,
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.metrics.end(self.seen.operation(), !self.done);
    }
}

/// What a request came to, recorded when its answer's body is done with.
#[derive(Debug)]
pub(crate) struct Outcome {
    pub(crate) request: Request,
    pub(crate) status: StatusCode,
    /// The S3 error code of an error answer, when its body names one.
    pub(crate) error: Option<String>,
    /// Until the answer's headers were ready.
    pub(crate) first_byte: Duration,
    /// Until its body was done with.
    pub(crate) duration: Duration,
    pub(crate) received: u64,
    pub(crate) sent: u64,
    /// Whether the client left before the whole answer was sent.
    pub(crate) canceled: bool,
}

/// An answer's body that counts the bytes sent and records the request when it's
/// dropped: after its last byte, or early when the client goes away.
struct Sent {
    body: s3s::Body,
    outcome: Option<Outcome>,
    /// The body's length, when it's known up front.
    length: Option<u64>,
    /// Whether the body said it had nothing more.
    ended: bool,
}

impl Body for Sent {
    type Data = Bytes;
    type Error = StdError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, StdError>>> {
        let poll = Pin::new(&mut self.body).poll_frame(cx);
        match &poll {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Some(outcome) = &mut self.outcome
                {
                    outcome.sent += data.len() as u64;
                }
            }
            Poll::Ready(None) => self.ended = true,
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl Drop for Sent {
    fn drop(&mut self) {
        if let Some(mut outcome) = self.outcome.take() {
            outcome.request.done = true;
            // A server that knows the length stops reading at it, before the body says
            // it has ended.
            let whole =
                self.ended || self.body.is_end_stream() || self.length == Some(outcome.sent);
            outcome.canceled = !whole;
            outcome.duration = outcome.request.started.elapsed();
            outcome.received = outcome.request.seen.received.load(Ordering::Relaxed);
            outcome.request.metrics.record(&outcome);
        }
    }
}

/// Gives an answer its request id (headers, and the body of an error that has none)
/// and records the request once the answer's body is done with.
pub(crate) fn finish(mut response: HttpResponse, request: Request) -> HttpResponse {
    let status = response.status();
    let id = &request.seen.id;
    let error = (status.is_client_error() || status.is_server_error() || status.is_redirection())
        .then(|| error_code(&mut response, id))
        .flatten();
    if let Ok(id) = HeaderValue::from_str(id) {
        response
            .headers_mut()
            .entry("x-amz-request-id")
            .or_insert(id);
    }
    let outcome = Outcome {
        first_byte: request.started.elapsed(),
        request,
        status,
        error,
        duration: Duration::ZERO,
        received: 0,
        sent: 0,
        canceled: false,
    };
    let length = response.body().size_hint().exact().or_else(|| {
        response
            .headers()
            .get(header::CONTENT_LENGTH)?
            .to_str()
            .ok()?
            .parse()
            .ok()
    });
    response.map(|body| {
        s3s::Body::http_body(Sent {
            body,
            outcome: Some(outcome),
            length,
            ended: false,
        })
    })
}

/// The error code an error answer's body names (S3's XML, or the admin API's JSON),
/// adding `<RequestId>` to an S3 error body that has none, as S3's have.
fn error_code(response: &mut HttpResponse, id: &str) -> Option<String> {
    let bytes = response.body().bytes()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    if text.trim_start().starts_with('{') {
        let json: serde_json::Value = serde_json::from_str(text).ok()?;
        return json.get("code")?.as_str().map(str::to_owned);
    }
    let code = between(text, "<Code>", "</Code>")?.to_owned();
    if !text.contains("<RequestId>")
        && let Some(end) = text.rfind("</Error>")
    {
        let body = format!(
            "{}<RequestId>{id}</RequestId>{}",
            &text[..end],
            &text[end..]
        );
        let headers = response.headers_mut();
        if headers.contains_key(header::CONTENT_LENGTH) {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        }
        *response.body_mut() = s3s::Body::from(body);
    }
    Some(code)
}

/// The text between the first `start` and the `end` after it.
fn between<'t>(text: &'t str, start: &str, end: &str) -> Option<&'t str> {
    let from = text.find(start)? + start.len();
    let len = text[from..].find(end)?;
    Some(&text[from..from + len])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    #[test]
    fn request_ids_are_unique_and_shaped_as_s3s() {
        let ids: Vec<String> = (0..1000).map(|_| next_id()).collect();
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(ids.iter().all(|id| {
            id.len() == 16
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        }));
    }

    #[test]
    fn names_are_kept_once() {
        let name = String::from("GetObject");
        assert!(std::ptr::eq(intern(&name), intern("GetObject")));
    }

    #[test]
    fn the_first_name_given_is_the_operation() {
        let mut extensions = http::Extensions::new();
        name(&extensions, "ignored: nothing observes it");
        let seen = Arc::new(Seen::new());
        extensions.insert(Arc::clone(&seen));
        assert_eq!(seen.operation(), UNKNOWN);
        name(&extensions, "PutObject");
        name(&extensions, "Admin");
        assert_eq!(seen.operation(), "PutObject");
        assert_eq!(request_id(&extensions), seen.id);
    }

    fn answer(status: StatusCode, body: &str) -> HttpResponse {
        let mut response = HttpResponse::new(s3s::Body::from(body.to_owned()));
        *response.status_mut() = status;
        response
    }

    #[test]
    fn error_bodies_get_the_request_id_and_name_their_code() {
        let mut response = answer(
            StatusCode::NOT_FOUND,
            "<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code><Message>m</Message></Error>",
        );
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(1));
        assert_eq!(
            error_code(&mut response, "ID").as_deref(),
            Some("NoSuchKey")
        );
        let body = response.body().bytes().unwrap();
        assert_eq!(
            &body[..],
            b"<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code><Message>m</Message>\
              <RequestId>ID</RequestId></Error>"
        );
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            body.len().to_string()
        );
        // One that has its id already keeps it; the admin API's JSON names its code.
        let kept =
            "<ErrorResponse><Error><Code>X</Code></Error><RequestId>A</RequestId></ErrorResponse>";
        let mut response = answer(StatusCode::FORBIDDEN, kept);
        assert_eq!(error_code(&mut response, "B").as_deref(), Some("X"));
        assert_eq!(&response.body().bytes().unwrap()[..], kept.as_bytes());
        let mut json = answer(StatusCode::CONFLICT, r#"{"code":"Busy","message":"m"}"#);
        assert_eq!(error_code(&mut json, "ID").as_deref(), Some("Busy"));
        assert_eq!(
            error_code(&mut answer(StatusCode::NOT_FOUND, ""), "ID"),
            None
        );
    }
}
