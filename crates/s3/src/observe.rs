//! What each request did, seen from around the whole service: an id for it (in
//! `x-amz-request-id` and error bodies, as S3 answers), the operation it turned out to
//! be, who asked it of what, the bytes it moved and how long it took. The metrics (and
//! the audit log, if one is kept) record it once its answer is sent, or abandoned by the
//! client.

use std::{
    collections::BTreeSet,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use s3s::{HttpResponse, StdError};

use crate::{
    access_log::{AccessLog, Also, Arrival},
    audit::{self, Asked, AuditSink},
    metrics::{Metrics, Scrapers},
    trace::Tracers,
};

/// The operation of a request no hook saw: refused before its signature was accepted.
pub(crate) const UNKNOWN: &str = "unknown";

/// What's learnt about a request while it's served, shared through its extensions.
#[derive(Debug)]
pub(crate) struct Seen {
    /// Its id.
    pub(crate) id: String,
    operation: OnceLock<&'static str>,
    kind: OnceLock<&'static str>,
    access_key: OnceLock<String>,
    /// The bucket and key it's on.
    target: OnceLock<(String, String)>,
    received: AtomicU64,
    /// What wasn't read of its body, if anything.
    leftover: Mutex<Option<Incoming>>,
    /// Who asked, as access log records name them.
    requester: OnceLock<String>,
    /// How it was signed: `SigV4`/`SigV2`, and `AuthHeader`/`QueryString`.
    signature: OnceLock<(&'static str, &'static str)>,
    /// Whether an ACL was what allowed it.
    acl_required: AtomicBool,
    /// The access log records it adds to its own.
    also: Mutex<Vec<Also>>,
}

impl Seen {
    pub(crate) fn new() -> Self {
        Self {
            id: next_id(),
            operation: OnceLock::new(),
            kind: OnceLock::new(),
            access_key: OnceLock::new(),
            target: OnceLock::new(),
            received: AtomicU64::new(0),
            leftover: Mutex::new(None),
            requester: OnceLock::new(),
            signature: OnceLock::new(),
            acl_required: AtomicBool::new(false),
            also: Mutex::new(Vec::new()),
        }
    }

    /// Records who asked (an IAM ARN, or the owner's canonical id for the root user).
    pub(crate) fn requester_is(&self, requester: String) {
        let _ = self.requester.set(requester);
    }

    pub(crate) fn requester(&self) -> Option<&str> {
        self.requester.get().map(String::as_str)
    }

    /// Records how it was signed.
    pub(crate) fn signed_with(&self, version: &'static str, auth: &'static str) {
        let _ = self.signature.set((version, auth));
    }

    pub(crate) fn signature(&self) -> Option<(&'static str, &'static str)> {
        self.signature.get().copied()
    }

    /// Records that an ACL was what allowed it.
    pub(crate) fn allowed_by_acl(&self) {
        self.acl_required.store(true, Ordering::Relaxed);
    }

    pub(crate) fn acl_required(&self) -> bool {
        self.acl_required.load(Ordering::Relaxed)
    }

    /// Adds an access log record to its own.
    pub(crate) fn add(&self, also: Also) {
        self.also
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(also);
    }

    pub(crate) fn also(&self) -> Vec<Also> {
        std::mem::take(&mut *self.also.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Says which API it's for, when not S3's: `Admin`, `IAM`, `STS` or `Control`.
    pub(crate) fn api(&self, kind: &'static str) {
        let _ = self.kind.set(kind);
    }

    /// Its API: `S3` unless said otherwise.
    pub(crate) fn kind(&self) -> &'static str {
        self.kind.get().copied().unwrap_or("S3")
    }

    /// Records the access key it was signed with.
    pub(crate) fn signed_by(&self, access_key: &str) {
        let _ = self.access_key.set(access_key.to_owned());
    }

    pub(crate) fn access_key(&self) -> Option<&str> {
        self.access_key.get().map(String::as_str)
    }

    /// Records the bucket and key (empty for none) it's on.
    pub(crate) fn on(&self, bucket: &str, key: &str) {
        let _ = self.target.set((bucket.to_owned(), key.to_owned()));
    }

    pub(crate) fn target(&self) -> Option<(String, String)> {
        self.target.get().cloned()
    }

    /// Request body bytes read so far.
    pub(crate) fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
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

/// Adds an access log record to the request with these extensions' own.
pub(crate) fn also(extensions: &http::Extensions, also: Also) {
    if let Some(seen) = extensions.get::<Arc<Seen>>() {
        seen.add(also);
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

/// An id for what no request did (a lifecycle rule's removal), ordered with requests'.
pub(crate) fn new_id() -> String {
    next_id()
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

/// A request body that counts the bytes read from it, and leaves what wasn't read
/// with the request's [`Seen`], for [`drain`].
pub(crate) struct Received {
    body: Option<Incoming>,
    seen: Arc<Seen>,
}

impl Received {
    pub(crate) const fn new(body: Incoming, seen: Arc<Seen>) -> Self {
        Self {
            body: Some(body),
            seen,
        }
    }
}

impl Body for Received {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let Some(body) = self.body.as_mut() else {
            return Poll::Ready(None);
        };
        let poll = Pin::new(body).poll_frame(cx);
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
        self.body.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        self.body
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), Body::size_hint)
    }
}

impl Drop for Received {
    fn drop(&mut self) {
        if let Some(body) = self.body.take()
            && !body.is_end_stream()
        {
            *self
                .seen
                .leftover
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(body);
        }
    }
}

/// The most of a body left unread (by a request refused before its body mattered)
/// that's read and thrown away before the answer, so the client gets to read the answer.
const DRAIN_LIMIT: u64 = 1024 * 1024;
/// How long that may take.
const DRAIN_TIME: Duration = Duration::from_secs(2);

/// Reads and throws away what's left of a request's body, up to [`DRAIN_LIMIT`]. A
/// server that answers without reading a body and then closes the connection makes
/// the client's write of it fail, and the client never reads the answer (the refusal
/// of an upload, say): a client still sending a small body can read the answer once
/// it's done. A larger body's client gets the connection closed.
pub(crate) async fn drain(seen: &Seen) {
    let Some(mut body) = seen
        .leftover
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    else {
        return;
    };
    let read = async {
        let mut read = 0;
        while read < DRAIN_LIMIT {
            match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                Some(Ok(frame)) => read += frame.data_ref().map_or(0, |d| d.len() as u64),
                Some(Err(_)) | None => break,
            }
        }
    };
    let _ = tokio::time::timeout(DRAIN_TIME, read).await;
}

/// What watches requests: the metrics, and the audit log if one is kept.
#[derive(Debug)]
pub(crate) struct Watch {
    pub(crate) metrics: Metrics,
    /// Who may read the metrics.
    pub(crate) scrapers: Scrapers,
    audit: Option<Arc<dyn AuditSink>>,
    /// Whoever watches live traces.
    pub(crate) tracers: Arc<Tracers>,
    /// The drive's id, which audit entries carry.
    drive: String,
    /// Where requests' access log records go.
    pub(crate) access_log: Arc<AccessLog>,
}

impl Watch {
    pub(crate) fn new(
        metrics: Metrics,
        scrapers: Scrapers,
        audit: Option<Arc<dyn AuditSink>>,
        tracers: Arc<Tracers>,
        drive: String,
        access_log: Arc<AccessLog>,
    ) -> Self {
        Self {
            metrics,
            scrapers,
            audit,
            tracers,
            drive,
            access_log,
        }
    }

    /// Whether requests are audited or traced, so what they asked is worth keeping.
    pub(crate) fn audits(&self) -> bool {
        self.audit.is_some() || self.tracers.watched()
    }

    /// Records a request that's done: its metrics were, this is the rest.
    fn done(
        &self,
        (asked, arrival): (Option<Asked>, Option<Arrival>),
        seen: &Seen,
        answer: &Answer,
        headers: &HeaderMap,
    ) {
        if let Some(arrival) = arrival {
            arrival.finish(seen, answer, &self.access_log);
        }
        self.audit(asked, seen, answer, headers);
    }

    fn audit(&self, asked: Option<Asked>, seen: &Seen, answer: &Answer, headers: &HeaderMap) {
        let Some(asked) = asked else { return };
        let entry = audit::entry(&self.drive, asked, seen, answer, headers);
        self.tracers.show(&entry);
        if let Some(sink) = &self.audit
            && !sink.log(entry)
        {
            self.metrics.audit_dropped();
        }
    }
}

/// The status recorded for a request whose client left before it was answered (nginx's).
pub(crate) const CLIENT_LEFT: u16 = 499;

/// A request being served: counted in flight until it's dropped, and recorded then as
/// the client's leaving if that's before it was answered.
#[derive(Debug)]
pub(crate) struct Request {
    watch: Arc<Watch>,
    pub(crate) seen: Arc<Seen>,
    started: Instant,
    /// What it asked, while it's audited.
    asked: Option<Asked>,
    /// What it was, while requests are access logged.
    arrival: Option<Arrival>,
    answered: bool,
}

impl Request {
    pub(crate) fn new(
        watch: Arc<Watch>,
        seen: Arc<Seen>,
        asked: Option<Asked>,
        arrival: Option<Arrival>,
    ) -> Self {
        watch.metrics.begin();
        Self {
            watch,
            seen,
            started: Instant::now(),
            asked,
            arrival,
            answered: false,
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.watch
            .metrics
            .end(self.seen.operation(), !self.answered);
        if !self.answered {
            let answer = Answer {
                status: StatusCode::from_u16(CLIENT_LEFT).expect("a valid status"),
                duration: self.started.elapsed(),
                received: self.seen.received(),
                canceled: true,
                ..Answer::default()
            };
            self.watch.done(
                (self.asked.take(), self.arrival.take()),
                &self.seen,
                &answer,
                &HeaderMap::new(),
            );
        }
    }
}

/// How a request was answered.
#[derive(Debug, Default)]
pub(crate) struct Answer {
    pub(crate) status: StatusCode,
    /// The S3 error code of an error answer, when its body names one.
    pub(crate) error: Option<String>,
    /// Until the answer's headers were ready; none when it never was.
    pub(crate) first_byte: Option<Duration>,
    /// Until its body was done with.
    pub(crate) duration: Duration,
    pub(crate) received: u64,
    pub(crate) sent: u64,
    /// Whether the client left before the whole answer was sent.
    pub(crate) canceled: bool,
    /// The size of the object it's about, as its headers say (access logged only).
    pub(crate) object_size: Option<u64>,
}

/// An answer's body that counts the bytes sent and records the request when it's
/// dropped: after its last byte, or early when the client goes away.
struct Sent {
    body: s3s::Body,
    request: Option<Request>,
    answer: Answer,
    /// The answer's headers, while the request is audited.
    headers: HeaderMap,
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
                if let Some(data) = frame.data_ref() {
                    self.answer.sent += data.len() as u64;
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
        let Some(mut request) = self.request.take() else {
            return;
        };
        request.answered = true;
        let answer = &mut self.answer;
        // A server that knows the length stops reading at it, before the body says it
        // has ended.
        let whole = self.ended || self.body.is_end_stream() || self.length == Some(answer.sent);
        answer.canceled = !whole;
        answer.duration = request.started.elapsed();
        answer.received = request.seen.received();
        let watch = &request.watch;
        watch.metrics.record(request.seen.operation(), answer);
        watch.done(
            (request.asked.take(), request.arrival.take()),
            &request.seen,
            answer,
            &self.headers,
        );
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
    let answer = Answer {
        status,
        error,
        first_byte: Some(request.started.elapsed()),
        object_size: request
            .arrival
            .as_ref()
            .and_then(|arrival| arrival.object_size(response.headers())),
        ..Answer::default()
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
    let headers = if request.asked.is_some() {
        response.headers().clone()
    } else {
        HeaderMap::new()
    };
    response.map(|body| {
        s3s::Body::http_body(Sent {
            body,
            request: Some(request),
            answer,
            headers,
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

    /// Keeps the entries it takes, or takes none.
    #[derive(Debug, Default)]
    struct Kept {
        refuse: bool,
        entries: Mutex<Vec<teifs_types::audit::AuditEntry>>,
    }

    impl AuditSink for Kept {
        fn log(&self, entry: teifs_types::audit::AuditEntry) -> bool {
            if !self.refuse {
                self.entries.lock().unwrap().push(entry);
            }
            !self.refuse
        }
    }

    fn watch(sink: &Arc<Kept>) -> (tempfile::TempDir, Arc<Watch>) {
        let dir = tempfile::tempdir().unwrap();
        let store = teifs_store::Store::open(dir.path()).unwrap();
        let sink: Arc<dyn AuditSink> = Arc::clone(sink) as _;
        let watch = Watch::new(
            Metrics::new(&store, Arc::new(teifs_notify::Notifier::none())),
            Scrapers::Anyone,
            Some(sink),
            Arc::new(Tracers::new()),
            "drive".into(),
            crate::access_log::AccessLog::new(false, crate::access_log::Counters::default()).0,
        );
        (dir, Arc::new(watch))
    }

    fn request(watch: &Arc<Watch>) -> Request {
        let asked = Asked::of(&http::Request::new(()), None);
        let seen = Arc::new(Seen::new());
        seen.name("PutObject");
        Request::new(Arc::clone(watch), seen, Some(asked), None)
    }

    #[tokio::test]
    async fn answered_and_abandoned_requests_are_audited() {
        use http_body_util::BodyExt;

        let sink = Arc::new(Kept::default());
        let (_dir, watch) = watch(&sink);
        let response = finish(answer(StatusCode::OK, "abc"), request(&watch));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"abc");
        // A request the client left before it was answered is the client's leaving.
        drop(request(&watch));
        let entries = sink.entries.lock().unwrap();
        let [answered, left] = &entries[..] else {
            panic!("{entries:?}")
        };
        assert_eq!((answered.api.status_code, answered.api.tx), (200, 3));
        assert_eq!(answered.deployment_id, "drive");
        assert_eq!(
            answered.response_header["x-amz-request-id"],
            answered.request_id
        );
        assert_eq!(
            (left.api.status_code, left.api.status.as_str()),
            (CLIENT_LEFT, "Client Closed Request")
        );
        assert!(left.api.time_to_first_byte.is_empty());
        let text = watch.metrics.text();
        assert!(
            text.contains("teifs_s3_canceled_total{api=\"PutObject\"} 1"),
            "{text}"
        );
        assert!(text.contains("teifs_audit_dropped_total 0"), "{text}");
    }

    #[test]
    fn entries_a_destination_refuses_are_counted() {
        let sink = Arc::new(Kept {
            refuse: true,
            ..Kept::default()
        });
        let (_dir, watch) = watch(&sink);
        drop(request(&watch));
        drop(request(&watch));
        assert!(watch.metrics.text().contains("teifs_audit_dropped_total 2"));
    }

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
