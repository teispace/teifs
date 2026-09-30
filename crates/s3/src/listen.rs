//! Listening for events (`MinIO`'s API, `mc watch`, `teifs watch`): `GET /BUCKET?events=…`
//! for one bucket's, `GET /?events=…` for every bucket's. The answer lasts until the
//! client leaves or the server stops, one `{"Records":[…]}` line per event, and
//! `{"Records":[]}` as its heartbeat (every `ping` seconds, 10 by default).
//!
//! Listeners get every event, whatever the buckets' notification rules say, and the
//! buckets' creations and removals too. Events are only made while someone listens or
//! the server has targets; one that falls behind skips events.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri, header};
use s3s::{Body, S3Response, S3Result, s3_error};
use serde::Serialize;
use teifs_types::notify::{EventRecord, ListenFilter};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::lines;

/// How many events wait for the slowest listener before it skips some.
const BACKLOG: usize = 4096;

/// The heartbeat: an event line with no events, which `MinIO`'s clients skip.
const PING: &[u8] = b"{\"Records\":[]}\n";

/// The longest `ping` asked for, in seconds: longer ones get a heartbeat this often.
const MAX_PING: u64 = 3600;

/// One event, for listeners.
#[derive(Debug)]
pub(crate) struct Heard {
    pub(crate) bucket: String,
    /// Its full name: `s3:ObjectCreated:Put`.
    pub(crate) event: String,
    pub(crate) key: String,
    /// Its line: `{"Records":[record]}`.
    line: Bytes,
}

impl Heard {
    pub(crate) fn new(bucket: &str, event: &str, key: &str, record: &EventRecord) -> Self {
        #[derive(Serialize)]
        struct Line<'a> {
            #[serde(rename = "Records")]
            records: [&'a EventRecord; 1],
        }
        let mut line =
            serde_json::to_vec(&Line { records: [record] }).expect("an event serializes");
        line.push(b'\n');
        Self {
            bucket: bucket.to_owned(),
            event: event.to_owned(),
            key: key.to_owned(),
            line: Bytes::from(line),
        }
    }
}

/// Everyone listening for events.
#[derive(Debug)]
pub(crate) struct Listeners {
    heard: broadcast::Sender<Arc<Heard>>,
}

impl Listeners {
    pub(crate) fn new() -> Self {
        Self {
            heard: broadcast::channel(BACKLOG).0,
        }
    }

    /// Whether anyone is listening.
    pub(crate) fn listened(&self) -> bool {
        self.heard.receiver_count() > 0
    }

    /// Tells whoever is listening.
    pub(crate) fn tell(&self, heard: Heard) {
        let _ = self.heard.send(Arc::new(heard));
    }

    /// The events `request` asks for, until the listener leaves or `stopping` is
    /// cancelled.
    pub(crate) fn follow(&self, request: Request, stopping: CancellationToken) -> Body {
        let Request {
            scope,
            filter,
            ping,
        } = request;
        lines::follow(
            self.heard.subscribe(),
            stopping,
            (ping, PING),
            move |heard: Arc<Heard>| {
                (scope.covers(&heard.bucket) && filter.matches(&heard.event, &heard.key))
                    .then(|| heard.line.clone())
            },
        )
    }
}

/// Whose events a listener asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every bucket's: `GET /?events=…`.
    Every,
    /// One bucket's: `GET /BUCKET?events=…`.
    Bucket(String),
}

impl Scope {
    fn covers(&self, bucket: &str) -> bool {
        match self {
            Self::Every => true,
            Self::Bucket(name) => name == bucket,
        }
    }
}

/// What a listener asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) scope: Scope,
    pub(crate) filter: ListenFilter,
    /// How often a heartbeat is sent.
    pub(crate) ping: Duration,
}

impl Request {
    /// The listen request `uri` makes, if it's one: a `GET` with `events` in its query,
    /// on the root or on a bucket (in the path, or in the host with `domains`).
    pub(crate) fn of(
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        domains: &[String],
    ) -> Option<Scope> {
        let query = uri.query()?;
        if method != Method::GET
            || !form_urlencoded::parse(query.as_bytes()).any(|(k, _)| k == "events")
        {
            return None;
        }
        let path = uri.path();
        if let Some(bucket) = crate::admin::virtual_bucket(headers, domains) {
            return (path == "/").then(|| Scope::Bucket(bucket.to_owned()));
        }
        let name = path.strip_prefix('/')?;
        let name = name.strip_suffix('/').unwrap_or(name);
        if name.contains('/') {
            None
        } else if name.is_empty() {
            Some(Scope::Every)
        } else {
            Some(Scope::Bucket(name.to_owned()))
        }
    }

    /// Reads the query: `events` (repeated), a `prefix` and a `suffix`, and `ping`.
    pub(crate) fn read(scope: Scope, query: &str) -> S3Result<Self> {
        let mut filter = ListenFilter::default();
        let (mut prefix, mut suffix, mut ping) = (None, None, None);
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            let slot = match name.as_ref() {
                "events" => {
                    filter.events.extend(
                        value
                            .split(',')
                            .filter(|e| !e.is_empty())
                            .map(str::to_owned),
                    );
                    continue;
                }
                "prefix" => &mut prefix,
                "suffix" => &mut suffix,
                "ping" => &mut ping,
                _ => continue,
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(s3_error!(
                    InvalidArgument,
                    "`{name}` is given more than once"
                ));
            }
        }
        filter.prefix = prefix.unwrap_or_default();
        filter.suffix = suffix.unwrap_or_default();
        filter
            .check()
            .map_err(|err| s3_error!(InvalidArgument, "{err}"))?;
        let ping = match ping {
            None => lines::HEARTBEAT,
            Some(ping) => match ping.parse::<u64>() {
                Ok(seconds) if seconds >= 1 => Duration::from_secs(seconds.min(MAX_PING)),
                _ => {
                    return Err(s3_error!(
                        InvalidArgument,
                        "`ping` is a number of seconds, at least 1"
                    ));
                }
            },
        };
        Ok(Self {
            scope,
            filter,
            ping,
        })
    }
}

/// The answer a listener reads.
pub(crate) fn response(body: Body) -> S3Response<Body> {
    let mut response = S3Response::new(body);
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Proxies that buffer answers would hold the events back.
    response
        .headers
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;

    async fn next_line(body: &mut Body) -> Bytes {
        body.frame().await.unwrap().unwrap().into_data().unwrap()
    }

    fn scope(method: &Method, uri: &str, host: &str) -> Option<Scope> {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        Request::of(
            method,
            &uri.parse().unwrap(),
            &headers,
            &["s3.example.com".to_owned()],
        )
    }

    #[test]
    fn listen_requests_are_told_apart() {
        let get = &Method::GET;
        let host = "localhost:9000";
        let bucket = |name: &str| Some(Scope::Bucket(name.to_owned()));
        assert_eq!(
            scope(get, "/?events=s3:ObjectCreated:*", host),
            Some(Scope::Every)
        );
        assert_eq!(
            scope(get, "/photos?events=x&prefix=a", host),
            bucket("photos")
        );
        assert_eq!(scope(get, "/photos/?events=x", host), bucket("photos"));
        assert_eq!(
            scope(get, "/?events=x", "photos.s3.example.com"),
            bucket("photos")
        );
        for (method, uri, host) in [
            (get, "/photos", host),
            (get, "/photos?list-type=2", host),
            (get, "/photos?eventsx=1", host),
            (get, "/photos/key?events=x", host),
            (get, "/key?events=x", "photos.s3.example.com"),
            (&Method::PUT, "/photos?events=x", host),
        ] {
            assert_eq!(scope(method, uri, host), None, "{method} {uri} {host}");
        }
    }

    #[test]
    fn queries_are_read_as_minio_reads_them() {
        let read = |query: &str| Request::read(Scope::Every, query);
        let request = read(
            "events=s3:ObjectCreated:*&events=s3:ObjectRemoved:*,s3:BucketCreated:*\
             &prefix=photos%2F&suffix=.jpg&ping=5&other=1",
        )
        .unwrap();
        assert_eq!(
            request.filter.events,
            [
                "s3:ObjectCreated:*",
                "s3:ObjectRemoved:*",
                "s3:BucketCreated:*"
            ]
        );
        assert_eq!(
            request.filter.prefix, "photos/",
            "decoded once, as a key is"
        );
        assert_eq!(request.filter.suffix, ".jpg");
        assert_eq!(request.ping, Duration::from_secs(5));
        assert_eq!(
            read("events=s3:ObjectCreated:Put").unwrap().ping,
            lines::HEARTBEAT
        );
        assert_eq!(
            read("events=s3:ObjectCreated:Put&ping=99999").unwrap().ping,
            Duration::from_secs(MAX_PING)
        );
        for bad in [
            "events=",
            "events=s3:Nothing",
            "events=s3:ObjectCreated:Put&prefix=a&prefix=b",
            "events=s3:ObjectCreated:Put&ping=0",
            "events=s3:ObjectCreated:Put&ping=soon",
        ] {
            let err = read(bad).unwrap_err();
            assert_eq!(err.code().as_str(), "InvalidArgument", "{bad}");
        }
    }

    #[tokio::test]
    async fn listeners_get_their_events_as_minio_sends_them() {
        let listeners = Listeners::new();
        assert!(!listeners.listened());
        let request = Request::read(
            Scope::Bucket("photos".into()),
            "events=s3:ObjectCreated:*&prefix=a/&ping=1",
        )
        .unwrap();
        let body = listeners.follow(request, CancellationToken::new());
        assert!(listeners.listened());
        let record: EventRecord = serde_json::from_value(serde_json::json!({
            "eventVersion": "2.6", "eventSource": "aws:s3", "awsRegion": "us-east-1",
            "eventTime": "2026-09-30T12:00:00.000Z", "eventName": "ObjectCreated:Put",
            "userIdentity": {"principalId": "key"},
            "requestParameters": {"sourceIPAddress": "127.0.0.1"},
            "responseElements": {"x-amz-request-id": "1", "x-amz-id-2": "drive"},
            "s3": {
                "s3SchemaVersion": "1.0", "configurationId": "Config",
                "bucket": {"name": "photos", "ownerIdentity": {"principalId": "o"},
                           "arn": "arn:aws:s3:::photos"},
                "object": {"key": "a/1", "sequencer": "1"}
            }
        }))
        .unwrap();
        let put = "s3:ObjectCreated:Put";
        listeners.tell(Heard::new("videos", put, "a/1", &record));
        listeners.tell(Heard::new("photos", put, "b/1", &record));
        listeners.tell(Heard::new(
            "photos",
            "s3:ObjectRemoved:Delete",
            "a/1",
            &record,
        ));
        listeners.tell(Heard::new("photos", put, "a/1", &record));
        let mut body = body;
        let first = next_line(&mut body).await;
        let line: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(line["Records"][0]["s3"]["object"]["key"], "a/1");
        assert_eq!(line.as_object().unwrap().len(), 1, "only Records");
        assert!(first.ends_with(b"\n"));
        let ping = next_line(&mut body).await;
        assert_eq!(
            &ping[..],
            PING,
            "then a heartbeat, the others being filtered"
        );
    }
}
