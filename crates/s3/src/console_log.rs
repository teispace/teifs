//! `MinIO`'s console log (`GET /minio/admin/v3/log`, `mc admin logs`): the server's
//! information, warnings and errors, as `madmin.LogInfo`, the last few first and then
//! as they're logged, until the caller leaves.
//!
//! [`ConsoleLayer`], added to the program's `tracing` subscriber, keeps the last
//! [`KEPT`] lines the subscriber lets through, so what went wrong before anyone asked
//! can still be read.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Write as _,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use http::{HeaderValue, header};
use s3s::{Body, S3Request, S3Response};
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::broadcast;
use tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::layer::{Context, Layer};

use crate::{lines, minio_info, routes::Routes};

/// How many lines are kept, as `MinIO`'s `defaultLogBufferCount`.
const KEPT: usize = 10_000;
/// How many lines a caller gets first when it doesn't say, as `MinIO`'s default.
const DEFAULT_LAST: usize = 10;
/// How often a quiet log sends a space, as `MinIO`'s does.
const KEEP_ALIVE: Duration = Duration::from_millis(500);

/// One line the server logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogLine {
    time: String,
    kind: Kind,
    /// Where it was logged: its module (`teifs_store::scrub`).
    target: String,
    /// Its file and line, if known.
    source: Option<String>,
    message: String,
    /// Its other fields, as text.
    fields: BTreeMap<String, String>,
}

/// `madmin.LogKind`, with its mask bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Warning,
    Error,
    Info,
}

impl Kind {
    const fn of(level: Level) -> Option<Self> {
        match level {
            Level::ERROR => Some(Self::Error),
            Level::WARN => Some(Self::Warning),
            Level::INFO => Some(Self::Info),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
            Self::Info => "INFO",
        }
    }

    /// `madmin.LogMask`'s bit.
    const fn mask(self) -> u8 {
        match self {
            Self::Warning => 1 << 1,
            Self::Error => 1 << 2,
            Self::Info => 1 << 4,
        }
    }
}

/// `madmin.LogKind(...).LogMask()`: one kind's bit, or all of them.
fn mask(log_type: &str) -> u8 {
    match log_type.to_ascii_uppercase().as_str() {
        "FATAL" => 1,
        "WARNING" => Kind::Warning.mask(),
        "ERROR" => Kind::Error.mask(),
        "EVENT" => 1 << 3,
        "INFO" => Kind::Info.mask(),
        _ => u8::MAX,
    }
}

/// The program's console log.
#[derive(Debug)]
pub(crate) struct ConsoleLog {
    kept: Mutex<VecDeque<Arc<LogLine>>>,
    lines: broadcast::Sender<Arc<LogLine>>,
}

impl ConsoleLog {
    fn new() -> Self {
        Self {
            kept: Mutex::new(VecDeque::with_capacity(KEPT)),
            lines: broadcast::channel(4096).0,
        }
    }

    /// The program's.
    pub(crate) fn global() -> &'static Self {
        static LOG: OnceLock<ConsoleLog> = OnceLock::new();
        LOG.get_or_init(Self::new)
    }

    fn push(&self, line: LogLine) {
        let line = Arc::new(line);
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if kept.len() == KEPT {
            kept.pop_front();
        }
        kept.push_back(Arc::clone(&line));
        // Sent under the lock, so a new watcher's first lines and what follows them
        // neither overlap nor leave a gap.
        let _ = self.lines.send(line);
    }

    /// The last `last` lines `shown` takes, and the ones that follow.
    fn watch(
        &self,
        last: usize,
        shown: impl Fn(&LogLine) -> bool,
    ) -> (Vec<Arc<LogLine>>, broadcast::Receiver<Arc<LogLine>>) {
        let kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        let mut first: Vec<_> = kept
            .iter()
            .rev()
            .filter(|line| shown(line))
            .take(last)
            .cloned()
            .collect();
        first.reverse();
        (first, self.lines.subscribe())
    }
}

/// A `tracing` layer that keeps what's logged at `INFO` and above in the console log.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsoleLayer;

impl<S: Subscriber> Layer<S> for ConsoleLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let metadata = event.metadata();
        let Some(kind) = Kind::of(*metadata.level()) else {
            return;
        };
        let mut fields = Fields::default();
        event.record(&mut fields);
        ConsoleLog::global().push(LogLine {
            time: OffsetDateTime::from(SystemTime::now())
                .format(&Rfc3339)
                .unwrap_or_default(),
            kind,
            target: metadata.target().to_owned(),
            source: metadata
                .file()
                .map(|file| format!("{file}:{}", metadata.line().unwrap_or(0))),
            message: fields.message,
            fields: fields.others,
        });
    }
}

/// An event's message and other fields.
#[derive(Default)]
struct Fields {
    message: String,
    others: BTreeMap<String, String>,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.set(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut text = String::new();
        let _ = write!(text, "{value:?}");
        self.set(field, text);
    }
}

impl Fields {
    fn set(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.others.insert(field.name().to_owned(), value);
        }
    }
}

/// `madmin.LogInfo`.
#[derive(Serialize)]
struct LogInfo<'a> {
    level: &'static str,
    #[serde(rename = "errKind")]
    kind: &'static str,
    time: &'a str,
    api: Api,
    #[serde(skip_serializing_if = "str::is_empty")]
    message: &'a str,
    #[serde(rename = "error", skip_serializing_if = "Option::is_none")]
    trace: Option<Trace<'a>>,
    node: &'a str,
}

#[derive(Serialize)]
struct Api {
    name: String,
}

#[derive(Serialize)]
struct Trace<'a> {
    message: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source: Vec<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    variables: &'a BTreeMap<String, String>,
}

/// `line` as `MinIO` sends it from `node`: errors and warnings with where they were
/// logged, information as a message with its fields after it.
fn log_info(line: &LogLine, node: &str) -> Bytes {
    let message = if line.fields.is_empty() || line.kind != Kind::Info {
        line.message.clone()
    } else {
        let mut message = line.message.clone();
        for (name, value) in &line.fields {
            let _ = write!(message, " {name}={value}");
        }
        message
    };
    let info = LogInfo {
        level: line.kind.name(),
        kind: line.kind.name(),
        time: &line.time,
        api: Api {
            name: format!("SYSTEM.{}", line.target),
        },
        message: if line.kind == Kind::Info {
            &message
        } else {
            ""
        },
        trace: (line.kind != Kind::Info).then(|| Trace {
            message: &line.message,
            source: line.source.iter().map(String::as_str).collect(),
            variables: &line.fields,
        }),
        node,
    };
    let mut bytes = serde_json::to_vec(&info).expect("a log line serializes");
    bytes.push(b'\n');
    Bytes::from(bytes)
}

/// What a caller asks for: `node`, `limit` and `logType`.
struct Asked {
    node: String,
    last: usize,
    mask: u8,
}

impl Asked {
    fn parse(query: &str) -> Self {
        let pairs: BTreeMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let get = |name: &str| pairs.get(name).map_or("", String::as_str);
        // As MinIO: no limit, or one it can't read, is 10; one out of range is all.
        let last = match get("limit").trim().parse::<i64>() {
            Err(_) => DEFAULT_LAST,
            Ok(n) => usize::try_from(n)
                .ok()
                .filter(|n| (1..=KEPT).contains(n))
                .unwrap_or(KEPT),
        };
        Self {
            node: get("node").to_owned(),
            last,
            mask: mask(get("logType")),
        }
    }
}

/// `GET /minio/admin/v3/log`.
pub(crate) fn log(routes: &Routes, req: &S3Request<Body>) -> S3Response<Body> {
    let asked = Asked::parse(req.uri.query().unwrap_or_default());
    let node = minio_info::endpoint(routes, req);
    // One server: another node's lines are none.
    let ours = asked.node.is_empty() || asked.node.eq_ignore_ascii_case(&node);
    let mask = asked.mask;
    let shown = move |line: &LogLine| ours && line.kind.mask() & mask != 0;
    let (first, following) = ConsoleLog::global().watch(asked.last, shown);
    let first = first.iter().map(|line| log_info(line, &node)).collect();
    let body = lines::follow_after(
        first,
        following,
        routes.tracers.stopping(),
        (KEEP_ALIVE, b" "),
        move |line: Arc<LogLine>| shown(&line).then(|| log_info(&line, &node)),
    );
    let mut response = S3Response::new(body);
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    fn line(kind: Kind, message: &str) -> LogLine {
        LogLine {
            time: "2026-10-02T10:00:00Z".to_owned(),
            kind,
            target: "teifs_store::scrub".to_owned(),
            source: Some("crates/store/src/scrub.rs:10".to_owned()),
            message: message.to_owned(),
            fields: BTreeMap::from([("bucket".to_owned(), "pics".to_owned())]),
        }
    }

    #[test]
    fn the_last_lines_asked_for_come_first() {
        let log = ConsoleLog::new();
        for n in 0..KEPT + 5 {
            log.push(line(
                if n % 2 == 0 { Kind::Error } else { Kind::Info },
                &n.to_string(),
            ));
        }
        assert_eq!(
            log.kept.lock().unwrap().len(),
            KEPT,
            "the oldest are dropped"
        );
        let (first, _) = log.watch(3, |l| l.kind == Kind::Error);
        let messages: Vec<&str> = first.iter().map(|l| l.message.as_str()).collect();
        assert_eq!(messages, ["10000", "10002", "10004"]);
    }

    #[test]
    fn queries_are_read_as_minio_reads_them() {
        let asked = Asked::parse("node=&limit=5&logType=error");
        assert_eq!((asked.last, asked.mask), (5, Kind::Error.mask()));
        for ten in ["limit=many", ""] {
            assert_eq!(Asked::parse(ten).last, DEFAULT_LAST, "{ten}");
        }
        for all in ["limit=0", "limit=-1", "limit=10001"] {
            assert_eq!(Asked::parse(all).last, KEPT, "{all}");
        }
        assert_eq!(Asked::parse("logType=all").mask, u8::MAX);
        assert_eq!(Asked::parse("").mask, u8::MAX);
    }

    #[test]
    fn lines_are_log_infos() {
        let error: serde_json::Value =
            serde_json::from_slice(&log_info(&line(Kind::Error, "disk full"), "h:9000")).unwrap();
        assert_eq!(
            error,
            serde_json::json!({
                "level": "ERROR",
                "errKind": "ERROR",
                "time": "2026-10-02T10:00:00Z",
                "api": {"name": "SYSTEM.teifs_store::scrub"},
                "error": {
                    "message": "disk full",
                    "source": ["crates/store/src/scrub.rs:10"],
                    "variables": {"bucket": "pics"},
                },
                "node": "h:9000",
            })
        );
        let info: serde_json::Value =
            serde_json::from_slice(&log_info(&line(Kind::Info, "scrubbed"), "h:9000")).unwrap();
        assert_eq!(info["message"], "scrubbed bucket=pics");
        assert_eq!(info["level"], "INFO");
        assert!(info.get("error").is_none());
    }

    #[test]
    fn the_layer_keeps_information_and_above() {
        let subscriber = tracing_subscriber::registry().with(ConsoleLayer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(bucket = "kept-by-layer", "a warning for the console log");
            tracing::debug!("not kept");
        });
        let (first, _) = ConsoleLog::global().watch(KEPT, |l| {
            l.fields.get("bucket").is_some_and(|b| b == "kept-by-layer")
        });
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind, Kind::Warning);
        assert_eq!(first[0].message, "a warning for the console log");
        assert!(
            first[0].target.ends_with("console_log::tests"),
            "{}",
            first[0].target
        );
    }
}
