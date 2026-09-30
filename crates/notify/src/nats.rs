//! NATS targets, as `MinIO`'s: each event, as a webhook is sent it, published to a
//! subject over NATS's client protocol, or to a `JetStream` stream that acknowledges
//! it. One connection, made again after a failure; TLS when asked for (or the server
//! requires it); a user and password, a token, an nkey, or a `.creds` file's user JWT.

use std::{fmt, sync::Arc, time::Duration};

use base64::Engine as _;
use rustls::ClientConfig;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    sync::Mutex,
};
use zeroize::Zeroizing;

use crate::{
    net::{self, Stream},
    nkey::UserKey,
};

/// How long a connection or a publish may take.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The longest line read: more is a server that isn't NATS.
const MAX_LINE: u64 = 64 << 10;
/// The longest message read (only acknowledgements come).
const MAX_MESSAGE: usize = 1 << 20;
/// The subject that lists `JetStream`'s streams.
pub(crate) const STREAM_NAMES: &str = "$JS.API.STREAM.NAMES";

/// A subject events are published to.
#[derive(Clone)]
pub struct Nats {
    /// `HOST:PORT`.
    pub address: String,
    /// The subject.
    pub subject: String,
    /// Whether a `JetStream` stream must acknowledge each event.
    pub jetstream: bool,
    /// The user its password is for.
    pub user: Option<String>,
    /// Its password.
    pub password: Option<Zeroizing<String>>,
    /// Its token, in place of a user.
    pub token: Option<Zeroizing<String>>,
    /// Its nkey, alone or with a user JWT, in place of a user.
    pub key: Option<Arc<UserKey>>,
    /// TLS, and how the server is verified; none for plain TCP unless the server
    /// requires TLS.
    pub tls: Option<Arc<ClientConfig>>,
    /// Whether TLS starts at once, before the server's `INFO` (its
    /// `handshake_first`), rather than after it.
    pub tls_first: bool,
    connection: Arc<Mutex<Option<Connection>>>,
}

impl Nats {
    /// Events for `subject` on the server at `address` (`HOST:PORT`).
    ///
    /// # Errors
    ///
    /// When `address` isn't `HOST:PORT`, or `subject` can't be published to.
    pub fn new(address: &str, subject: &str) -> Result<Self, String> {
        let address = address.trim();
        if !net::is_address(address) {
            return Err(format!("`{address}` isn't HOST:PORT"));
        }
        if !is_subject(subject) {
            return Err(format!(
                "`{subject}` can't be published to: give tokens separated by `.`, without \
                 spaces or the wildcards `*` and `>`"
            ));
        }
        Ok(Self {
            address: address.to_owned(),
            subject: subject.to_owned(),
            jetstream: false,
            user: None,
            password: None,
            token: None,
            key: None,
            tls: None,
            tls_first: false,
            connection: Arc::new(Mutex::new(None)),
        })
    }

    /// Where it publishes.
    #[must_use]
    pub fn shown(&self) -> String {
        format!(
            "{}://{} subject {}{}",
            if self.tls.is_some() { "tls" } else { "nats" },
            self.address,
            self.subject,
            if self.jetstream { " (JetStream)" } else { "" }
        )
    }

    /// Publishes `body`. A connection that was kept and fails is made again once at
    /// once: a server closes one it hasn't heard from in a while.
    pub(crate) async fn send(&self, body: &[u8]) -> Result<(), String> {
        let mut connection = self.connection.lock().await;
        let mut kept = connection.is_some();
        loop {
            if connection.is_none() {
                *connection = Some(self.connect().await?);
            }
            let open = connection.as_mut().expect("connected");
            let result = tokio::time::timeout(TIMEOUT, open.publish(&self.subject, body))
                .await
                .unwrap_or_else(|_| Err("it didn't answer in time".to_owned()));
            match result {
                Ok(()) => return Ok(()),
                Err(_) if kept => kept = false,
                Err(e) => {
                    *connection = None;
                    return Err(e);
                }
            }
            *connection = None;
        }
    }

    /// Checks that the server takes the connection and, for `JetStream`, that a stream
    /// takes the subject, without publishing.
    pub(crate) async fn test(&self) -> Result<(), String> {
        let mut connection = self.connection.lock().await;
        *connection = None;
        let mut open = self.connect().await?;
        if self.jetstream {
            let body = serde_json::json!({ "subject": self.subject }).to_string();
            let reply =
                tokio::time::timeout(TIMEOUT, open.request(STREAM_NAMES, body.as_bytes(), None))
                    .await
                    .unwrap_or_else(|_| Err("it didn't answer in time".to_owned()))?;
            let answer = reply.answer(|| "JetStream isn't enabled for its account".to_owned())?;
            if answer["streams"].as_array().is_none_or(Vec::is_empty) {
                return Err(format!("no JetStream stream takes `{}`", self.subject));
            }
        }
        *connection = Some(open);
        Ok(())
    }

    /// Connects: TLS if asked for or required, then `CONNECT` with its credentials,
    /// answered by the `PONG` to a `PING`.
    async fn connect(&self) -> Result<Connection, String> {
        let tcp = net::connect(&self.address).await?;
        let stream: Stream = if self.tls_first {
            let tls = self
                .tls
                .as_ref()
                .ok_or("TLS first needs TLS: give tls=true or ca=PATH")?;
            net::secure(tcp, &self.address, Some(tls)).await?
        } else {
            Box::new(tcp)
        };
        let mut stream = BufReader::new(stream);
        let line = tokio::time::timeout(TIMEOUT, read_line(&mut stream))
            .await
            .unwrap_or_else(|_| Err("it didn't answer in time".to_owned()))?;
        let info: serde_json::Value = line
            .strip_prefix("INFO ")
            .and_then(|json| serde_json::from_str(json).ok())
            .ok_or("it answered with something that isn't NATS")?;
        let stream = if self.tls_first || !(self.tls.is_some() || info["tls_required"] == true) {
            stream.into_inner()
        } else {
            let tls = self
                .tls
                .as_ref()
                .ok_or("it requires TLS: give tls=true or ca=PATH")?;
            net::secure(stream.into_inner(), &self.address, Some(tls)).await?
        };
        let headers = info["headers"] == true;
        let mut connection = Connection {
            stream: BufReader::new(stream),
            inbox: format!("_INBOX.{}", random_token()?),
            next: 0,
            max_payload: info["max_payload"]
                .as_u64()
                .and_then(|m| usize::try_from(m).ok())
                .unwrap_or(1 << 20),
            headers,
            jetstream: self.jetstream,
        };
        let mut command = self.connect_command(&info, headers)?;
        command.extend_from_slice(b"PING\r\n");
        tokio::time::timeout(TIMEOUT, async {
            connection.write(&command).await?;
            connection.pong().await
        })
        .await
        .unwrap_or_else(|_| Err("it didn't answer in time".to_owned()))?;
        if self.jetstream {
            let sub = format!("SUB {}.* 1\r\n", connection.inbox);
            connection.write(sub.as_bytes()).await?;
        }
        Ok(connection)
    }

    /// `CONNECT`, its secrets written only into memory that's wiped.
    fn connect_command(
        &self,
        info: &serde_json::Value,
        headers: bool,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut fields = serde_json::json!({
            "verbose": false,
            "pedantic": false,
            "tls_required": self.tls.is_some(),
            "name": "teifs",
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": 1,
            "echo": false,
            "headers": headers,
            "no_responders": headers,
        });
        if let Some(user) = &self.user {
            fields["user"] = user.as_str().into();
        }
        if let Some(key) = &self.key {
            let nonce = info["nonce"]
                .as_str()
                .ok_or("it sent no nonce to sign: is it set up for nkeys?")?;
            fields["sig"] = key.sign(nonce).into();
            match &key.jwt {
                Some(jwt) => fields["jwt"] = jwt.as_str().into(),
                None => fields["nkey"] = key.public.as_str().into(),
            }
        }
        let secrets = [("pass", &self.password), ("auth_token", &self.token)];
        let size: usize = secrets
            .iter()
            .filter_map(|(_, s)| s.as_ref().map(|s| s.len() * 6 + 16))
            .sum();
        let open = fields.to_string();
        let mut command = Zeroizing::new(Vec::with_capacity(open.len() + size + 16));
        command.extend_from_slice(b"CONNECT ");
        command.extend_from_slice(&open.as_bytes()[..open.len() - 1]);
        for (name, secret) in secrets {
            if let Some(secret) = secret {
                command.extend_from_slice(format!(",\"{name}\":").as_bytes());
                serde_json::to_writer(&mut *command, secret.as_str()).map_err(|e| e.to_string())?;
            }
        }
        command.extend_from_slice(b"}\r\n");
        Ok(command)
    }
}

impl fmt::Debug for Nats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nats")
            .field("at", &self.shown())
            .finish_non_exhaustive()
    }
}

/// Whether events can be published to `subject`: tokens separated by `.`, no
/// whitespace, no wildcards.
fn is_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.split('.').all(|token| {
            !token.is_empty()
                && token != "*"
                && token != ">"
                && !token
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        })
}

/// A random name for the connection's inbox.
fn random_token() -> Result<String, String> {
    let mut bytes = [0; 12];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| "no randomness".to_owned())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(bytes)
        .replace(['-', '_'], "x"))
}

/// A connection to a NATS server.
struct Connection {
    stream: BufReader<Stream>,
    /// Where `JetStream`'s acknowledgements come, `_INBOX.<random>`.
    inbox: String,
    /// The number of the last request.
    next: u64,
    max_payload: usize,
    /// Whether the server takes headers (and so answers "no responders").
    headers: bool,
    /// Whether `JetStream` acknowledges what's published, the inbox subscribed.
    jetstream: bool,
}

/// What the server sends.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Ping,
    Pong,
    Ok,
    Info,
    Err(String),
    Msg {
        subject: String,
        status: Option<u16>,
        payload: Vec<u8>,
    },
}

/// A reply to a request: its status (503 for no responders), and its body.
pub(crate) struct Reply {
    status: Option<u16>,
    payload: Vec<u8>,
}

impl Reply {
    /// The JSON answer of a `JetStream` API; `none` says what no responders means.
    fn answer(self, none: impl FnOnce() -> String) -> Result<serde_json::Value, String> {
        match self.status {
            Some(503) => return Err(none()),
            Some(status) => return Err(format!("it answered {status}")),
            None => {}
        }
        let answer: serde_json::Value = serde_json::from_slice(&self.payload)
            .map_err(|_| "JetStream's answer isn't JSON".to_owned())?;
        if let Some(error) = answer.get("error") {
            return Err(format!(
                "JetStream refused it: {} ({})",
                error["description"].as_str().unwrap_or("no reason"),
                error["err_code"]
                    .as_u64()
                    .or(error["code"].as_u64())
                    .unwrap_or(0)
            ));
        }
        Ok(answer)
    }
}

impl Connection {
    async fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        let lost = |e: std::io::Error| format!("the connection failed: {e}");
        let stream = self.stream.get_mut();
        stream.write_all(bytes).await.map_err(lost)?;
        stream.flush().await.map_err(lost)
    }

    /// Publishes `body` to `subject`: confirmed by a `PONG`, or acknowledged by
    /// `JetStream` when the connection has an inbox subscribed.
    async fn publish(&mut self, subject: &str, body: &[u8]) -> Result<(), String> {
        if body.len() > self.max_payload {
            return Err(format!(
                "the event is larger than the server takes ({} bytes)",
                self.max_payload
            ));
        }
        if self.jetstream {
            // The same event sent again has the same id, which the stream drops.
            let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(body));
            let ack = self.request(subject, body, Some(&id)).await?;
            let answer = ack.answer(|| format!("no JetStream stream takes `{subject}`"))?;
            if answer["stream"].as_str().is_none_or(str::is_empty) {
                return Err("JetStream didn't acknowledge it".to_owned());
            }
            return Ok(());
        }
        let mut command = format!("PUB {subject} {}\r\n", body.len()).into_bytes();
        command.extend_from_slice(body);
        command.extend_from_slice(b"\r\nPING\r\n");
        self.write(&command).await?;
        self.pong().await
    }

    /// Sends `body` to `subject` with a reply subject, with `Nats-Msg-Id: id` when the
    /// server takes headers, and waits for the reply.
    async fn request(
        &mut self,
        subject: &str,
        body: &[u8],
        id: Option<&str>,
    ) -> Result<Reply, String> {
        self.next += 1;
        let reply = format!("{}.{}", self.inbox, self.next);
        let mut command = match id.filter(|_| self.headers) {
            Some(id) => {
                let headers = format!("NATS/1.0\r\nNats-Msg-Id: {id}\r\n\r\n");
                let mut command = format!(
                    "HPUB {subject} {reply} {} {}\r\n",
                    headers.len(),
                    headers.len() + body.len()
                )
                .into_bytes();
                command.extend_from_slice(headers.as_bytes());
                command
            }
            None => format!("PUB {subject} {reply} {}\r\n", body.len()).into_bytes(),
        };
        command.extend_from_slice(body);
        command.extend_from_slice(b"\r\n");
        self.write(&command).await?;
        loop {
            match self.op().await? {
                Op::Msg {
                    subject,
                    status,
                    payload,
                } if subject == reply => return Ok(Reply { status, payload }),
                // A reply to an earlier request that timed out.
                Op::Msg { .. } | Op::Ok | Op::Info | Op::Pong => {}
                Op::Ping => self.write(b"PONG\r\n").await?,
                Op::Err(message) => return Err(format!("it answered: {message}")),
            }
        }
    }

    /// Waits for the `PONG` to a `PING`: everything sent before it was taken.
    async fn pong(&mut self) -> Result<(), String> {
        loop {
            match self.op().await? {
                Op::Pong => return Ok(()),
                Op::Ping => self.write(b"PONG\r\n").await?,
                Op::Ok | Op::Info | Op::Msg { .. } => {}
                Op::Err(message) => return Err(format!("it answered: {message}")),
            }
        }
    }

    async fn op(&mut self) -> Result<Op, String> {
        read_op(&mut self.stream).await
    }
}

/// Reads one line, without its `\r\n`.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(stream: &mut R) -> Result<String, String> {
    let mut line = Vec::new();
    (&mut *stream)
        .take(MAX_LINE)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|e| format!("the connection failed: {e}"))?;
    if line.is_empty() {
        return Err("the connection was closed".to_owned());
    }
    if !line.ends_with(b"\r\n") {
        return Err("it answered with something that isn't NATS".to_owned());
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_| "it answered with something that isn't NATS".to_owned())
}

/// Reads one thing the server sends, with its payload.
pub(crate) async fn read_op<R: tokio::io::AsyncBufRead + Unpin>(
    stream: &mut R,
) -> Result<Op, String> {
    let bad = || "it answered with something that isn't NATS".to_owned();
    let line = read_line(stream).await?;
    let mut words = line.split_ascii_whitespace();
    let name = words.next().unwrap_or_default().to_ascii_uppercase();
    let words: Vec<&str> = words.collect();
    let size = |word: Option<&&str>| {
        word.and_then(|w| w.parse::<usize>().ok())
            .filter(|&s| s <= MAX_MESSAGE)
            .ok_or_else(bad)
    };
    let (subject, headers, total) = match (name.as_str(), words.len()) {
        ("PING", _) => return Ok(Op::Ping),
        ("PONG", _) => return Ok(Op::Pong),
        ("+OK", _) => return Ok(Op::Ok),
        ("INFO", _) => return Ok(Op::Info),
        ("-ERR", _) => {
            let message = line[4..].trim().trim_matches('\'');
            return Ok(Op::Err(message.to_owned()));
        }
        ("MSG", 3 | 4) => (words[0], 0, size(words.last())?),
        ("HMSG", 4 | 5) => (
            words[0],
            size(words.get(words.len() - 2))?,
            size(words.last())?,
        ),
        _ => return Err(bad()),
    };
    if headers > total {
        return Err(bad());
    }
    let mut data = vec![0; total + 2];
    stream
        .read_exact(&mut data)
        .await
        .map_err(|e| format!("the connection failed: {e}"))?;
    if !data.ends_with(b"\r\n") {
        return Err(bad());
    }
    data.truncate(total);
    let status = (headers > 0)
        .then(|| {
            let head = std::str::from_utf8(&data[..headers]).ok()?;
            let first = head.lines().next()?.strip_prefix("NATS/1.0")?.trim();
            first.split_ascii_whitespace().next()?.parse().ok()
        })
        .flatten();
    Ok(Op::Msg {
        subject: subject.to_owned(),
        status,
        payload: data.split_off(headers),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ops_are_read_as_the_server_sends_them() {
        let read = |bytes: &'static [u8]| async move { read_op(&mut &bytes[..]).await };
        assert_eq!(read(b"PING\r\n").await, Ok(Op::Ping));
        assert_eq!(read(b"pong\r\n").await, Ok(Op::Pong));
        assert_eq!(read(b"+OK\r\n").await, Ok(Op::Ok));
        assert_eq!(read(b"INFO {\"a\":1}\r\n").await, Ok(Op::Info));
        assert_eq!(
            read(b"-ERR 'Authorization Violation'\r\n").await,
            Ok(Op::Err("Authorization Violation".into()))
        );
        assert_eq!(
            read(b"MSG _INBOX.x.1 1 5\r\nhello\r\n").await,
            Ok(Op::Msg {
                subject: "_INBOX.x.1".into(),
                status: None,
                payload: b"hello".to_vec()
            })
        );
        assert_eq!(
            read(b"MSG a 1 reply 2\r\nhi\r\n").await,
            Ok(Op::Msg {
                subject: "a".into(),
                status: None,
                payload: b"hi".to_vec()
            })
        );
        assert_eq!(
            read(b"HMSG _INBOX.x.2 1 16 16\r\nNATS/1.0 503\r\n\r\n\r\n").await,
            Ok(Op::Msg {
                subject: "_INBOX.x.2".into(),
                status: Some(503),
                payload: vec![]
            })
        );
        for bad in [
            &b"MSG a 1 5\r\nhel"[..],
            b"MSG a 1 5\r\nhelloXX",
            b"MSG a 1\r\n",
            b"MSG a 1 99999999999\r\n",
            b"HMSG a 1 9 4\r\n",
            b"WHAT\r\n",
            b"PING\n",
            b"",
        ] {
            assert!(
                read(bad).await.is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn subjects_and_addresses_are_checked() {
        for good in ["s3", "s3.events", "a.b-c.d_e", "$JS.x"] {
            assert!(Nats::new("h:4222", good).is_ok(), "{good}");
        }
        for bad in ["", "a b", "a..b", ".a", "a.", "a.*", "a.>", "*", "a\tb"] {
            assert!(Nats::new("h:4222", bad).is_err(), "{bad}");
        }
        assert!(Nats::new("h", "s").is_err());
        let mut nats = Nats::new("h:4222", "s3.events").unwrap();
        assert_eq!(nats.shown(), "nats://h:4222 subject s3.events");
        nats.jetstream = true;
        assert_eq!(nats.shown(), "nats://h:4222 subject s3.events (JetStream)");
    }

    #[test]
    fn secrets_go_only_into_the_connect_command() {
        let mut nats = Nats::new("h:4222", "s").unwrap();
        nats.user = Some("teifs".into());
        nats.password = Some(Zeroizing::new("p\"w".into()));
        let command = nats.connect_command(&serde_json::json!({}), true).unwrap();
        let text = std::str::from_utf8(&command).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(text.strip_prefix("CONNECT ").unwrap().trim_end()).unwrap();
        assert_eq!(
            (json["user"].as_str(), json["pass"].as_str()),
            (Some("teifs"), Some("p\"w"))
        );
        assert_eq!(json["headers"], true);
        assert!(!format!("{nats:?}").contains("p\\\"w"));
    }
}
