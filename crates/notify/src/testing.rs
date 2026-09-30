//! Targets on this machine, for tests (the `testing` feature): a webhook receiver that
//! takes requests (`POST`s, and the others an Elasticsearch target makes), or fails as
//! many as it's told to first, Redis, NSQ, NATS and MQTT servers, a Kafka cluster, an AMQP
//! broker, PostgreSQL and MySQL servers, and a server that answers as AWS's SQS, SNS, Lambda and
//! EventBridge do.

mod amqp;
mod kafka;
mod mysql;
mod postgres;

use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

pub use amqp::{AmqpDeclare, AmqpMessage, AmqpServer, AmqpSetup};
use aws_lc_rs::{digest, hmac, pbkdf2};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use http_body_util::BodyExt;
pub use kafka::{KafkaRecord, KafkaServer, KafkaSetup};
pub use mysql::{MyAuth, MyPassword, MyStartup, MysqlServer, MysqlSetup, rsa_public_key_pem};
pub use postgres::{PgAuth, PgImpostor, PgStartup, PostgresServer, PostgresSetup};

/// One request taken.
#[derive(Debug, Clone)]
pub struct Post {
    /// Its method.
    pub method: String,
    /// Its path.
    pub path: String,
    /// Its `Authorization`, or empty.
    pub authorization: String,
    /// Its `Content-Type`, or empty.
    pub content_type: String,
    /// Its body.
    pub body: String,
}

#[derive(Debug, Default)]
struct State {
    failing: AtomicUsize,
    tries: AtomicUsize,
    posts: Mutex<Vec<Post>>,
    /// Paths answered with `404` until something is `PUT` there.
    missing: Mutex<Vec<String>>,
}

/// The receiver.
#[derive(Debug, Clone)]
pub struct Receiver {
    url: String,
    state: Arc<State>,
}

impl Receiver {
    /// Starts one that fails the first `failing` `POST`s with `500`.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(failing: usize) -> Self {
        let state = Arc::new(State::default());
        state.failing.store(failing, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let url = format!(
            "http://{}/hook",
            listener.local_addr().expect("a bound address")
        );
        let served = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&served);
                let service = hyper::service::service_fn(move |req| take(Arc::clone(&state), req));
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service),
                );
            }
        });
        Self { url, state }
    }

    /// Its URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Answers `404` for `path` until something is `PUT` there.
    pub fn missing(&self, path: &str) {
        self.state
            .missing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(path.to_owned());
    }

    /// Fails the next `count` `POST`s.
    pub fn fail(&self, count: usize) {
        self.state.failing.store(count, Ordering::SeqCst);
    }

    /// How many `POST`s came, taken or not.
    #[must_use]
    pub fn tries(&self) -> usize {
        self.state.tries.load(Ordering::SeqCst)
    }

    /// The `POST`s taken so far.
    #[must_use]
    pub fn taken(&self) -> Vec<Post> {
        self.state
            .posts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The `POST`s taken, once there are at least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn posts(&self, count: usize) -> Vec<Post> {
        for _ in 0..500 {
            let taken = self.taken();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the webhook never took {count} posts");
    }
}

async fn take(
    state: Arc<State>,
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<http_body_util::Empty<hyper::body::Bytes>>, Infallible> {
    let header = |name| {
        req.headers()
            .get(name)
            .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let (authorization, content_type) = (header("authorization"), header("content-type"));
    let (method, path) = (req.method().to_string(), req.uri().path().to_owned());
    {
        let mut missing = state.missing.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = missing.iter().position(|p| *p == path) {
            if method != "PUT" {
                return Ok(hyper::Response::builder()
                    .status(404)
                    .body(http_body_util::Empty::new())
                    .expect("a valid response"));
            }
            missing.remove(i);
        }
    }
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
        .unwrap_or_default();
    state.tries.fetch_add(1, Ordering::SeqCst);
    let fail = state
        .failing
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok();
    let status = if fail {
        500
    } else {
        state
            .posts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Post {
                method,
                path,
                authorization,
                content_type,
                body,
            });
        200
    };
    Ok(hyper::Response::builder()
        .status(status)
        .body(http_body_util::Empty::new())
        .expect("a valid response"))
}

/// A Redis server on this machine, for tests: it answers the commands a Redis target
/// sends and keeps them.
#[derive(Debug, Clone)]
pub struct RedisServer {
    address: String,
    commands: Arc<Mutex<Vec<Vec<String>>>>,
}

impl RedisServer {
    /// Starts one whose keys all have type `kind` (`none`, `hash`, `list`…) and which
    /// wants `password`, if any.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(kind: &str, password: Option<&str>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let address = listener.local_addr().expect("a bound address").to_string();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let (kind, password) = (kind.to_owned(), password.map(str::to_owned));
        let kept = Arc::clone(&commands);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (kept, kind, password) = (Arc::clone(&kept), kind.clone(), password.clone());
                tokio::spawn(async move {
                    let mut stream = tokio::io::BufReader::new(stream);
                    let mut authenticated = password.is_none();
                    while let Ok(crate::redis::Reply::Array(Some(parts))) =
                        crate::redis::read_reply(&mut stream, 0).await
                    {
                        let command: Vec<String> = parts
                            .into_iter()
                            .map(|p| match p {
                                crate::redis::Reply::Bulk(Some(b)) => {
                                    String::from_utf8_lossy(&b).into_owned()
                                }
                                other => format!("{other:?}"),
                            })
                            .collect();
                        let name = command[0].to_ascii_uppercase();
                        let reply: &[u8] = match name.as_str() {
                            "AUTH" => {
                                authenticated =
                                    command.last().map(String::as_str) == password.as_deref();
                                if authenticated {
                                    b"+OK\r\n"
                                } else {
                                    b"-WRONGPASS invalid\r\n"
                                }
                            }
                            _ if !authenticated => b"-NOAUTH Authentication required.\r\n",
                            "PING" => b"+PONG\r\n",
                            "TYPE" => {
                                let reply = format!("+{kind}\r\n");
                                kept.lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .push(command);
                                let _ = tokio::io::AsyncWriteExt::write_all(
                                    stream.get_mut(),
                                    reply.as_bytes(),
                                )
                                .await;
                                continue;
                            }
                            "HSET" | "HDEL" | "RPUSH" => b":1\r\n",
                            _ => b"+OK\r\n",
                        };
                        if name != "AUTH" {
                            kept.lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .push(command);
                        }
                        if tokio::io::AsyncWriteExt::write_all(stream.get_mut(), reply)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        Self { address, commands }
    }

    /// Its `HOST:PORT`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The commands it took (but `AUTH`), once there are at least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn commands(&self, count: usize) -> Vec<Vec<String>> {
        for _ in 0..500 {
            let taken = self
                .commands
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the Redis server never took {count} commands");
    }
}

/// An `nsqd` on this machine, for tests: it takes `IDENTIFY` and `PUB`, sends a
/// heartbeat before each answer (which a client must answer with `NOP`), and keeps what's
/// published.
#[derive(Debug, Clone)]
pub struct NsqServer {
    address: String,
    published: Arc<Mutex<Vec<(String, String)>>>,
    nops: Arc<AtomicUsize>,
}

impl NsqServer {
    /// Starts one.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start() -> Self {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let address = listener.local_addr().expect("a bound address").to_string();
        let published = Arc::new(Mutex::new(Vec::new()));
        let nops = Arc::new(AtomicUsize::new(0));
        let (kept, counted) = (Arc::clone(&published), Arc::clone(&nops));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (kept, counted) = (Arc::clone(&kept), Arc::clone(&counted));
                tokio::spawn(async move {
                    let mut stream = tokio::io::BufReader::new(stream);
                    let mut magic = [0; 4];
                    if stream.read_exact(&mut magic).await.is_err() || magic != *crate::nsq::MAGIC {
                        return;
                    }
                    let frame = |kind: u32, data: &[u8]| {
                        let mut out = (u32::try_from(data.len()).expect("short") + 4)
                            .to_be_bytes()
                            .to_vec();
                        out.extend_from_slice(&kind.to_be_bytes());
                        out.extend_from_slice(data);
                        out
                    };
                    loop {
                        let mut line = String::new();
                        if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let line = line.trim_end().to_owned();
                        if line == "NOP" {
                            counted.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        let Ok(size) = stream.read_u32().await else {
                            return;
                        };
                        let mut body = vec![0; size as usize];
                        if stream.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let reply = match line.split_once(' ') {
                            Some(("PUB", topic)) => {
                                kept.lock().unwrap_or_else(PoisonError::into_inner).push((
                                    topic.to_owned(),
                                    String::from_utf8_lossy(&body).into_owned(),
                                ));
                                frame(0, b"OK")
                            }
                            None if line == "IDENTIFY" => frame(0, b"OK"),
                            _ => frame(1, b"E_INVALID"),
                        };
                        let mut out = frame(0, crate::nsq::HEARTBEAT);
                        out.extend_from_slice(&reply);
                        if stream.get_mut().write_all(&out).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            address,
            published,
            nops,
        }
    }

    /// Its `HOST:PORT`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// How many heartbeats were answered.
    #[must_use]
    pub fn nops(&self) -> usize {
        self.nops.load(Ordering::SeqCst)
    }

    /// What was published, as (topic, body), once there are at least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn published(&self, count: usize) -> Vec<(String, String)> {
        for _ in 0..500 {
            let taken = self
                .published
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the nsqd never took {count} messages");
    }
}

/// How a [`NatsServer`] behaves.
#[derive(Clone, Default)]
pub struct NatsSetup {
    /// The user and password it wants.
    pub user: Option<(String, String)>,
    /// The token it wants.
    pub token: Option<String>,
    /// The user keys (`U…`) it takes, its nonce signed by one of them (alone, or the
    /// subject of a user JWT); none for no nkeys.
    pub nkeys: Vec<String>,
    /// Its TLS, and whether it starts before `INFO` (`handshake_first`) rather than
    /// being required after it.
    pub tls: Option<(tokio_rustls::TlsAcceptor, bool)>,
    /// `JetStream`'s streams, as (name, subject); none without `JetStream`.
    pub streams: Option<Vec<(String, String)>>,
    /// Whether it takes headers (and so answers "no responders").
    pub headers: bool,
}

/// A message a [`NatsServer`] took.
#[derive(Debug, Clone)]
pub struct Published {
    /// Its subject.
    pub subject: String,
    /// Its reply subject.
    pub reply: Option<String>,
    /// Its `Nats-Msg-Id`.
    pub id: Option<String>,
    /// Its body.
    pub body: String,
}

/// A NATS server that takes `CONNECT` as it's set up to, keeps what's published, and
/// acknowledges what its streams take as `JetStream` does.
pub struct NatsServer {
    address: String,
    published: Arc<Mutex<Vec<Published>>>,
    connects: Arc<Mutex<Vec<serde_json::Value>>>,
    kick: tokio::sync::watch::Sender<u64>,
}

impl NatsServer {
    /// Starts one.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(setup: NatsSetup) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let address = listener.local_addr().expect("a bound address").to_string();
        let server = Self {
            address,
            published: Arc::new(Mutex::new(Vec::new())),
            connects: Arc::new(Mutex::new(Vec::new())),
            kick: tokio::sync::watch::channel(0).0,
        };
        let shared = Arc::new(NatsShared {
            setup,
            published: Arc::clone(&server.published),
            connects: Arc::clone(&server.connects),
            ids: Mutex::new(Vec::new()),
        });
        let kick = server.kick.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (shared, kicked) = (Arc::clone(&shared), kick.subscribe());
                tokio::spawn(async move {
                    let _ = shared.serve(stream, kicked).await;
                });
            }
        });
        server
    }

    /// Its `HOST:PORT`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Closes every connection, as a server does one it hasn't heard from.
    pub fn kick(&self) {
        self.kick.send_modify(|n| *n += 1);
    }

    /// The `CONNECT`s taken.
    #[must_use]
    pub fn connects(&self) -> Vec<serde_json::Value> {
        self.connects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What was published, not counting `JetStream` API requests, once there are at
    /// least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn published(&self, count: usize) -> Vec<Published> {
        for _ in 0..500 {
            let taken: Vec<Published> = self
                .published
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|p| !p.subject.starts_with("$JS.API."))
                .cloned()
                .collect();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the NATS server never took {count} messages");
    }
}

struct NatsShared {
    setup: NatsSetup,
    published: Arc<Mutex<Vec<Published>>>,
    connects: Arc<Mutex<Vec<serde_json::Value>>>,
    /// The `Nats-Msg-Id`s its streams took.
    ids: Mutex<Vec<String>>,
}

impl NatsShared {
    /// The nonce it wants signed.
    const NONCE: &str = "a-nonce-to-sign";

    /// Sends `INFO`, with TLS before or after it as set up.
    async fn greet(&self, tcp: tokio::net::TcpStream) -> Result<crate::net::Stream, String> {
        use tokio::io::AsyncWriteExt;
        let io = |e: std::io::Error| e.to_string();
        let setup = &self.setup;
        let info = serde_json::json!({
            "server_id": "test",
            "version": "2.11.0",
            "proto": 1,
            "headers": setup.headers,
            "max_payload": 4096,
            "tls_required": setup.tls.is_some(),
            "auth_required": setup.user.is_some() || setup.token.is_some() || !setup.nkeys.is_empty(),
            "nonce": (!setup.nkeys.is_empty()).then_some(Self::NONCE),
            "jetstream": setup.streams.is_some(),
        });
        let info = format!("INFO {info}\r\n");
        let mut stream: crate::net::Stream = match &setup.tls {
            Some((acceptor, true)) => Box::new(acceptor.accept(tcp).await.map_err(io)?),
            _ => Box::new(tcp),
        };
        stream.write_all(info.as_bytes()).await.map_err(io)?;
        if let Some((acceptor, false)) = &setup.tls {
            stream = Box::new(acceptor.accept(stream).await.map_err(io)?);
        }
        Ok(stream)
    }

    async fn serve(
        &self,
        tcp: tokio::net::TcpStream,
        mut kicked: tokio::sync::watch::Receiver<u64>,
    ) -> Result<(), String> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        let io = |e: std::io::Error| e.to_string();
        let mut stream = tokio::io::BufReader::new(self.greet(tcp).await?);
        let mut inbox: Option<(String, String)> = None;
        loop {
            let mut line = String::new();
            tokio::select! {
                read = stream.read_line(&mut line) => {
                    if read.unwrap_or(0) == 0 {
                        return Ok(());
                    }
                }
                _ = kicked.changed() => return Ok(()),
            }
            let words: Vec<&str> = line.split_ascii_whitespace().collect();
            let mut out = Vec::new();
            match words.first().copied().unwrap_or_default() {
                "CONNECT" => {
                    let connect: serde_json::Value =
                        serde_json::from_str(line["CONNECT".len()..].trim())
                            .map_err(|e| e.to_string())?;
                    let allowed = self.allows(&connect, Self::NONCE);
                    self.connects
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(connect);
                    if !allowed {
                        let _ = stream
                            .get_mut()
                            .write_all(b"-ERR 'Authorization Violation'\r\n")
                            .await;
                        return Ok(());
                    }
                }
                "PING" => out.extend_from_slice(b"PONG\r\n"),
                "SUB" if words.len() == 3 => {
                    let prefix = words[1].strip_suffix('*').unwrap_or(words[1]).to_owned();
                    inbox = Some((prefix, words[2].to_owned()));
                }
                verb @ ("PUB" | "HPUB") => {
                    let headers = verb == "HPUB";
                    let sizes = if headers { 2 } else { 1 };
                    if words.len() < 2 + sizes {
                        return Err(format!("a bad {verb}"));
                    }
                    let total: usize = words[words.len() - 1].parse().map_err(|_| "a bad size")?;
                    let head: usize = if headers {
                        words[words.len() - 2].parse().map_err(|_| "a bad size")?
                    } else {
                        0
                    };
                    let mut data = vec![0; total + 2];
                    stream.read_exact(&mut data).await.map_err(io)?;
                    let head_text = String::from_utf8_lossy(&data[..head]).into_owned();
                    let id = head_text
                        .lines()
                        .find_map(|l| l.strip_prefix("Nats-Msg-Id: "))
                        .map(str::to_owned);
                    let reply = (words.len() == 3 + sizes).then(|| words[2].to_owned());
                    let message = Published {
                        subject: words[1].to_owned(),
                        reply: reply.clone(),
                        id,
                        body: String::from_utf8_lossy(&data[head..total]).into_owned(),
                    };
                    if let (Some(reply), Some((prefix, sid))) = (reply, &inbox)
                        && reply.starts_with(prefix.as_str())
                    {
                        out = self.answer(&message, &reply, sid);
                    }
                    self.published
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(message);
                }
                _ => out.extend_from_slice(b"-ERR 'Unknown Protocol Operation'\r\n"),
            }
            if !out.is_empty() {
                stream.get_mut().write_all(&out).await.map_err(io)?;
            }
        }
    }

    /// Whether `connect` has the credentials it wants.
    fn allows(&self, connect: &serde_json::Value, nonce: &str) -> bool {
        let setup = &self.setup;
        let text = |name: &str| connect[name].as_str().unwrap_or_default().to_owned();
        if let Some((user, password)) = &setup.user {
            return text("user") == *user && text("pass") == *password;
        }
        if let Some(token) = &setup.token {
            return text("auth_token") == *token;
        }
        if !setup.nkeys.is_empty() {
            use base64::Engine as _;
            let public = match connect["jwt"].as_str() {
                Some(jwt) => jwt
                    .split('.')
                    .nth(1)
                    .and_then(|p| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(p)
                            .ok()
                    })
                    .and_then(|p| serde_json::from_slice::<serde_json::Value>(&p).ok())
                    .and_then(|p| p["sub"].as_str().map(str::to_owned))
                    .unwrap_or_default(),
                None => text("nkey"),
            };
            return setup.nkeys.contains(&public)
                && crate::nkey::verifies(&public, nonce, &text("sig"));
        }
        true
    }

    /// The reply to a request, as `JetStream` gives it: the streams that take a subject,
    /// an acknowledgement, or no responders.
    fn answer(&self, message: &Published, reply: &str, sid: &str) -> Vec<u8> {
        let no_responders = || format!("HMSG {reply} {sid} 16 16\r\nNATS/1.0 503\r\n\r\n\r\n");
        let Some(streams) = &self.setup.streams else {
            return no_responders().into_bytes();
        };
        let body = if message.subject == crate::nats::STREAM_NAMES {
            let asked: serde_json::Value = serde_json::from_str(&message.body).unwrap_or_default();
            let names: Vec<&str> = streams
                .iter()
                .filter(|(_, subject)| asked["subject"] == subject.as_str())
                .map(|(name, _)| name.as_str())
                .collect();
            serde_json::json!({ "total": names.len(), "streams": names })
        } else if let Some((name, _)) = streams.iter().find(|(_, s)| *s == message.subject) {
            let mut ids = self.ids.lock().unwrap_or_else(PoisonError::into_inner);
            let duplicate = message.id.as_ref().is_some_and(|id| ids.contains(id));
            if !duplicate {
                ids.extend(message.id.clone());
            }
            serde_json::json!({ "stream": name, "seq": ids.len(), "duplicate": duplicate })
        } else if message.subject.starts_with("$JS.API.") {
            serde_json::json!({ "error": { "code": 400, "err_code": 10003, "description": "bad request" } })
        } else {
            return no_responders().into_bytes();
        };
        let body = body.to_string();
        format!("MSG {reply} {sid} {}\r\n{body}\r\n", body.len()).into_bytes()
    }
}

/// A user seed of the `nkeys` project's tests.
pub const NKEY_SEED: &str = "SUAOTBNEUHZDFJT3EUMELT7MQTP24JF3XVCXQNDSCU74G5IU6VAJBKH5LI";
/// [`NKEY_SEED`]'s public key.
pub const NKEY_PUBLIC: &str = "UDE6WTGLTTPCRJRJCKBJRGVNZTLIVR7LEEELR4CYWWWBKJS7XYIKXDUU";
/// A user JWT of the `nkeys` project's tests, for [`NKEY_PUBLIC`].
pub const NKEY_JWT: &str = "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJHVDROVU5NRUY3Wk1XQ1JCWFZWVURLUVQ2WllQWjc3VzRKUlFYRDNMMjRIS1VKRUNRSDdRIiwiaWF0IjoxNTkwNzgxNTkzLCJpc3MiOiJBQURXTFRISUNWNFNVQUdGNkVLTlZFVzVCQlA3WVJESUJHV0dHSFo1SkJET1FZQTdHVUZNNkFRVSIsIm5hbWUiOiJPUEVSQVRPUiIsInN1YiI6IlVERTZXVEdMVFRQQ1JKUkpDS0JKUkdWTlpUTElWUjdMRUVFTFI0Q1lXV1dCS0pTN1hZSUtYRFVVIiwibmF0cyI6eyJwdWIiOnt9LCJzdWIiOnt9LCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.c_XQT04wEoVVNDRjPHeKwe17BOrSpQTcftwIbB7KoNEIz6peZCJDc4-J3emVepHofUOWy7IAo9TlLwYhuGHWAQ";

/// A `.creds` file as `nsc` writes it, of [`NKEY_JWT`] and [`NKEY_SEED`].
#[must_use]
pub fn creds() -> String {
    format!(
        "-----BEGIN NATS USER JWT-----\n{NKEY_JWT}\n------END NATS USER JWT------\n\n\
         ************************* IMPORTANT *************************\n\
         NKEY Seed printed below can be used to sign and prove identity.\n\n\
         -----BEGIN USER NKEY SEED-----\n{NKEY_SEED}\n------END USER NKEY SEED------\n\n\
         *************************************************************\n"
    )
}

/// A message an [`MqttServer`] took.
#[derive(Debug, Clone)]
pub struct MqttMessage {
    /// Its topic.
    pub topic: String,
    /// Its quality of service.
    pub qos: u8,
    /// Its body.
    pub body: String,
}

/// A client's `CONNECT`, as an [`MqttServer`] read it.
#[derive(Debug, Clone)]
pub struct MqttConnect {
    /// Its client id.
    pub client_id: String,
    /// Whether it asked for a clean session.
    pub clean: bool,
    /// Its keep alive, in seconds.
    pub keep_alive: u16,
    /// Its user.
    pub user: Option<String>,
}

/// An MQTT 3.1.1 broker that takes a user and password, if set up with one, and keeps
/// what's published, acknowledging each as its quality of service asks.
pub struct MqttServer {
    address: String,
    published: Arc<Mutex<Vec<MqttMessage>>>,
    connects: Arc<Mutex<Vec<MqttConnect>>>,
    denied: Arc<Mutex<Vec<String>>>,
}

impl MqttServer {
    /// Starts one that wants `login` (user, password), if any.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(login: Option<(&str, &str)>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let server = Self {
            address: listener.local_addr().expect("a bound address").to_string(),
            published: Arc::new(Mutex::new(Vec::new())),
            connects: Arc::new(Mutex::new(Vec::new())),
            denied: Arc::new(Mutex::new(Vec::new())),
        };
        let login = login.map(|(u, p)| (u.to_owned(), p.to_owned()));
        let (published, connects, denied) = (
            Arc::clone(&server.published),
            Arc::clone(&server.connects),
            Arc::clone(&server.denied),
        );
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (published, connects, denied, login) = (
                    Arc::clone(&published),
                    Arc::clone(&connects),
                    Arc::clone(&denied),
                    login.clone(),
                );
                tokio::spawn(async move {
                    let _ = mqtt_serve(stream, login, &published, &connects, &denied).await;
                });
            }
        });
        server
    }

    /// Closes the connection of a client that publishes to `topic`, without taking it,
    /// as a broker does a publish it doesn't allow.
    pub fn deny(&self, topic: &str) {
        self.denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(topic.to_owned());
    }

    /// Its `HOST:PORT`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The `CONNECT`s taken.
    #[must_use]
    pub fn connects(&self) -> Vec<MqttConnect> {
        self.connects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What was published, once there are at least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn published(&self, count: usize) -> Vec<MqttMessage> {
        for _ in 0..500 {
            let taken = self
                .published
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the MQTT broker never took {count} messages");
    }
}

async fn mqtt_serve(
    stream: tokio::net::TcpStream,
    login: Option<(String, String)>,
    published: &Mutex<Vec<MqttMessage>>,
    connects: &Mutex<Vec<MqttConnect>>,
    denied: &Mutex<Vec<String>>,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;

    use crate::mqtt::{packet, read_packet};
    fn string(body: &[u8], at: &mut usize) -> Option<Vec<u8>> {
        let size = usize::from(u16::from_be_bytes([*body.get(*at)?, *body.get(*at + 1)?]));
        let out = body.get(*at + 2..*at + 2 + size)?.to_vec();
        *at += 2 + size;
        Some(out)
    }
    let mut stream = tokio::io::BufReader::new(stream);
    let bad = || "a bad packet".to_owned();
    let (first, body) = read_packet(&mut stream, 1 << 20).await?;
    if first != packet::CONNECT << 4 || body.get(..7) != Some(b"\0\x04MQTT\x04") {
        return Err(bad());
    }
    let flags = body[7];
    let keep_alive = u16::from_be_bytes([body[8], body[9]]);
    let mut at = 10;
    let client_id = String::from_utf8_lossy(&string(&body, &mut at).ok_or_else(bad)?).into_owned();
    let user = (flags & 0x80 != 0)
        .then(|| string(&body, &mut at).map(|u| String::from_utf8_lossy(&u).into_owned()))
        .flatten();
    let password = (flags & 0x40 != 0)
        .then(|| string(&body, &mut at).map(|p| String::from_utf8_lossy(&p).into_owned()))
        .flatten();
    connects
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(MqttConnect {
            client_id,
            clean: flags & 0x02 != 0,
            keep_alive,
            user: user.clone(),
        });
    let allowed =
        login.is_none_or(|(u, p)| user.as_ref() == Some(&u) && password.as_ref() == Some(&p));
    let code = if allowed { 0 } else { 4 };
    let io = |e: std::io::Error| e.to_string();
    stream
        .get_mut()
        .write_all(&[packet::CONNACK << 4, 2, 0, code])
        .await
        .map_err(io)?;
    if !allowed {
        return Ok(());
    }
    loop {
        let (first, body) = read_packet(&mut stream, 1 << 20).await?;
        let reply: Vec<u8> = match first >> 4 {
            packet::PUBLISH => {
                let qos = (first >> 1) & 3;
                let mut at = 0;
                let topic =
                    String::from_utf8_lossy(&string(&body, &mut at).ok_or_else(bad)?).into_owned();
                if denied
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .contains(&topic)
                {
                    return Ok(());
                }
                let id = if qos > 0 {
                    let id = body.get(at..at + 2).ok_or_else(bad)?.to_vec();
                    at += 2;
                    id
                } else {
                    Vec::new()
                };
                published
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(MqttMessage {
                        topic,
                        qos,
                        body: String::from_utf8_lossy(&body[at..]).into_owned(),
                    });
                match qos {
                    0 => Vec::new(),
                    1 => [&[packet::PUBACK << 4, 2][..], &id].concat(),
                    _ => [&[packet::PUBREC << 4, 2][..], &id].concat(),
                }
            }
            packet::PUBREL if first & 0x0f == 0b0010 => {
                [&[packet::PUBCOMP << 4, 2][..], &body].concat()
            }
            packet::PINGREQ => vec![packet::PINGRESP << 4, 0],
            _ => return Err(bad()),
        };
        if !reply.is_empty() {
            stream.get_mut().write_all(&reply).await.map_err(io)?;
        }
    }
}

/// A request an [`AwsServer`] took.
#[derive(Debug, Clone)]
pub struct AwsRequest {
    /// Its `X-Amz-Target` for the JSON protocols, `AmazonSNS.Publish` for SNS's,
    /// `Lambda.Invoke:TYPE` for Lambda's.
    pub target: String,
    /// Its path.
    pub path: String,
    /// Its body.
    pub body: String,
    /// The message it sends: SQS's `MessageBody`, SNS's `Message`, Lambda's payload,
    /// EventBridge's `Entries`.
    pub message: String,
}

/// A server that answers as AWS's SQS (`SendMessage` in its JSON protocol), SNS
/// (`Publish` in its Query protocol), Lambda (`Invoke`) and EventBridge (`PutEvents`) do, and takes only requests signed with its keys for
/// its region.
pub struct AwsServer {
    url: String,
    state: Arc<AwsState>,
}

struct AwsState {
    region: String,
    access_key: String,
    secret: String,
    requests: Mutex<Vec<AwsRequest>>,
    missing: Mutex<Vec<String>>,
    wrong_digest: std::sync::atomic::AtomicBool,
}

impl AwsState {
    /// Whether the queue or topic `name` was said not to exist.
    fn is_missing(&self, name: &str) -> bool {
        self.missing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|m| m == name)
    }
}

impl AwsServer {
    /// Starts one for `region` that takes requests signed with `access_key` and
    /// `secret`.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(region: &str, access_key: &str, secret: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let url = format!("http://{}", listener.local_addr().expect("a bound address"));
        let state = Arc::new(AwsState {
            region: region.to_owned(),
            access_key: access_key.to_owned(),
            secret: secret.to_owned(),
            requests: Mutex::new(Vec::new()),
            missing: Mutex::new(Vec::new()),
            wrong_digest: false.into(),
        });
        let served = Arc::clone(&state);
        let base = url.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (state, base) = (Arc::clone(&served), base.clone());
                let service = hyper::service::service_fn(move |req| {
                    aws_answer(Arc::clone(&state), base.clone(), req)
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service),
                );
            }
        });
        Self { url, state }
    }

    /// Its URL, `http://HOST:PORT`.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Answers that the queue at `queue_url`, or the topic or function with that ARN,
    /// doesn't exist.
    pub fn missing(&self, queue_url: &str) {
        self.state
            .missing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(queue_url.to_owned());
    }

    /// Answers wrongly: SQS with a digest that doesn't match what was sent, SNS without
    /// a message id, Lambda with the status of a synchronous call, EventBridge failing
    /// each entry.
    pub fn wrong_digest(&self, wrong: bool) {
        self.state.wrong_digest.store(wrong, Ordering::SeqCst);
    }

    /// The requests taken, once there are at least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn requests(&self, count: usize) -> Vec<AwsRequest> {
        for _ in 0..500 {
            let taken = self
                .state
                .requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the AWS server never took {count} requests");
    }
}

/// Seconds since 1970 of `YYYYMMDDTHHMMSSZ`.
fn amz_date(text: &str) -> Option<u64> {
    let n = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(4..6)?, n(6..8)?);
    let (hh, mm, ss) = (n(9..11)?, n(11..13)?, n(13..15)?);
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

/// The `Authorization` a request with these parts would have, signed with `state`'s
/// keys for `service` in its region at `date`.
fn aws_expected(
    state: &AwsState,
    service: &str,
    url: &str,
    headers: &[(String, String)],
    date: &str,
    token: Option<&str>,
    body: &[u8],
) -> Option<String> {
    use aws_sigv4::{
        http_request::{SignableBody, SignableRequest, SigningSettings, sign},
        sign::v4,
    };
    let identity = aws_credential_types::Credentials::new(
        &state.access_key,
        &state.secret,
        token.map(str::to_owned),
        None,
        "test",
    )
    .into();
    let time = std::time::UNIX_EPOCH + Duration::from_secs(amz_date(date)?);
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&state.region)
        .name(service)
        .time(time)
        .settings(SigningSettings::default())
        .build()
        .ok()?
        .into();
    let signable = SignableRequest::new(
        "POST",
        url,
        headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
        SignableBody::Bytes(body),
    )
    .ok()?;
    let (instructions, _) = sign(signable, &params).ok()?.into_parts();
    instructions
        .headers()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.to_owned())
}

async fn aws_answer(
    state: Arc<AwsState>,
    base: String,
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let invocation = header("x-amz-invocation-type");
    let (authorization, date, token, target) = (
        header("authorization"),
        header("x-amz-date"),
        header("x-amz-security-token"),
        header("x-amz-target"),
    );
    let signed: Vec<String> = authorization
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .map(|list| list.split(';').map(str::to_owned).collect())
        .unwrap_or_default();
    let headers: Vec<(String, String)> = signed
        .iter()
        .filter(|name| !matches!(name.as_str(), "x-amz-date" | "x-amz-security-token"))
        .map(|name| (name.clone(), header(name)))
        .collect();
    let path = req.uri().path().to_owned();
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();
    let form: std::collections::BTreeMap<String, String> =
        form_urlencoded::parse(&body).into_owned().collect();
    let sns = form.get("Action").is_some_and(|a| a == "Publish");
    let lambda = path.starts_with("/2015-03-31/functions/");
    let service = if target.starts_with("AmazonSQS.") {
        "sqs"
    } else if target.starts_with("AWSEvents.") {
        "events"
    } else if lambda {
        "lambda"
    } else if sns {
        "sns"
    } else {
        "unknown"
    };
    let url = format!("{base}{path}");
    let token = (!token.is_empty()).then_some(token.as_str());
    let signed = aws_expected(&state, service, &url, &headers, &date, token, &body).as_deref()
        == Some(authorization.as_str());
    if sns {
        return sns_answer(&state, signed, path, &body, &form);
    }
    if lambda {
        return Ok(lambda_answer(&state, signed, &invocation, path, &body));
    }
    if target == "AWSEvents.PutEvents" {
        return Ok(events_answer(&state, signed, path, &body));
    }
    sqs_answer(&state, signed, &target, path, &body)
}

/// SNS's answer to a `Publish`, `signed` or not.
fn sns_answer(
    state: &AwsState,
    signed: bool,
    path: String,
    body: &[u8],
    form: &std::collections::BTreeMap<String, String>,
) -> Result<hyper::Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    let xml = |status: u16, body: String| {
        Ok(hyper::Response::builder()
            .status(status)
            .header("content-type", "text/xml")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
            .expect("a valid response"))
    };
    let error = |status, code: &str, message: &str| {
        xml(
            status,
            format!(
                "<ErrorResponse xmlns=\"https://sns.amazonaws.com/doc/2010-03-31/\"><Error>\
                 <Type>Sender</Type><Code>{code}</Code><Message>{message}</Message></Error>\
                 <RequestId>1</RequestId></ErrorResponse>"
            ),
        )
    };
    if !signed {
        return error(
            403,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
        );
    }
    state
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(AwsRequest {
            target: "AmazonSNS.Publish".to_owned(),
            path,
            body: String::from_utf8_lossy(body).into_owned(),
            message: form.get("Message").cloned().unwrap_or_default(),
        });
    let topic = form.get("TopicArn").map_or("", String::as_str);
    if state.is_missing(topic) {
        return error(404, "NotFound", "Topic does not exist");
    }
    let fifo = topic.strip_suffix(".fifo").is_some();
    if fifo != form.contains_key("MessageGroupId") {
        return error(400, "InvalidParameter", "Invalid parameter: MessageGroupId");
    }
    if state.wrong_digest.load(Ordering::SeqCst) {
        return xml(
            200,
            "<PublishResponse><PublishResult/></PublishResponse>".to_owned(),
        );
    }
    xml(
        200,
        "<PublishResponse xmlns=\"https://sns.amazonaws.com/doc/2010-03-31/\"><PublishResult>\
         <MessageId>94f20ce6-13c5-43a0-9a9e-ca52d816e90b</MessageId></PublishResult>\
         <ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></PublishResponse>"
            .to_owned(),
    )
}

/// SQS's answer to a request in its JSON protocol, `signed` or not.
fn sqs_answer(
    state: &AwsState,
    signed: bool,
    target: &str,
    path: String,
    body: &[u8],
) -> Result<hyper::Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    use md5::Digest as _;
    let reply = |status: u16, body: String| {
        Ok(hyper::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.0")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
            .expect("a valid response"))
    };
    if !signed {
        return reply(
            403,
            r#"{"__type":"com.amazon.coral.service#InvalidSignatureException","message":"The request signature we calculated does not match the signature you provided."}"#.to_owned(),
        );
    }
    let request: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    state
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(AwsRequest {
            target: target.to_owned(),
            path,
            body: String::from_utf8_lossy(body).into_owned(),
            message: request["MessageBody"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        });
    if target != "AmazonSQS.SendMessage" {
        return reply(
            400,
            r#"{"__type":"com.amazonaws.sqs#UnsupportedOperation","message":"no"}"#.to_owned(),
        );
    }
    if state.is_missing(request["QueueUrl"].as_str().unwrap_or_default()) {
        return reply(
            400,
            r#"{"__type":"com.amazonaws.sqs#QueueDoesNotExist","message":"The specified queue does not exist."}"#.to_owned(),
        );
    }
    let message = request["MessageBody"].as_str().unwrap_or_default();
    let mut digest = md5::Md5::digest(message.as_bytes()).to_vec();
    if state.wrong_digest.load(Ordering::SeqCst) {
        digest[0] ^= 1;
    }
    reply(
        200,
        serde_json::json!({
            "MD5OfMessageBody": crate::aws::hex(&digest),
            "MessageId": "5fea7756-0ea4-451a-a703-a558b933e274",
        })
        .to_string(),
    )
}

/// Lambda's answer to an `Invoke`, `signed` or not.
fn lambda_answer(
    state: &AwsState,
    signed: bool,
    invocation: &str,
    path: String,
    body: &[u8],
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    let answer = |status: u16, error: Option<(&str, &str)>| {
        let mut response = hyper::Response::builder()
            .status(status)
            .header("content-type", "application/json");
        let mut body = String::new();
        if let Some((kind, message)) = error {
            response = response.header(
                "x-amzn-ErrorType",
                format!("{kind}:http://internal.amazon.com/coral/com.amazonaws.lambda/"),
            );
            body = serde_json::json!({ "Type": "User", "message": message }).to_string();
        }
        response
            .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
            .expect("a valid response")
    };
    if !signed {
        return answer(
            403,
            Some((
                "InvalidSignatureException",
                "The request signature we calculated does not match the signature you provided.",
            )),
        );
    }
    let function = path
        .trim_start_matches("/2015-03-31/functions/")
        .trim_end_matches("/invocations")
        .replace("%3A", ":")
        .replace("%24", "$");
    state
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(AwsRequest {
            target: format!("Lambda.Invoke:{invocation}"),
            path,
            body: String::from_utf8_lossy(body).into_owned(),
            message: String::from_utf8_lossy(body).into_owned(),
        });
    if state.is_missing(&function) {
        return answer(
            404,
            Some((
                "ResourceNotFoundException",
                &format!("Function not found: {function}"),
            )),
        );
    }
    if state.wrong_digest.load(Ordering::SeqCst) {
        return answer(200, None);
    }
    match invocation {
        "Event" => answer(202, None),
        "DryRun" => answer(204, None),
        _ => answer(
            400,
            Some((
                "InvalidParameterValueException",
                "Unsupported invocation type",
            )),
        ),
    }
}

/// EventBridge's answer to a `PutEvents`, `signed` or not: an entry for a bus said not to
/// exist fails, as EventBridge fails entries one by one.
fn events_answer(
    state: &AwsState,
    signed: bool,
    path: String,
    body: &[u8],
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    let answer = |status: u16, body: serde_json::Value| {
        hyper::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.1")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body.to_string(),
            )))
            .expect("a valid response")
    };
    if !signed {
        return answer(
            400,
            serde_json::json!({
                "__type": "InvalidSignatureException",
                "message": "The request signature we calculated does not match the signature you provided.",
            }),
        );
    }
    let request: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    state
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(AwsRequest {
            target: "AWSEvents.PutEvents".to_owned(),
            path,
            body: String::from_utf8_lossy(body).into_owned(),
            message: request["Entries"].to_string(),
        });
    let wrong = state.wrong_digest.load(Ordering::SeqCst);
    let entries: Vec<serde_json::Value> = request["Entries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let bus = entry["EventBusName"].as_str().unwrap_or_default();
            if state.is_missing(bus) {
                serde_json::json!({
                    "ErrorCode": "ResourceNotFoundException",
                    "ErrorMessage": format!("Event bus {bus} does not exist."),
                })
            } else if wrong {
                serde_json::json!({ "ErrorCode": "InternalFailure", "ErrorMessage": "try again" })
            } else {
                serde_json::json!({ "EventId": "11710aed-b79e-4468-a20b-bb3c0c3b4860" })
            }
        })
        .collect();
    let failed = entries
        .iter()
        .filter(|e| e["ErrorCode"].is_string())
        .count();
    answer(
        200,
        serde_json::json!({ "FailedEntryCount": failed, "Entries": entries }),
    )
}

/// The salt test servers keep SCRAM passwords with.
pub(crate) const SCRAM_SALT: &[u8] = b"teifs-test-salt";

/// Checks SCRAM's client proof as a server does, from what it stores (the stored key
/// and server key); returns the server's signature.
pub(crate) fn scram_verify(
    mechanism: &str,
    password: &str,
    client_first_bare: &str,
    server_first: &str,
    client_final: &str,
) -> Option<Vec<u8>> {
    let (derive, mac, sha) = if mechanism == "SCRAM-SHA-512" {
        (
            pbkdf2::PBKDF2_HMAC_SHA512,
            hmac::HMAC_SHA512,
            &digest::SHA512,
        )
    } else {
        (
            pbkdf2::PBKDF2_HMAC_SHA256,
            hmac::HMAC_SHA256,
            &digest::SHA256,
        )
    };
    let mut salted = vec![0; sha.output_len()];
    pbkdf2::derive(
        derive,
        std::num::NonZeroU32::new(4096)?,
        SCRAM_SALT,
        password.as_bytes(),
        &mut salted,
    );
    let salted = hmac::Key::new(mac, &salted);
    let stored_key = digest::digest(sha, hmac::sign(&salted, b"Client Key").as_ref());
    let server_key = hmac::sign(&salted, b"Server Key");
    let (without_proof, proof) = client_final.rsplit_once(",p=")?;
    let nonce = server_first.split(',').next()?.strip_prefix("r=")?;
    if without_proof != format!("c=biws,r={nonce}") {
        return None;
    }
    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let client_signature = hmac::sign(
        &hmac::Key::new(mac, stored_key.as_ref()),
        auth_message.as_bytes(),
    );
    let client_key: Vec<u8> = BASE64
        .decode(proof)
        .ok()?
        .iter()
        .zip(client_signature.as_ref())
        .map(|(p, s)| p ^ s)
        .collect();
    (digest::digest(sha, &client_key).as_ref() == stored_key.as_ref()).then(|| {
        hmac::sign(
            &hmac::Key::new(mac, server_key.as_ref()),
            auth_message.as_bytes(),
        )
        .as_ref()
        .to_vec()
    })
}

/// The table `sql` names after `word`: up to a space or `;`, or a name in `quote`s whole.
pub(crate) fn table_after(sql: &str, word: &str, quote: char) -> String {
    let rest = sql
        .split_once(&format!(" {word} "))
        .map_or("", |(_, rest)| rest);
    let end = if let Some(quoted) = rest.strip_prefix(quote) {
        quoted.find(quote).map_or(rest.len(), |i| i + 2)
    } else {
        rest.find([' ', ';']).unwrap_or(rest.len())
    };
    rest[..end].to_owned()
}
