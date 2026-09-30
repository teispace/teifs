//! Targets on this machine, for tests (the `testing` feature): a webhook receiver that
//! takes requests (`POST`s, and the others an Elasticsearch target makes), or fails as
//! many as it's told to first, and Redis, NSQ and NATS servers.

use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use http_body_util::BodyExt;

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
