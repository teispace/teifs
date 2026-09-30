//! Targets on this machine, for tests (the `testing` feature): a webhook receiver that
//! takes requests (`POST`s, and the others an Elasticsearch target makes), or fails as
//! many as it's told to first, and a Redis server.

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
