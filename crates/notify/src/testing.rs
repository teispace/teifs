//! A webhook receiver on this machine, for tests (the `testing` feature): it takes
//! requests (`POST`s, and the others an Elasticsearch target makes), or fails as many as
//! it's told to first.

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
