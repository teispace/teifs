//! A fake identity plugin for tests: it answers each token as it was told to (an unknown
//! one with `403`), and keeps what it was sent.

#![allow(
    clippy::unwrap_used,
    reason = "a test double: a broken lock fails the test"
)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use zeroize::Zeroizing;

use super::PluginSettings;

/// The `Authorization` header the fake's settings send.
pub const AUTH_TOKEN: &str = "Bearer plugin-secret";

/// One request the fake was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// Its method.
    pub method: String,
    /// The `token` in its query.
    pub token: Option<String>,
    /// Its `Authorization` header.
    pub authorization: Option<String>,
}

type Answers = Arc<Mutex<HashMap<String, (u16, String)>>>;

/// A plugin on a loopback port, until dropped.
#[derive(Debug)]
pub struct FakePlugin {
    url: String,
    answers: Answers,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: JoinHandle<()>,
}

impl Drop for FakePlugin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakePlugin {
    /// Starts it.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/auth?tenant=t1", listener.local_addr().unwrap());
        let answers: Answers = Arc::default();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let (a, s) = (Arc::clone(&answers), Arc::clone(&seen));
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (a, s) = (Arc::clone(&a), Arc::clone(&s));
                tokio::spawn(async move { answer(socket, &a, &s).await });
            }
        });
        Self {
            url,
            answers,
            seen,
            task,
        }
    }

    /// Where it listens (with a query of its own, which must be kept).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Answers `token` with `status` and `body`; for a redirect (`3xx`), `body` is where
    /// to, and there's none.
    pub fn answer(&self, token: &str, status: u16, body: &str) {
        self.answers
            .lock()
            .unwrap()
            .insert(token.to_owned(), (status, body.to_owned()));
    }

    /// Vouches for `user` when given `token`, for up to `seconds`.
    pub fn vouch(&self, token: &str, user: &str, seconds: i64) {
        self.answer(
            token,
            200,
            &serde_json::json!({
                "user": user,
                "maxValiditySeconds": seconds,
                "claims": {"team": "storage", "sub": "ignored"},
            })
            .to_string(),
        );
    }

    /// What it was sent so far.
    #[must_use]
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Settings that ask it, with `policies` for its users.
    #[must_use]
    pub fn settings(&self, policies: &[&str]) -> PluginSettings {
        PluginSettings {
            url: self.url.clone(),
            auth_token: Some(Zeroizing::new(AUTH_TOKEN.to_owned())),
            role_policies: policies.iter().map(|p| (*p).to_owned()).collect(),
            role_id: Some("tests".into()),
            ca: Vec::new(),
        }
    }
}

async fn answer(mut socket: tokio::net::TcpStream, answers: &Answers, seen: &Mutex<Vec<Seen>>) {
    let mut request = Vec::new();
    let mut buffer = [0; 4096];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match socket.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buffer[..n]),
        }
    }
    let text = String::from_utf8_lossy(&request).into_owned();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_owned();
    let target = first.next().unwrap_or_default();
    let query = target.split_once('?').map_or("", |(_, q)| q);
    let token = form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "token")
        .map(|(_, value)| value.into_owned());
    let tenant_kept =
        form_urlencoded::parse(query.as_bytes()).any(|(n, v)| n == "tenant" && v == "t1");
    let authorization = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim().to_owned());
    seen.lock().unwrap().push(Seen {
        method: method.clone(),
        token: token.clone(),
        authorization,
    });
    let (status, body) = if method == "HEAD" {
        (200, String::new())
    } else if !tenant_kept {
        (
            400,
            r#"{"reason":"the URL's own query was lost"}"#.to_owned(),
        )
    } else {
        token
            .and_then(|t| answers.lock().unwrap().get(&t).cloned())
            .unwrap_or_else(|| (403, r#"{"reason":"unknown token"}"#.to_owned()))
    };
    let (location, body) = if (300..400).contains(&status) {
        (format!("Location: {body}\r\n"), String::new())
    } else {
        (String::new(), body)
    };
    let response = format!(
        "HTTP/1.1 {status} X\r\n{location}Content-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.shutdown().await;
}
