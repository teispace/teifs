//! A proxy in front of a server that misbehaves when told to: it answers an error, drops
//! the connection, or cuts a request's body short, for the requests a fault matches.
//! Everything else passes through unchanged (one request per connection), so signatures
//! still hold. What it saw is kept, to count the attempts.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// What a matching request gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// An S3 error with this status and code.
    Status(u16, &'static str),
    /// The connection closed, with no answer.
    Drop,
    /// Half the body sent on, then both connections closed.
    Cut,
}

#[derive(Debug, Clone)]
struct Fault {
    method: &'static str,
    /// What the path and query must contain.
    target: String,
    answer: Answer,
    /// How many more requests it takes.
    times: usize,
}

/// A request it saw: `METHOD /path?query`.
pub type Seen = String;

#[derive(Default)]
struct State {
    faults: Vec<Fault>,
    seen: Vec<Seen>,
}

/// The proxy; it stops with the test.
#[derive(Clone)]
pub struct Faulty {
    /// `127.0.0.1:PORT`.
    pub address: String,
    state: Arc<Mutex<State>>,
}

impl Faulty {
    /// A proxy for the server at `upstream` (`http://HOST:PORT`).
    pub async fn new(upstream: &str) -> Self {
        let upstream: SocketAddr = upstream.trim_start_matches("http://").parse().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let state = shared.clone();
                tokio::spawn(async move {
                    let _ = serve(client, upstream, &state).await;
                });
            }
        });
        Self { address, state }
    }

    /// `answer` for the next `times` requests with `method` whose path and query
    /// contain `target`.
    pub fn fail(&self, method: &'static str, target: &str, answer: Answer, times: usize) {
        lock(&self.state).faults.push(Fault {
            method,
            target: target.to_owned(),
            answer,
            times,
        });
    }

    /// The faults that weren't used up: `(method, target)`.
    pub fn unspent(&self) -> Vec<(&'static str, String)> {
        lock(&self.state)
            .faults
            .iter()
            .filter(|f| f.times > 0 && f.times != usize::MAX)
            .map(|f| (f.method, f.target.clone()))
            .collect()
    }

    /// Stops every fault.
    pub fn heal(&self) {
        lock(&self.state).faults.clear();
    }

    /// How many requests with `method` whose path and query contain `target` came.
    pub fn count(&self, method: &str, target: &str) -> usize {
        lock(&self.state)
            .seen
            .iter()
            .filter(|seen| seen.starts_with(&format!("{method} ")) && seen.contains(target))
            .count()
    }
}

fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads one request, then answers it as the faults say.
async fn serve(
    mut client: TcpStream,
    upstream: SocketAddr,
    state: &Mutex<State>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0; 8192];
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut length = 0;
    let mut expects = false;
    let mut kept = vec![request_line.clone()];
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').unwrap_or((line, ""));
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().unwrap_or(0),
            "expect" => {
                expects = true;
                continue;
            }
            "connection" => continue,
            _ => {}
        }
        kept.push(line.to_owned());
    }
    kept.push("Connection: close".to_owned());
    if expects {
        client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let mut chunk = vec![0; (length - body.len()).min(1 << 16)];
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let answer = {
        let mut state = lock(state);
        state.seen.push(format!("{method} {target}"));
        state
            .faults
            .iter_mut()
            .find(|f| f.times > 0 && f.method == method && target.contains(&f.target))
            .map(|fault| {
                fault.times -= 1;
                fault.answer
            })
    };
    let head = format!("{}\r\n\r\n", kept.join("\r\n"));
    match answer {
        None => {
            let mut server = TcpStream::connect(upstream).await?;
            server.write_all(head.as_bytes()).await?;
            server.write_all(&body).await?;
            let mut answer = Vec::new();
            server.read_to_end(&mut answer).await?;
            client.write_all(&answer).await?;
            client.shutdown().await
        }
        Some(Answer::Status(status, code)) => {
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>a fault</Message></Error>"
            );
            let answer = format!(
                "HTTP/1.1 {status} Fault\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}",
                xml.len()
            );
            client.write_all(answer.as_bytes()).await?;
            client.shutdown().await
        }
        Some(Answer::Drop) => Ok(()),
        Some(Answer::Cut) => {
            let mut server = TcpStream::connect(upstream).await?;
            server.write_all(head.as_bytes()).await?;
            server.write_all(&body[..body.len() / 2]).await?;
            server.shutdown().await?;
            Ok(())
        }
    }
}
