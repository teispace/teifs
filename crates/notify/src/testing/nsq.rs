//! An `nsqd` on this machine, answering as `nsqd` does: `IDENTIFY` with feature
//! negotiation (TLS and `AUTH` when it's set up for them) or a plain `OK`, `PUB`, and a
//! heartbeat before each answer, which a client must answer with `NOP`.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::{
    net::Stream,
    nsq::{HEARTBEAT, MAGIC},
};

/// How an [`NsqServer`] is made.
#[derive(Clone)]
pub struct NsqSetup {
    /// TLS, for a client that asks in `IDENTIFY`.
    pub tls: Option<tokio_rustls::TlsAcceptor>,
    /// The secret `AUTH` must send before `PUB`, if any.
    pub secret: Option<String>,
    /// Whether it negotiates features, as `nsqd` 0.2.28 and later do.
    pub negotiates: bool,
}

impl Default for NsqSetup {
    /// No TLS or `AUTH`, negotiating.
    fn default() -> Self {
        Self {
            tls: None,
            secret: None,
            negotiates: true,
        }
    }
}

/// A connection an [`NsqServer`] took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsqConnection {
    /// What its `IDENTIFY` said.
    pub identify: serde_json::Value,
    /// Whether it went on over TLS.
    pub tls: bool,
    /// The secrets it sent with `AUTH`.
    pub auths: Vec<String>,
}

#[derive(Default)]
struct State {
    published: Vec<(String, String)>,
    nops: usize,
    connections: Vec<NsqConnection>,
}

struct Shared {
    setup: NsqSetup,
    state: Mutex<State>,
}

impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// An `nsqd` for tests.
#[derive(Clone)]
pub struct NsqServer {
    address: String,
    shared: Arc<Shared>,
}

impl NsqServer {
    /// Starts one.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(setup: NsqSetup) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let address = format!(
            "localhost:{}",
            listener.local_addr().expect("a bound address").port()
        );
        let shared = Arc::new(Shared {
            setup,
            state: Mutex::new(State::default()),
        });
        let served = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shared = Arc::clone(&served);
                tokio::spawn(async move {
                    let _ = serve(Box::new(stream), &shared).await;
                });
            }
        });
        Self { address, shared }
    }

    /// Its `localhost:PORT`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// How many heartbeats were answered.
    #[must_use]
    pub fn nops(&self) -> usize {
        self.shared.state().nops
    }

    /// The connections it took.
    #[must_use]
    pub fn connections(&self) -> Vec<NsqConnection> {
        self.shared.state().connections.clone()
    }

    /// What was published, as (topic, body), once there are at least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn published(&self, count: usize) -> Vec<(String, String)> {
        for _ in 0..500 {
            let taken = self.shared.state().published.clone();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the nsqd never took {count} messages");
    }
}

fn frame(kind: u32, data: &[u8]) -> Vec<u8> {
    let mut out = (u32::try_from(data.len()).expect("short") + 4)
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// A heartbeat, then `answer`.
async fn reply(stream: &mut BufReader<Stream>, answer: &[u8]) -> std::io::Result<()> {
    let mut out = frame(0, HEARTBEAT);
    out.extend_from_slice(answer);
    stream.get_mut().write_all(&out).await
}

async fn serve(stream: Stream, shared: &Shared) -> std::io::Result<()> {
    let setup = &shared.setup;
    let mut stream = BufReader::new(stream);
    let mut magic = [0; 4];
    stream.read_exact(&mut magic).await?;
    if magic != *MAGIC {
        return Ok(());
    }
    let mut connection = None;
    let mut authed = setup.secret.is_none();
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let line = line.trim_end().to_owned();
        if line == "NOP" {
            shared.state().nops += 1;
            continue;
        }
        let size = stream.read_u32().await?;
        let mut body = vec![0; size as usize];
        stream.read_exact(&mut body).await?;
        match line.split_once(' ') {
            None if line == "IDENTIFY" => {
                let identify: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let tls = identify["tls_v1"] == true && setup.tls.is_some();
                shared.state().connections.push(NsqConnection {
                    identify: identify.clone(),
                    tls,
                    auths: Vec::new(),
                });
                connection = Some(shared.state().connections.len() - 1);
                if !setup.negotiates || identify["feature_negotiation"] != true {
                    reply(&mut stream, &frame(0, b"OK")).await?;
                    continue;
                }
                let features = serde_json::json!({
                    "max_rdy_count": 2500,
                    "version": "1.3.0",
                    "max_msg_timeout": 900_000,
                    "msg_timeout": 60000,
                    "tls_v1": tls,
                    "deflate": false,
                    "snappy": false,
                    "auth_required": setup.secret.is_some(),
                })
                .to_string();
                // `nsqd` upgrades as soon as it has answered: no heartbeat comes between.
                if tls {
                    stream
                        .get_mut()
                        .write_all(&frame(0, features.as_bytes()))
                        .await?;
                } else {
                    reply(&mut stream, &frame(0, features.as_bytes())).await?;
                }
                if let (true, Some(acceptor)) = (tls, &setup.tls) {
                    let plain = stream.into_inner();
                    let secured = tokio_rustls::TlsStream::Server(acceptor.accept(plain).await?);
                    stream = BufReader::new(Box::new(secured));
                    stream.get_mut().write_all(&frame(0, b"OK")).await?;
                }
            }
            None if line == "AUTH" => {
                let secret = String::from_utf8_lossy(&body).into_owned();
                if let Some(index) = connection {
                    shared.state().connections[index].auths.push(secret.clone());
                }
                let answer = if setup.secret.as_deref() == Some(&secret) {
                    authed = true;
                    frame(0, br#"{"identity":"teifs","permission_count":1}"#)
                } else {
                    frame(1, b"E_UNAUTHORIZED AUTH failed")
                };
                reply(&mut stream, &answer).await?;
            }
            Some(("PUB", _)) if !authed => {
                reply(&mut stream, &frame(1, b"E_UNAUTHORIZED AUTH required")).await?;
            }
            Some(("PUB", topic)) => {
                shared.state().published.push((
                    topic.to_owned(),
                    String::from_utf8_lossy(&body).into_owned(),
                ));
                reply(&mut stream, &frame(0, b"OK")).await?;
            }
            _ => reply(&mut stream, &frame(1, b"E_INVALID")).await?,
        }
    }
}
