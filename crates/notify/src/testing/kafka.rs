//! A Kafka cluster on this machine: several brokers, one topic whose partitions they
//! lead, SASL (PLAIN or SCRAM, checked as a broker checks it), and records read back as a
//! broker reads them (their CRC checked, gzip opened).

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::scram_verify;
use crate::kafka::wire::{Reader, Writer, api, read_batches};

/// How a [`KafkaServer`] is made.
#[derive(Debug, Clone)]
pub struct KafkaSetup {
    /// How many brokers.
    pub brokers: usize,
    /// The topic it has.
    pub topic: String,
    /// How many partitions the topic has; partition `p` is led by broker `p % brokers`.
    pub partitions: usize,
    /// The SASL mechanism (`PLAIN`, `SCRAM-SHA-256` or `SCRAM-SHA-512`), user and
    /// password each connection must sign in with, if any.
    pub sasl: Option<(String, String, String)>,
    /// The versions the brokers take, `(api, oldest, newest)`.
    pub versions: Vec<(i16, i16, i16)>,
    /// Whether SCRAM's last answer is signed with a key other than the password's, as a
    /// server that doesn't know it would sign it.
    pub impostor: bool,
}

impl KafkaSetup {
    /// `brokers` brokers with `topic` in `partitions` partitions, no SASL, and the
    /// versions Kafka 4 takes.
    #[must_use]
    pub fn new(brokers: usize, topic: &str, partitions: usize) -> Self {
        Self {
            brokers,
            topic: topic.to_owned(),
            partitions,
            sasl: None,
            versions: vec![
                (api::PRODUCE, 3, 12),
                (api::METADATA, 0, 13),
                (api::SASL_HANDSHAKE, 0, 1),
                (api::API_VERSIONS, 0, 5),
                (api::SASL_AUTHENTICATE, 0, 2),
            ],
            impostor: false,
        }
    }
}

/// A record a [`KafkaServer`] took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaRecord {
    /// The broker that took it, from 0.
    pub broker: usize,
    /// Its partition.
    pub partition: usize,
    /// Its key.
    pub key: Option<String>,
    /// Its value.
    pub value: String,
    /// Its batch's compression code (0 none, 1 gzip).
    pub compression: i16,
    /// The acknowledgement it asked for.
    pub acks: i16,
}

/// A Kafka cluster that answers `ApiVersions`, `SaslHandshake`, `SaslAuthenticate`,
/// `Metadata` (v1) and `Produce` (v3), as Kafka does.
pub struct KafkaServer {
    addresses: Vec<String>,
    shared: Arc<Shared>,
}

struct Shared {
    setup: KafkaSetup,
    /// Each broker's advertised port.
    ports: Vec<u16>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Each partition's leader, a broker from 0.
    leaders: Vec<usize>,
    records: Vec<KafkaRecord>,
    /// Metadata requests answered.
    lookups: usize,
    /// Metadata answers still to say a leader is being elected.
    electing: usize,
    /// Produce answers still to refuse, with this code.
    refusing: Option<(i16, usize)>,
    /// Sign-ins that succeeded, as `MECHANISM user`.
    signins: Vec<String>,
    /// Brokers' addresses said instead of their own, by broker.
    advertised: Vec<Option<(String, u16)>>,
}

impl KafkaServer {
    /// Starts one.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(setup: KafkaSetup) -> Self {
        let mut listeners = Vec::new();
        for _ in 0..setup.brokers {
            listeners.push(
                tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("a free port"),
            );
        }
        let ports: Vec<u16> = listeners
            .iter()
            .map(|l| l.local_addr().expect("a bound address").port())
            .collect();
        let leaders = (0..setup.partitions).map(|p| p % setup.brokers).collect();
        let shared = Arc::new(Shared {
            setup,
            ports: ports.clone(),
            state: Mutex::new(State {
                leaders,
                ..State::default()
            }),
        });
        for (broker, listener) in listeners.into_iter().enumerate() {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let shared = Arc::clone(&shared);
                    tokio::spawn(async move {
                        let _ = serve(stream, broker, &shared).await;
                    });
                }
            });
        }
        Self {
            addresses: ports.iter().map(|p| format!("127.0.0.1:{p}")).collect(),
            shared,
        }
    }

    /// Each broker's `HOST:PORT`.
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes `broker` the leader of `partition`: the old one refuses its records.
    pub fn move_leader(&self, partition: usize, broker: usize) {
        self.state().leaders[partition] = broker;
    }

    /// Says `broker` is at `host` and `port` (a proxy in front of it, say).
    pub fn advertise(&self, broker: usize, host: &str, port: u16) {
        let mut state = self.state();
        state.advertised.resize(self.addresses.len(), None);
        state.advertised[broker] = Some((host.to_owned(), port));
    }

    /// The next `count` Metadata answers say the topic's leader is being elected.
    pub fn electing(&self, count: usize) {
        self.state().electing = count;
    }

    /// The next `count` records are refused with the error `code`.
    pub fn refuse(&self, code: i16, count: usize) {
        self.state().refusing = Some((code, count));
    }

    /// How many Metadata requests were answered.
    #[must_use]
    pub fn lookups(&self) -> usize {
        self.state().lookups
    }

    /// The sign-ins that succeeded, as `MECHANISM user`.
    #[must_use]
    pub fn signins(&self) -> Vec<String> {
        self.state().signins.clone()
    }

    /// The records taken, once there are at least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn records(&self, count: usize) -> Vec<KafkaRecord> {
        for _ in 0..500 {
            let taken = self.state().records.clone();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the Kafka cluster never took {count} records");
    }
}

/// Where a connection's sign-in is.
enum Signin {
    /// Nothing's been asked.
    None,
    /// The mechanism was agreed.
    Agreed,
    /// SCRAM's first messages were exchanged: the client's without its header, and the
    /// server's.
    Scram(String, String),
    /// Signed in.
    Done,
}

async fn serve(mut stream: TcpStream, broker: usize, shared: &Shared) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    let mut signin = Signin::None;
    loop {
        let size = usize::try_from(stream.read_i32().await.map_err(io)?).map_err(|_| "size")?;
        let mut request = vec![0; size];
        stream.read_exact(&mut request).await.map_err(io)?;
        let mut reader = Reader::new(&request);
        let (key, version, correlation) = (reader.i16()?, reader.i16()?, reader.i32()?);
        let _client = reader.string()?;
        let signed_in = shared.setup.sasl.is_none() || matches!(signin, Signin::Done);
        let mut failed = false;
        let body = match key {
            api::API_VERSIONS => versions(shared),
            api::SASL_HANDSHAKE if version == 1 => handshake(&mut reader, shared, &mut signin)?,
            api::SASL_AUTHENTICATE if version == 0 => {
                let (body, ok) = authenticate(&mut reader, shared, &mut signin)?;
                failed = !ok;
                body
            }
            api::METADATA if version == 1 && signed_in => metadata(&mut reader, shared)?,
            api::PRODUCE if matches!(version, 3 | 7) && signed_in => {
                produce(&mut reader, version, broker, shared)?
            }
            // Anything else, or before signing in: the connection is closed.
            _ => return Ok(()),
        };
        let mut answer = Writer::default();
        answer
            .i32(i32::try_from(body.len() + 4).map_err(|_| "size")?)
            .i32(correlation);
        answer.0.extend_from_slice(&body);
        stream.write_all(&answer.0).await.map_err(io)?;
        if failed {
            // A broker closes the connection of a client that failed to sign in.
            return Ok(());
        }
    }
}

fn versions(shared: &Shared) -> Vec<u8> {
    let versions = &shared.setup.versions;
    let mut out = Writer::default();
    out.i16(0)
        .i32(i32::try_from(versions.len()).unwrap_or_default());
    for (key, min, max) in versions {
        out.i16(*key).i16(*min).i16(*max);
    }
    out.0
}

fn handshake(
    reader: &mut Reader<'_>,
    shared: &Shared,
    signin: &mut Signin,
) -> Result<Vec<u8>, String> {
    let asked = reader.string()?.unwrap_or_default();
    let offered = shared
        .setup
        .sasl
        .as_ref()
        .map_or("PLAIN", |(mechanism, ..)| mechanism.as_str());
    let mut out = Writer::default();
    if asked == offered && shared.setup.sasl.is_some() {
        *signin = Signin::Agreed;
        out.i16(0);
    } else {
        out.i16(33);
    }
    out.i32(1).string(Some(offered))?;
    Ok(out.0)
}

/// One SASL step: its answer, and whether it succeeded.
fn authenticate(
    reader: &mut Reader<'_>,
    shared: &Shared,
    signin: &mut Signin,
) -> Result<(Vec<u8>, bool), String> {
    let token = reader.bytes()?.unwrap_or_default();
    let (mechanism, user, password) = shared.setup.sasl.clone().ok_or("no SASL")?;
    let text = String::from_utf8_lossy(token).into_owned();
    let (reply, next) = match (std::mem::replace(signin, Signin::None), mechanism.as_str()) {
        (Signin::Agreed, "PLAIN") => {
            if text == format!("\0{user}\0{password}") {
                (Some(Vec::new()), Signin::Done)
            } else {
                (None, Signin::None)
            }
        }
        (Signin::Agreed, _) => {
            let bare = text.strip_prefix("n,,").ok_or("no GS2 header")?.to_owned();
            let nonce = bare
                .split(',')
                .find_map(|a| a.strip_prefix("r="))
                .ok_or("no nonce")?;
            let named = bare.split(',').find_map(|a| a.strip_prefix("n=")) == Some(user.as_str());
            if named {
                let first = format!("r={nonce}srv,s={},i=4096", BASE64.encode(super::SCRAM_SALT));
                (Some(first.clone().into_bytes()), Signin::Scram(bare, first))
            } else {
                (None, Signin::None)
            }
        }
        (Signin::Scram(bare, first), _) => {
            match scram_verify(&mechanism, &password, &bare, &first, &text) {
                Some(mut signature) => {
                    if shared.setup.impostor {
                        signature[0] ^= 1;
                    }
                    (
                        Some(format!("v={}", BASE64.encode(signature)).into_bytes()),
                        Signin::Done,
                    )
                }
                None => (None, Signin::None),
            }
        }
        _ => (None, Signin::None),
    };
    let done = matches!(next, Signin::Done);
    *signin = next;
    if done {
        shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .signins
            .push(format!("{mechanism} {user}"));
    }
    let mut out = Writer::default();
    let ok = reply.is_some();
    match reply {
        Some(bytes) => {
            out.i16(0).string(None)?.bytes(&bytes)?;
        }
        None => {
            out.i16(58)
                .string(Some("Authentication failed during authentication"))?
                .bytes(&[])?;
        }
    }
    Ok((out.0, ok))
}

fn metadata(reader: &mut Reader<'_>, shared: &Shared) -> Result<Vec<u8>, String> {
    let mut asked = Vec::new();
    for _ in 0..reader.array(2)? {
        asked.push(reader.string()?.unwrap_or_default().to_owned());
    }
    let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
    state.lookups += 1;
    let mut out = Writer::default();
    out.i32(i32::try_from(shared.ports.len()).map_err(|_| "brokers")?);
    for (id, port) in shared.ports.iter().enumerate() {
        let (host, port) = state
            .advertised
            .get(id)
            .cloned()
            .flatten()
            .unwrap_or_else(|| ("127.0.0.1".to_owned(), *port));
        out.i32(node(id))
            .string(Some(&host))?
            .i32(i32::from(port))
            .string(None)?;
    }
    out.i32(node(0));
    out.i32(i32::try_from(asked.len()).map_err(|_| "topics")?);
    for topic in asked {
        if topic != shared.setup.topic {
            out.i16(3).string(Some(&topic))?.i8(0).i32(0);
            continue;
        }
        if state.electing > 0 {
            state.electing -= 1;
            out.i16(5).string(Some(&topic))?.i8(0).i32(0);
            continue;
        }
        out.i16(0).string(Some(&topic))?.i8(0);
        out.i32(i32::try_from(state.leaders.len()).map_err(|_| "partitions")?);
        for (partition, leader) in state.leaders.iter().enumerate() {
            out.i16(0)
                .i32(i32::try_from(partition).map_err(|_| "partition")?)
                .i32(node(*leader))
                .i32(1)
                .i32(node(*leader))
                .i32(1)
                .i32(node(*leader));
        }
    }
    Ok(out.0)
}

/// A broker's node id: brokers count from 0, ids from 1, as a cluster's often do.
fn node(broker: usize) -> i32 {
    i32::try_from(broker + 1).unwrap_or(i32::MAX)
}

fn produce(
    reader: &mut Reader<'_>,
    version: i16,
    broker: usize,
    shared: &Shared,
) -> Result<Vec<u8>, String> {
    let _transaction = reader.string()?;
    let acks = reader.i16()?;
    let _timeout = reader.i32()?;
    let mut answers: Vec<(String, Vec<(i32, i16)>)> = Vec::new();
    let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
    for _ in 0..reader.array(6)? {
        let topic = reader.string()?.unwrap_or_default().to_owned();
        let mut partitions = Vec::new();
        for _ in 0..reader.array(8)? {
            let index = reader.i32()?;
            let batch = reader.bytes()?.unwrap_or_default();
            let partition = usize::try_from(index).map_err(|_| "partition")?;
            let code = if topic != shared.setup.topic || partition >= state.leaders.len() {
                3
            } else if state.leaders[partition] != broker {
                6
            } else if let Some((code, left)) = state.refusing.as_mut().filter(|(_, n)| *n > 0) {
                *left -= 1;
                *code
            } else {
                match read_batches(batch) {
                    Ok(records) => {
                        let compression = batch
                            .get(21..23)
                            .map_or(0, |a| i16::from_be_bytes([a[0], a[1]]) & 7);
                        for (key, value) in records {
                            state.records.push(KafkaRecord {
                                broker,
                                partition,
                                key: key.map(|k| String::from_utf8_lossy(&k).into_owned()),
                                value: String::from_utf8_lossy(&value.unwrap_or_default())
                                    .into_owned(),
                                compression,
                                acks,
                            });
                        }
                        0
                    }
                    Err(_) => 2, // CORRUPT_MESSAGE
                }
            };
            partitions.push((index, code));
        }
        answers.push((topic, partitions));
    }
    let mut out = Writer::default();
    out.i32(i32::try_from(answers.len()).map_err(|_| "topics")?);
    for (topic, partitions) in answers {
        out.string(Some(&topic))?
            .i32(i32::try_from(partitions.len()).map_err(|_| "partitions")?);
        for (index, code) in partitions {
            out.i32(index).i16(code).i64(0).i64(-1);
            if version >= 5 {
                out.i64(0); // log start offset
            }
        }
    }
    out.i32(0); // throttle time
    Ok(out.0)
}
