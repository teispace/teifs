//! Kafka targets, as `MinIO`'s: each event, as a webhook is sent it, produced to a topic
//! keyed `bucket/object`, so each object's events keep their order on one partition (the
//! one Kafka's own clients pick for the key). The bootstrap brokers name the topic's
//! partitions and their leaders; each record goes to its partition's leader, which
//! acknowledges it when every in-sync replica has it (`acks=all`, the default) or when
//! it has it (`acks=1`). A leader that moved is looked up again at once. SASL PLAIN,
//! SCRAM-SHA-256 or SCRAM-SHA-512; TLS when asked for; gzip.

pub(crate) mod wire;

use std::{collections::HashMap, fmt, future::Future, sync::Arc, time::Duration};

use rustls::ClientConfig;
use teifs_types::notify::EventMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub use wire::Compression;
use wire::{GARBLED, Reader, Writer, api};
use zeroize::Zeroizing;

use crate::{
    net::{self, Kept, Stream},
    scram::{Scram, ScramHash},
};

/// The versions of the APIs used: the oldest Kafka 4 still takes, which Kafka has
/// taken since 0.11 (and SASL's since 1.0); Produce's is its compression's
/// ([`Compression::produce_version`]).
const METADATA: i16 = 1;
const SASL_HANDSHAKE: i16 = 1;
const SASL_AUTHENTICATE: i16 = 0;
/// How long a leader waits for its replicas before it answers, in milliseconds.
const PRODUCE_TIMEOUT_MS: i32 = 5_000;
/// The largest answer read.
const MAX_ANSWER: usize = 16 << 20;
/// Errors that a fresh look at the topic's leaders mends.
const MOVED: [i16; 3] = [
    3, // UNKNOWN_TOPIC_OR_PARTITION: its partitions changed
    5, // LEADER_NOT_AVAILABLE: a leader is being elected
    6, // NOT_LEADER_OR_FOLLOWER: the leader moved
];

/// Which acknowledgement a record waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acks {
    /// Every in-sync replica has it.
    All,
    /// The leader has it.
    Leader,
}

impl Acks {
    /// Reads `all` (or `-1`) or `1`.
    ///
    /// # Errors
    ///
    /// When it's neither.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.to_ascii_lowercase().as_str() {
            "all" | "-1" => Ok(Self::All),
            "1" => Ok(Self::Leader),
            _ => Err(format!("acks is all or 1, not `{text}`")),
        }
    }

    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Leader => "1",
        }
    }

    const fn code(self) -> i16 {
        match self {
            Self::All => -1,
            Self::Leader => 1,
        }
    }
}

/// How TeiFS proves who it is to the brokers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslMechanism {
    /// The user and password, as they are: only over TLS.
    Plain,
    /// SCRAM, with SHA-256 or SHA-512.
    Scram(ScramHash),
}

impl SaslMechanism {
    /// Reads `plain`, `scram-sha-256` or `scram-sha-512`.
    ///
    /// # Errors
    ///
    /// When it's none of them.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.to_ascii_lowercase().as_str() {
            "plain" => Ok(Self::Plain),
            "scram-sha-256" => Ok(Self::Scram(ScramHash::Sha256)),
            "scram-sha-512" => Ok(Self::Scram(ScramHash::Sha512)),
            _ => Err(format!(
                "`{text}` isn't a SASL mechanism: give plain, scram-sha-256 or scram-sha-512"
            )),
        }
    }

    /// Its name, as brokers know it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Scram(hash) => hash.mechanism(),
        }
    }
}

/// A user and password, and how they're proved.
#[derive(Clone)]
pub struct KafkaSasl {
    /// How.
    pub mechanism: SaslMechanism,
    /// The user.
    pub user: String,
    /// Its password.
    pub password: Zeroizing<String>,
}

impl fmt::Debug for KafkaSasl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KafkaSasl")
            .field("mechanism", &self.mechanism)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// A topic events are produced to.
#[derive(Clone)]
pub struct Kafka {
    /// The brokers first asked about the topic, each `HOST:PORT`.
    pub brokers: Vec<String>,
    /// The topic.
    pub topic: String,
    /// Which acknowledgement each record waits for.
    pub acks: Acks,
    /// How records are compressed.
    pub compression: Compression,
    /// The user and password, if the brokers want them.
    pub sasl: Option<KafkaSasl>,
    /// TLS, and how the brokers are verified; none for plain TCP.
    pub tls: Option<Arc<ClientConfig>>,
    session: Kept<Session>,
}

impl Kafka {
    /// Events for `topic`, the brokers asked first `brokers` (`HOST:PORT`, separated by
    /// `;`), each record acknowledged by every in-sync replica, uncompressed.
    ///
    /// # Errors
    ///
    /// When a broker isn't `HOST:PORT`, or `topic` isn't a topic's name.
    pub fn new(brokers: &str, topic: &str) -> Result<Self, String> {
        let brokers: Vec<String> = brokers
            .split(';')
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .map(str::to_owned)
            .collect();
        if brokers.is_empty() {
            return Err("name a broker, HOST:PORT".to_owned());
        }
        if let Some(bad) = brokers.iter().find(|b| !net::is_address(b)) {
            return Err(format!("`{bad}` isn't HOST:PORT"));
        }
        // Kafka's own rule for topics' names.
        if topic.is_empty()
            || topic.len() > 249
            || topic == "."
            || topic == ".."
            || !topic
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(format!(
                "`{topic}` isn't a topic's name: use up to 249 letters, digits, `.`, `_` and `-`"
            ));
        }
        Ok(Self {
            brokers,
            topic: topic.to_owned(),
            acks: Acks::All,
            compression: Compression::None,
            sasl: None,
            tls: None,
            session: Kept::new(),
        })
    }

    /// Where it produces.
    #[must_use]
    pub fn shown(&self) -> String {
        let mut shown = format!(
            "{}://{} topic {} (acks={}",
            if self.tls.is_some() {
                "kafka+tls"
            } else {
                "kafka"
            },
            self.brokers.join(";"),
            self.topic,
            self.acks.name()
        );
        if self.compression != Compression::None {
            shown.push_str(", ");
            shown.push_str(self.compression.name());
        }
        if let Some(sasl) = &self.sasl {
            shown.push_str(", SASL ");
            shown.push_str(sasl.mechanism.name());
        }
        shown.push(')');
        shown
    }

    /// Produces `body`, keyed by its object (`bucket/object`).
    pub(crate) async fn send(&self, body: &[u8]) -> Result<(), String> {
        let key = serde_json::from_slice::<EventMessage>(body)
            .ok()
            .map(|event| event.key);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp = i64::try_from(now.as_millis()).unwrap_or(i64::MAX);
        let batch = wire::record_batch(
            key.as_deref().map(str::as_bytes),
            body,
            timestamp,
            self.compression,
        )?;
        let request = (self, key.as_deref().map(str::as_bytes), batch);
        // A record the leader refused keeps the connection; one that failed doesn't.
        self.session
            .run(self, false, &request, |session, (kafka, key, batch)| {
                Box::pin(session.produce(kafka, *key, batch))
            })
            .await?
    }

    /// Checks that a broker takes the connection and knows the topic, without producing.
    pub(crate) async fn test(&self) -> Result<(), String> {
        self.session
            .run(self, true, &(), |_, ()| Box::pin(async { Ok(()) }))
            .await
    }
}

impl net::Connects for Kafka {
    type Connection = Session;

    fn connect(&self) -> impl Future<Output = Result<Session, String>> + Send {
        Session::open(self)
    }
}

impl fmt::Debug for Kafka {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kafka")
            .field("at", &self.shown())
            .field("sasl", &self.sasl)
            .finish_non_exhaustive()
    }
}

/// What the brokers said about the topic, and the connections made to them.
pub(crate) struct Session {
    /// Connections by address.
    connections: HashMap<String, Connection>,
    /// The connection the topic is looked up on.
    bootstrap: String,
    /// The brokers' addresses, by id.
    brokers: HashMap<i32, String>,
    /// Each partition's leader, by partition; -1 while there's none.
    leaders: Vec<i32>,
}

impl Session {
    /// Connects to the first bootstrap broker that takes the connection, and looks up
    /// the topic.
    async fn open(kafka: &Kafka) -> Result<Self, String> {
        let mut failures = Vec::new();
        for address in &kafka.brokers {
            match Connection::open(kafka, address).await {
                Ok(connection) => {
                    let mut session = Self {
                        connections: HashMap::from([(address.clone(), connection)]),
                        bootstrap: address.clone(),
                        brokers: HashMap::new(),
                        leaders: Vec::new(),
                    };
                    session.look_up(kafka).await?;
                    return Ok(session);
                }
                Err(err) if kafka.brokers.len() == 1 => return Err(err),
                Err(err) => failures.push(format!("{address}: {err}")),
            }
        }
        Err(format!(
            "no broker took the connection ({})",
            failures.join("; ")
        ))
    }

    /// Looks up the topic's partitions and their leaders, waiting a little for a topic
    /// that's being made.
    async fn look_up(&mut self, kafka: &Kafka) -> Result<(), String> {
        let mut body = Writer::default();
        body.i32(1).string(Some(&kafka.topic))?;
        for pause in [300, 700, 0] {
            let connection = self
                .connections
                .get_mut(&self.bootstrap)
                .ok_or("the connection was lost")?;
            let answer = connection.call(api::METADATA, METADATA, &body.0).await?;
            match read_metadata(&answer, &kafka.topic)? {
                Ok((brokers, leaders)) => {
                    self.brokers = brokers;
                    self.leaders = leaders;
                    return Ok(());
                }
                Err(5) if pause > 0 => tokio::time::sleep(Duration::from_millis(pause)).await,
                Err(3) => {
                    return Err(format!(
                        "the topic `{}` doesn't exist, and the brokers don't make topics",
                        kafka.topic
                    ));
                }
                Err(code) => return Err(format!("about the topic, {}", refusal(code))),
            }
        }
        Err(format!("about the topic, {}", refusal(5)))
    }

    /// Produces `batch` to the partition `key` goes to, on its leader; if the leader
    /// moved, looks it up again and tries once more. A connection that fails is an
    /// error; a record the leader refused is an `Ok` error, with its reason.
    async fn produce(
        &mut self,
        kafka: &Kafka,
        key: Option<&[u8]>,
        batch: &[u8],
    ) -> Result<Result<(), String>, String> {
        let mut looked_again = false;
        loop {
            let partition = key.map_or(0, |key| wire::partition(key, self.leaders.len()));
            let leader = self.leaders.get(partition).copied().unwrap_or(-1);
            let code = match self.brokers.get(&leader).cloned() {
                None => 5,
                Some(address) => {
                    let connection = match self.connections.entry(address) {
                        std::collections::hash_map::Entry::Occupied(open) => open.into_mut(),
                        std::collections::hash_map::Entry::Vacant(new) => {
                            let open = Connection::open(kafka, new.key()).await?;
                            new.insert(open)
                        }
                    };
                    connection.produce(kafka, partition, batch).await?
                }
            };
            match code {
                0 => return Ok(Ok(())),
                code if MOVED.contains(&code) && !looked_again => {
                    looked_again = true;
                    self.look_up(kafka).await?;
                }
                code => return Ok(Err(refusal(code))),
            }
        }
    }
}

/// The brokers and each partition's leader from a Metadata (v1) answer, or the error
/// code the topic has.
#[expect(clippy::type_complexity, reason = "read once, here")]
fn read_metadata(
    answer: &[u8],
    topic: &str,
) -> Result<Result<(HashMap<i32, String>, Vec<i32>), i16>, String> {
    let mut reader = Reader::new(answer);
    let mut brokers = HashMap::new();
    for _ in 0..reader.array(12)? {
        let id = reader.i32()?;
        let host = reader.string()?.ok_or(GARBLED)?;
        let port = reader.i32()?;
        let _rack = reader.string()?;
        let address = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        brokers.insert(id, address);
    }
    let _controller = reader.i32()?;
    for _ in 0..reader.array(5)? {
        let code = reader.i16()?;
        let name = reader.string()?.ok_or(GARBLED)?;
        let _internal = reader.i8()?;
        let mut leaders = Vec::new();
        for _ in 0..reader.array(18)? {
            let _code = reader.i16()?;
            let index = usize::try_from(reader.i32()?).map_err(|_| GARBLED)?;
            let leader = reader.i32()?;
            for _ in 0..2 {
                // Its replicas, then those in sync.
                for _ in 0..reader.array(4)? {
                    reader.i32()?;
                }
            }
            if index >= leaders.len() {
                leaders.resize(index + 1, -1);
            }
            leaders[index] = leader;
        }
        if name != topic {
            continue;
        }
        if code != 0 {
            return Ok(Err(code));
        }
        if leaders.is_empty() {
            return Ok(Err(5));
        }
        return Ok(Ok((brokers, leaders)));
    }
    Err(GARBLED.to_owned())
}

/// What a broker's error code means.
fn refusal(code: i16) -> String {
    let name = match code {
        2 => "CORRUPT_MESSAGE",
        3 => "UNKNOWN_TOPIC_OR_PARTITION",
        5 => "LEADER_NOT_AVAILABLE",
        6 => "NOT_LEADER_OR_FOLLOWER",
        7 => "REQUEST_TIMED_OUT",
        10 => "MESSAGE_TOO_LARGE",
        17 => "INVALID_TOPIC_EXCEPTION",
        19 => "NOT_ENOUGH_REPLICAS",
        20 => "NOT_ENOUGH_REPLICAS_AFTER_APPEND",
        29 => "TOPIC_AUTHORIZATION_FAILED",
        31 => "CLUSTER_AUTHORIZATION_FAILED",
        33 => "UNSUPPORTED_SASL_MECHANISM",
        34 => "ILLEGAL_SASL_STATE",
        35 => "UNSUPPORTED_VERSION",
        58 => "SASL_AUTHENTICATION_FAILED",
        76 => "UNSUPPORTED_COMPRESSION_TYPE",
        87 => "INVALID_RECORD",
        _ => return format!("it answered with error {code}"),
    };
    format!("it answered {name} ({code})")
}

/// A connection to a broker.
struct Connection {
    stream: Stream,
    /// The last correlation id used.
    correlation: i32,
}

impl Connection {
    /// Connects to `address`, checks the broker speaks the versions used, and signs in.
    async fn open(kafka: &Kafka, address: &str) -> Result<Self, String> {
        let tcp = net::connect(address).await?;
        let stream = net::secure(tcp, address, kafka.tls.as_ref()).await?;
        let mut connection = Self {
            stream,
            correlation: 0,
        };
        let answer = connection.call(api::API_VERSIONS, 0, &[]).await?;
        let produce = kafka.compression.produce_version();
        let mut needed = vec![(api::PRODUCE, produce), (api::METADATA, METADATA)];
        if kafka.sasl.is_some() {
            needed.push((api::SASL_HANDSHAKE, SASL_HANDSHAKE));
            needed.push((api::SASL_AUTHENTICATE, SASL_AUTHENTICATE));
        }
        check_versions(&answer, &needed).map_err(|e| {
            if kafka.compression == Compression::Zstd {
                format!("{e}; zstd needs Kafka 2.1 or later")
            } else {
                e
            }
        })?;
        if let Some(sasl) = &kafka.sasl {
            connection.sign_in(sasl).await?;
        }
        Ok(connection)
    }

    /// Proves who TeiFS is with `sasl`.
    async fn sign_in(&mut self, sasl: &KafkaSasl) -> Result<(), String> {
        let mechanism = sasl.mechanism.name();
        let mut body = Writer::default();
        body.string(Some(mechanism))?;
        let answer = self
            .call(api::SASL_HANDSHAKE, SASL_HANDSHAKE, &body.0)
            .await?;
        let mut reader = Reader::new(&answer);
        let code = reader.i16()?;
        if code == 33 {
            let mut offered = Vec::new();
            for _ in 0..reader.array(2)? {
                offered.push(reader.string()?.unwrap_or_default());
            }
            return Err(format!(
                "it doesn't take SASL {mechanism}, only {}",
                offered.join(", ")
            ));
        }
        if code != 0 {
            return Err(refusal(code));
        }
        match sasl.mechanism {
            SaslMechanism::Plain => {
                let token = Zeroizing::new(format!("\0{}\0{}", sasl.user, sasl.password.as_str()));
                self.authenticate(token.as_bytes()).await.map(drop)
            }
            SaslMechanism::Scram(hash) => {
                let mut scram = Scram::new(hash, &sasl.user, &sasl.password)?;
                let first = self.authenticate(scram.first().as_bytes()).await?;
                let first = std::str::from_utf8(&first).map_err(|_| GARBLED)?;
                let last = scram.last(first)?;
                let last = self.authenticate(last.as_bytes()).await?;
                scram.check(std::str::from_utf8(&last).map_err(|_| GARBLED)?)
            }
        }
    }

    /// One SASL step: sends `token`, returns the broker's.
    async fn authenticate(&mut self, token: &[u8]) -> Result<Vec<u8>, String> {
        // Written only into memory that's wiped: it may be the password.
        let mut body = Zeroizing::new(Vec::with_capacity(token.len() + 4));
        body.extend_from_slice(
            &u32::try_from(token.len())
                .map_err(|_| GARBLED)?
                .to_be_bytes(),
        );
        body.extend_from_slice(token);
        let answer = self
            .call(api::SASL_AUTHENTICATE, SASL_AUTHENTICATE, &body)
            .await?;
        let mut reader = Reader::new(&answer);
        let code = reader.i16()?;
        let message = reader.string()?.unwrap_or_default().to_owned();
        match code {
            0 => Ok(reader.bytes()?.unwrap_or_default().to_vec()),
            58 => Err(format!("it refused the user or password ({message})")),
            code => Err(refusal(code)),
        }
    }

    /// Produces `batch` to `partition`; returns the partition's error code.
    async fn produce(
        &mut self,
        kafka: &Kafka,
        partition: usize,
        batch: &[u8],
    ) -> Result<i16, String> {
        let partition = i32::try_from(partition).map_err(|_| GARBLED)?;
        let mut body = Writer::default();
        body.string(None)? // not in a transaction
            .i16(kafka.acks.code())
            .i32(PRODUCE_TIMEOUT_MS)
            .i32(1)
            .string(Some(&kafka.topic))?
            .i32(1)
            .i32(partition)
            .bytes(batch)?;
        let version = kafka.compression.produce_version();
        let answer = self.call(api::PRODUCE, version, &body.0).await?;
        let mut reader = Reader::new(&answer);
        for _ in 0..reader.array(6)? {
            let name = reader.string()?.ok_or(GARBLED)?;
            for _ in 0..reader.array(22)? {
                let index = reader.i32()?;
                let code = reader.i16()?;
                let _offset = reader.i64()?;
                let _append_time = reader.i64()?;
                if version >= 5 {
                    let _log_start = reader.i64()?;
                }
                if name == kafka.topic && index == partition {
                    return Ok(code);
                }
            }
        }
        Err(GARBLED.to_owned())
    }

    /// Sends a request and reads its answer, after the correlation id.
    async fn call(&mut self, api: i16, version: i16, body: &[u8]) -> Result<Vec<u8>, String> {
        let lost = |e: std::io::Error| format!("the connection failed: {e}");
        self.correlation = self.correlation.wrapping_add(1);
        let request = Zeroizing::new(wire::request(api, version, self.correlation, body)?);
        self.stream.write_all(&request).await.map_err(lost)?;
        self.stream.flush().await.map_err(lost)?;
        let size = usize::try_from(self.stream.read_i32().await.map_err(lost)?)
            .ok()
            .filter(|n| (4..=MAX_ANSWER).contains(n))
            .ok_or(GARBLED)?;
        let mut answer = vec![0; size];
        self.stream.read_exact(&mut answer).await.map_err(lost)?;
        if answer[..4] != self.correlation.to_be_bytes() {
            return Err(GARBLED.to_owned());
        }
        answer.drain(..4);
        Ok(answer)
    }
}

/// Checks an `ApiVersions` (v0) answer: the broker takes each `(api, version)`.
fn check_versions(answer: &[u8], needed: &[(i16, i16)]) -> Result<(), String> {
    let mut reader = Reader::new(answer);
    let code = reader.i16()?;
    if code != 0 {
        return Err(refusal(code));
    }
    let mut ranges = HashMap::new();
    for _ in 0..reader.array(6)? {
        ranges.insert(reader.i16()?, (reader.i16()?, reader.i16()?));
    }
    for (api, version) in needed {
        if !ranges
            .get(api)
            .is_some_and(|(min, max)| (min..=max).contains(&version))
        {
            return Err(format!(
                "it doesn't speak the Kafka TeiFS speaks (API {api} version {version}): \
                 use Kafka 1.0 or later"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brokers_topics_and_options_are_checked() {
        let kafka = Kafka::new("a:9092; b:9093", "s3.events_1-x").unwrap();
        assert_eq!(kafka.brokers, ["a:9092", "b:9093"]);
        assert_eq!(
            kafka.shown(),
            "kafka://a:9092;b:9093 topic s3.events_1-x (acks=all)"
        );
        for bad in ["", ";", "a", "a:0", "a:9092;b"] {
            assert!(Kafka::new(bad, "t").is_err(), "{bad:?}");
        }
        let long = "t".repeat(250);
        for bad in ["", ".", "..", "a/b", "a b", "ü", long.as_str()] {
            assert!(Kafka::new("a:9092", bad).is_err(), "{bad:?}");
        }
        assert!(Kafka::new("a:9092", &"t".repeat(249)).is_ok());
        assert_eq!(Acks::parse("ALL"), Ok(Acks::All));
        assert_eq!(Acks::parse("-1"), Ok(Acks::All));
        assert_eq!(Acks::parse("1").map(Acks::code), Ok(1));
        assert!(Acks::parse("0").is_err(), "no acknowledgement loses events");
        assert_eq!(
            SaslMechanism::parse("SCRAM-sha-512").map(SaslMechanism::name),
            Ok("SCRAM-SHA-512")
        );
        assert_eq!(SaslMechanism::parse("plain"), Ok(SaslMechanism::Plain));
        assert!(SaslMechanism::parse("gssapi").is_err());
        let mut kafka = Kafka::new("a:9092", "t").unwrap();
        kafka.acks = Acks::Leader;
        kafka.compression = Compression::Gzip;
        kafka.sasl = Some(KafkaSasl {
            mechanism: SaslMechanism::Scram(ScramHash::Sha256),
            user: "teifs".into(),
            password: Zeroizing::new("hunter2".into()),
        });
        assert_eq!(
            kafka.shown(),
            "kafka://a:9092 topic t (acks=1, gzip, SASL SCRAM-SHA-256)"
        );
        assert!(!format!("{kafka:?}").contains("hunter2"));
    }

    #[test]
    fn versions_are_checked() {
        let mut answer = Writer::default();
        answer.i16(0).i32(2);
        answer.i16(api::PRODUCE).i16(3).i16(12);
        answer.i16(api::METADATA).i16(0).i16(13);
        let needed = [
            (api::PRODUCE, Compression::None.produce_version()),
            (api::METADATA, METADATA),
        ];
        assert_eq!(check_versions(&answer.0, &needed), Ok(()));
        let err = check_versions(&answer.0, &[(api::SASL_HANDSHAKE, 1)]).unwrap_err();
        assert!(err.contains("API 17"), "{err}");
        let err = check_versions(&answer.0, &[(api::PRODUCE, 2)]).unwrap_err();
        assert!(err.contains("version 2"), "{err}");
        assert!(check_versions(&[0, 35, 0, 0, 0, 0], &needed).is_err());
    }

    #[test]
    fn metadata_names_each_partitions_leader() {
        let mut answer = Writer::default();
        answer.i32(2);
        answer
            .i32(1)
            .string(Some("k1"))
            .unwrap()
            .i32(9092)
            .string(None)
            .unwrap();
        answer
            .i32(2)
            .string(Some("::1"))
            .unwrap()
            .i32(9093)
            .string(Some("r"))
            .unwrap();
        answer.i32(1); // controller
        answer.i32(2);
        // Another topic first, then ours with its partitions out of order.
        answer.i16(0).string(Some("other")).unwrap().i8(0).i32(0);
        answer.i16(0).string(Some("t")).unwrap().i8(0).i32(2);
        answer.i16(0).i32(1).i32(2).i32(1).i32(2).i32(0);
        answer
            .i16(0)
            .i32(0)
            .i32(1)
            .i32(2)
            .i32(1)
            .i32(2)
            .i32(1)
            .i32(1);
        let (brokers, leaders) = read_metadata(&answer.0, "t").unwrap().unwrap();
        assert_eq!(brokers[&1], "k1:9092");
        assert_eq!(brokers[&2], "[::1]:9093");
        assert_eq!(leaders, [1, 2]);
        assert!(read_metadata(&answer.0, "missing").is_err());
        assert!(read_metadata(&answer.0[..answer.0.len() - 1], "t").is_err());
        let mut unknown = Writer::default();
        unknown.i32(0).i32(1).i32(1);
        unknown.i16(3).string(Some("t")).unwrap().i8(0).i32(0);
        assert_eq!(read_metadata(&unknown.0, "t"), Ok(Err(3)));
        let mut leaderless = Writer::default();
        leaderless.i32(0).i32(1).i32(1);
        leaderless.i16(0).string(Some("t")).unwrap().i8(0).i32(0);
        assert_eq!(read_metadata(&leaderless.0, "t"), Ok(Err(5)));
    }

    /// An answer to another request than the one sent is refused, as is one larger than
    /// read.
    #[tokio::test]
    async fn answers_must_match_their_request() {
        for (size, correlation) in [(8, 2), (8, 1), (i32::MAX, 1), (3, 1)] {
            let (client, mut broker) = tokio::io::duplex(1024);
            let mut connection = Connection {
                stream: Box::new(client),
                correlation: 0,
            };
            tokio::spawn(async move {
                let mut request = [0; 19];
                broker.read_exact(&mut request).await.unwrap();
                let mut answer = Writer::default();
                answer.i32(size).i32(correlation).i32(7);
                broker.write_all(&answer.0).await.unwrap();
            });
            let answer = connection.call(api::API_VERSIONS, 0, &[]).await;
            if (size, correlation) == (8, 1) {
                assert_eq!(answer, Ok(vec![0, 0, 0, 7]));
            } else {
                assert_eq!(answer, Err(GARBLED.to_owned()), "{size} {correlation}");
            }
        }
    }

    #[test]
    fn refusals_are_named() {
        assert_eq!(refusal(6), "it answered NOT_LEADER_OR_FOLLOWER (6)");
        assert_eq!(refusal(999), "it answered with error 999");
    }
}
