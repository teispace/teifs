//! AMQP 0-9-1 targets (`RabbitMQ`, `LavinMQ`), as `MinIO`'s: each event, as a webhook is
//! sent it, published to an exchange with a routing key, `application/json`, with the
//! headers `minio-bucket` and `minio-event` `MinIO` sets. The exchange is declared when the
//! connection is made (or only checked, with `declare=false`), and each message waits for
//! the broker's publisher confirm, so none is lost between them. Messages are persistent
//! by default. One connection and channel, made again after a failure; TLS with
//! `amqps://`; a user and password (`guest` by default, as AMQP's URIs have it).

pub(crate) mod wire;

use std::{fmt, future::Future, sync::Arc};

use rustls::ClientConfig;
use teifs_types::notify::EventMessage;
use tokio::io::AsyncWriteExt;
use wire::{Field, Frame, GARBLED, Reader, Writer, frame, method};
use zeroize::Zeroizing;

use crate::net::{self, Kept, Stream};

/// The largest frame TeiFS takes or sends; the broker may agree to less.
const FRAME_MAX: u32 = 128 * 1024;
/// The channel used.
const CHANNEL: u16 = 1;

/// An exchange events are published to.
#[derive(Clone)]
pub struct Amqp {
    /// The broker, `HOST:PORT`.
    pub address: String,
    /// The virtual host.
    pub vhost: String,
    /// The exchange; empty for the default exchange (the routing key names a queue).
    pub exchange: String,
    /// The routing key.
    pub routing_key: String,
    /// How the exchange is declared (made if missing) when a connection is made; none
    /// only checks that it exists.
    pub declare: Option<Exchange>,
    /// Whether a message no queue takes is a failure (tried again), rather than dropped.
    pub mandatory: bool,
    /// Whether messages survive the broker's restart, in durable queues.
    pub persistent: bool,
    /// The user; `guest` when there's none.
    pub user: Option<String>,
    /// Its password; `guest` when there's no user.
    pub password: Option<Zeroizing<String>>,
    /// TLS, and how the broker is verified; none for plain TCP.
    pub tls: Option<Arc<ClientConfig>>,
    /// Whether its URL was `amqps://`.
    secure: bool,
    connection: Kept<Connection>,
}

/// How an exchange is declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// Its type: `direct`, `fanout`, `topic` or `headers`.
    pub kind: String,
    /// Whether it survives the broker's restart.
    pub durable: bool,
    /// Whether it's removed once no queue is bound to it.
    pub auto_delete: bool,
    /// Whether it takes messages only from other exchanges.
    pub internal: bool,
}

impl Default for Exchange {
    /// A durable `direct` exchange.
    fn default() -> Self {
        Self {
            kind: "direct".to_owned(),
            durable: true,
            auto_delete: false,
            internal: false,
        }
    }
}

impl Exchange {
    /// Sets its type.
    ///
    /// # Errors
    ///
    /// When it's none of AMQP's.
    pub fn set_kind(&mut self, kind: &str) -> Result<(), String> {
        let kind = kind.to_ascii_lowercase();
        if !matches!(kind.as_str(), "direct" | "fanout" | "topic" | "headers") {
            return Err(format!(
                "`{kind}` isn't an exchange type: give direct, fanout, topic or headers"
            ));
        }
        self.kind = kind;
        Ok(())
    }
}

impl Amqp {
    /// Events for `exchange` with `routing_key` on the broker at `url`
    /// (`amqp[s]://HOST[:PORT][/VHOST]`, the virtual host `/` when none is given), the
    /// exchange a durable `direct` one, declared, and messages persistent.
    ///
    /// # Errors
    ///
    /// When `url` isn't such a URL, or has credentials in it, or the exchange or routing
    /// key is longer than AMQP takes.
    pub fn new(url: &str, exchange: &str, routing_key: &str) -> Result<Self, String> {
        let parsed = reqwest::Url::parse(url.trim())
            .map_err(|_| format!("`{url}` isn't an AMQP URL: give amqp://HOST:PORT/VHOST"))?;
        let secure = match parsed.scheme() {
            "amqp" => false,
            "amqps" => true,
            _ => {
                return Err(format!(
                    "`{url}` isn't an AMQP URL: give amqp://HOST:PORT/VHOST"
                ));
            }
        };
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(
                "give its user as user=NAME and its password in the environment, not in the URL"
                    .to_owned(),
            );
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("`{url}` names no host"))?;
        let port = parsed.port().unwrap_or(if secure { 5671 } else { 5672 });
        let vhost = match parsed.path().trim_start_matches('/') {
            "" => "/".to_owned(),
            path => percent_decode(path)?,
        };
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(format!(
                "`{url}`: give its options as NAME=VALUE, not in the URL"
            ));
        }
        for (what, text) in [
            ("exchange", exchange),
            ("routing key", routing_key),
            ("virtual host", vhost.as_str()),
        ] {
            if text.len() > 255 {
                return Err(format!("the {what} is longer than AMQP's 255 bytes"));
            }
        }
        if !exchange
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(format!(
                "`{exchange}` isn't an exchange's name: use letters, digits, `-`, `_`, `.` and `:`"
            ));
        }
        if exchange.is_empty() && routing_key.is_empty() {
            return Err("name the exchange, or the queue as the routing key".to_owned());
        }
        Ok(Self {
            // An IPv6 host keeps its brackets.
            address: format!("{host}:{port}"),
            vhost,
            exchange: exchange.to_owned(),
            routing_key: routing_key.to_owned(),
            declare: Some(Exchange::default()),
            mandatory: false,
            persistent: true,
            user: None,
            password: None,
            tls: None,
            secure,
            connection: Kept::new(),
        })
    }

    /// Whether its URL asked for TLS (`amqps://`).
    #[must_use]
    pub const fn wants_tls(&self) -> bool {
        self.secure
    }

    /// Where it publishes.
    #[must_use]
    pub fn shown(&self) -> String {
        let vhost = if self.vhost == "/" {
            String::new()
        } else {
            self.vhost.replace('%', "%25").replace('/', "%2F")
        };
        let exchange = if self.exchange.is_empty() {
            "the default exchange".to_owned()
        } else {
            match &self.declare {
                Some(declared) => format!("exchange {} ({})", self.exchange, declared.kind),
                None => format!("exchange {}", self.exchange),
            }
        };
        let mut shown = format!(
            "{}://{}/{vhost} {exchange}",
            if self.tls.is_some() { "amqps" } else { "amqp" },
            self.address,
        );
        if !self.routing_key.is_empty() {
            shown.push_str(" key ");
            shown.push_str(&self.routing_key);
        }
        shown
    }

    /// Publishes `body` and waits for the broker's confirm.
    pub(crate) async fn send(&self, body: &[u8]) -> Result<(), String> {
        let request = (self, body);
        self.connection
            .run(self, false, &request, |open, (amqp, body)| {
                Box::pin(open.publish(amqp, body))
            })
            .await?
    }

    /// Checks that the broker takes the connection, the user and the exchange, without
    /// publishing.
    pub(crate) async fn test(&self) -> Result<(), String> {
        self.connection
            .run(self, true, &(), |_, ()| Box::pin(async { Ok(()) }))
            .await
    }
}

impl net::Connects for Amqp {
    type Connection = Connection;

    fn connect(&self) -> impl Future<Output = Result<Connection, String>> + Send {
        Connection::open(self)
    }
}

impl fmt::Debug for Amqp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Amqp")
            .field("at", &self.shown())
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// `%XX` decoded, as a URL's path is.
fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| format!("`{text}` isn't a virtual host's name"))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("`{text}` isn't a virtual host's name"))
}

/// A connection to a broker, with a channel in confirm mode.
pub(crate) struct Connection {
    stream: Stream,
    /// The largest frame agreed.
    frame_max: usize,
    /// The last message's delivery tag.
    tag: u64,
}

impl Connection {
    /// Connects, signs in, opens the virtual host and a channel, declares or checks the
    /// exchange, and turns publisher confirms on.
    async fn open(amqp: &Amqp) -> Result<Self, String> {
        let tcp = net::connect(&amqp.address).await?;
        let stream = net::secure(tcp, &amqp.address, amqp.tls.as_ref()).await?;
        let mut connection = Self {
            stream,
            frame_max: FRAME_MAX as usize,
            tag: 0,
        };
        connection.write(wire::PROTOCOL_HEADER).await?;
        connection.handshake(amqp).await?;
        connection
            .call(
                CHANNEL,
                Writer::method(method::CHANNEL_OPEN).shortstr("")?,
                method::CHANNEL_OPEN_OK,
            )
            .await?;
        if !amqp.exchange.is_empty() {
            // Passive when it's only checked: the broker ignores the rest.
            let (passive, exchange) = match &amqp.declare {
                Some(exchange) => (false, exchange.clone()),
                None => (true, Exchange::default()),
            };
            let mut declare = Writer::method(method::EXCHANGE_DECLARE);
            declare
                .short(0)
                .shortstr(&amqp.exchange)?
                .shortstr(&exchange.kind)?
                .bits(&[
                    passive,
                    exchange.durable && !passive,
                    exchange.auto_delete && !passive,
                    exchange.internal && !passive,
                    false,
                ])
                .table(&[])?;
            connection
                .call(CHANNEL, &mut declare, method::EXCHANGE_DECLARE_OK)
                .await
                .map_err(|e| {
                    if e.contains("PRECONDITION_FAILED") {
                        format!(
                            "{e}: the exchange exists with other settings; match them, or give \
                             declare=false"
                        )
                    } else {
                        e
                    }
                })?;
        }
        connection
            .call(
                CHANNEL,
                Writer::method(method::CONFIRM_SELECT).bits(&[false]),
                method::CONFIRM_SELECT_OK,
            )
            .await?;
        Ok(connection)
    }

    /// `Start` → `StartOk` (PLAIN), `Tune` → `TuneOk`, `Open` → `OpenOk`.
    async fn handshake(&mut self, amqp: &Amqp) -> Result<(), String> {
        let start = self.read().await?;
        let Some((method::CONNECTION_START, mut args)) = start.method() else {
            return Err(GARBLED.to_owned());
        };
        let (major, minor) = (args.octet()?, args.octet()?);
        args.skip_table()?;
        let mechanisms = String::from_utf8_lossy(args.longstr()?).into_owned();
        if (major, minor) != (0, 9) {
            return Err(format!("it speaks AMQP {major}-{minor}, not 0-9-1"));
        }
        if !mechanisms.split(' ').any(|m| m == "PLAIN") {
            return Err(format!(
                "it doesn't take a user and password (SASL PLAIN), only {mechanisms}"
            ));
        }
        let (user, password) = match (&amqp.user, &amqp.password) {
            (Some(user), Some(password)) => (user.as_str(), password.as_str()),
            (Some(user), None) => (user.as_str(), ""),
            (None, _) => ("guest", "guest"),
        };
        // Written only into memory that's wiped: it holds the password.
        let response = Zeroizing::new(format!("\0{user}\0{password}"));
        let mut start_ok = Writer::method(method::CONNECTION_START_OK);
        start_ok
            .table(&[
                ("product", Field::Str("TeiFS")),
                ("version", Field::Str(env!("CARGO_PKG_VERSION"))),
                ("platform", Field::Str("Rust")),
                (
                    "capabilities",
                    Field::Table(&[
                        ("publisher_confirms", Field::Bool(true)),
                        ("basic.nack", Field::Bool(true)),
                        ("connection.blocked", Field::Bool(false)),
                    ]),
                ),
            ])?
            .shortstr("PLAIN")?
            .longstr(response.as_bytes())?
            .shortstr("en_US")?;
        let start_ok = Zeroizing::new(start_ok.0);
        self.write(&wire::frame(frame::METHOD, 0, &start_ok)?)
            .await?;
        let tune = self
            .read()
            .await
            .map_err(|e| format!("it refused the user or password, or the connection ({e})"))?;
        let mut args = match tune.method() {
            Some((method::CONNECTION_TUNE, args)) => args,
            Some((method::CONNECTION_CLOSE, args)) => return Err(closed(args, "the connection")),
            _ => return Err(GARBLED.to_owned()),
        };
        let channel_max = args.short()?;
        let frame_max = args.long()?;
        let _heartbeat = args.short()?;
        // The broker's limit, if it has one, else TeiFS's; at least the 4096 AMQP allows.
        let frame_max = match frame_max {
            0 => FRAME_MAX,
            n => n.clamp(4096, FRAME_MAX),
        };
        self.frame_max = frame_max as usize;
        let mut tune_ok = Writer::method(method::CONNECTION_TUNE_OK);
        // No heartbeats: a connection the broker dropped while idle is made again at once.
        tune_ok.short(channel_max).long(frame_max).short(0);
        self.write(&wire::frame(frame::METHOD, 0, &tune_ok.0)?)
            .await?;
        self.call(
            0,
            Writer::method(method::CONNECTION_OPEN)
                .shortstr(&amqp.vhost)?
                .shortstr("")?
                .bits(&[false]),
            method::CONNECTION_OPEN_OK,
        )
        .await
    }

    /// Publishes `body` and waits for its confirm.
    async fn publish(&mut self, amqp: &Amqp, body: &[u8]) -> Result<Result<(), String>, String> {
        let event = serde_json::from_slice::<EventMessage>(body).ok();
        let bucket = event
            .as_ref()
            .and_then(|e| e.records.first())
            .map_or("", |r| r.s3.bucket.name.as_str());
        let name = event.as_ref().map_or("", |e| e.event_name.as_str());
        let mut out = wire::frame(
            frame::METHOD,
            CHANNEL,
            &Writer::method(method::BASIC_PUBLISH)
                .short(0)
                .shortstr(&amqp.exchange)?
                .shortstr(&amqp.routing_key)?
                .bits(&[amqp.mandatory, false])
                .0,
        )?;
        let mut header = Writer::default();
        header
            .short(wire::BASIC)
            .short(0)
            .longlong(body.len() as u64)
            // content-type, headers and delivery-mode
            .short(0b1011_0000_0000_0000)
            .shortstr("application/json")?
            .table(&[
                ("minio-bucket", Field::Str(bucket)),
                ("minio-event", Field::Str(name)),
            ])?
            .octet(if amqp.persistent { 2 } else { 1 });
        out.extend(wire::frame(frame::HEADER, CHANNEL, &header.0)?);
        for chunk in body.chunks(self.frame_max - 8) {
            out.extend(wire::frame(frame::BODY, CHANNEL, chunk)?);
        }
        self.write(&out).await?;
        self.tag += 1;
        let mut returned = None;
        loop {
            let frame = self.read().await?;
            let Some((method, mut args)) = frame.method() else {
                // A returned message's header and body, or a heartbeat.
                continue;
            };
            match method {
                method::BASIC_RETURN => {
                    let code = args.short()?;
                    returned = Some(format!("{code} {}", args.shortstr()?));
                }
                method::BASIC_ACK | method::BASIC_NACK => {
                    let tag = args.longlong()?;
                    let multiple = args.octet()? & 1 == 1;
                    if tag != self.tag && !(multiple && tag > self.tag) {
                        // An earlier message's, sent before a timeout.
                        continue;
                    }
                    if method == method::BASIC_NACK {
                        return Ok(Err(
                            "the broker didn't take it (it answered nack)".to_owned()
                        ));
                    }
                    return Ok(match returned {
                        None => Ok(()),
                        Some(why) => Err(format!(
                            "no queue took it: it was returned ({why}); bind a queue, or \
                             leave out mandatory=true"
                        )),
                    });
                }
                method::CHANNEL_CLOSE => return Err(closed(args, "the channel")),
                method::CONNECTION_CLOSE => return Err(closed(args, "the connection")),
                _ => {}
            }
        }
    }

    /// Sends a method on `channel` and reads until its answer `expected`.
    async fn call(
        &mut self,
        channel: u16,
        request: &mut Writer,
        expected: (u16, u16),
    ) -> Result<(), String> {
        self.write(&wire::frame(frame::METHOD, channel, &request.0)?)
            .await?;
        loop {
            let frame = self.read().await?;
            match frame.method() {
                Some((method, _)) if method == expected => return Ok(()),
                Some((method::CHANNEL_CLOSE, args)) => return Err(closed(args, "the channel")),
                Some((method::CONNECTION_CLOSE, args)) => {
                    return Err(closed(args, "the connection"));
                }
                None if frame.kind == frame::HEARTBEAT => {}
                _ => return Err(GARBLED.to_owned()),
            }
        }
    }

    async fn read(&mut self) -> Result<Frame, String> {
        wire::read_frame(&mut self.stream, self.frame_max).await
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        let lost = |e: std::io::Error| format!("the connection failed: {e}");
        self.stream.write_all(bytes).await.map_err(lost)?;
        self.stream.flush().await.map_err(lost)
    }
}

/// What a `Close` from the broker says.
fn closed(mut args: Reader<'_>, what: &str) -> String {
    let code = args.short().unwrap_or_default();
    let text = args.shortstr().unwrap_or_default();
    format!("it closed {what}: {code} {text}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_exchanges_and_keys_are_checked() {
        let amqp = Amqp::new("amqp://rabbit.local", "s3", "events").unwrap();
        assert_eq!(
            (amqp.address.as_str(), amqp.vhost.as_str()),
            ("rabbit.local:5672", "/")
        );
        assert!(!amqp.wants_tls());
        assert_eq!(
            amqp.shown(),
            "amqp://rabbit.local:5672/ exchange s3 (direct) key events"
        );
        let secure = Amqp::new("amqps://[::1]/prod%2Fs3", "s3", "").unwrap();
        assert_eq!(
            (secure.address.as_str(), secure.vhost.as_str()),
            ("[::1]:5671", "prod/s3")
        );
        assert!(secure.wants_tls());
        let queue = Amqp::new("amqp://h:5673/%2f", "", "events").unwrap();
        assert_eq!(queue.vhost, "/");
        assert_eq!(
            queue.shown(),
            "amqp://h:5673/ the default exchange key events"
        );
        for (url, exchange, key) in [
            ("http://h", "s3", ""),
            ("amqp://user:pw@h", "s3", ""),
            ("amqp://user@h", "s3", ""),
            ("amqp://h?heartbeat=10", "s3", ""),
            ("amqp://h/%zz", "s3", ""),
            ("amqp://h", "a b", ""),
            ("amqp://h", "", ""),
            ("h:5672", "s3", ""),
        ] {
            assert!(Amqp::new(url, exchange, key).is_err(), "{url} {exchange:?}");
        }
        assert!(Amqp::new("amqp://h", "s3", &"k".repeat(256)).is_err());
        assert_eq!(
            Amqp::new("amqp://h", "s3", "").unwrap().shown(),
            "amqp://h:5672/ exchange s3 (direct)"
        );
        let mut typed = Amqp::new("amqp://h", "s3", "k").unwrap();
        let mut exchange = Exchange::default();
        exchange.set_kind("Topic").unwrap();
        assert_eq!(exchange.kind, "topic");
        assert!(exchange.set_kind("x-delayed").is_err());
        typed.declare = None;
        assert_eq!(typed.shown(), "amqp://h:5672/ exchange s3 key k");
        typed.password = Some(Zeroizing::new("hunter2".into()));
        assert!(!format!("{typed:?}").contains("hunter2"));
    }
}
