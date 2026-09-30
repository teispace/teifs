//! An AMQP 0-9-1 broker on this machine, answering as `RabbitMQ` does: PLAIN sign-in,
//! virtual hosts, exchanges declared or checked (refusing one declared with other
//! settings), publisher confirms, and mandatory messages no queue takes returned.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::amqp::{
    Exchange,
    wire::{self, Frame, Reader, Writer, frame, method},
};

/// How an [`AmqpServer`] is made.
#[derive(Debug, Clone)]
pub struct AmqpSetup {
    /// The user and password it takes.
    pub login: (String, String),
    /// The virtual hosts it has.
    pub vhosts: Vec<String>,
    /// The exchanges it has, by name: their type and whether they're durable.
    pub exchanges: BTreeMap<String, (String, bool)>,
    /// Which `(exchange, routing key)` a queue takes.
    pub bindings: Vec<(String, String)>,
    /// The largest frame it takes.
    pub frame_max: u32,
}

impl Default for AmqpSetup {
    /// `guest`/`guest`, the virtual host `/`, no exchanges or queues, and AMQP's smallest
    /// frames.
    fn default() -> Self {
        Self {
            login: ("guest".into(), "guest".into()),
            vhosts: vec!["/".into()],
            exchanges: BTreeMap::new(),
            bindings: Vec::new(),
            frame_max: 4096,
        }
    }
}

/// An exchange declaration an [`AmqpServer`] took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmqpDeclare {
    /// The exchange.
    pub name: String,
    /// Whether it was only checked.
    pub passive: bool,
    /// How it was declared.
    pub exchange: Exchange,
}

/// A message an [`AmqpServer`] took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmqpMessage {
    /// Its virtual host.
    pub vhost: String,
    /// Its exchange.
    pub exchange: String,
    /// Its routing key.
    pub routing_key: String,
    /// Whether it was mandatory.
    pub mandatory: bool,
    /// Its content type.
    pub content_type: String,
    /// Its string headers.
    pub headers: Vec<(String, String)>,
    /// Its delivery mode (2 is persistent).
    pub delivery_mode: u8,
    /// Its body.
    pub body: String,
    /// How many body frames it came in.
    pub frames: usize,
}

#[derive(Default)]
struct State {
    declares: Vec<AmqpDeclare>,
    messages: Vec<AmqpMessage>,
    /// Messages still to refuse (nack).
    nacking: usize,
    /// The heartbeat each connection asked for.
    heartbeats: Vec<u16>,
}

struct Shared {
    setup: Mutex<AmqpSetup>,
    state: Mutex<State>,
}

/// An AMQP 0-9-1 broker for tests.
pub struct AmqpServer {
    address: String,
    shared: Arc<Shared>,
}

impl AmqpServer {
    /// Starts one.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(setup: AmqpSetup) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let address = listener.local_addr().expect("a bound address").to_string();
        let shared = Arc::new(Shared {
            setup: Mutex::new(setup),
            state: Mutex::new(State::default()),
        });
        let served = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shared = Arc::clone(&served);
                tokio::spawn(async move {
                    let _ = serve(stream, &shared).await;
                });
            }
        });
        Self { address, shared }
    }

    /// Its `HOST:PORT`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Binds a queue to `exchange` with `routing_key`.
    pub fn bind(&self, exchange: &str, routing_key: &str) {
        self.shared
            .setup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bindings
            .push((exchange.to_owned(), routing_key.to_owned()));
    }

    /// Refuses (nacks) the next `count` messages, each nack after a late ack of the
    /// connection's message before it, as a client that timed out may see.
    pub fn nack(&self, count: usize) {
        self.state().nacking = count;
    }

    /// The exchange declarations taken.
    #[must_use]
    pub fn declares(&self) -> Vec<AmqpDeclare> {
        self.state().declares.clone()
    }

    /// The heartbeat each connection asked for.
    #[must_use]
    pub fn heartbeats(&self) -> Vec<u16> {
        self.state().heartbeats.clone()
    }

    /// The messages taken, once there are at least `count`.
    ///
    /// # Panics
    ///
    /// When there aren't within ten seconds.
    pub async fn messages(&self, count: usize) -> Vec<AmqpMessage> {
        for _ in 0..500 {
            let taken = self.state().messages.clone();
            if taken.len() >= count {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the AMQP broker never took {count} messages");
    }
}

async fn send(stream: &mut TcpStream, channel: u16, method: &Writer) -> Result<(), String> {
    let frame = wire::frame(frame::METHOD, channel, &method.0)?;
    stream.write_all(&frame).await.map_err(|e| e.to_string())
}

/// Sends a `Close` of the connection (channel 0) or a channel.
async fn close(stream: &mut TcpStream, channel: u16, code: u16, text: &str) -> Result<(), String> {
    let what = if channel == 0 {
        method::CONNECTION_CLOSE
    } else {
        method::CHANNEL_CLOSE
    };
    let mut out = Writer::method(what);
    out.short(code).shortstr(text)?.short(0).short(0);
    send(stream, channel, &out).await
}

async fn expect(stream: &mut TcpStream, max: usize, wanted: (u16, u16)) -> Result<Frame, String> {
    let frame = wire::read_frame(stream, max).await?;
    match frame.method() {
        Some((method, _)) if method == wanted => Ok(frame),
        _ => Err(format!("expected {wanted:?}")),
    }
}

/// The connection's handshake: the virtual host opened and the largest frame agreed, or
/// none when the connection was refused.
async fn handshake(
    stream: &mut TcpStream,
    shared: &Shared,
    setup: &AmqpSetup,
) -> Result<Option<(String, usize)>, String> {
    let mut header = [0; 8];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| e.to_string())?;
    if &header != wire::PROTOCOL_HEADER {
        let _ = stream.write_all(wire::PROTOCOL_HEADER).await;
        return Ok(None);
    }
    let mut start = Writer::method(method::CONNECTION_START);
    start
        .octet(0)
        .octet(9)
        .table(&[("product", wire::Field::Str("fake"))])?
        .longstr(b"AMQPLAIN PLAIN")?
        .longstr(b"en_US")?;
    send(stream, 0, &start).await?;
    let start_ok = expect(stream, 1 << 16, method::CONNECTION_START_OK).await?;
    let (_, mut args) = start_ok.method().ok_or("no method")?;
    args.skip_table()?;
    let mechanism = args.shortstr()?.to_owned();
    let response = args.longstr()?.to_vec();
    let (user, password) = &setup.login;
    if mechanism != "PLAIN" || response != format!("\0{user}\0{password}").into_bytes() {
        close(
            stream,
            0,
            403,
            "ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN",
        )
        .await?;
        return Ok(None);
    }
    let mut tune = Writer::method(method::CONNECTION_TUNE);
    tune.short(2047).long(setup.frame_max).short(60);
    send(stream, 0, &tune).await?;
    let tune_ok = expect(stream, 1 << 16, method::CONNECTION_TUNE_OK).await?;
    let (_, mut args) = tune_ok.method().ok_or("no method")?;
    let (_, frame_max, heartbeat) = (args.short()?, args.long()?, args.short()?);
    if frame_max > setup.frame_max {
        close(stream, 0, 501, "FRAME_ERROR - frame_max too large").await?;
        return Ok(None);
    }
    shared
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .heartbeats
        .push(heartbeat);
    let max = usize::try_from(setup.frame_max).map_err(|_| "frame max")?;
    let open = expect(stream, max, method::CONNECTION_OPEN).await?;
    let (_, mut args) = open.method().ok_or("no method")?;
    let vhost = args.shortstr()?.to_owned();
    if !setup.vhosts.contains(&vhost) {
        let text = format!("NOT_ALLOWED - vhost {vhost} not found");
        close(stream, 0, 530, &text).await?;
        return Ok(None);
    }
    let mut open_ok = Writer::method(method::CONNECTION_OPEN_OK);
    open_ok.shortstr("")?;
    send(stream, 0, &open_ok).await?;
    Ok(Some((vhost, max)))
}

async fn serve(mut stream: TcpStream, shared: &Shared) -> Result<(), String> {
    let setup = shared
        .setup
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some((vhost, max)) = handshake(&mut stream, shared, &setup).await? else {
        return Ok(());
    };
    let mut tag = 0u64;
    loop {
        let frame = wire::read_frame(&mut stream, max).await?;
        let channel = frame.channel;
        let Some((method, mut args)) = frame.method() else {
            return Err("content outside a publish".to_owned());
        };
        match method {
            method::CHANNEL_OPEN => {
                let mut ok = Writer::method(method::CHANNEL_OPEN_OK);
                ok.longstr(b"")?;
                send(&mut stream, channel, &ok).await?;
            }
            method::EXCHANGE_DECLARE => {
                let _ = args.short()?;
                let name = args.shortstr()?.to_owned();
                let kind = args.shortstr()?.to_owned();
                let bits = args.octet()?;
                let declare = AmqpDeclare {
                    name: name.clone(),
                    passive: bits & 1 != 0,
                    exchange: Exchange {
                        kind: kind.clone(),
                        durable: bits & 2 != 0,
                        auto_delete: bits & 4 != 0,
                        internal: bits & 8 != 0,
                    },
                };
                let refusal = declared(shared, &declare, &vhost);
                shared
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .declares
                    .push(declare);
                match refusal {
                    Some((code, text)) => return close(&mut stream, channel, code, &text).await,
                    None => {
                        send(
                            &mut stream,
                            channel,
                            &Writer::method(method::EXCHANGE_DECLARE_OK),
                        )
                        .await?;
                    }
                }
            }
            method::CONFIRM_SELECT => {
                send(
                    &mut stream,
                    channel,
                    &Writer::method(method::CONFIRM_SELECT_OK),
                )
                .await?;
            }
            method::BASIC_PUBLISH => {
                tag += 1;
                let publish = Publish {
                    channel,
                    vhost: &vhost,
                    max,
                    tag,
                };
                if !publish.take(&mut stream, shared, args).await? {
                    return Ok(());
                }
            }
            _ => return Err(format!("unexpected {method:?}")),
        }
    }
}

/// A message being published.
struct Publish<'a> {
    channel: u16,
    vhost: &'a str,
    max: usize,
    tag: u64,
}

impl Publish<'_> {
    /// Reads the message and answers it: returned if mandatory and no queue takes it,
    /// then acknowledged (or refused); `false` when the channel was closed instead.
    async fn take(
        &self,
        stream: &mut TcpStream,
        shared: &Shared,
        mut args: Reader<'_>,
    ) -> Result<bool, String> {
        let _ = args.short()?;
        let exchange = args.shortstr()?.to_owned();
        let routing_key = args.shortstr()?.to_owned();
        let mandatory = args.octet()? & 1 != 0;
        let (mut message, content) =
            read_content(stream, self.max, self.vhost, &exchange, &routing_key).await?;
        message.mandatory = mandatory;
        let (known, routes) = {
            let setup = shared.setup.lock().unwrap_or_else(PoisonError::into_inner);
            (
                exchange.is_empty() || setup.exchanges.contains_key(&exchange),
                setup
                    .bindings
                    .iter()
                    .any(|(e, k)| *e == exchange && *k == routing_key),
            )
        };
        if !known {
            let text = format!(
                "NOT_FOUND - no exchange '{exchange}' in vhost '{}'",
                self.vhost
            );
            close(stream, self.channel, 404, &text).await?;
            return Ok(false);
        }
        let nack = {
            let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.nacking > 0 {
                state.nacking -= 1;
                true
            } else {
                if routes || !mandatory {
                    state.messages.push(message);
                }
                false
            }
        };
        if mandatory && !routes && !nack {
            let mut returned = Writer::method(method::BASIC_RETURN);
            returned
                .short(312)
                .shortstr("NO_ROUTE")?
                .shortstr(&exchange)?
                .shortstr(&routing_key)?;
            send(stream, self.channel, &returned).await?;
            stream
                .write_all(&content)
                .await
                .map_err(|e| e.to_string())?;
        }
        if nack && self.tag > 1 {
            let mut late = Writer::method(method::BASIC_ACK);
            late.longlong(self.tag - 1).octet(0);
            send(stream, self.channel, &late).await?;
        }
        let mut answer = Writer::method(if nack {
            method::BASIC_NACK
        } else {
            method::BASIC_ACK
        });
        answer.longlong(self.tag).octet(0);
        send(stream, self.channel, &answer).await?;
        Ok(true)
    }
}

/// Why an exchange declaration is refused, as `RabbitMQ` refuses it; declares it if not.
fn declared(shared: &Shared, declare: &AmqpDeclare, vhost: &str) -> Option<(u16, String)> {
    let mut setup = shared.setup.lock().unwrap_or_else(PoisonError::into_inner);
    match setup.exchanges.get(&declare.name) {
        None if declare.passive => Some((
            404,
            format!(
                "NOT_FOUND - no exchange '{}' in vhost '{vhost}'",
                declare.name
            ),
        )),
        None => {
            setup.exchanges.insert(
                declare.name.clone(),
                (declare.exchange.kind.clone(), declare.exchange.durable),
            );
            None
        }
        Some(_) if declare.passive => None,
        Some((kind, durable))
            if *kind != declare.exchange.kind || *durable != declare.exchange.durable =>
        {
            Some((
                406,
                format!(
                    "PRECONDITION_FAILED - inequivalent arg 'durable' for exchange '{}' in vhost \
                 '{vhost}'",
                    declare.name
                ),
            ))
        }
        Some(_) => None,
    }
}

/// Reads a published message's header and body frames; returns it, and the frames as
/// they came (to send back if it's returned).
async fn read_content(
    stream: &mut TcpStream,
    max: usize,
    vhost: &str,
    exchange: &str,
    routing_key: &str,
) -> Result<(AmqpMessage, Vec<u8>), String> {
    let header = wire::read_frame(stream, max).await?;
    if header.kind != frame::HEADER {
        return Err("no content header".to_owned());
    }
    let mut content = wire::frame(frame::HEADER, header.channel, &header.payload)?;
    let mut args = Reader::new(&header.payload);
    let (_class, _weight, size) = (args.short()?, args.short()?, args.longlong()?);
    let flags = args.short()?;
    let content_type = if flags & 0x8000 != 0 {
        args.shortstr()?.to_owned()
    } else {
        String::new()
    };
    let headers = if flags & 0x2000 != 0 {
        read_headers(args.longstr()?)?
    } else {
        Vec::new()
    };
    let delivery_mode = if flags & 0x1000 != 0 {
        args.octet()?
    } else {
        0
    };
    let mut body = Vec::new();
    let mut frames = 0;
    while (body.len() as u64) < size {
        let part = wire::read_frame(stream, max).await?;
        if part.kind != frame::BODY {
            return Err("no body frame".to_owned());
        }
        content.extend(wire::frame(frame::BODY, part.channel, &part.payload)?);
        body.extend_from_slice(&part.payload);
        frames += 1;
    }
    Ok((
        AmqpMessage {
            vhost: vhost.to_owned(),
            exchange: exchange.to_owned(),
            routing_key: routing_key.to_owned(),
            mandatory: false,
            content_type,
            headers,
            delivery_mode,
            body: String::from_utf8_lossy(&body).into_owned(),
            frames,
        },
        content,
    ))
}

/// A header table's string fields.
fn read_headers(table: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut reader = Reader::new(table);
    let mut out = Vec::new();
    while !reader.rest().is_empty() {
        let name = reader.shortstr()?.to_owned();
        if reader.octet()? != b'S' {
            return Err("a header that isn't a string".to_owned());
        }
        out.push((
            name,
            String::from_utf8_lossy(reader.longstr()?).into_owned(),
        ));
    }
    Ok(out)
}
