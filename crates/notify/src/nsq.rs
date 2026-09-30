//! NSQ targets, as `MinIO`'s: each event, as a webhook is sent it, published to a topic
//! on an `nsqd` over its TCP protocol (`PUB`), over one connection made again after a
//! failure.

use std::{fmt, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Mutex,
};

use crate::net;

/// How long a connection or a command may take.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The longest frame read: more is a server that isn't `nsqd`.
const MAX_FRAME: usize = 1 << 20;
/// What a connection starts with: the protocol's version.
pub(crate) const MAGIC: &[u8] = b"  V2";
/// The response that asks a client to show it's alive.
pub(crate) const HEARTBEAT: &[u8] = b"_heartbeat_";

/// A topic events are published to.
#[derive(Clone)]
pub struct Nsq {
    /// The `nsqd`'s TCP address, `HOST:PORT`.
    pub address: String,
    /// The topic.
    pub topic: String,
    connection: Arc<Mutex<Option<Connection>>>,
}

impl Nsq {
    /// Events for `topic` on the `nsqd` at `address` (`HOST:PORT`).
    ///
    /// # Errors
    ///
    /// When `address` isn't `HOST:PORT`, or `topic` can't name a topic.
    pub fn new(address: &str, topic: &str) -> Result<Self, String> {
        let address = address.trim();
        if !net::is_address(address) {
            return Err(format!("`{address}` isn't HOST:PORT"));
        }
        let name = topic.strip_suffix("#ephemeral").unwrap_or(topic);
        if name.is_empty()
            || topic.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(format!(
                "`{topic}` can't name a topic: use up to 64 letters, digits, `.`, `_` and `-`"
            ));
        }
        Ok(Self {
            address: address.to_owned(),
            topic: topic.to_owned(),
            connection: Arc::new(Mutex::new(None)),
        })
    }

    /// Where it publishes.
    #[must_use]
    pub fn shown(&self) -> String {
        format!("nsq://{} topic {}", self.address, self.topic)
    }

    /// Publishes `body`.
    pub(crate) async fn send(&self, body: &[u8]) -> Result<(), String> {
        let mut command = format!("PUB {}\n", self.topic).into_bytes();
        let size = u32::try_from(body.len()).map_err(|_| "the event is too large".to_owned())?;
        command.extend_from_slice(&size.to_be_bytes());
        command.extend_from_slice(body);
        self.call(&command).await
    }

    /// Checks that the `nsqd` answers.
    pub(crate) async fn test(&self) -> Result<(), String> {
        let mut connection = self.connection.lock().await;
        *connection = Some(self.connect().await?);
        Ok(())
    }

    /// Sends `command` on the connection, making it first if there's none, and reads its
    /// answer; a failure drops the connection.
    async fn call(&self, command: &[u8]) -> Result<(), String> {
        let mut connection = self.connection.lock().await;
        if connection.is_none() {
            *connection = Some(self.connect().await?);
        }
        let open = connection.as_mut().expect("connected");
        let result = tokio::time::timeout(TIMEOUT, open.call(command))
            .await
            .unwrap_or_else(|_| Err("it didn't answer in time".to_owned()));
        if result.is_err() {
            // `nsqd` closes a connection after an error anyway.
            *connection = None;
        }
        result
    }

    /// Connects, and says who's publishing (`IDENTIFY`), which `nsqd` answers.
    async fn connect(&self) -> Result<Connection, String> {
        let stream = net::connect(&self.address).await?;
        let mut connection = Connection {
            stream: BufReader::new(stream),
        };
        let identify = serde_json::json!({
            "client_id": "teifs",
            "user_agent": concat!("TeiFS/", env!("CARGO_PKG_VERSION")),
            "feature_negotiation": false,
        })
        .to_string();
        let mut command = MAGIC.to_vec();
        command.extend_from_slice(b"IDENTIFY\n");
        let size = u32::try_from(identify.len()).expect("a short message");
        command.extend_from_slice(&size.to_be_bytes());
        command.extend_from_slice(identify.as_bytes());
        tokio::time::timeout(TIMEOUT, connection.call(&command))
            .await
            .unwrap_or_else(|_| Err("it didn't answer in time".to_owned()))?;
        Ok(connection)
    }
}

impl fmt::Debug for Nsq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nsq")
            .field("at", &self.shown())
            .finish_non_exhaustive()
    }
}

/// A connection to an `nsqd`.
struct Connection {
    stream: BufReader<TcpStream>,
}

impl Connection {
    /// Sends `command` and waits for its `OK`, answering heartbeats meanwhile.
    async fn call(&mut self, command: &[u8]) -> Result<(), String> {
        let lost = |e: std::io::Error| format!("the connection failed: {e}");
        self.stream
            .get_mut()
            .write_all(command)
            .await
            .map_err(lost)?;
        loop {
            match read_frame(&mut self.stream).await? {
                Frame::Response(data) if data == HEARTBEAT => {
                    self.stream
                        .get_mut()
                        .write_all(b"NOP\n")
                        .await
                        .map_err(lost)?;
                }
                Frame::Response(_) => return Ok(()),
                Frame::Error(message) => return Err(format!("it answered: {message}")),
                Frame::Message => return Err("it sent a message to a publisher".to_owned()),
            }
        }
    }
}

/// A frame `nsqd` sends.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Response(Vec<u8>),
    Error(String),
    Message,
}

/// Reads one frame: its size, its type and its data.
pub(crate) async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<Frame, String> {
    let lost = |e: std::io::Error| format!("the connection failed: {e}");
    let size = stream.read_u32().await.map_err(lost)? as usize;
    if !(4..=MAX_FRAME).contains(&size) {
        return Err("it answered with something that isn't an NSQ frame".to_owned());
    }
    let kind = stream.read_u32().await.map_err(lost)?;
    let mut data = vec![0; size - 4];
    stream.read_exact(&mut data).await.map_err(lost)?;
    match kind {
        0 => Ok(Frame::Response(data)),
        1 => Ok(Frame::Error(String::from_utf8_lossy(&data).into_owned())),
        2 => Ok(Frame::Message),
        _ => Err("it answered with something that isn't an NSQ frame".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u32, data: &[u8]) -> Vec<u8> {
        let mut out = (u32::try_from(data.len()).unwrap() + 4)
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    #[tokio::test]
    async fn frames_are_read_as_nsqd_sends_them() {
        let read = |bytes: Vec<u8>| async move { read_frame(&mut &bytes[..]).await };
        assert_eq!(
            read(frame(0, b"OK")).await,
            Ok(Frame::Response(b"OK".to_vec()))
        );
        assert_eq!(
            read(frame(1, b"E_BAD_TOPIC")).await,
            Ok(Frame::Error("E_BAD_TOPIC".into()))
        );
        assert_eq!(read(frame(2, b"m")).await, Ok(Frame::Message));
        assert!(read(frame(7, b"")).await.is_err());
        assert!(
            read(vec![0, 0, 0, 2, 0, 0]).await.is_err(),
            "shorter than its type"
        );
        assert!(
            read(vec![0x7f, 0, 0, 0, 0, 0, 0, 0]).await.is_err(),
            "too long"
        );
        assert!(
            read(frame(0, b"OK")[..6].to_vec()).await.is_err(),
            "cut short"
        );
    }

    #[test]
    fn addresses_and_topics_are_checked() {
        assert!(Nsq::new("nsqd.local:4150", "s3-events").is_ok());
        assert!(Nsq::new("nsqd.local:4150", "s3.events#ephemeral").is_ok());
        for bad in ["", "a b", "a/b", "#ephemeral", &"x".repeat(65)] {
            assert!(Nsq::new("h:4150", bad).is_err(), "{bad}");
        }
        for bad in ["nsqd.local", "h:0", ":4150"] {
            assert!(Nsq::new(bad, "t").is_err(), "{bad}");
        }
        assert_eq!(
            Nsq::new("h:4150", "t").unwrap().shown(),
            "nsq://h:4150 topic t"
        );
    }
}
