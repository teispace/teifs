//! Redis targets, as `MinIO`'s: in the `namespace` format events go to a hash, a field
//! per object (`BUCKET/KEY`) holding `{"Records":[record]}`, set by each event and
//! removed with the object; in the `access` format each event is pushed onto a list as
//! `[{"Event":[record],"EventTime":…}]`. The client speaks RESP itself over one
//! connection (TLS when asked for), made again after a failure.

use std::{fmt, future::Future, sync::Arc};

use rustls::ClientConfig;
use teifs_types::notify::EventMessage;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use crate::{
    Format,
    net::{self, Kept, Stream, TIMEOUT},
};

/// The longest reply read: more is a server that isn't Redis.
const MAX_REPLY: usize = 1 << 20;
/// How deeply replies may nest.
const MAX_DEPTH: usize = 8;

/// The events that remove an object's field in the `namespace` format.
const REMOVALS: &[&str] = &["s3:ObjectRemoved:Delete", "s3:LifecycleExpiration:Delete"];

/// A key events are written to.
#[derive(Clone)]
pub struct Redis {
    /// `HOST:PORT`.
    pub address: String,
    /// The key: a hash (`namespace`) or a list (`access`).
    pub key: String,
    /// A field per object or an entry per event.
    pub format: Format,
    /// The database, when not 0.
    pub db: Option<u32>,
    /// The ACL user its password is for (Redis 6); none for the password alone.
    pub user: Option<String>,
    /// Its password.
    pub password: Option<Zeroizing<String>>,
    /// TLS, and how the server is verified; none for plain TCP.
    pub tls: Option<Arc<ClientConfig>>,
    connection: Kept<Connection>,
}

impl Redis {
    /// Events for `key` at `address` (`HOST:PORT`).
    ///
    /// # Errors
    ///
    /// When `address` isn't `HOST:PORT`, or `key` is empty.
    pub fn new(address: &str, key: &str, format: Format) -> Result<Self, String> {
        let address = address.trim();
        if !net::is_address(address) {
            return Err(format!("`{address}` isn't HOST:PORT"));
        }
        if key.is_empty() {
            return Err("name the key: key=NAME".to_owned());
        }
        Ok(Self {
            address: address.to_owned(),
            key: key.to_owned(),
            format,
            db: None,
            user: None,
            password: None,
            tls: None,
            connection: Kept::new(),
        })
    }

    /// Where it writes.
    #[must_use]
    pub fn shown(&self) -> String {
        let db = self.db.map(|db| format!(" db {db}")).unwrap_or_default();
        let scheme = if self.tls.is_some() {
            "rediss"
        } else {
            "redis"
        };
        format!(
            "{scheme}://{}{db} key {} ({})",
            self.address,
            self.key,
            self.format.name()
        )
    }

    /// Writes the event `body` (an [`EventMessage`]) as its format says.
    pub(crate) async fn send(&self, body: &[u8]) -> Result<(), String> {
        let message: EventMessage =
            serde_json::from_slice(body).map_err(|e| format!("not an event: {e}"))?;
        let command: Vec<Vec<u8>> = match self.format {
            Format::Namespace if REMOVALS.contains(&message.event_name.as_str()) => {
                args(&["HDEL", &self.key, &message.key])
            }
            Format::Namespace => {
                let value = serde_json::json!({ "Records": message.records }).to_string();
                args(&["HSET", &self.key, &message.key, &value])
            }
            Format::Access => {
                let time = message
                    .records
                    .first()
                    .map(|r| r.event_time.clone())
                    .unwrap_or_default();
                let value = serde_json::json!([{ "Event": message.records, "EventTime": time }])
                    .to_string();
                args(&["RPUSH", &self.key, &value])
            }
        };
        self.call(&command).await.map(drop)
    }

    /// Checks that the server answers, takes the password, and that the key is free or
    /// of the format's type.
    pub(crate) async fn test(&self) -> Result<(), String> {
        self.run(true, &args(&["PING"])).await.map(drop)
    }

    /// Runs `command` on the kept connection; an error it answers leaves it kept.
    async fn call(&self, command: &[Vec<u8>]) -> Result<Reply, String> {
        self.run(false, command).await
    }

    async fn run(&self, fresh: bool, command: &[Vec<u8>]) -> Result<Reply, String> {
        let reply = self
            .connection
            .run(self, fresh, command, |open, command| {
                Box::pin(open.call(command))
            })
            .await?;
        match reply {
            Reply::Error(message) => Err(format!("it answered: {message}")),
            reply => Ok(reply),
        }
    }

    /// Connects, authenticates, selects the database and checks the key's type.
    async fn open(&self) -> Result<Connection, String> {
        let stream = net::connect(&self.address).await?;
        let stream = net::secure(stream, &self.address, self.tls.as_ref()).await?;
        let mut connection = Connection {
            stream: BufReader::new(stream),
        };
        if let Some(password) = &self.password {
            let mut auth = vec![b"AUTH".to_vec()];
            if let Some(user) = &self.user {
                auth.push(user.as_bytes().to_vec());
            }
            auth.push(password.as_bytes().to_vec());
            connection.checked(&auth).await?;
        }
        if let Some(db) = self.db {
            connection
                .checked(&args(&["SELECT", &db.to_string()]))
                .await?;
        }
        // Named in `CLIENT LIST`; a server that won't is fine.
        let _ = connection
            .checked(&args(&["CLIENT", "SETNAME", "TeiFS"]))
            .await;
        let expected = match self.format {
            Format::Namespace => "hash",
            Format::Access => "list",
        };
        match connection.checked(&args(&["TYPE", &self.key])).await? {
            Reply::Simple(kind) if kind == "none" || kind == expected => Ok(connection),
            Reply::Simple(kind) => Err(format!(
                "the key `{}` holds a {kind}, and the {} format needs a {expected}",
                self.key,
                self.format.name()
            )),
            _ => Err("it answered TYPE with something else".to_owned()),
        }
    }
}

impl net::Connects for Redis {
    type Connection = Connection;

    fn connect(&self) -> impl Future<Output = Result<Connection, String>> + Send {
        self.open()
    }
}

impl fmt::Debug for Redis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redis")
            .field("at", &self.shown())
            .finish_non_exhaustive()
    }
}

fn args(parts: &[&str]) -> Vec<Vec<u8>> {
    parts.iter().map(|p| p.as_bytes().to_vec()).collect()
}

/// A reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<Self>>),
}

/// A connection to the server.
pub(crate) struct Connection {
    stream: BufReader<Stream>,
}

impl Connection {
    /// Runs `command` in time, an error reply being an error.
    async fn checked(&mut self, command: &[Vec<u8>]) -> Result<Reply, String> {
        match tokio::time::timeout(TIMEOUT, self.call(command)).await {
            Ok(Ok(Reply::Error(message))) => Err(format!("it answered: {message}")),
            Ok(result) => result,
            Err(_) => Err("it didn't answer in time".to_owned()),
        }
    }

    async fn call(&mut self, command: &[Vec<u8>]) -> Result<Reply, String> {
        self.stream
            .get_mut()
            .write_all(&encode(command))
            .await
            .map_err(|e| format!("can't send: {e}"))?;
        read_reply(&mut self.stream, 0).await
    }
}

/// `command` as RESP: an array of bulk strings.
pub(crate) fn encode(command: &[Vec<u8>]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", command.len()).into_bytes();
    for part in command {
        out.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Reads one reply.
pub(crate) async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(
    stream: &mut R,
    depth: usize,
) -> Result<Reply, String> {
    let lost = |e: std::io::Error| format!("the connection failed: {e}");
    let mut line = Vec::new();
    let read = (&mut *stream)
        .take(MAX_REPLY as u64)
        .read_until(b'\n', &mut line)
        .await
        .map_err(lost)?;
    if read == 0 {
        return Err("it closed the connection".to_owned());
    }
    let Some(line) = line.strip_suffix(b"\r\n") else {
        return Err("it answered with something that isn't RESP".to_owned());
    };
    let (kind, rest) = line.split_first().ok_or("an empty reply")?;
    let text = String::from_utf8_lossy(rest).into_owned();
    let number = || {
        text.parse::<i64>()
            .map_err(|_| format!("`{text}` isn't a number"))
    };
    match kind {
        b'+' => Ok(Reply::Simple(text)),
        b'-' => Ok(Reply::Error(text)),
        b':' => Ok(Reply::Integer(number()?)),
        b'$' => {
            let Ok(len) = usize::try_from(number()?) else {
                return Ok(Reply::Bulk(None));
            };
            if len > MAX_REPLY {
                return Err("its reply is too long".to_owned());
            }
            let mut data = vec![0; len + 2];
            stream.read_exact(&mut data).await.map_err(lost)?;
            data.truncate(len);
            Ok(Reply::Bulk(Some(data)))
        }
        b'*' => {
            let Ok(count) = usize::try_from(number()?) else {
                return Ok(Reply::Array(None));
            };
            if depth >= MAX_DEPTH || count > MAX_REPLY {
                return Err("its reply is too deep or too long".to_owned());
            }
            let mut items = Vec::new();
            for _ in 0..count {
                items.push(Box::pin(read_reply(stream, depth + 1)).await?);
            }
            Ok(Reply::Array(Some(items)))
        }
        _ => Err("it answered with something that isn't RESP".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(bytes: &[u8]) -> Result<Reply, String> {
        read_reply(&mut BufReader::new(bytes), 0).await
    }

    #[tokio::test]
    async fn replies_are_read_as_resp_gives_them() {
        assert_eq!(read(b"+OK\r\n").await, Ok(Reply::Simple("OK".into())));
        assert_eq!(
            read(b"-WRONGTYPE no\r\n").await,
            Ok(Reply::Error("WRONGTYPE no".into()))
        );
        assert_eq!(read(b":42\r\n").await, Ok(Reply::Integer(42)));
        assert_eq!(
            read(b"$3\r\nabc\r\n").await,
            Ok(Reply::Bulk(Some(b"abc".to_vec())))
        );
        assert_eq!(read(b"$-1\r\n").await, Ok(Reply::Bulk(None)));
        assert_eq!(
            read(b"*2\r\n:1\r\n$1\r\nx\r\n").await,
            Ok(Reply::Array(Some(vec![
                Reply::Integer(1),
                Reply::Bulk(Some(b"x".to_vec()))
            ])))
        );
        for bad in [
            &b""[..],
            b"OK\r\n",
            b"+OK\n",
            b":x\r\n",
            b"$5\r\nab",
            b"$99999999\r\n",
        ] {
            assert!(read(bad).await.is_err(), "{bad:?}");
        }
        let deep = "*1\r\n".repeat(MAX_DEPTH + 1) + ":1\r\n";
        assert!(read(deep.as_bytes()).await.is_err());
    }

    #[test]
    fn commands_are_arrays_of_bulk_strings() {
        assert_eq!(
            encode(&args(&["HSET", "k", "a b"])),
            b"*3\r\n$4\r\nHSET\r\n$1\r\nk\r\n$3\r\na b\r\n"
        );
    }

    #[test]
    fn addresses_and_keys_are_checked() {
        assert!(Redis::new("localhost:6379", "events", Format::Access).is_ok());
        assert!(Redis::new("[::1]:6379", "events", Format::Access).is_ok());
        for bad in ["localhost", ":6379", "h:0", "h:port", "h:70000"] {
            assert!(Redis::new(bad, "k", Format::Access).is_err(), "{bad}");
        }
        assert!(Redis::new("h:1", "", Format::Access).is_err());
        let mut redis = Redis::new("h:1", "k", Format::Namespace).unwrap();
        redis.password = Some(Zeroizing::new("secret".into()));
        assert!(!format!("{redis:?}").contains("secret"));
        assert_eq!(redis.shown(), "redis://h:1 key k (namespace)");
    }
}
