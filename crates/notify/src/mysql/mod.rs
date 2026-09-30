//! MySQL targets (MySQL 5.7 and later, `MariaDB`), as `MinIO`'s: in the `namespace` format
//! a table holds a row per object (`key_name`, `BUCKET/KEY`, its `key_hash` the primary
//! key, and `value`, `{"Records":[record]}` as JSON), set by each event and removed with
//! the object; in the `access` format a row per event (`event_time`, `event_data`). The
//! table is made when missing. The client speaks MySQL's protocol itself over one
//! connection, made again after a failure: `caching_sha2_password` (MySQL 8's default),
//! `mysql_native_password` (`MariaDB`'s), `sha256_password`, and a password in the clear only
//! over TLS; statements are prepared, their values bound, never spliced into SQL.

pub(crate) mod wire;

use std::{collections::HashMap, fmt, future::Future, sync::Arc};

use rustls::ClientConfig;
use tokio::io::AsyncWriteExt;
use wire::{GARBLED, Reader, ServerError, capability, command};
use zeroize::Zeroizing;

use crate::{
    Format,
    net::{self, Kept, Stream},
    sql::{self, Change},
};

/// The largest packet read.
const MAX_PACKET: usize = 64 << 20;
/// The capabilities TeiFS asks for; TLS is added when it's wanted.
const CAPABILITIES: u32 = capability::LONG_PASSWORD
    | capability::CONNECT_WITH_DB
    | capability::PROTOCOL_41
    | capability::TRANSACTIONS
    | capability::SECURE_CONNECTION
    | capability::PLUGIN_AUTH;
/// What the server must have: MySQL 5.7's handshake.
const NEEDED: u32 =
    capability::PROTOCOL_41 | capability::SECURE_CONNECTION | capability::PLUGIN_AUTH;
/// The table isn't there.
const NO_SUCH_TABLE: u16 = 1146;

/// How the password is sent to a server that wants it whole without TLS
/// (`caching_sha2_password` before it has the user cached, and `sha256_password`):
/// encrypted with the server's RSA key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ServerKey {
    /// It isn't: connect over TLS instead.
    #[default]
    None,
    /// With this key (`SubjectPublicKeyInfo` DER), the server's `public_key.pem`.
    Given(Vec<u8>),
    /// With the key the server gives when asked, which a machine in between could swap.
    Ask,
}

impl ServerKey {
    /// The key in a `PUBLIC KEY` PEM file's contents.
    ///
    /// # Errors
    ///
    /// When it holds no RSA public key.
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        wire::rsa_key_from_pem(pem).map(Self::Given)
    }
}

/// A table events are written to.
#[derive(Clone)]
pub struct Mysql {
    /// The server, `HOST:PORT`.
    pub address: String,
    /// The database.
    pub database: String,
    /// The table: a name, or one in backquotes.
    pub table: String,
    /// A row per object or a row per event.
    pub format: Format,
    /// The user.
    pub user: String,
    /// Its password, if it has one.
    pub password: Option<Zeroizing<String>>,
    /// TLS, and how the server is verified; none for plain TCP.
    pub tls: Option<Arc<ClientConfig>>,
    /// How the password is sent whole without TLS.
    pub server_key: ServerKey,
    connection: Kept<Connection>,
}

impl Mysql {
    /// Events for `table` in `database` on the server at `address` (`HOST:PORT`), signed
    /// in as `user`.
    ///
    /// # Errors
    ///
    /// When `address` isn't `HOST:PORT`, or the table, database or user isn't a name
    /// MySQL takes.
    pub fn new(
        address: &str,
        database: &str,
        table: &str,
        format: Format,
        user: &str,
    ) -> Result<Self, String> {
        let address = address.trim();
        if !net::is_address(address) {
            return Err(format!("`{address}` isn't HOST:PORT"));
        }
        if !sql::is_table(table, '`', 64) {
            return Err(format!(
                "`{table}` isn't a table's name: use letters, digits, `_` and `$` (starting with \
                 a letter or `_`), or a name in backquotes"
            ));
        }
        for (what, name, max) in [("database", database, 64), ("user", user, 80)] {
            if name.is_empty() || name.contains('\0') || name.len() > max {
                return Err(format!("`{name}` isn't a {what}'s name"));
            }
        }
        Ok(Self {
            address: address.to_owned(),
            database: database.to_owned(),
            table: table.to_owned(),
            format,
            user: user.to_owned(),
            password: None,
            tls: None,
            server_key: ServerKey::None,
            connection: Kept::new(),
        })
    }

    /// Where it writes.
    #[must_use]
    pub fn shown(&self) -> String {
        format!(
            "mysql://{}@{}/{} table {} ({}{})",
            self.user,
            self.address,
            self.database,
            self.table,
            self.format.name(),
            if self.tls.is_some() { ", TLS" } else { "" }
        )
    }

    /// Writes an event: a row set or removed (`namespace`), or a row added (`access`).
    pub(crate) async fn send(&self, body: &[u8]) -> Result<(), String> {
        let table = &self.table;
        let statement = match Change::of(self.format, body)? {
            Change::Delete { key } => Statement {
                sql: format!("DELETE FROM {table} WHERE key_hash = SHA2(?, 256);"),
                values: vec![key],
            },
            Change::Set { key, value } => Statement {
                sql: format!(
                    "INSERT INTO {table} (key_name, value) VALUES (?, ?) \
                     ON DUPLICATE KEY UPDATE value=VALUES(value);"
                ),
                values: vec![key, value],
            },
            Change::Add { time, event } => Statement {
                sql: format!("INSERT INTO {table} (event_time, event_data) VALUES (?, ?);"),
                values: vec![datetime(&time), event],
            },
        };
        // A statement the server refuses keeps the connection; one that failed doesn't.
        self.connection
            .run(self, false, &statement, |open, statement| {
                Box::pin(open.execute(statement))
            })
            .await?
    }

    /// Checks that the server takes the user, and that the table is there or can be made.
    pub(crate) async fn test(&self) -> Result<(), String> {
        self.connection
            .run(self, true, &(), |_, ()| Box::pin(async { Ok(()) }))
            .await
    }

    /// The table's columns and options, by format: `MinIO`'s. `MariaDB` takes no generated
    /// primary key, so there the object's hash is a unique key instead, which `ON DUPLICATE
    /// KEY` and the delete use the same way.
    fn columns(&self, mariadb: bool) -> &'static str {
        match self.format {
            Format::Namespace if mariadb => {
                "(key_name VARCHAR(3072) NOT NULL, key_hash CHAR(64) GENERATED ALWAYS AS \
                 (SHA2(key_name, 256)) STORED, value JSON, UNIQUE KEY key_hash (key_hash)) \
                 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic"
            }
            Format::Namespace => {
                "(key_name VARCHAR(3072) NOT NULL, key_hash CHAR(64) GENERATED ALWAYS AS \
                 (SHA2(key_name, 256)) STORED NOT NULL PRIMARY KEY, value JSON) \
                 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic"
            }
            Format::Access => {
                "(event_time DATETIME NOT NULL, event_data JSON) ROW_FORMAT = Dynamic"
            }
        }
    }
}

impl net::Connects for Mysql {
    type Connection = Connection;

    fn connect(&self) -> impl Future<Output = Result<Connection, String>> + Send {
        Connection::open(self)
    }
}

impl fmt::Debug for Mysql {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mysql")
            .field("at", &self.shown())
            .finish_non_exhaustive()
    }
}

/// An event's time (`2026-09-30T12:00:00.000Z`) as a `DATETIME` takes it, in UTC.
fn datetime(time: &str) -> String {
    time.strip_suffix('Z').unwrap_or(time).replacen('T', " ", 1)
}

/// A statement and the values bound to its parameters, as strings.
pub(crate) struct Statement {
    sql: String,
    values: Vec<String>,
}

/// A connection to the server, signed in.
pub(crate) struct Connection {
    stream: Stream,
    /// The next packet's sequence number.
    seq: u8,
    /// The statements prepared on it, by their SQL: their ids.
    prepared: HashMap<String, u32>,
}

/// Where a sign-in is: the plugin the server asked for, and its nonce.
struct Signin<'a> {
    target: &'a Mysql,
    plugin: String,
    nonce: Vec<u8>,
    tls: bool,
    /// Whether the server was asked for its RSA key, which comes next.
    asked_key: bool,
}

impl Signin<'_> {
    fn password(&self) -> &str {
        self.target.password.as_deref().map_or("", String::as_str)
    }

    /// The password whole: in the clear over TLS, else encrypted with the server's key.
    /// `None` when the server's key must be asked for first.
    fn whole(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        if self.tls {
            let mut clear = Zeroizing::new(self.password().as_bytes().to_vec());
            clear.push(0);
            return Ok(Some(clear));
        }
        match &self.target.server_key {
            ServerKey::Given(key) => Ok(Some(Zeroizing::new(wire::rsa_password(
                self.password(),
                &self.nonce,
                key,
            )?))),
            ServerKey::Ask => Ok(None),
            ServerKey::None => Err(
                "it wants the whole password, which TeiFS sends only over TLS or encrypted \
                 with the server's RSA key: connect with tls=true or ca=PATH, or give the key \
                 (server_public_key=PATH, the server's public_key.pem), or sign in once over \
                 TLS so the server caches the user"
                    .to_owned(),
            ),
        }
    }

    /// The first answer to the plugin's request.
    fn first(&mut self) -> Result<(String, Zeroizing<Vec<u8>>), String> {
        let answer = match self.plugin.as_str() {
            "caching_sha2_password" => wire::sha2_proof(self.password(), &self.nonce),
            "sha256_password" | "mysql_clear_password" if self.password().is_empty() => {
                vec![0]
            }
            "sha256_password" => {
                if let Some(whole) = self.whole()? {
                    return Ok((self.plugin.clone(), whole));
                }
                self.asked_key = true;
                vec![1]
            }
            "mysql_clear_password" => {
                if !self.tls {
                    return Err(
                        "it asks for the password in the clear: connect over TLS".to_owned()
                    );
                }
                return Ok((self.plugin.clone(), self.whole()?.ok_or(GARBLED)?));
            }
            // MySQL's own and anything else: the server switches to the user's plugin.
            _ => {
                "mysql_native_password".clone_into(&mut self.plugin);
                wire::native_proof(self.password(), &self.nonce)
            }
        };
        Ok((self.plugin.clone(), Zeroizing::new(answer)))
    }
}

impl Connection {
    /// Connects (with TLS when it's wanted), signs in, and makes the table if it's
    /// missing.
    async fn open(target: &Mysql) -> Result<Self, String> {
        let tcp = net::connect(&target.address).await?;
        let mut connection = Self {
            stream: Box::new(tcp),
            seq: 0,
            prepared: HashMap::new(),
        };
        let greeting = connection.read().await?;
        if greeting.first() == Some(&0xff) {
            return Err(ServerError::read(&greeting).message);
        }
        let Greeting {
            capabilities,
            nonce,
            plugin,
            mariadb,
        } = read_greeting(&greeting)?;
        if capabilities & NEEDED != NEEDED {
            return Err("it's older than MySQL 5.7 or MariaDB 10.2, which TeiFS needs".to_owned());
        }
        let mut ours = CAPABILITIES
            | (capabilities & capability::PLUGIN_AUTH_LENENC_DATA)
            | if target.tls.is_some() {
                capability::SSL
            } else {
                0
            };
        if let Some(tls) = &target.tls {
            if capabilities & capability::SSL == 0 {
                return Err("the server doesn't take TLS".to_owned());
            }
            // An SSL request: the handshake response's head alone, then TLS.
            let head = handshake_head(ours);
            connection.write(&head).await?;
            let Self { stream, .. } = connection;
            connection = Self {
                stream: net::secure(stream, &target.address, Some(tls)).await?,
                seq: connection.seq,
                prepared: HashMap::new(),
            };
        } else {
            ours &= !capability::SSL;
        }
        let mut signin = Signin {
            target,
            plugin,
            nonce,
            tls: target.tls.is_some(),
            asked_key: false,
        };
        let (plugin, answer) = signin.first()?;
        let mut response = handshake_head(ours);
        response.extend_from_slice(target.user.as_bytes());
        response.push(0);
        if ours & capability::PLUGIN_AUTH_LENENC_DATA == 0 {
            response.push(u8::try_from(answer.len()).map_err(|_| "the answer is too long")?);
            response.extend_from_slice(&answer);
        } else {
            wire::lenenc_bytes(&mut response, &answer);
        }
        response.extend_from_slice(target.database.as_bytes());
        response.push(0);
        response.extend_from_slice(plugin.as_bytes());
        response.push(0);
        connection.write(&response).await?;
        connection.sign_in(&mut signin).await?;
        connection.ensure_table(target, mariadb).await?;
        Ok(connection)
    }

    /// Answers the server until it takes the sign-in.
    async fn sign_in(&mut self, signin: &mut Signin<'_>) -> Result<(), String> {
        loop {
            let packet = self.read().await?;
            match packet.first() {
                Some(0x00) => return Ok(()),
                Some(0xff) => {
                    let error = ServerError::read(&packet);
                    return Err(if error.code == 1045 {
                        format!("it refused the user or password ({})", error.message)
                    } else {
                        error.message
                    });
                }
                // Another plugin, the user's, with a new nonce.
                Some(0xfe) => {
                    let mut reader = Reader::new(&packet[1..]);
                    let asked = String::from_utf8_lossy(reader.cstring()).into_owned();
                    let nonce = reader.rest();
                    signin.nonce = nonce.strip_suffix(&[0]).unwrap_or(nonce).to_vec();
                    signin.plugin.clone_from(&asked);
                    let (plugin, answer) = signin.first()?;
                    if plugin != asked {
                        return Err(format!(
                            "it asks for the sign-in `{asked}`, which TeiFS doesn't speak: use \
                             caching_sha2_password or mysql_native_password"
                        ));
                    }
                    self.write(&answer).await?;
                }
                Some(0x01) => self.more(signin, &packet[1..]).await?,
                _ => return Err(GARBLED.to_owned()),
            }
        }
    }

    /// The server's extra data: `caching_sha2_password`'s verdict, or its RSA key.
    async fn more(&mut self, signin: &mut Signin<'_>, data: &[u8]) -> Result<(), String> {
        if signin.asked_key {
            signin.asked_key = false;
            let key =
                wire::rsa_key_from_pem(data).map_err(|e| format!("the RSA key it gave: {e}"))?;
            let sealed = wire::rsa_password(signin.password(), &signin.nonce, &key)?;
            return self.write(&sealed).await;
        }
        match (signin.plugin.as_str(), data) {
            // The server had the user cached: the proof was enough.
            ("caching_sha2_password", [3]) => Ok(()),
            // It wants the password whole.
            ("caching_sha2_password", [4]) => {
                if let Some(whole) = signin.whole()? {
                    self.write(&whole).await
                } else {
                    signin.asked_key = true;
                    self.write(&[2]).await
                }
            }
            _ => Err(GARBLED.to_owned()),
        }
    }

    /// Makes the table if it's missing.
    async fn ensure_table(&mut self, target: &Mysql, mariadb: bool) -> Result<(), String> {
        let table = &target.table;
        match self
            .query(&format!("SELECT 1 FROM {table} LIMIT 0;"))
            .await?
        {
            Ok(()) => Ok(()),
            Err(error) if error.code == NO_SUCH_TABLE => self
                .query(&format!(
                    "CREATE TABLE IF NOT EXISTS {table} {};",
                    target.columns(mariadb)
                ))
                .await?
                .map_err(|e| format!("can't make the table: {}", e.message)),
            Err(error) => Err(error.message),
        }
    }

    /// Runs `sql` as a query, reading past any rows; a server error is `Ok(Err)`.
    async fn query(&mut self, sql: &str) -> Result<Result<(), ServerError>, String> {
        self.seq = 0;
        let mut out = vec![command::QUERY];
        out.extend_from_slice(sql.as_bytes());
        self.write(&out).await?;
        let first = self.read().await?;
        match first.first() {
            Some(0x00) => return Ok(Ok(())),
            Some(0xff) => return Ok(Err(ServerError::read(&first))),
            _ => {}
        }
        // A result set: its columns, an EOF, its rows, an EOF.
        let columns = Reader::new(&first).lenenc()?;
        for _ in 0..columns {
            self.read().await?;
        }
        self.eof().await?;
        loop {
            let row = self.read().await?;
            if is_eof(&row) {
                return Ok(Ok(()));
            }
            if row.first() == Some(&0xff) {
                return Ok(Err(ServerError::read(&row)));
            }
        }
    }

    /// Prepares `statement` once per connection, then runs it with its values; a server
    /// error is `Ok(Err)`.
    async fn execute(&mut self, statement: &Statement) -> Result<Result<(), String>, String> {
        let id = match self.prepared.get(&statement.sql) {
            Some(id) => *id,
            None => match self.prepare(&statement.sql).await? {
                Ok(id) => id,
                Err(error) => return Ok(Err(error.message)),
            },
        };
        self.seq = 0;
        let count = statement.values.len();
        let mut out = vec![command::STMT_EXECUTE];
        out.extend_from_slice(&id.to_le_bytes());
        // No cursor, run once, no NULLs, the types given.
        out.push(0);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend(std::iter::repeat_n(0, count.div_ceil(8)));
        out.push(1);
        for _ in 0..count {
            out.extend_from_slice(&[wire::TYPE_STRING, 0]);
        }
        for value in &statement.values {
            wire::lenenc_bytes(&mut out, value.as_bytes());
        }
        self.write(&out).await?;
        let answer = self.read().await?;
        match answer.first() {
            Some(0x00) => Ok(Ok(())),
            Some(0xff) => Ok(Err(ServerError::read(&answer).message)),
            _ => Err(GARBLED.to_owned()),
        }
    }

    /// Prepares `sql`: its id, kept for the connection.
    async fn prepare(&mut self, sql: &str) -> Result<Result<u32, ServerError>, String> {
        self.seq = 0;
        let mut out = vec![command::STMT_PREPARE];
        out.extend_from_slice(sql.as_bytes());
        self.write(&out).await?;
        let answer = self.read().await?;
        if answer.first() == Some(&0xff) {
            return Ok(Err(ServerError::read(&answer)));
        }
        let mut reader = Reader::new(&answer);
        if reader.u8()? != 0 {
            return Err(GARBLED.to_owned());
        }
        let id = reader.u32()?;
        let columns = reader.u16()?;
        let parameters = reader.u16()?;
        // Each parameter's and column's definition, each list ending with an EOF.
        for count in [parameters, columns] {
            if count > 0 {
                for _ in 0..count {
                    self.read().await?;
                }
                self.eof().await?;
            }
        }
        self.prepared.insert(sql.to_owned(), id);
        Ok(Ok(id))
    }

    async fn eof(&mut self) -> Result<(), String> {
        if is_eof(&self.read().await?) {
            Ok(())
        } else {
            Err(GARBLED.to_owned())
        }
    }

    async fn write(&mut self, payload: &[u8]) -> Result<(), String> {
        let packet = wire::packet(self.seq, payload)?;
        self.seq = self.seq.wrapping_add(1);
        let lost = |e: std::io::Error| format!("the connection failed: {e}");
        self.stream.write_all(&packet).await.map_err(lost)?;
        self.stream.flush().await.map_err(lost)
    }

    /// Reads a packet, checking it's the next in sequence.
    async fn read(&mut self) -> Result<Vec<u8>, String> {
        let (seq, payload) = wire::read_packet(&mut self.stream, MAX_PACKET).await?;
        if seq != self.seq {
            return Err(GARBLED.to_owned());
        }
        self.seq = seq.wrapping_add(1);
        Ok(payload)
    }
}

/// An EOF packet (`0xfe`, shorter than a row that starts with a length of 2^24 or more).
fn is_eof(packet: &[u8]) -> bool {
    packet.first() == Some(&0xfe) && packet.len() < 9
}

/// The handshake response's head: capabilities, largest packet, character set.
fn handshake_head(capabilities: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&capabilities.to_le_bytes());
    out.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    out.push(wire::UTF8MB4);
    out.extend_from_slice(&[0; 23]);
    out
}

/// What the server's greeting says.
#[derive(Debug, PartialEq, Eq)]
struct Greeting {
    capabilities: u32,
    nonce: Vec<u8>,
    /// The sign-in plugin it starts with.
    plugin: String,
    /// Whether it's `MariaDB`, by its version.
    mariadb: bool,
}

/// Reads the server's greeting (protocol 10).
fn read_greeting(greeting: &[u8]) -> Result<Greeting, String> {
    let mut reader = Reader::new(greeting);
    if reader.u8()? != 10 {
        return Err("it speaks an older protocol than MySQL 5.7's".to_owned());
    }
    let mariadb = String::from_utf8_lossy(reader.cstring()).contains("MariaDB");
    reader.u32()?;
    let mut nonce = reader.take(8)?.to_vec();
    reader.u8()?;
    let low = u32::from(reader.u16()?);
    reader.u8()?;
    reader.u16()?;
    let capabilities = low | u32::from(reader.u16()?) << 16;
    let data_size = usize::from(reader.u8()?);
    reader.take(10)?;
    let rest = reader.take(data_size.saturating_sub(8).max(13))?;
    nonce.extend_from_slice(rest.strip_suffix(&[0]).unwrap_or(rest));
    let plugin = String::from_utf8_lossy(reader.cstring()).into_owned();
    Ok(Greeting {
        capabilities,
        nonce,
        plugin,
        mariadb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_and_addresses_are_checked() {
        let db = Mysql::new("db.local:3306", "s3", "events", Format::Namespace, "teifs").unwrap();
        assert_eq!(
            db.shown(),
            "mysql://teifs@db.local:3306/s3 table events (namespace)"
        );
        assert!(Mysql::new("h:3306", "s3", "`S3 Events`", Format::Access, "u").is_ok());
        for bad in ["events;drop table x", "\"t\"", &"e".repeat(65)] {
            assert!(
                Mysql::new("h:3306", "s3", bad, Format::Access, "u").is_err(),
                "{bad}"
            );
        }
        assert!(Mysql::new("h", "s3", "t", Format::Access, "u").is_err());
        assert!(Mysql::new("h:3306", "", "t", Format::Access, "u").is_err());
        assert!(Mysql::new("h:3306", "s3", "t", Format::Access, "a\0b").is_err());
    }

    /// A packet out of sequence means the connection lost its place: it's refused.
    #[tokio::test]
    async fn packets_out_of_sequence_are_refused() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut connection = Connection {
            stream: Box::new(client),
            seq: 0,
            prepared: HashMap::new(),
        };
        server
            .write_all(&wire::packet(0, b"a").unwrap())
            .await
            .unwrap();
        server
            .write_all(&wire::packet(5, b"b").unwrap())
            .await
            .unwrap();
        assert_eq!(connection.read().await, Ok(b"a".to_vec()));
        assert_eq!(connection.read().await, Err(GARBLED.to_owned()));
    }

    #[test]
    fn times_are_datetimes_in_utc() {
        assert_eq!(
            datetime("2026-09-30T12:00:00.000Z"),
            "2026-09-30 12:00:00.000"
        );
        assert_eq!(datetime("odd"), "odd");
    }

    #[test]
    fn greetings_are_read_as_mysql_8_sends_them() {
        // MySQL 8.4's greeting, its connection id and nonce made up.
        let mut greeting = vec![10];
        greeting.extend_from_slice(b"8.4.6\0");
        greeting.extend_from_slice(&7u32.to_le_bytes());
        greeting.extend_from_slice(b"abcdefgh\0");
        greeting.extend_from_slice(&0xffffu16.to_le_bytes());
        greeting.push(255);
        greeting.extend_from_slice(&2u16.to_le_bytes());
        greeting.extend_from_slice(&0xdfffu16.to_le_bytes());
        greeting.push(21);
        greeting.extend_from_slice(&[0; 10]);
        greeting.extend_from_slice(b"ijklmnopqrst\0");
        greeting.extend_from_slice(b"caching_sha2_password\0");
        assert_eq!(
            read_greeting(&greeting),
            Ok(Greeting {
                capabilities: 0xdfff_ffff,
                nonce: b"abcdefghijklmnopqrst".to_vec(),
                plugin: "caching_sha2_password".into(),
                mariadb: false,
            })
        );
        let maria = [
            &greeting[..1],
            b"5.5.5-11.4.8-MariaDB-ubu2404",
            &greeting[6..],
        ]
        .concat();
        assert!(read_greeting(&maria).unwrap().mariadb);
        assert!(read_greeting(&greeting[..20]).is_err());
        assert!(read_greeting(&[9]).is_err());
    }
}
