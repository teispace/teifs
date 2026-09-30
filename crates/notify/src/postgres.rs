//! PostgreSQL targets, as `MinIO`'s: in the `namespace` format a table holds a row per
//! object (`key`, `BUCKET/KEY`, and `value`, `{"Records":[record]}` as JSONB), set by each
//! event and removed with the object; in the `access` format a row per event
//! (`event_time`, `event_data` holding the event as a webhook is sent it). The table is
//! made when missing. The client speaks PostgreSQL's protocol (3.0) itself over one
//! connection, made again after a failure: SCRAM-SHA-256 or MD5 sign-in (a password in the
//! clear only over TLS), statements with their values bound as parameters, never spliced
//! into SQL.

use std::{fmt, future::Future, sync::Arc};

use md5::{Digest as _, Md5};
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{
    Format,
    aws::hex,
    net::{self, Kept, Stream},
    scram::{Scram, ScramHash},
    sql::{self, Change},
};

/// The protocol, 3.0.
const PROTOCOL: i32 = 196_608;
/// What asks the server for TLS before the startup message.
const SSL_REQUEST: i32 = 80_877_103;
/// The largest message read.
const MAX_MESSAGE: usize = 16 << 20;
/// What an answer that can't be read is.
const GARBLED: &str = "it answered with something that isn't PostgreSQL";

/// A table events are written to.
#[derive(Clone)]
pub struct Postgres {
    /// The server, `HOST:PORT`.
    pub address: String,
    /// The database.
    pub database: String,
    /// The table: a name, or a quoted one.
    pub table: String,
    /// A row per object or a row per event.
    pub format: Format,
    /// The user.
    pub user: String,
    /// Its password, if the server asks for one.
    pub password: Option<Zeroizing<String>>,
    /// TLS, and how the server is verified; none for plain TCP.
    pub tls: Option<Arc<ClientConfig>>,
    connection: Kept<Connection>,
}

impl Postgres {
    /// Events for `table` in `database` on the server at `address` (`HOST:PORT`), signed
    /// in as `user`.
    ///
    /// # Errors
    ///
    /// When `address` isn't `HOST:PORT`, or the table, database or user isn't a name
    /// PostgreSQL takes.
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
        if !sql::is_table(table, '"', 63) {
            return Err(format!(
                "`{table}` isn't a table's name: use letters, digits, `_` and `$` (starting with \
                 a letter or `_`), or a name in double quotes"
            ));
        }
        for (what, name) in [("database", database), ("user", user)] {
            if name.is_empty() || name.contains('\0') || name.len() > 63 {
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
            connection: Kept::new(),
        })
    }

    /// Where it writes.
    #[must_use]
    pub fn shown(&self) -> String {
        format!(
            "postgresql://{}@{}/{} table {} ({}{})",
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
                sql: format!("DELETE FROM {table} WHERE key = $1;"),
                values: vec![key],
            },
            Change::Set { key, value } => Statement {
                sql: format!(
                    "INSERT INTO {table} (key, value) VALUES ($1, $2) \
                     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;"
                ),
                values: vec![key, value],
            },
            Change::Add { time, event } => Statement {
                sql: format!("INSERT INTO {table} (event_time, event_data) VALUES ($1, $2);"),
                values: vec![time, event],
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

    /// The table's columns, by format.
    fn columns(&self) -> &'static str {
        match self.format {
            Format::Namespace => "(key VARCHAR PRIMARY KEY, value JSONB)",
            Format::Access => "(event_time TIMESTAMP WITH TIME ZONE NOT NULL, event_data JSONB)",
        }
    }
}

impl net::Connects for Postgres {
    type Connection = Connection;

    fn connect(&self) -> impl Future<Output = Result<Connection, String>> + Send {
        Connection::open(self)
    }
}

impl fmt::Debug for Postgres {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Postgres")
            .field("at", &self.shown())
            .finish_non_exhaustive()
    }
}

/// A statement and the values bound to its parameters, as text.
pub(crate) struct Statement {
    sql: String,
    values: Vec<String>,
}

/// A connection to the server, ready for statements.
pub(crate) struct Connection {
    stream: Stream,
}

impl Connection {
    /// Connects (asking for TLS first when it's wanted), signs in, and makes the table
    /// if it's missing.
    async fn open(pg: &Postgres) -> Result<Self, String> {
        let mut tcp = net::connect(&pg.address).await?;
        if pg.tls.is_some() {
            let mut request = Vec::with_capacity(8);
            request.extend_from_slice(&8i32.to_be_bytes());
            request.extend_from_slice(&SSL_REQUEST.to_be_bytes());
            let lost = |e: std::io::Error| format!("the connection failed: {e}");
            tcp.write_all(&request).await.map_err(lost)?;
            if tcp.read_u8().await.map_err(lost)? != b'S' {
                return Err("the server doesn't take TLS".to_owned());
            }
        }
        let stream = net::secure(tcp, &pg.address, pg.tls.as_ref()).await?;
        let mut connection = Self { stream };
        connection.startup(pg).await?;
        connection.ensure_table(pg).await?;
        Ok(connection)
    }

    /// The startup message and the sign-in, until the server is ready.
    async fn startup(&mut self, pg: &Postgres) -> Result<(), String> {
        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&PROTOCOL.to_be_bytes());
        for (name, value) in [
            ("user", pg.user.as_str()),
            ("database", pg.database.as_str()),
            ("application_name", "teifs"),
            ("client_encoding", "UTF8"),
        ] {
            cstring(&mut body, name);
            cstring(&mut body, value);
        }
        body.push(0);
        let mut startup = Vec::with_capacity(body.len() + 4);
        startup.extend_from_slice(&length(body.len() + 4)?.to_be_bytes());
        startup.extend_from_slice(&body);
        self.write(&startup).await?;
        let mut scram: Option<Scram> = None;
        loop {
            let (kind, body) = self.read().await?;
            match kind {
                b'R' => {
                    if self.authenticate(pg, &body, &mut scram).await? {
                        break;
                    }
                }
                b'E' => return Err(signin_refused(&body)),
                b'N' => {}
                _ => return Err(GARBLED.to_owned()),
            }
        }
        // Parameters and the cancel key, until the server is ready.
        loop {
            match self.read().await? {
                (b'Z', _) => return Ok(()),
                (b'E', body) => return Err(server_error(&body)),
                _ => {}
            }
        }
    }

    /// One authentication request; `true` once the server takes the sign-in.
    async fn authenticate(
        &mut self,
        pg: &Postgres,
        body: &[u8],
        scram: &mut Option<Scram>,
    ) -> Result<bool, String> {
        let (code, data) = body.split_first_chunk::<4>().ok_or(GARBLED)?;
        let password = || {
            pg.password.as_deref().ok_or_else(|| {
                "it wants a password: set TEIFS_NOTIFY_POSTGRESQL_PASSWORD_ID".to_owned()
            })
        };
        match i32::from_be_bytes(*code) {
            0 => {
                if scram.is_some() {
                    return Err(
                        "it didn't prove it knows the password: it isn't the server".to_owned()
                    );
                }
                Ok(true)
            }
            3 => {
                if pg.tls.is_none() {
                    return Err(
                        "it asks for the password in the clear: connect over TLS, or have it \
                         ask with SCRAM-SHA-256"
                            .to_owned(),
                    );
                }
                let mut message = Zeroizing::new(password()?.as_bytes().to_vec());
                message.push(0);
                self.send(b'p', &message).await.map(|()| false)
            }
            5 => {
                let salt = data.get(..4).ok_or(GARBLED)?;
                let inner = hex(&Md5::digest(
                    [password()?.as_bytes(), pg.user.as_bytes()].concat(),
                ));
                let outer = hex(&Md5::digest([inner.as_bytes(), salt].concat()));
                let mut message = format!("md5{outer}").into_bytes();
                message.push(0);
                self.send(b'p', &message).await.map(|()| false)
            }
            10 => {
                let offered: Vec<&[u8]> =
                    data.split(|b| *b == 0).filter(|m| !m.is_empty()).collect();
                if !offered.contains(&&b"SCRAM-SHA-256"[..]) {
                    return Err("it asks for a SASL mechanism TeiFS doesn't speak".to_owned());
                }
                // PostgreSQL takes the user from the startup message, not SCRAM's.
                let exchange = Scram::new(ScramHash::Sha256, "", password()?)?;
                let first = exchange.first();
                let mut message = Vec::with_capacity(first.len() + 20);
                cstring(&mut message, "SCRAM-SHA-256");
                message.extend_from_slice(&length(first.len())?.to_be_bytes());
                message.extend_from_slice(first.as_bytes());
                *scram = Some(exchange);
                self.send(b'p', &message).await.map(|()| false)
            }
            11 => {
                let exchange = scram.as_mut().ok_or(GARBLED)?;
                let first = std::str::from_utf8(data).map_err(|_| GARBLED)?;
                let last = exchange.last(first)?;
                self.send(b'p', last.as_bytes()).await.map(|()| false)
            }
            12 => {
                let exchange = scram.take().ok_or(GARBLED)?;
                exchange.check(std::str::from_utf8(data).map_err(|_| GARBLED)?)?;
                Ok(false)
            }
            code => Err(format!(
                "it asks for a way of signing in TeiFS doesn't speak ({code}): use \
                 scram-sha-256 or md5"
            )),
        }
    }

    /// Makes the table if it's missing.
    async fn ensure_table(&mut self, pg: &Postgres) -> Result<(), String> {
        match self
            .query(&format!("SELECT 1 FROM {} LIMIT 0;", pg.table))
            .await?
        {
            Ok(()) => Ok(()),
            Err(error) if error.code == "42P01" => self
                .query(&format!(
                    "CREATE TABLE IF NOT EXISTS {} {};",
                    pg.table,
                    pg.columns()
                ))
                .await?
                .map_err(|e| format!("can't make the table: {}", e.message)),
            Err(error) => Err(error.message),
        }
    }

    /// Runs `sql` with the simple protocol; a server error is `Ok(Err)`.
    async fn query(&mut self, sql: &str) -> Result<Result<(), ServerError>, String> {
        let mut message = Vec::with_capacity(sql.len() + 1);
        cstring(&mut message, sql);
        self.send(b'Q', &message).await?;
        self.until_ready().await
    }

    /// Runs `statement` with the extended protocol, its values bound as text; a server
    /// error is `Ok(Err)`.
    async fn execute(&mut self, statement: &Statement) -> Result<Result<(), String>, String> {
        let mut out = Vec::with_capacity(statement.sql.len() + 256);
        // Parse the unnamed statement, its parameters' types inferred.
        let mut parse = Vec::with_capacity(statement.sql.len() + 4);
        parse.push(0);
        cstring(&mut parse, &statement.sql);
        parse.extend_from_slice(&0i16.to_be_bytes());
        message(&mut out, b'P', &parse)?;
        // Bind the values, as text, to the unnamed portal.
        let mut bind = vec![0, 0];
        bind.extend_from_slice(&0i16.to_be_bytes());
        let count = i16::try_from(statement.values.len()).map_err(|_| "too many values")?;
        bind.extend_from_slice(&count.to_be_bytes());
        for value in &statement.values {
            bind.extend_from_slice(&length(value.len())?.to_be_bytes());
            bind.extend_from_slice(value.as_bytes());
        }
        bind.extend_from_slice(&0i16.to_be_bytes());
        message(&mut out, b'B', &bind)?;
        message(&mut out, b'E', &[0, 0, 0, 0, 0])?;
        message(&mut out, b'S', &[])?;
        self.write(&out).await?;
        Ok(self.until_ready().await?.map_err(|e| e.message))
    }

    /// Reads until the server is ready again, keeping its first error.
    async fn until_ready(&mut self) -> Result<Result<(), ServerError>, String> {
        let mut error = None;
        loop {
            match self.read().await? {
                (b'Z', _) => return Ok(error.map_or(Ok(()), Err)),
                (b'E', body) => {
                    error.get_or_insert_with(|| ServerError::read(&body));
                }
                _ => {}
            }
        }
    }

    async fn send(&mut self, kind: u8, body: &[u8]) -> Result<(), String> {
        let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 5));
        message(&mut out, kind, body)?;
        self.write(&out).await
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        let lost = |e: std::io::Error| format!("the connection failed: {e}");
        self.stream.write_all(bytes).await.map_err(lost)?;
        self.stream.flush().await.map_err(lost)
    }

    /// Reads a message: its type and body.
    async fn read(&mut self) -> Result<(u8, Vec<u8>), String> {
        let lost = |e: std::io::Error| format!("the connection failed: {e}");
        let kind = self.stream.read_u8().await.map_err(lost)?;
        let size = usize::try_from(self.stream.read_i32().await.map_err(lost)?)
            .ok()
            .filter(|n| (4..=MAX_MESSAGE).contains(n))
            .ok_or(GARBLED)?;
        let mut body = vec![0; size - 4];
        self.stream.read_exact(&mut body).await.map_err(lost)?;
        Ok((kind, body))
    }
}

/// Appends a message: its type, its length (counting itself) and `body`.
fn message(out: &mut Vec<u8>, kind: u8, body: &[u8]) -> Result<(), String> {
    out.push(kind);
    out.extend_from_slice(&length(body.len() + 4)?.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

fn length(n: usize) -> Result<i32, String> {
    i32::try_from(n).map_err(|_| "larger than PostgreSQL takes".to_owned())
}

fn cstring(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

/// An `ErrorResponse`'s code (SQLSTATE) and what it says.
#[derive(Debug, PartialEq, Eq)]
struct ServerError {
    code: String,
    message: String,
}

impl ServerError {
    fn read(body: &[u8]) -> Self {
        let mut code = String::new();
        let mut text = String::new();
        let mut severity = String::new();
        for field in body.split(|b| *b == 0) {
            let Some((kind, value)) = field.split_first() else {
                continue;
            };
            let value = String::from_utf8_lossy(value).into_owned();
            match kind {
                b'C' => code = value,
                b'M' => text = value,
                b'V' => severity = value,
                b'S' if severity.is_empty() => severity = value,
                _ => {}
            }
        }
        Self {
            message: format!("it answered {severity} {code}: {text}"),
            code,
        }
    }
}

fn server_error(body: &[u8]) -> String {
    ServerError::read(body).message
}

/// A sign-in refused: the user or password (`28P01`, `28000`), or the database (`3D000`).
fn signin_refused(body: &[u8]) -> String {
    let error = ServerError::read(body);
    match error.code.as_str() {
        "28P01" | "28000" => format!("it refused the user or password ({})", error.message),
        _ => error.message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_and_addresses_are_checked() {
        let pg =
            Postgres::new("db.local:5432", "s3", "events", Format::Namespace, "teifs").unwrap();
        assert_eq!(
            pg.shown(),
            "postgresql://teifs@db.local:5432/s3 table events (namespace)"
        );
        for bad in ["events;drop table x", "`t`", &"e".repeat(64)] {
            assert!(Postgres::new("h:5432", "s3", bad, Format::Access, "u").is_err());
        }
        assert!(Postgres::new("h", "s3", "t", Format::Access, "u").is_err());
        assert!(Postgres::new("h:5432", "", "t", Format::Access, "u").is_err());
        assert!(Postgres::new("h:5432", "s3", "t", Format::Access, "a\0b").is_err());
    }

    #[test]
    fn errors_are_named_with_their_code() {
        let body = b"SERROR\0VERROR\0C28P01\0Mpassword authentication failed for user \"x\"\0\0";
        assert_eq!(
            signin_refused(body),
            "it refused the user or password (it answered ERROR 28P01: password \
             authentication failed for user \"x\")"
        );
        let missing = ServerError::read(b"SERROR\0C42P01\0Mrelation \"t\" does not exist\0\0");
        assert_eq!(missing.code, "42P01");
        assert_eq!(
            server_error(b"SFATAL\0C3D000\0Mdatabase \"s3\" does not exist\0\0"),
            "it answered FATAL 3D000: database \"s3\" does not exist"
        );
    }

    #[test]
    fn messages_count_their_own_length() {
        let mut out = Vec::new();
        message(&mut out, b'Q', b"SELECT 1;\0").unwrap();
        assert_eq!(&out[..5], [b'Q', 0, 0, 0, 14]);
    }
}
