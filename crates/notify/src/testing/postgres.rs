//! A PostgreSQL server on this machine, answering as PostgreSQL does: TLS when it's asked
//! for, sign-in as `pg_hba.conf` sets it (`trust`, `password`, `md5` or
//! `scram-sha-256`), and tables kept in memory, read by the simple protocol and written
//! by the extended one, with PostgreSQL's error codes.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use md5::{Digest as _, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{SCRAM_SALT, scram_verify, table_after};
use crate::{aws::hex, net::Stream};

/// How a [`PostgresServer`] signs people in, as `pg_hba.conf`'s methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgAuth {
    /// No password.
    Trust,
    /// The password in the clear.
    Password,
    /// The password's salted MD5.
    Md5,
    /// SCRAM-SHA-256.
    Scram,
}

/// How a [`PostgresServer`] pretends to be a server that knows the password, when it
/// doesn't.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgImpostor {
    /// SCRAM's last answer is signed with a key other than the password's.
    WrongProof,
    /// SCRAM's last answer is left out: the sign-in is taken at once.
    NoProof,
}

/// How a [`PostgresServer`] is made.
#[derive(Clone)]
pub struct PostgresSetup {
    /// The user and password it takes.
    pub login: (String, String),
    /// How it signs people in.
    pub auth: PgAuth,
    /// The databases it has.
    pub databases: Vec<String>,
    /// The tables it has, by name: their columns, as `CREATE TABLE` gave them.
    pub tables: BTreeMap<String, String>,
    /// TLS, for a client that asks.
    pub tls: Option<tokio_rustls::TlsAcceptor>,
    /// Whether, and how, it signs people in without knowing their password.
    pub impostor: Option<PgImpostor>,
}

impl Default for PostgresSetup {
    /// `teifs`/`pw` with SCRAM-SHA-256, the database `s3`, no tables and no TLS.
    fn default() -> Self {
        Self {
            login: ("teifs".into(), "pw".into()),
            auth: PgAuth::Scram,
            databases: vec!["s3".into()],
            tables: BTreeMap::new(),
            tls: None,
            impostor: None,
        }
    }
}

/// A connection a [`PostgresServer`] took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgStartup {
    /// The startup message's parameters.
    pub parameters: BTreeMap<String, String>,
    /// Whether it asked for, and got, TLS.
    pub tls: bool,
    /// Whether it signed in.
    pub signed_in: bool,
}

#[derive(Default)]
struct State {
    /// Each table's columns and rows.
    tables: BTreeMap<String, (String, Vec<Vec<String>>)>,
    startups: Vec<PgStartup>,
    /// Each statement run: its SQL and values.
    statements: Vec<(String, Vec<String>)>,
    /// Statements still to refuse.
    refusing: usize,
    /// Raised to close every connection open now.
    generation: usize,
}

struct Shared {
    setup: PostgresSetup,
    state: Mutex<State>,
}

impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A PostgreSQL server for tests.
pub struct PostgresServer {
    address: String,
    shared: Arc<Shared>,
}

impl PostgresServer {
    /// Starts one.
    ///
    /// # Panics
    ///
    /// When it can't listen.
    pub async fn start(setup: PostgresSetup) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let address = format!(
            "localhost:{}",
            listener.local_addr().expect("a bound address").port()
        );
        let state = State {
            tables: setup
                .tables
                .iter()
                .map(|(name, columns)| (name.clone(), (columns.clone(), Vec::new())))
                .collect(),
            ..State::default()
        };
        let shared = Arc::new(Shared {
            setup,
            state: Mutex::new(state),
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

    /// Refuses the next `count` statements.
    pub fn refuse(&self, count: usize) {
        self.shared.state().refusing = count;
    }

    /// Closes every connection open now, on its next message.
    pub fn hang_up(&self) {
        self.shared.state().generation += 1;
    }

    /// The connections it took.
    #[must_use]
    pub fn startups(&self) -> Vec<PgStartup> {
        self.shared.state().startups.clone()
    }

    /// Each statement it ran, simple or extended: its SQL and values.
    #[must_use]
    pub fn statements(&self) -> Vec<(String, Vec<String>)> {
        self.shared.state().statements.clone()
    }

    /// `table`'s columns and rows, if it has it.
    #[must_use]
    pub fn table(&self, table: &str) -> Option<(String, Vec<Vec<String>>)> {
        self.shared.state().tables.get(table).cloned()
    }

    /// `table`'s rows, once it has `count`.
    ///
    /// # Panics
    ///
    /// When it doesn't within ten seconds.
    pub async fn rows(&self, table: &str, count: usize) -> Vec<Vec<String>> {
        for _ in 0..1000 {
            if let Some((_, rows)) = self.table(table)
                && rows.len() == count
            {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{table} never had {count} rows: {:?}", self.table(table));
    }
}

/// A message: its type and body.
async fn read(stream: &mut Stream) -> std::io::Result<(u8, Vec<u8>)> {
    let kind = stream.read_u8().await?;
    let size = usize::try_from(stream.read_i32().await?).unwrap_or(0);
    let mut body = vec![0; size.saturating_sub(4)];
    stream.read_exact(&mut body).await?;
    Ok((kind, body))
}

fn message(out: &mut Vec<u8>, kind: u8, body: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&i32::try_from(body.len() + 4).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(body);
}

/// An `ErrorResponse` with its severity, code and message.
fn error(out: &mut Vec<u8>, severity: &str, code: &str, text: &str) {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', severity),
        (b'V', severity),
        (b'C', code),
        (b'M', text),
    ] {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    message(out, b'E', &body);
}

fn ready(out: &mut Vec<u8>) {
    message(out, b'Z', b"I");
}

/// An authentication request.
fn auth(out: &mut Vec<u8>, code: i32, data: &[u8]) {
    let mut body = code.to_be_bytes().to_vec();
    body.extend_from_slice(data);
    message(out, b'R', &body);
}

/// The C strings `bytes` holds.
fn strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

async fn serve(mut stream: Stream, shared: &Shared) -> std::io::Result<()> {
    let mut tls = false;
    let body = loop {
        let size = usize::try_from(stream.read_i32().await?).unwrap_or(0);
        let mut body = vec![0; size.saturating_sub(4)];
        stream.read_exact(&mut body).await?;
        if body[..4] != 80_877_103i32.to_be_bytes() {
            break body;
        }
        match &shared.setup.tls {
            Some(acceptor) if !tls => {
                stream.write_all(b"S").await?;
                let inner = tokio_rustls::TlsStream::Server(acceptor.accept(stream).await?);
                stream = Box::new(inner);
                tls = true;
            }
            _ => stream.write_all(b"N").await?,
        }
    };
    let pairs = strings(&body[4..]);
    let parameters: BTreeMap<String, String> = pairs
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|[name, _]| !name.is_empty())
        .map(|[name, value]| (name.clone(), value.clone()))
        .collect();
    let index = {
        let mut state = shared.state();
        state.startups.push(PgStartup {
            parameters: parameters.clone(),
            tls,
            signed_in: false,
        });
        state.startups.len() - 1
    };
    let mut out = Vec::new();
    let user = parameters.get("user").cloned().unwrap_or_default();
    let database = parameters.get("database").cloned().unwrap_or_default();
    if !sign_in(&mut stream, shared, &user).await? {
        error(
            &mut out,
            "FATAL",
            "28P01",
            &format!("password authentication failed for user \"{user}\""),
        );
        return stream.write_all(&out).await;
    }
    if !shared.setup.databases.contains(&database) {
        error(
            &mut out,
            "FATAL",
            "3D000",
            &format!("database \"{database}\" does not exist"),
        );
        return stream.write_all(&out).await;
    }
    shared.state().startups[index].signed_in = true;
    auth(&mut out, 0, &[]);
    message(&mut out, b'S', b"server_version\x0017.6\0");
    message(&mut out, b'K', &[0, 0, 0, 1, 0, 0, 0, 2]);
    ready(&mut out);
    stream.write_all(&out).await?;
    queries(stream, shared).await
}

/// Signs `user` in as the setup says; whether it did.
async fn sign_in(stream: &mut Stream, shared: &Shared, user: &str) -> std::io::Result<bool> {
    let (login, password) = &shared.setup.login;
    let mut out = Vec::new();
    let named = user == login;
    match shared.setup.auth {
        PgAuth::Trust => Ok(named),
        PgAuth::Password => {
            auth(&mut out, 3, &[]);
            stream.write_all(&out).await?;
            let (_, body) = read(stream).await?;
            Ok(named && body == format!("{password}\0").as_bytes())
        }
        PgAuth::Md5 => {
            let salt = [7, 1, 9, 3];
            auth(&mut out, 5, &salt);
            stream.write_all(&out).await?;
            let (_, body) = read(stream).await?;
            let inner = hex(&Md5::digest(format!("{password}{login}")));
            let outer = hex(&Md5::digest([inner.as_bytes(), &salt].concat()));
            Ok(named && body == format!("md5{outer}\0").as_bytes())
        }
        PgAuth::Scram => {
            auth(&mut out, 10, b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
            stream.write_all(&out).await?;
            let (_, body) = read(stream).await?;
            let Some(split) = body.iter().position(|b| *b == 0) else {
                return Ok(false);
            };
            let (mechanism, rest) = body.split_at(split);
            let Some((size, first)) = rest[1..].split_first_chunk::<4>() else {
                return Ok(false);
            };
            if mechanism != b"SCRAM-SHA-256"
                || usize::try_from(i32::from_be_bytes(*size)).ok() != Some(first.len())
            {
                return Ok(false);
            }
            let first = String::from_utf8_lossy(first);
            let Some(bare) = first.strip_prefix("n,,") else {
                return Ok(false);
            };
            let Some(nonce) = bare.split(',').find_map(|a| a.strip_prefix("r=")) else {
                return Ok(false);
            };
            let server_first = format!("r={nonce}srv,s={},i=4096", BASE64.encode(SCRAM_SALT));
            out.clear();
            auth(&mut out, 11, server_first.as_bytes());
            stream.write_all(&out).await?;
            let (_, last) = read(stream).await?;
            let last = String::from_utf8_lossy(&last);
            if shared.setup.impostor == Some(PgImpostor::NoProof) {
                return Ok(true);
            }
            let Some(mut signature) =
                scram_verify("SCRAM-SHA-256", password, bare, &server_first, &last)
            else {
                return Ok(false);
            };
            if shared.setup.impostor == Some(PgImpostor::WrongProof) {
                signature[0] ^= 1;
            }
            out.clear();
            auth(
                &mut out,
                12,
                format!("v={}", BASE64.encode(signature)).as_bytes(),
            );
            stream.write_all(&out).await?;
            Ok(named)
        }
    }
}

/// Answers queries until the connection closes or is hung up.
async fn queries(mut stream: Stream, shared: &Shared) -> std::io::Result<()> {
    let generation = shared.state().generation;
    let (mut sql, mut values) = (String::new(), Vec::new());
    let mut out = Vec::new();
    let mut failed = false;
    loop {
        let (kind, body) = read(&mut stream).await?;
        if shared.state().generation != generation {
            return Ok(());
        }
        match kind {
            b'Q' => {
                let text = strings(&body).swap_remove(0);
                match run(shared, &text, &[]) {
                    Ok(tag) => message(&mut out, b'C', format!("{tag}\0").as_bytes()),
                    Err((code, text)) => error(&mut out, "ERROR", code, &text),
                }
                ready(&mut out);
                stream.write_all(&std::mem::take(&mut out)).await?;
            }
            b'P' if !failed => {
                sql = strings(&body).swap_remove(1);
                message(&mut out, b'1', &[]);
            }
            b'B' if !failed => {
                values = bound(&body);
                message(&mut out, b'2', &[]);
            }
            b'E' if !failed => match run(shared, &sql, &values) {
                Ok(tag) => message(&mut out, b'C', format!("{tag}\0").as_bytes()),
                Err((code, text)) => {
                    error(&mut out, "ERROR", code, &text);
                    failed = true;
                }
            },
            b'S' => {
                failed = false;
                ready(&mut out);
                stream.write_all(&std::mem::take(&mut out)).await?;
            }
            b'X' => return Ok(()),
            _ => {}
        }
    }
}

/// A `Bind`'s values, as text.
fn bound(body: &[u8]) -> Vec<String> {
    let mut at = body.iter().position(|b| *b == 0).unwrap_or(0) + 1;
    at += body[at..].iter().position(|b| *b == 0).unwrap_or(0) + 1;
    let short = |at: usize| usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
    at += 2 + 2 * short(at);
    let count = short(at);
    at += 2;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let size = i32::from_be_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]);
        at += 4;
        let size = usize::try_from(size).unwrap_or(0);
        values.push(String::from_utf8_lossy(&body[at..at + size]).into_owned());
        at += size;
    }
    values
}

/// Runs the statements TeiFS makes on the tables; its command tag, or its error's code
/// and message.
fn run(shared: &Shared, sql: &str, values: &[String]) -> Result<String, (&'static str, String)> {
    let mut state = shared.state();
    state.statements.push((sql.to_owned(), values.to_vec()));
    if state.refusing > 0 {
        state.refusing -= 1;
        return Err(("42501", "permission denied for table".into()));
    }
    let table_after = |word: &str| table_after(sql, word, '"');
    let missing = |table: &str| ("42P01", format!("relation \"{table}\" does not exist"));
    match sql.split(' ').next() {
        Some("CREATE") => {
            let name = table_after("EXISTS");
            let columns = sql[sql.find('(').unwrap_or(0)..].trim_end_matches(';');
            state
                .tables
                .entry(name)
                .or_insert_with(|| (columns.to_owned(), Vec::new()));
            Ok("CREATE TABLE".into())
        }
        Some("SELECT") => {
            let name = table_after("FROM");
            state.tables.get(&name).ok_or_else(|| missing(&name))?;
            Ok("SELECT 0".into())
        }
        Some("INSERT") => {
            let name = table_after("INTO");
            let json = values.last().cloned().unwrap_or_default();
            if serde_json::from_str::<serde_json::Value>(&json).is_err() {
                return Err(("22P02", "invalid input syntax for type json".into()));
            }
            let (_, rows) = state.tables.get_mut(&name).ok_or_else(|| missing(&name))?;
            if sql.contains("ON CONFLICT (key) DO UPDATE") {
                rows.retain(|row| row[0] != values[0]);
            }
            rows.push(values.to_vec());
            Ok("INSERT 0 1".into())
        }
        Some("DELETE") => {
            let name = table_after("FROM");
            let (_, rows) = state.tables.get_mut(&name).ok_or_else(|| missing(&name))?;
            let before = rows.len();
            rows.retain(|row| row[0] != values[0]);
            Ok(format!("DELETE {}", before - rows.len()))
        }
        _ => Err(("42601", format!("syntax error: {sql}"))),
    }
}
