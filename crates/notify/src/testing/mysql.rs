//! A MySQL server on this machine, answering as MySQL 8 does: TLS when it's asked for,
//! sign-in by the user's plugin (`caching_sha2_password` with its cache and RSA key,
//! `mysql_native_password`, `sha256_password`, `mysql_clear_password`), switching to it
//! when the greeting named another, and tables kept in memory, checked by queries and
//! written by prepared statements, with MySQL's error numbers.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use aws_lc_rs::{
    encoding::AsDer as _,
    rsa::{KeySize, OAEP_SHA1_MGF1SHA1, OaepPrivateDecryptingKey, PrivateDecryptingKey},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::io::AsyncWriteExt;

use super::table_after;
use crate::{
    mysql::wire::{
        self, Reader, capability, command, err_packet, native_proof, read_packet, sha2_proof,
    },
    net::Stream,
};

/// A user's sign-in plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyAuth {
    /// `mysql_native_password`.
    Native,
    /// `caching_sha2_password`.
    CachingSha2,
    /// `sha256_password`.
    Sha256,
    /// `mysql_clear_password`.
    Clear,
    /// `MariaDB`'s `client_ed25519`, which TeiFS doesn't speak.
    Ed25519,
}

impl MyAuth {
    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Native => "mysql_native_password",
            Self::CachingSha2 => "caching_sha2_password",
            Self::Sha256 => "sha256_password",
            Self::Clear => "mysql_clear_password",
            Self::Ed25519 => "client_ed25519",
        }
    }
}

/// How a [`MysqlServer`] is made.
#[derive(Clone)]
pub struct MysqlSetup {
    /// The user and password it takes.
    pub login: (String, String),
    /// The user's plugin.
    pub auth: MyAuth,
    /// The plugin its greeting names, when not the user's: it then switches.
    pub greeting: Option<MyAuth>,
    /// Whether `caching_sha2_password` has the user cached from the start.
    pub cached: bool,
    /// The databases it has.
    pub databases: Vec<String>,
    /// The tables it has, by name: their columns.
    pub tables: BTreeMap<String, String>,
    /// TLS, for a client that asks.
    pub tls: Option<tokio_rustls::TlsAcceptor>,
    /// Capabilities it leaves out, as an older server does.
    pub lacks: u32,
    /// Whether it's `MariaDB`, which takes no generated primary key.
    pub mariadb: bool,
}

impl Default for MysqlSetup {
    /// `teifs`/`pw` with `caching_sha2_password`, cached, the database `s3`, no tables and
    /// no TLS.
    fn default() -> Self {
        Self {
            login: ("teifs".into(), "pw".into()),
            auth: MyAuth::CachingSha2,
            greeting: None,
            cached: true,
            databases: vec!["s3".into()],
            tables: BTreeMap::new(),
            tls: None,
            lacks: 0,
            mariadb: false,
        }
    }
}

/// How a connection sent its password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyPassword {
    /// Only a proof that it knows it.
    Proof,
    /// In the clear, over TLS.
    Clear,
    /// Encrypted with the server's RSA key, which it had or asked for.
    Encrypted {
        /// Whether it asked for the key.
        asked_key: bool,
    },
}

/// A connection a [`MysqlServer`] took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyStartup {
    /// Its user and database.
    pub user: String,
    /// Its database.
    pub database: String,
    /// Its character set.
    pub collation: u8,
    /// Whether it asked for, and got, TLS.
    pub tls: bool,
    /// The plugin it signed in with, after any switch.
    pub plugin: String,
    /// How it sent the password.
    pub password: MyPassword,
    /// Whether it signed in.
    pub signed_in: bool,
}

#[derive(Default)]
struct State {
    tables: BTreeMap<String, (String, Vec<Vec<String>>)>,
    startups: Vec<MyStartup>,
    /// Each statement run: its SQL and values.
    statements: Vec<(String, Vec<String>)>,
    /// How many statements were prepared.
    prepares: usize,
    /// Statements still to refuse.
    refusing: usize,
    /// Raised to close every connection open now.
    generation: usize,
    cached: bool,
}

struct Shared {
    setup: MysqlSetup,
    key: OaepPrivateDecryptingKey,
    pem: String,
    state: Mutex<State>,
}

impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A new RSA key pair's private key and its public key as a `PUBLIC KEY` PEM, as MySQL's
/// `private_key.pem` and `public_key.pem`.
fn rsa_key() -> (PrivateDecryptingKey, String) {
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("an RSA key");
    let public = private.public_key().as_der().expect("its public key");
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        BASE64.encode(public.as_ref())
    );
    (private, pem)
}

/// A new RSA public key, as a MySQL server's `public_key.pem`.
#[must_use]
pub fn rsa_public_key_pem() -> String {
    rsa_key().1
}

/// A MySQL server for tests.
pub struct MysqlServer {
    address: String,
    shared: Arc<Shared>,
}

impl MysqlServer {
    /// Starts one, with a new RSA key.
    ///
    /// # Panics
    ///
    /// When it can't listen or make a key.
    pub async fn start(setup: MysqlSetup) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let address = format!(
            "localhost:{}",
            listener.local_addr().expect("a bound address").port()
        );
        let (private, pem) = rsa_key();
        let state = State {
            tables: setup
                .tables
                .iter()
                .map(|(name, columns)| (name.clone(), (columns.clone(), Vec::new())))
                .collect(),
            cached: setup.cached,
            ..State::default()
        };
        let shared = Arc::new(Shared {
            setup,
            key: OaepPrivateDecryptingKey::new(private).expect("an OAEP key"),
            pem,
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

    /// Its RSA public key, as MySQL's `public_key.pem`.
    #[must_use]
    pub fn public_key_pem(&self) -> &str {
        &self.shared.pem
    }

    /// Refuses the next `count` statements.
    pub fn refuse(&self, count: usize) {
        self.shared.state().refusing = count;
    }

    /// Closes every connection open now, on its next command.
    pub fn hang_up(&self) {
        self.shared.state().generation += 1;
    }

    /// Forgets the users `caching_sha2_password` has cached, as a restart does.
    pub fn flush_cache(&self) {
        self.shared.state().cached = false;
    }

    /// The connections it took.
    #[must_use]
    pub fn startups(&self) -> Vec<MyStartup> {
        self.shared.state().startups.clone()
    }

    /// Each statement it ran, queried or prepared: its SQL and values.
    #[must_use]
    pub fn statements(&self) -> Vec<(String, Vec<String>)> {
        self.shared.state().statements.clone()
    }

    /// How many statements were prepared.
    #[must_use]
    pub fn prepares(&self) -> usize {
        self.shared.state().prepares
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

/// A connection's packets, numbered.
struct Wire {
    stream: Stream,
    seq: u8,
}

impl Wire {
    async fn read(&mut self) -> std::io::Result<Vec<u8>> {
        let (seq, payload) = read_packet(&mut self.stream, 1 << 26)
            .await
            .map_err(std::io::Error::other)?;
        if seq != self.seq {
            return Err(std::io::Error::other(format!(
                "packet {seq}, not {}",
                self.seq
            )));
        }
        self.seq = seq.wrapping_add(1);
        Ok(payload)
    }

    async fn write(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let packet = wire::packet(self.seq, payload).map_err(std::io::Error::other)?;
        self.seq = self.seq.wrapping_add(1);
        self.stream.write_all(&packet).await
    }
}

const OK: [u8; 7] = [0, 0, 0, 2, 0, 0, 0];
const EOF: [u8; 5] = [0xfe, 0, 0, 2, 0];

fn nonce() -> Vec<u8> {
    let mut bytes = [0; 20];
    aws_lc_rs::rand::fill(&mut bytes).expect("randomness");
    // MySQL's nonces are printable and never NUL.
    bytes.iter().map(|b| b'!' + b % 90).collect()
}

/// The greeting (protocol 10), naming the setup's capabilities and first plugin.
fn greeting(setup: &MysqlSetup, nonce: &[u8]) -> Vec<u8> {
    let mut capabilities = capability::LONG_PASSWORD
        | capability::CONNECT_WITH_DB
        | capability::PROTOCOL_41
        | capability::TRANSACTIONS
        | capability::SECURE_CONNECTION
        | capability::PLUGIN_AUTH
        | capability::PLUGIN_AUTH_LENENC_DATA;
    if setup.tls.is_some() {
        capabilities |= capability::SSL;
    }
    capabilities &= !setup.lacks;
    let named = setup.greeting.unwrap_or(setup.auth).name();
    let mut greeting = vec![10];
    greeting.extend_from_slice(if setup.mariadb {
        b"5.5.5-11.4.8-MariaDB-teifs-test\0"
    } else {
        b"8.4.6-teifs-test\0"
    });
    greeting.extend_from_slice(&1u32.to_le_bytes());
    greeting.extend_from_slice(&nonce[..8]);
    greeting.push(0);
    greeting.extend_from_slice(&capabilities.to_le_bytes()[..2]);
    greeting.push(255);
    greeting.extend_from_slice(&2u16.to_le_bytes());
    greeting.extend_from_slice(&capabilities.to_le_bytes()[2..]);
    greeting.push(21);
    greeting.extend_from_slice(&[0; 10]);
    greeting.extend_from_slice(&nonce[8..]);
    greeting.push(0);
    greeting.extend_from_slice(named.as_bytes());
    greeting.push(0);
    greeting
}

async fn serve(stream: Stream, shared: &Shared) -> std::io::Result<()> {
    let setup = &shared.setup;
    let mut wire = Wire { stream, seq: 0 };
    let mut nonce = nonce();
    wire.write(&greeting(setup, &nonce)).await?;
    let mut response = wire.read().await?;
    let mut tls = false;
    if response.len() == 32
        && let Some(acceptor) = &setup.tls
    {
        let Wire { stream, seq } = wire;
        let secured = tokio_rustls::TlsStream::Server(acceptor.accept(stream).await?);
        wire = Wire {
            stream: Box::new(secured),
            seq,
        };
        tls = true;
        response = wire.read().await?;
    }
    let mut reader = Reader::new(&response);
    let client = reader.u32().map_err(std::io::Error::other)?;
    reader.take(4).map_err(std::io::Error::other)?;
    let collation = reader.u8().map_err(std::io::Error::other)?;
    reader.take(23).map_err(std::io::Error::other)?;
    let user = String::from_utf8_lossy(reader.cstring()).into_owned();
    let mut answer = if client & capability::PLUGIN_AUTH_LENENC_DATA == 0 {
        let size = usize::from(reader.u8().map_err(std::io::Error::other)?);
        reader.take(size).map_err(std::io::Error::other)?.to_vec()
    } else {
        reader
            .lenenc_bytes()
            .map_err(std::io::Error::other)?
            .to_vec()
    };
    let database = String::from_utf8_lossy(reader.cstring()).into_owned();
    let mut plugin = String::from_utf8_lossy(reader.cstring()).into_owned();
    let mut startup = MyStartup {
        user: user.clone(),
        database: database.clone(),
        collation,
        tls,
        plugin: plugin.clone(),
        password: MyPassword::Proof,
        signed_in: false,
    };
    if plugin != setup.auth.name() {
        nonce = self::nonce();
        let mut switch = vec![0xfe];
        switch.extend_from_slice(setup.auth.name().as_bytes());
        switch.push(0);
        switch.extend_from_slice(&nonce);
        switch.push(0);
        wire.write(&switch).await?;
        answer = wire.read().await?;
        setup.auth.name().clone_into(&mut plugin);
        startup.plugin.clone_from(&plugin);
    }
    let signed_in = user == setup.login.0
        && sign_in(&mut wire, shared, &nonce, answer, tls, &mut startup).await?;
    let known = setup.databases.contains(&database);
    startup.signed_in = signed_in && known;
    shared.state().startups.push(startup);
    if !signed_in {
        let text = format!("Access denied for user '{user}'@'localhost' (using password: YES)");
        return wire.write(&err_packet(1045, "28000", &text)).await;
    }
    if !known {
        let text = format!("Unknown database '{database}'");
        return wire.write(&err_packet(1049, "42000", &text)).await;
    }
    wire.write(&OK).await?;
    commands(wire, shared).await
}

/// Checks the user's password by its plugin; whether it's right.
async fn sign_in(
    wire: &mut Wire,
    shared: &Shared,
    nonce: &[u8],
    answer: Vec<u8>,
    tls: bool,
    startup: &mut MyStartup,
) -> std::io::Result<bool> {
    let password = shared.setup.login.1.as_str();
    let whole = |sent: Vec<u8>, startup: &mut MyStartup| {
        startup.password = match (tls, startup.password) {
            (true, _) => MyPassword::Clear,
            (false, MyPassword::Encrypted { asked_key }) => MyPassword::Encrypted { asked_key },
            (false, _) => MyPassword::Encrypted { asked_key: false },
        };
        let mut clear = password.as_bytes().to_vec();
        clear.push(0);
        if tls {
            return sent == clear;
        }
        let mut out = vec![0; shared.key.min_output_size()];
        let Ok(plain) = shared
            .key
            .decrypt(&OAEP_SHA1_MGF1SHA1, &sent, &mut out, None)
        else {
            return false;
        };
        let plain: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ nonce[i % nonce.len()])
            .collect();
        plain == clear
    };
    let key = async |wire: &mut Wire, startup: &mut MyStartup| {
        startup.password = MyPassword::Encrypted { asked_key: true };
        let mut pem = vec![1];
        pem.extend_from_slice(shared.pem.as_bytes());
        wire.write(&pem).await?;
        wire.read().await
    };
    Ok(match shared.setup.auth {
        MyAuth::Native => answer == native_proof(password, nonce),
        MyAuth::Sha256 if answer == [1] => {
            let sealed = key(wire, startup).await?;
            whole(sealed, startup)
        }
        MyAuth::Clear | MyAuth::Sha256 => whole(answer, startup),
        MyAuth::Ed25519 => false,
        MyAuth::CachingSha2 => {
            if answer != sha2_proof(password, nonce) {
                return Ok(false);
            }
            if shared.state().cached {
                wire.write(&[1, 3]).await?;
                return Ok(true);
            }
            wire.write(&[1, 4]).await?;
            let mut sent = wire.read().await?;
            if sent == [2] {
                sent = key(wire, startup).await?;
            }
            let right = whole(sent, startup);
            if right {
                shared.state().cached = true;
            }
            right
        }
    })
}

/// Answers commands until the connection closes or is hung up.
async fn commands(mut wire: Wire, shared: &Shared) -> std::io::Result<()> {
    let generation = shared.state().generation;
    let mut prepared: HashMap<u32, (String, usize)> = HashMap::new();
    loop {
        wire.seq = 0;
        let packet = wire.read().await?;
        if shared.state().generation != generation {
            return Ok(());
        }
        let Some((&kind, body)) = packet.split_first() else {
            return Ok(());
        };
        let sql = String::from_utf8_lossy(body).into_owned();
        match kind {
            command::QUERY => match run(shared, &sql, &[]) {
                Ok(Some(())) => {
                    // One column, no rows.
                    wire.write(&[1]).await?;
                    wire.write(&column()).await?;
                    wire.write(&EOF).await?;
                    wire.write(&EOF).await?;
                }
                Ok(None) => wire.write(&OK).await?,
                Err(error) => wire.write(&error).await?,
            },
            command::STMT_PREPARE => {
                if let Err(error) = check(shared, &sql) {
                    wire.write(&error).await?;
                    continue;
                }
                let parameters = sql.matches('?').count();
                let id = {
                    let mut state = shared.state();
                    state.prepares += 1;
                    u32::try_from(state.prepares).unwrap_or(0)
                };
                prepared.insert(id, (sql, parameters));
                let mut out = vec![0];
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&u16::try_from(parameters).unwrap_or(0).to_le_bytes());
                out.extend_from_slice(&[0, 0, 0]);
                wire.write(&out).await?;
                for _ in 0..parameters {
                    wire.write(&column()).await?;
                }
                if parameters > 0 {
                    wire.write(&EOF).await?;
                }
            }
            command::STMT_EXECUTE => {
                let answer = match execute(shared, &prepared, body) {
                    Ok(()) => OK.to_vec(),
                    Err(error) => error,
                };
                wire.write(&answer).await?;
            }
            command::QUIT => return Ok(()),
            _ => {
                wire.write(&err_packet(1047, "08S01", "Unknown command"))
                    .await?;
            }
        }
    }
}

/// A column's definition (its content doesn't matter to TeiFS).
fn column() -> Vec<u8> {
    let mut out = Vec::new();
    for text in ["def", "s3", "t", "t", "c", "c"] {
        wire::lenenc_bytes(&mut out, text.as_bytes());
    }
    out.extend_from_slice(&[0x0c, 45, 0, 4, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0]);
    out
}

fn no_table(table: &str) -> Vec<u8> {
    err_packet(1146, "42S02", &format!("Table 's3.{table}' doesn't exist"))
}

/// The table a statement names, checked to be there.
fn check(shared: &Shared, sql: &str) -> Result<String, Vec<u8>> {
    let table = ["INTO", "FROM"]
        .iter()
        .map(|word| table_after(sql, word, '`'))
        .find(|t| !t.is_empty())
        .unwrap_or_default();
    if shared.state().tables.contains_key(&table) {
        Ok(table)
    } else {
        Err(no_table(&table))
    }
}

/// Runs a query: `Some` for a `SELECT`'s (empty) rows, `None` for a command.
fn run(shared: &Shared, sql: &str, values: &[String]) -> Result<Option<()>, Vec<u8>> {
    shared
        .state()
        .statements
        .push((sql.to_owned(), values.to_vec()));
    if sql.starts_with("CREATE TABLE IF NOT EXISTS ") {
        if shared.setup.mariadb && sql.contains("STORED NOT NULL PRIMARY KEY") {
            return Err(err_packet(
                1903,
                "HY000",
                "Primary key cannot be defined upon a generated column",
            ));
        }
        let name = table_after(sql, "EXISTS", '`');
        let columns = sql[sql.find('(').unwrap_or(0)..].trim_end_matches(';');
        shared
            .state()
            .tables
            .entry(name)
            .or_insert_with(|| (columns.to_owned(), Vec::new()));
        return Ok(None);
    }
    if sql.starts_with("SELECT 1 FROM ") {
        let mut state = shared.state();
        if state.refusing > 0 {
            state.refusing -= 1;
            return Err(err_packet(1142, "42000", "SELECT command denied to user"));
        }
        let name = table_after(sql, "FROM", '`');
        return if state.tables.contains_key(&name) {
            Ok(Some(()))
        } else {
            Err(no_table(&name))
        };
    }
    Err(err_packet(
        1064,
        "42000",
        "You have an error in your SQL syntax",
    ))
}

/// Runs a prepared statement with the values in `body`, all strings.
fn execute(
    shared: &Shared,
    prepared: &HashMap<u32, (String, usize)>,
    body: &[u8],
) -> Result<(), Vec<u8>> {
    let garbled = || err_packet(1210, "HY000", "Incorrect arguments to mysqld_stmt_execute");
    let mut reader = Reader::new(body);
    let id = reader.u32().map_err(|_| garbled())?;
    let (sql, count) = prepared.get(&id).ok_or_else(garbled)?;
    let head = reader.take(5).map_err(|_| garbled())?;
    let nulls = reader.take(count.div_ceil(8)).map_err(|_| garbled())?;
    if head != [0, 1, 0, 0, 0] || nulls.iter().any(|b| *b != 0) || reader.u8() != Ok(1) {
        return Err(garbled());
    }
    for _ in 0..*count {
        if reader.take(2) != Ok(&[wire::TYPE_STRING, 0][..]) {
            return Err(garbled());
        }
    }
    let mut values = Vec::with_capacity(*count);
    for _ in 0..*count {
        let value = reader.lenenc_bytes().map_err(|_| garbled())?;
        values.push(String::from_utf8(value.to_vec()).map_err(|_| garbled())?);
    }
    if !reader.rest().is_empty() {
        return Err(garbled());
    }
    let mut state = shared.state();
    state.statements.push((sql.clone(), values.clone()));
    if state.refusing > 0 {
        state.refusing -= 1;
        return Err(err_packet(1142, "42000", "INSERT command denied to user"));
    }
    let table = ["INTO", "FROM"]
        .iter()
        .map(|word| table_after(sql, word, '`'))
        .find(|t| !t.is_empty())
        .unwrap_or_default();
    let (_, rows) = state
        .tables
        .get_mut(&table)
        .ok_or_else(|| no_table(&table))?;
    if sql.starts_with("DELETE FROM ") && sql.contains("WHERE key_hash = SHA2(?, 256)") {
        rows.retain(|row| row[0] != values[0]);
        return Ok(());
    }
    let json = values.last().cloned().unwrap_or_default();
    if serde_json::from_str::<serde_json::Value>(&json).is_err() {
        return Err(err_packet(3140, "22032", "Invalid JSON text"));
    }
    if sql.contains("(event_time, event_data)") {
        let time = &values[0];
        let digits = time.chars().filter(char::is_ascii_digit).count();
        if time.len() < 19 || &time[10..11] != " " || digits < 14 || time.ends_with('Z') {
            return Err(err_packet(1292, "22007", "Incorrect datetime value"));
        }
    } else if sql.contains("ON DUPLICATE KEY UPDATE value=VALUES(value)") {
        rows.retain(|row| row[0] != values[0]);
    }
    rows.push(values);
    Ok(())
}
