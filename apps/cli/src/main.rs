//! `teifs`: serve a folder as a drive over S3, and manage it from the terminal.

#![allow(clippy::print_stdout, reason = "a command line prints its results")]

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

mod client;
mod config;
mod error;
mod health;
mod init;
mod ui;
mod units;

use clap::{Parser, Subcommand};
use teifs_server::{
    Config, Credentials, Durability, JobOptions, KeyRules, KmsLocation, Limits, Server, Transit,
    credentials,
};
use teifs_store::{Layout, Store};
use units::{date, from_ms, parse_count, parse_duration, rfc3339};

// Measured faster than the system allocator on macOS (and musl's is far slower still).
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "teifs", version, about = "Your folders as a drive and as S3")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Print results as JSON Lines (one object per line, each with a `type`).
    #[arg(long, global = true)]
    json: bool,
    /// Print only results, warnings and errors.
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Answer yes to questions (like confirming a deletion).
    #[arg(short, long, global = true)]
    yes: bool,
    /// When to use colors.
    #[arg(long, global = true, value_enum, default_value = "auto")]
    color: ui::ColorArg,
}

#[derive(Subcommand)]
enum Command {
    /// Set up a drive: its folder, keys, keyring and settings, and an alias to reach it.
    /// Asks on a terminal; flags answer instead.
    Init(init::InitArgs),
    /// Serve a drive over the S3 API. Every folder in it is a bucket.
    Serve(ServeArgs),
    /// Show the settings `teifs serve` would use, and where each comes from.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Show the drive's access key and where its secret is kept.
    Credentials {
        /// The drive's folder.
        #[arg(default_value = ".", env = "TEIFS_DIR")]
        dir: PathBuf,
    },
    /// List, create or remove buckets.
    Bucket {
        #[command(subcommand)]
        action: BucketAction,
    },
    /// Manage the KMS keys that encrypt objects (SSE-S3 uses `teifs-default`).
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    #[command(flatten)]
    Client(client::Command),
    /// Check that a TeiFS server answers its health check (exit code 0 when it does);
    /// for container health checks and scripts.
    Health(health::HealthArgs),
    /// Print the shell completion script for `shell`, for example
    /// `teifs completions zsh > ~/.zfunc/_teifs` or
    /// `teifs completions bash > ~/.local/share/bash-completion/completions/teifs`.
    Completions { shell: clap_complete::Shell },
}

/// `teifs serve`'s settings. Each can also be set in a settings file (`--config`),
/// under the flag's name; flags and environment variables win over it.
#[derive(clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is an independent command-line flag"
)]
pub(crate) struct ServeArgs {
    /// A TOML file of settings, under the flags' names (`listen = "0.0.0.0:9000"`).
    #[arg(long, env = "TEIFS_CONFIG")]
    config: Option<PathBuf>,
    /// The drive's folder (created if missing).
    #[arg(default_value = ".", env = "TEIFS_DIR")]
    dir: PathBuf,
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:9000", env = "TEIFS_LISTEN")]
    listen: SocketAddr,
    /// A domain for virtual-hosted-style requests (bucket.domain); repeatable.
    #[arg(long = "domain", env = "TEIFS_DOMAINS", value_delimiter = ',')]
    domains: Vec<String>,
    /// The access key (else one is generated and kept in the drive).
    #[arg(long, env = "TEIFS_ACCESS_KEY")]
    access_key: Option<String>,
    /// How buckets created over S3 store objects, unless the request says: `object`
    /// (any key S3 allows, encrypted at rest by default, as on AWS) or `folder`
    /// (plain files you can open anywhere).
    #[arg(
        long,
        value_enum,
        default_value = "object",
        env = "TEIFS_DEFAULT_LAYOUT"
    )]
    default_layout: LayoutArg,
    /// The KMS keyring (default: `<config dir>/teifs/keys/<drive id>.json`). Keep it
    /// off the drive and back it up: encrypted objects can't be read without it.
    #[arg(long, env = "TEIFS_KMS_KEYRING")]
    kms_keyring: Option<PathBuf>,
    /// Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`);
    /// its token comes from `VAULT_TOKEN` or `BAO_TOKEN`.
    #[arg(long, env = "TEIFS_KMS_TRANSIT", conflicts_with = "kms_keyring")]
    kms_transit: Option<String>,
    /// Where the transit engine is mounted.
    #[arg(long, default_value = "transit", env = "TEIFS_KMS_TRANSIT_MOUNT")]
    kms_transit_mount: String,
    /// The transit engine's namespace (Vault Enterprise, OpenBao).
    #[arg(long, env = "TEIFS_KMS_TRANSIT_NAMESPACE")]
    kms_transit_namespace: Option<String>,
    /// Allow SSE-C (customer-provided keys) on buckets that don't set it themselves;
    /// AWS blocks it by default since April 2026.
    #[arg(long, env = "TEIFS_ALLOW_SSE_C")]
    allow_sse_c: bool,
    /// Accept Signature Version 2 (HMAC-SHA1) requests and links, for old clients and
    /// boto3's default presigned links. AWS deprecated it and refuses it for newer
    /// buckets; prefer configuring clients for Signature Version 4.
    #[arg(long, env = "TEIFS_ALLOW_SIGV2")]
    allow_sigv2: bool,
    /// Make new buckets as S3 did before April 2023: ACLs enabled and no Block Public
    /// Access, for applications that upload with public ACLs such as `public-read`.
    /// Without it, new buckets start as AWS's do now: ACLs disabled, public access
    /// blocked. Either way each bucket's settings can be changed.
    #[arg(long, env = "TEIFS_LEGACY_BUCKET_DEFAULTS")]
    legacy_bucket_defaults: bool,
    /// Accept SSE-C keys over plain HTTP. Only behind a proxy that terminates TLS;
    /// a server listening on this machine only accepts them anyway.
    #[arg(long, env = "TEIFS_SSE_C_OVER_HTTP")]
    sse_c_over_http: bool,
    /// Abort multipart uploads left unfinished this long (`30m`, `12h`, `7d`), or
    /// `never`.
    #[arg(long, default_value = "7d", value_parser = parse_expiry, env = "TEIFS_UPLOAD_EXPIRY")]
    upload_expiry: Expiry,
    /// How hard writes are made to survive a power cut: `strict` (nothing
    /// acknowledged is lost), `relaxed` (file data synced; the last moments' writes
    /// may be lost) or `none` (scratch data). None of them can corrupt the drive.
    #[arg(long, value_enum, default_value = "strict", env = "TEIFS_DURABILITY")]
    durability: DurabilityArg,
    /// Which names folder buckets may create: `portable` (names Windows, macOS and
    /// Linux can all hold, so the drive can move between them) or `host` (whatever
    /// this system can hold). Object buckets take any S3 key either way.
    #[arg(long, value_enum, default_value = "portable", env = "TEIFS_KEY_NAMES")]
    key_names: KeyNamesArg,
    /// How long a client has to send a request's headers; idle connections close
    /// after it too.
    #[arg(long, default_value = "30s", value_parser = parse_duration, env = "TEIFS_HEADER_TIMEOUT")]
    header_timeout: Duration,
    /// How long an upload's body may stop arriving before the request fails with
    /// `RequestTimeout`.
    #[arg(long, default_value = "60s", value_parser = parse_duration, env = "TEIFS_BODY_TIMEOUT")]
    body_timeout: Duration,
    /// The most connections served at once; more wait until one closes.
    #[arg(long, default_value = "4096", value_parser = parse_count, env = "TEIFS_MAX_CONNECTIONS")]
    max_connections: usize,
    /// A file holding the secret key, for use with the access key (Docker and
    /// systemd secrets). Or set `TEIFS_SECRET_KEY`; never on the command line.
    #[arg(long, env = "TEIFS_SECRET_KEY_FILE")]
    secret_key_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the effective settings as TOML, with where each comes from. Secrets are
    /// never printed.
    Show(ServeArgs),
}

/// Where a key command finds the keyring.
#[derive(clap::Args)]
struct KeyringArgs {
    /// The keyring (default: the drive's, in `<config dir>/teifs/keys/`).
    #[arg(long, env = "TEIFS_KMS_KEYRING")]
    kms_keyring: Option<PathBuf>,
    /// The drive whose default keyring to use.
    #[arg(long, default_value = ".", env = "TEIFS_DIR")]
    dir: PathBuf,
    /// A Vault or OpenBao transit engine instead of a keyring (token from `VAULT_TOKEN`
    /// or `BAO_TOKEN`).
    #[arg(long, env = "TEIFS_KMS_TRANSIT", conflicts_with = "kms_keyring")]
    kms_transit: Option<String>,
    /// Where the transit engine is mounted.
    #[arg(long, default_value = "transit", env = "TEIFS_KMS_TRANSIT_MOUNT")]
    kms_transit_mount: String,
    /// The transit engine's namespace.
    #[arg(long, env = "TEIFS_KMS_TRANSIT_NAMESPACE")]
    kms_transit_namespace: Option<String>,
}

#[derive(Subcommand)]
enum KeyAction {
    /// List the keys and their newest versions.
    List {
        #[command(flatten)]
        keyring: KeyringArgs,
    },
    /// Create a key (for SSE-KMS: `x-amz-server-side-encryption-aws-kms-key-id`).
    Create {
        /// Its name: letters, digits, `-`, `_` and `.`.
        name: String,
        #[command(flatten)]
        keyring: KeyringArgs,
    },
    /// Add a new version to a key; objects sealed by older versions stay readable.
    Rotate {
        name: String,
        #[command(flatten)]
        keyring: KeyringArgs,
    },
}

#[derive(Subcommand)]
enum BucketAction {
    /// List buckets.
    List {
        /// The drive's folder (while `teifs serve` isn't using it).
        #[arg(long, default_value = ".", env = "TEIFS_DIR")]
        dir: PathBuf,
    },
    /// Create a bucket.
    Create {
        name: String,
        /// How it stores objects: `object` (any key S3 allows) or `folder` (plain files).
        #[arg(long, value_enum, default_value = "object")]
        layout: LayoutArg,
        /// The drive's folder (while `teifs serve` isn't using it).
        #[arg(long, default_value = ".", env = "TEIFS_DIR")]
        dir: PathBuf,
    },
    /// Remove an empty bucket.
    Remove {
        name: String,
        /// The drive's folder (while `teifs serve` isn't using it).
        #[arg(long, default_value = ".", env = "TEIFS_DIR")]
        dir: PathBuf,
    },
}

/// A bucket layout on the command line.
#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum LayoutArg {
    /// Objects stored by id under `.teifs`, with every key S3 allows.
    Object,
    /// A folder of plain files.
    Folder,
}

impl LayoutArg {
    /// Its name on the command line and in settings.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Folder => "folder",
        }
    }
}

impl From<LayoutArg> for Layout {
    fn from(arg: LayoutArg) -> Self {
        match arg {
            LayoutArg::Object => Layout::Object,
            LayoutArg::Folder => Layout::Folder,
        }
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            // s3s logs every refused request (a missing key, a bad signature) as an
            // error; server errors are still logged by s3s and by TeiFS. The AWS SDK
            // warns that it can't check a multipart object's composite checksum on
            // download; it checks every other kind, and there's nothing to do about it.
            tracing_subscriber::EnvFilter::try_from_env("TEIFS_LOG").unwrap_or_else(|_| {
                "info,s3s::ops=off,aws_sdk_s3::http_response_checksum=error".into()
            }),
        )
        .with_writer(std::io::stderr)
        .init();
    let (cli, sources) = match config::parse(std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(message) => {
            let err = error::Error::usage(message);
            ui::error(&err);
            return ExitCode::from(err.kind.code());
        }
    };
    // Commands run on a worker thread with a roomy stack: the AWS SDK's futures poll
    // deep, and Windows gives the main thread only 1 MiB.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(STACK_SIZE)
        .build()
        .expect("a Tokio runtime");
    ui::init(
        ui::Settings {
            json: cli.json,
            quiet: cli.quiet,
            yes: cli.yes,
        },
        cli.color,
    );
    let result = runtime.block_on(async move {
        match tokio::spawn(async move { run(cli.command, &sources).await }).await {
            Ok(result) => result,
            Err(err) => std::panic::resume_unwind(err.into_panic()),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            ui::error(&err);
            ExitCode::from(err.kind.code())
        }
    }
}

/// The stack of the threads commands run on.
const STACK_SIZE: usize = 8 * 1024 * 1024;

pub(crate) fn open(dir: &Path) -> Result<Store, error::Error> {
    use teifs_store::StoreError;
    Store::open(dir).map_err(|e| match e {
        StoreError::DriveInUse => error::Error::new(
            error::Kind::Conflict,
            format!(
                "the drive at {} is open in another TeiFS process",
                dir.display()
            ),
        )
        .with_hint("stop `teifs serve`, or use an S3 client against it (`teifs ls ALIAS`)"),
        StoreError::Io(err) if err.kind() == std::io::ErrorKind::NotFound => error::Error::new(
            error::Kind::NotFound,
            format!("there's no drive at {}", dir.display()),
        )
        .with_hint("make one with `teifs init`, or serve a folder with `teifs serve DIR`"),
        e => error::Error::general(format!("can't open the drive at {}: {e}", dir.display())),
    })
}

async fn run(command: Command, sources: &config::Sources) -> Result<(), error::Error> {
    match command {
        Command::Init(args) => init::init(&args),
        Command::Health(args) => health::health(&args).await,
        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "teifs", &mut script);
            ui::raw(&String::from_utf8_lossy(&script));
            Ok(())
        }
        Command::Serve(args) => Ok(serve(args).await?),
        Command::Config {
            action: ConfigAction::Show(args),
        } => Ok(config::show(&args, sources)?),
        Command::Credentials { dir } => {
            let store = open(&dir)?;
            let (credentials, _) = credentials::load_or_create(store.root())
                .map_err(|e| format!("can't read the credentials: {e}"))?;
            let path = credentials::path(store.root()).display().to_string();
            ui::details(
                &[
                    ("Access key", credentials.access_key.clone()),
                    ("Secret key", format!("in {path}")),
                ],
                || {
                    serde_json::json!({
                        "type": "credentials",
                        "accessKey": credentials.access_key,
                        "secretKeyFile": path,
                    })
                },
            );
            Ok(())
        }
        Command::Bucket { action } => Ok(bucket(action).await?),
        Command::Key { action } => Ok(key(action).await?),
        Command::Client(command) => client::run(command).await,
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum KeyNamesArg {
    Portable,
    Host,
}

impl From<KeyNamesArg> for KeyRules {
    fn from(arg: KeyNamesArg) -> Self {
        match arg {
            KeyNamesArg::Portable => Self::Portable,
            KeyNamesArg::Host => Self::Host,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DurabilityArg {
    Strict,
    Relaxed,
    None,
}

impl From<DurabilityArg> for Durability {
    fn from(arg: DurabilityArg) -> Self {
        match arg {
            DurabilityArg::Strict => Self::Strict,
            DurabilityArg::Relaxed => Self::Relaxed,
            DurabilityArg::None => Self::None,
        }
    }
}

/// How long unfinished uploads are kept; `None` for ever.
#[derive(Debug, Clone, Copy)]
struct Expiry(Option<Duration>);

/// Parses `never`, or a duration ([`parse_duration`]).
fn parse_expiry(text: &str) -> Result<Expiry, String> {
    if text.trim().eq_ignore_ascii_case("never") {
        return Ok(Expiry(None));
    }
    parse_duration(text)
        .map(|duration| Expiry(Some(duration)))
        .map_err(|e| format!("{e} (or say never)"))
}

async fn serve(args: ServeArgs) -> Result<(), String> {
    let keys = config::keys(&args, config::env)?;
    let credentials = match &keys {
        Some(keys) => Some(Credentials {
            access_key: keys.access.clone(),
            secret_key: keys.secret.read()?,
        }),
        None => None,
    };
    let server = Server::bind(Config {
        dir: args.dir,
        listen: args.listen,
        domains: args.domains,
        credentials,
        default_layout: args.default_layout.into(),
        kms_keyring: args.kms_keyring,
        kms_transit: args.kms_transit.map(|address| Transit {
            address,
            mount: args.kms_transit_mount,
            namespace: args.kms_transit_namespace,
        }),
        allow_sse_c: args.allow_sse_c,
        allow_sig_v2: args.allow_sigv2,
        legacy_bucket_defaults: args.legacy_bucket_defaults,
        plain_http_is_secure: args.sse_c_over_http.then_some(true),
        jobs: JobOptions {
            upload_expiry: args.upload_expiry.0,
            ..JobOptions::default()
        },
        durability: args.durability.into(),
        key_rules: args.key_names.into(),
        limits: Limits {
            header_timeout: args.header_timeout,
            body_timeout: args.body_timeout,
            max_connections: args.max_connections,
        },
    })
    .await
    .map_err(|e| e.to_string())?;
    if let Some(config::Keys {
        from_minio: true, ..
    }) = &keys
    {
        ui::note("Using MINIO_ROOT_USER and MINIO_ROOT_PASSWORD as the access and secret key.");
    }
    let address = server.local_addr().map_err(|e| e.to_string())?;
    announce(&server, address, keys.as_ref(), args.durability.into());
    server.run(shutdown_signal()).await;
    ui::note("Stopped.");
    Ok(())
}

/// Says what `teifs serve` is serving and how to reach it: a block for people on
/// standard error, or one `serving` record for `--json` (its endpoint is the one to use,
/// even with `--listen 127.0.0.1:0`).
fn announce(
    server: &Server,
    address: SocketAddr,
    keys: Option<&config::Keys>,
    durability: Durability,
) {
    let endpoint = format!("http://{}", announce_address(address));
    let drive = server.root().display().to_string();
    let secret = match keys {
        Some(keys) => keys.secret.describe(),
        None => format!("in {}", credentials::path(server.root()).display()),
    };
    let (keyring, created) = match server.kms() {
        KmsLocation::Keyring { path, created } => (path.display().to_string(), *created),
        KmsLocation::Transit(address) => (format!("the transit engine at {address}"), false),
    };
    let durability_name = match durability {
        Durability::Strict => "strict",
        Durability::Relaxed => "relaxed",
        Durability::None => "none",
    };
    if ui::json() {
        ui::emit(&serde_json::json!({
            "type": "serving",
            "endpoint": endpoint,
            "listen": address.to_string(),
            "drive": drive,
            "accessKey": server.access_key(),
            "keyring": keyring,
            "durability": durability_name,
        }));
        return;
    }
    let alias = match keys {
        None => format!(
            "teifs alias set local {endpoint} --drive {}",
            shell_word(&drive)
        ),
        Some(keys) => format!(
            "teifs alias set local {endpoint} --access-key {}",
            shell_word(&keys.access)
        ),
    };
    ui::banner(
        format!("Serving {drive} over S3"),
        &[
            ("Endpoint", endpoint.clone()),
            ("Access key", server.access_key().to_owned()),
            ("Secret key", secret),
            ("Keyring", keyring.clone()),
            ("Durability", durability_name.to_owned()),
        ],
        &[
            alias,
            "teifs ls local".to_owned(),
            format!("aws --endpoint-url {endpoint} s3 ls"),
        ],
    );
    if server.created_credentials() {
        ui::note(format!(
            "Created this drive's credentials in {}",
            credentials::path(server.root()).display()
        ));
    }
    if created {
        ui::warn(format!(
            "created the encryption keyring in {keyring}; back it up: encrypted objects can't be read without it"
        ));
    }
    match durability {
        Durability::Strict => {}
        Durability::Relaxed => ui::warn(
            "durability is relaxed: a power cut can lose the last moments' writes (never corrupt the drive)",
        ),
        Durability::None => {
            ui::warn("durability is none: nothing is synced to disk; use it only for scratch data");
        }
    }
}

/// The address to reach a server listening on `address` from this machine: loopback
/// for "every address".
pub(crate) fn announce_address(address: SocketAddr) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let ip = match address.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, address.port())
}

/// `text` as one word for a POSIX shell: as is when it's plain, else single-quoted.
pub(crate) fn shell_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c));
    if plain {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

async fn key(action: KeyAction) -> Result<(), error::Error> {
    use teifs_store::{Kms, LocalKms, TransitKms};
    let (KeyAction::List { keyring }
    | KeyAction::Create { keyring, .. }
    | KeyAction::Rotate { keyring, .. }) = &action;
    let (kms, place): (Box<dyn Kms>, String) = if let Some(address) = &keyring.kms_transit {
        let token = std::env::var("VAULT_TOKEN")
            .or_else(|_| std::env::var("BAO_TOKEN"))
            .map_err(|_| "set VAULT_TOKEN (or BAO_TOKEN) to use a transit engine".to_owned())?;
        let kms = TransitKms::new(
            address,
            &keyring.kms_transit_mount,
            token,
            keyring.kms_transit_namespace.clone(),
        )
        .map_err(|e| e.to_string())?;
        (Box::new(kms), format!("the transit engine at {address}"))
    } else {
        let path = if let Some(path) = &keyring.kms_keyring {
            path.clone()
        } else {
            let store = open(&keyring.dir)?;
            teifs_server::default_keyring(&store.format().drive).map_err(|e| e.to_string())?
        };
        let kms = LocalKms::open(&path)
            .map_err(|e| format!("can't open the keyring at {}: {e}", path.display()))?;
        (Box::new(kms), path.display().to_string())
    };
    match action {
        KeyAction::List { .. } => {
            let mut table = ui::Table::new(&["NAME", ">VERSION", "CREATED"]);
            let mut records = Vec::new();
            for key in kms.keys().await.map_err(|e| e.to_string())? {
                let created = from_ms(key.created_ms);
                table.row(vec![
                    key.name.clone(),
                    key.version.to_string(),
                    date(created),
                ]);
                records.push(serde_json::json!({
                    "type": "key",
                    "name": key.name,
                    "version": key.version,
                    "created": rfc3339(created),
                }));
            }
            ui::rows(&table, &records, &format!("No keys in {place} yet."));
        }
        KeyAction::Create { name, .. } => {
            kms.create_key(&name).await.map_err(|e| e.to_string())?;
            ui::done(
                format!("Created key {name} in {place}"),
                || serde_json::json!({"type": "key", "name": name, "version": 1}),
            );
        }
        KeyAction::Rotate { name, .. } => {
            let info = kms.rotate_key(&name).await.map_err(|e| e.to_string())?;
            ui::done(
                format!("Rotated {name}: new objects use version {}", info.version),
                || serde_json::json!({"type": "key", "name": name, "version": info.version}),
            );
        }
    }
    Ok(())
}

async fn bucket(action: BucketAction) -> Result<(), error::Error> {
    match action {
        BucketAction::List { dir } => {
            let mut table = ui::Table::new(&["NAME", "LAYOUT", "CREATED"]);
            let mut records = Vec::new();
            for bucket in open(&dir)?
                .list_buckets()
                .await
                .map_err(|e| e.to_string())?
            {
                let layout = match bucket.layout {
                    Layout::Object => "object",
                    Layout::Folder => "folder",
                };
                table.row(vec![
                    bucket.name.clone(),
                    layout.to_owned(),
                    date(bucket.created),
                ]);
                records.push(serde_json::json!({
                    "type": "bucket",
                    "name": bucket.name,
                    "layout": layout,
                    "created": rfc3339(bucket.created),
                }));
            }
            ui::rows(
                &table,
                &records,
                "No buckets yet. Make one: teifs bucket create NAME",
            );
        }
        BucketAction::Create { name, layout, dir } => {
            open(&dir)?
                .create_bucket(&name, layout.into())
                .await
                .map_err(|e| format!("can't create {name}: {e}"))?;
            ui::done(
                format!("Created {name}"),
                || serde_json::json!({"type": "bucket", "name": name, "created": true}),
            );
        }
        BucketAction::Remove { name, dir } => {
            open(&dir)?
                .delete_bucket(&name)
                .await
                .map_err(|e| format!("can't remove {name}: {e}"))?;
            ui::done(
                format!("Removed {name}"),
                || serde_json::json!({"type": "bucket", "name": name, "removed": true}),
            );
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("a SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    ui::note("Stopping…");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiries_parse_with_units_or_never() {
        let hours = |h: u64| Some(Duration::from_hours(h));
        assert_eq!(parse_expiry("7d").unwrap().0, hours(7 * 24));
        assert_eq!(parse_expiry("12h").unwrap().0, hours(12));
        assert_eq!(
            parse_expiry("30m").unwrap().0,
            Some(Duration::from_mins(30))
        );
        assert_eq!(parse_expiry("NEVER").unwrap().0, None);
        for bad in [
            "",
            "7",
            "d",
            "0d",
            "7w",
            "-1h",
            "1.5h",
            "99999999999999999999d",
        ] {
            assert!(parse_expiry(bad).is_err(), "{bad}");
        }
    }
}
