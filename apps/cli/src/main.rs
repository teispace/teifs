//! `teifs`: serve a folder as a drive over S3, and manage it from the terminal.

#![allow(clippy::print_stdout, reason = "a command line prints its results")]

use std::{net::SocketAddr, path::PathBuf, process::ExitCode, time::Duration};

mod client;
mod config;
mod units;

use clap::{Parser, Subcommand};
use teifs_server::{
    Config, Credentials, Durability, JobOptions, KeyRules, KmsLocation, Limits, Server, Transit,
    credentials,
};
use teifs_store::{Layout, Store};
use units::{date, from_ms, parse_count, parse_duration};

#[derive(Parser)]
#[command(name = "teifs", version, about = "Your folders as a drive and as S3")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
}

/// `teifs serve`'s settings. Each can also be set in a settings file (`--config`),
/// under the flag's name; flags and environment variables win over it.
#[derive(clap::Args)]
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
        #[arg(long, default_value = ".", env = "TEIFS_DIR")]
        dir: PathBuf,
    },
    /// Create a bucket.
    Create {
        name: String,
        /// How it stores objects: `object` (any key S3 allows) or `folder` (plain files).
        #[arg(long, value_enum, default_value = "object")]
        layout: LayoutArg,
        #[arg(long, default_value = ".", env = "TEIFS_DIR")]
        dir: PathBuf,
    },
    /// Remove an empty bucket.
    Remove {
        name: String,
        #[arg(long, default_value = ".", env = "TEIFS_DIR")]
        dir: PathBuf,
    },
}

/// A bucket layout on the command line.
#[derive(Clone, Copy, clap::ValueEnum)]
enum LayoutArg {
    /// Objects stored by id under `.teifs`, with every key S3 allows.
    Object,
    /// A folder of plain files.
    Folder,
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
            // error; server errors are still logged by s3s and by TeiFS.
            tracing_subscriber::EnvFilter::try_from_env("TEIFS_LOG")
                .unwrap_or_else(|_| "info,s3s::ops=off".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let (cli, sources) = match config::parse(std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("teifs: {message}");
            return ExitCode::FAILURE;
        }
    };
    // Commands run on a worker thread with a roomy stack: the AWS SDK's futures poll
    // deep, and Windows gives the main thread only 1 MiB.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(STACK_SIZE)
        .build()
        .expect("a Tokio runtime");
    let result = runtime.block_on(async move {
        match tokio::spawn(async move { run(cli.command, &sources).await }).await {
            Ok(result) => result,
            Err(err) => std::panic::resume_unwind(err.into_panic()),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("teifs: {err}");
            ExitCode::from(err.kind as u8)
        }
    }
}

/// The stack of the threads commands run on.
const STACK_SIZE: usize = 8 * 1024 * 1024;

fn open(dir: &PathBuf) -> Result<Store, String> {
    Store::open(dir).map_err(|e| match e {
        teifs_store::StoreError::DriveInUse => format!(
            "the drive at {} is open in another TeiFS process (a running `teifs serve`?); stop it, or use an S3 client against it",
            dir.display()
        ),
        e => format!("can't open the drive at {}: {e}", dir.display()),
    })
}

async fn run(command: Command, sources: &config::Sources) -> Result<(), client::Error> {
    match command {
        Command::Serve(args) => Ok(serve(args).await?),
        Command::Config {
            action: ConfigAction::Show(args),
        } => Ok(config::show(&args, sources)?),
        Command::Credentials { dir } => {
            let store = open(&dir)?;
            let (credentials, _) = credentials::load_or_create(store.root())
                .map_err(|e| format!("can't read the credentials: {e}"))?;
            println!("Access key: {}", credentials.access_key);
            println!(
                "Secret key: in {}",
                credentials::path(store.root()).display()
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
        eprintln!("Using MINIO_ROOT_USER and MINIO_ROOT_PASSWORD as the access and secret key.");
    }
    if server.created_credentials() {
        eprintln!(
            "Created credentials for this drive in {}",
            credentials::path(server.root()).display()
        );
    }
    match server.kms() {
        KmsLocation::Keyring {
            path,
            created: true,
        } => eprintln!(
            "Created the encryption keyring for this drive in {}\n  Back it up: encrypted objects can't be read without it.",
            path.display()
        ),
        KmsLocation::Keyring { path, .. } => {
            eprintln!("Encryption keys: {}", path.display());
        }
        KmsLocation::Transit(address) => eprintln!("Encryption keys: transit engine at {address}"),
    }
    match args.durability.into() {
        Durability::Strict => {}
        Durability::Relaxed => eprintln!(
            "Durability: relaxed. A power cut can lose the last moments' writes (never corrupt the drive)."
        ),
        Durability::None => {
            eprintln!("Durability: none. Nothing is synced to disk; use only for scratch data.");
        }
    }
    let address = server.local_addr().map_err(|e| e.to_string())?;
    eprintln!(
        "Serving {} over S3 at http://{address}",
        server.root().display()
    );
    let secret = keys.map_or_else(
        || "`teifs credentials`".to_owned(),
        |keys| keys.secret.describe(),
    );
    eprintln!("Access key: {}  (secret: {secret})", server.access_key());
    server.run(shutdown_signal()).await;
    eprintln!("Stopped.");
    Ok(())
}

async fn key(action: KeyAction) -> Result<(), String> {
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
            for key in kms.keys().await.map_err(|e| e.to_string())? {
                println!(
                    "{}  v{:<3}  {}",
                    date(from_ms(key.created_ms)),
                    key.version,
                    key.name
                );
            }
        }
        KeyAction::Create { name, .. } => {
            kms.create_key(&name).await.map_err(|e| e.to_string())?;
            println!("Created key {name} in {place}");
        }
        KeyAction::Rotate { name, .. } => {
            let info = kms.rotate_key(&name).await.map_err(|e| e.to_string())?;
            println!("Key {name} is now at version {}", info.version);
        }
    }
    Ok(())
}

async fn bucket(action: BucketAction) -> Result<(), String> {
    match action {
        BucketAction::List { dir } => {
            for bucket in open(&dir)?
                .list_buckets()
                .await
                .map_err(|e| e.to_string())?
            {
                let layout = match bucket.layout {
                    Layout::Object => "object",
                    Layout::Folder => "folder",
                };
                println!("{}  {layout:<6}  {}", date(bucket.created), bucket.name);
            }
        }
        BucketAction::Create { name, layout, dir } => {
            open(&dir)?
                .create_bucket(&name, layout.into())
                .await
                .map_err(|e| format!("can't create {name}: {e}"))?;
            println!("Created {name}");
        }
        BucketAction::Remove { name, dir } => {
            open(&dir)?
                .delete_bucket(&name)
                .await
                .map_err(|e| format!("can't remove {name}: {e}"))?;
            println!("Removed {name}");
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
    eprintln!("Stopping…");
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
