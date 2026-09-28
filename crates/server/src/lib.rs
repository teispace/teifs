//! The TeiFS server: opens a drive, loads or creates its credentials, and serves it over
//! S3 until told to stop. The `teifs` command is a thin layer over this crate, and
//! anything that embeds TeiFS (such as Teitunnel) starts it the same way.

pub mod credentials;
mod serve;

use std::{
    future::Future,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use std::sync::Arc;
use teifs_iam::{Iam, RootKey};
use teifs_s3::Options;

use teifs_store::{
    BucketEncryption, Layout, LocalKms, Store, StoreError, StoreOptions, TransitKms,
};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

pub use credentials::Credentials;
pub use serve::{DRAIN, Limits, serve};
pub use teifs_s3::{HEALTH_PATH, LAYOUT_HEADER};
pub use teifs_store::{Durability, JobOptions, KeyRules};

/// How to serve a drive.
#[derive(Debug, Clone)]
pub struct Config {
    /// The drive's folder (created if missing).
    pub dir: PathBuf,
    /// Where to listen.
    pub listen: SocketAddr,
    /// Domains for virtual-hosted-style requests (`bucket.domain`).
    pub domains: Vec<String>,
    /// Credentials to use; `None` loads the drive's own, generating them on first run.
    pub credentials: Option<Credentials>,
    /// The layout of buckets created without choosing one.
    pub default_layout: Layout,
    /// The KMS keyring; `None` for the default, `<config dir>/teifs/keys/<drive id>.json`,
    /// kept off the drive so a copy of the drive alone can't be decrypted. Unused with a
    /// transit engine.
    pub kms_keyring: Option<PathBuf>,
    /// A Vault or OpenBao transit engine to use as the KMS instead of a keyring. Its
    /// token comes from `VAULT_TOKEN` (or `BAO_TOKEN`).
    pub kms_transit: Option<Transit>,
    /// Allow SSE-C on buckets that don't set it themselves (AWS blocks it by default
    /// since April 2026).
    pub allow_sse_c: bool,
    /// Whether plain HTTP counts as secure for SSE-C keys; `None` decides by the listen
    /// address (secure only on loopback).
    pub plain_http_is_secure: Option<bool>,
    /// How the background jobs (upload expiry, cleanup) run.
    pub jobs: JobOptions,
    /// How hard writes are made to survive a power cut.
    pub durability: Durability,
    /// Which names folder buckets may create.
    pub key_rules: KeyRules,
    /// Bounds on what clients can make the server hold.
    pub limits: Limits,
    /// Accept Signature Version 2 (deprecated; off by default, as on AWS).
    pub allow_sig_v2: bool,
}

/// A Vault or OpenBao transit engine.
#[derive(Debug, Clone)]
pub struct Transit {
    /// Its address, such as `https://vault.example:8200`.
    pub address: String,
    /// Where the engine is mounted (usually `transit`).
    pub mount: String,
    /// A Vault Enterprise or OpenBao namespace.
    pub namespace: Option<String>,
}

/// Where a server's KMS keys are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsLocation {
    /// A keyring file; `created` when this start made it (a new key: back it up).
    Keyring {
        /// The file.
        path: PathBuf,
        /// Whether this start created it.
        created: bool,
    },
    /// A transit engine.
    Transit(String),
}

/// Why the server couldn't start.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The drive's folder couldn't be created.
    #[error("can't create {}: {source}", path.display())]
    CreateDir {
        /// The folder.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// The drive couldn't be opened.
    #[error("can't open the drive at {}: {source}", path.display())]
    Open {
        /// The folder.
        path: PathBuf,
        /// Why.
        source: StoreError,
    },
    /// The drive's credentials couldn't be read or created.
    #[error("can't read the credentials: {0}")]
    Credentials(io::Error),
    /// IAM couldn't be opened.
    #[error("can't open IAM: {0}")]
    Iam(teifs_iam::IamError),
    /// A domain for virtual-hosted-style requests is invalid.
    #[error("invalid domain: {0}")]
    Domain(String),
    /// The KMS keyring couldn't be opened or created.
    #[error("can't open the KMS keyring at {}: {source}", path.display())]
    Keyring {
        /// The keyring.
        path: PathBuf,
        /// Why.
        source: teifs_store::CryptoError,
    },
    /// A transit engine was asked for without a token.
    #[error("set VAULT_TOKEN (or BAO_TOKEN) to use the transit engine at {0}")]
    NoTransitToken(String),
    /// The transit engine client couldn't be set up.
    #[error("can't use the transit engine at {address}: {source}")]
    Transit {
        /// The engine.
        address: String,
        /// Why.
        source: teifs_store::CryptoError,
    },
    /// There's no default place for the keyring (no home folder).
    #[error("there's no config folder for the KMS keyring; give one with --kms-keyring")]
    NoKeyringHome,
    /// The address couldn't be listened on.
    #[error("can't listen on {address}: {source}")]
    Listen {
        /// The address.
        address: SocketAddr,
        /// Why.
        source: io::Error,
    },
}

/// A drive ready to serve: listening, but not yet accepting requests.
pub struct Server {
    store: Store,
    jobs: JobOptions,
    limits: Limits,
    service: teifs_s3::Service,
    listener: TcpListener,
    iam: Arc<Iam>,
    access_key: String,
    created_credentials: bool,
    kms: KmsLocation,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("root", &self.store.root())
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

/// The KMS: a transit engine when one is given, else the keyring (the drive's default one
/// unless `keyring` names another).
fn open_kms(
    transit: Option<Transit>,
    keyring: Option<PathBuf>,
    drive: &str,
) -> Result<(Arc<dyn teifs_store::Kms>, KmsLocation), ServerError> {
    if let Some(transit) = transit {
        let token = std::env::var("VAULT_TOKEN")
            .or_else(|_| std::env::var("BAO_TOKEN"))
            .map_err(|_| ServerError::NoTransitToken(transit.address.clone()))?;
        let kms = TransitKms::new(&transit.address, &transit.mount, token, transit.namespace)
            .map_err(|source| ServerError::Transit {
                address: transit.address.clone(),
                source,
            })?;
        return Ok((Arc::new(kms), KmsLocation::Transit(transit.address)));
    }
    let path = match keyring {
        Some(path) => path,
        None => default_keyring(drive)?,
    };
    let created = !path.exists();
    let kms = LocalKms::open(&path).map_err(|source| ServerError::Keyring {
        path: path.clone(),
        source,
    })?;
    Ok((Arc::new(kms), KmsLocation::Keyring { path, created }))
}

/// Where a drive's keyring goes by default: the user's config folder, not the drive.
pub fn default_keyring(drive: &str) -> Result<PathBuf, ServerError> {
    let dir = dirs::config_dir().ok_or(ServerError::NoKeyringHome)?;
    Ok(dir.join("teifs").join("keys").join(format!("{drive}.json")))
}

impl Server {
    /// Opens the drive and starts listening.
    pub async fn bind(config: Config) -> Result<Self, ServerError> {
        std::fs::create_dir_all(&config.dir).map_err(|source| ServerError::CreateDir {
            path: config.dir.clone(),
            source,
        })?;
        let default_encryption = config.allow_sse_c.then(|| BucketEncryption {
            block_customer_keys: false,
            ..BucketEncryption::aws_default()
        });
        let store = Store::open_with(
            &config.dir,
            StoreOptions {
                kms: None,
                default_encryption,
                durability: config.durability,
                key_rules: config.key_rules,
            },
        )
        .map_err(|source| ServerError::Open {
            path: config.dir.clone(),
            source,
        })?;
        let (kms, location) = open_kms(
            config.kms_transit,
            config.kms_keyring,
            &store.format().drive,
        )?;
        store
            .attach_kms(kms.clone())
            .map_err(|source| ServerError::Open {
                path: config.dir.clone(),
                source,
            })?;
        let (credentials, created_credentials) = match config.credentials {
            Some(credentials) => (credentials, false),
            None => credentials::load_or_create(store.root()).map_err(ServerError::Credentials)?,
        };
        let access_key = credentials.access_key.clone();
        let root = RootKey {
            access_key: credentials.access_key,
            secret: Zeroizing::new(credentials.secret_key),
        };
        let iam = Arc::new(
            Iam::open(
                &store.system_db(),
                &store.format().drive,
                kms.as_ref(),
                Some(root),
            )
            .await
            .map_err(ServerError::Iam)?,
        );
        let service = teifs_s3::service(
            store.clone(),
            Options {
                iam: Some(iam.clone()),
                domains: config.domains,
                default_layout: config.default_layout,
                plain_http_is_secure: config
                    .plain_http_is_secure
                    .unwrap_or_else(|| config.listen.ip().is_loopback()),
                body_timeout: Some(config.limits.body_timeout),
                allow_sig_v2: config.allow_sig_v2,
            },
        )
        .map_err(|e| ServerError::Domain(e.to_string()))?;
        let listener =
            TcpListener::bind(config.listen)
                .await
                .map_err(|source| ServerError::Listen {
                    address: config.listen,
                    source,
                })?;
        Ok(Self {
            store,
            jobs: config.jobs,
            limits: config.limits,
            service,
            listener,
            iam,
            access_key,
            created_credentials,
            kms: location,
        })
    }

    /// The address it listens on (useful with port 0).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The drive's folder.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.store.root()
    }

    /// The root user's access key.
    #[must_use]
    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    /// The drive's IAM: its users, access keys, groups and policies.
    #[must_use]
    pub fn iam(&self) -> &Arc<Iam> {
        &self.iam
    }

    /// Where the KMS keys the drive's encrypted objects need are.
    #[must_use]
    pub fn kms(&self) -> &KmsLocation {
        &self.kms
    }

    /// Whether this start generated the drive's credentials.
    #[must_use]
    pub fn created_credentials(&self) -> bool {
        self.created_credentials
    }

    /// Serves requests, and runs the background jobs, until `shutdown` resolves; then
    /// lets open requests finish for up to [`DRAIN`] and stops the jobs.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let jobs = self.store.start_jobs(&self.jobs);
        serve(self.listener, self.service, self.limits, shutdown).await;
        jobs.stop().await;
    }
}
