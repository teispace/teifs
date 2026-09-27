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
use teifs_s3::Options;

use teifs_store::{BucketEncryption, Layout, LocalKms, Store, StoreError, StoreOptions};
use tokio::net::TcpListener;

pub use credentials::Credentials;
pub use serve::{DRAIN, serve};

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
    /// kept off the drive so a copy of the drive alone can't be decrypted.
    pub kms_keyring: Option<PathBuf>,
    /// Allow SSE-C on buckets that don't set it themselves (AWS blocks it by default
    /// since April 2026).
    pub allow_sse_c: bool,
    /// Whether plain HTTP counts as secure for SSE-C keys; `None` decides by the listen
    /// address (secure only on loopback).
    pub plain_http_is_secure: Option<bool>,
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
    service: s3s::service::S3Service,
    listener: TcpListener,
    access_key: String,
    created_credentials: bool,
    keyring: PathBuf,
    created_keyring: bool,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("root", &self.store.root())
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
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
            },
        )
        .map_err(|source| ServerError::Open {
            path: config.dir.clone(),
            source,
        })?;
        let keyring = match config.kms_keyring {
            Some(path) => path,
            None => default_keyring(&store.format().drive)?,
        };
        let created_keyring = !keyring.exists();
        let kms = LocalKms::open(&keyring).map_err(|source| ServerError::Keyring {
            path: keyring.clone(),
            source,
        })?;
        store
            .attach_kms(Arc::new(kms))
            .map_err(|source| ServerError::Open {
                path: config.dir.clone(),
                source,
            })?;
        let (credentials, created_credentials) = match config.credentials {
            Some(credentials) => (credentials, false),
            None => credentials::load_or_create(store.root()).map_err(ServerError::Credentials)?,
        };
        let access_key = credentials.access_key.clone();
        let service = teifs_s3::service(
            store.clone(),
            Options {
                credentials: Some((credentials.access_key, credentials.secret_key)),
                domains: config.domains,
                default_layout: config.default_layout,
                plain_http_is_secure: config
                    .plain_http_is_secure
                    .unwrap_or_else(|| config.listen.ip().is_loopback()),
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
            service,
            listener,
            access_key,
            created_credentials,
            keyring,
            created_keyring,
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

    /// The access key requests must be signed with.
    #[must_use]
    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    /// The KMS keyring the drive's encrypted objects need.
    #[must_use]
    pub fn keyring(&self) -> &Path {
        &self.keyring
    }

    /// Whether this start created the keyring (a new key: back it up).
    #[must_use]
    pub fn created_keyring(&self) -> bool {
        self.created_keyring
    }

    /// Whether this start generated the drive's credentials.
    #[must_use]
    pub fn created_credentials(&self) -> bool {
        self.created_credentials
    }

    /// Serves requests until `shutdown` resolves, then lets open requests finish for up to
    /// [`DRAIN`].
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        serve(self.listener, self.service, shutdown).await;
    }
}
