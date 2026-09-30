//! The TeiFS server: opens a drive, loads or creates its credentials, and serves it over
//! S3 until told to stop. The `teifs` command is a thin layer over this crate, and
//! anything that embeds TeiFS (such as Teitunnel) starts it the same way.

mod audit;
pub mod credentials;
mod serve;
mod signals;
pub mod tls;

use std::{
    future::Future,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use std::sync::Arc;
use teifs_iam::{Iam, RootKey};
use teifs_s3::Options;
use teifs_types::admin::{KmsConfig, NotifyTarget, ServerConfig};

use teifs_store::{
    BucketEncryption, Layout, LocalKms, Store, StoreError, StoreOptions, TransitKms,
};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

pub use audit::AuditTarget;
pub use credentials::Credentials;
pub use serve::{DRAIN, Limits, serve};
use teifs_notify::Notifier;
pub use teifs_notify::{
    Elasticsearch, Format, Nsq, Redis, TargetConfig, TargetKind, Webhook, tls_config,
};
pub use teifs_s3::{HEALTH_PATH, LAYOUT_HEADER, ProxyHeader, TrustedProxies};
pub use teifs_store::{Durability, JobOptions, KeyRules};
pub use tls::{Tls, TlsError, TlsSource};

/// How to serve a drive.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is an independent setting of the server"
)]
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
    /// address (secure only on loopback, and only with no proxies trusted: a proxy on
    /// this machine may be passing on plain HTTP from anywhere).
    pub plain_http_is_secure: Option<bool>,
    /// The reverse proxies trusted to say who their clients are (and whether they came
    /// over HTTPS); none by default.
    pub trusted_proxies: TrustedProxies,
    /// How the background jobs (upload expiry, cleanup) run.
    pub jobs: JobOptions,
    /// How hard writes are made to survive a power cut.
    pub durability: Durability,
    /// Which names folder buckets may create.
    pub key_rules: KeyRules,
    /// How long a day is for lifecycle rules; `None` is a real day. Only for testing
    /// rules without waiting days.
    pub lifecycle_day: Option<std::time::Duration>,
    /// Bounds on what clients can make the server hold.
    pub limits: Limits,
    /// Accept Signature Version 2 (deprecated; off by default, as on AWS).
    pub allow_sig_v2: bool,
    /// New buckets start with ACLs enabled and no Block Public Access, as S3's did before
    /// April 2023 (off by default: AWS's defaults now).
    pub legacy_bucket_defaults: bool,
    /// Serve metrics to anyone who can reach the server, without a bearer token.
    pub public_metrics: bool,
    /// Where to keep an audit log of every request: each target gets every entry.
    pub audit: Vec<AuditTarget>,
    /// Where bucket notifications may be sent: buckets' rules name them by ARN.
    pub notify: Vec<TargetConfig>,
    /// Serve HTTPS with these certificates; `None` serves plain HTTP.
    pub tls: Option<TlsSource>,
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
    /// The TLS certificates couldn't be loaded.
    #[error("can't load the TLS certificates: {0}")]
    Tls(TlsError),
    /// The KMS keyring couldn't be opened or created.
    #[error("can't open the KMS keyring at {}: {source}", path.display())]
    Keyring {
        /// The keyring.
        path: PathBuf,
        /// Why.
        source: teifs_store::CryptoError,
    },
    /// The audit log couldn't be opened.
    #[error("can't open the audit log {target}: {source}")]
    Audit {
        /// Where it goes.
        target: AuditTarget,
        /// Why.
        source: io::Error,
    },
    /// Bucket notifications couldn't start.
    #[error(transparent)]
    Notify(teifs_notify::OpenError),
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
    tls: Option<Arc<Tls>>,
    /// Write the audit log until the service is gone.
    audit_writers: Vec<audit::Writer>,
    /// Sends bucket notifications.
    notifier: Arc<Notifier>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("root", &self.store.root())
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

/// The audit log, if one is kept, and its writers.
type Audit = (Option<Arc<dyn teifs_s3::AuditSink>>, Vec<audit::Writer>);

/// Opens the audit log's targets and starts their writers; none without targets.
fn start_audit(targets: &[AuditTarget]) -> Result<Audit, ServerError> {
    if targets.is_empty() {
        return Ok((None, Vec::new()));
    }
    let (logs, writers) =
        audit::start(targets).map_err(|(target, source)| ServerError::Audit { target, source })?;
    Ok((Some(logs), writers))
}

/// Opens (or creates) the drive, with its KMS.
fn open_drive(
    config: &Config,
) -> Result<(Store, Arc<dyn teifs_store::Kms>, KmsLocation), ServerError> {
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
            lifecycle_day: config.lifecycle_day,
        },
    )
    .map_err(|source| ServerError::Open {
        path: config.dir.clone(),
        source,
    })?;
    let (kms, location) = open_kms(
        config.kms_transit.clone(),
        config.kms_keyring.clone(),
        &store.format().drive,
    )?;
    store
        .attach_kms(kms.clone())
        .map_err(|source| ServerError::Open {
            path: config.dir.clone(),
            source,
        })?;
    Ok((store, kms, location))
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

/// How the server was started, as the admin API reports it (no secrets).
fn admin_config(config: &Config, kms: &KmsLocation, listen: SocketAddr) -> ServerConfig {
    ServerConfig {
        listen: listen.to_string(),
        domains: config.domains.clone(),
        default_layout: match config.default_layout {
            Layout::Folder => "folder",
            Layout::Object => "object",
        }
        .into(),
        durability: match config.durability {
            Durability::Strict => "strict",
            Durability::Relaxed => "relaxed",
            Durability::None => "none",
        }
        .into(),
        key_names: match config.key_rules {
            KeyRules::Portable => "portable",
            KeyRules::Host => "host",
        }
        .into(),
        kms: match kms {
            KmsLocation::Keyring { path, .. } => KmsConfig::Keyring {
                path: path.display().to_string(),
            },
            KmsLocation::Transit(address) => KmsConfig::Transit {
                address: address.clone(),
            },
        },
        root_credentials: if config.credentials.is_some() {
            "given"
        } else {
            "drive"
        }
        .into(),
        allow_sse_c: config.allow_sse_c,
        plain_http_is_secure: config.plain_http_is_secure.unwrap_or_else(|| {
            config.listen.ip().is_loopback() && config.trusted_proxies.is_empty()
        }),
        allow_sig_v2: config.allow_sig_v2,
        legacy_bucket_defaults: config.legacy_bucket_defaults,
        public_metrics: config.public_metrics,
        audit_log: config
            .audit
            .iter()
            .find(|t| !matches!(t, AuditTarget::Webhook(_)))
            .map(ToString::to_string),
        audit_webhook: config
            .audit
            .iter()
            .find(|t| matches!(t, AuditTarget::Webhook(_)))
            .map(ToString::to_string),
        notify_targets: config
            .notify
            .iter()
            .map(|target| NotifyTarget {
                arn: target.arn().to_string(),
                endpoint: target.shown(),
            })
            .collect(),
        upload_expiry_seconds: config.jobs.upload_expiry.map(|d| d.as_secs()),
        scrub_every_seconds: config.jobs.scrub_every.map(|d| d.as_secs()),
        snapshots: config.jobs.snapshots,
        job_pace: config.jobs.pace,
        header_timeout_seconds: config.limits.header_timeout.as_secs(),
        body_timeout_seconds: config.limits.body_timeout.as_secs(),
        max_connections: config.limits.max_connections,
        tls: config.tls.as_ref().map(ToString::to_string),
        trusted_proxies: config.trusted_proxies.networks(),
        proxy_header: (!config.trusted_proxies.is_empty())
            .then(|| config.trusted_proxies.header().name().to_owned()),
    }
}

/// Listens on `address`: the listener, and the address it got (its port, for port 0).
async fn listen(address: SocketAddr) -> Result<(TcpListener, SocketAddr), ServerError> {
    let failed = |source| ServerError::Listen { address, source };
    let listener = TcpListener::bind(address).await.map_err(failed)?;
    let bound = listener.local_addr().map_err(failed)?;
    Ok((listener, bound))
}

impl Server {
    /// Opens the drive and starts listening.
    pub async fn bind(config: Config) -> Result<Self, ServerError> {
        // Certificates first: a mistake in them shouldn't wait for the drive to open.
        let tls = config
            .tls
            .clone()
            .map(Tls::load)
            .transpose()
            .map_err(ServerError::Tls)?
            .map(Arc::new);
        let (store, kms, location) = open_drive(&config)?;
        let (listener, listen) = listen(config.listen).await?;
        let admin_config = admin_config(&config, &location, listen);
        let root_keys: Option<Arc<dyn teifs_s3::RootKeyStore>> =
            config.credentials.is_none().then(|| {
                Arc::new(credentials::DriveKeys {
                    drive: store.root().to_owned(),
                }) as _
            });
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
        let (audit, audit_writers) = start_audit(&config.audit)?;
        let notifier = Arc::new(
            Notifier::start(&store.events_db(), config.notify).map_err(ServerError::Notify)?,
        );
        let service = teifs_s3::service(
            store.clone(),
            Options {
                iam: Some(iam.clone()),
                domains: config.domains,
                default_layout: config.default_layout,
                plain_http_is_secure: admin_config.plain_http_is_secure,
                trusted_proxies: config.trusted_proxies,
                body_timeout: Some(config.limits.body_timeout),
                allow_sig_v2: config.allow_sig_v2,
                legacy_bucket_defaults: config.legacy_bucket_defaults,
                public_metrics: config.public_metrics,
                audit,
                notifier: Some(Arc::clone(&notifier)),
                config: Some(admin_config),
                root_keys,
            },
        )
        .map_err(|e| ServerError::Domain(e.to_string()))?;
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
            tls,
            audit_writers,
            notifier,
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

    /// The root user's access key as the server started (the admin API may replace a
    /// generated one while it runs).
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

    /// The listener's TLS, if it serves HTTPS.
    #[must_use]
    pub const fn tls(&self) -> Option<&Arc<Tls>> {
        self.tls.as_ref()
    }

    /// `https` or `http`: how clients reach it.
    #[must_use]
    pub const fn scheme(&self) -> &'static str {
        if self.tls.is_some() { "https" } else { "http" }
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
        let reloads = self.tls.clone().map(|tls| tokio::spawn(tls::watch(tls)));
        // Live traces last until the server stops: they end when it starts to.
        let stopping = self.service.stopping();
        let shutdown = async move {
            shutdown.await;
            stopping.cancel();
        };
        serve(self.listener, self.service, self.limits, self.tls, shutdown).await;
        if let Some(reloads) = reloads {
            reloads.abort();
        }
        jobs.stop().await;
        // What's still queued is sent after the next start.
        self.notifier.stop().await;
        // The service is gone with its connections, so the writers are finishing what's
        // queued.
        let deadline = tokio::time::Instant::now() + DRAIN;
        for writer in self.audit_writers {
            if tokio::time::timeout_at(deadline, writer).await.is_err() {
                tracing::warn!("the audit log's last entries weren't all written");
            }
        }
    }
}
