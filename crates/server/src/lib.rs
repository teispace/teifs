//! The TeiFS server: opens a drive, loads or creates its credentials, and serves it over
//! S3 until told to stop. The `teifs` command is a thin layer over this crate, and
//! anything that embeds TeiFS (such as Teitunnel) starts it the same way.

mod audit;
pub mod credentials;
mod kms;
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
use teifs_iam::{CertificateDer, Ensured, Iam, RootKey, certificate::CertificateSignIn};
use teifs_s3::Options;
use teifs_types::admin::{
    CertificateConfig, IdentityPluginConfig, KmsConfig, LdapConfig, NotifyTarget, OpenIdConfig,
    ServerConfig,
};

use teifs_store::{BucketEncryption, Layout, Store, StoreError, StoreOptions};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

pub use audit::AuditTarget;
pub use credentials::Credentials;
pub use kms::{
    AwsKmsConfig, ExternalKms, Kes, KmsLocation, Transit, default_keyring, open_external, open_kms,
    with_default_key,
};
pub use serve::{DRAIN, Limits, serve};
pub use teifs_iam::{
    ConfiguredOidcProvider, Directory, LdapSettings, SrvRecord, Transport,
    plugin::{IdentityPlugin, PluginSettings},
};
use teifs_notify::Notifier;
pub use teifs_notify::{
    Acks, Amqp, AwsCredentials, Compression, Elasticsearch, EventBridge, Exchange, Format, Kafka,
    KafkaSasl, Lambda, Mqtt, Mysql, Nats, Nsq, Postgres, Redis, SaslMechanism, ServerKey, Sns, Sqs,
    TargetConfig, TargetKind, UserKey, Webhook, tls_config,
};
pub use teifs_s3::{
    ConsoleLayer, Control, HEALTH_PATH, LAYOUT_HEADER, ProxyHeader, Stop, TrustedProxies,
    replication_from_xml, replication_to_xml,
};
pub use teifs_store::{Durability, JobOptions, KeyRules};
pub use tls::{Tls, TlsError, TlsSource, read_authorities};

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
    /// Domains for buckets' static websites (`bucket.domain`).
    pub website_domains: Vec<String>,
    /// Credentials to use; `None` loads the drive's own, generating them on first run.
    pub credentials: Option<Credentials>,
    /// The layout of buckets created without choosing one.
    pub default_layout: Layout,
    /// The KMS keyring; `None` for the default, `<config dir>/teifs/keys/<drive id>.json`,
    /// kept off the drive so a copy of the drive alone can't be decrypted. Unused with an
    /// external KMS.
    pub kms_keyring: Option<PathBuf>,
    /// A KMS to use instead of a keyring: a transit engine, KES or AWS KMS.
    pub kms_external: Option<ExternalKms>,
    /// The key to use where TeiFS would use its default key, `teifs-default` (SSE-S3,
    /// SSE-KMS without a key, the drive's own secrets); `None` keeps that name.
    pub kms_default_key: Option<String>,
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
    /// The largest object (as stored) an object bucket keeps in the index; `None` is
    /// the store's default. For measuring.
    pub inline_max: Option<u64>,
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
    /// How often each logging bucket's access log records are delivered as a log
    /// object; `None` is every five minutes.
    pub access_log_interval: Option<std::time::Duration>,
    /// Serve HTTPS with these certificates; `None` serves plain HTTP.
    pub tls: Option<TlsSource>,
    /// The LDAP directory users sign in with (`AssumeRoleWithLDAPIdentity`); none by
    /// default.
    pub ldap: Option<LdapSettings>,
    /// Sign in clients with certificates (`AssumeRoleWithCertificate`); needs `tls`.
    /// None by default.
    pub client_certificates: Option<ClientCertificates>,
    /// The identity plugin custom tokens are checked with (`AssumeRoleWithCustomToken`);
    /// none by default.
    pub identity_plugin: Option<PluginSettings>,
    /// OpenID Connect providers to make, or bring in line with these settings, when it
    /// starts (MinIO's `identity_openid`); none by default.
    pub openid: Vec<ConfiguredOidcProvider>,
    /// How a change `mc admin config` makes to the drive's `.teifs/config.kv` is checked
    /// before it's kept.
    pub config_check: ConfigCheck,
    /// Whether the root key, the service accounts it made and the sessions it started
    /// sign in (MinIO's `root_access`); off, only IAM's users and roles do.
    pub root_access: bool,
}

/// Checks a change to the drive's key-value configuration as the next start would read
/// it, so a change it would refuse is refused now. The default takes any change the
/// configuration's own rules allow.
#[derive(Clone)]
pub struct ConfigCheck(pub Arc<teifs_s3::CheckConfig>);

impl Default for ConfigCheck {
    fn default() -> Self {
        Self(Arc::new(|_| Ok(())))
    }
}

impl std::fmt::Debug for ConfigCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfigCheck")
    }
}

/// How clients sign in with certificates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientCertificates {
    /// The CA certificates (PEM: a file, or a folder of files) that must have issued
    /// them; by default the certificates folder's `CAs`, as MinIO has it.
    pub authorities: Option<PathBuf>,
    /// Take any certificate, whoever issued it: for testing only.
    pub skip_verify: bool,
}

/// How often the directory is asked about LDAP users with live sessions, whose sessions
/// end when it no longer has them (as MinIO's do).
const LDAP_CHECK_EVERY: std::time::Duration = std::time::Duration::from_mins(10);

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
    /// A domain for virtual-hosted-style requests or websites is invalid.
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
    /// The LDAP settings are wrong.
    #[error("the LDAP settings are wrong: {0}")]
    Ldap(String),
    /// Client certificates can't sign in as asked.
    #[error("client certificates can't sign in: {0}")]
    ClientCertificates(String),
    /// The OpenID Connect providers' settings are wrong.
    #[error("the OpenID Connect providers' settings are wrong: {0}")]
    OpenId(teifs_iam::IamError),
    /// The identity plugin's settings are wrong.
    #[error("the identity plugin's settings are wrong: {0}")]
    IdentityPlugin(String),
    /// The audit log couldn't be opened.
    #[error("can't open the audit log {target}: {source}")]
    Audit {
        /// Where it goes, as shown.
        target: String,
        /// Why.
        source: io::Error,
    },
    /// Bucket notifications couldn't start.
    #[error(transparent)]
    Notify(teifs_notify::OpenError),
    /// A transit engine was asked for without a token.
    #[error("set VAULT_TOKEN (or BAO_TOKEN) to use the transit engine at {0}")]
    NoTransitToken(String),
    /// KES was asked for without a way to sign in.
    #[error(
        "set TEIFS_KMS_KES_API_KEY, or give --kms-kes-cert and --kms-kes-key, to use KES at {0}"
    )]
    NoKesIdentity(String),
    /// An external KMS couldn't be set up.
    #[error("can't use {kms}: {source}")]
    Kms {
        /// Which, in words.
        kms: String,
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
async fn open_drive(
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
            inline_max: config.inline_max,
        },
    )
    .map_err(|source| ServerError::Open {
        path: config.dir.clone(),
        source,
    })?;
    let (kms, location) = open_kms(
        config.kms_external.as_ref(),
        config.kms_keyring.clone(),
        &store.format().drive,
        config.kms_default_key.clone(),
    )
    .await?;
    store
        .attach_kms(kms.clone())
        .map_err(|source| ServerError::Open {
            path: config.dir.clone(),
            source,
        })?;
    Ok((store, kms, location))
}

/// How the server was started, as the admin API reports it (no secrets).
fn admin_config(config: &Config, kms: &KmsLocation, listen: SocketAddr) -> ServerConfig {
    ServerConfig {
        listen: listen.to_string(),
        domains: config.domains.clone(),
        website_domains: config.website_domains.clone(),
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
            KmsLocation::Kes {
                endpoints,
                identity,
            } => KmsConfig::Kes {
                endpoints: endpoints.clone(),
                identity: identity.clone(),
            },
            KmsLocation::AwsKms(region) => KmsConfig::AwsKms {
                region: region.clone(),
            },
        },
        kms_default_key: config.kms_default_key.clone(),
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
        ldap: config.ldap.as_ref().map(|ldap| LdapConfig {
            server: ldap.server.clone(),
            transport: ldap.transport.as_str().to_owned(),
            lookup_dn: ldap.lookup_dn.clone(),
            user_bases: ldap.user_bases.clone(),
            user_filter: ldap.user_filter.clone(),
            group_bases: ldap.group_bases.clone(),
            group_filter: ldap.group_filter.clone(),
        }),
        certificates: None,
        identity_plugin: None,
        openid: Vec::new(),
    }
}

/// How users sign in besides with keys: an LDAP directory, client certificates, an
/// identity plugin.
struct SignIns {
    directory: Option<Directory>,
    certificates: Option<CertificateSignIn>,
    /// How the admin API shows the certificates' sign-in.
    shown_certificates: Option<CertificateConfig>,
    plugin: Option<IdentityPlugin>,
    openid: Vec<ConfiguredOidcProvider>,
    root_access: bool,
}

impl SignIns {
    /// The sign-ins `config` asks for, checked before the drive is opened.
    fn new(config: &Config) -> Result<Self, ServerError> {
        let (certificates, shown_certificates) = client_certificates(config)?.unzip();
        let directory = config
            .ldap
            .clone()
            .map(Directory::new)
            .transpose()
            .map_err(ServerError::Ldap)?;
        // MinIO's role ARNs name the server's region, which is none by default.
        let plugin = config
            .identity_plugin
            .clone()
            .map(|settings| IdentityPlugin::new(settings, ""))
            .transpose()
            .map_err(ServerError::IdentityPlugin)?;
        Ok(Self {
            directory,
            certificates,
            shown_certificates,
            plugin,
            openid: config.openid.clone(),
            root_access: config.root_access,
        })
    }

    /// Shows them in the admin API's configuration (never a secret).
    fn show(&self, admin: &mut ServerConfig) {
        admin.certificates.clone_from(&self.shown_certificates);
        admin.identity_plugin = self.plugin.as_ref().map(|plugin| IdentityPluginConfig {
            url: plugin.shown_url(),
            role_arn: plugin.role_arn().to_owned(),
            role_policies: plugin.role_policies().to_vec(),
        });
        admin.openid = self
            .openid
            .iter()
            .map(|p| {
                let roles = !p.role_policies.is_empty();
                OpenIdConfig {
                    url: p.url.clone(),
                    client_id: p.client_id.clone(),
                    role_arn: roles.then(|| teifs_iam::openid_role_arn(&p.client_id)),
                    role_policies: p.role_policies.clone(),
                    policy_claim: (!roles)
                        .then(|| p.claim_name.clone().unwrap_or_else(|| "policy".to_owned())),
                    claim_userinfo: p.claim_userinfo,
                }
            })
            .collect();
    }
}

/// Opens the drive's IAM, signing users in as `sign_ins` says.
async fn open_iam(
    store: &Store,
    kms: &dyn teifs_store::Kms,
    root: RootKey,
    sign_ins: SignIns,
) -> Result<Iam, ServerError> {
    let mut iam = Iam::open(&store.system_db(), &store.format().drive, kms, Some(root))
        .await
        .map_err(ServerError::Iam)?;
    let SignIns {
        directory,
        certificates,
        plugin,
        openid,
        root_access,
        ..
    } = sign_ins;
    if !root_access {
        iam = iam.without_root_access();
    }
    for (arn, done) in iam
        .ensure_oidc_providers(&openid)
        .map_err(ServerError::OpenId)?
    {
        match done {
            Ensured::Created => tracing::info!(%arn, "made the OpenID Connect provider"),
            Ensured::Updated => tracing::info!(%arn, "updated the OpenID Connect provider"),
            Ensured::Unchanged => {}
        }
    }
    if let Some(certificates) = certificates {
        iam = iam.with_certificates(certificates);
    }
    if let Some(plugin) = plugin {
        // A plugin that's down now may be up when someone signs in.
        if let Err(err) = plugin.check().await {
            tracing::warn!(error = %err, "the identity plugin can't be asked yet");
        }
        iam = iam.with_plugin(plugin);
    }
    let Some(directory) = directory else {
        return Ok(iam);
    };
    // A directory that's down now may be up when someone signs in.
    if let Err(err) = directory.check().await {
        tracing::warn!(error = %err, "the LDAP directory can't be used yet");
    }
    Ok(iam.with_ldap(directory))
}

/// How client certificates sign in, if they do, and how the admin API shows it.
fn client_certificates(
    config: &Config,
) -> Result<Option<(CertificateSignIn, CertificateConfig)>, ServerError> {
    config
        .client_certificates
        .as_ref()
        .map(|asked| {
            asked
                .sign_in(config.tls.as_ref())
                .map(|(sign_in, shown, _)| (sign_in, shown))
        })
        .transpose()
        .map_err(ServerError::ClientCertificates)
}

impl ClientCertificates {
    /// How clients sign in with certificates when the server's own come from `tls`:
    /// whom they're trusted from, how the admin API shows it, and the authorities'
    /// certificates.
    ///
    /// # Errors
    /// Why they can't: no HTTPS, no authority (unless verification is off), or
    /// authorities that can't be read.
    pub fn sign_in(
        &self,
        tls: Option<&TlsSource>,
    ) -> Result<
        (
            CertificateSignIn,
            CertificateConfig,
            Vec<CertificateDer<'static>>,
        ),
        String,
    > {
        let Some(source) = tls else {
            return Err("they come over HTTPS: give the server certificates too".into());
        };
        let path = self.authorities.clone().or_else(|| source.authorities());
        let roots = match &path {
            Some(path) if self.authorities.is_some() || path.exists() => {
                read_authorities(path).map_err(|e| e.to_string())?
            }
            _ => Vec::new(),
        };
        if roots.is_empty() && !self.skip_verify {
            return Err(match &path {
                Some(path) => format!(
                    "no authority issues them: put CA certificates in {}, or name them",
                    path.display()
                ),
                None => "no authority issues them: name the CA certificates".into(),
            });
        }
        let sign_in = CertificateSignIn::new(&roots, self.skip_verify)?;
        let shown = CertificateConfig {
            authorities: path.map(|p| p.display().to_string()).unwrap_or_default(),
            count: roots.len(),
            skip_verify: self.skip_verify,
        };
        Ok((sign_in, shown, roots))
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
            .map(|source| Tls::load_with(source, config.client_certificates.is_some()))
            .transpose()
            .map_err(ServerError::Tls)?
            .map(Arc::new);
        let sign_ins = SignIns::new(&config)?;
        let (store, kms, location) = open_drive(&config).await?;
        let (listener, listen) = listen(config.listen).await?;
        let mut admin_config = admin_config(&config, &location, listen);
        sign_ins.show(&mut admin_config);
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
        let iam = Arc::new(open_iam(&store, kms.as_ref(), root, sign_ins).await?);
        let (audit, audit_writers) = start_audit(&config.audit)?;
        let notifier = Arc::new(
            Notifier::start(&store.events_db(), config.notify).map_err(ServerError::Notify)?,
        );
        let access_logging =
            store
                .any_bucket_logging()
                .await
                .map_err(|source| ServerError::Open {
                    path: config.dir.clone(),
                    source,
                })?;
        let request_metrics = store
            .any_bucket_counting_requests()
            .await
            .map_err(|source| ServerError::Open {
                path: config.dir.clone(),
                source,
            })?;
        check_website_domains(&config.domains, &config.website_domains)?;
        let service = teifs_s3::service(
            store.clone(),
            Options {
                iam: Some(iam.clone()),
                domains: config.domains,
                website_domains: config.website_domains,
                default_layout: config.default_layout,
                plain_http_is_secure: admin_config.plain_http_is_secure,
                trusted_proxies: config.trusted_proxies,
                body_timeout: Some(config.limits.body_timeout),
                allow_sig_v2: config.allow_sig_v2,
                legacy_bucket_defaults: config.legacy_bucket_defaults,
                public_metrics: config.public_metrics,
                audit,
                notifier: Some(Arc::clone(&notifier)),
                access_logging,
                request_metrics,
                access_log_interval: config.access_log_interval,
                config: Some(admin_config),
                config_settings: Some(teifs_s3::ConfigSettings {
                    files: teifs_store::ConfigFiles::new(&config.dir),
                    check: config.config_check.0,
                }),
                root_keys,
                certificates: tls
                    .clone()
                    .map(|tls| tls as Arc<dyn teifs_s3::ServingCertificates>),
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

    /// What the admin API asks of the server (`MinIO`'s service calls): to stop or
    /// restart, and to hold S3's requests.
    #[must_use]
    pub fn control(&self) -> Arc<teifs_s3::Control> {
        self.service.control()
    }

    /// Serves requests, and runs the background jobs, until `shutdown` resolves or the
    /// admin API asks it to stop or restart; then lets open requests finish for up to
    /// [`DRAIN`] and stops the jobs. Returns what the admin API asked, if that's why it
    /// stopped: a restart is for whoever started it to do.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Option<teifs_s3::Stop> {
        // `SIGHUP` reloads what can be reloaded (the TLS certificates, the audit log), and
        // otherwise does nothing: it never stops the server, as it would by default.
        let _hangups = signals::Hangups::new();
        let jobs = self.store.start_jobs(&self.jobs);
        let reloads = self.tls.clone().map(|tls| tokio::spawn(tls::watch(tls)));
        let ldap_checks = self.iam.ldap().is_some().then(|| {
            let iam = Arc::clone(&self.iam);
            tokio::spawn(async move {
                let mut every = tokio::time::interval(LDAP_CHECK_EVERY);
                every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                every.tick().await;
                loop {
                    every.tick().await;
                    if let Err(err) = iam.check_ldap_users().await {
                        tracing::warn!(error = %err, "can't check the LDAP users");
                    }
                }
            })
        });
        let (workers_stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let workers = self.service.workers().map(|workers| {
            tokio::spawn(workers.run(async move {
                let _ = stopped.await;
            }))
        });
        // Live traces last until the server stops: they end when it starts to, and
        // frozen requests are let go.
        let stopping = self.service.stopping();
        let control = self.service.control();
        let asked = std::sync::OnceLock::new();
        let shutdown = async {
            tokio::select! {
                () = shutdown => {}
                stop = control.asked() => {
                    let _ = asked.set(stop);
                }
            }
            stopping.cancel();
            control.thaw();
        };
        serve(self.listener, self.service, self.limits, self.tls, shutdown).await;
        if let Some(reloads) = reloads {
            reloads.abort();
        }
        if let Some(checks) = ldap_checks {
            checks.abort();
        }
        jobs.stop().await;
        // The connections are gone: what's spooled is delivered after the next start, and
        // a report being made is made again.
        drop(workers_stop);
        if let Some(workers) = workers {
            let _ = workers.await;
        }
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
        asked.into_inner()
    }
}

/// Refuses a domain that's both for S3 requests and for websites: its hosts couldn't
/// tell which a request is for.
fn check_website_domains(
    domains: &[String],
    website_domains: &[String],
) -> Result<(), ServerError> {
    let name = |domain: &String| domain.trim_matches('.').to_ascii_lowercase();
    for website in website_domains {
        if domains.iter().any(|domain| name(domain) == name(website)) {
            return Err(ServerError::Domain(format!(
                "{website} is both a --domain and a --website-domain: give websites a domain \
                 of their own"
            )));
        }
    }
    Ok(())
}
