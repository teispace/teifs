//! The S3 API over a TeiFS store: any S3 client, SDK or tool (the AWS CLI, rclone,
//! restic, boto3, …) reads and writes the drive's folders as buckets.

mod access;
mod access_log;
mod acl;
mod admin;
mod analytics;
mod audit;
mod bucket_access;
mod bucket_export;
mod caps;
mod checksums;
mod configs;
mod console_log;
mod control;
mod cors;
mod crc_combine;
mod delivery;
mod drive;
mod encode;
mod errors;
mod events;
mod health;
mod iam_api;
mod inventory;
mod lifecycle;
mod limits;
mod lines;
mod listen;
mod logging;
mod metrics;
mod minio_bucket_metadata;
mod minio_config;
mod minio_heal;
mod minio_health;
mod minio_iam;
mod minio_iam_transfer;
mod minio_idp_config;
mod minio_info;
mod minio_inspect;
mod minio_kms;
mod minio_ldap;
mod minio_metrics;
mod minio_pools;
mod minio_profile;
mod minio_service;
mod minio_service_accounts;
mod minio_speedtest;
mod minio_trace;
mod notification;
mod object_lock;
mod observe;
#[cfg(test)]
mod operations_doc;
mod post_form;
mod proxy;
mod quota;
mod replication;
mod replication_targets;
mod replicator;
mod request_metrics;
mod routes;
mod sig_v2;
mod sse;
mod tagging;
mod trace;
mod website;
mod workers;

use std::sync::Arc;

use s3s::{
    config::{S3Config, StaticConfigProvider},
    host::MultiDomain,
    service::S3ServiceBuilder,
};
use teifs_iam::Iam;
use teifs_store::{Layout, Store};

pub use access::{Client, ClientCertificates};
pub use access_log::{DEFAULT_INTERVAL as DEFAULT_ACCESS_LOG_INTERVAL, Worker as AccessLogWorker};
pub use admin::RootKeyStore;
pub use audit::{AuditSink, REDACTED};
pub use console_log::ConsoleLayer;
pub use cors::Service;
pub use drive::{Drive, LAYOUT_HEADER};
pub use health::HEALTH_PATH;
pub use limits::{MAX_HEADER_BYTES, MAX_USER_METADATA_BYTES};
pub use minio_config::{CheckConfig, ConfigSettings};
pub use minio_health::ServingCertificates;
pub use minio_service::{Control, Stop};
pub use proxy::{ProxyHeader, TrustedProxies};
pub use routes::{Api, EndpointInfo, endpoints};
pub use workers::Workers;

/// How the S3 endpoint accepts requests.
#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is an independent setting of the server"
)]
pub struct Options {
    /// Who may sign requests and what each may do. `None` accepts unsigned requests
    /// and decides nothing: only for a drive nobody else can reach.
    pub iam: Option<Arc<Iam>>,
    /// Domains for virtual-hosted-style requests (`bucket.domain/key`), besides the
    /// path style (`domain/bucket/key`) that always works.
    pub domains: Vec<String>,
    /// Domains for buckets' static websites (`bucket.domain/key`), as S3's website
    /// endpoint.
    pub website_domains: Vec<String>,
    /// The layout of buckets created without choosing one.
    pub default_layout: Layout,
    /// Whether plain HTTP counts as a secure connection for SSE-C keys: true for a server
    /// that only listens on this machine, or behind a proxy that terminates TLS.
    pub plain_http_is_secure: bool,
    /// The reverse proxies trusted to say who their clients are; none by default.
    pub trusted_proxies: TrustedProxies,
    /// How long a request body may stop arriving before the request fails with
    /// `RequestTimeout`; `None` waits for ever.
    pub body_timeout: Option<std::time::Duration>,
    /// Accept Signature Version 2 (HMAC-SHA1, deprecated by AWS and refused for its
    /// newer buckets), for old clients and boto3's default presigned links.
    pub allow_sig_v2: bool,
    /// New buckets start as S3's did before April 2023: ACLs enabled and no Block Public
    /// Access, for applications that upload with public ACLs. Off, they start as AWS's do
    /// now.
    pub legacy_bucket_defaults: bool,
    /// How the server was started, as the admin API reports it; `None` when whoever
    /// embeds the service doesn't say.
    pub config: Option<teifs_types::admin::ServerConfig>,
    /// Where `mc admin config` keeps what it sets and how a change is checked; `None`
    /// answers that the server's settings aren't kept on its drive.
    pub config_settings: Option<ConfigSettings>,
    /// Where the root key is kept, if the admin API may replace it (a key the drive
    /// generated); `None` answers that it's managed elsewhere.
    pub root_keys: Option<Arc<dyn RootKeyStore>>,
    /// The certificates the server presents, which `mc support diag` describes; none
    /// when it serves plain HTTP.
    pub certificates: Option<Arc<dyn ServingCertificates>>,
    /// Serve metrics to anyone who can reach the server, not only to bearer tokens of
    /// keys that may `teifs:GetMetrics`: for a network only Prometheus shares.
    pub public_metrics: bool,
    /// Where audit entries go, one per request; none keeps no audit log.
    pub audit: Option<Arc<dyn AuditSink>>,
    /// The targets bucket notifications are sent to; none has no targets.
    pub notifier: Option<Arc<teifs_notify::Notifier>>,
    /// Whether some bucket logs its requests as the server starts (see
    /// [`Store::any_bucket_logging`]): requests are watched from the first.
    pub access_logging: bool,
    /// Whether some bucket's requests are counted as the server starts (see
    /// [`Store::any_bucket_counting_requests`]): requests are watched from the first.
    pub request_metrics: bool,
    /// How often each bucket's access log records are delivered as a log object; `None`
    /// is every five minutes.
    pub access_log_interval: Option<std::time::Duration>,
}

/// How s3s reads requests.
fn s3_config(allow_sig_v2: bool) -> S3Config {
    let mut config = S3Config::default();
    config.enable_sig_v2 = allow_sig_v2;
    config.sig_v4_allowed_services = ["s3", "iam", "sts"].map(str::to_owned).into();
    // Each route reads at most its own limit, after deciding the caller may call it.
    config.custom_route_max_body_size = Some(admin::MAX_IMPORT_BYTES as u64);
    // Forms are parsed with the limits TeiFS reads their fields with.
    config.form_max_field_size = post_form::MAX_FIELDS_BYTES;
    config.form_max_fields_size = post_form::MAX_FIELDS_BYTES;
    config.form_max_parts = post_form::MAX_PARTS;
    config
}

/// Builds the S3 service for a store, with CORS in front of it.
pub fn service(store: Store, options: Options) -> Result<Service, s3s::host::DomainError> {
    let notifier = options
        .notifier
        .unwrap_or_else(|| Arc::new(teifs_notify::Notifier::none()));
    let metrics = metrics::Metrics::new(&store, Arc::clone(&notifier));
    let (access_log, records) =
        access_log::AccessLog::new(options.access_logging, metrics.access_log());
    let (request_metrics, answered) =
        request_metrics::RequestMetrics::new(options.request_metrics, metrics.request_series());
    let drive = Drive::new(
        store.clone(),
        options.default_layout,
        options.legacy_bucket_defaults,
        Arc::clone(&notifier),
        options.iam.as_ref().map(|iam| iam.account()).as_deref(),
    )
    .with_access_log(Arc::clone(&access_log))
    .with_request_metrics(Arc::clone(&request_metrics));
    let interval = options
        .access_log_interval
        .unwrap_or(access_log::DEFAULT_INTERVAL);
    let workers = Workers::new(
        (&drive, &store),
        (records, Arc::clone(&access_log), interval),
        (answered, Arc::clone(&request_metrics)),
    );
    let inventory = Arc::new(inventory::Worker::new(drive.clone(), store.clone()));
    let events = drive.events();
    // A store serves one service: a second is told nothing new.
    let expirations: Arc<dyn teifs_store::Expirations> = Arc::new(access_log::Expired {
        events: events.clone(),
        log: Arc::clone(&access_log),
    });
    let _ = store.tell_expirations(&expirations);
    let rules = drive.rules();
    let scrapers = match &options.iam {
        Some(iam) if !options.public_metrics => metrics::Scrapers::Allowed(Arc::clone(iam)),
        _ => metrics::Scrapers::Anyone,
    };
    let tracers = Arc::new(trace::Tracers::new());
    let watch = observe::Watch::new(
        metrics,
        scrapers,
        options.audit,
        Arc::clone(&tracers),
        store.format().drive.clone(),
        (Arc::clone(&access_log), Arc::clone(&request_metrics)),
    );
    let control = Arc::new(Control::default());
    let mut builder = S3ServiceBuilder::new(drive);
    builder.set_config(Arc::new(StaticConfigProvider::new(Arc::new(s3_config(
        options.allow_sig_v2,
    )))));
    if let Some(iam) = options.iam {
        builder.set_auth(access::Auth(iam.clone()));
        builder.set_access(access::Access::new(
            iam.clone(),
            rules.clone(),
            store.clone(),
            Arc::clone(&control),
        ));
        builder.set_route(routes::Routes {
            iam,
            store: store.clone(),
            rules,
            domains: options.domains.clone(),
            started: std::time::SystemTime::now(),
            config: options.config.map(Arc::new),
            root_keys: options.root_keys,
            certificates: options.certificates,
            tracers,
            live: watch.metrics.live(),
            heals: Arc::default(),
            profiles: Arc::default(),
            events,
            access_log,
            request_metrics,
            control: Arc::clone(&control),
            inventory,
            configs: options
                .config_settings
                .map(|settings| Arc::new(minio_config::Configs::new(settings))),
        });
    }
    let host = if options.domains.is_empty() {
        None
    } else {
        builder.set_host(MultiDomain::new(&options.domains)?);
        Some(MultiDomain::new(&options.domains)?)
    };
    Ok(Service::new(
        builder.build(),
        store,
        host,
        options.body_timeout,
        options.plain_http_is_secure,
        options.trusted_proxies,
        watch,
    )
    .with_workers(workers, expirations)
    .with_control(control)
    .with_website_domains(&options.website_domains))
}
