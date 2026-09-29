//! The S3 API over a TeiFS store: any S3 client, SDK or tool (the AWS CLI, rclone,
//! restic, boto3, …) reads and writes the drive's folders as buckets.

mod access;
mod acl;
mod admin;
mod bucket_access;
mod caps;
mod checksums;
mod control;
mod cors;
mod crc_combine;
mod drive;
mod encode;
mod errors;
mod health;
mod iam_api;
mod limits;
mod post_form;
mod proxy;
mod routes;
mod sig_v2;
mod sse;
mod tagging;

use std::sync::Arc;

use s3s::{
    config::{S3Config, StaticConfigProvider},
    host::MultiDomain,
    service::S3ServiceBuilder,
};
use teifs_iam::Iam;
use teifs_store::{Layout, Store};

pub use access::Client;
pub use admin::RootKeyStore;
pub use cors::Service;
pub use drive::{Drive, LAYOUT_HEADER};
pub use health::HEALTH_PATH;
pub use limits::{MAX_HEADER_BYTES, MAX_USER_METADATA_BYTES};
pub use proxy::{ProxyHeader, TrustedProxies};
pub use routes::{Api, EndpointInfo, endpoints};

/// How the S3 endpoint accepts requests.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Who may sign requests and what each may do. `None` accepts unsigned requests
    /// and decides nothing: only for a drive nobody else can reach.
    pub iam: Option<Arc<Iam>>,
    /// Domains for virtual-hosted-style requests (`bucket.domain/key`), besides the
    /// path style (`domain/bucket/key`) that always works.
    pub domains: Vec<String>,
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
    /// Where the root key is kept, if the admin API may replace it (a key the drive
    /// generated); `None` answers that it's managed elsewhere.
    pub root_keys: Option<Arc<dyn RootKeyStore>>,
}

/// Builds the S3 service for a store, with CORS in front of it.
pub fn service(store: Store, options: Options) -> Result<Service, s3s::host::DomainError> {
    let drive = Drive::new(
        store.clone(),
        options.default_layout,
        options.legacy_bucket_defaults,
    );
    let rules = drive.rules();
    let mut builder = S3ServiceBuilder::new(drive);
    let mut config = S3Config::default();
    config.enable_sig_v2 = options.allow_sig_v2;
    config.sig_v4_allowed_services = ["s3", "iam", "sts"].map(str::to_owned).into();
    // Each route reads at most its own limit, after deciding the caller may call it.
    config.custom_route_max_body_size = Some(admin::MAX_IMPORT_BYTES as u64);
    // Forms are parsed with the limits TeiFS reads their fields with.
    config.form_max_field_size = post_form::MAX_FIELDS_BYTES;
    config.form_max_fields_size = post_form::MAX_FIELDS_BYTES;
    config.form_max_parts = post_form::MAX_PARTS;
    builder.set_config(Arc::new(StaticConfigProvider::new(Arc::new(config))));
    if let Some(iam) = options.iam {
        builder.set_auth(access::Auth(iam.clone()));
        builder.set_access(access::Access::new(
            iam.clone(),
            rules.clone(),
            store.clone(),
        ));
        builder.set_route(routes::Routes {
            iam,
            store: store.clone(),
            rules,
            domains: options.domains.clone(),
            started: std::time::SystemTime::now(),
            config: options.config.map(Arc::new),
            root_keys: options.root_keys,
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
    ))
}
