//! The S3 API over a TeiFS store: any S3 client, SDK or tool (the AWS CLI, rclone,
//! restic, boto3, …) reads and writes the drive's folders as buckets.

mod checksums;
mod cors;
mod crc_combine;
mod drive;
mod encode;
mod errors;
mod limits;
mod sse;
mod tagging;

use std::sync::Arc;

use s3s::{
    auth::SimpleAuth,
    config::{S3Config, StaticConfigProvider},
    host::MultiDomain,
    service::S3ServiceBuilder,
};
use teifs_store::{Layout, Store};

pub use cors::Service;
pub use drive::{Drive, LAYOUT_HEADER};
pub use limits::{MAX_HEADER_BYTES, MAX_USER_METADATA_BYTES};

/// How the S3 endpoint accepts requests.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The access key and secret key requests must be signed with. `None` accepts
    /// unsigned requests: only for a drive nobody else can reach.
    pub credentials: Option<(String, String)>,
    /// Domains for virtual-hosted-style requests (`bucket.domain/key`), besides the
    /// path style (`domain/bucket/key`) that always works.
    pub domains: Vec<String>,
    /// The layout of buckets created without choosing one.
    pub default_layout: Layout,
    /// Whether plain HTTP counts as a secure connection for SSE-C keys: true for a server
    /// that only listens on this machine, or behind a proxy that terminates TLS.
    pub plain_http_is_secure: bool,
    /// How long a request body may stop arriving before the request fails with
    /// `RequestTimeout`; `None` waits for ever.
    pub body_timeout: Option<std::time::Duration>,
    /// Accept Signature Version 2 (HMAC-SHA1, deprecated by AWS and refused for its
    /// newer buckets), for old clients and boto3's default presigned links.
    pub allow_sig_v2: bool,
}

/// Builds the S3 service for a store, with CORS in front of it.
pub fn service(store: Store, options: Options) -> Result<Service, s3s::host::DomainError> {
    let mut builder = S3ServiceBuilder::new(Drive::new(
        store.clone(),
        options.default_layout,
        options.plain_http_is_secure,
    ));
    let mut config = S3Config::default();
    config.enable_sig_v2 = options.allow_sig_v2;
    builder.set_config(Arc::new(StaticConfigProvider::new(Arc::new(config))));
    if let Some((access_key, secret_key)) = options.credentials {
        builder.set_auth(SimpleAuth::from_single(access_key, secret_key));
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
    ))
}
