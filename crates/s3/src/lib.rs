//! The S3 API over a TeiFS store: any S3 client, SDK or tool (the AWS CLI, rclone,
//! restic, boto3, …) reads and writes the drive's folders as buckets.

mod checksums;
mod crc_combine;
mod drive;
mod encode;
mod errors;
mod sse;

use s3s::{
    auth::SimpleAuth,
    host::MultiDomain,
    service::{S3Service, S3ServiceBuilder},
};
use teifs_store::{Layout, Store};

pub use drive::{Drive, LAYOUT_HEADER};

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
}

/// Builds the S3 service for a store.
pub fn service(store: Store, options: Options) -> Result<S3Service, s3s::host::DomainError> {
    let mut builder = S3ServiceBuilder::new(Drive::new(
        store,
        options.default_layout,
        options.plain_http_is_secure,
    ));
    if let Some((access_key, secret_key)) = options.credentials {
        builder.set_auth(SimpleAuth::from_single(access_key, secret_key));
    }
    if !options.domains.is_empty() {
        builder.set_host(MultiDomain::new(&options.domains)?);
    }
    Ok(builder.build())
}
