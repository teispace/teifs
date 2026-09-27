//! The S3 API over a TeiDrive store: any S3 client, SDK or tool (the AWS CLI, rclone,
//! restic, boto3, …) reads and writes the drive's folders as buckets.

mod checksums;
mod drive;
mod encode;
mod errors;
pub mod server;

use s3s::{
    auth::SimpleAuth,
    host::MultiDomain,
    service::{S3Service, S3ServiceBuilder},
};
use teidrive_store::Store;

pub use drive::Drive;

/// How the S3 endpoint accepts requests.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The access key and secret key requests must be signed with. `None` accepts
    /// unsigned requests: only for a drive nobody else can reach.
    pub credentials: Option<(String, String)>,
    /// Domains for virtual-hosted-style requests (`bucket.domain/key`), besides the
    /// path style (`domain/bucket/key`) that always works.
    pub domains: Vec<String>,
}

/// Builds the S3 service for a store.
pub fn service(store: Store, options: Options) -> Result<S3Service, s3s::host::DomainError> {
    let mut builder = S3ServiceBuilder::new(Drive::new(store));
    if let Some((access_key, secret_key)) = options.credentials {
        builder.set_auth(SimpleAuth::from_single(access_key, secret_key));
    }
    if !options.domains.is_empty() {
        builder.set_host(MultiDomain::new(&options.domains)?);
    }
    Ok(builder.build())
}
