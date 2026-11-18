//! File-protocol gateways to TeiFS: buckets and objects as folders and files, for tools
//! that don't speak S3. Each gateway is a client of the server's own S3 service: people
//! sign in with an access key and its secret, and every operation is an S3 request
//! signed with that key, sent to the service in memory, and checked, audited and
//! counted as any S3 client's is. A gateway holds no authority of its own.

mod attempts;
mod backend;
pub mod files;
pub mod sftp;

use std::{net::SocketAddr, path::PathBuf};

pub use attempts::{Attempts, MAX_FAILURES, WINDOW};
pub use backend::{Backend, Key, SignInError};
pub use sftp::{Sftp, SftpConfig};

/// The gateways a server serves, each off unless configured.
#[derive(Debug, Clone, Default)]
pub struct Gateways {
    /// The SFTP gateway.
    pub sftp: Option<SftpConfig>,
}

/// Why a gateway couldn't start.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The address couldn't be listened on.
    #[error("can't listen on {address}: {source}")]
    Listen {
        /// The address.
        address: SocketAddr,
        /// Why.
        source: std::io::Error,
    },
    /// The SFTP host key can't be read or made.
    #[error("the SFTP host key {path} can't be used: {why}")]
    HostKey {
        /// Where it is.
        path: PathBuf,
        /// Why.
        why: String,
    },
}
