//! Connections to targets that aren't HTTP: TCP with a timeout, and TLS when asked for,
//! the server verified with the system's trust store or a CA file of the operator's.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Mutex,
};

/// How long a connection may take to open.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an event may take to be taken, or a check to be answered.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);

/// What an operation on a kept connection returns.
pub(crate) type Op<'c, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'c>>;

/// A target that keeps a connection.
pub(crate) trait Connects: Sync {
    type Connection: Send;
    /// Opens a connection, ready for events.
    fn connect(&self) -> impl Future<Output = Result<Self::Connection, String>> + Send;
}

/// A connection kept between events: made when there's none, dropped when it fails.
pub(crate) struct Kept<C>(Arc<Mutex<Option<C>>>);

impl<C: Send> Kept<C> {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    /// Runs `op` with `request` on `target`'s connection, made if there's none, each
    /// within [`TIMEOUT`]. A kept connection that fails is made again once, at once: servers
    /// close connections that were idle a while. `fresh` drops the kept one first.
    pub(crate) async fn run<X, R, T>(
        &self,
        target: &X,
        fresh: bool,
        request: &R,
        op: for<'c> fn(&'c mut C, &'c R) -> Op<'c, T>,
    ) -> Result<T, String>
    where
        X: Connects<Connection = C>,
        R: Sync + ?Sized,
    {
        let mut slot = self.0.lock().await;
        if fresh {
            *slot = None;
        }
        let mut kept = slot.is_some();
        loop {
            let open = match &mut *slot {
                Some(open) => open,
                None => slot.insert(
                    tokio::time::timeout(TIMEOUT, target.connect())
                        .await
                        .unwrap_or_else(|_| Err("it didn't answer in time".to_owned()))?,
                ),
            };
            let result = tokio::time::timeout(TIMEOUT, op(open, request))
                .await
                .unwrap_or_else(|_| Err("it didn't answer in time".to_owned()));
            match result {
                Ok(value) => return Ok(value),
                Err(err) => {
                    *slot = None;
                    if !kept {
                        return Err(err);
                    }
                    kept = false;
                }
            }
        }
    }
}

impl<C> Clone for Kept<C> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

/// A connection, plain or TLS.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type Stream = Box<dyn Io>;

/// How a target's server is verified over TLS (with the system's certificates, or only
/// `ca_pem`'s), and the certificate chain and key TeiFS shows it, if it asks for one.
///
/// # Errors
///
/// When `ca_pem` holds no certificate, the system's trust store can't be used, or the
/// identity's chain or key can't be read or don't go together.
pub fn tls_config(
    ca_pem: Option<&[u8]>,
    identity: Option<(&[u8], &[u8])>,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let config = if let Some(pem) = ca_pem {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| format!("the CA file isn't PEM: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("the CA file's certificate can't be used: {e}"))?;
        }
        if roots.is_empty() {
            return Err("the CA file holds no certificate".to_owned());
        }
        builder.with_root_certificates(roots)
    } else {
        let verifier = rustls_platform_verifier::Verifier::new(provider)
            .map_err(|e| format!("the system's certificates can't be used: {e}"))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
    };
    let Some((chain_pem, key_pem)) = identity else {
        return Ok(Arc::new(config.with_no_client_auth()));
    };
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("the certificate file isn't PEM: {e}"))?;
    if chain.is_empty() {
        return Err("the certificate file holds no certificate".to_owned());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| "the key file holds no private key".to_owned())?;
    let config = config
        .with_client_auth_cert(chain, key)
        .map_err(|e| format!("the certificate and key can't be used together: {e}"))?;
    Ok(Arc::new(config))
}

/// Opens a TCP connection to `address` (`HOST:PORT`).
pub(crate) async fn connect(address: &str) -> Result<TcpStream, String> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| "it didn't answer in time".to_owned())?
        .map_err(|e| format!("can't connect: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Secures `stream` to `address`'s host with `tls`, or leaves it plain without.
pub(crate) async fn secure<S: Io + 'static>(
    stream: S,
    address: &str,
    tls: Option<&Arc<ClientConfig>>,
) -> Result<Stream, String> {
    let Some(tls) = tls else {
        return Ok(Box::new(stream));
    };
    let host = host_of(address);
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| format!("`{host}` can't be verified over TLS"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
    let secured = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| "its TLS handshake didn't finish in time".to_owned())?
        .map_err(|e| format!("TLS failed: {e}"))?;
    Ok(Box::new(secured))
}

/// `HOST` of `HOST:PORT` (`[::1]:PORT` gives `::1`).
fn host_of(address: &str) -> &str {
    let host = address.rsplit_once(':').map_or(address, |(host, _)| host);
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Whether `address` is `HOST:PORT`.
pub(crate) fn is_address(address: &str) -> bool {
    address
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_taken_from_addresses() {
        assert_eq!(host_of("redis.local:6379"), "redis.local");
        assert_eq!(host_of("[::1]:6379"), "::1");
        assert_eq!(host_of("10.0.0.1:1"), "10.0.0.1");
        assert!(is_address("h:1") && !is_address("h") && !is_address(":1") && !is_address("h:0"));
    }

    /// Connections numbered as they're made; each takes as many operations as its
    /// server lets it before failing.
    struct Server {
        made: std::sync::atomic::AtomicU32,
        lives: u32,
    }

    impl Connects for Server {
        type Connection = (u32, u32);

        fn connect(&self) -> impl Future<Output = Result<(u32, u32), String>> + Send {
            let n = self.made.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            async move {
                if n > 3 {
                    Err("down".to_owned())
                } else {
                    Ok((n, 0))
                }
            }
        }
    }

    fn op<'c>(open: &'c mut (u32, u32), lives: &'c u32) -> Op<'c, u32> {
        Box::pin(async move {
            open.1 += 1;
            if open.1 > *lives {
                Err(format!("connection {} closed", open.0))
            } else {
                Ok(open.0)
            }
        })
    }

    #[tokio::test]
    async fn a_kept_connection_that_failed_is_made_again_once() {
        let server = Server {
            made: 0.into(),
            lives: 1,
        };
        let kept = Kept::new();
        assert_eq!(kept.run(&server, false, &server.lives, op).await, Ok(1));
        // The kept connection fails (its server closed it): a new one, at once.
        assert_eq!(kept.run(&server, false, &server.lives, op).await, Ok(2));
        // A fresh connection that fails isn't tried again.
        let err = kept.run(&server, false, &0, op).await.unwrap_err();
        assert_eq!(
            err, "connection 3 closed",
            "the kept one, then one fresh try"
        );
        assert_eq!(
            kept.run(&server, true, &server.lives, op).await,
            Err("down".into())
        );
    }

    #[test]
    fn a_ca_file_must_hold_a_certificate() {
        assert!(tls_config(Some(b""), None).is_err());
        assert!(tls_config(Some(b"not pem"), None).is_err());
        assert!(tls_config(None, None).is_ok());
    }
}
