//! Connections to targets that aren't HTTP: TCP with a timeout, and TLS when asked for,
//! the server verified with the system's trust store or a CA file of the operator's.

use std::{sync::Arc, time::Duration};

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

/// How long a connection may take to open.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection, plain or TLS.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type Stream = Box<dyn Io>;

/// How a target's server is verified over TLS.
///
/// # Errors
///
/// When `ca_pem` holds no certificate, or the system's trust store can't be used.
pub fn tls_config(ca_pem: Option<&[u8]>) -> Result<Arc<ClientConfig>, String> {
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
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        let verifier = rustls_platform_verifier::Verifier::new(provider)
            .map_err(|e| format!("the system's certificates can't be used: {e}"))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    };
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

    #[test]
    fn a_ca_file_must_hold_a_certificate() {
        assert!(tls_config(Some(b"")).is_err());
        assert!(tls_config(Some(b"not pem")).is_err());
        assert!(tls_config(None).is_ok());
    }
}
