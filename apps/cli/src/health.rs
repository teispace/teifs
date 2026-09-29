//! `teifs health`: asks a TeiFS server for its health check, for container health checks
//! and scripts (distroless images have no curl). It's for the server's own machine or
//! container: over HTTPS it checks the handshake but not whom the certificate names (a
//! private CA's, or one for a public name while it asks `127.0.0.1`), since it sends
//! nothing secret and learns only a status.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

use crate::{
    error::{Error, Kind},
    ui,
};

/// `teifs health`'s arguments.
#[derive(clap::Args)]
pub(crate) struct HealthArgs {
    /// The server's address (`teifs serve --listen`'s), or its `http://` or `https://`
    /// URL. An address is asked over HTTPS when the server only speaks that.
    #[arg(default_value = "127.0.0.1:9000", env = "TEIFS_LISTEN")]
    address: String,
    /// How long to wait for an answer.
    #[arg(long, default_value = "5s", value_parser = crate::units::parse_duration)]
    timeout: Duration,
}

pub(crate) async fn health(args: &HealthArgs) -> Result<(), Error> {
    let (target, https) = target(&args.address)?;
    let url = |https: bool| {
        let scheme = if https { "https" } else { "http" };
        format!("{scheme}://{target}{}", teifs_server::HEALTH_PATH)
    };
    let started = Instant::now();
    let (status, https) = tokio::time::timeout(args.timeout, ask(&target, https))
        .await
        .map_err(|_| {
            Error::new(
                Kind::Network,
                format!(
                    "{} didn't answer within {:.1} s",
                    url(https),
                    args.timeout.as_secs_f64()
                ),
            )
        })?
        .map_err(|e| {
            Error::new(Kind::Network, format!("can't reach {}: {e}", url(https)))
                .with_hint("check the address, and that `teifs serve` is running")
        })?;
    let url = url(https);
    if status != 200 {
        return Err(
            Error::new(Kind::General, format!("{url} answered {status}, not 200"))
                .with_hint("is that a TeiFS server?"),
        );
    }
    let elapsed = started.elapsed();
    ui::done(
        format!("{url} is healthy ({} ms)", elapsed.as_millis()),
        || serde_json::json!({"type": "health", "url": url, "healthy": true, "ms": elapsed.as_millis()}),
    );
    Ok(())
}

/// `host:port` from an address or URL, and whether the URL says HTTPS; an unspecified
/// address (`0.0.0.0`) means this machine.
fn target(address: &str) -> Result<(String, bool), Error> {
    let (bare, https) = match address.strip_prefix("https://") {
        Some(rest) => (rest, true),
        None => (address.trim_start_matches("http://"), false),
    };
    let bare = bare.trim_end_matches('/');
    if bare.is_empty() || bare.contains('/') {
        return Err(Error::usage(format!(
            "`{address}` isn't an address like 127.0.0.1:9000"
        )));
    }
    let target = match bare.parse::<SocketAddr>() {
        Ok(socket) => crate::announce_address(socket).to_string(),
        Err(_) if bare.contains(':') => bare.to_owned(),
        Err(_) => format!("{bare}:9000"),
    };
    Ok((target, https))
}

/// The status of `GET` for the health check, and whether it was asked over HTTPS: when
/// told to, or when the server answers plain HTTP with `400` because it speaks HTTPS.
async fn ask(target: &str, https: bool) -> std::io::Result<(u16, bool)> {
    if https {
        return Ok((ask_over_tls(target).await?, true));
    }
    match ask_over(TcpStream::connect(target).await?, target).await? {
        Status::Https => Ok((ask_over_tls(target).await?, true)),
        Status::Code(code) => Ok((code, false)),
    }
}

async fn ask_over_tls(target: &str) -> std::io::Result<u16> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let host = target
        .rsplit_once(':')
        .map_or(target, |(host, _)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    let name = ServerName::try_from(host.to_owned()).map_err(std::io::Error::other)?;
    let tcp = TcpStream::connect(target).await?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?;
    match ask_over(stream, target).await? {
        Status::Code(code) => Ok(code),
        Status::Https => Ok(400),
    }
}

/// A health check's answer.
enum Status {
    Code(u16),
    /// Plain HTTP was refused: the server speaks HTTPS.
    Https,
}

async fn ask_over<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: S,
    target: &str,
) -> std::io::Result<Status> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n",
        teifs_server::HEALTH_PATH
    );
    socket.write_all(request.as_bytes()).await?;
    // The status line is all that's needed.
    let mut head = [0; 64];
    let mut read = 0;
    while read < 12 {
        let n = socket.read(&mut head[read..]).await?;
        if n == 0 {
            break;
        }
        read += n;
    }
    let line = std::str::from_utf8(&head[..read]).unwrap_or_default();
    // TeiFS's (and Go's) answer to plain HTTP on an HTTPS port.
    if line.starts_with("HTTP/1.0 400 ") {
        return Ok(Status::Https);
    }
    line.strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .map(Status::Code)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "not an HTTP answer"))
}

/// Accepts the server's certificate whatever it names or whoever signed it, but checks
/// that the server holds its key: the health check sends nothing secret.
#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_become_host_and_port() {
        let plain = |address| target(address).unwrap();
        assert_eq!(plain("127.0.0.1:9000"), ("127.0.0.1:9000".into(), false));
        assert_eq!(plain("0.0.0.0:9100"), ("127.0.0.1:9100".into(), false));
        assert_eq!(plain("[::]:9100"), ("[::1]:9100".into(), false));
        assert_eq!(
            plain("http://localhost:9000/"),
            ("localhost:9000".into(), false)
        );
        assert_eq!(plain("teifs"), ("teifs:9000".into(), false));
        assert_eq!(
            plain("https://s3.example.com"),
            ("s3.example.com:9000".into(), true)
        );
        assert_eq!(plain("https://[::1]:9443"), ("[::1]:9443".into(), true));
        assert!(target("http://host:9000/path").is_err());
        assert!(target("").is_err());
    }
}
