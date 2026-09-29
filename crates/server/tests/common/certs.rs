//! Certificates for HTTPS tests: a certificate authority of their own, the server
//! certificates it issues, and clients that trust it.

use std::{fs, net::SocketAddr, path::Path, sync::Arc};

use aws_smithy_http_client::{
    Builder,
    tls::{self, TlsContext, TrustStore, rustls_provider::CryptoMode},
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A certificate authority of its own.
pub struct Authority {
    params: CertificateParams,
    key: KeyPair,
    /// Its certificate, PEM.
    pub pem: String,
    der: CertificateDer<'static>,
}

/// A server certificate and its key, PEM.
pub struct Issued {
    pub cert: String,
    pub key: String,
    pub der: CertificateDer<'static>,
}

impl Authority {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "TeiFS test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Self {
            pem: cert.pem(),
            der: cert.der().clone(),
            params,
            key,
        }
    }

    /// A server certificate for `names` (host names, wildcards or IP addresses).
    pub fn issue(&self, names: &[&str]) -> Issued {
        let params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        let key = KeyPair::generate().unwrap();
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        Issued {
            cert: format!("{}{}", cert.pem(), self.pem),
            key: key.serialize_pem(),
            der: cert.der().clone(),
        }
    }

    /// Issues a certificate for `names` into `dir` as `public.crt` and `private.key`.
    pub fn issue_into(&self, dir: &Path, names: &[&str]) -> Issued {
        fs::create_dir_all(dir).unwrap();
        let issued = self.issue(names);
        fs::write(dir.join("public.crt"), &issued.cert).unwrap();
        fs::write(dir.join("private.key"), &issued.key).unwrap();
        issued
    }

    /// Connects to `address` asking for `name` (none for an IP address), offering
    /// `alpn`: the certificate the server presented and the protocol it chose.
    pub async fn handshake(
        &self,
        address: SocketAddr,
        name: &str,
        alpn: &[&str],
    ) -> Result<(CertificateDer<'static>, Option<Vec<u8>>), std::io::Error> {
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        let mut config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        let tcp = TcpStream::connect(address).await?;
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let stream = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await?;
        let (_, session) = stream.get_ref();
        Ok((
            session.peer_certificates().unwrap()[0].clone(),
            session.alpn_protocol().map(<[u8]>::to_vec),
        ))
    }

    /// An S3 client for `server` that trusts this authority.
    pub fn client(&self, server: &super::Server) -> aws_sdk_s3::Client {
        let http = Builder::new()
            .tls_provider(tls::Provider::Rustls(CryptoMode::AwsLc))
            .tls_context(
                TlsContext::builder()
                    .with_trust_store(
                        TrustStore::empty()
                            .with_native_roots(false)
                            .with_pem_certificate(self.pem.as_bytes()),
                    )
                    .build()
                    .unwrap(),
            )
            .build_https();
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                super::ACCESS_KEY,
                super::SECRET_KEY,
                None,
                None,
                "tests",
            ))
            .force_path_style(true)
            .http_client(http)
            .build();
        aws_sdk_s3::Client::from_conf(config)
    }

    /// A plain HTTP client that trusts this authority.
    pub fn reqwest(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_pem(self.pem.as_bytes()).unwrap()])
            .build()
            .unwrap()
    }
}
