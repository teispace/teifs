//! TLS client settings for the services TeiFS calls (notification targets, a KES
//! server): the server verified with the system's trust store or a CA file of the
//! operator's, and a client certificate when the service asks for one.

use std::sync::Arc;

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

/// How a service's server is verified over TLS (with the system's certificates, or only
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
