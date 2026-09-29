//! A certificate authority to trust besides the system's: for a server whose
//! certificate a company's own CA signed, or a self-signed one. An alias names it
//! (`ca-cert`), or `TEIFS_CA_CERT` does for every alias; the S3, IAM, STS and admin
//! clients all trust it.

use std::{
    fmt,
    path::Path,
    sync::{Arc, OnceLock},
};

use aws_sdk_s3::config::SharedHttpClient;
use aws_smithy_http_client::{
    Builder,
    tls::{self, TlsContext, TrustStore, rustls_provider::CryptoMode},
};
use rustls::pki_types::{CertificateDer, pem::PemObject};

/// The environment variable naming a certificate authority for every alias that
/// doesn't name one.
pub const CA_ENV: &str = "TEIFS_CA_CERT";

/// The certificate authority an alias trusts, read when aliases are loaded.
#[derive(Clone, Default)]
pub struct Trust(Option<Result<Arc<Authority>, String>>);

struct Authority {
    pem: Vec<u8>,
    /// The AWS SDKs' HTTP client trusting it, made once and shared.
    sdk: OnceLock<SharedHttpClient>,
}

/// Trust is read from an alias's settings, which are what's compared.
impl PartialEq for Trust {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Trust {}

impl fmt::Debug for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            None => f.write_str("system"),
            Some(Ok(_)) => f.write_str("system and a CA"),
            Some(Err(err)) => write!(f, "unusable: {err}"),
        }
    }
}

impl Trust {
    /// The system's certificate authorities and, if `path` names one, that one too.
    pub fn load(path: Option<&Path>) -> Self {
        Self(path.map(|path| {
            read(path).map(|pem| {
                Arc::new(Authority {
                    pem,
                    sdk: OnceLock::new(),
                })
            })
        }))
    }

    /// Why it can't be used, if it can't.
    pub fn check(&self) -> Result<(), String> {
        match &self.0 {
            Some(Err(err)) => Err(err.clone()),
            _ => Ok(()),
        }
    }

    /// The extra authority's certificates, PEM.
    pub fn pem(&self) -> Option<&[u8]> {
        match &self.0 {
            Some(Ok(authority)) => Some(&authority.pem),
            _ => None,
        }
    }

    /// An HTTP client for the AWS SDKs that trusts it; `None` for the SDKs' own.
    pub fn sdk_client(&self) -> Option<SharedHttpClient> {
        let Some(Ok(authority)) = &self.0 else {
            return None;
        };
        let client = authority.sdk.get_or_init(|| {
            let trust = TrustStore::default()
                .with_native_roots(true)
                .with_pem_certificate(authority.pem.clone());
            Builder::new()
                .tls_provider(tls::Provider::Rustls(CryptoMode::AwsLc))
                .tls_context(
                    TlsContext::builder()
                        .with_trust_store(trust)
                        .build()
                        .expect("a trust store with PEM certificates builds"),
                )
                .build_https()
        });
        Some(client.clone())
    }
}

/// Reads a certificate authority file: PEM, with at least one certificate.
pub fn read(path: &Path) -> Result<Vec<u8>, String> {
    let pem = std::fs::read(path)
        .map_err(|e| format!("can't read the CA certificate {}: {e}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{} isn't a PEM certificate: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} has no certificate", path.display()));
    }
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ca_file_must_hold_pem_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let err = read(&path).unwrap_err();
        assert!(err.starts_with("can't read the CA certificate"), "{err}");
        std::fs::write(&path, "nonsense").unwrap();
        assert!(read(&path).unwrap_err().ends_with("has no certificate"));
        std::fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(read(&path).unwrap_err().contains("isn't a PEM certificate"));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["ca.test".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(&path, cert.pem()).unwrap();
        assert_eq!(read(&path).unwrap(), cert.pem().as_bytes());

        let trust = Trust::load(Some(&path));
        assert!(trust.check().is_ok());
        assert_eq!(trust.pem(), Some(cert.pem().as_bytes()));
        assert!(trust.sdk_client().is_some());
        let system = Trust::load(None);
        assert!(system.check().is_ok());
        assert!(system.pem().is_none() && system.sdk_client().is_none());
        let missing = Trust::load(Some(&dir.path().join("gone.pem")));
        assert!(missing.check().is_err());
        assert!(missing.pem().is_none() && missing.sdk_client().is_none());
        assert_eq!(
            format!("{system:?} / {trust:?}"),
            "system / system and a CA"
        );
    }
}
