//! MinIO's `AssumeRoleWithCertificate`: the client certificate a TLS connection was made
//! with says who is asking. The handshake proved the client holds its key; this checks
//! the certificate itself, as MinIO does: one leaf and at most ten intermediate CAs,
//! issued by one of the configured authorities (unless verification is off), for client
//! authentication, with a subject common name, which names the session's policy.

use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use x509_parser::prelude::{FromDer, X509Certificate};

/// The most intermediate CAs a client may send, as MinIO allows.
const MAX_INTERMEDIATES: usize = 10;

/// Whom certificates are trusted from.
#[derive(Debug)]
pub struct CertificateSignIn {
    anchors: Vec<TrustAnchor<'static>>,
    skip_verify: bool,
}

/// Why a client certificate gets no session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CertificateError {
    /// The connection isn't over TLS, or the client sent no certificate.
    #[error("No client certificate provided")]
    Missing,
    #[error("More than one client certificate provided")]
    Several,
    #[error("client certificate contains more than {MAX_INTERMEDIATES} intermediate CAs")]
    TooManyIntermediates,
    #[error("certificate subject CN cannot be empty")]
    NoCommonName,
    #[error("certificate is not valid for client authentication")]
    NotForClients,
    /// Not issued by a trusted authority, expired, or unreadable: why.
    #[error("{0}")]
    Invalid(String),
}

/// A certificate that passed: who it names, and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Presented {
    /// The subject's common name.
    pub(crate) cn: String,
    /// When the certificate expires, in seconds since the Unix epoch.
    pub(crate) not_after: i64,
}

impl CertificateSignIn {
    /// Trusts certificates issued by `roots` (DER); with `skip_verify`, any
    /// certificate, which is for testing only.
    ///
    /// # Errors
    /// Which root isn't a CA certificate, when one isn't.
    pub fn new(roots: &[CertificateDer<'_>], skip_verify: bool) -> Result<Self, String> {
        let anchors = roots
            .iter()
            .enumerate()
            .map(|(i, der)| {
                webpki::anchor_from_trusted_cert(der)
                    .map(|anchor| anchor.to_owned())
                    .map_err(|e| format!("certificate {} isn't a CA certificate: {e}", i + 1))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            anchors,
            skip_verify,
        })
    }

    /// How many authorities are trusted.
    #[must_use]
    pub fn authorities(&self) -> usize {
        self.anchors.len()
    }

    /// Whether certificates are taken without checking who issued them.
    #[must_use]
    pub const fn skips_verification(&self) -> bool {
        self.skip_verify
    }

    /// Checks the chain a client sent at `now` (seconds since the Unix epoch).
    pub(crate) fn check(
        &self,
        chain: &[CertificateDer<'_>],
        now: i64,
    ) -> Result<Presented, CertificateError> {
        let mut leaves = Vec::new();
        let mut intermediates = Vec::new();
        for der in chain {
            let parsed = parse(der)?;
            if parsed.is_ca() {
                intermediates.push(der.clone());
            } else {
                leaves.push((der, parsed));
            }
        }
        if intermediates.len() > MAX_INTERMEDIATES {
            return Err(CertificateError::TooManyIntermediates);
        }
        let (der, leaf) = match leaves.len() {
            0 => return Err(CertificateError::Missing),
            1 => leaves.remove(0),
            _ => return Err(CertificateError::Several),
        };
        let not_after = leaf.validity().not_after.timestamp();
        if !self.skip_verify {
            let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                u64::try_from(now).unwrap_or_default(),
            ));
            let end = webpki::EndEntityCert::try_from(der)
                .map_err(|e| CertificateError::Invalid(e.to_string()))?;
            end.verify_for_usage(
                rustls::crypto::aws_lc_rs::default_provider()
                    .signature_verification_algorithms
                    .all,
                &self.anchors,
                &intermediates,
                time,
                webpki::KeyUsage::client_auth(),
                None,
                None,
            )
            .map_err(|e| CertificateError::Invalid(e.to_string()))?;
        } else if not_after <= now || leaf.validity().not_before.timestamp() > now {
            return Err(CertificateError::Invalid(
                "the certificate isn't valid now".into(),
            ));
        }
        // Required whether or not the issuer was checked: a certificate that doesn't
        // say it's for clients isn't taken as one.
        let for_clients = leaf
            .extended_key_usage()
            .ok()
            .flatten()
            .is_some_and(|eku| eku.value.any || eku.value.client_auth);
        if !for_clients {
            return Err(CertificateError::NotForClients);
        }
        let cn = leaf
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or_default();
        if cn.is_empty() {
            return Err(CertificateError::NoCommonName);
        }
        Ok(Presented {
            cn: cn.to_owned(),
            not_after,
        })
    }
}

fn parse<'a>(der: &'a CertificateDer<'_>) -> Result<X509Certificate<'a>, CertificateError> {
    X509Certificate::from_der(der)
        .map(|(_, parsed)| parsed)
        .map_err(|e| CertificateError::Invalid(format!("the certificate can't be read: {e}")))
}

#[cfg(test)]
mod tests;
