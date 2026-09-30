//! How an OpenID Connect provider's certificate is trusted when its keys are fetched, as
//! AWS trusts it: a certificate the system trusts is enough; else, one of the
//! certificates the provider presents must have one of the provider's thumbprints (the
//! hex SHA-1 of its DER, as `CreateOpenIDConnectProvider` takes them): the top
//! intermediate certificate authority's, or the server's own if it signs itself. That
//! certificate is then the only trust anchor: the chain up to it, the dates and the host
//! name are still verified, so a thumbprint pins a certificate but never excuses a bad
//! chain.

use std::{fmt, sync::Arc};

use aws_lc_rs::digest;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};

/// The TLS settings for fetching from a provider with these `thumbprints`.
pub(crate) fn config(thumbprints: &[String]) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let platform = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        .map_err(|e| format!("the system's certificates can't be used: {e}"))?;
    let verifier = Pinned {
        platform,
        thumbprints: thumbprints.iter().filter_map(|t| parse(t)).collect(),
        provider: Arc::clone(&provider),
    };
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// A thumbprint's 20 bytes; none if it isn't 40 hex digits (IAM refuses those).
fn parse(hex: &str) -> Option<[u8; 20]> {
    teifs_types::unhex(hex)
}

/// The system's verifier, and the provider's thumbprints when it refuses.
struct Pinned {
    platform: rustls_platform_verifier::Verifier,
    thumbprints: Vec<[u8; 20]>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for Pinned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pinned")
            .field("thumbprints", &self.thumbprints.len())
            .finish_non_exhaustive()
    }
}

impl Pinned {
    /// The presented certificate a thumbprint pins, if one does.
    fn pinned<'a>(
        &self,
        end_entity: &'a CertificateDer<'a>,
        intermediates: &'a [CertificateDer<'a>],
    ) -> Option<&'a CertificateDer<'a>> {
        std::iter::once(end_entity)
            .chain(intermediates)
            .find(|cert| {
                let sha1 = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, cert);
                self.thumbprints.iter().any(|t| t == sha1.as_ref())
            })
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let refused = match self.platform.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => return Ok(verified),
            Err(err) => err,
        };
        let Some(anchor) = self.pinned(end_entity, intermediates) else {
            return Err(refused);
        };
        let mut roots = RootCertStore::empty();
        roots
            .add(anchor.clone())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&self.provider))
            .build()
            .map_err(|e| Error::General(e.to_string()))?
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.platform.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.platform.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.platform.supported_verify_schemes()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::oidc::{
        jwt::tests::Signer,
        keys::{KeyCache, tests::publishing_with},
    };

    /// A certificate authority of its own, as a company's identity provider might have.
    pub(crate) struct Authority {
        params: CertificateParams,
        key: KeyPair,
        pub(crate) der: CertificateDer<'static>,
    }

    impl Authority {
        pub(crate) fn new(name: &str) -> Self {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name.push(DnType::CommonName, name);
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let key = KeyPair::generate().unwrap();
            let der = params.self_signed(&key).unwrap().der().clone();
            Self { params, key, der }
        }

        /// A server certificate for `host` it signs, valid until `until`.
        pub(crate) fn issue(
            &self,
            host: &str,
            until: OffsetDateTime,
        ) -> (CertificateDer<'static>, KeyPair) {
            let mut params = CertificateParams::new(vec![host.to_owned()]).unwrap();
            params.not_before = OffsetDateTime::now_utc() - Duration::days(2);
            params.not_after = until;
            let key = KeyPair::generate().unwrap();
            let issuer = Issuer::from_params(&self.params, &self.key);
            let der = params.signed_by(&key, &issuer).unwrap().der().clone();
            (der, key)
        }
    }

    pub(crate) fn thumbprint(cert: &CertificateDer<'_>) -> String {
        digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, cert)
            .as_ref()
            .iter()
            .fold(String::new(), |mut hex, b| {
                use std::fmt::Write as _;
                let _ = write!(hex, "{b:02X}");
                hex
            })
    }

    pub(crate) fn server(
        chain: Vec<CertificateDer<'static>>,
        key: &KeyPair,
    ) -> Arc<rustls::ServerConfig> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
        )
    }

    /// Whether the keys of a provider serving `chain` can be fetched with
    /// `thumbprints`.
    async fn fetches(
        chain: Vec<CertificateDer<'static>>,
        key: &KeyPair,
        thumbprints: &[String],
    ) -> Result<(), String> {
        let provider = publishing_with(
            vec![Signer::rsa().jwk("k1", "")],
            "",
            Some(server(chain, key)),
        )
        .await;
        let url = format!("{}/idp", provider.url);
        let cache = KeyCache::default();
        cache.refresh(&url, thumbprints, None).await;
        cache.keys(&url).map(|keys| assert_eq!(keys.len(), 1))
    }

    #[tokio::test]
    async fn a_thumbprint_pins_a_certificate_the_system_does_not_trust() {
        let ca = Authority::new("TeiFS test CA");
        let year = OffsetDateTime::now_utc() + Duration::days(365);
        let (leaf, key) = ca.issue("localhost", year);
        let chain = vec![leaf.clone(), ca.der.clone()];

        // The system doesn't trust the authority: no keys without a thumbprint.
        let err = fetches(chain.clone(), &key, &[]).await.unwrap_err();
        assert!(err.contains("certificate"), "{err}");
        // The authority's thumbprint, as AWS asks for (the top intermediate), in any
        // case, among others.
        let pinned = thumbprint(&ca.der);
        fetches(chain.clone(), &key, std::slice::from_ref(&pinned))
            .await
            .unwrap();
        fetches(
            chain.clone(),
            &key,
            &["0".repeat(40), pinned.to_lowercase()],
        )
        .await
        .unwrap();
        // The server's own certificate is no anchor when an authority signed it: the
        // chain must lead to the pinned certificate.
        fetches(chain.clone(), &key, &[thumbprint(&leaf)])
            .await
            .unwrap_err();
        // A certificate that signs itself is pinned by its own thumbprint.
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.not_after = year;
        let own_key = KeyPair::generate().unwrap();
        let own = params.self_signed(&own_key).unwrap().der().clone();
        fetches(vec![own.clone()], &own_key, &[thumbprint(&own)])
            .await
            .unwrap();

        // Another certificate's thumbprint, or one that isn't one, pins nothing.
        let other = Authority::new("Someone else");
        for thumbprints in [vec![thumbprint(&other.der)], vec!["xyz".to_owned()]] {
            fetches(chain.clone(), &key, &thumbprints)
                .await
                .unwrap_err();
        }
        // A pinned authority doesn't excuse a certificate for another host, an expired
        // one, or one it didn't sign.
        let pin = [thumbprint(&ca.der)];
        let (elsewhere, elsewhere_key) = ca.issue("idp.example.com", year);
        let (expired, expired_key) =
            ca.issue("localhost", OffsetDateTime::now_utc() - Duration::days(1));
        let (foreign, foreign_key) = other.issue("localhost", year);
        for (cert, key) in [
            (elsewhere, &elsewhere_key),
            (expired, &expired_key),
            (foreign, &foreign_key),
        ] {
            let err = fetches(vec![cert, ca.der.clone()], key, &pin)
                .await
                .unwrap_err();
            assert!(err.contains("certificate"), "{err}");
        }
    }

    #[test]
    fn thumbprints_are_forty_hex_digits() {
        assert_eq!(parse(&"ab".repeat(20)), Some([0xab; 20]));
        assert_eq!(parse(&"AB".repeat(20)), Some([0xab; 20]));
        for bad in [
            "ab".repeat(19),
            "ab".repeat(21),
            "zz".repeat(20),
            "+1".repeat(20),
        ] {
            assert_eq!(parse(&bad), None, "{bad}");
        }
    }
}
