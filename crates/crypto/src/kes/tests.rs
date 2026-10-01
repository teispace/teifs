//! The KES backend against a fake KES server that behaves like KES: TLS with a client
//! certificate required, the client identified by its public key's SHA-256, its API's
//! routes and answers, and its errors.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{
    DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use serde_json::{Value, json};

use super::*;

/// kes-go's example API key and the identity it documents for it.
const EXAMPLE_KEY: &str = "kes:v1:AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs";
const EXAMPLE_IDENTITY: &str = "ea9826089311fe44d7590408ede9150f7c637b6cab0a91ee6fe1aa5d9fb366f6";

/// Any client certificate, as KES takes them (it trusts identities, not issuers).
#[derive(Debug)]
struct AnyClient(Arc<CryptoProvider>);

impl ClientCertVerifier for AnyClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
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

#[derive(Default)]
struct FakeKes {
    /// Key name → when it was made (RFC 3339).
    keys: BTreeMap<String, String>,
    /// The identities allowed in; anyone when empty.
    allowed: Vec<String>,
    /// The identities that called.
    seen: Vec<String>,
}

fn reply(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn refuse(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    reply(status, &json!({ "message": message }))
}

impl FakeKes {
    fn call(
        &mut self,
        identity: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Response<Full<Bytes>> {
        self.seen.push(identity.to_owned());
        if !self.allowed.is_empty() && !self.allowed.iter().any(|a| a == identity) {
            return refuse(
                StatusCode::FORBIDDEN,
                "not authorized: insufficient permissions",
            );
        }
        let Some((api, name)) = path
            .strip_prefix("/v1/key/")
            .and_then(|rest| rest.split_once('/'))
        else {
            return refuse(StatusCode::NOT_FOUND, "not found");
        };
        // KES takes POST where it expects PUT.
        let method = if method == "POST" { "PUT" } else { method };
        match (method, api) {
            ("GET", "list") => {
                assert_eq!(name, "*");
                // Newest first: TeiFS sorts them itself.
                reply(
                    StatusCode::OK,
                    &json!({ "names": self.keys.keys().rev().collect::<Vec<_>>() }),
                )
            }
            ("PUT", "create") if self.keys.contains_key(name) => {
                refuse(StatusCode::BAD_REQUEST, "key already exists")
            }
            ("PUT", "create") => {
                self.keys
                    .insert(name.to_owned(), "2026-09-01T10:00:00.123456Z".to_owned());
                reply(StatusCode::OK, &json!({}))
            }
            (_, _) if !self.keys.contains_key(name) => {
                refuse(StatusCode::NOT_FOUND, "key does not exist")
            }
            ("GET", "describe") => reply(
                StatusCode::OK,
                &json!({"name": name, "algorithm": "AES256", "created_at": self.keys[name],
                        "created_by": identity}),
            ),
            ("PUT", "encrypt") => {
                let sealed = json!({"key": name, "plaintext": body["plaintext"], "context": body["context"]});
                reply(
                    StatusCode::OK,
                    &json!({ "ciphertext": STANDARD.encode(sealed.to_string()) }),
                )
            }
            ("PUT", "decrypt") => {
                let sealed: Value = STANDARD
                    .decode(body["ciphertext"].as_str().unwrap_or_default())
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(Value::Null);
                if sealed["key"] != name || sealed["context"] != body["context"] {
                    return refuse(
                        StatusCode::BAD_REQUEST,
                        "decryption failed: ciphertext is not authentic",
                    );
                }
                reply(StatusCode::OK, &json!({ "plaintext": sealed["plaintext"] }))
            }
            _ => refuse(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
        }
    }
}

/// A certificate authority and a server certificate for 127.0.0.1 it signed, PEM.
struct Certs {
    ca: String,
    server: String,
    server_key: String,
}

fn certs() -> Certs {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "fake KES CA");
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let server_key = rcgen::KeyPair::generate().unwrap();
    let server = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .signed_by(&server_key, &issuer)
        .unwrap();
    Certs {
        ca: ca_cert.pem(),
        server: server.pem(),
        server_key: server_key.serialize_pem(),
    }
}

/// Starts a fake KES server; its URL, its CA and its state.
async fn fake_kes() -> (String, String, Arc<Mutex<FakeKes>>) {
    let certs = certs();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(Arc::new(AnyClient(provider)))
        .with_single_cert(
            CertificateDer::pem_slice_iter(certs.server.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            PrivateKeyDer::from_pem_slice(certs.server_key.as_bytes()).unwrap(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(FakeKes::default()));
    let kes = state.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let (acceptor, kes) = (acceptor.clone(), kes.clone());
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(socket).await else {
                    return;
                };
                let identity = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| {
                        let (_, parsed) = x509_parser::parse_x509_certificate(c).unwrap();
                        hex_sha256(parsed.tbs_certificate.subject_pki.raw)
                    })
                    .unwrap_or_default();
                let service = service_fn(move |req: Request<Incoming>| {
                    let (kes, identity) = (kes.clone(), identity.clone());
                    async move {
                        let method = req.method().as_str().to_owned();
                        let path = req.uri().path().to_owned();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let answer = kes.lock().unwrap().call(&identity, &method, &path, &json);
                        Ok::<_, Infallible>(answer)
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (url, certs.ca, state)
}

/// An API key from a seed: KES's format, `kes:v1:` and base64 of a zero and the seed.
fn api_key(seed: u8) -> KesAuth {
    let mut bytes = vec![0u8];
    bytes.extend([seed; 32]);
    KesAuth::ApiKey(Zeroizing::new(format!("kes:v1:{}", STANDARD.encode(bytes))))
}

fn ctx(object: &str) -> Context {
    Context::object("drive", "bucket", object)
}

#[test]
fn api_keys_give_kes_identities() {
    // kes-go's documented identities for its example keys.
    for (key, identity) in [
        (EXAMPLE_KEY, EXAMPLE_IDENTITY),
        (
            "kes:v1:ACQpoGqx3rHHjT938Hfu5hVVQJHZWSqVI2Xp1KlYxFVw",
            "0426fa9a04bc2756b92fbe8a97e1a1e07b53ecf04ed33da22c33e5c9faeb8cbb",
        ),
        (
            "kes:v1:AMxvd2uV1l5dDSRwuKZxSjuM5BDemlr+685+JAHA1TuJ",
            "ab785e3b95d80d72cc9c27cb9fde886a0bf9068a69d40e3bd08a54e68c3f2bf7",
        ),
    ] {
        let (chain, _) = certificate_for(key).unwrap();
        assert_eq!(identity_of(&chain).unwrap(), identity, "{key}");
        let kms = KesKms::new(
            &["https://kes.example:7373"],
            KesAuth::ApiKey(Zeroizing::new(format!(" {key}\n"))),
            None,
        )
        .unwrap();
        assert_eq!(kms.identity(), identity);
    }
}

#[test]
fn api_key_certificates_are_for_client_authentication() {
    let (chain, key) = certificate_for(EXAMPLE_KEY).unwrap();
    let der = CertificateDer::pem_slice_iter(&chain)
        .next()
        .unwrap()
        .unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let common_name = cert.subject().iter_common_name().next().unwrap();
    assert_eq!(common_name.as_str().unwrap(), EXAMPLE_IDENTITY);
    let usage = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(usage.client_auth && !usage.server_auth);
    assert!(cert.key_usage().unwrap().unwrap().value.digital_signature());
    assert!(String::from_utf8_lossy(&key).contains("PRIVATE KEY"));
}

#[test]
fn wrong_api_keys_are_refused() {
    for wrong in [
        "v1:AM0F5TP43FYEShMzA42f2drFYGnBOiNx7UH4DK0nm08E",
        "kes:AM0F5TP43FYEShMzA42f2drFYGnBOiNx7UH4DK0nm08E",
        // Not type 0 (Ed25519).
        "kes:v1:sbDvZFqUPFFwxRS4EkuoEb2nyyInkdKSUEYHXFHeTouW",
        // Too short.
        "kes:v1:AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NA=",
        "kes:v1:not base64!",
    ] {
        assert!(
            matches!(certificate_for(wrong), Err(CryptoError::Kms(m)) if m.contains("isn't a KES API key")),
            "{wrong}"
        );
    }
}

#[test]
fn endpoints_are_https_urls_without_users() {
    for wrong in [
        "http://kes.example:7373",
        "kes.example:7373",
        "https://user:pass@kes.example:7373",
        "https://user@kes.example:7373",
    ] {
        assert!(KesKms::new(&[wrong], api_key(1), None).is_err(), "{wrong}");
    }
    assert!(KesKms::new(&[], api_key(1), None).is_err());
    let kms = KesKms::new(
        &["https://kes.example:7373/kes", "https://kes2.example:7373/"],
        api_key(1),
        None,
    )
    .unwrap();
    assert_eq!(
        kms.endpoints(),
        [
            "https://kes.example:7373/kes/",
            "https://kes2.example:7373/"
        ]
    );
    assert_eq!(
        url(&kms.endpoints[0], "encrypt", "a b/c").as_str(),
        "https://kes.example:7373/kes/v1/key/encrypt/a%20b%2Fc"
    );
    assert_eq!(
        url(&kms.endpoints[1], "list", "*").as_str(),
        "https://kes2.example:7373/v1/key/list/*"
    );
}

/// An https URL nothing listens on.
fn dead_endpoint() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("https://{}", listener.local_addr().unwrap())
}

#[tokio::test]
async fn calls_fail_over_to_the_next_server() {
    let (live, ca, state) = fake_kes().await;
    let dead = dead_endpoint();
    let kms = KesKms::new(&[&dead, &live], api_key(7), Some(ca.as_bytes())).unwrap();
    kms.create_key("photos").await.unwrap();
    assert_eq!(kms.current.load(Ordering::Relaxed), 1);
    let (key, sealed) = kms.generate(Some("photos"), &ctx("o")).await.unwrap();
    assert_eq!(kms.unseal(&sealed, &ctx("o")).await.unwrap(), key);
    assert_eq!(state.lock().unwrap().seen.len(), 4);
    // Calls start at the server that answered last, not the first one.
    let (other, other_ca, other_state) = fake_kes().await;
    let cas = format!("{ca}{other_ca}");
    let kms = KesKms::new(&[&other, &live], api_key(7), Some(cas.as_bytes())).unwrap();
    kms.current.store(1, Ordering::Relaxed);
    kms.keys().await.unwrap();
    assert!(other_state.lock().unwrap().seen.is_empty());
    assert!(state.lock().unwrap().seen.len() > 4);
    // With none reachable, the call fails.
    let kms = KesKms::new(&[&dead, &dead_endpoint()], api_key(7), None).unwrap();
    assert!(matches!(
        kms.keys().await,
        Err(CryptoError::Kms(m)) if m.starts_with("can't reach KES")
    ));
}

#[tokio::test]
async fn seals_through_kes_bound_to_the_context() {
    let (url, ca, state) = fake_kes().await;
    let kms = KesKms::new(&[&url], api_key(7), Some(ca.as_bytes())).unwrap();
    kms.create_key(DEFAULT_KEY).await.unwrap();
    let (key, sealed) = kms.generate(None, &ctx("o1")).await.unwrap();
    assert_eq!(sealed.provider, KES);
    assert_eq!(
        (sealed.kms_key.as_str(), sealed.kms_version),
        (DEFAULT_KEY, 1)
    );
    assert_eq!(kms.unseal(&sealed, &ctx("o1")).await.unwrap(), key);
    // KES saw the identity the backend reports.
    assert!(
        state
            .lock()
            .unwrap()
            .seen
            .iter()
            .all(|s| s == kms.identity())
    );
    // Another object's context doesn't open it.
    assert!(matches!(
        kms.unseal(&sealed, &ctx("o2")).await,
        Err(CryptoError::Authentication)
    ));
    // Nor another provider's seal, nor TeiFS's own unsealing.
    let transit = SealedKey {
        provider: crate::TRANSIT.to_owned(),
        ..sealed.clone()
    };
    assert!(matches!(
        kms.unseal(&transit, &ctx("o1")).await,
        Err(CryptoError::Kms(m)) if m.contains("KES")
    ));
    assert!(crate::unseal(&[0; 32], &ctx("o1"), &sealed).is_err());
}

#[tokio::test]
async fn keys_are_created_and_listed_but_not_rotated() {
    let (url, ca, _) = fake_kes().await;
    let kms = KesKms::new(&[&url], api_key(7), Some(ca.as_bytes())).unwrap();
    let created = kms.create_key("photos").await.unwrap();
    assert_eq!(
        (created.name.as_str(), created.version, created.created_ms),
        ("photos", 1, 1_788_256_800_123)
    );
    assert!(matches!(
        kms.create_key("photos").await,
        Err(CryptoError::KeyExists(name)) if name == "photos"
    ));
    assert!(kms.create_key("not/a name").await.is_err());
    kms.create_key("audio").await.unwrap();
    let keys = kms.keys().await.unwrap();
    let listed: Vec<_> = keys.iter().map(|k| (k.name.as_str(), k.version)).collect();
    assert_eq!(listed, [("audio", 1), ("photos", 1)]);
    assert!(matches!(
        kms.rotate_key("photos").await,
        Err(CryptoError::Kms(m)) if m.contains("can't be rotated")
    ));
}

#[tokio::test]
async fn missing_keys_are_reported_by_name() {
    let (url, ca, _) = fake_kes().await;
    let kms = KesKms::new(&[&url], api_key(7), Some(ca.as_bytes())).unwrap();
    assert!(kms.keys().await.unwrap().is_empty());
    assert!(matches!(
        kms.generate(Some("typo"), &ctx("o")).await,
        Err(CryptoError::NoSuchKey(name)) if name == "typo"
    ));
}

#[tokio::test]
async fn identities_kes_doesnt_allow_are_refused() {
    let (url, ca, state) = fake_kes().await;
    let allowed = KesKms::new(&[&url], api_key(1), Some(ca.as_bytes())).unwrap();
    state.lock().unwrap().allowed = vec![allowed.identity().to_owned()];
    allowed.create_key("photos").await.unwrap();
    let other = KesKms::new(&[&url], api_key(2), Some(ca.as_bytes())).unwrap();
    assert_ne!(other.identity(), allowed.identity());
    assert!(matches!(
        other.generate(Some("photos"), &ctx("o")).await,
        Err(CryptoError::Kms(m)) if m.contains("403") && m.contains("not authorized")
    ));
}

#[tokio::test]
async fn certificate_files_sign_in_too() {
    let (url, ca, state) = fake_kes().await;
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key).unwrap();
    let kms = KesKms::new(
        &[&url],
        KesAuth::Certificate {
            chain: cert.pem().into_bytes(),
            key: Zeroizing::new(key.serialize_pem().into_bytes()),
        },
        Some(ca.as_bytes()),
    )
    .unwrap();
    kms.create_key("photos").await.unwrap();
    assert_eq!(
        state.lock().unwrap().seen,
        vec![kms.identity().to_owned(); 2]
    );
    assert!(
        KesKms::new(
            &[&url],
            KesAuth::Certificate {
                chain: b"no certificate".to_vec(),
                key: Zeroizing::new(key.serialize_pem().into_bytes()),
            },
            None,
        )
        .is_err()
    );
}

#[tokio::test]
async fn servers_are_verified() {
    let (url, _, _) = fake_kes().await;
    let other_ca = certs().ca;
    let kms = KesKms::new(&[&url], api_key(7), Some(other_ca.as_bytes())).unwrap();
    assert!(matches!(
        kms.create_key("photos").await,
        Err(CryptoError::Kms(m)) if m.starts_with("can't reach KES")
    ));
}
