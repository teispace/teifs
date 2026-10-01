//! A KMS backed by a MinIO KES server: TeiFS generates each data key and KES encrypts it
//! under a named key, with the object's context as associated data, so a sealed key
//! opens only for its own object. TeiFS proves who it is with a client certificate: one
//! derived from a KES API key (`kes:v1:…`, read from the environment, never a command
//! line), or a certificate and key file. KES identifies it by the SHA-256 of that
//! certificate's public key, which [`KesKms::identity`] shows for KES's policy.
//!
//! KES keys have no versions TeiFS can see and can't be rotated over its API: every seal
//! is at version 1.

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    Context, CryptoError, DEFAULT_KEY, DataKey, KeyInfo, Kms, Result, SealedKey, kms::check_name,
    tls_config,
};

/// The provider name recorded in keys this backend seals.
pub const KES: &str = "kes";

/// How long a call to KES may take.
const TIMEOUT: Duration = Duration::from_secs(30);

/// How TeiFS proves who it is to KES.
pub enum KesAuth {
    /// A KES API key, `kes:v1:` and a base64 Ed25519 seed.
    ApiKey(Zeroizing<String>),
    /// A client certificate chain and its private key, both PEM.
    Certificate {
        /// The chain, the client's certificate first.
        chain: Vec<u8>,
        /// The private key.
        key: Zeroizing<Vec<u8>>,
    },
}

/// A KES server, or several serving the same keys (each call goes to the one that last
/// answered, and on to the next when one can't be reached).
pub struct KesKms {
    client: reqwest::Client,
    /// `https://kes.example:7373/`, ….
    endpoints: Vec<reqwest::Url>,
    /// The endpoint that last answered.
    current: AtomicUsize,
    identity: String,
}

impl std::fmt::Debug for KesKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KesKms")
            .field("endpoints", &self.endpoints())
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Ciphertext {
    ciphertext: String,
}

#[derive(Deserialize)]
struct Plaintext {
    plaintext: String,
}

#[derive(Deserialize)]
struct Names {
    #[serde(default)]
    names: Vec<String>,
}

#[derive(Deserialize)]
struct Description {
    #[serde(default)]
    created_at: Option<String>,
}

#[derive(Deserialize)]
struct Failure {
    message: String,
}

impl KesKms {
    /// The KES servers at `endpoints` (`https://…`, at least one), verified with the
    /// system's certificates or only `ca_pem`'s, signed in with `auth`.
    pub fn new(endpoints: &[&str], auth: KesAuth, ca_pem: Option<&[u8]>) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(CryptoError::Kms("KES needs a server's URL".to_owned()));
        }
        let endpoints = endpoints
            .iter()
            .map(|e| endpoint(e))
            .collect::<Result<Vec<_>>>()?;
        let (chain, key) = match auth {
            KesAuth::ApiKey(api_key) => certificate_for(&api_key)?,
            KesAuth::Certificate { chain, key } => (chain, key),
        };
        let identity = identity_of(&chain)?;
        let tls = tls_config(ca_pem, Some((&chain, &key))).map_err(CryptoError::Kms)?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured((*tls).clone())
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| CryptoError::Kms(e.to_string()))?;
        Ok(Self {
            client,
            endpoints,
            current: AtomicUsize::new(0),
            identity,
        })
    }

    /// TeiFS's identity at KES: the hex SHA-256 of its certificate's public key.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The endpoints.
    #[must_use]
    pub fn endpoints(&self) -> Vec<&str> {
        self.endpoints.iter().map(reqwest::Url::as_str).collect()
    }

    /// Calls `method /v1/key/<api>/<name>` with `body`; the answer, or `None` for one
    /// without a body. A 400 answer's message becomes the error `bad_request` makes of it.
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        (api, name): (&str, &str),
        body: Option<&serde_json::Value>,
        bad_request: fn(&str, String) -> CryptoError,
    ) -> Result<Option<T>> {
        let first = self.current.load(Ordering::Relaxed);
        let mut unreachable = None;
        let mut answer = None;
        for step in 0..self.endpoints.len() {
            let at = (first + step) % self.endpoints.len();
            let mut request = self
                .client
                .request(method.clone(), url(&self.endpoints[at], api, name));
            if let Some(body) = body {
                request = request.json(body);
            }
            match request.send().await {
                Ok(response) => {
                    self.current.store(at, Ordering::Relaxed);
                    answer = Some(response);
                    break;
                }
                Err(e) if e.is_connect() || e.is_timeout() => unreachable = Some(e),
                Err(e) => return Err(CryptoError::Kms(format!("can't reach KES: {}", why(&e)))),
            }
        }
        let Some(response) = answer else {
            let why = unreachable.map(|e| why(&e)).unwrap_or_default();
            return Err(CryptoError::Kms(format!("can't reach KES: {why}")));
        };
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|e| CryptoError::Kms(format!("KES's answer was cut short: {e}")))?;
        if !status.is_success() {
            let message = serde_json::from_slice::<Failure>(&body).map_or_else(
                |_| String::from_utf8_lossy(&body).into_owned(),
                |f| f.message,
            );
            return Err(match status {
                reqwest::StatusCode::NOT_FOUND => CryptoError::NoSuchKey(name.to_owned()),
                reqwest::StatusCode::BAD_REQUEST => bad_request(name, message),
                _ => CryptoError::Kms(format!("KES: {status}: {message}")),
            });
        }
        if body.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|e| CryptoError::Kms(format!("KES's answer isn't one: {e}")))
    }

    async fn created_ms(&self, name: &str) -> Result<i64> {
        let described: Option<Description> = self
            .call(reqwest::Method::GET, ("describe", name), None, failed)
            .await?;
        Ok(described
            .and_then(|d| d.created_at)
            .and_then(|at| {
                time::OffsetDateTime::parse(&at, &time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .map_or(0, |at| {
                i64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
            }))
    }
}

/// A KES server's URL: https, no user, ending in `/`.
fn endpoint(given: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(given.trim())
        .ok()
        .filter(|u| u.scheme() == "https" && u.host_str().is_some())
        .ok_or_else(|| CryptoError::Kms(format!("`{given}` isn't a KES server's https URL")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CryptoError::Kms(
            "KES takes a certificate, not a user in the URL".to_owned(),
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

/// `<endpoint>v1/key/<api>/<name>`.
fn url(endpoint: &reqwest::Url, api: &str, name: &str) -> reqwest::Url {
    let mut url = endpoint.clone();
    if let Ok(mut path) = url.path_segments_mut() {
        path.pop_if_empty().extend(["v1", "key", api, name]);
    }
    url
}

/// An error and what caused it, down to the root: reqwest's own message leaves out
/// whether DNS, TCP or TLS failed.
fn why(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !out.contains(&cause_text) {
            out.push_str(": ");
            out.push_str(&cause_text);
        }
        source = cause.source();
    }
    out
}

/// A refusal as KES words it.
#[expect(
    clippy::needless_pass_by_value,
    reason = "a `bad_request` for `call`, whose others keep the message"
)]
fn failed(_name: &str, message: String) -> CryptoError {
    CryptoError::Kms(format!("KES refused it: {message}"))
}

/// The self-signed client certificate and key a KES API key stands for: Ed25519, its
/// common name the identity, for client authentication, as KES's own clients make it.
fn certificate_for(api_key: &str) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    use rcgen::PublicKeyData as _;
    let wrong = || CryptoError::Kms("that isn't a KES API key (kes:v1:…)".to_owned());
    let encoded = api_key.trim().strip_prefix("kes:v1:").ok_or_else(wrong)?;
    let bytes = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| wrong())?);
    let [0, seed @ ..] = bytes.as_slice() else {
        return Err(wrong());
    };
    let pair =
        aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| wrong())?;
    let pkcs8 = pair.to_pkcs8v1().map_err(|_| wrong())?;
    let key = rcgen::KeyPair::try_from(pkcs8.as_ref()).map_err(|_| wrong())?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|_| wrong())?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        hex_sha256(&key.subject_public_key_info()),
    );
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let certificate = params
        .self_signed(&key)
        .map_err(|e| CryptoError::Kms(format!("can't make a certificate for the API key: {e}")))?;
    Ok((
        certificate.pem().into_bytes(),
        Zeroizing::new(key.serialize_pem().into_bytes()),
    ))
}

/// The identity KES gives the first certificate in `chain`.
fn identity_of(chain: &[u8]) -> Result<String> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let first = CertificateDer::pem_slice_iter(chain)
        .next()
        .and_then(std::result::Result::ok)
        .ok_or_else(|| CryptoError::Kms("the certificate file holds no certificate".to_owned()))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&first)
        .map_err(|_| CryptoError::Kms("the certificate can't be read".to_owned()))?;
    Ok(hex_sha256(parsed.tbs_certificate.subject_pki.raw))
}

fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[async_trait::async_trait]
impl Kms for KesKms {
    async fn seal(
        &self,
        key: Option<&str>,
        context: &Context,
        data_key: &DataKey,
    ) -> Result<SealedKey> {
        let name = key.unwrap_or(DEFAULT_KEY);
        let body = json!({
            "plaintext": STANDARD.encode(data_key.bytes()),
            "context": STANDARD.encode(context.canonical()),
        });
        let sealed: Ciphertext = self
            .call(reqwest::Method::PUT, ("encrypt", name), Some(&body), failed)
            .await?
            .ok_or_else(|| CryptoError::Kms("KES returned nothing".to_owned()))?;
        let ciphertext = STANDARD
            .decode(sealed.ciphertext)
            .map_err(|_| CryptoError::Kms("KES returned an unknown ciphertext".to_owned()))?;
        Ok(SealedKey {
            version: 1,
            provider: KES.to_owned(),
            kms_key: name.to_owned(),
            kms_version: 1,
            salt: Vec::new(),
            sealed: ciphertext,
        })
    }

    async fn unseal(&self, sealed: &SealedKey, context: &Context) -> Result<DataKey> {
        if sealed.provider != KES {
            return Err(CryptoError::Kms("the key wasn't sealed by KES".to_owned()));
        }
        let body = json!({
            "ciphertext": STANDARD.encode(&sealed.sealed),
            "context": STANDARD.encode(context.canonical()),
        });
        let name = &sealed.kms_key;
        let plain: Plaintext = self
            .call(
                reqwest::Method::PUT,
                ("decrypt", name),
                Some(&body),
                // KES answers 400 when the context or ciphertext doesn't match.
                |_, _| CryptoError::Authentication,
            )
            .await?
            .ok_or(CryptoError::Authentication)?;
        let bytes = Zeroizing::new(
            STANDARD
                .decode(plain.plaintext)
                .map_err(|_| CryptoError::Authentication)?,
        );
        DataKey::from_slice(&bytes)
    }

    async fn keys(&self) -> Result<Vec<KeyInfo>> {
        let listed: Option<Names> = self
            .call(reqwest::Method::GET, ("list", "*"), None, failed)
            .await?;
        let mut out = Vec::new();
        for name in listed.map(|l| l.names).unwrap_or_default() {
            out.push(KeyInfo {
                version: 1,
                created_ms: self.created_ms(&name).await?,
                name,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn create_key(&self, name: &str) -> Result<KeyInfo> {
        check_name(name)?;
        self.call::<serde_json::Value>(
            reqwest::Method::PUT,
            ("create", name),
            None,
            |name, message| {
                if message.contains("already exists") {
                    CryptoError::KeyExists(name.to_owned())
                } else {
                    failed(name, message)
                }
            },
        )
        .await?;
        Ok(KeyInfo {
            name: name.to_owned(),
            version: 1,
            created_ms: self.created_ms(name).await?,
        })
    }

    async fn rotate_key(&self, _name: &str) -> Result<KeyInfo> {
        Err(CryptoError::Kms(
            "KES keys can't be rotated: create a new key, make it the buckets' key \
             (`teifs encrypt set`) and move objects to it (`teifs encrypt update`)"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests;
