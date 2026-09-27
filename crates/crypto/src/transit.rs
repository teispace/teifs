//! A KMS backed by a Vault or OpenBao transit engine: TeiFS generates each data key and
//! the engine seals it, with the object's context as associated data (AES-256-GCM keys),
//! so a sealed key opens only for its own object. The engine's key versions and rotation
//! carry over; its token is read from the environment, never a command line.

use std::{collections::HashSet, sync::Mutex};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::json;

use crate::{Context, CryptoError, DEFAULT_KEY, DataKey, KeyInfo, Kms, Result, SealedKey};

/// The provider name recorded in keys this backend seals.
pub const TRANSIT: &str = "transit";

/// A Vault or OpenBao transit engine.
pub struct TransitKms {
    client: reqwest::Client,
    /// `https://vault.example:8200/v1/<mount>`.
    base: String,
    token: zeroize::Zeroizing<String>,
    namespace: Option<String>,
    /// Keys known to exist (the engine's encrypt would create a missing one).
    known: Mutex<HashSet<String>>,
}

impl std::fmt::Debug for TransitKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitKms")
            .field("base", &self.base)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
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
struct KeyList {
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct KeyData {
    latest_version: u32,
    #[serde(default)]
    keys: std::collections::BTreeMap<String, serde_json::Value>,
}

impl TransitKms {
    /// A transit engine at `address` (e.g. `https://vault:8200`), mounted at `mount`
    /// (usually `transit`), authenticated with `token`, in an optional namespace.
    pub fn new(
        address: &str,
        mount: &str,
        token: String,
        namespace: Option<String>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| CryptoError::Kms(e.to_string()))?;
        Ok(Self {
            client,
            base: format!(
                "{}/v1/{}",
                address.trim_end_matches('/'),
                mount.trim_matches('/')
            ),
            token: zeroize::Zeroizing::new(token),
            namespace,
            known: Mutex::new(HashSet::new()),
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut builder = self
            .client
            .request(method, format!("{}/{path}", self.base))
            .header("X-Vault-Token", self.token.as_str());
        if let Some(namespace) = &self.namespace {
            builder = builder.header("X-Vault-Namespace", namespace);
        }
        builder
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
        key: &str,
    ) -> Result<Option<T>> {
        let response = builder
            .send()
            .await
            .map_err(|e| CryptoError::Kms(format!("can't reach the transit engine: {e}")))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CryptoError::NoSuchKey(key.to_owned()));
        }
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(CryptoError::Kms(format!(
                "transit engine: {status}: {text}"
            )));
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        let body = response
            .json::<Envelope<T>>()
            .await
            .map_err(|e| CryptoError::Kms(format!("transit engine: {e}")))?;
        Ok(Some(body.data))
    }

    async fn key_data(&self, name: &str) -> Result<KeyData> {
        self.send(
            self.request(reqwest::Method::GET, &format!("keys/{name}")),
            name,
        )
        .await?
        .ok_or_else(|| CryptoError::NoSuchKey(name.to_owned()))
    }

    /// Fails with `NoSuchKey` unless the key exists (checked once, then remembered).
    async fn ensure_exists(&self, name: &str) -> Result<()> {
        if self.known().contains(name) {
            return Ok(());
        }
        self.key_data(name).await?;
        self.known().insert(name.to_owned());
        Ok(())
    }

    fn known(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.known
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The key version in a transit ciphertext (`vault:v3:…` → 3).
fn version_of(ciphertext: &str) -> Result<u32> {
    ciphertext
        .split(':')
        .nth(1)
        .and_then(|v| v.strip_prefix('v'))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| CryptoError::Kms("the transit engine returned an unknown ciphertext".into()))
}

fn created_ms(data: &KeyData) -> i64 {
    data.keys
        .get(&data.latest_version.to_string())
        .and_then(serde_json::Value::as_i64)
        .map_or(0, |secs| secs.saturating_mul(1000))
}

#[async_trait::async_trait]
impl Kms for TransitKms {
    async fn generate(&self, key: Option<&str>, context: &Context) -> Result<(DataKey, SealedKey)> {
        let name = key.unwrap_or(DEFAULT_KEY);
        self.ensure_exists(name).await?;
        let data_key = DataKey::generate();
        let body = json!({
            "plaintext": STANDARD.encode(data_key.bytes()),
            "associated_data": STANDARD.encode(context.canonical()),
        });
        let sealed: Ciphertext = self
            .send(
                self.request(reqwest::Method::POST, &format!("encrypt/{name}"))
                    .json(&body),
                name,
            )
            .await?
            .ok_or_else(|| CryptoError::Kms("the transit engine returned nothing".into()))?;
        let version = version_of(&sealed.ciphertext)?;
        Ok((
            data_key,
            SealedKey {
                version: 1,
                provider: TRANSIT.to_owned(),
                kms_key: name.to_owned(),
                kms_version: version,
                salt: Vec::new(),
                sealed: sealed.ciphertext.into_bytes(),
            },
        ))
    }

    async fn unseal(&self, sealed: &SealedKey, context: &Context) -> Result<DataKey> {
        if sealed.provider != TRANSIT {
            return Err(CryptoError::Kms(
                "the key wasn't sealed by the transit engine".into(),
            ));
        }
        let ciphertext =
            String::from_utf8(sealed.sealed.clone()).map_err(|_| CryptoError::Authentication)?;
        let body = json!({
            "ciphertext": ciphertext,
            "associated_data": STANDARD.encode(context.canonical()),
        });
        let plain: Plaintext = self
            .send(
                self.request(
                    reqwest::Method::POST,
                    &format!("decrypt/{}", sealed.kms_key),
                )
                .json(&body),
                &sealed.kms_key,
            )
            .await
            .map_err(|e| match e {
                // The engine answers 400 when the associated data doesn't match.
                CryptoError::Kms(_) => CryptoError::Authentication,
                other => other,
            })?
            .ok_or(CryptoError::Authentication)?;
        let bytes = zeroize::Zeroizing::new(
            STANDARD
                .decode(plain.plaintext)
                .map_err(|_| CryptoError::Authentication)?,
        );
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Authentication)?;
        Ok(DataKey::from_bytes(key))
    }

    async fn keys(&self) -> Result<Vec<KeyInfo>> {
        let method = reqwest::Method::from_bytes(b"LIST").expect("LIST is a valid method");
        let list: Option<KeyList> = match self.send(self.request(method, "keys"), "").await {
            Err(CryptoError::NoSuchKey(_)) => None,
            other => other?,
        };
        let mut out = Vec::new();
        for name in list.map(|l| l.keys).unwrap_or_default() {
            let data = self.key_data(&name).await?;
            out.push(KeyInfo {
                version: data.latest_version,
                created_ms: created_ms(&data),
                name,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn create_key(&self, name: &str) -> Result<KeyInfo> {
        match self.key_data(name).await {
            Ok(_) => {
                return Err(CryptoError::Kms(format!(
                    "a key named {name} already exists"
                )));
            }
            Err(CryptoError::NoSuchKey(_)) => {}
            Err(err) => return Err(err),
        }
        let body = json!({ "type": "aes256-gcm96" });
        self.send::<serde_json::Value>(
            self.request(reqwest::Method::POST, &format!("keys/{name}"))
                .json(&body),
            name,
        )
        .await?;
        let data = self.key_data(name).await?;
        self.known().insert(name.to_owned());
        Ok(KeyInfo {
            name: name.to_owned(),
            version: data.latest_version,
            created_ms: created_ms(&data),
        })
    }

    async fn rotate_key(&self, name: &str) -> Result<KeyInfo> {
        self.send::<serde_json::Value>(
            self.request(reqwest::Method::POST, &format!("keys/{name}/rotate")),
            name,
        )
        .await?;
        let data = self.key_data(name).await?;
        Ok(KeyInfo {
            name: name.to_owned(),
            version: data.latest_version,
            created_ms: created_ms(&data),
        })
    }
}

#[cfg(test)]
mod tests;
