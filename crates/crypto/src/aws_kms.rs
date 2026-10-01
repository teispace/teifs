//! A KMS backed by AWS KMS (or a service that speaks its API, such as LocalStack): TeiFS
//! generates each data key and AWS KMS encrypts it under a symmetric key, with the
//! object's context as the encryption context, so a sealed key opens only for its own
//! object. Credentials come from the usual AWS places (environment, shared config and
//! SSO, container and instance roles, web identity), never a command line.
//!
//! TeiFS's key names are aliases: `photos` is `alias/photos`. Key ids, key ARNs and
//! `alias/…` names are used as they are. A key's version is one more than its completed
//! rotations, so `teifs key rewrap` can re-seal data keys under the newest material.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_sdk_kms::{
    Client,
    error::{DisplayErrorContext, ProvideErrorMetadata, SdkError},
    primitives::Blob,
    types::{KeySpec, KeyUsageType, Tag},
};

use crate::{
    Context, CryptoError, DEFAULT_KEY, DataKey, KeyInfo, Kms, Result, SealedKey, kms::check_name,
};

/// The provider name recorded in keys this backend seals.
pub const AWS_KMS: &str = "aws-kms";

/// How long a key's version is trusted before its rotations are counted again (AWS
/// rotates keys on its own schedule too).
const VERSION_FOR: Duration = Duration::from_hours(1);

/// AWS KMS.
pub struct AwsKms {
    client: Client,
    /// The region, for messages.
    region: String,
    /// Key name → its version and until when it's trusted.
    versions: Mutex<HashMap<String, (u32, Instant)>>,
}

impl std::fmt::Debug for AwsKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKms")
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl AwsKms {
    /// AWS KMS in `region` (else the one AWS's configuration names), at `endpoint` if one
    /// is given (`LocalStack`, a VPC endpoint), with credentials found the way AWS's SDKs
    /// find them.
    pub async fn from_environment(
        region: Option<String>,
        endpoint: Option<String>,
    ) -> Result<Self> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(aws_config::Region::new(region));
        }
        if let Some(endpoint) = endpoint {
            loader = loader.endpoint_url(endpoint);
        }
        let config = loader.load().await;
        let region = config
            .region()
            .ok_or_else(|| {
                CryptoError::Kms(
                    "it needs a region: give --kms-aws-region or set AWS_REGION".to_owned(),
                )
            })?
            .to_string();
        Ok(Self::with_client(Client::new(&config), region))
    }

    /// AWS KMS through `client`.
    #[must_use]
    pub fn with_client(client: Client, region: String) -> Self {
        Self {
            client,
            region,
            versions: Mutex::new(HashMap::new()),
        }
    }

    /// The region it's in.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    fn versions(&self) -> std::sync::MutexGuard<'_, HashMap<String, (u32, Instant)>> {
        self.versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The key `name` names: its id and ARN.
    async fn describe(
        &self,
        name: &str,
    ) -> Result<(String, Option<aws_sdk_kms::types::KeyMetadata>)> {
        let found = self
            .client
            .describe_key()
            .key_id(key_id(name))
            .send()
            .await
            .map_err(|e| failure(&e, name))?;
        let metadata = found.key_metadata;
        let id = metadata
            .as_ref()
            .map(|m| m.key_id.clone())
            .ok_or_else(|| CryptoError::NoSuchKey(name.to_owned()))?;
        Ok((id, metadata))
    }

    /// The newest version of the key with id `id`, one more than its completed
    /// rotations, and when the newest rotation was (0 for none). A key that can't be
    /// rotated, or whose rotations this identity may not list, is at version 1.
    async fn newest(&self, id: &str) -> Result<(u32, i64)> {
        let mut rotations = 0u32;
        let mut rotated_ms = 0;
        let mut marker = None;
        loop {
            let page = match self
                .client
                .list_key_rotations()
                .key_id(id)
                .limit(1000)
                .set_marker(marker)
                .send()
                .await
            {
                Ok(page) => page,
                Err(e)
                    if matches!(
                        e.code(),
                        Some("AccessDeniedException" | "UnsupportedOperationException")
                    ) =>
                {
                    return Ok((1, 0));
                }
                Err(e) => return Err(failure(&e, id)),
            };
            for rotation in page.rotations.unwrap_or_default() {
                rotations = rotations.saturating_add(1);
                rotated_ms = rotated_ms.max(millis(rotation.rotation_date.as_ref()));
            }
            match (page.truncated, page.next_marker) {
                (true, Some(next)) => marker = Some(next),
                _ => return Ok((rotations.saturating_add(1), rotated_ms)),
            }
        }
    }

    /// The version of `name`, counted at most once an hour.
    async fn version(&self, name: &str) -> Result<u32> {
        if let Some((version, until)) = self.versions().get(name)
            && Instant::now() < *until
        {
            return Ok(*version);
        }
        let (id, _) = self.describe(name).await?;
        let (version, _) = self.newest(&id).await?;
        self.versions()
            .insert(name.to_owned(), (version, Instant::now() + VERSION_FOR));
        Ok(version)
    }
}

/// The `KeyId` for a key name: ids, ARNs and aliases as they are, other names as aliases.
fn key_id(name: &str) -> String {
    if name.starts_with("arn:") || name.starts_with("alias/") || is_key_id(name) {
        name.to_owned()
    } else {
        format!("alias/{name}")
    }
}

/// Whether `name` is a key id: a UUID, or `mrk-` and 32 hex digits (multi-Region keys).
fn is_key_id(name: &str) -> bool {
    let hex = |s: &str| s.bytes().all(|b| b.is_ascii_hexdigit());
    if let Some(rest) = name.strip_prefix("mrk-") {
        return rest.len() == 32 && hex(rest);
    }
    let groups: Vec<&str> = name.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12]) && groups.iter().all(|g| hex(g))
}

/// AWS KMS's error as TeiFS's: a missing key, a seal that doesn't open, or a failure.
fn failure<E, R>(err: &SdkError<E, R>, name: &str) -> CryptoError
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    match err.code() {
        Some("NotFoundException") => CryptoError::NoSuchKey(name.to_owned()),
        Some("InvalidCiphertextException" | "IncorrectKeyException") => CryptoError::Authentication,
        Some(code) => CryptoError::Kms(format!(
            "AWS KMS: {code}: {}",
            err.message().unwrap_or("no message")
        )),
        None => CryptoError::Kms(format!("can't reach AWS KMS: {}", DisplayErrorContext(err))),
    }
}

/// An encryption context for AWS KMS (none when it's empty).
fn encryption_context(context: &Context) -> Option<HashMap<String, String>> {
    let pairs = context.pairs();
    (!pairs.is_empty()).then(|| pairs.clone().into_iter().collect())
}

fn millis(date: Option<&aws_sdk_kms::primitives::DateTime>) -> i64 {
    date.and_then(|d| d.to_millis().ok()).unwrap_or(0)
}

#[async_trait::async_trait]
impl Kms for AwsKms {
    async fn seal(
        &self,
        key: Option<&str>,
        context: &Context,
        data_key: &DataKey,
    ) -> Result<SealedKey> {
        let name = key.unwrap_or(DEFAULT_KEY);
        let version = self.version(name).await?;
        let sealed = self
            .client
            .encrypt()
            .key_id(key_id(name))
            .plaintext(Blob::new(data_key.bytes().to_vec()))
            .set_encryption_context(encryption_context(context))
            .send()
            .await
            .map_err(|e| failure(&e, name))?;
        let ciphertext = sealed
            .ciphertext_blob
            .ok_or_else(|| CryptoError::Kms("AWS KMS returned no ciphertext".to_owned()))?;
        Ok(SealedKey {
            version: 1,
            provider: AWS_KMS.to_owned(),
            kms_key: name.to_owned(),
            kms_version: version,
            salt: Vec::new(),
            sealed: ciphertext.into_inner(),
        })
    }

    async fn unseal(&self, sealed: &SealedKey, context: &Context) -> Result<DataKey> {
        if sealed.provider != AWS_KMS {
            return Err(CryptoError::Kms(
                "the key wasn't sealed by AWS KMS".to_owned(),
            ));
        }
        // The ciphertext names its key, so the alias may have moved since.
        let plain = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(sealed.sealed.clone()))
            .set_encryption_context(encryption_context(context))
            .send()
            .await
            .map_err(|e| failure(&e, &sealed.kms_key))?;
        let bytes = zeroize::Zeroizing::new(
            plain
                .plaintext
                .ok_or(CryptoError::Authentication)?
                .into_inner(),
        );
        DataKey::from_slice(&bytes)
    }

    async fn keys(&self) -> Result<Vec<KeyInfo>> {
        let mut out = Vec::new();
        let mut marker = None;
        loop {
            let page = self
                .client
                .list_aliases()
                .limit(100)
                .set_marker(marker)
                .send()
                .await
                .map_err(|e| failure(&e, ""))?;
            for alias in page.aliases.unwrap_or_default() {
                let (Some(name), Some(target)) = (
                    alias
                        .alias_name
                        .as_deref()
                        .and_then(|a| a.strip_prefix("alias/")),
                    alias.target_key_id.as_deref(),
                ) else {
                    continue;
                };
                if name.starts_with("aws/") {
                    continue;
                }
                let (version, rotated_ms) = self.newest(target).await?;
                // The newest version was made by the last rotation, else with the key.
                let created_ms = if rotated_ms > 0 {
                    rotated_ms
                } else {
                    let (_, metadata) = self.describe(target).await?;
                    millis(metadata.as_ref().and_then(|m| m.creation_date.as_ref()))
                };
                self.versions()
                    .insert(name.to_owned(), (version, Instant::now() + VERSION_FOR));
                out.push(KeyInfo {
                    name: name.to_owned(),
                    version,
                    created_ms,
                });
            }
            match (page.truncated, page.next_marker) {
                (true, Some(next)) => marker = Some(next),
                _ => break,
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn create_key(&self, name: &str) -> Result<KeyInfo> {
        check_name(name)?;
        match self.describe(name).await {
            Ok(_) => {
                return Err(CryptoError::KeyExists(name.to_owned()));
            }
            Err(CryptoError::NoSuchKey(_)) => {}
            Err(err) => return Err(err),
        }
        let tag = Tag::builder()
            .tag_key("teifs-key")
            .tag_value(name)
            .build()
            .map_err(|e| CryptoError::Kms(e.to_string()))?;
        let created = self
            .client
            .create_key()
            .description(format!("TeiFS key {name}"))
            .key_usage(KeyUsageType::EncryptDecrypt)
            .key_spec(KeySpec::SymmetricDefault)
            .tags(tag)
            .send()
            .await
            .map_err(|e| failure(&e, name))?;
        let metadata = created
            .key_metadata
            .ok_or_else(|| CryptoError::Kms("AWS KMS returned no key".to_owned()))?;
        if let Err(err) = self
            .client
            .create_alias()
            .alias_name(format!("alias/{name}"))
            .target_key_id(&metadata.key_id)
            .send()
            .await
        {
            // Another server took the name meanwhile: don't leave an unnamed key behind.
            let _ = self
                .client
                .schedule_key_deletion()
                .key_id(&metadata.key_id)
                .pending_window_in_days(7)
                .send()
                .await;
            return Err(match err.code() {
                Some("AlreadyExistsException") => {
                    CryptoError::KeyExists(name.to_owned())
                }
                _ => failure(&err, name),
            });
        }
        self.versions()
            .insert(name.to_owned(), (1, Instant::now() + VERSION_FOR));
        Ok(KeyInfo {
            name: name.to_owned(),
            version: 1,
            created_ms: millis(metadata.creation_date.as_ref()),
        })
    }

    async fn rotate_key(&self, name: &str) -> Result<KeyInfo> {
        let (id, _) = self.describe(name).await?;
        let (before, _) = self.newest(&id).await?;
        self.client
            .rotate_key_on_demand()
            .key_id(&id)
            .send()
            .await
            .map_err(|e| failure(&e, name))?;
        // The rotation finishes in the background. Until it's counted, data keys keep
        // being recorded at the old version, so a rewrap re-seals them at worst once more.
        self.versions().remove(name);
        Ok(KeyInfo {
            name: name.to_owned(),
            version: before.saturating_add(1),
            created_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)),
        })
    }
}

#[cfg(test)]
mod tests;
