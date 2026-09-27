//! Bucket settings kept in `system.db` (the `config` JSON of a bucket's record).

use serde::{Deserialize, Serialize};
use teifs_types::SseMode;

use crate::{Bucket, Store, StoreError, error::Result};

/// A bucket's settings. Unknown fields from a newer TeiFS are kept.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BucketConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption: Option<BucketEncryption>,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

/// How a bucket encrypts objects written without asking, and which encryption it
/// refuses (S3's bucket encryption configuration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketEncryption {
    /// What objects written without asking get.
    pub default: DefaultEncryption,
    /// Whether writes that ask for SSE-C are refused (S3's `BlockedEncryptionTypes`).
    pub block_customer_keys: bool,
}

/// The encryption objects get by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultEncryption {
    /// SSE-S3 or SSE-KMS.
    pub mode: SseMode,
    /// The KMS key for SSE-KMS (the managed key when `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key: Option<String>,
    /// S3 Bucket Keys (fewer KMS calls); recorded and reported.
    #[serde(default)]
    pub bucket_key: bool,
}

impl BucketEncryption {
    /// What every new bucket has on AWS since 2026-04: SSE-S3, SSE-C blocked.
    #[must_use]
    pub fn aws_default() -> Self {
        Self {
            default: DefaultEncryption {
                mode: SseMode::S3,
                kms_key: None,
                bucket_key: false,
            },
            block_customer_keys: true,
        }
    }
}

impl Store {
    /// A bucket's encryption settings: `None` for a folder bucket (its objects are plain
    /// files); an object bucket without its own settings has the store's default
    /// ([`BucketEncryption::aws_default`] unless the store was opened with another).
    pub async fn bucket_encryption(&self, bucket: &str) -> Result<Option<BucketEncryption>> {
        let name = bucket.to_owned();
        self.blocking(move |inner| match inner.bucket(&name)? {
            Bucket::Folder(..) => Ok(None),
            Bucket::Object(_) => {
                let config = read_config(inner.system().bucket_config(&name)?.as_deref())?;
                Ok(Some(
                    config
                        .encryption
                        .unwrap_or_else(|| inner.default_encryption.clone()),
                ))
            }
        })
        .await
    }

    /// Replaces an object bucket's encryption settings; `None` goes back to the default.
    pub async fn set_bucket_encryption(
        &self,
        bucket: &str,
        encryption: Option<BucketEncryption>,
    ) -> Result<()> {
        let name = bucket.to_owned();
        self.blocking(move |inner| match inner.bucket(&name)? {
            Bucket::Folder(..) => Err(StoreError::InvalidRequest(
                "encryption at rest needs an object bucket",
            )),
            Bucket::Object(_) => {
                let system = inner.system();
                let mut config = read_config(system.bucket_config(&name)?.as_deref())?;
                config.encryption = encryption;
                let json = serde_json::to_string(&config).expect("the config serializes");
                if !system.set_bucket_config(&name, &json)? {
                    return Err(StoreError::NoSuchBucket);
                }
                Ok(())
            }
        })
        .await
    }
}

fn read_config(json: Option<&str>) -> Result<BucketConfig> {
    match json {
        None => Ok(BucketConfig::default()),
        Some(json) => serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata),
    }
}
