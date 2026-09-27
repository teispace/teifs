//! Bucket settings kept in `system.db` (the `config` JSON of a bucket's record).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use teifs_meta::{BucketRecord, Layout};
use teifs_types::SseMode;

use crate::{Bucket, Inner, Store, StoreError, error::Result, now_ms};

/// A bucket's settings. Unknown fields from a newer TeiFS are kept.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BucketConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption: Option<BucketEncryption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tags: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cors: Option<Vec<CorsRule>>,
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

/// One rule of a bucket's CORS configuration; the first rule that matches a request
/// applies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorsRule {
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Origins it applies to; each may hold one `*`.
    pub allowed_origins: Vec<String>,
    /// Methods it allows (`GET`, `PUT`, `POST`, `DELETE`, `HEAD`).
    pub allowed_methods: Vec<String>,
    /// Headers a preflight request may ask for; each may hold one `*`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_headers: Vec<String>,
    /// Response headers scripts may read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose_headers: Vec<String>,
    /// How long browsers may cache a preflight answer, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<i32>,
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
                inner.update_config(&name, |config| config.encryption = encryption)
            }
        })
        .await
    }

    /// A bucket's tags, if it has any.
    pub async fn bucket_tags(&self, bucket: &str) -> Result<Option<BTreeMap<String, String>>> {
        Ok(self.config(bucket).await?.tags)
    }

    /// A bucket's CORS rules, if it has any.
    pub async fn bucket_cors(&self, bucket: &str) -> Result<Option<Vec<CorsRule>>> {
        Ok(self.config(bucket).await?.cors)
    }

    /// Replaces a bucket's CORS rules; `None` removes them.
    pub async fn set_bucket_cors(&self, bucket: &str, rules: Option<Vec<CorsRule>>) -> Result<()> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            inner.update_config(&name, |config| config.cors = rules)
        })
        .await
    }

    async fn config(&self, bucket: &str) -> Result<BucketConfig> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            read_config(inner.system().bucket_config(&name)?.as_deref())
        })
        .await
    }

    /// Replaces a bucket's tags; `None` removes them.
    pub async fn set_bucket_tags(
        &self,
        bucket: &str,
        tags: Option<BTreeMap<String, String>>,
    ) -> Result<()> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            inner.update_config(&name, |config| config.tags = tags)
        })
        .await
    }
}

impl Inner {
    /// Changes a bucket's settings. A folder bucket made outside TeiFS gets its record.
    fn update_config(&self, name: &str, change: impl FnOnce(&mut BucketConfig)) -> Result<()> {
        let system = self.system();
        if system.bucket(name)?.is_none() {
            system.record_bucket(&BucketRecord {
                id: uuid::Uuid::new_v4().simple().to_string(),
                name: name.to_owned(),
                layout: Layout::Folder,
                created_ms: now_ms(),
            })?;
        }
        let mut config = read_config(system.bucket_config(name)?.as_deref())?;
        change(&mut config);
        let json = serde_json::to_string(&config).expect("the config serializes");
        if !system.set_bucket_config(name, &json)? {
            return Err(StoreError::NoSuchBucket);
        }
        Ok(())
    }
}

fn read_config(json: Option<&str>) -> Result<BucketConfig> {
    match json {
        None => Ok(BucketConfig::default()),
        Some(json) => serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata),
    }
}
