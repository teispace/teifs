//! Bucket settings kept in `system.db` (the `config` JSON of a bucket's record).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use teifs_meta::{BucketRecord, Layout};
use teifs_types::{Acl, SseMode};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_access_block: Option<PublicAccessBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ownership: Option<ObjectOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acl: Option<Acl>,
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

/// S3 Block Public Access: what a bucket refuses to make public, and whether it ignores
/// what already is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "S3's four independent settings, as its API names them"
)]
pub struct PublicAccessBlock {
    /// Writes that give an object a public ACL are refused.
    pub block_public_acls: bool,
    /// Public ACLs grant nothing.
    pub ignore_public_acls: bool,
    /// A public bucket policy is refused.
    pub block_public_policy: bool,
    /// While the bucket's policy is public, it grants nothing to anyone outside the
    /// account: anonymous requests are refused.
    pub restrict_public_buckets: bool,
}

impl PublicAccessBlock {
    /// Every setting on: what every new bucket has, as on AWS since 2023-04.
    pub const ALL: Self = Self {
        block_public_acls: true,
        ignore_public_acls: true,
        block_public_policy: true,
        restrict_public_buckets: true,
    };

    /// Each setting on where either is: what applies when both the account and a bucket
    /// have settings (the most restrictive).
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self {
            block_public_acls: self.block_public_acls || other.block_public_acls,
            ignore_public_acls: self.ignore_public_acls || other.ignore_public_acls,
            block_public_policy: self.block_public_policy || other.block_public_policy,
            restrict_public_buckets: self.restrict_public_buckets || other.restrict_public_buckets,
        }
    }
}

/// The name the account's Block Public Access settings are kept under.
const ACCOUNT_PUBLIC_ACCESS_BLOCK: &str = "accountPublicAccessBlock";

/// S3 Object Ownership: whether a bucket's ACLs are enabled, and who owns objects others
/// write (in a one-account drive, always the account).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectOwnership {
    /// ACLs are disabled: they neither grant nor can be set. Every new bucket's.
    #[default]
    BucketOwnerEnforced,
    /// ACLs are enabled; the bucket owner owns objects written with
    /// `bucket-owner-full-control`.
    BucketOwnerPreferred,
    /// ACLs are enabled; the writer owns what it writes. Buckets without the setting.
    ObjectWriter,
}

impl ObjectOwnership {
    /// Every setting, as S3 names them.
    pub const ALL: [Self; 3] = [
        Self::BucketOwnerEnforced,
        Self::BucketOwnerPreferred,
        Self::ObjectWriter,
    ];

    /// S3's name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BucketOwnerEnforced => "BucketOwnerEnforced",
            Self::BucketOwnerPreferred => "BucketOwnerPreferred",
            Self::ObjectWriter => "ObjectWriter",
        }
    }

    /// The setting S3 names so.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.name() == name)
    }

    /// Whether ACLs are in force.
    #[must_use]
    pub const fn acls_enabled(self) -> bool {
        !matches!(self, Self::BucketOwnerEnforced)
    }
}

/// What decides who may reach a bucket, read together.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BucketAccess {
    /// The bucket policy, as it was given.
    pub policy: Option<String>,
    /// The bucket's Block Public Access settings.
    pub public_access_block: Option<PublicAccessBlock>,
    /// The bucket's Object Ownership setting; none for a bucket made before TeiFS had
    /// them, which behaves as [`ObjectOwnership::ObjectWriter`], as on AWS.
    pub ownership: Option<ObjectOwnership>,
    /// The bucket's ACL; none is private.
    pub acl: Option<Acl>,
    /// The account's Block Public Access settings, which apply with the bucket's.
    pub account_public_access_block: Option<PublicAccessBlock>,
}

/// How a new bucket starts, beyond its layout. The default is AWS's: ACLs disabled and
/// Block Public Access on, which a folder bucket made outside TeiFS gets too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBucket {
    /// Its Object Ownership setting; none leaves ACLs enabled with no setting, as on
    /// buckets S3 made before April 2023.
    pub ownership: Option<ObjectOwnership>,
    /// Whether all four Block Public Access settings start on; off, it has none.
    pub block_public_access: bool,
    /// Its ACL (the caller checks it against the ownership); none is private.
    pub acl: Option<Acl>,
}

impl Default for NewBucket {
    fn default() -> Self {
        Self {
            ownership: Some(ObjectOwnership::default()),
            block_public_access: true,
            acl: None,
        }
    }
}

fn new_bucket(options: NewBucket) -> BucketConfig {
    BucketConfig {
        public_access_block: options
            .block_public_access
            .then_some(PublicAccessBlock::ALL),
        ownership: options.ownership,
        acl: options.acl,
        ..BucketConfig::default()
    }
}

/// A new bucket's settings, to record with it.
pub(crate) fn new_bucket_config(options: NewBucket) -> String {
    serde_json::to_string(&new_bucket(options)).expect("the config serializes")
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
            Bucket::Object(_) => inner.update_config(&name, |config| {
                config.encryption = encryption;
                Ok(())
            }),
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
        self.change_config(bucket, move |config| config.cors = rules)
            .await
    }

    /// What decides who may reach a bucket: its policy, Block Public Access settings,
    /// Object Ownership and ACL, and the account's Block Public Access settings.
    pub async fn bucket_access(&self, bucket: &str) -> Result<BucketAccess> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            let system = inner.system();
            let config = read_config(system.bucket_config(&name)?.as_deref())?;
            Ok(BucketAccess {
                policy: config.policy,
                public_access_block: config.public_access_block,
                ownership: config.ownership,
                acl: config.acl,
                account_public_access_block: account_block(&system)?,
            })
        })
        .await
    }

    /// The account's Block Public Access settings, if it has any.
    pub async fn account_public_access_block(&self) -> Result<Option<PublicAccessBlock>> {
        self.blocking(|inner| account_block(&inner.system())).await
    }

    /// Replaces the account's Block Public Access settings; `None` removes them.
    pub async fn set_account_public_access_block(
        &self,
        block: Option<PublicAccessBlock>,
    ) -> Result<()> {
        let json = block.map(|b| serde_json::to_string(&b).expect("the settings serialize"));
        self.blocking(move |inner| {
            Ok(inner
                .system()
                .set_setting(ACCOUNT_PUBLIC_ACCESS_BLOCK, json.as_deref())?)
        })
        .await
    }

    /// Replaces a bucket's policy (checked by the caller); `None` removes it.
    pub async fn set_bucket_policy(&self, bucket: &str, policy: Option<String>) -> Result<()> {
        self.change_config(bucket, move |config| config.policy = policy)
            .await
    }

    /// Replaces a bucket's Object Ownership setting; `None` removes it (the bucket then
    /// has ACLs, as `ObjectWriter`). ACLs can only be disabled while the bucket's ACL
    /// grants only the owner ([`StoreError::AclGrantsOthers`]).
    pub async fn set_bucket_ownership(
        &self,
        bucket: &str,
        ownership: Option<ObjectOwnership>,
    ) -> Result<()> {
        self.try_change_config(bucket, move |config| {
            let disables = ownership.is_some_and(|o| !o.acls_enabled());
            if disables && !config.acl.as_ref().is_none_or(Acl::owner_only) {
                return Err(StoreError::AclGrantsOthers);
            }
            config.ownership = ownership;
            Ok(())
        })
        .await
    }

    /// Replaces a bucket's ACL; `None` makes it private. Refused while the bucket's
    /// Object Ownership disables ACLs ([`StoreError::AclsDisabled`]).
    pub async fn set_bucket_acl(&self, bucket: &str, acl: Option<Acl>) -> Result<()> {
        self.try_change_config(bucket, move |config| {
            if !config.ownership.is_none_or(ObjectOwnership::acls_enabled) {
                return Err(StoreError::AclsDisabled);
            }
            config.acl = acl;
            Ok(())
        })
        .await
    }

    /// Replaces a bucket's Block Public Access settings; `None` removes them.
    pub async fn set_bucket_public_access_block(
        &self,
        bucket: &str,
        block: Option<PublicAccessBlock>,
    ) -> Result<()> {
        self.change_config(bucket, move |config| config.public_access_block = block)
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
        self.change_config(bucket, move |config| config.tags = tags)
            .await
    }

    /// Changes an existing bucket's settings.
    async fn change_config(
        &self,
        bucket: &str,
        change: impl FnOnce(&mut BucketConfig) + Send + 'static,
    ) -> Result<()> {
        self.try_change_config(bucket, |config| {
            change(config);
            Ok(())
        })
        .await
    }

    /// Changes a bucket's settings if `change` succeeds, as one step: nothing else
    /// changes them in between.
    async fn try_change_config(
        &self,
        bucket: &str,
        change: impl FnOnce(&mut BucketConfig) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            inner.update_config(&name, change)
        })
        .await
    }
}

impl Inner {
    /// Changes a bucket's settings. A folder bucket made outside TeiFS gets its record.
    fn update_config(
        &self,
        name: &str,
        change: impl FnOnce(&mut BucketConfig) -> Result<()>,
    ) -> Result<()> {
        let system = self.system();
        if system.bucket(name)?.is_none() {
            system.record_bucket(
                &BucketRecord {
                    id: uuid::Uuid::new_v4().simple().to_string(),
                    name: name.to_owned(),
                    layout: Layout::Folder,
                    created_ms: now_ms(),
                },
                &new_bucket_config(NewBucket::default()),
            )?;
        }
        let mut config = read_config(system.bucket_config(name)?.as_deref())?;
        change(&mut config)?;
        let json = serde_json::to_string(&config).expect("the config serializes");
        if !system.set_bucket_config(name, &json)? {
            return Err(StoreError::NoSuchBucket);
        }
        Ok(())
    }
}

fn account_block(system: &teifs_meta::System) -> Result<Option<PublicAccessBlock>> {
    system
        .setting(ACCOUNT_PUBLIC_ACCESS_BLOCK)?
        .map(|json| serde_json::from_str(&json).map_err(|_| StoreError::CorruptMetadata))
        .transpose()
}

fn read_config(json: Option<&str>) -> Result<BucketConfig> {
    match json {
        None => Ok(new_bucket(NewBucket::default())),
        Some(json) => serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata),
    }
}
