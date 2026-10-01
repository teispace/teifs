//! Bucket settings kept in `system.db` (the `config` JSON of a bucket's record).

use std::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize, Serialize};
use teifs_meta::{BucketRecord, Layout, Versioning};
use teifs_types::{
    Acl, SseMode,
    configs::{Configurations, Kind, MAX_CONFIGURATIONS},
    logging::LoggingConfig,
    notify::NotificationConfig,
    website::WebsiteConfig,
};

use crate::{
    Bucket, Inner, Store, StoreError, error::Result, folder::FolderBucket, lifecycle::Lifecycle,
    lock::ObjectLock, now_ms,
};

/// What the names of background tasks' notes start with, apart from other settings.
const NOTE: &str = "note.";

/// Why a bucket's tags can't be replaced or deleted as a whole.
const ABAC_TAGS: &str = "The bucket's tags decide access (ABAC is enabled): change them with \
                         TagResource and UntagResource";

/// A bucket's settings. Unknown fields from a newer TeiFS are kept.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BucketConfig {
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
    /// Whether the bucket's tags decide access (S3's ABAC), which also means only
    /// `TagResource` and `UntagResource` change them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    abac: bool,
    /// Its Object Lock, once turned on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) object_lock: Option<ObjectLock>,
    /// Its lifecycle rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) lifecycle: Option<Lifecycle>,
    /// Its notification rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notifications: Option<NotificationConfig>,
    /// Where its access log goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logging: Option<LoggingConfig>,
    /// How its website endpoint answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    website: Option<WebsiteConfig>,
    /// The most bytes it may hold (`MinIO`'s hard quota).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quota: Option<u64>,
    /// Requester Pays and its inventory, analytics, metrics and Intelligent-Tiering
    /// configurations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    configurations: Option<Configurations>,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

/// A bucket's settings, all together, under the names an export gives them. `None`
/// (or `false`) is a setting the bucket doesn't have.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketSettings {
    /// Its own encryption settings (without, an object bucket has the store's default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<BucketEncryption>,
    /// Its tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    /// Its CORS rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<Vec<CorsRule>>,
    /// Its policy, as it was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Its Block Public Access settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_access_block: Option<PublicAccessBlock>,
    /// Its Object Ownership setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<ObjectOwnership>,
    /// Its ACL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<Acl>,
    /// Whether its tags decide access (S3's ABAC).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub abac: bool,
    /// Its Object Lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_lock: Option<ObjectLock>,
    /// Its lifecycle rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<Lifecycle>,
    /// Its notification rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<NotificationConfig>,
    /// Where its access log goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingConfig>,
    /// How its website endpoint answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<WebsiteConfig>,
    /// The most bytes it may hold (`MinIO`'s hard quota).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<u64>,
    /// Requester Pays and its inventory, analytics, metrics and Intelligent-Tiering
    /// configurations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configurations: Option<Configurations>,
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
    /// The bucket's tags when they decide access (ABAC is on); none otherwise.
    pub abac_tags: Option<BTreeMap<String, String>>,
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
    /// Its tags (checked by the caller); none has none.
    pub tags: Option<BTreeMap<String, String>>,
    /// Whether it starts with Object Lock on (and so versioning enabled), with no
    /// default retention.
    pub object_lock: bool,
}

impl Default for NewBucket {
    fn default() -> Self {
        Self {
            ownership: Some(ObjectOwnership::default()),
            block_public_access: true,
            acl: None,
            tags: None,
            object_lock: false,
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
        tags: options.tags,
        object_lock: options.object_lock.then(ObjectLock::default),
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

    /// All of a bucket's settings.
    pub async fn bucket_settings(&self, bucket: &str) -> Result<BucketSettings> {
        let config = self.config(bucket).await?;
        Ok(BucketSettings {
            encryption: config.encryption,
            tags: config.tags,
            cors: config.cors,
            policy: config.policy,
            public_access_block: config.public_access_block,
            ownership: config.ownership,
            acl: config.acl,
            abac: config.abac,
            object_lock: config.object_lock,
            lifecycle: config.lifecycle,
            notifications: config.notifications,
            logging: config.logging,
            website: config.website,
            quota: config.quota,
            configurations: config.configurations,
        })
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

    /// A bucket's notification rules, if it has any; from memory once read.
    pub async fn bucket_notifications(
        &self,
        bucket: &str,
    ) -> Result<Option<Arc<NotificationConfig>>> {
        if let Some(found) = self.inner.notifications.cached(bucket) {
            return Ok(found);
        }
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            inner.notifications.get(&name, || {
                Ok(read_config(inner.system().bucket_config(&name)?.as_deref())?.notifications)
            })
        })
        .await
    }

    /// Replaces a bucket's notification rules (checked by the caller); `None`, or no rules
    /// and EventBridge off, removes them.
    pub async fn set_bucket_notifications(
        &self,
        bucket: &str,
        rules: Option<NotificationConfig>,
    ) -> Result<()> {
        let rules = rules.filter(|config| !config.is_empty());
        self.change_config(bucket, move |config| config.notifications = rules)
            .await
    }

    /// Where a bucket's access log goes, if anywhere; from memory once read.
    pub async fn bucket_logging(&self, bucket: &str) -> Result<Option<Arc<LoggingConfig>>> {
        if let Some(found) = self.inner.logging.cached(bucket) {
            return Ok(found);
        }
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            inner.logging.get(&name, || {
                Ok(read_config(inner.system().bucket_config(&name)?.as_deref())?.logging)
            })
        })
        .await
    }

    /// Whether any bucket logs its requests (reads every bucket's settings: for a start).
    pub async fn any_bucket_logging(&self) -> Result<bool> {
        for bucket in self.list_buckets().await? {
            match self.bucket_logging(&bucket.name).await {
                Ok(Some(_)) => return Ok(true),
                Ok(None) | Err(StoreError::NoSuchBucket) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(false)
    }

    /// Whether any bucket's requests are counted, for request metrics or a storage class
    /// analysis that exports (reads every bucket's configurations: for a start).
    pub async fn any_bucket_counting_requests(&self) -> Result<bool> {
        for bucket in self.list_buckets().await? {
            match self.bucket_configurations(&bucket.name).await {
                Ok(configurations) if configurations.counts_requests() => return Ok(true),
                Ok(_) | Err(StoreError::NoSuchBucket) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(false)
    }

    /// Replaces where a bucket's access log goes (checked by the caller); `None` stops it.
    pub async fn set_bucket_logging(
        &self,
        bucket: &str,
        logging: Option<LoggingConfig>,
    ) -> Result<()> {
        self.change_config(bucket, move |config| config.logging = logging)
            .await
    }

    /// How a bucket's website endpoint answers, if it's a website; from memory once
    /// read.
    pub async fn bucket_website(&self, bucket: &str) -> Result<Option<Arc<WebsiteConfig>>> {
        if let Some(found) = self.inner.websites.cached(bucket) {
            return Ok(found);
        }
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            inner.websites.get(&name, || {
                Ok(read_config(inner.system().bucket_config(&name)?.as_deref())?.website)
            })
        })
        .await
    }

    /// Replaces a bucket's website configuration (checked by the caller); `None`
    /// removes it.
    pub async fn set_bucket_website(
        &self,
        bucket: &str,
        website: Option<WebsiteConfig>,
    ) -> Result<()> {
        self.change_config(bucket, move |config| config.website = website)
            .await
    }

    /// The most bytes a bucket may hold, if it has a quota; from memory once read.
    pub async fn bucket_quota(&self, bucket: &str) -> Result<Option<u64>> {
        if let Some(found) = self.inner.quotas.cached(bucket) {
            return Ok(found.map(|quota| *quota));
        }
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            let quota = inner.quotas.get(&name, || {
                Ok(read_config(inner.system().bucket_config(&name)?.as_deref())?.quota)
            })?;
            Ok(quota.map(|quota| *quota))
        })
        .await
    }

    /// Sets the most bytes a bucket may hold; `None` removes its quota.
    pub async fn set_bucket_quota(&self, bucket: &str, quota: Option<u64>) -> Result<()> {
        self.change_config(bucket, move |config| config.quota = quota)
            .await
    }

    /// How long a day is for the drive's schedules (lifecycle rules, reports): a real
    /// day, except on drives opened for tests with a shorter one.
    #[must_use]
    pub fn day_ms(&self) -> i64 {
        self.inner.day_ms
    }

    /// A note a background task keeps with the drive's metadata (when it last did
    /// something, say), by name; `None` when there's none.
    pub async fn note(&self, name: &str) -> Result<Option<String>> {
        let name = format!("{NOTE}{name}");
        self.blocking(move |inner| Ok(inner.system().setting(&name)?))
            .await
    }

    /// Keeps a background task's note; `None` removes it.
    pub async fn set_note(&self, name: &str, value: Option<String>) -> Result<()> {
        let name = format!("{NOTE}{name}");
        self.blocking(move |inner| Ok(inner.system().set_setting(&name, value.as_deref())?))
            .await
    }

    /// A bucket's Requester Pays setting and its inventory, analytics, metrics and
    /// Intelligent-Tiering configurations; from memory once read.
    pub async fn bucket_configurations(&self, bucket: &str) -> Result<Arc<Configurations>> {
        if let Some(found) = self.inner.configurations.cached(bucket) {
            return Ok(found.unwrap_or_default());
        }
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            let found = inner.configurations.get(&name, || {
                Ok(read_config(inner.system().bucket_config(&name)?.as_deref())?.configurations)
            })?;
            Ok(found.unwrap_or_default())
        })
        .await
    }

    /// Replaces all of a bucket's configurations (an import); empty removes them.
    pub async fn set_bucket_configurations(
        &self,
        bucket: &str,
        configurations: Configurations,
    ) -> Result<()> {
        self.change_config(bucket, move |config| {
            config.configurations = (!configurations.is_empty()).then_some(configurations);
        })
        .await
    }

    /// Sets whether a bucket's requesters pay.
    pub async fn set_requester_pays(&self, bucket: &str, requester_pays: bool) -> Result<()> {
        self.change_configurations(bucket, move |configurations| {
            configurations.requester_pays = requester_pays;
            Ok(())
        })
        .await
    }

    /// Adds or replaces one of a bucket's configurations: `put` changes the set of that
    /// kind. A new one beyond [`MAX_CONFIGURATIONS`] of its kind is refused
    /// ([`StoreError::TooManyConfigurations`]).
    pub async fn put_configuration(
        &self,
        bucket: &str,
        kind: Kind,
        id: &str,
        put: impl FnOnce(&mut Configurations) + Send + 'static,
    ) -> Result<()> {
        let id = id.to_owned();
        self.change_configurations(bucket, move |configurations| {
            let (count, exists) = configurations.count(kind, &id);
            if !exists && count >= MAX_CONFIGURATIONS {
                return Err(StoreError::TooManyConfigurations);
            }
            put(configurations);
            Ok(())
        })
        .await
    }

    /// Removes one of a bucket's configurations; `false` when it had none by that id.
    pub async fn delete_configuration(&self, bucket: &str, kind: Kind, id: &str) -> Result<bool> {
        let id = id.to_owned();
        let (sender, removed) = std::sync::mpsc::channel();
        self.change_configurations(bucket, move |configurations| {
            let _ = sender.send(configurations.remove(kind, &id));
            Ok(())
        })
        .await?;
        Ok(removed.try_recv().unwrap_or(false))
    }

    async fn change_configurations(
        &self,
        bucket: &str,
        change: impl FnOnce(&mut Configurations) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        self.try_change_config(bucket, move |config| {
            let mut configurations = config.configurations.take().unwrap_or_default();
            let result = change(&mut configurations);
            config.configurations = (!configurations.is_empty()).then_some(configurations);
            result
        })
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
                abac_tags: config.abac.then(|| config.tags.unwrap_or_default()),
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

    /// Replaces a bucket's Object Ownership setting and ACL together, so one can change
    /// what the other allows: refused when the ownership disables ACLs and the ACL
    /// grants others ([`StoreError::AclGrantsOthers`]).
    pub async fn set_bucket_ownership_and_acl(
        &self,
        bucket: &str,
        ownership: Option<ObjectOwnership>,
        acl: Option<Acl>,
    ) -> Result<()> {
        self.try_change_config(bucket, move |config| {
            let disables = ownership.is_some_and(|o| !o.acls_enabled());
            if disables && !acl.as_ref().is_none_or(Acl::owner_only) {
                return Err(StoreError::AclGrantsOthers);
            }
            config.ownership = ownership;
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

    /// Replaces a bucket's tags; `None` removes them. Refused while ABAC is on, when
    /// only [`Self::tag_bucket`] and [`Self::untag_bucket`] change them, as on AWS.
    pub async fn set_bucket_tags(
        &self,
        bucket: &str,
        tags: Option<BTreeMap<String, String>>,
    ) -> Result<()> {
        self.try_change_config(bucket, move |config| {
            if config.abac {
                return Err(StoreError::InvalidRequest(ABAC_TAGS));
            }
            config.tags = tags;
            Ok(())
        })
        .await
    }

    /// Adds `tags` to a bucket's, replacing the values of keys it has; refused when that
    /// would make more than `max` ([`StoreError::TooManyTags`]).
    pub async fn tag_bucket(
        &self,
        bucket: &str,
        tags: BTreeMap<String, String>,
        max: usize,
    ) -> Result<()> {
        self.try_change_config(bucket, move |config| {
            let mut all = config.tags.take().unwrap_or_default();
            all.extend(tags);
            if all.len() > max {
                return Err(StoreError::TooManyTags(max));
            }
            config.tags = Some(all).filter(|all| !all.is_empty());
            Ok(())
        })
        .await
    }

    /// Removes the tags with these keys from a bucket; keys it doesn't have are ignored.
    pub async fn untag_bucket(&self, bucket: &str, keys: Vec<String>) -> Result<()> {
        self.change_config(bucket, move |config| {
            if let Some(tags) = &mut config.tags {
                for key in &keys {
                    tags.remove(key);
                }
            }
            config.tags = config.tags.take().filter(|tags| !tags.is_empty());
        })
        .await
    }

    /// Whether a bucket's tags decide access (S3's ABAC status).
    pub async fn bucket_abac(&self, bucket: &str) -> Result<bool> {
        Ok(self.config(bucket).await?.abac)
    }

    /// Turns a bucket's ABAC on or off.
    pub async fn set_bucket_abac(&self, bucket: &str, enabled: bool) -> Result<()> {
        self.change_config(bucket, move |config| config.abac = enabled)
            .await
    }

    /// A bucket's versioning.
    pub async fn bucket_versioning(&self, bucket: &str) -> Result<Versioning> {
        let name = bucket.to_owned();
        self.blocking(move |inner| match inner.bucket(&name)? {
            Bucket::Object(bucket) => Ok(bucket.versioning),
            Bucket::Folder(bucket) => Ok(bucket.versioning()),
        })
        .await
    }

    /// Turns a bucket's versioning on, or suspends it. As on S3, a bucket that has had
    /// versioning never goes back to having none. In a folder bucket the current versions
    /// stay the plain files; older ones are kept in the drive's system folder.
    pub async fn set_bucket_versioning(&self, bucket: &str, versioning: Versioning) -> Result<()> {
        if versioning == Versioning::Unversioned {
            return Err(StoreError::InvalidRequest(
                "versioning can only be enabled or suspended",
            ));
        }
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            // Under the commit lock, so no write sees the bucket half-changed.
            let _lock = inner.lock();
            let bucket = inner.bucket(&name)?;
            if versioning == Versioning::Suspended && inner.object_lock(bucket.versions())?.is_some()
            {
                return Err(StoreError::InvalidBucketState(
                    "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
                ));
            }
            if let Bucket::Folder(FolderBucket { versions: None, .. }) = bucket {
                // A folder made outside TeiFS gets its record, which names its versions.
                inner.update_config(&name, |_| Ok(()))?;
            }
            inner.system().set_bucket_versioning(&name, versioning)?;
            Ok(())
        })
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
    /// Forgets the settings kept in memory, after any bucket's change or a bucket goes.
    pub(crate) fn settings_changed(&self) {
        self.lifecycles.clear();
        self.notifications.clear();
        self.logging.clear();
        self.websites.clear();
        self.quotas.clear();
        self.configurations.clear();
    }

    /// Changes a bucket's settings. A folder bucket made outside TeiFS gets its record.
    pub(crate) fn update_config(
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
                    versioning: Versioning::Unversioned,
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
        drop(system);
        self.settings_changed();
        Ok(())
    }
}

fn account_block(system: &teifs_meta::System) -> Result<Option<PublicAccessBlock>> {
    system
        .setting(ACCOUNT_PUBLIC_ACCESS_BLOCK)?
        .map(|json| serde_json::from_str(&json).map_err(|_| StoreError::CorruptMetadata))
        .transpose()
}

pub(crate) fn read_config(json: Option<&str>) -> Result<BucketConfig> {
    match json {
        None => Ok(new_bucket(NewBucket::default())),
        Some(json) => serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata),
    }
}
