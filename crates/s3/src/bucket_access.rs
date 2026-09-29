//! Bucket policies and Block Public Access. [`Rules`] is what every request's decision
//! reads of a bucket: its policy, parsed, whether the policy is public, the bucket's
//! Block Public Access settings, its Object Ownership and its ACL. It's read from the store once and kept until the drive
//! changes one of them.

use std::{
    collections::HashMap,
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use s3s::{S3Error, S3ErrorCode, S3Result, dto, s3_error};
use teifs_policy::{Kind, Policy};
use teifs_store::{Acl, BucketAccess, ObjectOwnership, PublicAccessBlock, Store, StoreError};

use crate::errors::from_store;

/// The largest bucket policy AWS accepts, in bytes.
pub(crate) const MAX_POLICY_BYTES: usize = 20 * 1024;

/// What a bucket's own settings say about who may reach it.
#[derive(Debug, Default)]
pub(crate) struct BucketRules {
    /// The bucket policy.
    pub(crate) policy: Option<Arc<Policy>>,
    /// Whether the policy is public.
    pub(crate) public: bool,
    /// The Block Public Access settings in force: the bucket's and the account's, each
    /// setting on where either has it (none when neither has any).
    pub(crate) block: PublicAccessBlock,
    /// Its Object Ownership: a bucket made before the setting existed has ACLs, as
    /// `ObjectWriter`.
    pub(crate) ownership: ObjectOwnership,
    /// Its ACL, kept while ACLs are disabled so enabling them brings it back.
    pub(crate) acl: Option<Acl>,
    /// Its tags, while they decide access (ABAC is on): `aws:ResourceTag` and
    /// `s3:BucketTag` for everything in it. None while ABAC is off.
    pub(crate) resource_tags: Option<crate::tagging::Tags>,
}

impl BucketRules {
    fn read(bucket: &str, access: BucketAccess) -> Self {
        let policy = access.policy.map(|text| {
            Arc::new(Policy::parse(&text, Kind::Resource).unwrap_or_else(|err| {
                // Only policies that parsed were stored: a newer TeiFS's, or a damaged
                // database. Refuse everything but the root user's rescue.
                tracing::error!(bucket, %err, "the bucket's policy can't be read; denying access");
                Policy::parse(DENY_ALL, Kind::Resource).expect("the deny-all policy parses")
            }))
        });
        Self {
            public: policy.as_deref().is_some_and(Policy::is_public),
            policy,
            block: access
                .public_access_block
                .unwrap_or_default()
                .or(access.account_public_access_block.unwrap_or_default()),
            ownership: access.ownership.unwrap_or(ObjectOwnership::ObjectWriter),
            acl: access.acl,
            resource_tags: access.abac_tags,
        }
    }

    /// Whether ACLs grant anything: Object Ownership enables them and `IgnorePublicAcls`
    /// is off (every grant that changes access is public).
    pub(crate) fn acls_apply(&self) -> bool {
        self.ownership.acls_enabled() && !self.block.ignore_public_acls
    }

    /// Whether `RestrictPublicBuckets` is in force: the setting is on and the policy is
    /// public, so the policy grants nothing to anyone outside the account.
    pub(crate) fn restricted(&self) -> bool {
        self.public && self.block.restrict_public_buckets
    }
}

const DENY_ALL: &str = r#"{"Version": "2012-10-17", "Statement": {"Effect": "Deny",
    "Principal": "*", "Action": "*", "Resource": "*"}}"#;

/// Every bucket's [`BucketRules`], read once.
#[derive(Debug)]
pub(crate) struct Rules {
    store: Store,
    /// Moves on whenever an entry is forgotten, so a read that raced a change doesn't
    /// keep what it read.
    generation: AtomicU64,
    cache: RwLock<HashMap<Box<str>, Arc<BucketRules>>>,
}

impl Rules {
    pub(crate) fn new(store: Store) -> Self {
        Self {
            store,
            generation: AtomicU64::new(0),
            cache: RwLock::default(),
        }
    }

    /// A bucket's rules; none for a bucket that doesn't exist (and those aren't kept, so
    /// names that don't exist can't fill the cache).
    pub(crate) async fn of(&self, bucket: &str) -> S3Result<Arc<BucketRules>> {
        if let Some(rules) = self
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(bucket)
        {
            return Ok(Arc::clone(rules));
        }
        let generation = self.generation.load(Ordering::Acquire);
        let access = match self.store.bucket_access(bucket).await {
            Ok(access) => access,
            Err(StoreError::NoSuchBucket) => return Ok(Arc::default()),
            Err(err) => return Err(from_store(err)),
        };
        let rules = Arc::new(BucketRules::read(bucket, access));
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        if self.generation.load(Ordering::Acquire) == generation {
            cache.insert(bucket.into(), Arc::clone(&rules));
        }
        Ok(rules)
    }

    /// Forgets a bucket's rules, after they changed in the store.
    pub(crate) fn forget(&self, bucket: &str) {
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        self.generation.fetch_add(1, Ordering::AcqRel);
        cache.remove(bucket);
    }

    /// Forgets every bucket's rules, after the account's settings changed.
    pub(crate) fn forget_all(&self) {
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        self.generation.fetch_add(1, Ordering::AcqRel);
        cache.clear();
    }
}

/// Reads a bucket policy to store for `bucket`, refusing what AWS refuses.
pub(crate) fn parse_policy(bucket: &str, text: &str) -> S3Result<Policy> {
    let malformed = |message: String| S3Error::with_message(S3ErrorCode::MalformedPolicy, message);
    if text.len() > MAX_POLICY_BYTES {
        return Err(malformed(format!(
            "Policies must be at most {MAX_POLICY_BYTES} bytes; this one is {}.",
            text.len()
        )));
    }
    let policy = Policy::parse(text, Kind::Resource).map_err(|err| malformed(err.to_string()))?;
    policy
        .check_bucket(bucket)
        .map_err(|err| malformed(err.to_string()))?;
    Ok(policy)
}

pub(crate) fn no_policy() -> S3Error {
    s3_error!(NoSuchBucketPolicy, "The bucket policy does not exist")
}

pub(crate) fn no_public_access_block() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("NoSuchPublicAccessBlockConfiguration".into()),
        "The public access block configuration was not found",
    );
    err.set_status_code(http::StatusCode::NOT_FOUND);
    err
}

pub(crate) fn block_from_dto(config: &dto::PublicAccessBlockConfiguration) -> PublicAccessBlock {
    PublicAccessBlock {
        block_public_acls: config.block_public_acls.unwrap_or(false),
        ignore_public_acls: config.ignore_public_acls.unwrap_or(false),
        block_public_policy: config.block_public_policy.unwrap_or(false),
        restrict_public_buckets: config.restrict_public_buckets.unwrap_or(false),
    }
}

pub(crate) fn block_to_dto(block: PublicAccessBlock) -> dto::PublicAccessBlockConfiguration {
    dto::PublicAccessBlockConfiguration {
        block_public_acls: Some(block.block_public_acls),
        ignore_public_acls: Some(block.ignore_public_acls),
        block_public_policy: Some(block.block_public_policy),
        restrict_public_buckets: Some(block.restrict_public_buckets),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(policy: &str, block: Option<PublicAccessBlock>) -> BucketAccess {
        BucketAccess {
            policy: Some(policy.to_owned()),
            public_access_block: block,
            ..BucketAccess::default()
        }
    }

    const PUBLIC_READ: &str = r#"{"Version": "2012-10-17", "Statement": {"Effect": "Allow",
        "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}}"#;

    #[test]
    fn only_a_public_policy_is_restricted() {
        let rules = BucketRules::read("b", access(PUBLIC_READ, Some(PublicAccessBlock::ALL)));
        assert!(rules.public && rules.restricted());
        let open = BucketRules::read("b", access(PUBLIC_READ, None));
        assert!(open.public && !open.restricted());
        assert_eq!(open.block, PublicAccessBlock::default());
        let named = PUBLIC_READ.replace(r#""*""#, r#"{"AWS": "123456789012"}"#);
        let private = BucketRules::read("b", access(&named, Some(PublicAccessBlock::ALL)));
        assert!(!private.public && !private.restricted());
    }

    #[test]
    fn a_policy_that_no_longer_reads_denies_everything() {
        let rules = BucketRules::read("b", access(r#"{"Statement": "nonsense"}"#, None));
        let policy = rules.policy.unwrap();
        assert_eq!(policy.statement_count(), 1);
        assert!(!rules.public);
        let root = teifs_policy::Context::new(
            teifs_policy::Principal::root("123456789012"),
            teifs_policy::Date::from_unix_seconds(0),
        );
        let decision = teifs_policy::evaluate(
            &teifs_policy::Policies {
                resource: Some(&policy),
                ..teifs_policy::Policies::default()
            },
            &teifs_policy::Request {
                action: "s3:GetObject",
                resource: "arn:aws:s3:::b/k",
                context: &root,
            },
        );
        assert_eq!(decision, teifs_policy::Decision::ExplicitDeny);
    }

    #[test]
    fn policies_are_checked_for_their_bucket_and_size() {
        assert!(parse_policy("b", PUBLIC_READ).is_ok());
        let code =
            |bucket: &str, text: &str| parse_policy(bucket, text).unwrap_err().code().clone();
        assert_eq!(code("other", PUBLIC_READ), S3ErrorCode::MalformedPolicy);
        assert_eq!(code("b", "{"), S3ErrorCode::MalformedPolicy);
        let identity = PUBLIC_READ.replace(r#""Principal": "*", "#, "");
        assert_eq!(code("b", &identity), S3ErrorCode::MalformedPolicy);
        let padded = PUBLIC_READ.replace(
            "\"Version\"",
            &format!("{}\"Version\"", " ".repeat(MAX_POLICY_BYTES)),
        );
        assert_eq!(code("b", &padded), S3ErrorCode::MalformedPolicy);
        let just_fits = PUBLIC_READ.replace(
            "\"Version\"",
            &format!(
                "{}\"Version\"",
                " ".repeat(MAX_POLICY_BYTES - PUBLIC_READ.len())
            ),
        );
        assert!(parse_policy("b", &just_fits).is_ok());
    }

    #[tokio::test]
    async fn rules_are_kept_until_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let rules = Rules::new(store.clone());
        let cached = || rules.cache.read().unwrap().len();
        // Names that aren't buckets aren't kept.
        assert!(rules.of("nope").await.unwrap().policy.is_none());
        assert_eq!(cached(), 0);
        store
            .create_bucket("bkt", teifs_store::Layout::Object)
            .await
            .unwrap();
        let first = rules.of("bkt").await.unwrap();
        assert_eq!(
            (first.policy.is_none(), first.block),
            (true, PublicAccessBlock::ALL)
        );
        assert!(Arc::ptr_eq(&first, &rules.of("bkt").await.unwrap()));
        store
            .set_bucket_policy("bkt", Some(PUBLIC_READ.to_owned()))
            .await
            .unwrap();
        assert!(
            rules.of("bkt").await.unwrap().policy.is_none(),
            "until forgotten"
        );
        rules.forget("bkt");
        let second = rules.of("bkt").await.unwrap();
        assert!(second.public && second.restricted());
        assert_eq!(cached(), 1);

        // The account's settings apply with the bucket's, once every bucket is forgotten.
        store
            .set_bucket_public_access_block("bkt", None)
            .await
            .unwrap();
        let account = PublicAccessBlock {
            ignore_public_acls: true,
            ..PublicAccessBlock::default()
        };
        store
            .set_account_public_access_block(Some(account))
            .await
            .unwrap();
        assert!(
            rules.of("bkt").await.unwrap().restricted(),
            "until forgotten"
        );
        rules.forget_all();
        assert_eq!(cached(), 0);
        let third = rules.of("bkt").await.unwrap();
        assert_eq!(third.block, account);
        assert!(!third.restricted());
    }

    #[test]
    fn missing_settings_read_as_off() {
        let config = dto::PublicAccessBlockConfiguration {
            block_public_policy: Some(true),
            ..Default::default()
        };
        let block = block_from_dto(&config);
        assert_eq!(
            block,
            PublicAccessBlock {
                block_public_policy: true,
                ..PublicAccessBlock::default()
            }
        );
        assert_eq!(
            block_from_dto(&block_to_dto(PublicAccessBlock::ALL)),
            PublicAccessBlock::ALL
        );
    }
}
