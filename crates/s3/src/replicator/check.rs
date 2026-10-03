//! Whether a bucket's replication can work (`MinIO`'s `?replication-check`): the bucket
//! is versioned and has rules, and each enabled rule's destination is there, versioned,
//! has Object Lock when the bucket does, and takes the replicator's writes and deletes.
//! A target on another service is asked with `MinIO`'s check header, which a receiver
//! refuses once its access check lets the request through, without writing
//! ([`crate::replica_headers::refuse_check`]).

use std::collections::BTreeSet;

use teifs_store::{Store, StoreError, Versioning};
use teifs_types::replication::LOCAL_ARN;

use super::{Missed, remote};

/// Why a bucket's replication can't work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unready {
    /// The bucket isn't versioned.
    NotVersioned,
    /// It has no replication configuration.
    NoConfig,
    /// A rule's destination isn't a target any more: the rule's id.
    StaleTarget(String),
    /// A destination bucket isn't versioned: its name.
    TargetNotVersioned(String),
    /// A destination bucket has no Object Lock, which the bucket has: its name.
    TargetUnlocked(String),
    /// Anything else: why.
    Invalid(String),
}

impl From<StoreError> for Unready {
    fn from(err: StoreError) -> Self {
        Self::Invalid(err.to_string())
    }
}

impl From<Missed> for Unready {
    fn from(missed: Missed) -> Self {
        match missed {
            Missed::Failed(why) | Missed::Later(why) | Missed::Unreachable(why) => {
                Self::Invalid(why)
            }
        }
    }
}

/// Checks that `bucket`'s replication can work, each destination once.
pub(crate) async fn check(store: &Store, bucket: &str) -> Result<(), Unready> {
    if store.bucket_versioning(bucket).await? != Versioning::Enabled {
        return Err(Unready::NotVersioned);
    }
    let config = store
        .bucket_replication(bucket)
        .await?
        .ok_or(Unready::NoConfig)?;
    let locked = store.bucket_object_lock(bucket).await?.is_some();
    let mut checked = BTreeSet::new();
    for rule in config.rules.iter().filter(|rule| rule.enabled) {
        let arn = rule.destination.bucket.as_str();
        if !checked.insert(arn) {
            continue;
        }
        if let Some(local) = arn.strip_prefix(LOCAL_ARN) {
            check_local(store, local, locked).await?;
        } else if store.replication_target(arn).await?.is_none() {
            return Err(Unready::StaleTarget(rule.id.clone()));
        } else {
            remote::Target::of(store, arn).await?.check(locked).await?;
        }
    }
    Ok(())
}

/// Checks a destination on this server: there, versioned, with Object Lock when
/// `locked`.
async fn check_local(store: &Store, bucket: &str, locked: bool) -> Result<(), Unready> {
    match store.bucket_versioning(bucket).await {
        Ok(Versioning::Enabled) => {}
        Ok(_) => return Err(Unready::TargetNotVersioned(bucket.to_owned())),
        Err(StoreError::NoSuchBucket) => {
            return Err(Unready::Invalid(format!(
                "the destination bucket {bucket} doesn't exist"
            )));
        }
        Err(err) => return Err(err.into()),
    }
    if locked && store.bucket_object_lock(bucket).await?.is_none() {
        return Err(Unready::TargetUnlocked(bucket.to_owned()));
    }
    Ok(())
}
