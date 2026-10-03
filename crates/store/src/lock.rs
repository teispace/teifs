//! S3 Object Lock: a bucket's lock and default retention, and the rules that keep a
//! version from being removed while its retention or legal hold protects it.
//!
//! A version's lock is part of its attributes ([`ObjectAttrs::retention`] and
//! [`ObjectAttrs::legal_hold`]), so it travels wherever the version does (archived,
//! restored, listed). A copy never inherits it: it gets the request's, or the bucket's
//! default. Anything that can't be read fails closed: a damaged bucket setting refuses the
//! write, and a version's own lock is enforced without reading the bucket at all.

use serde::{Deserialize, Serialize};
use teifs_meta::Versioning;
use teifs_types::{
    LockMode, ObjectKey, Retention,
    replication::{ReplicationConfig, VersionReplication},
};

use crate::{
    Bucket, Inner, ObjectAttrs, ObjectInfo, Store, StoreError,
    error::Result,
    now_ms,
    objects::{Marking, ObjectBucket},
};

/// What a write gets when it asks for a lock in a bucket without Object Lock.
const NO_LOCK: &str = "Bucket is missing Object Lock Configuration";
/// The longest retention S3 allows, in days (100 years).
pub const MAX_RETENTION_DAYS: u32 = 36_500;
/// The longest retention S3 allows, in years.
pub const MAX_RETENTION_YEARS: u32 = 100;

/// A bucket's Object Lock, which once on stays on (as does its versioning).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectLock {
    /// The retention a new version gets when its write asks for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_retention: Option<DefaultRetention>,
}

/// A bucket's default retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultRetention {
    /// How new versions are protected.
    pub mode: LockMode,
    /// For how long, from each version's creation.
    pub period: RetentionPeriod,
}

/// How long a default retention lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RetentionPeriod {
    /// Whole days (1 to 36 500).
    Days(u32),
    /// Calendar years (1 to 100).
    Years(u32),
}

impl RetentionPeriod {
    /// Whether it's one S3 allows: at least one day or year, at most 100 years.
    #[must_use]
    pub fn is_valid(self) -> bool {
        match self {
            Self::Days(days) => (1..=MAX_RETENTION_DAYS).contains(&days),
            Self::Years(years) => (1..=MAX_RETENTION_YEARS).contains(&years),
        }
    }

    /// When a retention of this length that starts at `from_ms` ends. A year is a
    /// calendar year: 29 February becomes 28 February in a year without one.
    #[must_use]
    pub fn after(self, from_ms: i64) -> i64 {
        const DAY_MS: i64 = 86_400_000;
        match self {
            Self::Days(days) => from_ms.saturating_add(i64::from(days) * DAY_MS),
            Self::Years(years) => {
                let Ok(start) = time::OffsetDateTime::from_unix_timestamp_nanos(
                    i128::from(from_ms) * 1_000_000,
                ) else {
                    return i64::MAX;
                };
                let year = start
                    .year()
                    .saturating_add(i32::try_from(years).unwrap_or(i32::MAX));
                let end = start
                    .replace_year(year)
                    .or_else(|_| start.replace_day(28).and_then(|d| d.replace_year(year)));
                end.map_or(i64::MAX, |end| {
                    i64::try_from(end.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
                })
            }
        }
    }
}

impl DefaultRetention {
    /// The retention a version created at `now_ms` gets.
    fn from(self, now_ms: i64) -> Retention {
        Retention {
            mode: self.mode,
            until_ms: self.period.after(now_ms),
        }
    }
}

/// Refuses to remove a version for good while Object Lock protects it: a legal hold
/// always, a compliance retention always, a governance one unless `bypass`.
pub(crate) fn check_removal(attrs: &ObjectAttrs, bypass: bool, now_ms: i64) -> Result<()> {
    let retained = attrs
        .retention
        .is_some_and(|r| r.active(now_ms) && (r.mode == LockMode::Compliance || !bypass));
    if attrs.legal_hold == Some(true) || retained {
        return Err(StoreError::ObjectLocked);
    }
    Ok(())
}

/// Checks a change of a version's retention from `current` to `new` (`None`: removed).
/// Anyone allowed to set retention may keep or extend it in the same mode; shortening,
/// removing or changing the mode of a governance retention needs `bypass`, and of a
/// compliance one isn't possible. A retention that has ended protects nothing.
pub(crate) fn check_retention_change(
    current: Option<&Retention>,
    new: Option<&Retention>,
    bypass: bool,
    now_ms: i64,
) -> Result<()> {
    let Some(current) = current.filter(|r| r.active(now_ms)) else {
        return Ok(());
    };
    let extends = new.is_some_and(|n| n.mode == current.mode && n.until_ms >= current.until_ms);
    if extends || (current.mode == LockMode::Governance && bypass) {
        Ok(())
    } else {
        Err(StoreError::ObjectLocked)
    }
}

impl Inner {
    /// The Object Lock of the bucket whose record (or version store) is `versions`:
    /// only a bucket with versioning enabled can have one.
    pub(crate) fn object_lock(
        &self,
        versions: Option<&ObjectBucket>,
    ) -> Result<Option<ObjectLock>> {
        let Some(versions) = versions.filter(|v| v.versioning == Versioning::Enabled) else {
            return Ok(None);
        };
        let json = self.system().bucket_config_by_id(&versions.id)?;
        Ok(crate::settings::read_config(json.as_deref())?.object_lock)
    }

    /// Settles the lock of a version about to be written as `attrs`: one the write asks
    /// for needs the bucket's Object Lock; one that asks for none gets the bucket's
    /// default retention.
    pub(crate) fn lock_new_version(
        &self,
        versions: Option<&ObjectBucket>,
        attrs: &mut ObjectAttrs,
    ) -> Result<()> {
        lock_new_version(self.object_lock(versions)?, attrs)
    }

    /// Settles a version about to be written as `attrs`, of `key` (SSE-KMS encrypted when
    /// `kms`), in the bucket whose record (or version store) is `versions`: its lock (as
    /// [`Inner::lock_new_version`] does) and its replication, which it gets from the
    /// bucket's replication rules alone (a `replica` is one, and isn't replicated again),
    /// never from a request or a copied version.
    pub(crate) fn settle_new_version(
        &self,
        versions: Option<&ObjectBucket>,
        key: &str,
        attrs: &mut ObjectAttrs,
        kms: bool,
        replica: bool,
    ) -> Result<()> {
        attrs.replication = replica.then(VersionReplication::replica);
        let Some(versions) = versions.filter(|v| v.versioning == Versioning::Enabled) else {
            return lock_new_version(None, attrs);
        };
        let json = self.system().bucket_config_by_id(&versions.id)?;
        let config = crate::settings::read_config(json.as_deref())?;
        lock_new_version(config.object_lock, attrs)?;
        if let Some(replication) = config.replication.filter(|_| !replica) {
            attrs.replication =
                VersionReplication::pending(replication.destinations(key, &attrs.tags, kms));
        }
        Ok(())
    }
}

impl Inner {
    /// What a delete marker of `key` that `marking` makes is, in the bucket whose
    /// version store is `versions`: waiting for the destinations of the rules that
    /// replicate markers, when a request made it; a replica's is marked so.
    pub(crate) fn marker_attrs(
        &self,
        versions: &ObjectBucket,
        key: &str,
        marking: &Marking,
    ) -> Result<ObjectAttrs> {
        let mut attrs = ObjectAttrs::default();
        match marking {
            Marking::Replica(_) => attrs.replication = Some(VersionReplication::replica()),
            Marking::Request if versions.versioning == Versioning::Enabled => {
                let json = self.system().bucket_config_by_id(&versions.id)?;
                let config = crate::settings::read_config(json.as_deref())?;
                if let Some(replication) = config.replication {
                    attrs.replication =
                        VersionReplication::pending(replication.marker_destinations(key));
                }
            }
            Marking::Request | Marking::Lifecycle | Marking::Replicated => {}
        }
        Ok(attrs)
    }

    /// The replication configuration that decides where a version removal `marking`
    /// makes in the bucket whose version store is `versions` goes: none for lifecycle's
    /// removals, replicated ones, or without versioning enabled.
    pub(crate) fn removal_config(
        &self,
        versions: &ObjectBucket,
        marking: &Marking,
    ) -> Result<Option<ReplicationConfig>> {
        if !matches!(marking, Marking::Request) || versions.versioning != Versioning::Enabled {
            return Ok(None);
        }
        let json = self.system().bucket_config_by_id(&versions.id)?;
        Ok(crate::settings::read_config(json.as_deref())?.replication)
    }
}

/// Settles the lock of a version about to be written as `attrs` in a bucket with `lock`.
fn lock_new_version(lock: Option<ObjectLock>, attrs: &mut ObjectAttrs) -> Result<()> {
    let asked = attrs.retention.is_some() || attrs.legal_hold.is_some();
    match lock {
        None if asked => Err(StoreError::InvalidRequest(NO_LOCK)),
        None => Ok(()),
        Some(lock) => {
            if attrs.retention.is_none() {
                attrs.retention = lock.default_retention.map(|d| d.from(now_ms()));
            }
            Ok(())
        }
    }
}

impl Store {
    /// A bucket's Object Lock; `None` when it has none.
    pub async fn bucket_object_lock(&self, bucket: &str) -> Result<Option<ObjectLock>> {
        let name = bucket.to_owned();
        self.blocking(move |inner| inner.object_lock(inner.bucket(&name)?.versions()))
            .await
    }

    /// Turns a bucket's Object Lock on, or replaces its default retention. The bucket's
    /// versioning must be enabled; as on S3, Object Lock can't be turned off again.
    pub async fn set_bucket_object_lock(&self, bucket: &str, lock: ObjectLock) -> Result<()> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            // Under the commit lock, so versioning can't change underneath.
            let _lock = inner.lock();
            if inner.bucket(&name)?.versioning() != Versioning::Enabled {
                return Err(StoreError::InvalidBucketState(
                    "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration",
                ));
            }
            inner.update_config(&name, |config| {
                config.object_lock = Some(lock);
                Ok(())
            })
        })
        .await
    }

    /// Sets or removes (`None`) the retention of a version of an object (`None`: the
    /// current one). Shortening or removing a governance retention, or changing its
    /// mode, needs `bypass` (the caller may `s3:BypassGovernanceRetention` and asked).
    pub async fn set_retention(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        retention: Option<Retention>,
        bypass: bool,
    ) -> Result<ObjectInfo> {
        self.require_lock(bucket).await?;
        let now = now_ms();
        self.change_attrs(bucket, key, version_id, move |attrs| {
            check_retention_change(attrs.retention.as_ref(), retention.as_ref(), bypass, now)?;
            attrs.retention = retention;
            Ok(())
        })
        .await
    }

    /// Places or lifts the legal hold on a version of an object (`None`: the current one).
    pub async fn set_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        on: bool,
    ) -> Result<ObjectInfo> {
        self.require_lock(bucket).await?;
        self.change_attrs(bucket, key, version_id, move |attrs| {
            attrs.legal_hold = Some(on);
            Ok(())
        })
        .await
    }

    /// Fails unless the bucket has Object Lock, as S3 does for a version's retention or
    /// legal hold.
    async fn require_lock(&self, bucket: &str) -> Result<()> {
        match self.bucket_object_lock(bucket).await? {
            Some(_) => Ok(()),
            None => Err(StoreError::InvalidRequest(NO_LOCK)),
        }
    }
}

impl Bucket {
    /// Where its versions are recorded: an object bucket's own, a folder bucket's store.
    pub(crate) fn versions(&self) -> Option<&ObjectBucket> {
        match self {
            Self::Object(bucket) => Some(bucket),
            Self::Folder(bucket) => bucket.versions.as_ref(),
        }
    }

    /// Its versioning.
    pub(crate) fn versioning(&self) -> Versioning {
        self.versions()
            .map_or(Versioning::Unversioned, |v| v.versioning)
    }
}

/// Refuses a lock on a folder in a folder bucket: folders there have no versions.
pub(crate) fn check_folder(key: &ObjectKey, attrs: &ObjectAttrs) -> Result<()> {
    if key.is_folder() && (attrs.retention.is_some() || attrs.legal_hold.is_some()) {
        return Err(StoreError::InvalidRequest(
            "a folder in a folder bucket has no versions, so it can't be locked",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn retention(mode: LockMode, until_ms: i64) -> Retention {
        Retention { mode, until_ms }
    }

    #[test]
    fn a_lock_protects_until_it_ends_or_is_bypassed() {
        let locked = |retention, hold: bool| ObjectAttrs {
            retention,
            legal_hold: Some(hold),
            ..ObjectAttrs::default()
        };
        let gov = Some(retention(LockMode::Governance, NOW + 1));
        let comp = Some(retention(LockMode::Compliance, NOW + 1));
        assert!(check_removal(&locked(None, false), false, NOW).is_ok());
        assert!(check_removal(&locked(gov, false), false, NOW).is_err());
        assert!(check_removal(&locked(gov, false), true, NOW).is_ok());
        assert!(check_removal(&locked(comp, false), true, NOW).is_err());
        // Ended: exactly at its date, it protects nothing.
        assert!(check_removal(&locked(comp, false), false, NOW + 1).is_ok());
        // A legal hold holds whatever the retention and the bypass.
        assert!(check_removal(&locked(None, true), true, NOW).is_err());
        assert!(check_removal(&locked(gov, true), true, NOW + 5).is_err());
    }

    #[test]
    fn retention_is_extended_freely_and_shortened_only_in_governance_with_bypass() {
        let gov = retention(LockMode::Governance, NOW + 100);
        let comp = retention(LockMode::Compliance, NOW + 100);
        let change = |current: &Retention, new: Option<Retention>, bypass| {
            check_retention_change(Some(current), new.as_ref(), bypass, NOW).is_ok()
        };
        for current in [gov, comp] {
            let longer = Retention {
                until_ms: NOW + 200,
                ..current
            };
            let shorter = Retention {
                until_ms: NOW + 50,
                ..current
            };
            assert!(change(&current, Some(current), false));
            assert!(change(&current, Some(longer), false));
            assert!(!change(&current, Some(shorter), false));
            assert!(!change(&current, None, false));
        }
        assert!(change(
            &gov,
            Some(retention(LockMode::Governance, NOW + 50)),
            true
        ));
        assert!(change(&gov, None, true));
        assert!(!change(&gov, Some(comp), false));
        assert!(change(&gov, Some(comp), true));
        assert!(!change(&comp, Some(gov), true));
        assert!(!change(
            &comp,
            Some(retention(LockMode::Compliance, NOW + 50)),
            true
        ));
        assert!(!change(&comp, None, true));
        // Nothing, or one that has ended, can become anything.
        assert!(check_retention_change(None, Some(&comp), false, NOW).is_ok());
        let ended = retention(LockMode::Compliance, NOW);
        assert!(check_retention_change(Some(&ended), None, false, NOW).is_ok());
    }

    #[test]
    fn periods_are_days_or_calendar_years() {
        assert!(RetentionPeriod::Days(1).is_valid());
        assert!(RetentionPeriod::Days(MAX_RETENTION_DAYS).is_valid());
        assert!(!RetentionPeriod::Days(0).is_valid());
        assert!(!RetentionPeriod::Days(MAX_RETENTION_DAYS + 1).is_valid());
        assert!(RetentionPeriod::Years(MAX_RETENTION_YEARS).is_valid());
        assert!(!RetentionPeriod::Years(0).is_valid());
        assert!(!RetentionPeriod::Years(MAX_RETENTION_YEARS + 1).is_valid());
        assert_eq!(RetentionPeriod::Days(2).after(NOW), NOW + 2 * 86_400_000);
        let noon = |year, day| {
            let date = time::Date::from_calendar_date(year, time::Month::February, day).unwrap();
            let at = date.with_hms(12, 0, 0).unwrap().assume_utc();
            i64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap()
        };
        assert_eq!(
            RetentionPeriod::Years(1).after(noon(2028, 29)),
            noon(2029, 28)
        );
        assert_eq!(
            RetentionPeriod::Years(4).after(noon(2028, 29)),
            noon(2032, 29)
        );
        assert_eq!(
            RetentionPeriod::Years(1).after(noon(2027, 3)),
            noon(2028, 3)
        );
    }
}
