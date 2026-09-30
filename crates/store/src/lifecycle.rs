//! S3 Lifecycle: a bucket's rules, which of them applies to an object or an upload, and
//! when.
//!
//! A rule is kept the way it was written (a rule-level prefix, an empty filter, one
//! condition or an `And`), so a bucket answers its configuration exactly as it was
//! given. The request layer checks a configuration before it's stored; what's here only
//! evaluates it.
//!
//! Days are counted from an object's creation (or an upload's start) and rounded up to
//! the next midnight UTC, as on S3. A drive can be given a shorter "day" for tests; the
//! rounding is then to the next multiple of that day since the Unix epoch, which for a
//! real day is midnight UTC.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use teifs_types::ObjectInfo;

use crate::{Inner, Store, error::Result};

/// The most rules a configuration may have.
pub const MAX_LIFECYCLE_RULES: usize = 1000;
/// The longest a rule's id may be.
pub const MAX_RULE_ID_LEN: usize = 255;
/// The most noncurrent versions a rule may keep (`NewerNoncurrentVersions`).
pub const MAX_NEWER_NONCURRENT: u32 = 100;
/// A day, in milliseconds.
pub const DAY_MS: i64 = 86_400_000;

/// A bucket's lifecycle configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lifecycle {
    /// Its rules, in the order they were given.
    pub rules: Vec<LifecycleRule>,
    /// `x-amz-transition-default-minimum-object-size`, as it was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_minimum_size: Option<String>,
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleRule {
    /// Its id, unique in the configuration.
    pub id: String,
    /// Whether it's applied (`Enabled`) or kept for later (`Disabled`).
    pub enabled: bool,
    /// Which objects it applies to.
    pub filter: RuleFilter,
    /// When current versions expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<Expiration>,
    /// When noncurrent versions are removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noncurrent_expiration: Option<NoncurrentExpiration>,
    /// Days after which an unfinished multipart upload is aborted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_uploads_after_days: Option<u32>,
}

/// Which objects a rule applies to, as the rule says it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleFilter {
    /// Neither a filter nor a prefix: every object.
    All,
    /// A rule-level `Prefix` (the older form of the API).
    RulePrefix(String),
    /// A `Filter` element.
    Filter(Condition),
}

/// What a `Filter` element holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Condition {
    /// An empty filter: every object.
    Empty,
    /// Keys that start with this.
    Prefix(String),
    /// Objects with this tag.
    Tag(Tag),
    /// Objects larger than this many bytes.
    GreaterThan(u64),
    /// Objects smaller than this many bytes.
    LessThan(u64),
    /// Objects that meet every condition given.
    And(And),
}

/// An object tag a rule looks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    /// Its key.
    pub key: String,
    /// Its value.
    pub value: String,
}

/// An `And` filter: every condition given must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct And {
    /// Keys that start with this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Tags the object must all have.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
    /// Objects larger than this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub greater_than: Option<u64>,
    /// Objects smaller than this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub less_than: Option<u64>,
}

/// When current versions expire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Expiration {
    /// This many days after the object's creation.
    Days(u32),
    /// From this date on (midnight UTC, in milliseconds since the Unix epoch).
    Date(i64),
    /// Whether a delete marker left with no versions behind it is removed.
    ExpiredDeleteMarker(bool),
}

/// When noncurrent versions are removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoncurrentExpiration {
    /// Days after a version became noncurrent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<u32>,
    /// How many of the newest noncurrent versions are kept whatever their age.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newer_versions: Option<u32>,
}

/// When something expires, and the rule that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expiry {
    /// When, in milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// The rule's id.
    pub rule_id: String,
}

impl RuleFilter {
    /// The key prefix every object it applies to has (`""`: any).
    #[must_use]
    pub fn prefix(&self) -> &str {
        match self {
            Self::RulePrefix(prefix)
            | Self::Filter(
                Condition::Prefix(prefix)
                | Condition::And(And {
                    prefix: Some(prefix),
                    ..
                }),
            ) => prefix,
            _ => "",
        }
    }

    /// Whether it looks at tags.
    #[must_use]
    pub fn has_tags(&self) -> bool {
        match self {
            Self::Filter(Condition::Tag(_)) => true,
            Self::Filter(Condition::And(and)) => !and.tags.is_empty(),
            _ => false,
        }
    }

    /// Whether it looks at sizes.
    #[must_use]
    pub fn has_sizes(&self) -> bool {
        match self {
            Self::Filter(Condition::GreaterThan(_) | Condition::LessThan(_)) => true,
            Self::Filter(Condition::And(and)) => {
                and.greater_than.is_some() || and.less_than.is_some()
            }
            _ => false,
        }
    }

    /// Whether it applies to an object with this key, size and tags.
    #[must_use]
    pub fn matches(
        &self,
        key: &str,
        size: u64,
        tags: &std::collections::BTreeMap<String, String>,
    ) -> bool {
        let tagged = |tag: &Tag| tags.get(&tag.key) == Some(&tag.value);
        let condition = match self {
            Self::All => return true,
            Self::RulePrefix(prefix) => return key.starts_with(prefix.as_str()),
            Self::Filter(condition) => condition,
        };
        match condition {
            Condition::Empty => true,
            Condition::Prefix(prefix) => key.starts_with(prefix.as_str()),
            Condition::Tag(tag) => tagged(tag),
            Condition::GreaterThan(min) => size > *min,
            Condition::LessThan(max) => size < *max,
            Condition::And(and) => {
                and.prefix.as_deref().is_none_or(|p| key.starts_with(p))
                    && and.tags.iter().all(tagged)
                    && and.greater_than.is_none_or(|min| size > min)
                    && and.less_than.is_none_or(|max| size < max)
            }
        }
    }
}

/// When something that started at `from_ms` is `days` days old, rounded up to the next
/// day boundary (midnight UTC for a real day).
#[must_use]
pub fn due(from_ms: i64, days: u32, day_ms: i64) -> i64 {
    let at = from_ms.saturating_add(i64::from(days).saturating_mul(day_ms));
    let rest = at.rem_euclid(day_ms);
    if rest == 0 {
        at
    } else {
        at.saturating_add(day_ms - rest)
    }
}

impl Lifecycle {
    /// The enabled rules.
    pub fn enabled(&self) -> impl Iterator<Item = &LifecycleRule> {
        self.rules.iter().filter(|rule| rule.enabled)
    }

    /// When the current version of an object expires, and by which rule: the earliest
    /// of the enabled rules with an `Expiration` by days or date that apply to it.
    #[must_use]
    pub fn expiry(&self, info: &ObjectInfo, day_ms: i64) -> Option<Expiry> {
        let created = crate::jobs::millis(info.modified);
        self.enabled()
            .filter(|rule| rule.filter.matches(&info.key, info.size, &info.attrs.tags))
            .filter_map(|rule| {
                let at_ms = match rule.expiration? {
                    Expiration::Days(days) => due(created, days, day_ms),
                    Expiration::Date(date) => date,
                    Expiration::ExpiredDeleteMarker(_) => return None,
                };
                Some(Expiry {
                    at_ms,
                    rule_id: rule.id.clone(),
                })
            })
            .min_by_key(|expiry| expiry.at_ms)
    }

    /// Whether a noncurrent version of `key` (`info`: its size and tags; a delete marker
    /// has neither) that became noncurrent at `since_ms`, with `newer` noncurrent
    /// versions ahead of it, is to be removed at `now_ms`: some enabled rule that applies
    /// to it has kept it long enough and has enough newer versions kept.
    #[must_use]
    pub fn removes_noncurrent(
        &self,
        info: &ObjectInfo,
        since_ms: i64,
        newer: u32,
        now_ms: i64,
        day_ms: i64,
    ) -> bool {
        self.enabled()
            .filter(|rule| rule.filter.matches(&info.key, info.size, &info.attrs.tags))
            .filter_map(|rule| rule.noncurrent_expiration)
            .any(|n| {
                n.days
                    .is_none_or(|days| due(since_ms, days, day_ms) <= now_ms)
                    && n.newer_versions.is_none_or(|kept| newer >= kept)
            })
    }

    /// Whether a delete marker of `key` made at `made_ms`, with no versions left behind
    /// it, is to be removed at `now_ms`: a rule that applies to it removes expired delete
    /// markers, or expires objects after a number of days that have passed since.
    #[must_use]
    pub fn removes_marker(&self, key: &str, made_ms: i64, now_ms: i64, day_ms: i64) -> bool {
        let none = std::collections::BTreeMap::new();
        self.enabled()
            .filter(|rule| rule.filter.matches(key, 0, &none))
            .any(|rule| match rule.expiration {
                Some(Expiration::ExpiredDeleteMarker(on)) => on,
                Some(Expiration::Days(days)) => due(made_ms, days, day_ms) <= now_ms,
                _ => false,
            })
    }

    /// The key prefix everything the enabled rules apply to has in common.
    #[must_use]
    pub fn common_prefix(&self) -> &str {
        let mut prefixes = self.enabled().map(|rule| rule.filter.prefix());
        let Some(first) = prefixes.next() else {
            return "";
        };
        prefixes.fold(first, |common, prefix| {
            let len = common
                .char_indices()
                .zip(prefix.chars())
                .take_while(|((_, a), b)| a == b)
                .last()
                .map_or(0, |((at, a), _)| at + a.len_utf8());
            &common[..len]
        })
    }

    /// When an upload to `key` started at `started_ms` is aborted, and by which rule.
    #[must_use]
    pub fn upload_abort(&self, key: &str, started_ms: i64, day_ms: i64) -> Option<Expiry> {
        self.enabled()
            // Uploads have no tags or size yet: rules that look at them don't apply.
            .filter(|rule| {
                !rule.filter.has_tags()
                    && !rule.filter.has_sizes()
                    && key.starts_with(rule.filter.prefix())
            })
            .filter_map(|rule| {
                Some(Expiry {
                    at_ms: due(started_ms, rule.abort_uploads_after_days?, day_ms),
                    rule_id: rule.id.clone(),
                })
            })
            .min_by_key(|expiry| expiry.at_ms)
    }
}

impl Inner {
    /// A bucket's lifecycle configuration, if it has one.
    pub(crate) fn lifecycle(&self, bucket: &str) -> Result<Option<Arc<Lifecycle>>> {
        self.lifecycles.get(bucket, || {
            let config =
                crate::settings::read_config(self.system().bucket_config(bucket)?.as_deref())?;
            Ok(config.lifecycle)
        })
    }
}

impl Store {
    /// A bucket's lifecycle configuration, if it has one.
    pub async fn bucket_lifecycle(&self, bucket: &str) -> Result<Option<Arc<Lifecycle>>> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            inner.lifecycle(&name)
        })
        .await
    }

    /// Replaces a bucket's lifecycle configuration (checked by the caller); `None`
    /// removes it.
    pub async fn set_bucket_lifecycle(
        &self,
        bucket: &str,
        lifecycle: Option<Lifecycle>,
    ) -> Result<()> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            inner.bucket(&name)?;
            inner.update_config(&name, |config| {
                config.lifecycle = lifecycle;
                Ok(())
            })
        })
        .await
    }

    /// When the current version `info` of an object in `bucket` expires, and by which
    /// rule (S3's `x-amz-expiration`). Answered from memory once the bucket's
    /// configuration has been read.
    pub async fn expiry(&self, bucket: &str, info: &ObjectInfo) -> Result<Option<Expiry>> {
        let Some(lifecycle) = self.cached_lifecycle(bucket).await? else {
            return Ok(None);
        };
        // Answers count in real days, even on a drive whose rules run faster for tests.
        Ok(lifecycle.expiry(info, DAY_MS))
    }

    /// When an upload to `key` in `bucket` that started at `started_ms` is aborted, and
    /// by which rule (S3's `x-amz-abort-date` and `x-amz-abort-rule-id`).
    pub async fn upload_abort(
        &self,
        bucket: &str,
        key: &str,
        started_ms: i64,
    ) -> Result<Option<Expiry>> {
        let Some(lifecycle) = self.cached_lifecycle(bucket).await? else {
            return Ok(None);
        };
        Ok(lifecycle.upload_abort(key, started_ms, DAY_MS))
    }

    /// A bucket's configuration from memory, reading it only when it isn't there.
    async fn cached_lifecycle(&self, bucket: &str) -> Result<Option<Arc<Lifecycle>>> {
        if let Some(found) = self.inner.lifecycles.cached(bucket) {
            return Ok(found);
        }
        let name = bucket.to_owned();
        self.blocking(move |inner| inner.lifecycle(&name)).await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::SystemTime};

    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn tag(key: &str, value: &str) -> Tag {
        Tag {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    fn rule(id: &str, filter: RuleFilter, expiration: Option<Expiration>) -> LifecycleRule {
        LifecycleRule {
            id: id.to_owned(),
            enabled: true,
            filter,
            expiration,
            noncurrent_expiration: None,
            abort_uploads_after_days: None,
        }
    }

    fn object(key: &str, size: u64, created_ms: i64, tags: BTreeMap<String, String>) -> ObjectInfo {
        ObjectInfo {
            key: key.to_owned(),
            size,
            modified: SystemTime::UNIX_EPOCH
                + std::time::Duration::from_millis(u64::try_from(created_ms).unwrap()),
            etag: String::new(),
            attrs: teifs_types::ObjectAttrs {
                tags,
                ..Default::default()
            },
            sse: None,
            parts: Vec::new(),
            version_id: None,
        }
    }

    #[test]
    fn days_round_up_to_the_next_midnight() {
        // 2026-09-30 10:00 UTC + 1 day → 2026-10-02 00:00 UTC.
        let created = 1_790_762_400_000;
        assert_eq!(due(created, 1, DAY_MS), 1_790_899_200_000);
        // Exactly at midnight stays there.
        assert_eq!(due(1_790_726_400_000, 2, DAY_MS), 1_790_899_200_000);
        // A short test day rounds to its own boundaries.
        assert_eq!(due(1_500, 1, 1000), 3000);
        assert_eq!(due(2_000, 1, 1000), 3000);
    }

    #[test]
    fn filters_match_prefixes_tags_and_sizes() {
        let none = BTreeMap::new();
        let both = tags(&[("a", "1"), ("b", "2")]);
        assert!(RuleFilter::All.matches("x", 0, &none));
        assert!(RuleFilter::RulePrefix("logs/".into()).matches("logs/a", 0, &none));
        assert!(!RuleFilter::RulePrefix("logs/".into()).matches("log", 0, &none));
        let filter = |c| RuleFilter::Filter(c);
        assert!(filter(Condition::Empty).matches("x", 0, &none));
        assert!(filter(Condition::Tag(tag("a", "1"))).matches("x", 0, &both));
        assert!(!filter(Condition::Tag(tag("a", "2"))).matches("x", 0, &both));
        assert!(!filter(Condition::GreaterThan(10)).matches("x", 10, &none));
        assert!(filter(Condition::GreaterThan(10)).matches("x", 11, &none));
        assert!(!filter(Condition::LessThan(10)).matches("x", 10, &none));
        assert!(filter(Condition::LessThan(10)).matches("x", 9, &none));
        let and = |tags: Vec<Tag>| {
            filter(Condition::And(And {
                prefix: Some("p/".into()),
                tags,
                greater_than: Some(1),
                less_than: Some(5),
            }))
        };
        assert!(and(vec![tag("a", "1"), tag("b", "2")]).matches("p/x", 3, &both));
        // Every tag, the prefix and both sizes must hold.
        assert!(!and(vec![tag("a", "1"), tag("b", "3")]).matches("p/x", 3, &both));
        assert!(!and(vec![]).matches("q/x", 3, &none));
        assert!(!and(vec![]).matches("p/x", 1, &none));
        assert!(!and(vec![]).matches("p/x", 5, &none));
        assert!(and(vec![]).has_sizes() && !and(vec![]).has_tags());
        assert_eq!(and(vec![]).prefix(), "p/");
    }

    #[test]
    fn the_earliest_enabled_rule_that_applies_decides() {
        let created = 1_790_762_400_000;
        let mut lifecycle = Lifecycle {
            rules: vec![
                rule("late", RuleFilter::All, Some(Expiration::Days(10))),
                rule(
                    "soon",
                    RuleFilter::RulePrefix("a".into()),
                    Some(Expiration::Days(2)),
                ),
                rule(
                    "other",
                    RuleFilter::RulePrefix("b".into()),
                    Some(Expiration::Days(1)),
                ),
                rule(
                    "markers",
                    RuleFilter::All,
                    Some(Expiration::ExpiredDeleteMarker(true)),
                ),
                rule(
                    "date",
                    RuleFilter::All,
                    Some(Expiration::Date(2_000_000_000_000)),
                ),
            ],
            transition_minimum_size: None,
        };
        let info = object("a1", 1, created, BTreeMap::new());
        let expiry = lifecycle.expiry(&info, DAY_MS).unwrap();
        assert_eq!(expiry.rule_id, "soon");
        assert_eq!(expiry.at_ms, due(created, 2, DAY_MS));
        lifecycle.rules[1].enabled = false;
        assert_eq!(lifecycle.expiry(&info, DAY_MS).unwrap().rule_id, "late");
        lifecycle.rules[0].expiration = Some(Expiration::Days(10_000));
        assert_eq!(
            lifecycle.expiry(&info, DAY_MS).unwrap(),
            Expiry {
                at_ms: 2_000_000_000_000,
                rule_id: "date".into()
            }
        );
        lifecycle.rules.truncate(4);
        lifecycle.rules.remove(0);
        assert_eq!(lifecycle.expiry(&info, DAY_MS), None);
    }

    #[test]
    fn uploads_are_aborted_by_prefix_rules_only() {
        let abort = |id, filter, days| {
            let mut r = rule(id, filter, None);
            r.abort_uploads_after_days = Some(days);
            r
        };
        let lifecycle = Lifecycle {
            rules: vec![
                abort("sized", RuleFilter::Filter(Condition::GreaterThan(0)), 1),
                abort("up", RuleFilter::RulePrefix("up/".into()), 3),
                rule("none", RuleFilter::All, Some(Expiration::Days(1))),
            ],
            transition_minimum_size: None,
        };
        assert_eq!(
            lifecycle.upload_abort("up/x", 0, DAY_MS),
            Some(Expiry {
                at_ms: 3 * DAY_MS,
                rule_id: "up".into()
            })
        );
        assert_eq!(lifecycle.upload_abort("down/x", 0, DAY_MS), None);
    }

    #[test]
    fn noncurrent_versions_go_after_their_days_beyond_the_newest_kept() {
        let mut r = rule("n", RuleFilter::RulePrefix("a".into()), None);
        r.noncurrent_expiration = Some(NoncurrentExpiration {
            days: Some(2),
            newer_versions: Some(1),
        });
        let lifecycle = Lifecycle {
            rules: vec![r],
            transition_minimum_size: None,
        };
        let info = object("a1", 1, 0, BTreeMap::new());
        let since = DAY_MS / 2;
        let removes = |newer, now| lifecycle.removes_noncurrent(&info, since, newer, now, DAY_MS);
        // Two days after it became noncurrent, rounded up: day 3.
        assert!(!removes(1, 3 * DAY_MS - 1));
        assert!(removes(1, 3 * DAY_MS));
        // The newest noncurrent version is kept whatever its age.
        assert!(!removes(0, 30 * DAY_MS));
        let other = object("b1", 1, 0, BTreeMap::new());
        assert!(!lifecycle.removes_noncurrent(&other, since, 5, 30 * DAY_MS, DAY_MS));
        let mut only_newer = lifecycle.clone();
        only_newer.rules[0].noncurrent_expiration = Some(NoncurrentExpiration {
            days: None,
            newer_versions: Some(2),
        });
        assert!(!only_newer.removes_noncurrent(&info, since, 1, since, DAY_MS));
        assert!(only_newer.removes_noncurrent(&info, since, 2, since, DAY_MS));
    }

    #[test]
    fn lone_delete_markers_go_by_the_flag_or_after_the_days() {
        let lifecycle = |expiration| Lifecycle {
            rules: vec![rule(
                "m",
                RuleFilter::RulePrefix("a".into()),
                Some(expiration),
            )],
            transition_minimum_size: None,
        };
        assert!(lifecycle(Expiration::ExpiredDeleteMarker(true)).removes_marker("a", 0, 0, DAY_MS));
        assert!(
            !lifecycle(Expiration::ExpiredDeleteMarker(false)).removes_marker("a", 0, 0, DAY_MS)
        );
        assert!(
            !lifecycle(Expiration::ExpiredDeleteMarker(true)).removes_marker("b", 0, 0, DAY_MS)
        );
        let days = lifecycle(Expiration::Days(1));
        assert!(!days.removes_marker("a", 1, DAY_MS, DAY_MS));
        assert!(days.removes_marker("a", 1, 2 * DAY_MS, DAY_MS));
        assert!(!lifecycle(Expiration::Date(0)).removes_marker("a", 0, DAY_MS, DAY_MS));
    }

    #[test]
    fn the_common_prefix_covers_every_enabled_rule() {
        let with = |prefixes: &[&str]| Lifecycle {
            rules: prefixes
                .iter()
                .map(|p| rule(p, RuleFilter::RulePrefix((*p).to_owned()), None))
                .collect(),
            transition_minimum_size: None,
        };
        assert_eq!(with(&[]).common_prefix(), "");
        assert_eq!(with(&["logs/a", "logs/b"]).common_prefix(), "logs/");
        assert_eq!(with(&["é1", "é2"]).common_prefix(), "é");
        assert_eq!(with(&["a", "b"]).common_prefix(), "");
        let mut disabled = with(&["x/1", "y"]);
        disabled.rules[1].enabled = false;
        assert_eq!(disabled.common_prefix(), "x/1");
    }

    #[test]
    fn a_configuration_keeps_its_form() {
        let lifecycle = Lifecycle {
            rules: vec![
                rule(
                    "a",
                    RuleFilter::RulePrefix(String::new()),
                    Some(Expiration::Days(1)),
                ),
                rule(
                    "b",
                    RuleFilter::Filter(Condition::And(And {
                        prefix: None,
                        tags: vec![tag("k", "v")],
                        greater_than: None,
                        less_than: Some(3),
                    })),
                    None,
                ),
            ],
            transition_minimum_size: Some("varies_by_storage_class".into()),
        };
        let json = serde_json::to_string(&lifecycle).unwrap();
        assert_eq!(serde_json::from_str::<Lifecycle>(&json).unwrap(), lifecycle);
    }
}
