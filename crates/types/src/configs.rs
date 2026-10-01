//! A bucket's reporting configurations, as S3 sets them: Requester Pays, inventory
//! reports, storage class analysis, request metrics and S3 Intelligent-Tiering. Each
//! kind but Requester Pays is a set of configurations named by an id.

use std::{collections::BTreeMap, ops::Not};

use serde::{Deserialize, Serialize};

/// At most this many configurations of one kind on a bucket, as on S3.
pub const MAX_CONFIGURATIONS: usize = 1_000;

/// At most this many configurations in a page of a listing, as on S3.
pub const LIST_PAGE: usize = 100;

/// The longest id S3 takes.
pub const MAX_ID_LEN: usize = 64;

/// A bucket's configurations of every kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configurations {
    /// Whether requesters pay (S3's Requester Pays): here, anonymous requests are refused.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub requester_pays: bool,
    /// Inventory reports, by id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inventory: BTreeMap<String, InventoryConfig>,
    /// Storage class analyses, by id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub analytics: BTreeMap<String, AnalyticsConfig>,
    /// Request metrics, by id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metrics: BTreeMap<String, MetricsConfig>,
    /// S3 Intelligent-Tiering archive settings, by id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub intelligent_tiering: BTreeMap<String, TieringConfig>,
}

impl Configurations {
    /// Whether it holds nothing (a bucket without any).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// How many of a kind it holds, and whether one has this id.
    #[must_use]
    pub fn count(&self, kind: Kind, id: &str) -> (usize, bool) {
        match kind {
            Kind::Inventory => (self.inventory.len(), self.inventory.contains_key(id)),
            Kind::Analytics => (self.analytics.len(), self.analytics.contains_key(id)),
            Kind::Metrics => (self.metrics.len(), self.metrics.contains_key(id)),
            Kind::IntelligentTiering => (
                self.intelligent_tiering.len(),
                self.intelligent_tiering.contains_key(id),
            ),
        }
    }

    /// Removes the one of a kind with this id; `false` when there's none.
    pub fn remove(&mut self, kind: Kind, id: &str) -> bool {
        match kind {
            Kind::Inventory => self.inventory.remove(id).is_some(),
            Kind::Analytics => self.analytics.remove(id).is_some(),
            Kind::Metrics => self.metrics.remove(id).is_some(),
            Kind::IntelligentTiering => self.intelligent_tiering.remove(id).is_some(),
        }
    }
}

/// The kinds of configurations named by an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `?inventory`.
    Inventory,
    /// `?analytics`.
    Analytics,
    /// `?metrics`.
    Metrics,
    /// `?intelligent-tiering`.
    IntelligentTiering,
}

impl Kind {
    /// What S3 calls it in messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Analytics => "analytics",
            Self::Metrics => "metrics",
            Self::IntelligentTiering => "intelligent-tiering",
        }
    }
}

/// Why an id isn't one S3 takes, or `None` when it is: 1 to 64 letters, digits,
/// `.`, `-` and `_`.
#[must_use]
pub fn id_problem(id: &str) -> Option<&'static str> {
    if id.is_empty() {
        Some("The id is empty")
    } else if id.len() > MAX_ID_LEN {
        Some("The id is longer than 64 characters")
    } else if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Some("The id may only contain letters, digits, periods, dashes and underscores")
    } else {
        None
    }
}

/// A tag a filter asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagFilter {
    /// Its key.
    pub key: String,
    /// Its value.
    pub value: String,
}

/// Which objects a configuration is about: all it names must hold. Kept as it was
/// given (one condition, or `And` of several) so it's answered the same way.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    /// Given as `And`.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub and: bool,
    /// Keys start with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// The object has each of these tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<TagFilter>,
    /// Requests come through this access point (metrics only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_point: Option<String>,
}

impl Filter {
    /// Whether an object with this key matches, when its tags are known.
    #[must_use]
    pub fn matches(&self, key: &str, tags: &BTreeMap<String, String>) -> bool {
        self.prefix
            .as_deref()
            .is_none_or(|prefix| key.starts_with(prefix))
            && self.access_point.is_none()
            && self
                .tags
                .iter()
                .all(|tag| tags.get(&tag.key) == Some(&tag.value))
    }

    /// Whether it names tags (so matching needs the object's).
    #[must_use]
    pub fn needs_tags(&self) -> bool {
        !self.tags.is_empty()
    }
}

/// An inventory report's settings (`InventoryConfiguration`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryConfig {
    /// Whether reports are made.
    pub enabled: bool,
    /// Only keys starting with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Where reports go.
    pub destination: InventoryDestination,
    /// Every version, or only current ones.
    pub all_versions: bool,
    /// The fields after the bucket and key, in the order given.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<InventoryField>,
    /// How often.
    pub frequency: Frequency,
}

/// Where an inventory report goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryDestination {
    /// The bucket, by name (given as an ARN).
    pub bucket: String,
    /// The account given with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The format of the report's files.
    pub format: InventoryFormat,
    /// Keys start with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// How the report's files are encrypted, besides the bucket's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<ReportEncryption>,
}

/// How report files are encrypted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportEncryption {
    /// SSE-S3.
    S3,
    /// SSE-KMS with this key.
    Kms(String),
}

/// An inventory report's file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InventoryFormat {
    /// Gzipped CSV.
    #[serde(rename = "CSV")]
    Csv,
    /// Apache ORC, zlib compressed.
    #[serde(rename = "ORC")]
    Orc,
    /// Apache Parquet, Snappy compressed.
    Parquet,
}

impl InventoryFormat {
    /// S3's name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Csv => "CSV",
            Self::Orc => "ORC",
            Self::Parquet => "Parquet",
        }
    }

    /// The format S3 names so.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Csv, Self::Orc, Self::Parquet]
            .into_iter()
            .find(|format| format.name() == name)
    }
}

/// How often a report is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frequency {
    /// Every day.
    Daily,
    /// Every Sunday (UTC).
    Weekly,
}

impl Frequency {
    /// S3's name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Daily => "Daily",
            Self::Weekly => "Weekly",
        }
    }

    /// The frequency S3 names so.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Daily, Self::Weekly]
            .into_iter()
            .find(|frequency| frequency.name() == name)
    }
}

macro_rules! fields {
    ($($field:ident),* $(,)?) => {
        /// An optional field of an inventory report.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum InventoryField {
            $(#[allow(missing_docs)] $field,)*
        }

        impl InventoryField {
            /// Every field, in S3's order.
            pub const ALL: &'static [Self] = &[$(Self::$field),*];

            /// S3's name for it.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$field => stringify!($field),)*
                }
            }
        }
    };
}

fields!(
    Size,
    LastModifiedDate,
    StorageClass,
    ETag,
    IsMultipartUploaded,
    ReplicationStatus,
    EncryptionStatus,
    ObjectLockRetainUntilDate,
    ObjectLockMode,
    ObjectLockLegalHoldStatus,
    ObjectLockEventHoldStatus,
    ObjectLockEventHoldDuration,
    IntelligentTieringAccessTier,
    BucketKeyStatus,
    ChecksumAlgorithm,
    ObjectAccessControlList,
    ObjectOwner,
    LifecycleExpirationDate,
);

impl InventoryField {
    /// The field S3 names so.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|field| field.name() == name)
    }
}

/// A storage class analysis (`AnalyticsConfiguration`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsConfig {
    /// The objects analysed; all when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,
    /// Where the daily figures are exported, if anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<AnalyticsExport>,
}

/// Where an analysis's CSV export goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsExport {
    /// The bucket, by name (given as an ARN).
    pub bucket: String,
    /// The account given with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Keys start with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// Request metrics for some of a bucket's objects (`MetricsConfiguration`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsConfig {
    /// The requests counted; all the bucket's when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,
}

/// S3 Intelligent-Tiering's archive settings (`IntelligentTieringConfiguration`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TieringConfig {
    /// The objects it's about; all when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,
    /// Whether it applies.
    pub enabled: bool,
    /// After how many days without access objects move to each tier, in the order given.
    pub tierings: Vec<Tiering>,
}

/// An archive tier and when objects move to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tiering {
    /// The tier.
    pub tier: ArchiveTier,
    /// Days without access.
    pub days: u32,
}

/// An S3 Intelligent-Tiering archive tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveTier {
    /// `ARCHIVE_ACCESS`: after 90 to 730 days.
    #[serde(rename = "ARCHIVE_ACCESS")]
    Archive,
    /// `DEEP_ARCHIVE_ACCESS`: after 180 to 730 days.
    #[serde(rename = "DEEP_ARCHIVE_ACCESS")]
    DeepArchive,
}

impl ArchiveTier {
    /// S3's name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Archive => "ARCHIVE_ACCESS",
            Self::DeepArchive => "DEEP_ARCHIVE_ACCESS",
        }
    }

    /// The tier S3 names so.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Archive, Self::DeepArchive]
            .into_iter()
            .find(|tier| tier.name() == name)
    }

    /// The days S3 allows before it.
    #[must_use]
    pub const fn days(self) -> std::ops::RangeInclusive<u32> {
        match self {
            Self::Archive => 90..=730,
            Self::DeepArchive => 180..=730,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_checked_as_s3_checks_them() {
        assert_eq!(id_problem("report-1_a.b"), None);
        assert_eq!(id_problem(&"a".repeat(64)), None);
        assert!(id_problem("").is_some());
        assert!(id_problem(&"a".repeat(65)).is_some());
        for bad in ["a b", "a/b", "ü", "a+b"] {
            assert!(id_problem(bad).is_some(), "{bad}");
        }
    }

    #[test]
    fn names_go_both_ways() {
        for field in InventoryField::ALL {
            assert_eq!(InventoryField::parse(field.name()), Some(*field));
        }
        assert_eq!(InventoryField::ALL.len(), 18);
        assert_eq!(InventoryField::parse("ETag"), Some(InventoryField::ETag));
        assert_eq!(InventoryField::parse("Etag"), None);
        for format in [
            InventoryFormat::Csv,
            InventoryFormat::Orc,
            InventoryFormat::Parquet,
        ] {
            assert_eq!(InventoryFormat::parse(format.name()), Some(format));
        }
        assert_eq!(InventoryFormat::parse("csv"), None);
        assert_eq!(Frequency::parse("Weekly"), Some(Frequency::Weekly));
        assert_eq!(
            ArchiveTier::parse("DEEP_ARCHIVE_ACCESS"),
            Some(ArchiveTier::DeepArchive)
        );
        assert_eq!(ArchiveTier::Archive.days(), 90..=730);
    }

    #[test]
    fn filters_need_all_they_name() {
        let tags: BTreeMap<String, String> = [("team".into(), "blue".into())].into();
        let none = BTreeMap::new();
        let filter = Filter {
            and: true,
            prefix: Some("docs/".into()),
            tags: vec![TagFilter {
                key: "team".into(),
                value: "blue".into(),
            }],
            access_point: None,
        };
        assert!(filter.matches("docs/a", &tags));
        assert!(!filter.matches("docs/a", &none));
        assert!(!filter.matches("img/a", &tags));
        assert!(filter.needs_tags());
        assert!(Filter::default().matches("anything", &none));
        // Requests through an access point never match here: TeiFS has none yet.
        let through = Filter {
            access_point: Some("arn:aws:s3:x".into()),
            ..Filter::default()
        };
        assert!(!through.matches("a", &none));
    }

    #[test]
    fn nothing_set_is_empty() {
        assert!(Configurations::default().is_empty());
        let pays = Configurations {
            requester_pays: true,
            ..Configurations::default()
        };
        assert!(!pays.is_empty());
        assert_eq!(
            serde_json::to_string(&Configurations::default()).unwrap(),
            "{}"
        );
    }
}
