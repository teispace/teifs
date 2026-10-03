//! Bucket replication: which of a bucket's objects are copied to which buckets, as S3's
//! `PutBucketReplication` sets it. Kept as it was given, so `GetBucketReplication`
//! answers the same.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The most rules a configuration may have.
pub const MAX_RULES: usize = 1_000;

/// The longest a rule's id may be.
pub const MAX_ID: usize = 255;

/// What a destination's ARN starts with when it names a bucket on the same drive.
pub const LOCAL_ARN: &str = "arn:aws:s3:::";

/// What a destination's ARN starts with when it names a remote target (`MinIO`'s form).
pub const TARGET_ARN: &str = "arn:minio:replication:";

/// Another S3 service's bucket a bucket replicates to (`MinIO`'s remote target): where it
/// is and the access key that signs there. Its secret key is kept apart, sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTarget {
    /// Its ARN, which a rule's destination names: `arn:minio:replication:REGION:ID:BUCKET`.
    pub arn: String,
    /// The bucket on this drive that replicates to it.
    pub source_bucket: String,
    /// The service's host and port (`s3.example.com:9000`).
    pub endpoint: String,
    /// Whether it's reached over HTTPS.
    pub secure: bool,
    /// The bucket there.
    pub target_bucket: String,
    /// Its region (requests are signed for it; `us-east-1` when empty).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// The access key requests there are signed with.
    pub access_key: String,
    /// The storage class replicas get there, if not the source's.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub storage_class: String,
    /// The most bytes a second it's sent (0: no limit).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bandwidth_limit: u64,
    /// Whether writes wait until the replica is made (`MinIO`'s synchronous mode).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sync: bool,
    /// How often it's checked to be reachable, in seconds (0: the default).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub health_check_secs: u64,
    /// When it was added (Unix milliseconds).
    pub created_ms: i64,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// A bucket's replication configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationConfig {
    /// The role replication acts as (`Role`), as given.
    pub role: String,
    /// The rules, in the order given.
    pub rules: Vec<ReplicationRule>,
}

/// One rule: which objects, to where, and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationRule {
    /// Its id (one is made up when none is given).
    pub id: String,
    /// Which rule wins when several match (`None` in the first version of the
    /// configuration, which has no `Filter`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    /// Whether it's on.
    pub enabled: bool,
    /// Which objects it covers.
    pub filter: ReplicationFilter,
    /// Whether delete markers are replicated (`DeleteMarkerReplication`; `None` when not
    /// given, as in the first version, which replicates them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_markers: Option<bool>,
    /// Whether deletes of versions by id are replicated too (`MinIO`'s
    /// `DeleteReplication`; S3 never replicates them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_replication: Option<bool>,
    /// Whether objects from before the rule are replicated (`ExistingObjectReplication`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_objects: Option<bool>,
    /// Whether SSE-KMS objects are replicated (`SseKmsEncryptedObjects`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse_kms_objects: Option<bool>,
    /// Whether changes to replicas' metadata come back (`ReplicaModifications`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_modifications: Option<bool>,
    /// Where objects go.
    pub destination: ReplicationDestination,
}

/// Which objects a rule covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReplicationFilter {
    /// The first version's `Prefix`, beside the rule's other elements.
    V1Prefix(String),
    /// `Filter` with nothing in it: every object.
    All,
    /// `Filter` with a `Prefix`.
    Prefix(String),
    /// `Filter` with one `Tag`.
    Tag(Tag),
    /// `Filter` with `And`: a prefix (if any) and every tag.
    And {
        /// The prefix, if given.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        /// The tags.
        tags: Vec<Tag>,
    },
}

/// A tag a filter needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    /// Its key.
    pub key: String,
    /// Its value.
    pub value: String,
}

/// Where a rule's objects go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationDestination {
    /// The bucket's ARN: `arn:aws:s3:::NAME` on the same drive, or a remote target's.
    pub bucket: String,
    /// The account that owns it (`Account`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The replicas' storage class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// Whether replicas belong to the destination's owner (`AccessControlTranslation`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owner_override: bool,
    /// How replicas are encrypted (`EncryptionConfiguration`), if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<ReplicaEncryption>,
    /// S3 Replication Time Control: on or off, and its minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication_time: Option<Switch>,
    /// Replication metrics: on or off, and the event threshold's minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Switch>,
}

/// How replicas are encrypted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicaEncryption {
    /// The KMS key replicas of SSE-KMS objects are encrypted with (`ReplicaKmsKeyID`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key: Option<String>,
}

/// A setting that's on or off, with minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Switch {
    /// Whether it's on.
    pub enabled: bool,
    /// Its minutes, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minutes: Option<i32>,
}

/// Where a version stands in replication, as `x-amz-replication-status` says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplicationStatus {
    /// Not copied yet (or copying failed for a while and will be tried again).
    Pending,
    /// Copied to every destination.
    Completed,
    /// Can't be copied to some destination, and won't be tried again by itself.
    Failed,
    /// A copy another bucket replicated here.
    Replica,
}

impl ReplicationStatus {
    /// As S3 spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Replica => "REPLICA",
        }
    }
}

/// A version's replication: where it stands with each destination it goes to (by ARN),
/// and so overall; or that it's a replica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionReplication {
    /// Where it stands overall: `FAILED` if any destination failed, else `PENDING` while
    /// any waits, else `COMPLETED`.
    pub status: ReplicationStatus,
    /// Each destination's status.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub targets: BTreeMap<String, ReplicationStatus>,
    /// The waiting destinations that have the version and wait only for what changed
    /// in its metadata since (tags, retention, legal hold).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub metadata: BTreeSet<String>,
}

impl VersionReplication {
    /// Waiting for each of `destinations`; `None` when there are none.
    #[must_use]
    pub fn pending(destinations: impl IntoIterator<Item = String>) -> Option<Self> {
        let targets: BTreeMap<_, _> = destinations
            .into_iter()
            .map(|arn| (arn, ReplicationStatus::Pending))
            .collect();
        (!targets.is_empty()).then_some(Self {
            status: ReplicationStatus::Pending,
            targets,
            metadata: BTreeSet::new(),
        })
    }

    /// A replica's.
    #[must_use]
    pub const fn replica() -> Self {
        Self {
            status: ReplicationStatus::Replica,
            targets: BTreeMap::new(),
            metadata: BTreeSet::new(),
        }
    }

    /// With `arn`'s status set to `status`, and the overall one to match.
    #[must_use]
    pub fn with(mut self, arn: &str, status: ReplicationStatus) -> Self {
        if let Some(target) = self.targets.get_mut(arn) {
            *target = status;
        }
        if status != ReplicationStatus::Pending {
            self.metadata.remove(arn);
        }
        self.overall()
    }

    /// After its metadata changed: waiting again for every destination (those that have
    /// the version, for the change alone; those that failed, for all of it). A replica's
    /// is as it was.
    #[must_use]
    pub fn changed(mut self) -> Self {
        if self.status == ReplicationStatus::Replica {
            return self;
        }
        for (arn, status) in &mut self.targets {
            if *status == ReplicationStatus::Completed {
                self.metadata.insert(arn.clone());
            }
            *status = ReplicationStatus::Pending;
        }
        self.overall()
    }

    /// With the overall status matching each destination's.
    fn overall(mut self) -> Self {
        let statuses = || self.targets.values().copied();
        self.status = if statuses().any(|s| s == ReplicationStatus::Failed) {
            ReplicationStatus::Failed
        } else if statuses().any(|s| s == ReplicationStatus::Pending) {
            ReplicationStatus::Pending
        } else {
            ReplicationStatus::Completed
        };
        self
    }

    /// The destinations still waiting.
    pub fn waiting(&self) -> impl Iterator<Item = &str> {
        self.targets
            .iter()
            .filter(|(_, s)| **s == ReplicationStatus::Pending)
            .map(|(arn, _)| arn.as_str())
    }
}

impl ReplicationConfig {
    /// The destinations a new version of `key` with `tags` goes to: those of the enabled
    /// rules it matches (SSE-KMS versions, `kms`, only by rules that take them), each
    /// once.
    #[must_use]
    pub fn destinations(
        &self,
        key: &str,
        tags: &BTreeMap<String, String>,
        kms: bool,
    ) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for rule in &self.rules {
            if rule.matches(key, tags, kms) && !found.contains(&rule.destination.bucket) {
                found.push(rule.destination.bucket.clone());
            }
        }
        found
    }

    /// The destinations an existing version of `key` with `tags` (one written before
    /// the rules, or that no rule took then) goes to: those of the enabled rules it
    /// matches that replicate existing objects (`ExistingObjectReplication`), each once.
    #[must_use]
    pub fn existing_destinations(
        &self,
        key: &str,
        tags: &BTreeMap<String, String>,
        kms: bool,
    ) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for rule in &self.rules {
            if rule.existing_objects == Some(true)
                && rule.matches(key, tags, kms)
                && !found.contains(&rule.destination.bucket)
            {
                found.push(rule.destination.bucket.clone());
            }
        }
        found
    }

    /// Whether a rule replicates existing objects.
    #[must_use]
    pub fn replicates_existing(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.enabled && rule.existing_objects == Some(true))
    }

    /// The destinations a delete marker of `key` goes to: those of the enabled rules
    /// that replicate delete markers and take the key (a marker has no tags, and S3
    /// refuses marker replication in rules that filter by tag), each once.
    #[must_use]
    pub fn marker_destinations(&self, key: &str) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for rule in &self.rules {
            if rule.replicates_delete_markers()
                && rule.matches(key, &BTreeMap::new(), false)
                && !found.contains(&rule.destination.bucket)
            {
                found.push(rule.destination.bucket.clone());
            }
        }
        found
    }

    /// The destinations the removal of a version of `key` (with `tags`; SSE-KMS, `kms`)
    /// goes to, as `MinIO` decides: those of the enabled rules it matches that replicate
    /// version deletes (`DeleteReplication`) and, for a delete marker, those it was
    /// replicated to (`sent_to`), each once. S3 replicates neither.
    #[must_use]
    pub fn removal_destinations(
        &self,
        key: &str,
        (tags, kms): (&BTreeMap<String, String>, bool),
        sent_to: &[&str],
    ) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for rule in &self.rules {
            let arn = &rule.destination.bucket;
            if rule.matches(key, tags, kms)
                && (rule.delete_replication == Some(true) || sent_to.contains(&arn.as_str()))
                && !found.contains(arn)
            {
                found.push(arn.clone());
            }
        }
        found
    }
}

impl ReplicationRule {
    /// Whether the rule is on and takes a version of `key` with `tags` (SSE-KMS, `kms`).
    #[must_use]
    pub fn matches(&self, key: &str, tags: &BTreeMap<String, String>, kms: bool) -> bool {
        self.enabled
            && key.starts_with(self.prefix())
            && self
                .tags()
                .iter()
                .all(|t| tags.get(&t.key) == Some(&t.value))
            && (!kms || self.sse_kms_objects == Some(true))
    }

    /// Whether the rule replicates delete markers: the first version always does (for
    /// deletes people make); later ones when `DeleteMarkerReplication` is enabled.
    #[must_use]
    pub fn replicates_delete_markers(&self) -> bool {
        match self.filter {
            ReplicationFilter::V1Prefix(_) => true,
            _ => self.delete_markers == Some(true),
        }
    }

    /// The prefix keys must start with (empty: every key).
    #[must_use]
    pub fn prefix(&self) -> &str {
        match &self.filter {
            ReplicationFilter::V1Prefix(prefix)
            | ReplicationFilter::Prefix(prefix)
            | ReplicationFilter::And {
                prefix: Some(prefix),
                ..
            } => prefix,
            _ => "",
        }
    }

    /// The tags an object must have.
    #[must_use]
    pub fn tags(&self) -> &[Tag] {
        match &self.filter {
            ReplicationFilter::Tag(tag) => std::slice::from_ref(tag),
            ReplicationFilter::And { tags, .. } => tags,
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(filter: ReplicationFilter, delete_markers: Option<bool>) -> ReplicationRule {
        ReplicationRule {
            id: "r".to_owned(),
            priority: Some(1),
            enabled: true,
            filter,
            delete_markers,
            delete_replication: None,
            existing_objects: None,
            sse_kms_objects: None,
            replica_modifications: None,
            destination: ReplicationDestination {
                bucket: "arn:aws:s3:::copy".to_owned(),
                account: None,
                storage_class: None,
                owner_override: false,
                encryption: None,
                replication_time: None,
                metrics: None,
            },
        }
    }

    #[test]
    fn configurations_round_trip_as_given() {
        let tag = Tag {
            key: "team".to_owned(),
            value: "red".to_owned(),
        };
        let config = ReplicationConfig {
            role: "arn:aws:iam::123456789012:role/replication".to_owned(),
            rules: vec![rule(
                ReplicationFilter::And {
                    prefix: Some("docs/".to_owned()),
                    tags: vec![tag],
                },
                Some(false),
            )],
        };
        let text = serde_json::to_string(&config).unwrap();
        assert_eq!(
            text,
            r#"{"role":"arn:aws:iam::123456789012:role/replication","rules":[{"id":"r","priority":1,"enabled":true,"filter":{"and":{"prefix":"docs/","tags":[{"key":"team","value":"red"}]}},"deleteMarkers":false,"destination":{"bucket":"arn:aws:s3:::copy"}}]}"#
        );
        assert_eq!(
            serde_json::from_str::<ReplicationConfig>(&text).unwrap(),
            config
        );
    }

    #[test]
    fn the_first_version_replicates_delete_markers_and_later_ones_when_asked() {
        let v1 = rule(ReplicationFilter::V1Prefix("a/".to_owned()), None);
        assert!(v1.replicates_delete_markers());
        assert_eq!(v1.prefix(), "a/");
        assert!(!rule(ReplicationFilter::All, None).replicates_delete_markers());
        assert!(!rule(ReplicationFilter::All, Some(false)).replicates_delete_markers());
        assert!(rule(ReplicationFilter::All, Some(true)).replicates_delete_markers());
        let tag = Tag {
            key: "k".to_owned(),
            value: "v".to_owned(),
        };
        let tagged = rule(ReplicationFilter::Tag(tag.clone()), None);
        assert_eq!(tagged.tags(), [tag]);
        assert_eq!(tagged.prefix(), "");
    }

    #[test]
    fn existing_versions_go_only_where_rules_replicate_existing_objects() {
        let mut existing = rule(ReplicationFilter::Prefix("docs/".to_owned()), None);
        existing.existing_objects = Some(true);
        existing.destination.bucket = "arn:aws:s3:::other".to_owned();
        let mut config = ReplicationConfig {
            role: String::new(),
            rules: vec![rule(ReplicationFilter::All, None), existing.clone()],
        };
        assert!(config.replicates_existing());
        let none = BTreeMap::new();
        assert_eq!(
            config.existing_destinations("docs/a", &none, false),
            ["arn:aws:s3:::other"]
        );
        assert!(
            config
                .existing_destinations("photos/a", &none, false)
                .is_empty()
        );
        // SSE-KMS versions only by rules that take them.
        assert!(
            config
                .existing_destinations("docs/a", &none, true)
                .is_empty()
        );
        config.rules[1].enabled = false;
        assert!(!config.replicates_existing());
        assert!(
            config
                .existing_destinations("docs/a", &none, false)
                .is_empty()
        );
    }

    #[test]
    fn markers_go_where_rules_that_replicate_them_send_the_key() {
        let mut other = rule(ReplicationFilter::Prefix("docs/".to_owned()), Some(true));
        other.destination.bucket = "arn:aws:s3:::other".to_owned();
        let config = ReplicationConfig {
            role: String::new(),
            rules: vec![
                rule(ReplicationFilter::All, Some(false)),
                other.clone(),
                ReplicationRule {
                    enabled: false,
                    ..rule(ReplicationFilter::All, Some(true))
                },
            ],
        };
        assert_eq!(config.marker_destinations("docs/a"), ["arn:aws:s3:::other"]);
        assert!(config.marker_destinations("photos/a").is_empty());
        // Versions go to both.
        assert_eq!(
            config.destinations("docs/a", &BTreeMap::new(), false),
            ["arn:aws:s3:::copy", "arn:aws:s3:::other"]
        );
    }
    #[test]
    fn removals_go_where_rules_replicate_deletes_or_the_marker_went() {
        let mut deletes = rule(ReplicationFilter::Prefix("docs/".to_owned()), Some(true));
        deletes.delete_replication = Some(true);
        deletes.destination.bucket = "arn:aws:s3:::deletes".to_owned();
        let config = ReplicationConfig {
            role: String::new(),
            rules: vec![
                rule(ReplicationFilter::All, Some(true)),
                deletes.clone(),
                ReplicationRule {
                    enabled: false,
                    destination: ReplicationDestination {
                        bucket: "arn:aws:s3:::off".to_owned(),
                        ..deletes.destination.clone()
                    },
                    ..deletes
                },
            ],
        };
        let none = BTreeMap::new();
        assert_eq!(
            config.removal_destinations("docs/a", (&none, false), &[]),
            ["arn:aws:s3:::deletes"]
        );
        assert!(
            config
                .removal_destinations("photos/a", (&none, false), &[])
                .is_empty()
        );
        // A marker's removal follows the marker, where a rule still sends the key.
        assert_eq!(
            config.removal_destinations(
                "photos/a",
                (&none, false),
                &["arn:aws:s3:::copy", "arn:aws:s3:::off", "arn:aws:s3:::gone"]
            ),
            ["arn:aws:s3:::copy"]
        );
        assert_eq!(
            config.removal_destinations("docs/a", (&none, false), &["arn:aws:s3:::copy"]),
            ["arn:aws:s3:::copy", "arn:aws:s3:::deletes"]
        );
    }

    #[test]
    fn a_metadata_change_waits_for_the_change_alone_where_the_version_is() {
        let arns = ["arn:a", "arn:b", "arn:c"].map(str::to_owned);
        let replication = VersionReplication::pending(arns.clone())
            .unwrap()
            .with("arn:a", ReplicationStatus::Completed)
            .with("arn:b", ReplicationStatus::Failed);
        let changed = replication.changed();
        assert_eq!(changed.status, ReplicationStatus::Pending);
        assert_eq!(changed.waiting().count(), 3);
        // Only where it arrived does the change go alone.
        assert_eq!(changed.metadata, BTreeSet::from(["arn:a".to_owned()]));
        let sent = changed.with("arn:a", ReplicationStatus::Completed);
        assert!(sent.metadata.is_empty());
        // A replica's changes aren't sent back.
        assert_eq!(
            VersionReplication::replica().changed(),
            VersionReplication::replica()
        );
        // Written before there was a `metadata`, it reads as empty.
        let old: VersionReplication =
            serde_json::from_str(r#"{"status":"COMPLETED","targets":{"arn:a":"COMPLETED"}}"#)
                .unwrap();
        assert!(old.metadata.is_empty());
        assert!(!serde_json::to_string(&old).unwrap().contains("metadata"));
    }
}
