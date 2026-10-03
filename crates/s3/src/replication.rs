//! `PutBucketReplication`, `GetBucketReplication`, `DeleteBucketReplication`: a bucket's
//! replication configuration, read from S3's XML with S3's checks, and answered as it
//! was given.

use s3s::{S3Error, S3ErrorCode, S3Result, dto, s3_error};
use teifs_store::{Store, Versioning};
use teifs_types::replication::{
    LOCAL_ARN, MAX_ID, MAX_RULES, ReplicaEncryption, ReplicationConfig, ReplicationDestination,
    ReplicationFilter, ReplicationRule, Switch, TARGET_ARN, Tag,
};

use crate::errors::StoreResultExt as _;

/// The minutes S3 Replication Time Control and its metrics' threshold take: S3 accepts
/// only these.
const RTC_MINUTES: i32 = 15;

/// The storage classes a destination may give replicas.
const STORAGE_CLASSES: [&str; 9] = [
    "STANDARD",
    "REDUCED_REDUNDANCY",
    "STANDARD_IA",
    "ONEZONE_IA",
    "INTELLIGENT_TIERING",
    "GLACIER",
    "DEEP_ARCHIVE",
    "GLACIER_IR",
    "OUTPOSTS",
];

/// `GetBucketReplication`'s answer for a bucket without a configuration.
pub(crate) fn not_found() -> S3Error {
    S3Error::with_message(
        S3ErrorCode::ReplicationConfigurationNotFoundError,
        "The replication configuration was not found",
    )
}

fn invalid_request(message: impl Into<String>) -> S3Error {
    S3Error::with_message(S3ErrorCode::InvalidRequest, message.into())
}

fn invalid_argument(message: impl Into<String>) -> S3Error {
    S3Error::with_message(S3ErrorCode::InvalidArgument, message.into())
}

fn enabled(status: &str) -> S3Result<bool> {
    match status {
        "Enabled" => Ok(true),
        "Disabled" => Ok(false),
        _ => Err(s3_error!(MalformedXML)),
    }
}

/// The configuration a `ReplicationConfiguration` gives, checked as S3 checks it on its
/// own (what it names on the drive is [`check`]ed apart).
pub(crate) fn from_dto(config: dto::ReplicationConfiguration) -> S3Result<ReplicationConfig> {
    if config.rules.is_empty() {
        return Err(s3_error!(MalformedXML));
    }
    if config.rules.len() > MAX_RULES {
        return Err(invalid_request(format!(
            "Number of rules in the replication configuration exceeds the allowed limit of \
             {MAX_RULES}"
        )));
    }
    // Every rule is the first version (a `Prefix` beside it) or every rule the later one
    // (a `Filter`), as on S3.
    let filtered = config.rules.iter().filter(|r| r.filter.is_some()).count();
    if filtered != 0 && filtered != config.rules.len() {
        return Err(s3_error!(MalformedXML));
    }
    let rules = config
        .rules
        .into_iter()
        .map(rule)
        .collect::<S3Result<Vec<_>>>()?;
    for (i, rule) in rules.iter().enumerate() {
        if rules[..i].iter().any(|other| other.id == rule.id) {
            return Err(invalid_argument("Rule Id must be unique"));
        }
        if rule.priority.is_some() && rules[..i].iter().any(|o| o.priority == rule.priority) {
            return Err(invalid_request(
                "Found duplicate priority. Rule priorities must be unique",
            ));
        }
    }
    Ok(ReplicationConfig {
        role: config.role,
        rules,
    })
}

fn rule(rule: dto::ReplicationRule) -> S3Result<ReplicationRule> {
    let id = match rule.id {
        Some(id) if id.chars().count() > MAX_ID => {
            return Err(invalid_argument(format!(
                "ID length should not exceed allowed limit of {MAX_ID}"
            )));
        }
        Some(id) if !id.is_empty() => id,
        // S3 names a rule given without an id.
        _ => uuid::Uuid::new_v4().simple().to_string(),
    };
    let filter = match (rule.prefix, rule.filter) {
        (Some(prefix), None) => ReplicationFilter::V1Prefix(prefix),
        (None, Some(filter)) => filter_of(filter)?,
        // Both, or neither.
        _ => return Err(s3_error!(MalformedXML)),
    };
    let v1 = matches!(filter, ReplicationFilter::V1Prefix(_));
    // The later version needs a priority and says whether delete markers go; the first
    // has neither.
    if !v1 && (rule.priority.is_none() || rule.delete_marker_replication.is_none()) {
        return Err(s3_error!(MalformedXML));
    }
    if rule.priority.is_some_and(|p| p < 0) {
        return Err(invalid_argument(
            "Priority must be zero or a positive integer",
        ));
    }
    let delete_markers = rule
        .delete_marker_replication
        .map(|d| d.status.as_ref().map_or(Ok(false), |s| enabled(s.as_str())))
        .transpose()?;
    let tagged = matches!(
        filter,
        ReplicationFilter::Tag(_) | ReplicationFilter::And { .. }
    ) && !matches!(&filter, ReplicationFilter::And { tags, .. } if tags.is_empty());
    if tagged && delete_markers == Some(true) {
        return Err(invalid_request(
            "Delete marker replication is not supported if any Tag filter is specified. \
             Please refer to S3 Developer Guide for more information.",
        ));
    }
    let criteria = rule.source_selection_criteria;
    let sse_kms_objects = criteria
        .as_ref()
        .and_then(|c| c.sse_kms_encrypted_objects.as_ref())
        .map(|s| enabled(s.status.as_str()))
        .transpose()?;
    let replica_modifications = criteria
        .as_ref()
        .and_then(|c| c.replica_modifications.as_ref())
        .map(|s| enabled(s.status.as_str()))
        .transpose()?;
    let destination = destination(rule.destination)?;
    if sse_kms_objects == Some(true)
        && destination
            .encryption
            .as_ref()
            .is_none_or(|e| e.kms_key.is_none())
    {
        return Err(invalid_request(
            "ReplicaKmsKeyID must be specified if SseKmsEncryptedObjects tag is present.",
        ));
    }
    Ok(ReplicationRule {
        id,
        priority: rule.priority,
        enabled: enabled(rule.status.as_str())?,
        filter,
        delete_markers,
        delete_replication: rule
            .delete_replication
            .map(|d| enabled(d.status.as_str()))
            .transpose()?,
        existing_objects: rule
            .existing_object_replication
            .map(|e| enabled(e.status.as_str()))
            .transpose()?,
        sse_kms_objects,
        replica_modifications,
        destination,
    })
}

fn tag(tag: dto::Tag) -> S3Result<Tag> {
    match (tag.key, tag.value) {
        (Some(key), Some(value)) if !key.is_empty() => Ok(Tag { key, value }),
        _ => Err(s3_error!(MalformedXML)),
    }
}

fn filter_of(filter: dto::ReplicationRuleFilter) -> S3Result<ReplicationFilter> {
    // minio-go (`mc replicate add`) writes every element of a filter, the empty ones too:
    // an `And` or a `Tag` with nothing in it says nothing, and an empty `Prefix` beside
    // either says nothing more, as `MinIO` reads them.
    let and = filter.and.filter(|a| {
        a.prefix.as_deref().is_some_and(|p| !p.is_empty())
            || a.tags.as_ref().is_some_and(|t| !t.is_empty())
    });
    let one_tag = filter
        .tag
        .filter(|t| t.key.as_deref().is_some_and(|k| !k.is_empty()) || t.value.is_some());
    let prefix = filter
        .prefix
        .filter(|p| !p.is_empty() || (and.is_none() && one_tag.is_none()));
    match (prefix, one_tag, and) {
        (None, None, None) => Ok(ReplicationFilter::All),
        (Some(prefix), None, None) => Ok(ReplicationFilter::Prefix(prefix)),
        (None, Some(t), None) => Ok(ReplicationFilter::Tag(tag(t)?)),
        (None, None, Some(and)) => {
            let tags = and
                .tags
                .unwrap_or_default()
                .into_iter()
                .map(tag)
                .collect::<S3Result<Vec<_>>>()?;
            if tags
                .iter()
                .enumerate()
                .any(|(i, t)| tags[..i].iter().any(|o| o.key == t.key))
            {
                return Err(invalid_request("Duplicate Tag Keys are not allowed."));
            }
            Ok(ReplicationFilter::And {
                prefix: and.prefix,
                tags,
            })
        }
        _ => Err(s3_error!(MalformedXML)),
    }
}

fn switch(status: &str, minutes: Option<i32>, what: &str) -> S3Result<Switch> {
    let switch = Switch {
        enabled: enabled(status)?,
        minutes,
    };
    if switch.enabled && minutes != Some(RTC_MINUTES) {
        return Err(invalid_argument(format!(
            "{what} must be {RTC_MINUTES} minutes"
        )));
    }
    Ok(switch)
}

fn destination(destination: dto::Destination) -> S3Result<ReplicationDestination> {
    if destination.bucket.is_empty() {
        return Err(s3_error!(MalformedXML));
    }
    let storage_class = destination.storage_class.map(|c| c.as_str().to_owned());
    if let Some(class) = &storage_class
        && !STORAGE_CLASSES.contains(&class.as_str())
    {
        return Err(s3_error!(
            InvalidStorageClass,
            "The storage class you specified is not valid"
        ));
    }
    let owner_override = match destination.access_control_translation {
        Some(translation) if translation.owner.as_str() == dto::OwnerOverride::DESTINATION => true,
        Some(_) => return Err(s3_error!(MalformedXML)),
        None => false,
    };
    if owner_override && destination.account.is_none() {
        return Err(invalid_request(
            "Account must be specified when AccessControlTranslation is specified",
        ));
    }
    let replication_time = destination
        .replication_time
        .map(|t| {
            switch(
                t.status.as_str(),
                t.time.minutes,
                "Replication Time Control's time",
            )
        })
        .transpose()?;
    let metrics = destination
        .metrics
        .map(|m| {
            switch(
                m.status.as_str(),
                m.event_threshold.and_then(|t| t.minutes),
                "The metrics' event threshold",
            )
        })
        .transpose()?;
    if replication_time.is_some_and(|t| t.enabled) && !metrics.is_some_and(|m| m.enabled) {
        return Err(invalid_request(
            "Replication Time Control must be used with Metrics enabled",
        ));
    }
    Ok(ReplicationDestination {
        bucket: destination.bucket,
        account: destination.account,
        storage_class,
        owner_override,
        encryption: destination
            .encryption_configuration
            .map(|e| ReplicaEncryption {
                kms_key: e.replica_kms_key_id,
            }),
        replication_time,
        metrics,
    })
}

/// `config` checked again as it would be given (an import's).
pub(crate) fn checked(config: &ReplicationConfig) -> S3Result<ReplicationConfig> {
    from_dto(to_dto(config))
}

/// The configuration as `PutBucketReplication`'s body, as `teifs replicate` sends it.
#[must_use]
pub fn to_xml(config: &ReplicationConfig) -> Vec<u8> {
    use s3s::xml::Serialize;
    let mut xml = Vec::new();
    to_dto(config)
        .serialize(&mut s3s::xml::Serializer::new(&mut xml))
        .expect("a replication configuration serializes");
    xml
}

/// A configuration from `GetBucketReplication`'s answer, checked as a request's would be.
///
/// # Errors
///
/// Why it isn't a configuration S3 would take.
pub fn from_xml(xml: &[u8]) -> Result<ReplicationConfig, String> {
    use s3s::xml::Deserialize;
    let mut d = s3s::xml::Deserializer::new(xml);
    let config = dto::ReplicationConfiguration::deserialize(&mut d)
        .and_then(|config| d.expect_eof().map(|()| config))
        .map_err(|_| "the answer isn't a replication configuration".to_owned())?;
    from_dto(config).map_err(|err| {
        err.message()
            .unwrap_or("the replication configuration isn't valid")
            .to_owned()
    })
}

/// Checks what `config` names on the drive: the bucket keeps every version, and each
/// destination is a bucket that does too.
pub(crate) async fn check(store: &Store, bucket: &str, config: &ReplicationConfig) -> S3Result<()> {
    if store.bucket_versioning(bucket).await.s3()? != Versioning::Enabled {
        return Err(invalid_request(
            "Versioning must be 'Enabled' on the bucket to apply a replication configuration",
        ));
    }
    for rule in &config.rules {
        let arn = &rule.destination.bucket;
        if let Some(name) = arn.strip_prefix(LOCAL_ARN) {
            if name == bucket {
                return Err(invalid_request(
                    "Destination bucket cannot be the same as the source bucket.",
                ));
            }
            match store.bucket_versioning(name).await {
                Ok(Versioning::Enabled) => {}
                Ok(_) => {
                    return Err(invalid_request(
                        "Destination bucket must have versioning enabled.",
                    ));
                }
                Err(teifs_store::StoreError::NoSuchBucket) => {
                    return Err(invalid_request("Destination bucket must exist."));
                }
                Err(err) => return Err(err).s3(),
            }
        } else if arn.starts_with(TARGET_ARN) {
            // A remote target, which must be the source bucket's.
            let target = store.replication_target(arn).await.s3()?;
            if target.is_none_or(|t| t.source_bucket != bucket) {
                return Err(invalid_request(format!(
                    "{arn} isn't a replication target of this bucket"
                )));
            }
        } else {
            return Err(invalid_argument("Invalid ARN"));
        }
    }
    Ok(())
}

fn status(on: bool) -> &'static str {
    if on { "Enabled" } else { "Disabled" }
}

fn tag_dto(tag: &Tag) -> dto::Tag {
    dto::Tag {
        key: Some(tag.key.clone()),
        value: Some(tag.value.clone()),
    }
}

/// The configuration as `GetBucketReplication` answers it: as it was given.
pub(crate) fn to_dto(config: &ReplicationConfig) -> dto::ReplicationConfiguration {
    dto::ReplicationConfiguration {
        role: config.role.clone(),
        rules: config.rules.iter().map(rule_dto).collect(),
    }
}

fn rule_dto(rule: &ReplicationRule) -> dto::ReplicationRule {
    let (prefix, filter) = match &rule.filter {
        ReplicationFilter::V1Prefix(prefix) => (Some(prefix.clone()), None),
        ReplicationFilter::All => (None, Some(dto::ReplicationRuleFilter::default())),
        ReplicationFilter::Prefix(prefix) => (
            None,
            Some(dto::ReplicationRuleFilter {
                prefix: Some(prefix.clone()),
                ..Default::default()
            }),
        ),
        ReplicationFilter::Tag(tag) => (
            None,
            Some(dto::ReplicationRuleFilter {
                tag: Some(tag_dto(tag)),
                ..Default::default()
            }),
        ),
        ReplicationFilter::And { prefix, tags } => (
            None,
            Some(dto::ReplicationRuleFilter {
                and: Some(dto::ReplicationRuleAndOperator {
                    prefix: prefix.clone(),
                    tags: Some(tags.iter().map(tag_dto).collect()),
                }),
                ..Default::default()
            }),
        ),
    };
    let criteria =
        (rule.sse_kms_objects.is_some() || rule.replica_modifications.is_some()).then(|| {
            dto::SourceSelectionCriteria {
                replica_modifications: rule.replica_modifications.map(|on| {
                    dto::ReplicaModifications {
                        status: dto::ReplicaModificationsStatus::from_static(status(on)),
                    }
                }),
                sse_kms_encrypted_objects: rule.sse_kms_objects.map(|on| {
                    dto::SseKmsEncryptedObjects {
                        status: dto::SseKmsEncryptedObjectsStatus::from_static(status(on)),
                    }
                }),
            }
        });
    let d = &rule.destination;
    dto::ReplicationRule {
        delete_marker_replication: rule.delete_markers.map(|on| dto::DeleteMarkerReplication {
            status: Some(dto::DeleteMarkerReplicationStatus::from_static(status(on))),
        }),
        delete_replication: rule.delete_replication.map(|on| dto::DeleteReplication {
            status: dto::DeleteReplicationStatus::from_static(status(on)),
        }),
        destination: dto::Destination {
            access_control_translation: d.owner_override.then(|| dto::AccessControlTranslation {
                owner: dto::OwnerOverride::from_static(dto::OwnerOverride::DESTINATION),
            }),
            account: d.account.clone(),
            bucket: d.bucket.clone(),
            encryption_configuration: d.encryption.as_ref().map(|e| dto::EncryptionConfiguration {
                replica_kms_key_id: e.kms_key.clone(),
            }),
            metrics: d.metrics.map(|m| dto::Metrics {
                event_threshold: m.minutes.map(|minutes| dto::ReplicationTimeValue {
                    minutes: Some(minutes),
                }),
                status: dto::MetricsStatus::from_static(status(m.enabled)),
            }),
            replication_time: d.replication_time.map(|t| dto::ReplicationTime {
                status: dto::ReplicationTimeStatus::from_static(status(t.enabled)),
                time: dto::ReplicationTimeValue { minutes: t.minutes },
            }),
            storage_class: d.storage_class.clone().map(dto::StorageClass::from),
        },
        existing_object_replication: rule.existing_objects.map(|on| {
            dto::ExistingObjectReplication {
                status: dto::ExistingObjectReplicationStatus::from_static(status(on)),
            }
        }),
        filter,
        id: Some(rule.id.clone()),
        prefix,
        priority: rule.priority,
        source_selection_criteria: criteria,
        status: dto::ReplicationRuleStatus::from_static(status(rule.enabled)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configuration_goes_to_xml_and_back_with_minios_elements() {
        let config = ReplicationConfig {
            role: String::new(),
            rules: vec![ReplicationRule {
                id: "to-backup".to_owned(),
                priority: Some(3),
                enabled: true,
                filter: ReplicationFilter::And {
                    prefix: Some("photos/".to_owned()),
                    tags: vec![Tag {
                        key: "keep".to_owned(),
                        value: "yes".to_owned(),
                    }],
                },
                delete_markers: Some(false),
                delete_replication: Some(true),
                existing_objects: Some(false),
                sse_kms_objects: None,
                replica_modifications: Some(true),
                destination: ReplicationDestination {
                    bucket: format!("{TARGET_ARN}us-east-1:1:backup"),
                    account: None,
                    storage_class: Some("STANDARD_IA".to_owned()),
                    owner_override: false,
                    encryption: None,
                    replication_time: None,
                    metrics: None,
                },
            }],
        };
        let xml = to_xml(&config);
        let text = String::from_utf8_lossy(&xml);
        assert!(text.contains("<DeleteReplication>"), "{text}");
        assert_eq!(from_xml(&xml).as_ref(), Ok(&config));
        // S3's checks apply: a rule with a tag can't replicate delete markers.
        let mut tagged = config;
        tagged.rules[0].delete_markers = Some(true);
        let err = from_xml(&to_xml(&tagged)).unwrap_err();
        assert!(err.contains("Delete marker replication"), "{err}");
        assert!(from_xml(b"not xml").is_err());
    }
}
