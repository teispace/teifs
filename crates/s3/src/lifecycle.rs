//! S3 Lifecycle's messages: a bucket's configuration, checked the way S3 checks it and
//! answered exactly as it was given, and the headers that say when an object expires or
//! an upload is aborted. What the rules mean is the store's.

use s3s::{S3Result, dto, s3_error};
use teifs_store::{
    And, Condition, DAY_MS, Expiration, Expiry, Lifecycle, LifecycleRule, MAX_LIFECYCLE_RULES,
    MAX_NEWER_NONCURRENT, MAX_RULE_ID_LEN, NoncurrentExpiration, RuleFilter, Tag,
};

use crate::{object_lock::ms_of, tagging};

/// A bucket's lifecycle configuration from `PutBucketLifecycleConfiguration`'s body (or
/// the older `PutBucketLifecycle`'s, which names a prefix on each rule instead of a
/// filter), checked as S3 checks it.
pub(crate) fn from_dto(
    config: Option<dto::BucketLifecycleConfiguration>,
    transition_minimum_size: Option<&dto::TransitionDefaultMinimumObjectSize>,
) -> S3Result<Lifecycle> {
    let config = config.ok_or_else(|| s3_error!(MalformedXML))?;
    if config.rules.is_empty() || config.rules.len() > MAX_LIFECYCLE_RULES {
        return Err(s3_error!(
            MalformedXML,
            "A lifecycle configuration has 1 to {MAX_LIFECYCLE_RULES} rules"
        ));
    }
    let transition_minimum_size = transition_minimum_size
        .map(|size| match size.as_str() {
            s @ ("all_storage_classes_128K" | "varies_by_storage_class") => Ok(s.to_owned()),
            _ => Err(s3_error!(
                InvalidArgument,
                "Invalid x-amz-transition-default-minimum-object-size"
            )),
        })
        .transpose()?;
    let mut rules: Vec<LifecycleRule> = Vec::with_capacity(config.rules.len());
    for rule in config.rules {
        let rule = rule_from_dto(rule)?;
        if rules.iter().any(|r| r.id == rule.id) {
            return Err(s3_error!(
                InvalidArgument,
                "Rule ID must be unique. Found same ID for more than one rule"
            ));
        }
        rules.push(rule);
    }
    Ok(Lifecycle {
        rules,
        transition_minimum_size,
    })
}

fn rule_from_dto(rule: dto::LifecycleRule) -> S3Result<LifecycleRule> {
    let id = match rule.id {
        Some(id) if id.chars().count() > MAX_RULE_ID_LEN => {
            return Err(s3_error!(
                InvalidArgument,
                "ID length should not exceed allowed limit of {MAX_RULE_ID_LEN}"
            ));
        }
        Some(id) if !id.is_empty() => id,
        // S3 names a rule given without an id.
        _ => uuid::Uuid::new_v4().simple().to_string(),
    };
    let enabled = match rule.status.as_str() {
        dto::ExpirationStatus::ENABLED => true,
        dto::ExpirationStatus::DISABLED => false,
        _ => return Err(s3_error!(MalformedXML)),
    };
    let filter = match (rule.filter, rule.prefix) {
        (Some(_), Some(_)) => return Err(s3_error!(MalformedXML)),
        (Some(filter), None) => RuleFilter::Filter(condition_from_dto(filter)?),
        (None, Some(prefix)) => RuleFilter::RulePrefix(prefix),
        (None, None) => RuleFilter::All,
    };
    let expiration = rule.expiration.map(expiration_from_dto).transpose()?;
    let noncurrent_expiration = rule
        .noncurrent_version_expiration
        .map(|n| noncurrent_from_dto(&n, &filter))
        .transpose()?;
    let abort_uploads_after_days = rule
        .abort_incomplete_multipart_upload
        .map(|abort| {
            positive(
                abort.days_after_initiation,
                "'DaysAfterInitiation' for AbortIncompleteMultipartUpload action must be a positive integer",
            )
        })
        .transpose()?;
    check_transitions(rule.transitions, rule.noncurrent_version_transitions)?;
    if expiration.is_none() && noncurrent_expiration.is_none() && abort_uploads_after_days.is_none()
    {
        return Err(s3_error!(
            InvalidRequest,
            "At least one action needs to be specified in a rule"
        ));
    }
    if filter.has_tags() && matches!(expiration, Some(Expiration::ExpiredDeleteMarker(_))) {
        return Err(s3_error!(
            InvalidRequest,
            "ExpiredObjectDeleteMarker cannot be specified with object tags"
        ));
    }
    if abort_uploads_after_days.is_some() && (filter.has_tags() || filter.has_sizes()) {
        return Err(s3_error!(
            InvalidRequest,
            "AbortIncompleteMultipartUpload cannot be specified with object tags or sizes"
        ));
    }
    Ok(LifecycleRule {
        id,
        enabled,
        filter,
        expiration,
        noncurrent_expiration,
        abort_uploads_after_days,
    })
}

/// A number of days S3 requires to be at least one.
fn positive(days: Option<i32>, message: &'static str) -> S3Result<u32> {
    days.and_then(|d| u32::try_from(d).ok())
        .filter(|&d| d > 0)
        .ok_or_else(|| s3_error!(InvalidArgument, "{message}"))
}

fn size(bytes: i64) -> S3Result<u64> {
    u64::try_from(bytes)
        .map_err(|_| s3_error!(InvalidArgument, "Object size filters can't be negative"))
}

fn tag(tag: &dto::Tag) -> S3Result<Tag> {
    let (Some(key), Some(value)) = (&tag.key, &tag.value) else {
        return Err(s3_error!(MalformedXML));
    };
    tagging::check(vec![(key.clone(), value.clone())], 1)?;
    Ok(Tag {
        key: key.clone(),
        value: value.clone(),
    })
}

fn condition_from_dto(filter: dto::LifecycleRuleFilter) -> S3Result<Condition> {
    let given = usize::from(filter.prefix.is_some())
        + usize::from(filter.tag.is_some())
        + usize::from(filter.object_size_greater_than.is_some())
        + usize::from(filter.object_size_less_than.is_some())
        + usize::from(filter.and.is_some());
    if given > 1 {
        return Err(s3_error!(
            MalformedXML,
            "A filter has one condition; use And to combine them"
        ));
    }
    Ok(if let Some(prefix) = filter.prefix {
        Condition::Prefix(prefix)
    } else if let Some(t) = &filter.tag {
        Condition::Tag(tag(t)?)
    } else if let Some(bytes) = filter.object_size_greater_than {
        Condition::GreaterThan(size(bytes)?)
    } else if let Some(bytes) = filter.object_size_less_than {
        Condition::LessThan(size(bytes)?)
    } else if let Some(and) = filter.and {
        Condition::And(and_from_dto(and)?)
    } else {
        Condition::Empty
    })
}

fn and_from_dto(and: dto::LifecycleRuleAndOperator) -> S3Result<And> {
    let tags: Vec<Tag> = and
        .tags
        .unwrap_or_default()
        .iter()
        .map(tag)
        .collect::<S3Result<_>>()?;
    tagging::check(
        tags.iter()
            .map(|t| (t.key.clone(), t.value.clone()))
            .collect(),
        usize::MAX,
    )?;
    let and = And {
        prefix: and.prefix,
        tags,
        greater_than: and.object_size_greater_than.map(size).transpose()?,
        less_than: and.object_size_less_than.map(size).transpose()?,
    };
    if and == And::default() {
        return Err(s3_error!(MalformedXML));
    }
    if let (Some(min), Some(max)) = (and.greater_than, and.less_than)
        && min >= max
    {
        return Err(s3_error!(
            InvalidArgument,
            "ObjectSizeGreaterThan must be less than ObjectSizeLessThan"
        ));
    }
    Ok(and)
}

fn expiration_from_dto(expiration: dto::LifecycleExpiration) -> S3Result<Expiration> {
    match (
        expiration.days,
        expiration.date,
        expiration.expired_object_delete_marker,
    ) {
        (Some(days), None, None) => Ok(Expiration::Days(positive(
            Some(days),
            "'Days' for Expiration action must be a positive integer",
        )?)),
        (None, Some(date), None) => {
            let ms = ms_of(&date);
            if ms.rem_euclid(DAY_MS) != 0 {
                return Err(s3_error!(InvalidArgument, "'Date' must be at midnight GMT"));
            }
            Ok(Expiration::Date(ms))
        }
        (None, None, Some(marker)) => Ok(Expiration::ExpiredDeleteMarker(marker)),
        (_, _, Some(_)) => Err(s3_error!(
            InvalidArgument,
            "ExpiredObjectDeleteMarker cannot be specified with Days or Date in a Lifecycle Expiration Policy"
        )),
        _ => Err(s3_error!(MalformedXML)),
    }
}

fn noncurrent_from_dto(
    noncurrent: &dto::NoncurrentVersionExpiration,
    filter: &RuleFilter,
) -> S3Result<NoncurrentExpiration> {
    let days = noncurrent
        .noncurrent_days
        .map(|d| {
            positive(
                Some(d),
                "'NoncurrentDays' for NoncurrentVersionExpiration action must be a positive integer",
            )
        })
        .transpose()?;
    let newer_versions = noncurrent
        .newer_noncurrent_versions
        .map(|n| {
            u32::try_from(n)
                .ok()
                .filter(|n| (1..=MAX_NEWER_NONCURRENT).contains(n))
                .ok_or_else(|| {
                    s3_error!(
                        InvalidArgument,
                        "'NewerNoncurrentVersions' must be between 1 and {MAX_NEWER_NONCURRENT}"
                    )
                })
        })
        .transpose()?;
    if newer_versions.is_some() && !matches!(filter, RuleFilter::Filter(_)) {
        return Err(s3_error!(
            InvalidRequest,
            "NewerNoncurrentVersions needs a Filter element in its rule"
        ));
    }
    if days.is_none() && newer_versions.is_none() {
        return Err(s3_error!(MalformedXML));
    }
    Ok(NoncurrentExpiration {
        days,
        newer_versions,
    })
}

/// TeiFS keeps every object in one storage class: a transition to another is refused
/// once the rest of it is checked, as S3 refuses a storage class it doesn't have.
fn check_transitions(
    transitions: Option<dto::TransitionList>,
    noncurrent: Option<dto::NoncurrentVersionTransitionList>,
) -> S3Result<()> {
    let transitions = transitions.unwrap_or_default();
    let noncurrent = noncurrent.unwrap_or_default();
    for transition in &transitions {
        if let Some(date) = &transition.date
            && ms_of(date).rem_euclid(DAY_MS) != 0
        {
            return Err(s3_error!(InvalidArgument, "'Date' must be at midnight GMT"));
        }
        if transition.days.is_some_and(|d| d < 0) {
            return Err(s3_error!(
                InvalidArgument,
                "'Days' in Transition action must be nonnegative"
            ));
        }
    }
    if noncurrent
        .iter()
        .any(|t| t.noncurrent_days.is_some_and(|d| d < 0))
    {
        return Err(s3_error!(
            InvalidArgument,
            "'NoncurrentDays' in NoncurrentVersionTransition action must be nonnegative"
        ));
    }
    if transitions.is_empty() && noncurrent.is_empty() {
        return Ok(());
    }
    Err(s3_error!(
        InvalidStorageClass,
        "The storage class you specified is not valid: this server keeps every object in STANDARD"
    ))
}

/// A bucket's lifecycle configuration as `GetBucketLifecycleConfiguration` answers it.
pub(crate) fn to_dto(lifecycle: &Lifecycle) -> dto::GetBucketLifecycleConfigurationOutput {
    dto::GetBucketLifecycleConfigurationOutput {
        rules: Some(lifecycle.rules.iter().map(rule_to_dto).collect()),
        transition_default_minimum_object_size: Some(minimum_size(lifecycle)),
    }
}

/// The `x-amz-transition-default-minimum-object-size` a configuration answers with.
pub(crate) fn minimum_size(lifecycle: &Lifecycle) -> dto::TransitionDefaultMinimumObjectSize {
    dto::TransitionDefaultMinimumObjectSize::from(
        lifecycle
            .transition_minimum_size
            .clone()
            .unwrap_or_else(|| "all_storage_classes_128K".to_owned()),
    )
}

fn tag_to_dto(tag: &Tag) -> dto::Tag {
    dto::Tag {
        key: Some(tag.key.clone()),
        value: Some(tag.value.clone()),
    }
}

fn size_to_dto(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

fn rule_to_dto(rule: &LifecycleRule) -> dto::LifecycleRule {
    let (filter, prefix) = match &rule.filter {
        RuleFilter::All => (None, None),
        RuleFilter::RulePrefix(prefix) => (None, Some(prefix.clone())),
        RuleFilter::Filter(condition) => {
            let mut filter = dto::LifecycleRuleFilter::default();
            match condition {
                Condition::Empty => {}
                Condition::Prefix(prefix) => filter.prefix = Some(prefix.clone()),
                Condition::Tag(tag) => filter.tag = Some(tag_to_dto(tag)),
                Condition::GreaterThan(b) => {
                    filter.object_size_greater_than = Some(size_to_dto(*b));
                }
                Condition::LessThan(b) => filter.object_size_less_than = Some(size_to_dto(*b)),
                Condition::And(and) => {
                    filter.and = Some(dto::LifecycleRuleAndOperator {
                        prefix: and.prefix.clone(),
                        tags: (!and.tags.is_empty())
                            .then(|| and.tags.iter().map(tag_to_dto).collect()),
                        object_size_greater_than: and.greater_than.map(size_to_dto),
                        object_size_less_than: and.less_than.map(size_to_dto),
                    });
                }
            }
            (Some(filter), None)
        }
    };
    let days = |d: u32| i32::try_from(d).unwrap_or(i32::MAX);
    dto::LifecycleRule {
        abort_incomplete_multipart_upload: rule.abort_uploads_after_days.map(|d| {
            dto::AbortIncompleteMultipartUpload {
                days_after_initiation: Some(days(d)),
            }
        }),
        expiration: rule.expiration.map(|e| {
            let mut out = dto::LifecycleExpiration::default();
            match e {
                Expiration::Days(d) => out.days = Some(days(d)),
                Expiration::Date(ms) => out.date = Some(timestamp(ms)),
                Expiration::ExpiredDeleteMarker(m) => out.expired_object_delete_marker = Some(m),
            }
            out
        }),
        filter,
        id: Some(rule.id.clone()),
        noncurrent_version_expiration: rule.noncurrent_expiration.map(|n| {
            dto::NoncurrentVersionExpiration {
                newer_noncurrent_versions: n.newer_versions.map(days),
                noncurrent_days: n.days.map(days),
            }
        }),
        noncurrent_version_transitions: None,
        prefix,
        status: dto::ExpirationStatus::from_static(if rule.enabled {
            dto::ExpirationStatus::ENABLED
        } else {
            dto::ExpirationStatus::DISABLED
        }),
        transitions: None,
    }
}

/// A time in milliseconds since the Unix epoch, as S3 sends one.
pub(crate) fn timestamp(ms: i64) -> dto::Timestamp {
    let time = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    dto::Timestamp::from(time)
}

/// The `x-amz-expiration` header of an object that expires.
pub(crate) fn expiration_header(expiry: &Expiry) -> String {
    let date = crate::drive::http_date(&crate::drive::millis(expiry.at_ms));
    format!(
        "expiry-date=\"{date}\", rule-id=\"{}\"",
        expiry.rule_id.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> dto::LifecycleRule {
        dto::LifecycleRule {
            abort_incomplete_multipart_upload: None,
            expiration: Some(dto::LifecycleExpiration {
                days: Some(1),
                ..Default::default()
            }),
            filter: None,
            id: Some("r".into()),
            noncurrent_version_expiration: None,
            noncurrent_version_transitions: None,
            prefix: Some("p/".into()),
            status: dto::ExpirationStatus::from_static(dto::ExpirationStatus::ENABLED),
            transitions: None,
        }
    }

    fn from_rules(rules: Vec<dto::LifecycleRule>) -> S3Result<Lifecycle> {
        from_dto(Some(dto::BucketLifecycleConfiguration { rules }), None)
    }

    fn code(result: S3Result<Lifecycle>) -> String {
        result.unwrap_err().code().as_str().to_owned()
    }

    #[test]
    fn rules_round_trip_as_given() {
        let mut filtered = rule();
        filtered.id = Some("f".into());
        filtered.prefix = None;
        filtered.filter = Some(dto::LifecycleRuleFilter {
            and: Some(dto::LifecycleRuleAndOperator {
                prefix: Some("a/".into()),
                tags: Some(vec![dto::Tag {
                    key: Some("k".into()),
                    value: Some("v".into()),
                }]),
                object_size_greater_than: Some(1),
                object_size_less_than: Some(9),
            }),
            ..Default::default()
        });
        filtered.expiration = None;
        filtered.noncurrent_version_expiration = Some(dto::NoncurrentVersionExpiration {
            newer_noncurrent_versions: Some(3),
            noncurrent_days: Some(2),
        });
        let mut dated = rule();
        dated.id = Some("d".into());
        dated.prefix = None;
        dated.filter = Some(dto::LifecycleRuleFilter::default());
        dated.expiration = Some(dto::LifecycleExpiration {
            date: Some(timestamp(20 * DAY_MS)),
            ..Default::default()
        });
        dated.abort_incomplete_multipart_upload = Some(dto::AbortIncompleteMultipartUpload {
            days_after_initiation: Some(4),
        });
        let rules = vec![rule(), filtered, dated];
        let lifecycle = from_rules(rules.clone()).unwrap();
        let back = to_dto(&lifecycle);
        assert_eq!(back.rules.unwrap(), rules);
        assert_eq!(
            back.transition_default_minimum_object_size
                .unwrap()
                .as_str(),
            "all_storage_classes_128K"
        );
    }

    #[test]
    fn a_rule_without_an_id_gets_one() {
        let mut r = rule();
        r.id = None;
        let mut empty = rule();
        empty.id = Some(String::new());
        let lifecycle = from_rules(vec![r, empty]).unwrap();
        assert_eq!(lifecycle.rules[0].id.len(), 32);
        assert_eq!(lifecycle.rules[1].id.len(), 32);
    }

    #[test]
    fn bad_rules_are_refused_as_s3_refuses_them() {
        let with = |change: fn(&mut dto::LifecycleRule)| {
            let mut r = rule();
            change(&mut r);
            code(from_rules(vec![r]))
        };
        assert_eq!(code(from_dto(None, None)), "MalformedXML");
        assert_eq!(code(from_rules(vec![])), "MalformedXML");
        assert_eq!(code(from_rules(vec![rule(), rule()])), "InvalidArgument");
        assert_eq!(with(|r| r.id = Some("x".repeat(256))), "InvalidArgument");
        // A filter and the older rule-level prefix together.
        assert_eq!(
            with(|r| {
                r.filter = Some(dto::LifecycleRuleFilter {
                    prefix: Some("a".into()),
                    ..Default::default()
                });
            }),
            "MalformedXML"
        );
        assert_eq!(
            with(|r| {
                r.prefix = None;
                r.filter = Some(dto::LifecycleRuleFilter {
                    tag: Some(dto::Tag {
                        key: Some("aws:reserved".into()),
                        value: Some("v".into()),
                    }),
                    ..Default::default()
                });
            }),
            "InvalidTag"
        );
        assert_eq!(
            with(|r| r.status = dto::ExpirationStatus::from_static("enabled")),
            "MalformedXML"
        );
        assert_eq!(
            with(|r| r.filter = Some(dto::LifecycleRuleFilter::default())),
            "MalformedXML"
        );
        assert_eq!(
            with(|r| r.expiration.as_mut().unwrap().days = Some(0)),
            "InvalidArgument"
        );
        assert_eq!(
            with(|r| r.expiration.as_mut().unwrap().expired_object_delete_marker = Some(true)),
            "InvalidArgument"
        );
        assert_eq!(
            with(|r| r.expiration = Some(dto::LifecycleExpiration::default())),
            "MalformedXML"
        );
        assert_eq!(
            with(|r| {
                r.expiration = Some(dto::LifecycleExpiration {
                    date: Some(timestamp(DAY_MS + 1)),
                    ..Default::default()
                });
            }),
            "InvalidArgument"
        );
        assert_eq!(with(|r| r.expiration = None), "InvalidRequest");
    }

    #[test]
    fn bad_actions_are_refused_as_s3_refuses_them() {
        let with = |change: fn(&mut dto::LifecycleRule)| {
            let mut r = rule();
            change(&mut r);
            code(from_rules(vec![r]))
        };
        assert_eq!(
            with(|r| {
                r.noncurrent_version_expiration = Some(dto::NoncurrentVersionExpiration {
                    newer_noncurrent_versions: Some(2),
                    noncurrent_days: Some(1),
                });
            }),
            "InvalidRequest"
        );
        assert_eq!(
            with(|r| {
                r.prefix = None;
                r.filter = Some(dto::LifecycleRuleFilter {
                    prefix: Some(String::new()),
                    ..Default::default()
                });
                r.noncurrent_version_expiration = Some(dto::NoncurrentVersionExpiration {
                    newer_noncurrent_versions: Some(101),
                    noncurrent_days: Some(1),
                });
            }),
            "InvalidArgument"
        );
        assert_eq!(
            with(|r| {
                r.noncurrent_version_expiration = Some(dto::NoncurrentVersionExpiration {
                    newer_noncurrent_versions: None,
                    noncurrent_days: Some(0),
                });
            }),
            "InvalidArgument"
        );
        assert_eq!(
            with(|r| {
                r.abort_incomplete_multipart_upload = Some(dto::AbortIncompleteMultipartUpload {
                    days_after_initiation: Some(0),
                });
            }),
            "InvalidArgument"
        );
        assert_eq!(
            with(|r| {
                r.transitions = Some(vec![dto::Transition {
                    days: Some(30),
                    storage_class: Some(dto::TransitionStorageClass::from_static("GLACIER")),
                    date: None,
                }]);
            }),
            "InvalidStorageClass"
        );
        assert_eq!(
            with(|r| {
                r.transitions = Some(vec![dto::Transition {
                    date: Some(timestamp(5)),
                    ..Default::default()
                }]);
            }),
            "InvalidArgument"
        );
    }

    #[test]
    fn filters_are_checked() {
        let filtered = |filter: dto::LifecycleRuleFilter, expiration: dto::LifecycleExpiration| {
            let mut r = rule();
            r.prefix = None;
            r.filter = Some(filter);
            r.expiration = Some(expiration);
            from_rules(vec![r])
        };
        let days = dto::LifecycleExpiration {
            days: Some(1),
            ..Default::default()
        };
        let marker = dto::LifecycleExpiration {
            expired_object_delete_marker: Some(true),
            ..Default::default()
        };
        let tag = |k: &str| dto::Tag {
            key: Some(k.into()),
            value: Some("v".into()),
        };
        let and = |and: dto::LifecycleRuleAndOperator| dto::LifecycleRuleFilter {
            and: Some(and),
            ..Default::default()
        };
        assert_eq!(
            code(filtered(
                dto::LifecycleRuleFilter {
                    prefix: Some("a".into()),
                    tag: Some(tag("k")),
                    ..Default::default()
                },
                days.clone()
            )),
            "MalformedXML"
        );
        assert_eq!(
            code(filtered(
                and(dto::LifecycleRuleAndOperator::default()),
                days.clone()
            )),
            "MalformedXML"
        );
        assert_eq!(
            code(filtered(
                and(dto::LifecycleRuleAndOperator {
                    tags: Some(vec![tag("k"), tag("k")]),
                    ..Default::default()
                }),
                days.clone()
            )),
            "InvalidTag"
        );
        assert_eq!(
            code(filtered(
                and(dto::LifecycleRuleAndOperator {
                    object_size_greater_than: Some(5),
                    object_size_less_than: Some(5),
                    ..Default::default()
                }),
                days.clone()
            )),
            "InvalidArgument"
        );
        assert_eq!(
            code(filtered(
                dto::LifecycleRuleFilter {
                    object_size_less_than: Some(-1),
                    ..Default::default()
                },
                days.clone()
            )),
            "InvalidArgument"
        );
        assert_eq!(
            code(filtered(
                dto::LifecycleRuleFilter {
                    tag: Some(tag("k")),
                    ..Default::default()
                },
                marker
            )),
            "InvalidRequest"
        );
    }

    #[test]
    fn uploads_and_the_minimum_size_are_checked() {
        let sized = dto::LifecycleRuleFilter {
            object_size_greater_than: Some(1),
            ..Default::default()
        };
        let mut r = rule();
        r.prefix = None;
        r.filter = Some(sized);
        r.abort_incomplete_multipart_upload = Some(dto::AbortIncompleteMultipartUpload {
            days_after_initiation: Some(1),
        });
        assert_eq!(code(from_rules(vec![r])), "InvalidRequest");
        let size = dto::TransitionDefaultMinimumObjectSize::from_static("tiny");
        assert_eq!(
            code(from_dto(
                Some(dto::BucketLifecycleConfiguration {
                    rules: vec![rule()]
                }),
                Some(&size)
            )),
            "InvalidArgument"
        );
    }

    #[test]
    fn the_expiration_header_is_s3s() {
        let header = expiration_header(&Expiry {
            at_ms: 1_356_220_800_000,
            rule_id: "a \"b\"".into(),
        });
        assert_eq!(
            header,
            r#"expiry-date="Sun, 23 Dec 2012 00:00:00 GMT", rule-id="a \"b\"""#
        );
    }
}
