//! `PutBucketNotificationConfiguration` and `GetBucketNotificationConfiguration`: a
//! bucket's rules, read from S3's XML with S3's checks, and written back as S3 does.

use s3s::{S3Result, dto, s3_error};
use teifs_types::notify::{DestinationKind, NotificationConfig, NotificationRule, TargetArn};

/// The rules a configuration gives, checked, with `known` saying which targets exist.
/// A rule without an id gets one, as on S3.
pub(crate) fn from_dto(
    config: dto::NotificationConfiguration,
    known: impl Fn(&TargetArn) -> bool,
) -> S3Result<NotificationConfig> {
    if config.event_bridge_configuration.is_some() {
        return Err(s3_error!(
            NotImplemented,
            "EventBridge isn't available: name one of the server's targets instead"
        ));
    }
    let mut rules = Vec::new();
    for queue in config.queue_configurations.into_iter().flatten() {
        rules.push(rule(
            DestinationKind::Queue,
            queue.id,
            queue.queue_arn,
            queue.events,
            queue.filter,
        )?);
    }
    for topic in config.topic_configurations.into_iter().flatten() {
        rules.push(rule(
            DestinationKind::Topic,
            topic.id,
            topic.topic_arn,
            topic.events,
            topic.filter,
        )?);
    }
    for function in config.lambda_function_configurations.into_iter().flatten() {
        rules.push(rule(
            DestinationKind::CloudFunction,
            function.id,
            function.lambda_function_arn,
            function.events,
            function.filter,
        )?);
    }
    let config = NotificationConfig { rules };
    config
        .check(known)
        .map_err(|err| s3_error!(InvalidArgument, "{err}"))?;
    Ok(config)
}

fn rule(
    kind: DestinationKind,
    id: Option<String>,
    arn: String,
    events: Vec<dto::Event>,
    filter: Option<dto::NotificationConfigurationFilter>,
) -> S3Result<NotificationRule> {
    let (mut prefix, mut suffix) = (None, None);
    let rules = filter
        .and_then(|f| f.key)
        .and_then(|key| key.filter_rules)
        .unwrap_or_default();
    for rule in rules {
        let name = rule.name.as_ref().map_or("", dto::FilterRuleName::as_str);
        let slot = if name.eq_ignore_ascii_case("prefix") {
            &mut prefix
        } else if name.eq_ignore_ascii_case("suffix") {
            &mut suffix
        } else {
            return Err(s3_error!(
                InvalidArgument,
                "filter rule name must be either prefix or suffix"
            ));
        };
        if slot.is_some() {
            return Err(s3_error!(
                InvalidArgument,
                "Cannot specify more than one {} rule in a filter.",
                name.to_ascii_lowercase()
            ));
        }
        *slot = Some(rule.value.unwrap_or_default());
    }
    Ok(NotificationRule {
        id: id
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string()),
        kind,
        arn,
        events: events.into_iter().map(String::from).collect(),
        prefix,
        suffix,
    })
}

/// A bucket's rules as S3 answers them (none: an empty configuration).
pub(crate) fn to_dto(
    config: Option<&NotificationConfig>,
) -> dto::GetBucketNotificationConfigurationOutput {
    let mut out = dto::GetBucketNotificationConfigurationOutput::default();
    for rule in config.map_or(&[][..], |c| &c.rules) {
        let (id, events, filter) = (
            Some(rule.id.clone()),
            rule.events.iter().cloned().map(dto::Event::from).collect(),
            filter(rule),
        );
        match rule.kind {
            DestinationKind::Queue => {
                out.queue_configurations.get_or_insert_with(Vec::new).push(
                    dto::QueueConfiguration {
                        events,
                        filter,
                        id,
                        queue_arn: rule.arn.clone(),
                    },
                );
            }
            DestinationKind::Topic => {
                out.topic_configurations.get_or_insert_with(Vec::new).push(
                    dto::TopicConfiguration {
                        events,
                        filter,
                        id,
                        topic_arn: rule.arn.clone(),
                    },
                );
            }
            DestinationKind::CloudFunction => {
                out.lambda_function_configurations
                    .get_or_insert_with(Vec::new)
                    .push(dto::LambdaFunctionConfiguration {
                        events,
                        filter,
                        id,
                        lambda_function_arn: rule.arn.clone(),
                    });
            }
        }
    }
    out
}

/// A rule's filter, named as the API names its values (`prefix`, `suffix`: what SDKs
/// read).
fn filter(rule: &NotificationRule) -> Option<dto::NotificationConfigurationFilter> {
    let rules: Vec<dto::FilterRule> = [
        (dto::FilterRuleName::PREFIX, &rule.prefix),
        (dto::FilterRuleName::SUFFIX, &rule.suffix),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        Some(dto::FilterRule {
            name: Some(dto::FilterRuleName::from_static(name)),
            value: Some(value.clone()?),
        })
    })
    .collect();
    (!rules.is_empty()).then_some(dto::NotificationConfigurationFilter {
        key: Some(dto::S3KeyFilter {
            filter_rules: Some(rules),
        }),
    })
}

/// The targets `config` names that `before` didn't: the ones S3 sends a test event.
pub(crate) fn new_targets(
    config: &NotificationConfig,
    before: Option<&NotificationConfig>,
) -> Vec<TargetArn> {
    let old: Vec<TargetArn> = before
        .map(|b| {
            b.rules
                .iter()
                .filter_map(NotificationRule::target)
                .collect()
        })
        .unwrap_or_default();
    let mut new: Vec<TargetArn> = config
        .rules
        .iter()
        .filter_map(NotificationRule::target)
        .filter(|arn| !old.contains(arn))
        .collect();
    new.sort();
    new.dedup();
    new
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARN: &str = "arn:minio:sqs::primary:webhook";

    fn filter_rules(rules: &[(&str, &str)]) -> dto::NotificationConfigurationFilter {
        dto::NotificationConfigurationFilter {
            key: Some(dto::S3KeyFilter {
                filter_rules: Some(
                    rules
                        .iter()
                        .map(|(name, value)| dto::FilterRule {
                            name: Some(dto::FilterRuleName::from((*name).to_owned())),
                            value: Some((*value).to_owned()),
                        })
                        .collect(),
                ),
            }),
        }
    }

    fn queue(id: Option<&str>, filter: &[(&str, &str)]) -> dto::QueueConfiguration {
        dto::QueueConfiguration {
            events: vec![dto::Event::from("s3:ObjectCreated:*".to_owned())],
            filter: Some(filter_rules(filter)),
            id: id.map(str::to_owned),
            queue_arn: ARN.to_owned(),
        }
    }

    fn config(queues: Vec<dto::QueueConfiguration>) -> dto::NotificationConfiguration {
        dto::NotificationConfiguration {
            queue_configurations: Some(queues),
            ..Default::default()
        }
    }

    fn known(arn: &TargetArn) -> bool {
        arn.id == "primary"
    }

    fn code(result: S3Result<NotificationConfig>) -> String {
        result.unwrap_err().code().as_str().to_owned()
    }

    #[test]
    fn a_configuration_reads_back_as_s3_writes_it() {
        let read = from_dto(
            config(vec![queue(
                None,
                &[("prefix", "images/"), ("Suffix", ".jpg")],
            )]),
            known,
        )
        .unwrap();
        let rule = &read.rules[0];
        assert_eq!(rule.id.len(), 32, "an id is made up");
        assert_eq!(
            (rule.prefix.as_deref(), rule.suffix.as_deref()),
            (Some("images/"), Some(".jpg"))
        );
        let out = to_dto(Some(&read));
        let queues = out.queue_configurations.unwrap();
        assert_eq!(queues[0].queue_arn, ARN);
        assert_eq!(queues[0].id.as_deref(), Some(rule.id.as_str()));
        let names: Vec<_> = queues[0]
            .filter
            .as_ref()
            .and_then(|f| f.key.as_ref())
            .and_then(|k| k.filter_rules.as_ref())
            .unwrap()
            .iter()
            .map(|r| r.name.as_ref().unwrap().as_str().to_owned())
            .collect();
        assert_eq!(names, ["prefix", "suffix"]);
        assert!(out.topic_configurations.is_none());
        let empty = to_dto(None);
        assert!(empty.queue_configurations.is_none());
    }

    #[test]
    fn bad_configurations_are_refused_as_s3_refuses_them() {
        let bad_name = config(vec![queue(None, &[("infix", "x")])]);
        assert_eq!(code(from_dto(bad_name, known)), "InvalidArgument");
        let twice = config(vec![queue(None, &[("prefix", "a"), ("Prefix", "b")])]);
        assert_eq!(code(from_dto(twice, known)), "InvalidArgument");
        let overlapping = config(vec![
            queue(Some("1"), &[("prefix", "a")]),
            queue(Some("2"), &[("prefix", "ab")]),
        ]);
        assert_eq!(code(from_dto(overlapping, known)), "InvalidArgument");
        let unknown = config(vec![queue(None, &[])]);
        assert_eq!(code(from_dto(unknown, |_| false)), "InvalidArgument");
        let bridge = dto::NotificationConfiguration {
            event_bridge_configuration: Some(dto::EventBridgeConfiguration {}),
            ..Default::default()
        };
        assert_eq!(code(from_dto(bridge, known)), "NotImplemented");
    }

    #[test]
    fn only_targets_a_rule_starts_naming_are_tested() {
        let one = from_dto(config(vec![queue(Some("1"), &[("prefix", "a/")])]), known).unwrap();
        let mut two = one.clone();
        let mut other = two.rules[0].clone();
        other.id = "2".into();
        other.arn = "arn:teifs:sqs::second:webhook".into();
        other.prefix = Some("b/".into());
        two.rules.push(other);
        let arn = |s: &str| TargetArn::parse(s).unwrap();
        assert_eq!(new_targets(&one, None), [arn(ARN)]);
        assert_eq!(
            new_targets(&two, Some(&one)),
            [arn("arn:teifs:sqs::second:webhook")]
        );
        assert!(new_targets(&one, Some(&two)).is_empty());
    }
}
