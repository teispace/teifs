//! A bucket's notification rules: `teifs event add|ls|rm`, as `mc event` manages
//! them. Each change reads the bucket's rules, changes them and writes them back, so the
//! server checks the whole configuration as S3 does (and tests a target a rule starts
//! naming).

use aws_sdk_s3::types::{
    Event, FilterRule, FilterRuleName, LambdaFunctionConfiguration, NotificationConfiguration,
    NotificationConfigurationFilter, QueueConfiguration, S3KeyFilter, TopicConfiguration,
};
use clap::Subcommand;
use serde_json::json;

use super::{Error, Kind, alias::Aliases, commands::plural, target::Target};
use crate::ui;

#[derive(Subcommand)]
pub enum EventAction {
    /// Send a bucket's events to one of the server's targets (`teifs admin config`
    /// lists them).
    Add {
        /// `ALIAS/BUCKET`.
        target: String,
        /// The target's ARN: `arn:teifs:sqs::ID:webhook` (or MinIO's `arn:minio:…`).
        arn: String,
        /// The events: `put`, `delete`, `get`, `ilm` (lifecycle expirations), or S3's
        /// names (`s3:ObjectCreated:Copy`), comma-separated.
        #[arg(long, value_delimiter = ',', default_value = "put,delete,get")]
        event: Vec<String>,
        /// Only keys starting with this.
        #[arg(long)]
        prefix: Option<String>,
        /// Only keys ending with this.
        #[arg(long)]
        suffix: Option<String>,
        /// The rule's id (the server makes one up when not given).
        #[arg(long)]
        id: Option<String>,
        /// Succeed if the bucket already has this rule.
        #[arg(long)]
        ignore_existing: bool,
    },
    /// List a bucket's rules, or those sending to one target.
    Ls {
        /// `ALIAS/BUCKET`.
        target: String,
        /// Only the rules sending to this ARN.
        arn: Option<String>,
    },
    /// Remove a bucket's rules: one (`--id`), those sending to a target (its ARN), or
    /// all of them (`--all`).
    Rm {
        /// `ALIAS/BUCKET`.
        target: String,
        /// Remove the rules sending to this ARN.
        #[arg(required_unless_present_any = ["id", "all"], conflicts_with = "all")]
        arn: Option<String>,
        /// The rule to remove.
        #[arg(long, conflicts_with = "all")]
        id: Option<String>,
        /// Every rule of the bucket.
        #[arg(long)]
        all: bool,
        /// Remove them all without asking.
        #[arg(long, requires = "all")]
        force: bool,
    },
}

/// The events a short name stands for (as `mc event` and `mc watch` read them), or
/// `name` itself.
pub(super) fn events_of(name: &str) -> Vec<String> {
    let events: &[&str] = match name {
        "put" => &["s3:ObjectCreated:*"],
        "delete" => &["s3:ObjectRemoved:*"],
        "get" => &["s3:ObjectAccessed:*"],
        "ilm" => &["s3:LifecycleExpiration:*"],
        "bucket" => &["s3:BucketCreated:*", "s3:BucketRemoved:*"],
        other => return vec![other.to_owned()],
    };
    events.iter().map(|&e| e.to_owned()).collect()
}

/// How a rule was given, kept so it's written back the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Destination {
    Queue,
    Topic,
    Function,
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    kind: Destination,
    id: Option<String>,
    arn: String,
    events: Vec<String>,
    prefix: Option<String>,
    suffix: Option<String>,
}

impl Rule {
    fn read(
        kind: Destination,
        id: Option<&str>,
        arn: &str,
        events: &[Event],
        filter: Option<&NotificationConfigurationFilter>,
    ) -> Self {
        let value = |name: &str| {
            filter
                .and_then(|f| f.key())
                .map(S3KeyFilter::filter_rules)
                .unwrap_or_default()
                .iter()
                .find(|r| {
                    r.name()
                        .is_some_and(|n| n.as_str().eq_ignore_ascii_case(name))
                })
                .and_then(|r| r.value().map(str::to_owned))
        };
        Self {
            kind,
            id: id.map(str::to_owned),
            arn: arn.to_owned(),
            events: events.iter().map(|e| e.as_str().to_owned()).collect(),
            prefix: value("prefix"),
            suffix: value("suffix"),
        }
    }

    fn filter(&self) -> Option<NotificationConfigurationFilter> {
        let rules: Vec<FilterRule> = [
            (FilterRuleName::Prefix, &self.prefix),
            (FilterRuleName::Suffix, &self.suffix),
        ]
        .into_iter()
        .filter_map(|(name, value)| {
            Some(
                FilterRule::builder()
                    .name(name)
                    .value(value.clone()?)
                    .build(),
            )
        })
        .collect();
        (!rules.is_empty()).then(|| {
            NotificationConfigurationFilter::builder()
                .key(S3KeyFilter::builder().set_filter_rules(Some(rules)).build())
                .build()
        })
    }

    /// Whether it sends what `other` does, whatever its id.
    fn same_as(&self, other: &Self) -> bool {
        let mut mine = self.events.clone();
        let mut theirs = other.events.clone();
        mine.sort();
        theirs.sort();
        self.arn == other.arn
            && mine == theirs
            && self.prefix == other.prefix
            && self.suffix == other.suffix
    }

    fn record(&self, bucket: &str) -> serde_json::Value {
        json!({
            "type": "eventRule", "bucket": bucket, "id": self.id, "arn": self.arn,
            "events": self.events, "prefix": self.prefix, "suffix": self.suffix,
        })
    }
}

/// `teifs event …`.
pub(super) async fn event(action: EventAction, aliases: &Aliases) -> Result<(), Error> {
    let target = match &action {
        EventAction::Add { target, .. }
        | EventAction::Ls { target, .. }
        | EventAction::Rm { target, .. } => target,
    };
    let bucket = Rules::new(target, aliases)?;
    match action {
        EventAction::Add {
            arn,
            event,
            prefix,
            suffix,
            id,
            ignore_existing,
            ..
        } => {
            let rule = Rule {
                kind: Destination::Queue,
                id,
                arn,
                events: event.iter().flat_map(|e| events_of(e)).collect(),
                prefix,
                suffix,
            };
            add(&bucket, rule, ignore_existing).await
        }
        EventAction::Ls { arn, .. } => ls(&bucket, arn.as_deref()).await,
        EventAction::Rm {
            arn,
            id,
            all,
            force,
            ..
        } => rm(&bucket, arn.as_deref(), id.as_deref(), all, force).await,
    }
}

/// The bucket whose rules a command reads and writes.
struct Rules {
    client: aws_sdk_s3::Client,
    bucket: String,
    /// `ALIAS/BUCKET`, for messages.
    name: String,
}

impl Rules {
    fn new(target: &str, aliases: &Aliases) -> Result<Self, Error> {
        let remote = Target::parse(target, aliases)?.remote("event")?;
        let name = remote.display("");
        if !remote.key.is_empty() {
            return Err(Error::usage(format!(
                "notification rules belong to a bucket: give {name}, and the keys with --prefix"
            )));
        }
        Ok(Self {
            bucket: remote.bucket()?.to_owned(),
            client: remote.alias.client(),
            name,
        })
    }

    async fn read(&self) -> Result<Vec<Rule>, Error> {
        let out = self
            .client
            .get_bucket_notification_configuration()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|e| {
                Error::s3(
                    format!("can't read the notification rules of {}", self.name),
                    &e,
                )
            })?;
        let queues = out.queue_configurations().iter().map(|q| {
            Rule::read(
                Destination::Queue,
                q.id(),
                q.queue_arn(),
                q.events(),
                q.filter(),
            )
        });
        let topics = out.topic_configurations().iter().map(|t| {
            Rule::read(
                Destination::Topic,
                t.id(),
                t.topic_arn(),
                t.events(),
                t.filter(),
            )
        });
        let functions = out.lambda_function_configurations().iter().map(|f| {
            Rule::read(
                Destination::Function,
                f.id(),
                f.lambda_function_arn(),
                f.events(),
                f.filter(),
            )
        });
        Ok(queues.chain(topics).chain(functions).collect())
    }

    /// Replaces the bucket's rules.
    async fn write(&self, rules: &[Rule]) -> Result<(), Error> {
        let invalid = |e: aws_sdk_s3::error::BuildError| Error::usage(e.to_string());
        let (mut queues, mut topics, mut functions) = (Vec::new(), Vec::new(), Vec::new());
        for rule in rules {
            let events = Some(
                rule.events
                    .iter()
                    .map(|e| Event::from(e.as_str()))
                    .collect(),
            );
            match rule.kind {
                Destination::Queue => queues.push(
                    QueueConfiguration::builder()
                        .set_id(rule.id.clone())
                        .queue_arn(&rule.arn)
                        .set_events(events)
                        .set_filter(rule.filter())
                        .build()
                        .map_err(invalid)?,
                ),
                Destination::Topic => topics.push(
                    TopicConfiguration::builder()
                        .set_id(rule.id.clone())
                        .topic_arn(&rule.arn)
                        .set_events(events)
                        .set_filter(rule.filter())
                        .build()
                        .map_err(invalid)?,
                ),
                Destination::Function => functions.push(
                    LambdaFunctionConfiguration::builder()
                        .set_id(rule.id.clone())
                        .lambda_function_arn(&rule.arn)
                        .set_events(events)
                        .set_filter(rule.filter())
                        .build()
                        .map_err(invalid)?,
                ),
            }
        }
        let config = NotificationConfiguration::builder()
            .set_queue_configurations(Some(queues))
            .set_topic_configurations(Some(topics))
            .set_lambda_function_configurations(Some(functions))
            .build();
        self.client
            .put_bucket_notification_configuration()
            .bucket(&self.bucket)
            .notification_configuration(config)
            .send()
            .await
            .map(drop)
            .map_err(|e| {
                Error::s3(
                    format!("can't set the notification rules of {}", self.name),
                    &e,
                )
            })
    }
}

async fn add(bucket: &Rules, rule: Rule, ignore_existing: bool) -> Result<(), Error> {
    let name = &bucket.name;
    let mut rules = bucket.read().await?;
    if let Some(existing) = rules.iter().find(|r| r.same_as(&rule)) {
        if ignore_existing {
            ui::done(
                format!("{name} already sends these events to {}", rule.arn),
                || existing.record(name),
            );
            return Ok(());
        }
        return Err(Error::new(
            Kind::Conflict,
            format!("{name} already sends these events to {}", rule.arn),
        )
        .with_hint("add --ignore-existing to succeed anyway"));
    }
    if let Some(id) = &rule.id
        && rules.iter().any(|r| r.id.as_ref() == Some(id))
    {
        return Err(Error::new(
            Kind::Conflict,
            format!("{name} already has a notification rule {id}"),
        )
        .with_hint(format!("list them: teifs event ls {name}")));
    }
    rules.push(rule);
    bucket.write(&rules).await?;
    // Read back for the id the server made up.
    let added = bucket.read().await?.pop();
    let id = added
        .as_ref()
        .and_then(|r| r.id.clone())
        .unwrap_or_default();
    ui::done(
        format!(
            "{name} sends its events to {} (rule {id})",
            added.as_ref().map_or("", |r| r.arn.as_str())
        ),
        || added.map(|r| r.record(name)).unwrap_or_default(),
    );
    Ok(())
}

async fn ls(bucket: &Rules, arn: Option<&str>) -> Result<(), Error> {
    let name = &bucket.name;
    let rules = bucket.read().await?;
    let mut table = ui::Table::new(&["ID", "ARN", "EVENTS", "KEYS"]);
    let mut records = Vec::new();
    for rule in rules.iter().filter(|r| arn.is_none_or(|a| r.arn == a)) {
        let keys = format!(
            "{}*{}",
            rule.prefix.as_deref().unwrap_or_default(),
            rule.suffix.as_deref().unwrap_or_default()
        );
        table.row(vec![
            rule.id.clone().unwrap_or_default(),
            rule.arn.clone(),
            rule.events.join(", "),
            keys,
        ]);
        records.push(rule.record(name));
    }
    ui::rows(
        &table,
        &records,
        &format!(
            "{name} has no notification rules. Add one: teifs event add {name} arn:teifs:sqs::ID:webhook"
        ),
    );
    Ok(())
}

async fn rm(
    bucket: &Rules,
    arn: Option<&str>,
    id: Option<&str>,
    all: bool,
    force: bool,
) -> Result<(), Error> {
    let name = &bucket.name;
    let mut rules = bucket.read().await?;
    let before = rules.len();
    if all {
        if before == 0 {
            return Err(Error::new(
                Kind::NotFound,
                format!("{name} has no notification rules"),
            ));
        }
        let question = format!(
            "Remove all {before} notification rule{} of {name}?",
            plural(before)
        );
        if !force && !ui::confirm(&question, "add --force to remove them all")? {
            ui::note("Nothing was removed.");
            return Ok(());
        }
        rules.clear();
    } else {
        rules.retain(|r| {
            !(arn.is_none_or(|a| r.arn == a) && id.is_none_or(|i| r.id.as_deref() == Some(i)))
        });
        if rules.len() == before {
            let which = match (id, arn) {
                (Some(id), _) => format!("rule {id}"),
                (None, Some(arn)) => format!("rule sending to {arn}"),
                (None, None) => "rule".to_owned(),
            };
            return Err(Error::new(
                Kind::NotFound,
                format!("{name} has no notification {which}"),
            )
            .with_hint(format!("list them: teifs event ls {name}")));
        }
    }
    bucket.write(&rules).await?;
    let removed = before - rules.len();
    ui::done(
        format!(
            "Removed {removed} notification rule{} from {name}",
            plural(removed)
        ),
        || json!({"type": "eventRules", "bucket": name, "removed": removed}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_stand_for_groups() {
        assert_eq!(events_of("put"), ["s3:ObjectCreated:*"]);
        assert_eq!(
            events_of("bucket"),
            ["s3:BucketCreated:*", "s3:BucketRemoved:*"]
        );
        assert_eq!(
            events_of("s3:ObjectCreated:Copy"),
            ["s3:ObjectCreated:Copy"]
        );
    }

    #[test]
    fn rules_are_the_same_whatever_their_id_and_event_order() {
        let rule = Rule {
            kind: Destination::Queue,
            id: Some("a".into()),
            arn: "arn:teifs:sqs::hook:webhook".into(),
            events: vec!["s3:ObjectCreated:*".into(), "s3:ObjectRemoved:*".into()],
            prefix: Some("logs/".into()),
            suffix: None,
        };
        let other = Rule {
            id: None,
            events: vec!["s3:ObjectRemoved:*".into(), "s3:ObjectCreated:*".into()],
            ..rule.clone()
        };
        assert!(rule.same_as(&other));
        let elsewhere = Rule {
            prefix: None,
            ..rule.clone()
        };
        assert!(!rule.same_as(&elsewhere));
        let filter = rule.filter().unwrap();
        let read = Rule::read(
            Destination::Queue,
            Some("a"),
            &rule.arn,
            &[
                Event::from("s3:ObjectCreated:*"),
                Event::from("s3:ObjectRemoved:*"),
            ],
            Some(&filter),
        );
        assert_eq!(read, rule);
    }
}
