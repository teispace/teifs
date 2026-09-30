//! Lifecycle rules: `teifs ilm rule add|edit|ls|rm|export|import`, with mc's names.
//!
//! Rules are handled as JSON in the shape AWS gives them (`aws s3api
//! get-bucket-lifecycle-configuration`), so an export can be edited and imported here or
//! with the AWS CLI; changes read the bucket's rules, change them and write them back.

use aws_sdk_s3::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    primitives::{DateTime, DateTimeFormat},
    types::{
        AbortIncompleteMultipartUpload, BucketLifecycleConfiguration, ExpirationStatus,
        LifecycleExpiration, LifecycleRule, LifecycleRuleAndOperator, LifecycleRuleFilter,
        NoncurrentVersionExpiration, NoncurrentVersionTransition, Tag, Transition,
        TransitionStorageClass,
    },
};
use serde_json::{Map, Value, json};

use super::{
    Error, IlmAction, Kind, RuleAction, RuleArgs, alias::Aliases, commands::plural, target::Target,
};
use crate::{
    ui,
    units::{from_ms, parse_day, rfc3339},
};

/// `teifs ilm …`.
pub(super) async fn ilm(action: IlmAction, aliases: &Aliases) -> Result<(), Error> {
    let IlmAction::Rule { action } = action;
    let target = match &action {
        RuleAction::Add { target, .. }
        | RuleAction::Edit { target, .. }
        | RuleAction::Ls { target }
        | RuleAction::Rm { target, .. }
        | RuleAction::Export { target }
        | RuleAction::Import { target } => target,
    };
    let bucket = Lifecycle::new(target, aliases)?;
    match action {
        RuleAction::Add {
            id, rule, disable, ..
        } => add(&bucket, id, &rule, disable).await,
        RuleAction::Edit {
            id,
            rule,
            enable,
            disable,
            ..
        } => {
            edit(
                &bucket,
                &id,
                &rule,
                enable.then_some(true).or(disable.then_some(false)),
            )
            .await
        }
        RuleAction::Ls { .. } => ls(&bucket).await,
        RuleAction::Rm { id, all, force, .. } => rm(&bucket, id.as_deref(), all, force).await,
        RuleAction::Export { .. } => export(&bucket).await,
        RuleAction::Import { .. } => import(&bucket).await,
    }
}

/// The bucket whose rules a command reads and writes.
struct Lifecycle {
    client: Client,
    bucket: String,
    /// `ALIAS/BUCKET`, for messages.
    name: String,
}

impl Lifecycle {
    fn new(target: &str, aliases: &Aliases) -> Result<Self, Error> {
        let remote = Target::parse(target, aliases)?.remote("ilm")?;
        let name = remote.display("");
        if !remote.key.is_empty() {
            return Err(Error::usage(format!(
                "lifecycle rules belong to a bucket: give {name}"
            )));
        }
        Ok(Self {
            bucket: remote.bucket()?.to_owned(),
            client: remote.alias.client(),
            name,
        })
    }

    /// The bucket's rules, as JSON; none when it has no configuration.
    async fn read(&self) -> Result<Vec<Value>, Error> {
        let result = self
            .client
            .get_bucket_lifecycle_configuration()
            .bucket(&self.bucket)
            .send()
            .await;
        match result {
            Ok(out) => Ok(out.rules().iter().map(rule_to_json).collect()),
            Err(e) if no_configuration(&e) => Ok(Vec::new()),
            Err(e) => Err(Error::s3(
                format!("can't read the lifecycle rules of {}", self.name),
                &e,
            )),
        }
    }

    /// The bucket's rules, or an error when it has none.
    async fn read_some(&self) -> Result<Vec<Value>, Error> {
        let rules = self.read().await?;
        if rules.is_empty() {
            return Err(Error::new(
                Kind::NotFound,
                format!("{} has no lifecycle rules", self.name),
            ));
        }
        Ok(rules)
    }

    /// Replaces the bucket's rules (none: removes its configuration).
    async fn write(&self, rules: &[Value]) -> Result<(), Error> {
        let name = &self.name;
        if rules.is_empty() {
            return self
                .client
                .delete_bucket_lifecycle()
                .bucket(&self.bucket)
                .send()
                .await
                .map(drop)
                .map_err(|e| Error::s3(format!("can't remove the lifecycle rules of {name}"), &e));
        }
        let rules = rules
            .iter()
            .map(rule_from_json)
            .collect::<Result<Vec<_>, _>>()?;
        let config = BucketLifecycleConfiguration::builder()
            .set_rules(Some(rules))
            .build()
            .map_err(|e| Error::usage(e.to_string()))?;
        self.client
            .put_bucket_lifecycle_configuration()
            .bucket(&self.bucket)
            .lifecycle_configuration(config)
            .send()
            .await
            .map(drop)
            .map_err(|e| Error::s3(format!("can't set the lifecycle rules of {name}"), &e))
    }

    fn no_rule(&self, id: &str) -> Error {
        let name = &self.name;
        Error::new(Kind::NotFound, format!("{name} has no lifecycle rule {id}"))
            .with_hint(format!("list them: teifs ilm rule ls {name}"))
    }
}

async fn add(
    bucket: &Lifecycle,
    id: Option<String>,
    rule: &RuleArgs,
    disable: bool,
) -> Result<(), Error> {
    if !rule.has_action() {
        return Err(Error::usage(
            "say what the rule does: --expire-days, --expire-date, --expire-delete-marker, --noncurrent-expire-days, --noncurrent-expire-newer, --abort-uploads-days or a transition",
        ));
    }
    let name = &bucket.name;
    let mut rules = bucket.read().await?;
    let id = id.unwrap_or_else(new_id);
    if find(&rules, &id).is_some() {
        return Err(Error::new(
            Kind::Conflict,
            format!(
                "{name} already has a rule {id}: change it with `teifs ilm rule edit --id {id}`"
            ),
        ));
    }
    let mut new = json!({"ID": id, "Status": status(!disable)});
    rule.apply(&mut new)?;
    rules.push(new);
    bucket.write(&rules).await?;
    ui::done(
        format!("Added rule {id} to {name}"),
        || json!({"type": "lifecycleRule", "bucket": name, "id": id, "status": "added"}),
    );
    Ok(())
}

/// Changes rule `id`: what `rule` gives, and turns it on or off when `enabled` says.
async fn edit(
    bucket: &Lifecycle,
    id: &str,
    rule: &RuleArgs,
    enabled: Option<bool>,
) -> Result<(), Error> {
    let name = &bucket.name;
    let mut rules = bucket.read().await?;
    let at = find(&rules, id).ok_or_else(|| bucket.no_rule(id))?;
    rule.apply(&mut rules[at])?;
    if let Some(enabled) = enabled {
        rules[at]["Status"] = json!(status(enabled));
    }
    bucket.write(&rules).await?;
    ui::done(
        format!("Changed rule {id} of {name}"),
        || json!({"type": "lifecycleRule", "bucket": name, "id": id, "status": "changed"}),
    );
    Ok(())
}

async fn ls(bucket: &Lifecycle) -> Result<(), Error> {
    let name = &bucket.name;
    let rules = bucket.read().await?;
    let mut table = ui::Table::new(&["ID", "STATUS", "APPLIES TO", "DOES"]);
    let mut records = Vec::new();
    for rule in &rules {
        table.row(vec![
            text(&rule["ID"]),
            text(&rule["Status"]),
            filter_text(rule),
            actions_text(rule),
        ]);
        records.push(json!({"type": "lifecycleRule", "bucket": name, "rule": rule}));
    }
    ui::rows(
        &table,
        &records,
        &format!(
            "{name} has no lifecycle rules. Add one: teifs ilm rule add {name} --expire-days 30"
        ),
    );
    Ok(())
}

async fn rm(bucket: &Lifecycle, id: Option<&str>, all: bool, force: bool) -> Result<(), Error> {
    let name = &bucket.name;
    let mut rules;
    let removed = if all {
        rules = bucket.read_some().await?;
        let count = rules.len();
        let question = format!(
            "Remove all {count} lifecycle rule{} of {name}?",
            plural(count)
        );
        if !force && !ui::confirm(&question, "add --force to remove them all")? {
            ui::note("Nothing was removed.");
            return Ok(());
        }
        rules.clear();
        count
    } else {
        rules = bucket.read().await?;
        let id = id.unwrap_or_default();
        rules.remove(find(&rules, id).ok_or_else(|| bucket.no_rule(id))?);
        1
    };
    bucket.write(&rules).await?;
    ui::done(
        format!(
            "Removed {removed} lifecycle rule{} from {name}",
            plural(removed)
        ),
        || json!({"type": "lifecycleRules", "bucket": name, "removed": removed}),
    );
    Ok(())
}

async fn export(bucket: &Lifecycle) -> Result<(), Error> {
    let rules = bucket.read_some().await?;
    let text = serde_json::to_string_pretty(&json!({"Rules": rules})).expect("JSON serializes");
    ui::raw(&format!("{text}\n"));
    Ok(())
}

async fn import(bucket: &Lifecycle) -> Result<(), Error> {
    let name = &bucket.name;
    let mut input = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut tokio::io::stdin(), &mut input)
        .await
        .map_err(|e| Error::general(format!("can't read standard input: {e}")))?;
    let rules = import_rules(&input)?;
    bucket.write(&rules).await?;
    let count = rules.len();
    ui::done(
        format!("Imported {count} lifecycle rule{} to {name}", plural(count)),
        || json!({"type": "lifecycleRules", "bucket": name, "imported": count}),
    );
    Ok(())
}

/// The rules in an export (`{"Rules": [...]}`, as AWS and `export` write them).
fn import_rules(input: &str) -> Result<Vec<Value>, Error> {
    let bad = |why: String| {
        Error::usage(format!(
            "standard input isn't a lifecycle configuration ({why}): give JSON like `teifs ilm rule export` writes"
        ))
    };
    let value: Value = serde_json::from_str(input).map_err(|e| bad(e.to_string()))?;
    let rules = value
        .get("Rules")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("no \"Rules\" list".to_owned()))?;
    if rules.is_empty() {
        return Err(bad("no rules".to_owned()));
    }
    Ok(rules.clone())
}

fn status(enabled: bool) -> &'static str {
    if enabled { "Enabled" } else { "Disabled" }
}

/// A rule id: 20 hex digits, different on every call.
fn new_id() -> String {
    use md5::{Digest, Md5};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let seed = format!(
        "{nanos}-{}-{}",
        std::process::id(),
        COUNT.fetch_add(1, Ordering::Relaxed)
    );
    teifs_types::hex(&Md5::digest(seed.as_bytes()))[..20].to_owned()
}

fn find(rules: &[Value], id: &str) -> Option<usize> {
    rules.iter().position(|rule| rule["ID"] == id)
}

/// A JSON string's text (empty for anything else).
fn text(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_owned()
}

fn no_configuration<E: ProvideErrorMetadata, R>(err: &SdkError<E, R>) -> bool {
    err.as_service_error().and_then(ProvideErrorMetadata::code)
        == Some("NoSuchLifecycleConfiguration")
}

impl RuleArgs {
    /// Whether any option says what a rule does.
    fn has_action(&self) -> bool {
        self.expire_days.is_some()
            || self.expire_date.is_some()
            || self.expire_delete_marker
            || self.noncurrent_expire_days.is_some()
            || self.noncurrent_expire_newer.is_some()
            || self.abort_uploads_days.is_some()
            || self.transition_tier.is_some()
            || self.noncurrent_transition_tier.is_some()
    }

    /// Sets what the options say on `rule` (JSON), keeping what they don't mention.
    fn apply(&self, rule: &mut Value) -> Result<(), Error> {
        let obj = rule.as_object_mut().expect("rules are objects");
        if self.prefix.is_some()
            || self.tags.is_some()
            || self.size_gt.is_some()
            || self.size_lt.is_some()
        {
            let (mut prefix, mut tags, mut gt, mut lt) = conditions(obj);
            if let Some(p) = &self.prefix {
                prefix = Some(p.clone());
            }
            if let Some(t) = &self.tags {
                tags = parse_tags(t)?;
            }
            if let Some(n) = self.size_gt {
                gt = Some(n);
            }
            if let Some(n) = self.size_lt {
                lt = Some(n);
            }
            obj.remove("Prefix");
            obj.insert("Filter".into(), filter(prefix, &tags, gt, lt));
        } else if !obj.contains_key("Filter") && !obj.contains_key("Prefix") {
            // The whole bucket.
            obj.insert("Filter".into(), json!({}));
        }
        if let Some(days) = self.expire_days {
            obj.insert("Expiration".into(), json!({"Days": days}));
        }
        if let Some(date) = self.expire_date {
            obj.insert("Expiration".into(), json!({"Date": rfc3339(from_ms(date))}));
        }
        if self.expire_delete_marker {
            obj.insert(
                "Expiration".into(),
                json!({"ExpiredObjectDeleteMarker": true}),
            );
        }
        if self.noncurrent_expire_days.is_some() || self.noncurrent_expire_newer.is_some() {
            let entry = section(obj, "NoncurrentVersionExpiration");
            if let Some(days) = self.noncurrent_expire_days {
                entry.insert("NoncurrentDays".into(), json!(days));
            }
            if let Some(newer) = self.noncurrent_expire_newer {
                entry.insert("NewerNoncurrentVersions".into(), json!(newer));
            }
        }
        if let Some(days) = self.abort_uploads_days {
            obj.insert(
                "AbortIncompleteMultipartUpload".into(),
                json!({"DaysAfterInitiation": days}),
            );
        }
        if self.transition_days.is_some()
            || self.transition_date.is_some()
            || self.transition_tier.is_some()
        {
            let entry = first_of(obj, "Transitions");
            if let Some(days) = self.transition_days {
                entry.remove("Date");
                entry.insert("Days".into(), json!(days));
            }
            if let Some(date) = self.transition_date {
                entry.remove("Days");
                entry.insert("Date".into(), json!(rfc3339(from_ms(date))));
            }
            if let Some(tier) = &self.transition_tier {
                entry.insert("StorageClass".into(), json!(tier));
            }
        }
        if self.noncurrent_transition_days.is_some()
            || self.noncurrent_transition_newer.is_some()
            || self.noncurrent_transition_tier.is_some()
        {
            let entry = first_of(obj, "NoncurrentVersionTransitions");
            if let Some(days) = self.noncurrent_transition_days {
                entry.insert("NoncurrentDays".into(), json!(days));
            }
            if let Some(newer) = self.noncurrent_transition_newer {
                entry.insert("NewerNoncurrentVersions".into(), json!(newer));
            }
            if let Some(tier) = &self.noncurrent_transition_tier {
                entry.insert("StorageClass".into(), json!(tier));
            }
        }
        // Checked as the SDK will need it.
        rule_from_json(rule).map(drop)
    }
}

/// The object at `key` in `obj`, made if missing.
fn section<'a>(obj: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    let entry = obj.entry(key).or_insert_with(|| json!({}));
    if !entry.is_object() {
        *entry = json!({});
    }
    entry.as_object_mut().expect("just made an object")
}

/// The first object of the list at `key` in `obj`, made if missing.
fn first_of<'a>(obj: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    let list = obj.entry(key).or_insert_with(|| json!([{}]));
    if !list
        .as_array()
        .is_some_and(|l| l.first().is_some_and(Value::is_object))
    {
        *list = json!([{}]);
    }
    list[0].as_object_mut().expect("just made an object")
}

type Tags = Vec<(String, String)>;

/// Tags as mc writes them: `key=value&key2=value2`.
fn parse_tags(text: &str) -> Result<Tags, Error> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').ok_or_else(|| {
                Error::usage(format!(
                    "`{pair}` isn't a tag: write key=value, joined with &"
                ))
            })?;
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect()
}

/// A rule's prefix, tags and sizes, from its filter (or the older rule-level prefix).
fn conditions(rule: &Map<String, Value>) -> (Option<String>, Tags, Option<u64>, Option<u64>) {
    let tag = |t: &Value| (text(&t["Key"]), text(&t["Value"]));
    let size = |v: &Value| v.as_u64();
    let prefix = rule
        .get("Prefix")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let Some(filter) = rule.get("Filter") else {
        return (prefix, Vec::new(), None, None);
    };
    let and = &filter["And"];
    if and.is_object() {
        return (
            and["Prefix"].as_str().map(str::to_owned),
            and["Tags"]
                .as_array()
                .map(|tags| tags.iter().map(tag).collect())
                .unwrap_or_default(),
            size(&and["ObjectSizeGreaterThan"]),
            size(&and["ObjectSizeLessThan"]),
        );
    }
    (
        filter["Prefix"].as_str().map(str::to_owned),
        filter
            .get("Tag")
            .filter(|t| t.is_object())
            .map(|t| vec![tag(t)])
            .unwrap_or_default(),
        size(&filter["ObjectSizeGreaterThan"]),
        size(&filter["ObjectSizeLessThan"]),
    )
}

/// A `Filter` for these conditions: the one element alone, or an `And` of several.
fn filter(
    prefix: Option<String>,
    tags: &[(String, String)],
    gt: Option<u64>,
    lt: Option<u64>,
) -> Value {
    let prefix = prefix.filter(|p| !p.is_empty());
    let count = usize::from(prefix.is_some())
        + tags.len()
        + usize::from(gt.is_some())
        + usize::from(lt.is_some());
    let tag = |(key, value): &(String, String)| json!({"Key": key, "Value": value});
    if count > 1 {
        let mut and = Map::new();
        if let Some(prefix) = prefix {
            and.insert("Prefix".into(), json!(prefix));
        }
        if !tags.is_empty() {
            and.insert("Tags".into(), tags.iter().map(tag).collect());
        }
        if let Some(n) = gt {
            and.insert("ObjectSizeGreaterThan".into(), json!(n));
        }
        if let Some(n) = lt {
            and.insert("ObjectSizeLessThan".into(), json!(n));
        }
        return json!({"And": and});
    }
    if let Some(prefix) = prefix {
        json!({"Prefix": prefix})
    } else if let Some(t) = tags.first() {
        json!({"Tag": tag(t)})
    } else if let Some(n) = gt {
        json!({"ObjectSizeGreaterThan": n})
    } else if let Some(n) = lt {
        json!({"ObjectSizeLessThan": n})
    } else {
        json!({})
    }
}

/// What a rule applies to, in words.
fn filter_text(rule: &Value) -> String {
    let obj = rule.as_object().cloned().unwrap_or_default();
    let (prefix, tags, gt, lt) = conditions(&obj);
    let mut parts = Vec::new();
    if let Some(prefix) = prefix.filter(|p| !p.is_empty()) {
        parts.push(format!("{prefix}*"));
    }
    parts.extend(tags.iter().map(|(k, v)| format!("tag {k}={v}")));
    if let Some(n) = gt {
        parts.push(format!("over {n} B"));
    }
    if let Some(n) = lt {
        parts.push(format!("under {n} B"));
    }
    if parts.is_empty() {
        "everything".to_owned()
    } else {
        parts.join(", ")
    }
}

/// A date in an export (`2026-10-01T00:00:00Z`), as `2026-10-01`.
fn day_text(value: &Value) -> String {
    text(value).split('T').next().unwrap_or_default().to_owned()
}

/// What a rule does, in words.
fn actions_text(rule: &Value) -> String {
    let mut parts = Vec::new();
    let expiration = &rule["Expiration"];
    if let Some(days) = expiration["Days"].as_u64() {
        parts.push(format!("expire after {days}d"));
    } else if expiration["Date"].is_string() {
        parts.push(format!("expire from {}", day_text(&expiration["Date"])));
    } else if expiration["ExpiredObjectDeleteMarker"] == true {
        parts.push("remove lone delete markers".to_owned());
    }
    let noncurrent = &rule["NoncurrentVersionExpiration"];
    if noncurrent.is_object() {
        let days = noncurrent["NoncurrentDays"]
            .as_u64()
            .map(|days| format!(" after {days}d"));
        let newer = noncurrent["NewerNoncurrentVersions"]
            .as_u64()
            .map(|newer| format!(" beyond the newest {newer}"));
        parts.push(format!(
            "remove older versions{}{}",
            days.unwrap_or_default(),
            newer.unwrap_or_default()
        ));
    }
    if let Some(days) = rule["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"].as_u64() {
        parts.push(format!("abort uploads after {days}d"));
    }
    for transition in rule["Transitions"].as_array().into_iter().flatten() {
        let when = transition["Days"].as_u64().map_or_else(
            || format!("from {}", day_text(&transition["Date"])),
            |days| format!("after {days}d"),
        );
        parts.push(format!("to {} {when}", text(&transition["StorageClass"])));
    }
    for transition in rule["NoncurrentVersionTransitions"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let days = transition["NoncurrentDays"].as_u64().unwrap_or(0);
        parts.push(format!(
            "older versions to {} after {days}d",
            text(&transition["StorageClass"])
        ));
    }
    parts.join("; ")
}

fn int(value: &Value, what: &str) -> Result<Option<i32>, Error> {
    match value {
        Value::Null => Ok(None),
        v => v
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| Error::usage(format!("{what} must be a whole number"))),
    }
}

fn long(value: &Value, what: &str) -> Result<Option<i64>, Error> {
    match value {
        Value::Null => Ok(None),
        v => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| Error::usage(format!("{what} must be a whole number"))),
    }
}

fn date_of(value: &Value, what: &str) -> Result<Option<DateTime>, Error> {
    let Some(text) = value.as_str() else {
        return match value {
            Value::Null => Ok(None),
            _ => Err(Error::usage(format!("{what} must be a date"))),
        };
    };
    DateTime::from_str(text, DateTimeFormat::DateTime)
        .ok()
        .or_else(|| with_offset(text))
        .or_else(|| parse_day(text).ok().map(DateTime::from_millis))
        .map(Some)
        .ok_or_else(|| Error::usage(format!("{what} `{text}` isn't a date like 2026-10-01")))
}

/// A date and time with an offset, as the AWS CLI writes them
/// (`2026-10-01T00:00:00+00:00`).
fn with_offset(text: &str) -> Option<DateTime> {
    let (base, offset) = text.split_at(text.len().checked_sub(6)?);
    let sign = match offset.as_bytes()[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (hours, minutes) = offset[1..].split_once(':')?;
    let (hours, minutes): (i64, i64) = (hours.parse().ok()?, minutes.parse().ok()?);
    let at = DateTime::from_str(&format!("{base}Z"), DateTimeFormat::DateTime).ok()?;
    Some(DateTime::from_secs(
        at.secs() - sign * (hours * 3600 + minutes * 60),
    ))
}

fn tag_of(value: &Value) -> Result<Tag, Error> {
    Tag::builder()
        .key(text(&value["Key"]))
        .value(text(&value["Value"]))
        .build()
        .map_err(|e| Error::usage(format!("a tag needs a Key and a Value: {e}")))
}

/// A rule from its JSON (as AWS writes it).
fn rule_from_json(rule: &Value) -> Result<LifecycleRule, Error> {
    let mut builder = LifecycleRule::builder()
        .set_id(rule["ID"].as_str().map(str::to_owned))
        .status(ExpirationStatus::from(
            rule["Status"].as_str().unwrap_or_default(),
        ));
    #[allow(deprecated, reason = "the older rule-level prefix is still S3's")]
    if let Some(prefix) = rule["Prefix"].as_str() {
        builder = builder.prefix(prefix);
    }
    if rule["Filter"].is_object() {
        builder = builder.filter(filter_from_json(&rule["Filter"])?);
    }
    let expiration = &rule["Expiration"];
    if expiration.is_object() {
        builder = builder.expiration(
            LifecycleExpiration::builder()
                .set_days(int(&expiration["Days"], "Expiration Days")?)
                .set_date(date_of(&expiration["Date"], "Expiration Date")?)
                .set_expired_object_delete_marker(expiration["ExpiredObjectDeleteMarker"].as_bool())
                .build(),
        );
    }
    let noncurrent = &rule["NoncurrentVersionExpiration"];
    if noncurrent.is_object() {
        builder = builder.noncurrent_version_expiration(
            NoncurrentVersionExpiration::builder()
                .set_noncurrent_days(int(&noncurrent["NoncurrentDays"], "NoncurrentDays")?)
                .set_newer_noncurrent_versions(newer(noncurrent)?)
                .build(),
        );
    }
    let abort = &rule["AbortIncompleteMultipartUpload"];
    if abort.is_object() {
        builder = builder.abort_incomplete_multipart_upload(
            AbortIncompleteMultipartUpload::builder()
                .set_days_after_initiation(int(
                    &abort["DaysAfterInitiation"],
                    "DaysAfterInitiation",
                )?)
                .build(),
        );
    }
    for t in list(&rule["Transitions"]) {
        builder = builder.transitions(
            Transition::builder()
                .set_days(int(&t["Days"], "Transition Days")?)
                .set_date(date_of(&t["Date"], "Transition Date")?)
                .set_storage_class(storage_class(t))
                .build(),
        );
    }
    for t in list(&rule["NoncurrentVersionTransitions"]) {
        builder = builder.noncurrent_version_transitions(
            NoncurrentVersionTransition::builder()
                .set_noncurrent_days(int(&t["NoncurrentDays"], "NoncurrentDays")?)
                .set_newer_noncurrent_versions(newer(t)?)
                .set_storage_class(storage_class(t))
                .build(),
        );
    }
    builder
        .build()
        .map_err(|e| Error::usage(format!("a rule needs a Status: {e}")))
}

/// A rule's filter from its JSON.
fn filter_from_json(filter: &Value) -> Result<LifecycleRuleFilter, Error> {
    let (gt, lt) = sizes(filter)?;
    let mut built = LifecycleRuleFilter::builder()
        .set_prefix(filter["Prefix"].as_str().map(str::to_owned))
        .set_object_size_greater_than(gt)
        .set_object_size_less_than(lt);
    if filter["Tag"].is_object() {
        built = built.tag(tag_of(&filter["Tag"])?);
    }
    let and = &filter["And"];
    if and.is_object() {
        let (gt, lt) = sizes(and)?;
        let tags = and["Tags"]
            .as_array()
            .map(|tags| tags.iter().map(tag_of).collect::<Result<Vec<_>, _>>())
            .transpose()?;
        built = built.and(
            LifecycleRuleAndOperator::builder()
                .set_prefix(and["Prefix"].as_str().map(str::to_owned))
                .set_tags(tags)
                .set_object_size_greater_than(gt)
                .set_object_size_less_than(lt)
                .build(),
        );
    }
    Ok(built.build())
}

/// The list at `value` (none when it isn't one).
fn list(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

/// `ObjectSizeGreaterThan` and `ObjectSizeLessThan`.
fn sizes(value: &Value) -> Result<(Option<i64>, Option<i64>), Error> {
    Ok((
        long(&value["ObjectSizeGreaterThan"], "ObjectSizeGreaterThan")?,
        long(&value["ObjectSizeLessThan"], "ObjectSizeLessThan")?,
    ))
}

fn newer(value: &Value) -> Result<Option<i32>, Error> {
    int(&value["NewerNoncurrentVersions"], "NewerNoncurrentVersions")
}

fn storage_class(value: &Value) -> Option<TransitionStorageClass> {
    value["StorageClass"]
        .as_str()
        .map(TransitionStorageClass::from)
}

/// An object of the fields that have a value.
fn fields<const N: usize>(fields: [(&str, Option<Value>); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .filter_map(|(key, value)| Some((key.to_owned(), value?)))
            .collect(),
    )
}

fn date_json(date: &DateTime) -> Value {
    json!(rfc3339(from_ms(date.to_millis().unwrap_or(0))))
}

fn tag_json(tag: &Tag) -> Value {
    json!({"Key": tag.key(), "Value": tag.value()})
}

/// A list's JSON, or none for an empty one (AWS leaves it out).
fn list_json<T>(items: &[T], each: impl Fn(&T) -> Value) -> Option<Value> {
    (!items.is_empty()).then(|| items.iter().map(each).collect())
}

/// A rule as JSON, as AWS writes it.
fn rule_to_json(rule: &LifecycleRule) -> Value {
    #[allow(deprecated, reason = "the older rule-level prefix is still S3's")]
    let prefix = rule.prefix().map(Value::from);
    fields([
        ("ID", rule.id().map(Value::from)),
        ("Status", Some(rule.status().as_str().into())),
        ("Prefix", prefix),
        ("Filter", rule.filter().map(filter_to_json)),
        (
            "Expiration",
            rule.expiration().map(|e| {
                fields([
                    ("Days", e.days().map(Value::from)),
                    ("Date", e.date().map(date_json)),
                    (
                        "ExpiredObjectDeleteMarker",
                        e.expired_object_delete_marker().map(Value::from),
                    ),
                ])
            }),
        ),
        (
            "NoncurrentVersionExpiration",
            rule.noncurrent_version_expiration().map(|n| {
                fields([
                    ("NoncurrentDays", n.noncurrent_days().map(Value::from)),
                    (
                        "NewerNoncurrentVersions",
                        n.newer_noncurrent_versions().map(Value::from),
                    ),
                ])
            }),
        ),
        (
            "AbortIncompleteMultipartUpload",
            rule.abort_incomplete_multipart_upload()
                .and_then(AbortIncompleteMultipartUpload::days_after_initiation)
                .map(|days| json!({"DaysAfterInitiation": days})),
        ),
        (
            "Transitions",
            list_json(rule.transitions(), |t| {
                fields([
                    ("Days", t.days().map(Value::from)),
                    ("Date", t.date().map(date_json)),
                    ("StorageClass", t.storage_class().map(|c| c.as_str().into())),
                ])
            }),
        ),
        (
            "NoncurrentVersionTransitions",
            list_json(rule.noncurrent_version_transitions(), |t| {
                fields([
                    ("NoncurrentDays", t.noncurrent_days().map(Value::from)),
                    (
                        "NewerNoncurrentVersions",
                        t.newer_noncurrent_versions().map(Value::from),
                    ),
                    ("StorageClass", t.storage_class().map(|c| c.as_str().into())),
                ])
            }),
        ),
    ])
}

/// A rule's filter as JSON.
fn filter_to_json(filter: &LifecycleRuleFilter) -> Value {
    let and = filter.and().map(|and| {
        fields([
            ("Prefix", and.prefix().map(Value::from)),
            ("Tags", list_json(and.tags(), tag_json)),
            (
                "ObjectSizeGreaterThan",
                and.object_size_greater_than().map(Value::from),
            ),
            (
                "ObjectSizeLessThan",
                and.object_size_less_than().map(Value::from),
            ),
        ])
    });
    fields([
        ("Prefix", filter.prefix().map(Value::from)),
        ("Tag", filter.tag().map(tag_json)),
        (
            "ObjectSizeGreaterThan",
            filter.object_size_greater_than().map(Value::from),
        ),
        (
            "ObjectSizeLessThan",
            filter.object_size_less_than().map(Value::from),
        ),
        ("And", and),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> RuleArgs {
        RuleArgs::default()
    }

    #[test]
    fn options_build_filters_and_actions() {
        let mut rule = json!({"ID": "r", "Status": "Enabled"});
        let mut logs = args();
        logs.prefix = Some("logs/".into());
        logs.expire_days = Some(30);
        logs.noncurrent_expire_days = Some(7);
        logs.abort_uploads_days = Some(2);
        logs.apply(&mut rule).unwrap();
        assert_eq!(
            rule,
            json!({
                "ID": "r", "Status": "Enabled",
                "Filter": {"Prefix": "logs/"},
                "Expiration": {"Days": 30},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 7},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2}
            })
        );
        // More conditions make an And; options not given are kept.
        let mut more = args();
        more.tags = Some("k=v&t=u".into());
        more.size_gt = Some(10);
        more.noncurrent_expire_newer = Some(3);
        more.apply(&mut rule).unwrap();
        assert_eq!(
            rule["Filter"],
            json!({"And": {"Prefix": "logs/", "Tags": [{"Key": "k", "Value": "v"}, {"Key": "t", "Value": "u"}], "ObjectSizeGreaterThan": 10}})
        );
        assert_eq!(
            rule["NoncurrentVersionExpiration"],
            json!({"NoncurrentDays": 7, "NewerNoncurrentVersions": 3})
        );
        // A rule-level prefix becomes a filter when conditions change.
        let mut legacy =
            json!({"ID": "l", "Status": "Enabled", "Prefix": "a/", "Expiration": {"Days": 1}});
        let mut smaller = args();
        smaller.size_lt = Some(5);
        smaller.apply(&mut legacy).unwrap();
        assert_eq!(legacy.get("Prefix"), None);
        assert_eq!(
            legacy["Filter"],
            json!({"And": {"Prefix": "a/", "ObjectSizeLessThan": 5}})
        );
        // No condition at all: the whole bucket.
        let mut whole = json!({"ID": "w", "Status": "Enabled"});
        let mut markers = args();
        markers.expire_delete_marker = true;
        markers.apply(&mut whole).unwrap();
        assert_eq!(whole["Filter"], json!({}));
        assert_eq!(
            whole["Expiration"],
            json!({"ExpiredObjectDeleteMarker": true})
        );
        assert!(parse_tags("novalue").is_err());
        // An empty prefix is no condition.
        let mut tagged = args();
        tagged.prefix = Some(String::new());
        tagged.tags = Some("k=v".into());
        tagged.apply(&mut whole).unwrap();
        assert_eq!(whole["Filter"], json!({"Tag": {"Key": "k", "Value": "v"}}));
        // A transition's date replaces its days, and the other way round.
        let mut days = args();
        days.transition_days = Some(30);
        days.transition_tier = Some("GLACIER".into());
        days.apply(&mut whole).unwrap();
        let mut date = args();
        date.transition_date = Some(0);
        date.apply(&mut whole).unwrap();
        assert_eq!(
            whole["Transitions"],
            json!([{"Date": "1970-01-01T00:00:00Z", "StorageClass": "GLACIER"}])
        );
        days.apply(&mut whole).unwrap();
        assert_eq!(
            whole["Transitions"],
            json!([{"Days": 30, "StorageClass": "GLACIER"}])
        );
        // Each action alone is one; conditions aren't.
        let setters: [fn(&mut RuleArgs); 8] = [
            |a| a.expire_days = Some(1),
            |a| a.expire_date = Some(0),
            |a| a.expire_delete_marker = true,
            |a| a.noncurrent_expire_days = Some(1),
            |a| a.noncurrent_expire_newer = Some(1),
            |a| a.abort_uploads_days = Some(1),
            |a| a.transition_tier = Some("GLACIER".into()),
            |a| a.noncurrent_transition_tier = Some("GLACIER".into()),
        ];
        for set in setters {
            let mut logs = args();
            set(&mut logs);
            assert!(logs.has_action());
        }
        assert!(
            !RuleArgs {
                prefix: Some("p".into()),
                size_gt: Some(1),
                ..args()
            }
            .has_action()
        );
    }

    #[test]
    fn rules_survive_the_sdk_both_ways() {
        let rules = [
            json!({"ID": "a", "Status": "Enabled", "Prefix": "old/", "Expiration": {"Date": "2026-10-01T00:00:00Z"}}),
            json!({
                "ID": "b", "Status": "Disabled",
                "Filter": {"And": {"Prefix": "p", "Tags": [{"Key": "k", "Value": "v"}], "ObjectSizeGreaterThan": 1, "ObjectSizeLessThan": 9}},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 3, "NewerNoncurrentVersions": 2},
                "Transitions": [{"Days": 30, "StorageClass": "GLACIER"}],
                "NoncurrentVersionTransitions": [{"NoncurrentDays": 5, "NewerNoncurrentVersions": 4, "StorageClass": "STANDARD_IA"}]
            }),
            json!({"ID": "c", "Status": "Enabled", "Filter": {"Tag": {"Key": "x", "Value": "y"}}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}, "Expiration": {"ExpiredObjectDeleteMarker": false}}),
            json!({"ID": "d", "Status": "Enabled", "Filter": {}, "Expiration": {"Days": 1}}),
        ];
        for rule in &rules {
            assert_eq!(&rule_to_json(&rule_from_json(rule).unwrap()), rule);
        }
        // Dates may also be written as days.
        let day = json!({"ID": "e", "Status": "Enabled", "Filter": {}, "Expiration": {"Date": "2026-10-01"}});
        assert_eq!(
            rule_to_json(&rule_from_json(&day).unwrap())["Expiration"]["Date"],
            "2026-10-01T00:00:00Z"
        );
        assert!(
            rule_from_json(&json!({"ID": "x", "Status": "Enabled", "Expiration": {"Days": "1"}}))
                .is_err()
        );
        assert!(
            rule_from_json(
                &json!({"ID": "x", "Status": "Enabled", "Expiration": {"Date": "soon"}})
            )
            .is_err()
        );
        // With an offset, as the AWS CLI writes them.
        let date = |text: &str| date_of(&json!(text), "Date").unwrap().map(|d| d.secs());
        assert_eq!(date("2026-10-01T00:00:00+00:00"), Some(1_790_812_800));
        assert_eq!(date("2026-10-01T02:30:00+02:30"), Some(1_790_812_800));
        assert_eq!(date("2026-09-30T22:00:00-02:00"), Some(1_790_812_800));
        assert!(date_of(&json!("2026-10-01T00:00:00*02:00"), "Date").is_err());
    }

    #[test]
    fn imports_need_rules() {
        assert!(import_rules("{").is_err());
        assert!(import_rules(r#"{"Rules": []}"#).is_err());
        assert!(import_rules(r#"{"rules": [{}]}"#).is_err());
        let rules = import_rules(r#"{"Rules": [{"ID": "a", "Status": "Enabled", "Filter": {}, "Expiration": {"Days": 1}}]}"#).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn rules_read_as_words() {
        let rule = json!({
            "Filter": {"And": {"Prefix": "logs/", "Tags": [{"Key": "k", "Value": "v"}], "ObjectSizeGreaterThan": 10}},
            "Expiration": {"Days": 30},
            "NoncurrentVersionExpiration": {"NoncurrentDays": 7, "NewerNoncurrentVersions": 2},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 3},
            "Transitions": [{"Date": "2027-01-01T00:00:00Z", "StorageClass": "GLACIER"}],
            "NoncurrentVersionTransitions": [{"NoncurrentDays": 5, "StorageClass": "STANDARD_IA"}]
        });
        assert_eq!(filter_text(&rule), "logs/*, tag k=v, over 10 B");
        assert_eq!(
            actions_text(&rule),
            "expire after 30d; remove older versions after 7d beyond the newest 2; abort uploads after 3d; to GLACIER from 2027-01-01; older versions to STANDARD_IA after 5d"
        );
        assert_eq!(filter_text(&json!({"Filter": {}})), "everything");
        assert_eq!(
            actions_text(&json!({"Expiration": {"ExpiredObjectDeleteMarker": true}})),
            "remove lone delete markers"
        );
        assert_ne!(new_id(), new_id());
        assert_eq!(new_id().len(), 20);
    }
}
