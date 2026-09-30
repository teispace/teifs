//! Bucket notifications: which events a bucket's rules send where, and the rules S3
//! checks them against.
//!
//! A rule names a target the server has configured by its ARN, `arn:teifs:sqs::ID:TYPE`
//! (`MinIO`'s `arn:minio:sqs::ID:TYPE` is read too, so `mc event add` works), the
//! events it sends (S3's names, a group's `*`, and `MinIO`'s extras) and a key prefix
//! and suffix. Two rules can't both send an event for the same key: S3 refuses a
//! configuration whose rules share an event type while their prefixes and suffixes
//! overlap.

use serde::{Deserialize, Serialize};

/// Every event a rule may name, one at a time. S3's first, then `MinIO`'s extras.
pub const EVENTS: &[&str] = &[
    "s3:ObjectCreated:Put",
    "s3:ObjectCreated:Post",
    "s3:ObjectCreated:Copy",
    "s3:ObjectCreated:CompleteMultipartUpload",
    "s3:ObjectRemoved:Delete",
    "s3:ObjectRemoved:DeleteMarkerCreated",
    "s3:ObjectRestore:Post",
    "s3:ObjectRestore:Completed",
    "s3:ObjectRestore:Delete",
    "s3:ReducedRedundancyLostObject",
    "s3:Replication:OperationFailedReplication",
    "s3:Replication:OperationMissedThreshold",
    "s3:Replication:OperationReplicatedAfterThreshold",
    "s3:Replication:OperationNotTracked",
    "s3:LifecycleExpiration:Delete",
    "s3:LifecycleExpiration:DeleteMarkerCreated",
    "s3:LifecycleTransition",
    "s3:IntelligentTiering",
    "s3:ObjectTagging:Put",
    "s3:ObjectTagging:Delete",
    "s3:ObjectAnnotation:Put",
    "s3:ObjectAnnotation:Delete",
    "s3:ObjectAcl:Put",
    "s3:ObjectRetention:Put",
    // MinIO's.
    "s3:ObjectAccessed:Get",
    "s3:ObjectAccessed:GetRetention",
    "s3:ObjectAccessed:GetLegalHold",
    "s3:ObjectAccessed:Head",
    "s3:ObjectAccessed:Attributes",
    "s3:ObjectCreated:PutLegalHold",
    "s3:ObjectRemoved:NoOP",
    "s3:ObjectRemoved:DeleteAllVersions",
    "s3:Replication:OperationCompletedReplication",
    "s3:ObjectTransition:Failed",
    "s3:ObjectTransition:Complete",
    "s3:LifecycleDelMarkerExpiration:Delete",
    "s3:Scanner:ManyVersions",
    "s3:Scanner:LargeVersions",
    "s3:Scanner:BigPrefix",
];

/// `MinIO`'s names for events S3 names otherwise: a rule may use either, and gets the
/// same events. (S3's `s3:ObjectCreated:*` doesn't include them.)
const ALIASES: &[(&str, &str)] = &[
    ("s3:ObjectCreated:PutTagging", "s3:ObjectTagging:Put"),
    ("s3:ObjectCreated:DeleteTagging", "s3:ObjectTagging:Delete"),
    ("s3:ObjectCreated:PutRetention", "s3:ObjectRetention:Put"),
];

/// The event S3 sends when a rule is set up, to check its destination.
pub const TEST_EVENT: &str = "s3:TestEvent";

/// The longest prefix or suffix, in bytes (a key's longest).
pub const MAX_FILTER_VALUE: usize = 1024;

/// The most rules a bucket may have.
pub const MAX_RULES: usize = 100;

/// The event `name` stands for: itself, or the S3 event a `MinIO` alias names.
fn canonical(name: &str) -> &str {
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
        .map_or(name, |(_, event)| event)
}

/// Whether `name` is an event a rule may name: one event, or a group's `*`.
#[must_use]
pub fn is_event(name: &str) -> bool {
    let name = canonical(name);
    match name.strip_suffix('*') {
        Some(group) => {
            group.ends_with(':')
                && group.matches(':').count() == 2
                && EVENTS.iter().any(|e| e.starts_with(group))
        }
        None => EVENTS.contains(&name),
    }
}

/// Whether the pattern a rule names (an event or a group's `*`) covers `event`.
#[must_use]
pub fn covers(pattern: &str, event: &str) -> bool {
    let (pattern, event) = (canonical(pattern), canonical(event));
    match pattern.strip_suffix('*') {
        Some(group) => event.starts_with(group) && !is_alias(event),
        None => pattern == event,
    }
}

fn is_alias(name: &str) -> bool {
    ALIASES.iter().any(|(alias, _)| *alias == name)
}

/// Whether some event is covered by both patterns.
fn share_an_event(a: &str, b: &str) -> bool {
    EVENTS.iter().any(|e| covers(a, e) && covers(b, e))
}

/// The kind of destination a rule was given as, kept so a configuration reads back as
/// it was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestinationKind {
    /// `QueueConfiguration` (`MinIO`'s targets are queues).
    Queue,
    /// `TopicConfiguration`.
    Topic,
    /// `CloudFunctionConfiguration`.
    CloudFunction,
}

/// One rule: which events on which keys go to which target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationRule {
    /// Its id (S3 makes one up when none is given), in each event's `configurationId`.
    pub id: String,
    /// How it was given.
    pub kind: DestinationKind,
    /// The target's ARN, as it was given.
    pub arn: String,
    /// The events it sends: names or groups' `*`.
    pub events: Vec<String>,
    /// Only keys starting with this, as given (URL-encoded, as S3 asks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Only keys ending with this, as given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
}

impl NotificationRule {
    /// Whether this rule sends `event` for `key`.
    #[must_use]
    pub fn matches(&self, event: &str, key: &str) -> bool {
        self.events.iter().any(|pattern| covers(pattern, event))
            && self
                .prefix
                .as_deref()
                .is_none_or(|p| key.starts_with(decoded(p).as_str()))
            && self
                .suffix
                .as_deref()
                .is_none_or(|s| key.ends_with(decoded(s).as_str()))
    }

    /// The target its ARN names, if it names one.
    #[must_use]
    pub fn target(&self) -> Option<TargetArn> {
        TargetArn::parse(&self.arn)
    }
}

/// A filter value as S3 reads it: URL-encoded, with `+` for a space.
fn decoded(value: &str) -> String {
    form_urlencoded::parse(format!("k={value}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// A bucket's notification rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationConfig {
    /// Its rules, in the order they were given.
    pub rules: Vec<NotificationRule>,
}

impl NotificationConfig {
    /// The rules that send `event` for `key`.
    pub fn matching<'a>(
        &'a self,
        event: &'a str,
        key: &'a str,
    ) -> impl Iterator<Item = &'a NotificationRule> {
        self.rules.iter().filter(move |r| r.matches(event, key))
    }

    /// Checks the configuration as S3 does, with `known` saying which targets the
    /// server has.
    ///
    /// # Errors
    ///
    /// What's wrong, for the caller: an unknown event, a filter value that's too long,
    /// a target that doesn't exist, two rules with the same id, or two rules that
    /// could send the same event for the same key.
    pub fn check(&self, known: impl Fn(&TargetArn) -> bool) -> Result<(), NotifyError> {
        if self.rules.len() > MAX_RULES {
            return Err(NotifyError::TooManyRules);
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.events.is_empty() {
                return Err(NotifyError::NoEvents(rule.id.clone()));
            }
            if let Some(event) = rule.events.iter().find(|e| !is_event(e)) {
                return Err(NotifyError::UnknownEvent(event.clone()));
            }
            let long = |v: &Option<String>| v.as_ref().is_some_and(|v| v.len() > MAX_FILTER_VALUE);
            if long(&rule.prefix) || long(&rule.suffix) {
                return Err(NotifyError::FilterTooLong);
            }
            if !rule.target().is_some_and(|t| known(&t)) {
                return Err(NotifyError::UnknownTarget(rule.arn.clone()));
            }
            for other in &self.rules[..i] {
                if other.id == rule.id {
                    return Err(NotifyError::DuplicateId(rule.id.clone()));
                }
                if overlap(other, rule) {
                    return Err(NotifyError::Ambiguous);
                }
            }
        }
        Ok(())
    }
}

/// Whether two rules could send the same event for the same key: they share an event
/// type, and some key both starts with both prefixes and ends with both suffixes (as S3
/// decides it, an absent prefix or suffix overlapping any).
fn overlap(a: &NotificationRule, b: &NotificationRule) -> bool {
    let shared = a
        .events
        .iter()
        .any(|x| b.events.iter().any(|y| share_an_event(x, y)));
    let prefixes = |x: &str, y: &str| x.starts_with(y) || y.starts_with(x);
    let suffixes = |x: &str, y: &str| x.ends_with(y) || y.ends_with(x);
    let (pa, pb) = (
        decoded_or_empty(a.prefix.as_deref()),
        decoded_or_empty(b.prefix.as_deref()),
    );
    let (sa, sb) = (
        decoded_or_empty(a.suffix.as_deref()),
        decoded_or_empty(b.suffix.as_deref()),
    );
    shared && prefixes(&pa, &pb) && suffixes(&sa, &sb)
}

fn decoded_or_empty(value: Option<&str>) -> String {
    value.map(decoded).unwrap_or_default()
}

/// The events only listeners get (`MinIO`'s): a bucket was created or removed. Their
/// records name the bucket and no object.
pub const BUCKET_EVENTS: &[&str] = &["s3:BucketCreated:*", "s3:BucketRemoved:*"];

/// What someone listening for events asks for (`MinIO`'s listen API, `mc watch`):
/// events or groups, on keys with a prefix and a suffix (as they are, not URL-encoded).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenFilter {
    /// The events: names, groups' `*`, or [`BUCKET_EVENTS`].
    pub events: Vec<String>,
    /// Only keys starting with this.
    pub prefix: String,
    /// Only keys ending with this.
    pub suffix: String,
}

impl ListenFilter {
    /// Checks it as `MinIO` does.
    ///
    /// # Errors
    ///
    /// No events, an unknown one, or a prefix or suffix longer than a key can be.
    pub fn check(&self) -> Result<(), NotifyError> {
        if self.events.is_empty() {
            return Err(NotifyError::NothingToListenFor);
        }
        if let Some(event) = self
            .events
            .iter()
            .find(|e| !is_event(e) && !BUCKET_EVENTS.contains(&e.as_str()))
        {
            return Err(NotifyError::UnknownEvent(event.clone()));
        }
        if self.prefix.len() > MAX_FILTER_VALUE || self.suffix.len() > MAX_FILTER_VALUE {
            return Err(NotifyError::FilterTooLong);
        }
        Ok(())
    }

    /// The query that asks for it: `events=…&prefix=…&suffix=…`, encoded as Signature
    /// V4 signs it (everything but letters, digits and `-._~`). No events still names
    /// `events`, so it's refused rather than read as another request.
    #[must_use]
    pub fn to_query(&self) -> String {
        let mut pairs: Vec<(&str, &str)> =
            self.events.iter().map(|e| ("events", e.as_str())).collect();
        if pairs.is_empty() {
            pairs.push(("events", ""));
        }
        for (name, value) in [("prefix", &self.prefix), ("suffix", &self.suffix)] {
            if !value.is_empty() {
                pairs.push((name, value));
            }
        }
        // Sorted as signatures sort them, so a server that keeps repeated names' order
        // (as `MinIO`'s clients sign) computes the same signature.
        let mut encoded: Vec<String> = pairs
            .iter()
            .map(|(name, value)| format!("{name}={}", uri_encoded(value)))
            .collect();
        encoded.sort();
        encoded.join("&")
    }

    /// Whether the listener wants `event` for `key`.
    #[must_use]
    pub fn matches(&self, event: &str, key: &str) -> bool {
        self.events.iter().any(|pattern| covers(pattern, event))
            && key.starts_with(&self.prefix)
            && key.ends_with(&self.suffix)
    }
}

/// `value` with every byte but letters, digits and `-._~` percent-encoded.
fn uri_encoded(value: &str) -> String {
    use std::fmt::Write as _;
    value.bytes().fold(String::new(), |mut out, b| {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
        out
    })
}

/// A target's ARN: `arn:teifs:sqs::ID:TYPE` (or `MinIO`'s `arn:minio:sqs::ID:TYPE`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TargetArn {
    /// The target's id, as the server names it.
    pub id: String,
    /// Its type: `webhook`, `nats`, `kafka`….
    pub kind: String,
}

impl TargetArn {
    /// Reads an ARN; `None` if it isn't one for a target.
    #[must_use]
    pub fn parse(arn: &str) -> Option<Self> {
        let mut parts = arn.split(':');
        let (
            Some("arn"),
            Some("teifs" | "minio"),
            Some("sqs"),
            Some(""),
            Some(id),
            Some(kind),
            None,
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return None;
        };
        let name = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        (name(id) && name(kind)).then(|| Self {
            id: id.to_owned(),
            kind: kind.to_owned(),
        })
    }
}

impl std::fmt::Display for TargetArn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "arn:teifs:sqs::{}:{}", self.id, self.kind)
    }
}

/// The version of the event records' shape (S3's current one).
pub const EVENT_VERSION: &str = "2.6";

/// What's sent for each event: `MinIO`'s envelope (its name and `BUCKET/KEY`) around
/// the record S3 sends, so consumers of either read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMessage {
    /// The event's full name: `s3:ObjectCreated:Put`.
    #[serde(rename = "EventName")]
    pub event_name: String,
    /// `BUCKET/KEY`.
    #[serde(rename = "Key")]
    pub key: String,
    /// The event, alone.
    #[serde(rename = "Records")]
    pub records: Vec<EventRecord>,
}

/// One event, as S3 describes it (`eventVersion` 2.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRecord {
    /// [`EVENT_VERSION`].
    pub event_version: String,
    /// `aws:s3`, as S3 names it, for consumers that check.
    pub event_source: String,
    /// The server's region.
    pub aws_region: String,
    /// When it happened: ISO 8601 with milliseconds, in UTC.
    pub event_time: String,
    /// Its name without `s3:`: `ObjectCreated:Put`.
    pub event_name: String,
    /// Who made it happen.
    pub user_identity: Identity,
    /// The request that made it happen.
    pub request_parameters: RequestParameters,
    /// Its answer.
    pub response_elements: ResponseElements,
    /// What it happened to.
    pub s3: S3Entity,
}

/// Who: an access key (empty for anyone), or the bucket's owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    /// Its id.
    pub principal_id: String,
}

/// The request's client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestParameters {
    /// Its address.
    #[serde(rename = "sourceIPAddress")]
    pub source_ip_address: String,
}

/// The answer's ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseElements {
    /// Its `x-amz-request-id`.
    #[serde(rename = "x-amz-request-id")]
    pub request_id: String,
    /// Its `x-amz-id-2`.
    #[serde(rename = "x-amz-id-2")]
    pub host_id: String,
}

/// The bucket and object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Entity {
    /// `1.0`.
    pub s3_schema_version: String,
    /// The id of the rule that sent it.
    pub configuration_id: String,
    /// The bucket.
    pub bucket: BucketEntity,
    /// The object.
    pub object: ObjectEntity,
}

/// The bucket an event happened in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketEntity {
    /// Its name.
    pub name: String,
    /// Its owner.
    pub owner_identity: Identity,
    /// Its ARN: `arn:aws:s3:::NAME`.
    pub arn: String,
}

/// The object an event happened to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectEntity {
    /// Its key, URL-encoded as S3 sends it ([`event_key`]).
    pub key: String,
    /// Its size, when it was written or read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Its ETag, unquoted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e_tag: Option<String>,
    /// Its version's id, in a versioned bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// Orders the events of one key: a later event's is greater (compared as hex
    /// numbers of the same length).
    pub sequencer: String,
}

/// A key as events carry it: URL-encoded, with `+` for a space and `/` left as it is
/// (as S3's events; decoded with `unquote_plus` and the like).
#[must_use]
pub fn event_key(key: &str) -> String {
    key.split('/')
        .map(|part| form_urlencoded::byte_serialize(part.as_bytes()).collect::<String>())
        .collect::<Vec<_>>()
        .join("/")
}

/// The key an event's record carries ([`event_key`]), decoded.
#[must_use]
pub fn event_key_decoded(key: &str) -> String {
    decoded(key)
}

/// What a target is sent to check it when a rule starts sending to it (S3's
/// `s3:TestEvent`), unless the request says to skip it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TestEvent {
    /// `TeiFS`.
    pub service: String,
    /// [`TEST_EVENT`].
    pub event: String,
    /// When: ISO 8601 with milliseconds, in UTC.
    pub time: String,
    /// The bucket.
    pub bucket: String,
    /// The request's id.
    pub request_id: String,
    /// The request's `x-amz-id-2`.
    pub host_id: String,
}

/// Why a notification configuration is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotifyError {
    /// An event name nothing sends.
    #[error("The event `{0}` isn't one S3 or TeiFS sends")]
    UnknownEvent(String),
    /// A rule without events.
    #[error("The rule `{0}` names no events")]
    NoEvents(String),
    /// A prefix or suffix longer than a key can be.
    #[error("A filter's prefix or suffix is longer than 1024 bytes")]
    FilterTooLong,
    /// An ARN that isn't one of the server's targets.
    #[error(
        "A specified destination ARN does not exist or is not well-formed: `{0}`. Name a \
         target the server has, as arn:teifs:sqs::ID:TYPE"
    )]
    UnknownTarget(String),
    /// Two rules with the same id.
    #[error("Two rules have the id `{0}`")]
    DuplicateId(String),
    /// Two rules that could send the same event for the same key.
    #[error(
        "Configuration is ambiguously defined. Cannot have overlapping suffixes in two \
         rules if the prefixes are overlapping for the same event type."
    )]
    Ambiguous,
    /// More rules than a bucket may have.
    #[error("A bucket may have at most 100 notification rules")]
    TooManyRules,
    /// A listener that asks for no events.
    #[error("Name the events to listen for with `events`")]
    NothingToListenFor,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        id: &str,
        events: &[&str],
        prefix: Option<&str>,
        suffix: Option<&str>,
    ) -> NotificationRule {
        NotificationRule {
            id: id.into(),
            kind: DestinationKind::Queue,
            arn: "arn:teifs:sqs::hook:webhook".into(),
            events: events.iter().map(|&e| e.to_owned()).collect(),
            prefix: prefix.map(str::to_owned),
            suffix: suffix.map(str::to_owned),
        }
    }

    fn check(rules: Vec<NotificationRule>) -> Result<(), NotifyError> {
        NotificationConfig { rules }.check(|t| t.id == "hook")
    }

    #[test]
    fn events_are_names_or_groups() {
        for good in [
            "s3:ObjectCreated:*",
            "s3:ObjectCreated:Put",
            "s3:ObjectRemoved:*",
            "s3:ObjectAccessed:*",
            "s3:LifecycleTransition",
            "s3:ObjectCreated:PutTagging",
        ] {
            assert!(is_event(good), "{good}");
        }
        for bad in [
            "s3:ObjectCreated",
            "s3:Nothing:*",
            "ObjectCreated:Put",
            "*",
            "s3:*",
            "",
        ] {
            assert!(!is_event(bad), "{bad}");
        }
        assert!(covers("s3:ObjectCreated:*", "s3:ObjectCreated:Copy"));
        assert!(!covers("s3:ObjectCreated:*", "s3:ObjectRemoved:Delete"));
        assert!(!covers("s3:ObjectCreated:*", "s3:ObjectTagging:Put"));
        assert!(covers(
            "s3:ObjectCreated:PutTagging",
            "s3:ObjectTagging:Put"
        ));
        assert!(covers("s3:ObjectTagging:*", "s3:ObjectTagging:Put"));
    }

    #[test]
    fn rules_match_events_and_keys() {
        let r = rule("1", &["s3:ObjectCreated:*"], Some("images/"), Some(".jpg"));
        assert!(r.matches("s3:ObjectCreated:Put", "images/a.jpg"));
        assert!(!r.matches("s3:ObjectCreated:Put", "images/a.png"));
        assert!(!r.matches("s3:ObjectCreated:Put", "logs/a.jpg"));
        assert!(!r.matches("s3:ObjectRemoved:Delete", "images/a.jpg"));
        // Filter values are URL-encoded, a space as `+`.
        let spaced = rule("2", &["s3:ObjectCreated:*"], Some("my+photos%2F"), None);
        assert!(spaced.matches("s3:ObjectCreated:Put", "my photos/a.jpg"));
    }

    /// S3's examples, valid and not (userguide/notification-how-to-filtering).
    #[test]
    fn overlapping_rules_for_the_same_event_are_refused() {
        let put = &["s3:ObjectCreated:Put"][..];
        let created = &["s3:ObjectCreated:*"][..];
        let valid = [
            vec![
                rule("1", put, Some("images/"), None),
                rule("2", put, Some("logs/"), None),
            ],
            vec![
                rule("1", put, None, Some(".jpg")),
                rule("2", put, None, Some(".png")),
            ],
            vec![
                rule("1", put, Some("images"), Some(".jpg")),
                rule("2", put, Some("images"), Some(".png")),
            ],
            vec![
                rule("1", put, Some("image/"), None),
                rule("2", &["s3:ObjectRemoved:*"], Some("image/"), None),
            ],
        ];
        for rules in valid {
            assert_eq!(check(rules.clone()), Ok(()), "{rules:?}");
        }
        let invalid = [
            vec![
                rule("1", created, None, None),
                rule("2", created, Some("images"), None),
            ],
            vec![
                rule("1", created, None, Some("jpg")),
                rule("2", put, None, Some("pg")),
            ],
            vec![
                rule("1", created, Some("images"), Some("jpg")),
                rule("2", put, None, Some("jpg")),
            ],
        ];
        for rules in invalid {
            assert_eq!(
                check(rules.clone()),
                Err(NotifyError::Ambiguous),
                "{rules:?}"
            );
        }
    }

    #[test]
    fn bad_rules_say_what_is_wrong() {
        let mut unknown = rule("1", &["s3:ObjectCreated:Put"], None, None);
        unknown.arn = "arn:aws:sqs:us-east-1:123456789012:queue".into();
        assert!(matches!(
            check(vec![unknown]),
            Err(NotifyError::UnknownTarget(_))
        ));
        let mut elsewhere = rule("1", &["s3:ObjectCreated:Put"], None, None);
        elsewhere.arn = "arn:teifs:sqs::other:webhook".into();
        assert!(matches!(
            check(vec![elsewhere]),
            Err(NotifyError::UnknownTarget(_))
        ));
        assert!(matches!(
            check(vec![rule("1", &["s3:Bogus"], None, None)]),
            Err(NotifyError::UnknownEvent(_))
        ));
        assert!(matches!(
            check(vec![rule("1", &[], None, None)]),
            Err(NotifyError::NoEvents(_))
        ));
        let long = "a".repeat(MAX_FILTER_VALUE + 1);
        assert_eq!(
            check(vec![rule(
                "1",
                &["s3:ObjectCreated:Put"],
                Some(&long),
                None
            )]),
            Err(NotifyError::FilterTooLong)
        );
        assert!(matches!(
            check(vec![
                rule("1", &["s3:ObjectCreated:Put"], Some("a/"), None),
                rule("1", &["s3:ObjectCreated:Put"], Some("b/"), None),
            ]),
            Err(NotifyError::DuplicateId(_))
        ));
        let many = (0..=MAX_RULES)
            .map(|i| {
                rule(
                    &i.to_string(),
                    &["s3:ObjectCreated:Put"],
                    Some(&format!("{i}/")),
                    None,
                )
            })
            .collect();
        assert_eq!(check(many), Err(NotifyError::TooManyRules));
    }

    #[test]
    fn listeners_get_the_events_they_ask_for() {
        let filter = ListenFilter {
            events: vec!["s3:ObjectCreated:*".into(), "s3:BucketCreated:*".into()],
            prefix: "photos/".into(),
            suffix: ".jpg".into(),
        };
        assert_eq!(filter.check(), Ok(()));
        assert!(filter.matches("s3:ObjectCreated:Put", "photos/a.jpg"));
        assert!(!filter.matches("s3:ObjectCreated:Put", "photos/a.png"));
        assert!(!filter.matches("s3:ObjectCreated:Put", "videos/a.jpg"));
        assert!(!filter.matches("s3:ObjectRemoved:Delete", "photos/a.jpg"));
        let buckets = ListenFilter {
            events: vec!["s3:BucketCreated:*".into()],
            ..ListenFilter::default()
        };
        assert!(buckets.matches("s3:BucketCreated:*", ""));
        assert!(!buckets.matches("s3:BucketRemoved:*", ""));
        assert_eq!(
            filter.to_query(),
            "events=s3%3ABucketCreated%3A%2A&events=s3%3AObjectCreated%3A%2A\
             &prefix=photos%2F&suffix=.jpg"
        );
        let spaced = ListenFilter {
            prefix: "a b+ü".into(),
            ..buckets.clone()
        };
        assert_eq!(
            spaced.to_query(),
            "events=s3%3ABucketCreated%3A%2A&prefix=a%20b%2B%C3%BC"
        );
        assert_eq!(ListenFilter::default().to_query(), "events=");
        assert_eq!(
            ListenFilter::default().check(),
            Err(NotifyError::NothingToListenFor)
        );
        let unknown = ListenFilter {
            events: vec!["s3:ObjectMoved:*".into()],
            ..ListenFilter::default()
        };
        assert!(matches!(unknown.check(), Err(NotifyError::UnknownEvent(_))));
        let long = ListenFilter {
            suffix: "x".repeat(MAX_FILTER_VALUE + 1),
            ..buckets
        };
        assert_eq!(long.check(), Err(NotifyError::FilterTooLong));
    }

    #[test]
    fn keys_are_encoded_as_s3_sends_them() {
        for key in ["a b/c+d/é?.txt", "plain", "x/ y/"] {
            assert_eq!(event_key_decoded(&event_key(key)), key);
        }
        assert_eq!(
            event_key("photos/my cat+dog=1.jpg"),
            "photos/my+cat%2Bdog%3D1.jpg"
        );
        assert_eq!(event_key("ü/a"), "%C3%BC/a");
    }

    #[test]
    fn records_have_s3s_field_names() {
        let record = EventRecord {
            event_version: EVENT_VERSION.into(),
            event_source: "aws:s3".into(),
            aws_region: "us-east-1".into(),
            event_time: "2026-09-30T12:00:00.000Z".into(),
            event_name: "ObjectCreated:Put".into(),
            user_identity: Identity {
                principal_id: "AKIA".into(),
            },
            request_parameters: RequestParameters {
                source_ip_address: "127.0.0.1".into(),
            },
            response_elements: ResponseElements {
                request_id: "ID".into(),
                host_id: "HOST".into(),
            },
            s3: S3Entity {
                s3_schema_version: "1.0".into(),
                configuration_id: "rule".into(),
                bucket: BucketEntity {
                    name: "bkt".into(),
                    owner_identity: Identity {
                        principal_id: "owner".into(),
                    },
                    arn: "arn:aws:s3:::bkt".into(),
                },
                object: ObjectEntity {
                    key: "a+b".into(),
                    size: Some(3),
                    e_tag: Some("abc".into()),
                    version_id: None,
                    sequencer: "0A".into(),
                },
            },
        };
        let json = serde_json::to_value(&record).unwrap();
        for path in [
            "/eventVersion",
            "/awsRegion",
            "/userIdentity/principalId",
            "/requestParameters/sourceIPAddress",
            "/responseElements/x-amz-request-id",
            "/responseElements/x-amz-id-2",
            "/s3/s3SchemaVersion",
            "/s3/configurationId",
            "/s3/bucket/ownerIdentity/principalId",
            "/s3/object/eTag",
            "/s3/object/sequencer",
        ] {
            assert!(json.pointer(path).is_some(), "{path}");
        }
        assert!(json.pointer("/s3/object/versionId").is_none());
    }

    #[test]
    fn target_arns_are_ours_or_minios() {
        let hook = TargetArn {
            id: "primary".into(),
            kind: "webhook".into(),
        };
        assert_eq!(
            TargetArn::parse("arn:teifs:sqs::primary:webhook"),
            Some(hook.clone())
        );
        assert_eq!(
            TargetArn::parse("arn:minio:sqs::primary:webhook"),
            Some(hook.clone())
        );
        assert_eq!(hook.to_string(), "arn:teifs:sqs::primary:webhook");
        for bad in [
            "arn:aws:sqs::primary:webhook",
            "arn:teifs:sns::primary:webhook",
            "arn:teifs:sqs:us-east-1:primary:webhook",
            "arn:teifs:sqs:::webhook",
            "arn:teifs:sqs::primary:webhook:extra",
            "arn:teifs:sqs::pri mary:webhook",
        ] {
            assert_eq!(TargetArn::parse(bad), None, "{bad}");
        }
    }
}
