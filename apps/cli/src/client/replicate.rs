//! Bucket replication: `teifs replicate add|update|ls|rm|status|check|resync`, with
//! mc's names. A destination is named as `ALIAS/BUCKET`: under the source's own alias
//! it's a bucket on the same server; under another, a bucket on that alias's service,
//! added as a replication target that signs with the alias's keys, so no secret is
//! ever given on the command line. Rules are read and written as S3's XML, which keeps
//! `MinIO`'s `DeleteReplication` that the AWS SDK leaves out.

use std::time::Duration;

use clap::Subcommand;
use serde_json::json;
use teifs_client::{Client, NewReplicationTarget, ReplicationTarget};
use teifs_types::replication::{
    LOCAL_ARN, ReplicationConfig, ReplicationDestination, ReplicationFilter, ReplicationRule,
    TARGET_ARN, Tag,
};

use super::{Error, alias::Aliases, commands::plural, filters, target::Remote, target::Target};
use crate::{
    admin::client_for,
    ui,
    units::{self, parse_duration, parse_size},
};

/// What `--replicate` turns on when it isn't given: everything.
const EVERYTHING: &str = "delete-marker,delete,existing-objects,metadata-sync";

#[derive(Subcommand)]
pub enum ReplicateAction {
    /// Replicate `ALIAS/BUCKET`'s versions to `--remote-bucket`: a bucket on the same
    /// server when it's under the same alias, otherwise on the service its alias names,
    /// signing with that alias's keys. Both buckets must keep versions.
    Add {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// Where versions go: `ALIAS/BUCKET`.
        #[arg(long)]
        remote_bucket: String,
        /// The rule's id: `to-ALIAS-BUCKET` when not given.
        #[arg(long)]
        id: Option<String>,
        #[command(flatten)]
        rule: RuleOptions,
        /// Make writes wait until the replica is made (another service only).
        #[arg(long)]
        sync: bool,
        /// The most sent there a second: bytes, or with KiB, MiB or GiB (another
        /// service only).
        #[arg(long, value_parser = parse_size)]
        bandwidth: Option<u64>,
        /// Add the rule turned off.
        #[arg(long)]
        disable: bool,
    },
    /// Change a rule: what it applies to, what it replicates, or whether it's on.
    Update {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The rule's id.
        #[arg(long)]
        id: String,
        #[command(flatten)]
        rule: RuleOptions,
        /// Turn the rule on.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Turn the rule off: versions written meanwhile aren't replicated.
        #[arg(long)]
        disable: bool,
    },
    /// List a bucket's replication rules.
    Ls {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Remove a rule (with its target, when no other rule names it), or every one.
    #[command(group(clap::ArgGroup::new("which").required(true)))]
    Rm {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The rule's id.
        #[arg(long, group = "which")]
        id: Option<String>,
        /// Every rule.
        #[arg(long, group = "which")]
        all: bool,
        /// Don't ask before removing every rule.
        #[arg(long, requires = "all")]
        force: bool,
    },
    /// Show what replication did for each destination: replicated, waiting and failed.
    Status {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Check that replication can work: each destination is there, keeps versions,
    /// and takes the replicator's writes and deletes, without writing anything.
    Check {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Send versions a destination already had again, as when it lost them.
    Resync {
        #[command(subcommand)]
        action: ResyncAction,
    },
}

#[derive(Subcommand)]
pub enum ResyncAction {
    /// Send every version from before now (or `--older-than` ago) that the rules send
    /// to a destination again. Its rules must replicate existing objects.
    Start {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The destination: `ALIAS/BUCKET` (needed when there are several).
        #[arg(long)]
        remote_bucket: Option<String>,
        /// Only versions at least this old: `30d`, `12h`.
        #[arg(long, value_parser = parse_duration)]
        older_than: Option<Duration>,
    },
    /// Show where resyncs stand.
    Status {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// Only this destination's: `ALIAS/BUCKET`.
        #[arg(long)]
        remote_bucket: Option<String>,
    },
    /// Stop the resync going on.
    Cancel {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The destination: `ALIAS/BUCKET` (needed when there are several).
        #[arg(long)]
        remote_bucket: Option<String>,
    },
}

/// What a rule applies to and does.
#[derive(clap::Args)]
pub struct RuleOptions {
    /// Which rule wins when several match an object: higher first.
    #[arg(long)]
    priority: Option<i32>,
    /// Only objects whose keys start with this.
    #[arg(long)]
    prefix: Option<String>,
    /// Only objects with this tag, as `KEY=VALUE`; repeat for several.
    #[arg(long = "tag", value_parser = filters::tag)]
    tags: Vec<(String, String)>,
    /// What's replicated besides new versions, comma-separated: `delete-marker`,
    /// `delete` (removals of versions), `existing-objects`, `metadata-sync` (changes to
    /// replicas come back); `none` for nothing else. A new rule replicates all of them
    /// when it isn't given (without `delete-marker` when it has tags, which S3 doesn't
    /// allow).
    #[arg(long)]
    replicate: Option<String>,
    /// The storage class replicas get.
    #[arg(long)]
    storage_class: Option<String>,
}

/// What `--replicate` turns on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one for each of --replicate's words"
)]
struct Replicates {
    delete_markers: bool,
    deletes: bool,
    existing: bool,
    metadata: bool,
}

impl Replicates {
    fn parse(text: &str) -> Result<Self, Error> {
        let mut replicates = Self::default();
        for word in text.split(',').map(str::trim).filter(|w| !w.is_empty()) {
            match word {
                "delete-marker" => replicates.delete_markers = true,
                "delete" => replicates.deletes = true,
                "existing-objects" => replicates.existing = true,
                "metadata-sync" => replicates.metadata = true,
                "none" => {}
                other => {
                    return Err(Error::usage(format!(
                        "--replicate takes delete-marker, delete, existing-objects, \
                         metadata-sync or none, not {other}"
                    )));
                }
            }
        }
        Ok(replicates)
    }

    fn of(rule: &ReplicationRule) -> Self {
        Self {
            delete_markers: rule.delete_markers.unwrap_or(false),
            deletes: rule.delete_replication.unwrap_or(false),
            existing: rule.existing_objects.unwrap_or(false),
            metadata: rule.replica_modifications.unwrap_or(false),
        }
    }

    fn apply(self, rule: &mut ReplicationRule) {
        rule.delete_markers = Some(self.delete_markers);
        rule.delete_replication = Some(self.deletes);
        rule.existing_objects = Some(self.existing);
        rule.replica_modifications = Some(self.metadata);
    }

    fn words(self) -> String {
        let words: Vec<&str> = [
            (self.delete_markers, "delete-marker"),
            (self.deletes, "delete"),
            (self.existing, "existing-objects"),
            (self.metadata, "metadata-sync"),
        ]
        .into_iter()
        .filter_map(|(on, word)| on.then_some(word))
        .collect();
        if words.is_empty() {
            "new versions".to_owned()
        } else {
            words.join(",")
        }
    }
}

/// The bucket whose replication is changed or read.
struct Source {
    remote: Remote,
    name: String,
    client: Client,
}

impl Source {
    fn new(bucket: &str, aliases: &Aliases) -> Result<Self, Error> {
        let remote = Target::parse(bucket, aliases)?.remote("replicate")?;
        let name = remote.display("");
        if !remote.key.is_empty() {
            return Err(Error::usage(format!(
                "replication rules belong to a bucket: give {name}"
            )));
        }
        remote.bucket()?;
        let client = client_for(&remote.alias)?;
        Ok(Self {
            remote,
            name,
            client,
        })
    }

    fn bucket(&self) -> &str {
        self.remote.bucket.as_deref().unwrap_or_default()
    }

    /// The bucket's configuration; `None` when it has none.
    async fn read(&self) -> Result<Option<ReplicationConfig>, Error> {
        let xml = self
            .client
            .bucket_replication(self.bucket())
            .await
            .map_err(|e| {
                Error::admin(
                    format!("can't read the replication rules of {}", self.name),
                    &e,
                )
            })?;
        xml.map(|xml| {
            teifs_server::replication_from_xml(&xml).map_err(|why| {
                Error::general(format!(
                    "can't read the replication rules of {}: {why}",
                    self.name
                ))
            })
        })
        .transpose()
    }

    /// The bucket's configuration, which must have rules.
    async fn read_some(&self) -> Result<ReplicationConfig, Error> {
        self.read().await?.ok_or_else(|| {
            Error::general(format!("{} has no replication rules", self.name)).with_hint(format!(
                "add one: teifs replicate add {} --remote-bucket ALIAS/BUCKET",
                self.name
            ))
        })
    }

    /// Writes `config`, or removes the configuration when it has no rules.
    async fn write(&self, config: &ReplicationConfig) -> Result<(), Error> {
        let result = if config.rules.is_empty() {
            self.client.delete_bucket_replication(self.bucket()).await
        } else {
            self.client
                .set_bucket_replication(self.bucket(), teifs_server::replication_to_xml(config))
                .await
        };
        result.map_err(|e| {
            Error::admin(
                format!("can't change the replication rules of {}", self.name),
                &e,
            )
        })
    }

    async fn targets(&self) -> Result<Vec<ReplicationTarget>, Error> {
        self.client
            .replication_targets(self.bucket())
            .await
            .map_err(|e| {
                Error::admin(
                    format!("can't read the replication targets of {}", self.name),
                    &e,
                )
            })
    }

    /// Removes the targets in `arns` no rule of `config` names any more.
    async fn drop_unused(&self, config: &ReplicationConfig, arns: &[String]) -> Result<(), Error> {
        for arn in arns {
            let named = config.rules.iter().any(|r| &r.destination.bucket == arn);
            if arn.starts_with(TARGET_ARN) && !named {
                self.client
                    .remove_replication_target(self.bucket(), arn)
                    .await
                    .map_err(|e| Error::admin(format!("can't remove the target {arn}"), &e))?;
            }
        }
        Ok(())
    }

    /// The ARN `--remote-bucket` names among the bucket's destinations.
    async fn arn_of(
        &self,
        given: Option<&str>,
        aliases: &Aliases,
    ) -> Result<Option<String>, Error> {
        let Some(given) = given else {
            return Ok(None);
        };
        let destination = Destination::parse(given, &self.remote, aliases)?;
        let targets = self.targets().await?;
        destination
            .arn(&targets)
            .map(Some)
            .ok_or_else(|| Error::usage(format!("{} doesn't replicate to {given}", self.name)))
    }
}

/// Where a rule sends versions.
enum Destination {
    /// A bucket on the same server.
    Local(String),
    /// A bucket on the service another alias names.
    Remote(Remote),
}

impl Destination {
    fn parse(given: &str, source: &Remote, aliases: &Aliases) -> Result<Self, Error> {
        let remote = Target::parse(given, aliases)?.remote("--remote-bucket")?;
        let bucket = remote.bucket()?.to_owned();
        if !remote.key.is_empty() {
            return Err(Error::usage(format!(
                "--remote-bucket is a bucket: give {}",
                remote.display("")
            )));
        }
        if remote.alias_name == source.alias_name {
            if source.bucket.as_deref() == Some(bucket.as_str()) {
                return Err(Error::usage("a bucket can't replicate to itself"));
            }
            return Ok(Self::Local(bucket));
        }
        Ok(Self::Remote(remote))
    }

    /// Its service's host and port, and whether it's reached over HTTPS.
    fn endpoint(remote: &Remote) -> (bool, &str) {
        let url = remote.alias.url.as_str();
        match url.strip_prefix("https://") {
            Some(rest) => (true, rest.trim_end_matches('/')),
            None => (
                false,
                url.trim_start_matches("http://").trim_end_matches('/'),
            ),
        }
    }

    /// Its ARN, if it's a destination already.
    fn arn(&self, targets: &[ReplicationTarget]) -> Option<String> {
        match self {
            Self::Local(bucket) => Some(format!("{LOCAL_ARN}{bucket}")),
            Self::Remote(remote) => {
                let (secure, endpoint) = Self::endpoint(remote);
                targets
                    .iter()
                    .find(|t| {
                        t.endpoint == endpoint
                            && t.secure == secure
                            && Some(t.bucket.as_str()) == remote.bucket.as_deref()
                    })
                    .map(|t| t.arn.clone())
            }
        }
    }

    /// A rule id made from it: `to-ALIAS-BUCKET`.
    fn id(&self, source: &Remote) -> String {
        match self {
            Self::Local(bucket) => format!("to-{}-{bucket}", source.alias_name),
            Self::Remote(remote) => format!(
                "to-{}-{}",
                remote.alias_name,
                remote.bucket.as_deref().unwrap_or_default()
            ),
        }
    }
}

/// `teifs replicate …`.
pub(super) async fn run(action: ReplicateAction, aliases: &Aliases) -> Result<(), Error> {
    match action {
        ReplicateAction::Add {
            bucket,
            remote_bucket,
            id,
            rule,
            sync,
            bandwidth,
            disable,
        } => {
            let source = Source::new(&bucket, aliases)?;
            let destination = Destination::parse(&remote_bucket, &source.remote, aliases)?;
            let target = Added {
                sync,
                bandwidth: bandwidth.unwrap_or(0),
            };
            let id = id.unwrap_or_else(|| destination.id(&source.remote));
            add(&source, &destination, (&id, &rule), target, !disable).await
        }
        ReplicateAction::Update {
            bucket,
            id,
            rule,
            enable,
            disable,
        } => {
            let source = Source::new(&bucket, aliases)?;
            let on = enable.then_some(true).or(disable.then_some(false));
            update(&source, &id, &rule, on).await
        }
        ReplicateAction::Ls { bucket } => ls(&Source::new(&bucket, aliases)?).await,
        ReplicateAction::Rm {
            bucket,
            id,
            all,
            force,
        } => rm(&Source::new(&bucket, aliases)?, id.as_deref(), all, force).await,
        ReplicateAction::Status { bucket } => status(&Source::new(&bucket, aliases)?).await,
        ReplicateAction::Check { bucket } => check(&Source::new(&bucket, aliases)?).await,
        ReplicateAction::Resync { action } => resync(action, aliases).await,
    }
}

/// How a new target sends.
#[derive(Clone, Copy)]
struct Added {
    sync: bool,
    bandwidth: u64,
}

async fn add(
    source: &Source,
    destination: &Destination,
    (id, options): (&str, &RuleOptions),
    target: Added,
    enabled: bool,
) -> Result<(), Error> {
    let name = &source.name;
    if matches!(destination, Destination::Local(_)) && (target.sync || target.bandwidth > 0) {
        return Err(Error::usage(
            "--sync and --bandwidth are for another service's bucket, not one on the same server",
        ));
    }
    let mut config = source.read().await?.unwrap_or(ReplicationConfig {
        role: String::new(),
        rules: Vec::new(),
    });
    if config.rules.iter().any(|r| r.id == id) {
        return Err(Error::usage(format!(
            "{name} has a replication rule {id} already: change it with \
             teifs replicate update {name} --id {id}"
        )));
    }
    let targets = source.targets().await?;
    let (arn, new_target) = match (destination.arn(&targets), destination) {
        (Some(arn), _) => (arn, false),
        (None, Destination::Remote(remote)) => {
            (add_target(source, remote, options, target).await?, true)
        }
        (None, Destination::Local(bucket)) => (format!("{LOCAL_ARN}{bucket}"), false),
    };
    let priority = options.priority.unwrap_or_else(|| {
        config
            .rules
            .iter()
            .filter_map(|r| r.priority)
            .max()
            .map_or(1, |p| p.saturating_add(1))
    });
    let mut rule = ReplicationRule {
        id: id.to_owned(),
        priority: Some(priority),
        enabled,
        filter: ReplicationFilter::All,
        delete_markers: None,
        delete_replication: None,
        existing_objects: None,
        sse_kms_objects: None,
        replica_modifications: None,
        destination: ReplicationDestination {
            bucket: arn.clone(),
            account: None,
            storage_class: None,
            owner_override: false,
            encryption: None,
            replication_time: None,
            metrics: None,
        },
    };
    rule.filter = filter(options.prefix.clone(), &options.tags);
    let replicates = match &options.replicate {
        Some(text) => Replicates::parse(text)?,
        None => Replicates {
            delete_markers: options.tags.is_empty(),
            ..Replicates::parse(EVERYTHING)?
        },
    };
    replicates.apply(&mut rule);
    rule.destination
        .storage_class
        .clone_from(&options.storage_class);
    config.rules.push(rule);
    if let Err(err) = source.write(&config).await {
        // The target was only for this rule.
        if new_target {
            let _ = source
                .client
                .remove_replication_target(source.bucket(), &arn)
                .await;
        }
        return Err(err);
    }
    let shown = shown_destination(&arn, &source.remote, &targets_after(source, &targets).await);
    ui::done(
        format!(
            "{name} replicates to {shown}: rule {id} ({})",
            replicates.words()
        ),
        || json!({"type": "replicationRule", "bucket": name, "id": id, "destination": shown, "arn": arn}),
    );
    if enabled && let Err(err) = source.client.check_replication(source.bucket()).await {
        ui::warn(format!(
            "replication can't work yet: {}",
            Error::admin("the check failed", &err)
        ));
    }
    Ok(())
}

/// The targets after one may have been added: read again, or those before.
async fn targets_after(source: &Source, before: &[ReplicationTarget]) -> Vec<ReplicationTarget> {
    source.targets().await.unwrap_or_else(|_| before.to_vec())
}

/// Adds `remote` as a target of the source bucket: its ARN.
async fn add_target(
    source: &Source,
    remote: &Remote,
    options: &RuleOptions,
    target: Added,
) -> Result<String, Error> {
    let (secure, endpoint) = Destination::endpoint(remote);
    let alias = &remote.alias;
    let new = NewReplicationTarget {
        endpoint,
        secure,
        bucket: remote.bucket.as_deref().unwrap_or_default(),
        region: &alias.region,
        access_key: &alias.access_key,
        secret_key: &alias.secret_key,
        session_token: alias.session_token.as_deref(),
        storage_class: options.storage_class.as_deref().unwrap_or_default(),
        bandwidth_limit: target.bandwidth,
        sync: target.sync,
    };
    source
        .client
        .add_replication_target(source.bucket(), &new)
        .await
        .map_err(|e| {
            Error::admin(
                format!(
                    "can't add {} as a replication target of {}",
                    remote.display(""),
                    source.name
                ),
                &e,
            )
        })
}

/// A rule's filter from a prefix and tags.
fn filter(prefix: Option<String>, tags: &[(String, String)]) -> ReplicationFilter {
    let mut tags: Vec<Tag> = tags
        .iter()
        .map(|(key, value)| Tag {
            key: key.clone(),
            value: value.clone(),
        })
        .collect();
    match (prefix, tags.len()) {
        (None, 0) => ReplicationFilter::All,
        (Some(prefix), 0) => ReplicationFilter::Prefix(prefix),
        (None, 1) => tags
            .pop()
            .map_or(ReplicationFilter::All, ReplicationFilter::Tag),
        (prefix, _) => ReplicationFilter::And { prefix, tags },
    }
}

/// A filter's prefix and tags.
fn conditions(filter: &ReplicationFilter) -> (Option<&str>, Vec<(&str, &str)>) {
    match filter {
        ReplicationFilter::All => (None, Vec::new()),
        ReplicationFilter::V1Prefix(prefix) | ReplicationFilter::Prefix(prefix) => {
            (Some(prefix.as_str()).filter(|p| !p.is_empty()), Vec::new())
        }
        ReplicationFilter::Tag(tag) => (None, vec![(tag.key.as_str(), tag.value.as_str())]),
        ReplicationFilter::And { prefix, tags } => (
            prefix.as_deref(),
            tags.iter()
                .map(|t| (t.key.as_str(), t.value.as_str()))
                .collect(),
        ),
    }
}

async fn update(
    source: &Source,
    id: &str,
    options: &RuleOptions,
    enabled: Option<bool>,
) -> Result<(), Error> {
    let name = &source.name;
    let mut config = source.read_some().await?;
    let rule = config
        .rules
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(|| no_rule(name, id))?;
    if let Some(priority) = options.priority {
        rule.priority = Some(priority);
    }
    if options.prefix.is_some() || !options.tags.is_empty() {
        let (prefix, tags) = conditions(&rule.filter);
        let prefix = options.prefix.clone().or_else(|| prefix.map(str::to_owned));
        let tags: Vec<(String, String)> = if options.tags.is_empty() {
            tags.into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        } else {
            options.tags.clone()
        };
        rule.filter = filter(prefix.filter(|p| !p.is_empty()), &tags);
    }
    if let Some(text) = &options.replicate {
        Replicates::parse(text)?.apply(rule);
    }
    if let Some(class) = &options.storage_class {
        rule.destination.storage_class = Some(class.clone()).filter(|c| !c.is_empty());
    }
    if let Some(on) = enabled {
        rule.enabled = on;
    }
    if rule.priority.is_none() {
        // The first version's rules have none; written back, they're the later one's.
        rule.priority = Some(0);
        if let ReplicationFilter::V1Prefix(prefix) = &rule.filter {
            rule.filter = filter(Some(prefix.clone()).filter(|p| !p.is_empty()), &[]);
        }
        rule.delete_markers.get_or_insert(true);
    }
    source.write(&config).await?;
    ui::done(
        format!("Changed replication rule {id} of {name}"),
        || json!({"type": "replicationRule", "bucket": name, "id": id, "changed": true}),
    );
    Ok(())
}

fn no_rule(name: &str, id: &str) -> Error {
    Error::usage(format!("{name} has no replication rule {id}"))
        .with_hint(format!("see its rules: teifs replicate ls {name}"))
}

/// A destination for people: `ALIAS/BUCKET` on the same server, the target's
/// `endpoint/bucket`, or the ARN.
fn shown_destination(arn: &str, source: &Remote, targets: &[ReplicationTarget]) -> String {
    if let Some(bucket) = arn.strip_prefix(LOCAL_ARN) {
        return format!("{}/{bucket}", source.alias_name);
    }
    targets.iter().find(|t| t.arn == arn).map_or_else(
        || arn.to_owned(),
        |t| {
            let scheme = if t.secure { "https" } else { "http" };
            format!("{scheme}://{}/{}", t.endpoint, t.bucket)
        },
    )
}

async fn ls(source: &Source) -> Result<(), Error> {
    let name = &source.name;
    let config = source.read().await?;
    let targets = if config.is_some() {
        source.targets().await?
    } else {
        Vec::new()
    };
    let mut table = ui::Table::new(&[
        "ID",
        "STATUS",
        ">PRIORITY",
        "APPLIES TO",
        "TO",
        "REPLICATES",
    ]);
    let mut records = Vec::new();
    for rule in config.iter().flat_map(|c| &c.rules) {
        let to = shown_destination(&rule.destination.bucket, &source.remote, &targets);
        let (prefix, tags) = conditions(&rule.filter);
        let tags: std::collections::BTreeMap<&str, &str> = tags.into_iter().collect();
        let applies = filters::words(prefix, &tags).unwrap_or_else(|| "everything".to_owned());
        let replicates = Replicates::of(rule).words();
        table.row(vec![
            rule.id.clone(),
            if rule.enabled { "on" } else { "off" }.to_owned(),
            rule.priority.map(|p| p.to_string()).unwrap_or_default(),
            applies,
            to.clone(),
            replicates,
        ]);
        records.push(json!({
            "type": "replicationRule",
            "bucket": name,
            "destination": to,
            "rule": rule,
        }));
    }
    ui::rows(
        &table,
        &records,
        &format!(
            "{name} has no replication rules. Add one: teifs replicate add {name} \
             --remote-bucket ALIAS/BUCKET"
        ),
    );
    Ok(())
}

async fn rm(source: &Source, id: Option<&str>, all: bool, force: bool) -> Result<(), Error> {
    let name = &source.name;
    let mut config = source.read_some().await?;
    let arns: Vec<String> = config
        .rules
        .iter()
        .map(|r| r.destination.bucket.clone())
        .collect();
    let removed = if all {
        let count = config.rules.len();
        let question = format!(
            "Remove all {count} replication rule{} of {name}?",
            plural(count)
        );
        if !force && !ui::confirm(&question, "add --force to remove them all")? {
            ui::note("Nothing was removed.");
            return Ok(());
        }
        config.rules.clear();
        count
    } else {
        let id = id.unwrap_or_default();
        let at = config
            .rules
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| no_rule(name, id))?;
        config.rules.remove(at);
        1
    };
    source.write(&config).await?;
    source.drop_unused(&config, &arns).await?;
    ui::done(
        format!(
            "Removed {removed} replication rule{} from {name}",
            plural(removed)
        ),
        || json!({"type": "replicationRules", "bucket": name, "removed": removed}),
    );
    Ok(())
}

async fn status(source: &Source) -> Result<(), Error> {
    let name = &source.name;
    let config = source.read_some().await?;
    let targets = source.targets().await?;
    let metrics = source
        .client
        .replication_metrics(source.bucket())
        .await
        .map_err(|e| Error::admin(format!("can't read the replication of {name}"), &e))?;
    let mut arns: Vec<&str> = config
        .rules
        .iter()
        .map(|r| r.destination.bucket.as_str())
        .collect();
    arns.dedup();
    let mut table = ui::Table::new(&["TO", ">REPLICATED", ">WAITING", ">FAILED", "REACHABLE"]);
    let mut records = Vec::new();
    for arn in arns {
        let counts = metrics.targets.get(arn).copied().unwrap_or_default();
        let to = shown_destination(arn, &source.remote, &targets);
        let online = targets.iter().find(|t| t.arn == arn).map(|t| t.online);
        let count = |n: u64, bytes: u64| format!("{n} ({})", units::size(bytes));
        table.row(vec![
            to.clone(),
            count(counts.replicated, counts.replicated_size),
            count(counts.pending, counts.pending_size),
            count(counts.failed, counts.failed_size),
            match online {
                Some(true) => "yes",
                Some(false) => "no",
                None => "same server",
            }
            .to_owned(),
        ]);
        records.push(json!({
            "type": "replicationStatus",
            "bucket": name,
            "destination": to,
            "arn": arn,
            "replicated": counts.replicated,
            "replicatedBytes": counts.replicated_size,
            "waiting": counts.pending,
            "waitingBytes": counts.pending_size,
            "failed": counts.failed,
            "failedBytes": counts.failed_size,
            "online": online,
        }));
    }
    ui::rows(
        &table,
        &records,
        &format!("{name} has no replication rules."),
    );
    if metrics.replica_count > 0 && !ui::json() {
        ui::note(format!(
            "{name} received {} replica{} ({}) from other buckets",
            metrics.replica_count,
            plural(usize::try_from(metrics.replica_count).unwrap_or(usize::MAX)),
            units::size(metrics.replica_size)
        ));
    }
    Ok(())
}

async fn check(source: &Source) -> Result<(), Error> {
    let name = &source.name;
    source
        .client
        .check_replication(source.bucket())
        .await
        .map_err(|e| Error::admin(format!("replication of {name} can't work"), &e))?;
    ui::done(
        format!(
            "Replication of {name} can work: every destination is there, keeps versions and \
             takes its writes"
        ),
        || json!({"type": "replicationCheck", "bucket": name, "ready": true}),
    );
    Ok(())
}

async fn resync(action: ResyncAction, aliases: &Aliases) -> Result<(), Error> {
    match action {
        ResyncAction::Start {
            bucket,
            remote_bucket,
            older_than,
        } => {
            let source = Source::new(&bucket, aliases)?;
            let name = &source.name;
            let arn = source.arn_of(remote_bucket.as_deref(), aliases).await?;
            let started = source
                .client
                .start_resync(source.bucket(), arn.as_deref(), older_than)
                .await
                .map_err(|e| Error::admin(format!("can't start a resync of {name}"), &e))?;
            let targets = source.targets().await?;
            for resync in started {
                let to = shown_destination(&resync.arn, &source.remote, &targets);
                ui::done(
                    format!("Resync of {name} to {to} started ({})", resync.id),
                    || json!({"type": "replicationResync", "bucket": name, "destination": to, "arn": resync.arn, "id": resync.id}),
                );
            }
        }
        ResyncAction::Status {
            bucket,
            remote_bucket,
        } => {
            let source = Source::new(&bucket, aliases)?;
            let name = &source.name;
            let arn = source.arn_of(remote_bucket.as_deref(), aliases).await?;
            let resyncs = source
                .client
                .resyncs(source.bucket(), arn.as_deref())
                .await
                .map_err(|e| Error::admin(format!("can't read the resyncs of {name}"), &e))?;
            let targets = source.targets().await?;
            let mut table = ui::Table::new(&["TO", "ID", "STATUS", ">SENT", ">FAILED"]);
            let mut records = Vec::new();
            for resync in resyncs {
                let to = shown_destination(&resync.arn, &source.remote, &targets);
                table.row(vec![
                    to.clone(),
                    resync.id.clone(),
                    resync.resync_status.clone(),
                    format!(
                        "{} ({})",
                        resync.replicated,
                        units::size(resync.replicated_size)
                    ),
                    resync.failed.to_string(),
                ]);
                records.push(json!({
                    "type": "replicationResync",
                    "bucket": name,
                    "destination": to,
                    "arn": resync.arn,
                    "id": resync.id,
                    "status": resync.resync_status,
                    "sent": resync.replicated,
                    "sentBytes": resync.replicated_size,
                    "failed": resync.failed,
                }));
            }
            ui::rows(&table, &records, &format!("{name} has had no resyncs."));
        }
        ResyncAction::Cancel {
            bucket,
            remote_bucket,
        } => {
            let source = Source::new(&bucket, aliases)?;
            let name = &source.name;
            let arn = source.arn_of(remote_bucket.as_deref(), aliases).await?;
            let id = source
                .client
                .cancel_resync(source.bucket(), arn.as_deref())
                .await
                .map_err(|e| Error::admin(format!("can't cancel the resync of {name}"), &e))?;
            ui::done(
                format!("Canceled the resync of {name} ({id})"),
                || json!({"type": "replicationResync", "bucket": name, "id": id, "canceled": true}),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    #[test]
    fn replicate_takes_mcs_words() {
        let all = Replicates::parse(EVERYTHING).unwrap();
        assert!(all.delete_markers && all.deletes && all.existing && all.metadata);
        assert_eq!(all.words(), EVERYTHING);
        assert_eq!(Replicates::parse("none").unwrap(), Replicates::default());
        assert_eq!(Replicates::parse("none").unwrap().words(), "new versions");
        let some = Replicates::parse("delete, existing-objects").unwrap();
        assert!(!some.delete_markers && some.deletes && some.existing && !some.metadata);
        assert!(Replicates::parse("everything").is_err());
        let mut rule = rule_with(ReplicationFilter::All);
        some.apply(&mut rule);
        assert_eq!(Replicates::of(&rule), some);
    }

    fn rule_with(filter: ReplicationFilter) -> ReplicationRule {
        ReplicationRule {
            id: "r".to_owned(),
            priority: Some(1),
            enabled: true,
            filter,
            delete_markers: None,
            delete_replication: None,
            existing_objects: None,
            sse_kms_objects: None,
            replica_modifications: None,
            destination: ReplicationDestination {
                bucket: format!("{LOCAL_ARN}b"),
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
    fn filters_are_the_smallest_s3_takes() {
        let tag = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        assert_eq!(filter(None, &[]), ReplicationFilter::All);
        assert_eq!(
            filter(Some("a/".to_owned()), &[]),
            ReplicationFilter::Prefix("a/".to_owned())
        );
        let one = filter(None, &[tag("k", "v")]);
        assert!(matches!(&one, ReplicationFilter::Tag(t) if t.key == "k" && t.value == "v"));
        let both = filter(Some("a/".to_owned()), &[tag("k", "v")]);
        assert!(
            matches!(&both, ReplicationFilter::And { prefix: Some(p), tags } if p == "a/" && tags.len() == 1)
        );
        assert_eq!(conditions(&both), (Some("a/"), vec![("k", "v")]));
        assert_eq!(
            conditions(&ReplicationFilter::V1Prefix(String::new())),
            (None, vec![])
        );
    }
}
