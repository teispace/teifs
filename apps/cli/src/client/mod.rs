//! `teifs` as an S3 client, for TeiFS or any S3 service: aliases, and commands on
//! `ALIAS/BUCKET/KEY` paths and local files (`ls`, `cp`, `mirror`, …).

pub(crate) mod alias;
mod commands;
mod copy;
mod ilm;
mod listing;
mod lock;
mod target;
mod transfer;
pub(crate) mod trust;
mod versions;

use std::{path::PathBuf, time::Duration};

use clap::{Args, Subcommand};

pub use crate::error::{Error, Kind};

use crate::{
    LayoutArg,
    units::{parse_day, parse_duration, parse_size},
};

/// The client's commands, at the top level of `teifs`.
#[derive(Subcommand)]
pub enum Command {
    /// Name an S3 endpoint and its keys, to use as `NAME/BUCKET/KEY`.
    Alias {
        #[command(subcommand)]
        action: AliasAction,
    },
    /// List buckets (`ALIAS`) or objects (`ALIAS/BUCKET[/PREFIX]`).
    Ls {
        /// What to list.
        target: String,
        /// Everything under the prefix, not just one level.
        #[arg(short, long)]
        recursive: bool,
        /// Every version and delete marker too, each key's newest first.
        #[arg(long)]
        versions: bool,
    },
    /// Make a bucket.
    Mb {
        /// `ALIAS/BUCKET`.
        target: String,
        /// On TeiFS, how it stores objects: `object` (any key S3 allows) or `folder`
        /// (plain files). Other servers ignore it.
        #[arg(long, value_enum)]
        layout: Option<LayoutArg>,
        /// Succeed if the bucket is already there and yours.
        #[arg(long)]
        ignore_existing: bool,
        /// With Object Lock, so objects can be kept from deletion for a time or until
        /// released (this turns versioning on for good).
        #[arg(long)]
        with_lock: bool,
    },
    /// Remove a bucket.
    Rb {
        /// `ALIAS/BUCKET`.
        target: String,
        /// Delete every object in it first.
        #[arg(long)]
        force: bool,
    },
    /// Copy files and objects: local to S3, S3 to local, or S3 to S3.
    ///
    /// A destination ending in `/` (or a bucket, or a local folder) takes each source's
    /// name. With `-r`, a folder's contents go under the destination, as `aws s3 cp
    /// --recursive` does. Large files go in parallel parts, and an interrupted upload
    /// resumes when the same copy runs again.
    Cp(CopyArgs),
    /// Move files and objects: copy, then delete each source once it's copied.
    Mv(CopyArgs),
    /// Delete objects.
    Rm {
        /// `ALIAS/BUCKET/KEY`, one or more.
        #[arg(required = true)]
        targets: Vec<String>,
        /// Everything under each key prefix.
        #[arg(short, long)]
        recursive: bool,
        /// With `--recursive` or `--versions`, delete without asking (as `--yes` does).
        #[arg(long)]
        force: bool,
        /// Remove this version of the key for good, instead of deleting the key (which,
        /// in a bucket with versioning, only adds a delete marker).
        #[arg(long, conflicts_with_all = ["recursive", "versions"])]
        version_id: Option<String>,
        /// Remove every version and delete marker of the key for good (with
        /// `--recursive`, of every key under it). Asks first, unless `--force`.
        #[arg(long)]
        versions: bool,
        /// With `--version-id` or `--versions`: remove versions that a governance-mode
        /// retention keeps (needs `s3:BypassGovernanceRetention`).
        #[arg(long)]
        bypass: bool,
    },
    /// Print objects to standard output.
    Cat {
        /// `ALIAS/BUCKET/KEY`, one or more.
        #[arg(required = true)]
        targets: Vec<String>,
        /// Print this version of the object instead of the current one.
        #[arg(long)]
        version_id: Option<String>,
    },
    /// Show an object's or a bucket's details.
    Stat {
        /// `ALIAS/BUCKET[/KEY]`.
        target: String,
        /// Show this version of the object instead of the current one.
        #[arg(long)]
        version_id: Option<String>,
    },
    /// Turn a bucket's versioning on, suspend it, or show it.
    Version {
        #[command(subcommand)]
        action: VersionAction,
    },
    /// Keep objects from deletion until a date (Object Lock retention), or set a
    /// bucket's default retention.
    Retention {
        #[command(subcommand)]
        action: RetentionAction,
    },
    /// Keep objects from deletion until released (an Object Lock legal hold).
    Legalhold {
        #[command(subcommand)]
        action: LegalHoldAction,
    },
    /// Expire objects and old versions, and abort old uploads, by a bucket's lifecycle
    /// rules.
    Ilm {
        #[command(subcommand)]
        action: IlmAction,
    },
    /// Make a link that gets (or, with `--put`, uploads) an object without keys.
    Presign {
        /// `ALIAS/BUCKET/KEY`.
        target: String,
        /// How long the link works: up to 7d.
        #[arg(long, default_value = "1h", value_parser = parse_duration)]
        expires: Duration,
        /// A link for uploading the object instead.
        #[arg(long)]
        put: bool,
        /// The most the upload may be (with `--put`): bytes, or with KiB, MiB or GiB.
        /// The limit is part of the link's signature, so it can't be raised or removed.
        #[arg(long, requires = "put", value_parser = crate::units::parse_size)]
        max_size: Option<u64>,
    },
    /// Make a folder or a key prefix the same as another: copy what's new or changed,
    /// and (with `--remove`) delete what's gone.
    Mirror {
        /// A local folder or `ALIAS/BUCKET[/PREFIX]`.
        source: String,
        /// A local folder or `ALIAS/BUCKET[/PREFIX]`.
        destination: String,
        /// Delete what's in the destination but not the source.
        #[arg(long)]
        remove: bool,
        /// Show what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        transfer: TransferArgs,
    },
}

#[derive(Subcommand)]
pub enum VersionAction {
    /// Keep every version: writes add one, deletes add a delete marker.
    Enable {
        /// `ALIAS/BUCKET`.
        target: String,
    },
    /// Stop adding versions: writes and deletes replace the `null` version, and the
    /// versions kept so far stay. Versioning never goes back to off.
    Suspend {
        /// `ALIAS/BUCKET`.
        target: String,
    },
    /// Show whether versioning is on, suspended, or was never turned on.
    Info {
        /// `ALIAS/BUCKET`.
        target: String,
    },
}

#[derive(Subcommand)]
pub enum RetentionAction {
    /// Keep objects for a time: governance (only those allowed to bypass it may remove
    /// them early) or compliance (nobody may). With `--default`, what new objects in the
    /// bucket get.
    Set {
        /// `governance` or `compliance`.
        #[arg(value_enum)]
        mode: LockModeArg,
        /// For how long, from now: days or years, like `30d` or `1y`.
        #[arg(value_parser = lock::parse_validity)]
        validity: teifs_store::RetentionPeriod,
        #[command(flatten)]
        lock: RetentionArgs,
    },
    /// Remove objects' retention (a governance one needs `--bypass`; a compliance one
    /// can't be removed), or with `--default`, the bucket's default.
    Clear {
        #[command(flatten)]
        lock: RetentionArgs,
    },
    /// Show an object's retention, or with `--default`, the bucket's Object Lock.
    Info {
        /// `ALIAS/BUCKET/KEY` (`ALIAS/BUCKET` with `--default`).
        target: String,
        /// The bucket's default retention instead.
        #[arg(long)]
        default: bool,
        /// A version of the object instead of the current one.
        #[arg(long, conflicts_with = "default")]
        version_id: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum LegalHoldAction {
    /// Place a legal hold: nobody may remove the object until it's lifted.
    Set {
        #[command(flatten)]
        objects: HoldArgs,
    },
    /// Lift a legal hold.
    Clear {
        #[command(flatten)]
        objects: HoldArgs,
    },
    /// Show whether an object is under a legal hold.
    Info {
        /// `ALIAS/BUCKET/KEY`.
        target: String,
        /// A version of the object instead of the current one.
        #[arg(long)]
        version_id: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum IlmAction {
    /// Add, change, list, remove, export or import a bucket's lifecycle rules.
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },
}

#[derive(Subcommand)]
pub enum RuleAction {
    /// Add a rule.
    Add {
        /// `ALIAS/BUCKET`.
        target: String,
        /// The rule's name (made up when not given).
        #[arg(long)]
        id: Option<String>,
        #[command(flatten)]
        rule: RuleArgs,
        /// Add it turned off.
        #[arg(long)]
        disable: bool,
    },
    /// Change a rule: what's given replaces what it had, the rest stays.
    Edit {
        /// `ALIAS/BUCKET`.
        target: String,
        /// The rule to change.
        #[arg(long)]
        id: String,
        #[command(flatten)]
        rule: RuleArgs,
        /// Turn it on.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Turn it off.
        #[arg(long)]
        disable: bool,
    },
    /// List a bucket's rules.
    Ls {
        /// `ALIAS/BUCKET`.
        target: String,
    },
    /// Remove a rule, or all of them.
    Rm {
        /// `ALIAS/BUCKET`.
        target: String,
        /// The rule to remove.
        #[arg(long, required_unless_present = "all", conflicts_with = "all")]
        id: Option<String>,
        /// Every rule of the bucket.
        #[arg(long)]
        all: bool,
        /// Remove them all without asking.
        #[arg(long, requires = "all")]
        force: bool,
    },
    /// Print a bucket's rules as JSON, as AWS gives them.
    Export {
        /// `ALIAS/BUCKET`.
        target: String,
    },
    /// Replace a bucket's rules with JSON read from standard input (as `export`
    /// prints it).
    Import {
        /// `ALIAS/BUCKET`.
        target: String,
    },
}

/// What a lifecycle rule applies to and does.
#[derive(Args, Default)]
pub struct RuleArgs {
    /// Only keys starting with this.
    #[arg(long)]
    prefix: Option<String>,
    /// Only objects with these tags: `key=value&key2=value2`.
    #[arg(long)]
    tags: Option<String>,
    /// Only objects larger than this (bytes, or with KiB, MiB or GiB).
    #[arg(long, value_parser = parse_size)]
    size_gt: Option<u64>,
    /// Only objects smaller than this.
    #[arg(long, value_parser = parse_size)]
    size_lt: Option<u64>,
    /// Expire objects this many days after they're written.
    #[arg(long, value_parser = days(), conflicts_with_all = ["expire_date", "expire_delete_marker"])]
    expire_days: Option<i32>,
    /// Expire objects from this day on (`YYYY-MM-DD`, UTC).
    #[arg(long, value_parser = parse_day, conflicts_with = "expire_delete_marker")]
    expire_date: Option<i64>,
    /// Remove delete markers left with no versions behind them.
    #[arg(long)]
    expire_delete_marker: bool,
    /// Remove versions this many days after they stop being current.
    #[arg(long, value_parser = days())]
    noncurrent_expire_days: Option<i32>,
    /// Keep this many of the newest noncurrent versions of each object (1 to 100).
    #[arg(long, value_parser = clap::value_parser!(i32).range(1..=100))]
    noncurrent_expire_newer: Option<i32>,
    /// Abort uploads this many days after they start.
    #[arg(long, value_parser = days())]
    abort_uploads_days: Option<i32>,
    /// Move objects to `--transition-tier` this many days after they're written.
    #[arg(long, value_parser = clap::value_parser!(i32).range(0..), conflicts_with = "transition_date")]
    transition_days: Option<i32>,
    /// Move objects to `--transition-tier` from this day on.
    #[arg(long, value_parser = parse_day)]
    transition_date: Option<i64>,
    /// The storage class objects move to.
    #[arg(long)]
    transition_tier: Option<String>,
    /// Move versions to `--noncurrent-transition-tier` this many days after they stop
    /// being current.
    #[arg(long, value_parser = days())]
    noncurrent_transition_days: Option<i32>,
    /// Leave this many of the newest noncurrent versions where they are.
    #[arg(long, value_parser = clap::value_parser!(i32).range(1..=100))]
    noncurrent_transition_newer: Option<i32>,
    /// The storage class noncurrent versions move to.
    #[arg(long)]
    noncurrent_transition_tier: Option<String>,
}

/// A number of days: 1 or more.
fn days() -> clap::builder::RangedI64ValueParser<i32> {
    clap::value_parser!(i32).range(1..)
}

/// An Object Lock retention mode.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum LockModeArg {
    Governance,
    Compliance,
}

/// The objects a lock command changes.
#[derive(Args)]
pub struct HoldArgs {
    /// `ALIAS/BUCKET/KEY` (with `-r`, a prefix).
    target: String,
    /// A version of the object instead of the current one.
    #[arg(long, conflicts_with = "recursive")]
    version_id: Option<String>,
    /// Every object under the prefix (their current versions).
    #[arg(short, long)]
    recursive: bool,
}

/// `retention set` and `clear`.
#[derive(Args)]
pub struct RetentionArgs {
    #[command(flatten)]
    objects: HoldArgs,
    /// The bucket's default retention instead (give `ALIAS/BUCKET`).
    #[arg(long, conflicts_with_all = ["version_id", "recursive", "bypass"])]
    default: bool,
    /// Shorten or remove a governance-mode retention, or make it compliance (needs
    /// `s3:BypassGovernanceRetention`).
    #[arg(long)]
    bypass: bool,
}

#[derive(Subcommand)]
pub enum AliasAction {
    /// Add or replace an alias. The secret key is asked for (hidden) on a terminal, or
    /// read from standard input (`--secret-key-stdin`) or `TEIFS_SECRET_KEY`; never
    /// from the command line.
    Set(SetAlias),
    /// List aliases (never their secret keys).
    Ls,
    /// Remove an alias.
    Rm { name: String },
}

/// `alias set`'s arguments.
#[derive(Args)]
pub struct SetAlias {
    /// A short name: lowercase letters, digits, `-` and `_`.
    name: String,
    /// The endpoint, like `http://127.0.0.1:9000` or `https://s3.example.com`.
    url: String,
    /// The access key (or `TEIFS_ACCESS_KEY`; asked for on a terminal).
    #[arg(long, env = "TEIFS_ACCESS_KEY")]
    access_key: Option<String>,
    /// Read the secret key from the first line of standard input.
    #[arg(long)]
    secret_key_stdin: bool,
    /// Use the keys of the TeiFS drive in this folder (from `.teifs/credentials.json`),
    /// whatever else sets keys.
    #[arg(long)]
    drive: Option<PathBuf>,
    /// The region to sign for.
    #[arg(long, default_value = alias::DEFAULT_REGION)]
    region: String,
    /// Address buckets as host names (`bucket.host`), as AWS prefers, instead of
    /// as the first part of the path.
    #[arg(long)]
    virtual_hosted: bool,
    /// Trust this certificate authority (PEM) for the server besides the system's: for
    /// a certificate a private CA signed, or a self-signed one.
    #[arg(long, value_name = "FILE")]
    ca_cert: Option<PathBuf>,
    /// Save it without checking that the endpoint and keys work.
    #[arg(long)]
    no_check: bool,
}

/// `cp` and `mv`.
#[derive(Args)]
pub struct CopyArgs {
    /// What to copy, then where to (the last one). `-` is standard input (`tar c dir |
    /// teifs cp - home/b/dir.tar`) or output (`teifs cp home/b/dir.tar - | tar x`).
    #[arg(required = true, num_args = 2..)]
    paths: Vec<String>,
    /// Copy folders and key prefixes with everything in them.
    #[arg(short, long)]
    recursive: bool,
    /// Copy this version of the source (one object) instead of its current one.
    #[arg(long, conflicts_with = "recursive")]
    version_id: Option<String>,
    #[command(flatten)]
    transfer: TransferArgs,
}

/// How transfers run.
#[derive(Args, Clone, Copy)]
pub struct TransferArgs {
    /// Requests at once, across files and their parts.
    #[arg(long, default_value = "8", value_parser = crate::units::parse_count)]
    parallel: usize,
    /// Files larger than this go in parts of this size (at least 5 MiB; larger when a
    /// file needs more than 10,000 parts). A size in bytes or with KiB, MiB or GiB.
    #[arg(long, default_value = "8MiB", value_parser = transfer::parse_part_size)]
    part_size: u64,
}

/// Runs a client command.
pub async fn run(command: Command) -> Result<(), Error> {
    commands::run(command).await
}
