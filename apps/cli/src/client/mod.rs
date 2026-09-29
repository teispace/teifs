//! `teifs` as an S3 client, for TeiFS or any S3 service: aliases, and commands on
//! `ALIAS/BUCKET/KEY` paths and local files (`ls`, `cp`, `mirror`, …).

pub(crate) mod alias;
mod commands;
mod copy;
mod listing;
mod target;
mod transfer;

use std::{path::PathBuf, time::Duration};

use clap::{Args, Subcommand};

pub use crate::error::{Error, Kind};

use crate::{LayoutArg, units::parse_duration};

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
        /// With `--recursive`, delete without asking (as `--yes` does).
        #[arg(long)]
        force: bool,
    },
    /// Print objects to standard output.
    Cat {
        /// `ALIAS/BUCKET/KEY`, one or more.
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Show an object's or a bucket's details.
    Stat {
        /// `ALIAS/BUCKET[/KEY]`.
        target: String,
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
