//! `teifs admin bucket export|import`: buckets and their settings moved between
//! servers, as `mc admin cluster bucket export|import` moves them between `MinIO` servers.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde_json::json;
use teifs_client::{BucketsExport, BucketsImportReport};

use super::{client, read_file, record, write_file};
use crate::{
    client::alias::Aliases,
    error::{Error, Kind},
    plural, ui,
};

#[derive(Subcommand)]
pub enum BucketAction {
    /// Write every bucket's layout, versioning and settings (policy, lifecycle, Object
    /// Lock, encryption, CORS, tags, ACL, Block Public Access…) as JSON.
    Export {
        /// The server's alias, or ALIAS/BUCKET for one bucket.
        target: String,
        /// The file to write (owner-only); standard output without it.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Replace the file if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Create an export's buckets where they're missing and apply their settings,
    /// each checked as S3 checks it. Exit code 1 when an item couldn't be applied.
    Import {
        /// The server's alias.
        alias: String,
        /// The export: a file, or `-` for standard input.
        file: PathBuf,
    },
}

pub async fn run(aliases: &Aliases, action: BucketAction) -> Result<(), Error> {
    match action {
        BucketAction::Export {
            target,
            output,
            force,
        } => {
            let (alias, bucket) = match target.split_once('/') {
                Some((alias, "")) => (alias, None),
                Some((alias, bucket)) => (alias, Some(bucket)),
                None => (target.as_str(), None),
            };
            export(aliases, alias, bucket, output.as_deref(), force).await
        }
        BucketAction::Import { alias, file } => import(aliases, &alias, &file).await,
    }
}

async fn export(
    aliases: &Aliases,
    alias: &str,
    bucket: Option<&str>,
    output: Option<&Path>,
    force: bool,
) -> Result<(), Error> {
    if let Some(bucket) = bucket {
        teifs_types::check_bucket(bucket).map_err(|e| Error::usage(e.to_string()))?;
    }
    let export = client(aliases, alias)?
        .export_buckets(bucket)
        .await
        .map_err(|e| Error::admin("can't export buckets", &e))?;
    let Some(path) = output else {
        let text = if ui::json() {
            serde_json::to_string(&export)
        } else {
            serde_json::to_string_pretty(&export)
        };
        ui::raw(&text.map_err(|e| Error::general(e.to_string()))?);
        return Ok(());
    };
    let text = serde_json::to_vec_pretty(&export).map_err(|e| Error::general(e.to_string()))?;
    write_file(path, &text, force)?;
    let count = export.buckets.len() as u64;
    ui::done(
        format!(
            "Exported {count} bucket{} to {}",
            plural(count),
            path.display()
        ),
        || json!({"type": "bucketExport", "path": path, "buckets": count}),
    );
    Ok(())
}

async fn import(aliases: &Aliases, alias: &str, file: &Path) -> Result<(), Error> {
    let bytes = read_file(file)?;
    let export: BucketsExport = serde_json::from_slice(&bytes).map_err(|e| {
        Error::usage(format!("{} isn't a bucket export: {e}", file.display()))
            .with_hint("make one with `teifs admin bucket export`")
    })?;
    let report = client(aliases, alias)?
        .import_buckets(&export)
        .await
        .map_err(|e| Error::admin("can't import buckets", &e))?;
    for item in &report.items {
        if ui::json() {
            ui::emit(&record("bucketImport", item));
        } else if let Some(error) = &item.error {
            ui::warn(format!("{}: {}: {error}", item.bucket, item.item));
        }
    }
    let (created, applied, failed) = counts(&report);
    ui::done(
        format!(
            "Imported {} bucket{}: {created} created, {applied} setting{} applied, {failed} \
             failed",
            export.buckets.len(),
            plural(export.buckets.len() as u64),
            plural(applied),
        ),
        || {
            json!({
                "type": "bucketsImported",
                "created": created,
                "applied": applied,
                "failed": failed,
            })
        },
    );
    if failed > 0 {
        return Err(Error::new(
            Kind::General,
            format!("{failed} item{} couldn't be imported", plural(failed)),
        )
        .with_hint("each is named above, with why"));
    }
    Ok(())
}

/// Buckets created, items applied and items failed.
fn counts(report: &BucketsImportReport) -> (u64, u64, u64) {
    let count = |outcome: &str| {
        report
            .items
            .iter()
            .filter(|item| item.outcome == outcome)
            .count() as u64
    };
    (count("created"), count("applied"), count("failed"))
}
