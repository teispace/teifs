//! Versions: `ls --versions`, `rm --version-id` and `rm --versions`, and
//! `teifs version enable|suspend|info`.

use aws_sdk_s3::{
    Client,
    types::{BucketVersioningStatus, VersioningConfiguration},
};
use serde_json::json;

use super::{
    Error, Kind, VersionAction,
    alias::Aliases,
    commands::{delete_keys, plural},
    listing::{self, Version},
    target::{Remote, Target},
};
use crate::{
    ui,
    units::{date, rfc3339, size},
};

/// Width of the version column: TeiFS's and AWS's ids are 32 characters.
const VERSION_WIDTH: usize = 32;

/// Lists every version and delete marker under `prefix`, with the common prefixes at
/// `delimiter` as folders; names are shown from `shown_from`. Whether there was any.
pub(super) async fn ls(
    client: &Client,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    shown_from: usize,
    name: &str,
) -> Result<bool, Error> {
    let (versions, prefixes) = listing::versions(client, bucket, prefix, delimiter, name).await?;
    // Folders and versions in key order; a sort that keeps each key's versions in order.
    let mut rows: Vec<(&str, Option<&Version>)> = prefixes
        .iter()
        .map(|p| (p.as_str(), None))
        .chain(versions.iter().map(|v| (v.key.as_str(), Some(v))))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));
    for (key, version) in &rows {
        let shown = &key[shown_from.min(key.len())..];
        match version {
            None => ui::item(
                || {
                    let dir = ui::dim(format!("{:>10}", "DIR"));
                    format!(
                        "{:19}  {dir}  {:VERSION_WIDTH$}  {}",
                        "",
                        "",
                        ui::folder(shown)
                    )
                },
                || json!({"type": "folder", "key": key}),
            ),
            Some(v) => ui::item(|| version_line(v, shown), || version_record(v)),
        }
    }
    Ok(!rows.is_empty())
}

/// One version in `ls --versions`: when, how big (or that it's a delete marker), its
/// id, its name, and whether it's the current one.
fn version_line(v: &Version, shown: &str) -> String {
    let modified = v.modified.map_or_else(|| " ".repeat(19), date);
    let size = if v.delete_marker {
        format!("{:>10}", "deleted")
    } else {
        format!("{:>10}", size(v.size))
    };
    let current = if v.latest {
        format!("  {}", ui::dim("(current)"))
    } else {
        String::new()
    };
    format!(
        "{}  {}  {:VERSION_WIDTH$}  {shown}{current}",
        ui::dim(modified),
        ui::dim(size),
        v.id
    )
}

fn version_record(v: &Version) -> serde_json::Value {
    json!({
        "type": if v.delete_marker { "deleteMarker" } else { "version" },
        "key": v.key,
        "versionId": v.id,
        "latest": v.latest,
        "size": v.size,
        "modified": v.modified.map(rfc3339),
        "etag": v.etag,
    })
}

/// Removes one version of a key for good.
pub(super) async fn rm_version(remote: Remote, version_id: &str) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display(&remote.key);
    if remote.key.is_empty() {
        return Err(Error::usage(format!(
            "give the key whose version to remove, like {name}/KEY"
        )));
    }
    let client = remote.alias.client();
    // S3 removes a version that isn't there without a word: say so instead. A delete
    // marker can't be read (`405`), but it's there.
    let found = client
        .head_object()
        .bucket(bucket)
        .key(&remote.key)
        .version_id(version_id)
        .send()
        .await;
    if let Err(e) = found {
        let err = Error::s3(format!("can't find version {version_id} of {name}"), &e);
        if err.is_not_found() {
            return Err(err);
        }
    }
    client
        .delete_object()
        .bucket(bucket)
        .key(&remote.key)
        .version_id(version_id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't remove version {version_id} of {name}"), &e))?;
    ui::done(
        format!("Removed version {version_id} of {name}"),
        || json!({"type": "remove", "key": name, "versionId": version_id, "count": 1}),
    );
    Ok(())
}

/// Removes every version and delete marker of a key (with `recursive`, of every key
/// under it) for good, after asking unless `force`.
pub(super) async fn rm_versions(remote: Remote, recursive: bool, force: bool) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display(&remote.key);
    if remote.key.is_empty() && !recursive {
        return Err(Error::usage(format!(
            "give a key whose versions to remove, like {name}/KEY (or add -r for every key)"
        )));
    }
    let client = remote.alias.client();
    let (versions, _) = listing::versions(&client, bucket, &remote.key, None, &name).await?;
    // The key itself, and with -r what's "in" it (`photos` and `photos/…`, not `photos2`).
    let key = &remote.key;
    let versions: Vec<Version> = versions
        .into_iter()
        .filter(|v| {
            v.key == *key
                || recursive
                    && (key.is_empty() || key.ends_with('/') || v.key[key.len()..].starts_with('/'))
        })
        .collect();
    if versions.is_empty() {
        return Err(Error::new(Kind::NotFound, format!("no versions at {name}")));
    }
    let count = versions.len();
    let mut keys: Vec<&str> = versions.iter().map(|v| v.key.as_str()).collect();
    keys.dedup();
    let question = format!(
        "Remove {count} version{} of {} key{} at {name} for good?",
        plural(count),
        keys.len(),
        plural(keys.len())
    );
    if !force && !ui::confirm(&question, "add --force to remove without asking")? {
        ui::note("Nothing was removed.");
        return Ok(());
    }
    let pairs = versions.into_iter().map(|v| (v.key, Some(v.id))).collect();
    delete_keys(&client, bucket, &name, pairs).await?;
    ui::done(
        format!("Removed {count} version{} at {name}", plural(count)),
        || json!({"type": "remove", "prefix": name, "versions": count}),
    );
    Ok(())
}

/// A bucket's versioning, as a word: `enabled`, `suspended`, or `off` (never turned on).
pub(super) async fn status(client: &Client, bucket: &str) -> Result<&'static str, Error> {
    let out = client
        .get_bucket_versioning()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read the versioning of {bucket}"), &e))?;
    Ok(match out.status() {
        Some(BucketVersioningStatus::Enabled) => "enabled",
        Some(BucketVersioningStatus::Suspended) => "suspended",
        _ => "off",
    })
}

/// `teifs version enable|suspend|info ALIAS/BUCKET`.
pub(super) async fn versioning(action: VersionAction, aliases: &Aliases) -> Result<(), Error> {
    let (target, change) = match action {
        VersionAction::Enable { target } => (target, Some(BucketVersioningStatus::Enabled)),
        VersionAction::Suspend { target } => (target, Some(BucketVersioningStatus::Suspended)),
        VersionAction::Info { target } => (target, None),
    };
    let remote = Target::parse(&target, aliases)?.remote("version")?;
    let bucket = remote.bucket()?;
    if !remote.key.is_empty() {
        return Err(Error::usage(format!(
            "versioning is a bucket's: give ALIAS/BUCKET, not {}",
            remote.display(&remote.key)
        )));
    }
    let name = remote.display("");
    let client = remote.alias.client();
    let Some(change) = change else {
        let versioning = status(&client, bucket).await?;
        ui::details(
            &[
                ("Bucket", name.clone()),
                ("Versioning", versioning.to_owned()),
            ],
            || json!({"type": "versioning", "bucket": name, "status": versioning}),
        );
        return Ok(());
    };
    let config = VersioningConfiguration::builder()
        .status(change.clone())
        .build();
    client
        .put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(config)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't change the versioning of {name}"), &e))?;
    let (message, word) = match change {
        BucketVersioningStatus::Enabled => (
            format!("Versioning is on for {name}: every write keeps the version it replaces"),
            "enabled",
        ),
        _ => (
            format!("Versioning is suspended for {name}: the versions kept so far stay"),
            "suspended",
        ),
    };
    ui::done(
        message,
        || json!({"type": "versioning", "bucket": name, "status": word}),
    );
    Ok(())
}
