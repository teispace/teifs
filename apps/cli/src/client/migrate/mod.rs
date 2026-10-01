//! `teifs migrate SOURCE DESTINATION`: buckets moved from any S3 service to another
//! (MinIO, AWS, RustFS or TeiFS to TeiFS, say) with everything S3 lets a client carry:
//! each version and delete marker in order, the objects' headers, metadata, tags,
//! retention and legal holds, the same ETags, and the buckets' settings.
//!
//! The source and destination are listed side by side, key by key, a page at a time,
//! and only what the destination lacks is copied: a migration that stopped carries on
//! when it's run again, and a later run copies only what's new. A key whose versions at
//! the destination aren't the source's first ones is a conflict: it's reported and left
//! alone.

mod buckets;
mod exact;
mod keys;

use std::time::{Instant, SystemTime};

use aws_sdk_s3::{Client, primitives::DateTime};
use futures::{StreamExt, stream};
use serde_json::json;

use self::{
    exact::{Source, same_etag},
    keys::{Group, Item, Keys},
};
use super::{
    Error, Kind, TransferArgs,
    alias::Aliases,
    attributes::Attributes,
    commands::plural,
    target::{Remote, Target},
    transfer::{Object, Transfers},
};
use crate::{
    ui,
    units::{rate, size},
};

/// `teifs migrate`'s arguments.
#[derive(clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is an independent command-line flag"
)]
pub struct MigrateArgs {
    /// `ALIAS` (every bucket) or `ALIAS/BUCKET[/PREFIX]`.
    source: String,
    /// `ALIAS` (the same bucket names) or `ALIAS/BUCKET[/PREFIX]`.
    destination: String,
    /// Copy only the current objects, not every version.
    #[arg(long)]
    latest: bool,
    /// Show what would be copied, and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Tell objects apart by size alone, not by ETag as well (for services whose ETags
    /// aren't MD5s, such as for objects encrypted with KMS keys).
    #[arg(long)]
    size_only: bool,
    /// Don't copy the buckets' settings (versioning, policy, lifecycle…).
    #[arg(long)]
    no_configs: bool,
    #[command(flatten)]
    transfer: TransferArgs,
    /// How many keys a listing page asks for (the tests' small pages).
    #[arg(long, hide = true)]
    page_size: Option<i32>,
}

/// A source bucket (or prefix in it) and where it goes.
pub struct Pair {
    from_client: Client,
    to_client: Client,
    from_alias: String,
    to_alias: String,
    from_bucket: String,
    to_bucket: String,
    from_prefix: String,
    to_prefix: String,
    to_region: String,
    from_endpoint: (String, String),
    to_endpoint: (String, String),
}

impl Pair {
    fn source_name(&self) -> String {
        name(&self.from_alias, &self.from_bucket, "")
    }

    fn destination_name(&self) -> String {
        name(&self.to_alias, &self.to_bucket, "")
    }

    fn object(&self, source: bool, relative: &str, version_id: Option<String>) -> Object {
        let (client, alias, bucket, prefix, endpoint) = if source {
            let p = self;
            (
                &p.from_client,
                &p.from_alias,
                &p.from_bucket,
                &p.from_prefix,
                &p.from_endpoint,
            )
        } else {
            let p = self;
            (
                &p.to_client,
                &p.to_alias,
                &p.to_bucket,
                &p.to_prefix,
                &p.to_endpoint,
            )
        };
        let key = format!("{prefix}{relative}");
        Object {
            client: client.clone(),
            bucket: bucket.clone(),
            name: name(alias, bucket, &key),
            key,
            endpoint: endpoint.clone(),
            version_id,
            sse: None,
        }
    }
}

fn name(alias: &str, bucket: &str, key: &str) -> String {
    if key.is_empty() {
        format!("{alias}/{bucket}")
    } else {
        format!("{alias}/{bucket}/{key}")
    }
}

/// What a migration did.
#[derive(Default)]
struct Tally {
    versions: usize,
    markers: usize,
    bytes: u64,
    /// Versions and markers already at the destination.
    present: usize,
    conflicts: usize,
    failed: Vec<Error>,
}

impl Tally {
    fn fail(&mut self, err: Error) {
        ui::error(&err);
        self.failed.push(err);
    }
}

pub async fn migrate(options: MigrateArgs, aliases: &Aliases) -> Result<(), Error> {
    let source = Target::parse(&options.source, aliases)?.remote("migrate")?;
    let destination = Target::parse(&options.destination, aliases)?.remote("migrate")?;
    let pairs = pairs(&source, &destination).await?;
    let started = Instant::now();
    let label = if options.dry_run {
        "Comparing"
    } else {
        "Migrating"
    };
    let transfers = Transfers::new(options.transfer, ui::Progress::stream(label));
    let mut tally = Tally::default();
    for pair in &pairs {
        let plan = match buckets::prepare(
            pair,
            options.latest,
            !options.no_configs,
            options.dry_run,
        )
        .await
        {
            Ok(plan) => plan,
            Err(err) => {
                tally.fail(err);
                continue;
            }
        };
        objects(pair, plan.versions, &options, &transfers, &mut tally).await;
        if plan.suspend_after && !options.dry_run && tally.failed.is_empty() {
            let suspended = pair
                .to_client
                .put_bucket_versioning()
                .bucket(&pair.to_bucket)
                .versioning_configuration(
                    aws_sdk_s3::types::VersioningConfiguration::builder()
                        .status(aws_sdk_s3::types::BucketVersioningStatus::Suspended)
                        .build(),
                )
                .send()
                .await;
            if let Err(e) = suspended {
                tally.fail(Error::s3(
                    format!("can't suspend versioning on {}", pair.destination_name()),
                    &e,
                ));
            }
        }
    }
    transfers.finish();
    summary(&tally, started, options.dry_run)
}

/// The buckets to migrate and where each goes: every bucket of an alias to the same
/// names at another, or one bucket (or prefix) to a bucket (or prefix).
async fn pairs(source: &Remote, destination: &Remote) -> Result<Vec<Pair>, Error> {
    let from_client = source.alias.client();
    let to_client = destination.alias.client();
    let buckets: Vec<(String, String, String, String)> = match &source.bucket {
        None => {
            if destination.bucket.is_some() {
                return Err(Error::usage(format!(
                    "{} is every bucket of an alias: give the destination as an alias too \
                     (each bucket keeps its name)",
                    source.alias_name
                )));
            }
            let listed = from_client.list_buckets().send().await.map_err(|e| {
                Error::s3(format!("can't list {}'s buckets", source.alias_name), &e)
            })?;
            listed
                .buckets()
                .iter()
                .filter_map(|b| b.name())
                .map(|b| (b.to_owned(), b.to_owned(), String::new(), String::new()))
                .collect()
        }
        Some(bucket) => {
            let (to_bucket, to_prefix) = match &destination.bucket {
                Some(to) => (to.clone(), destination.key.clone()),
                None => (bucket.clone(), source.key.clone()),
            };
            vec![(bucket.clone(), to_bucket, source.key.clone(), to_prefix)]
        }
    };
    let from_endpoint = (source.alias.url.clone(), source.alias.access_key.clone());
    let to_endpoint = (
        destination.alias.url.clone(),
        destination.alias.access_key.clone(),
    );
    let mut pairs = Vec::new();
    for (from_bucket, to_bucket, from_prefix, to_prefix) in buckets {
        let same_place = source.alias.url == destination.alias.url && from_bucket == to_bucket;
        if same_place
            && (from_prefix.starts_with(&to_prefix) || to_prefix.starts_with(&from_prefix))
        {
            return Err(Error::usage(format!(
                "{} and {} overlap: migrate to another bucket, or to a prefix outside it",
                name(&source.alias_name, &from_bucket, &from_prefix),
                name(&destination.alias_name, &to_bucket, &to_prefix),
            )));
        }
        pairs.push(Pair {
            from_client: from_client.clone(),
            to_client: to_client.clone(),
            from_alias: source.alias_name.clone(),
            to_alias: destination.alias_name.clone(),
            from_bucket,
            to_bucket,
            from_prefix,
            to_prefix,
            to_region: destination.alias.region.clone(),
            from_endpoint: from_endpoint.clone(),
            to_endpoint: to_endpoint.clone(),
        });
    }
    Ok(pairs)
}

/// What to do with a key.
#[derive(Debug, PartialEq, Eq)]
enum KeyPlan<'a> {
    /// Copy these (none: it's all there already).
    Add(&'a [Item]),
    /// The destination's versions aren't the source's first ones.
    Conflict,
}

/// Whether two versions (or markers) are the same object.
fn same(source: &Item, there: &Item, size_only: bool) -> bool {
    source.marker == there.marker
        && (source.marker
            || source.size == there.size
                && (size_only
                    || matches!((&source.etag, &there.etag), (Some(a), Some(b)) if same_etag(a, b))))
}

/// What to copy of a key's `source` items, given what's `there` (both oldest first).
/// Current objects only: the source's, unless the destination's is the same. Versions:
/// those after the destination's, which must be the source's first ones.
fn plan<'a>(source: &'a [Item], there: &[Item], versions: bool, size_only: bool) -> KeyPlan<'a> {
    if !versions {
        return match (source.last(), there.last()) {
            (Some(s), Some(t)) if same(s, t, size_only) => KeyPlan::Add(&[]),
            _ => KeyPlan::Add(source),
        };
    }
    if there.len() <= source.len() && there.iter().zip(source).all(|(t, s)| same(s, t, size_only)) {
        KeyPlan::Add(&source[there.len()..])
    } else {
        KeyPlan::Conflict
    }
}

/// What happened to a key.
#[derive(Default)]
struct KeyDone {
    versions: usize,
    markers: usize,
    bytes: u64,
    present: usize,
    conflict: bool,
    failed: Option<Error>,
}

/// Copies what the destination lacks of each key, several keys at once (each key's
/// versions in order).
async fn objects(
    pair: &Pair,
    versions: bool,
    options: &MigrateArgs,
    transfers: &Transfers,
    tally: &mut Tally,
) {
    let source = Keys::new(
        pair.from_client.clone(),
        &pair.from_bucket,
        &pair.from_prefix,
        versions,
        pair.source_name(),
        false,
        options.page_size,
    );
    let destination = Keys::new(
        pair.to_client.clone(),
        &pair.to_bucket,
        &pair.to_prefix,
        versions,
        pair.destination_name(),
        true,
        options.page_size,
    );
    let merged = stream::unfold(Merge::new(source, destination), |mut merge| async move {
        let next = merge.next().await.transpose()?;
        Some((next, merge))
    });
    let done = merged
        .map(|next| async move {
            match next {
                Ok((group, there)) => key(pair, &group, &there, versions, options, transfers).await,
                Err(err) => KeyDone {
                    failed: Some(err),
                    ..KeyDone::default()
                },
            }
        })
        .buffer_unordered(transfers.parallel());
    let mut done = std::pin::pin!(done);
    while let Some(key) = done.next().await {
        tally.versions += key.versions;
        tally.markers += key.markers;
        tally.bytes += key.bytes;
        tally.present += key.present;
        tally.conflicts += usize::from(key.conflict);
        if let Some(err) = key.failed {
            tally.fail(err);
        }
    }
}

/// The source's keys, each with what the destination has of it.
struct Merge {
    source: Keys,
    destination: Keys,
    /// The destination's next key, read ahead.
    ahead: Option<Group>,
    destination_done: bool,
}

impl Merge {
    fn new(source: Keys, destination: Keys) -> Self {
        Self {
            source,
            destination,
            ahead: None,
            destination_done: false,
        }
    }

    async fn next(&mut self) -> Result<Option<(Group, Vec<Item>)>, Error> {
        let Some(group) = self.source.next().await? else {
            return Ok(None);
        };
        loop {
            let there = match self.ahead.take() {
                Some(there) => there,
                None if self.destination_done => return Ok(Some((group, Vec::new()))),
                None => {
                    let Some(there) = self.destination.next().await? else {
                        self.destination_done = true;
                        return Ok(Some((group, Vec::new())));
                    };
                    there
                }
            };
            match there.relative.cmp(&group.relative) {
                // Only at the destination: left alone.
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Ok(Some((group, there.items))),
                std::cmp::Ordering::Greater => {
                    self.ahead = Some(there);
                    return Ok(Some((group, Vec::new())));
                }
            }
        }
    }
}

/// Copies what the destination lacks of one key.
async fn key(
    pair: &Pair,
    group: &Group,
    there: &[Item],
    versions: bool,
    options: &MigrateArgs,
    transfers: &Transfers,
) -> KeyDone {
    let mut done = KeyDone::default();
    let to = pair.object(false, &group.relative, None);
    let add = match plan(&group.items, there, versions, options.size_only) {
        KeyPlan::Add(add) => add,
        KeyPlan::Conflict => {
            done.conflict = true;
            ui::warn(format!(
                "{}: its versions there aren't the source's first ones, so none were copied \
                 (remove them there to copy them all)",
                to.name
            ));
            return done;
        }
    };
    done.present = if versions {
        there.len()
    } else {
        group.items.len() - add.len()
    };
    for item in add {
        let version = item.version_id.clone();
        if options.dry_run {
            let action = if item.marker { "mark deleted" } else { "copy" };
            ui::item(
                || match &version {
                    Some(v) => format!("would {action} {} (version {v})", to.name),
                    None => format!("would {action} {}", to.name),
                },
                || json!({"type": "plan", "action": action, "key": to.name, "version": version, "size": item.size}),
            );
            if item.marker {
                done.markers += 1;
            } else {
                done.versions += 1;
                done.bytes += item.size;
            }
            continue;
        }
        let result = if item.marker {
            mark(&to).await.map(|()| {
                done.markers += 1;
            })
        } else {
            let from = pair.object(true, &group.relative, version.clone());
            copy_one(&from, &to, options.size_only, transfers)
                .await
                .map(|size| {
                    done.versions += 1;
                    done.bytes += size;
                })
        };
        match result {
            Ok(()) => ui::done(
                match &version {
                    Some(v) if item.marker => format!("{}: delete marker (for {v})", to.name),
                    Some(v) => format!("{} (version {v})", to.name),
                    None => to.name.clone(),
                },
                || json!({"type": if item.marker { "marker" } else { "copy" }, "key": to.name, "source_version": version, "size": item.size}),
            ),
            Err(err) => {
                // The rest of the key's versions would come out of order: stop here.
                done.failed = Some(err);
                return done;
            }
        }
    }
    done
}

/// Puts a delete marker on `to`'s key.
async fn mark(to: &Object) -> Result<(), Error> {
    to.client
        .delete_object()
        .bucket(&to.bucket)
        .key(&to.key)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| Error::s3(format!("can't mark {} deleted", to.name), &e))
}

/// Copies one version, with its attributes; its size.
async fn copy_one(
    from: &Object,
    to: &Object,
    size_only: bool,
    transfers: &Transfers,
) -> Result<u64, Error> {
    let head = {
        let _permit = transfers.permit().await;
        from.client
            .head_object()
            .bucket(&from.bucket)
            .key(&from.key)
            .set_version_id(from.version_id.clone())
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't read {}", from.name), &e))?
    };
    let tags = if head.tag_count().unwrap_or(0) > 0 {
        let _permit = transfers.permit().await;
        from.client
            .get_object_tagging()
            .bucket(&from.bucket)
            .key(&from.key)
            .set_version_id(from.version_id.clone())
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't read the tags of {}", from.name), &e))?
            .tag_set
            .into_iter()
            .map(|t| (t.key, t.value))
            .collect()
    } else {
        Vec::new()
    };
    let size = head
        .content_length()
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0);
    let etag = head
        .e_tag()
        .ok_or_else(|| Error::general(format!("{} has no ETag", from.name)))?;
    let attributes = Attributes::of(&head, &tags, DateTime::from(SystemTime::now()));
    let source = Source {
        object: from,
        size,
        etag,
        attributes: &attributes,
    };
    exact::copy(transfers, &source, to, !size_only).await?;
    Ok(size)
}

/// Prints what was done, and fails when anything failed or conflicted.
fn summary(tally: &Tally, started: Instant, dry_run: bool) -> Result<(), Error> {
    let elapsed = started.elapsed();
    let verb = if dry_run { "Would copy" } else { "Copied" };
    let mut said = vec![format!(
        "{verb} {} version{} ({}), {} delete marker{}",
        tally.versions,
        plural(tally.versions),
        size(tally.bytes),
        tally.markers,
        plural(tally.markers),
    )];
    if tally.present > 0 {
        said.push(format!("{} already there", tally.present));
    }
    if tally.conflicts > 0 {
        said.push(format!(
            "{} key{} in conflict",
            tally.conflicts,
            plural(tally.conflicts)
        ));
    }
    if !dry_run && tally.bytes > 0 {
        said.push(format!(
            "in {:.1} s ({})",
            elapsed.as_secs_f64(),
            rate(tally.bytes, elapsed)
        ));
    }
    ui::done(said.join("; "), || {
        json!({
            "type": "summary",
            "action": if dry_run { "plan" } else { "migrate" },
            "versions": tally.versions,
            "markers": tally.markers,
            "bytes": tally.bytes,
            "present": tally.present,
            "conflicts": tally.conflicts,
            "failed": tally.failed.len(),
            "seconds": elapsed.as_secs_f64(),
        })
    });
    if let Some(first) = tally.failed.first() {
        return Err(Error::new(
            first.kind,
            format!(
                "{} failed (shown above): run it again to carry on",
                tally.failed.len()
            ),
        ));
    }
    if tally.conflicts > 0 {
        return Err(Error::new(
            Kind::General,
            format!(
                "{} key{} in conflict (shown above)",
                tally.conflicts,
                plural(tally.conflicts)
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(etag: &str, size: u64) -> Item {
        Item {
            version_id: Some(etag.to_owned()),
            marker: false,
            latest: false,
            size,
            etag: Some(format!("\"{etag}\"")),
            modified: None,
        }
    }

    fn marker() -> Item {
        Item {
            version_id: Some("m".to_owned()),
            marker: true,
            latest: false,
            size: 0,
            etag: None,
            modified: None,
        }
    }

    #[test]
    fn versions_are_added_after_those_already_there() {
        let source = [object("a", 1), marker(), object("b", 2)];
        assert_eq!(plan(&source, &[], true, false), KeyPlan::Add(&source));
        assert_eq!(
            plan(&source, &[object("a", 1)], true, false),
            KeyPlan::Add(&source[1..])
        );
        assert_eq!(
            plan(
                &source,
                &[object("a", 1), marker(), object("b", 2)],
                true,
                false
            ),
            KeyPlan::Add(&[])
        );
        // Different, or more than the source has.
        assert_eq!(
            plan(&source, &[object("x", 1)], true, false),
            KeyPlan::Conflict
        );
        assert_eq!(plan(&source, &[marker()], true, false), KeyPlan::Conflict);
        let more = [object("a", 1), marker(), object("b", 2), object("c", 3)];
        assert_eq!(plan(&source, &more, true, false), KeyPlan::Conflict);
        // By size alone (ETags that differ, as encrypted objects' can).
        assert_eq!(
            plan(&source, &[object("x", 1)], true, true),
            KeyPlan::Add(&source[1..])
        );
        assert_eq!(
            plan(&source, &[object("x", 9)], true, true),
            KeyPlan::Conflict
        ); // A delete marker isn't an empty object, whatever their sizes.
        let empty = [object("e", 0)];
        assert_eq!(plan(&[marker()], &empty, true, true), KeyPlan::Conflict);
    }

    #[test]
    fn current_objects_are_copied_when_different() {
        let source = [object("a", 1)];
        assert_eq!(plan(&source, &[], false, false), KeyPlan::Add(&source));
        assert_eq!(
            plan(&source, &[object("a", 1)], false, false),
            KeyPlan::Add(&[])
        );
        assert_eq!(
            plan(&source, &[object("b", 1)], false, false),
            KeyPlan::Add(&source)
        );
        assert_eq!(
            plan(&source, &[object("b", 1)], false, true),
            KeyPlan::Add(&[])
        );
        assert_eq!(
            plan(&source, &[object("a", 2)], false, true),
            KeyPlan::Add(&source)
        );
    }
}
