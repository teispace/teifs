//! `cp`, `mv` and `mirror`: working out which files and objects go where, then
//! transferring them several at once.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Instant,
};

use futures::{StreamExt, stream};
use serde_json::json;

use super::{
    CopyArgs, Error, Kind, TransferArgs,
    alias::Aliases,
    commands::{object, plural, with_folder_hint},
    listing::{self, Entry},
    target::{Target, base_name, local_path},
    transfer::{Head, Object, Transfers},
};
use crate::{
    ui,
    units::{rate, size},
};

/// One end of a copy.
enum End {
    Local(PathBuf),
    Remote(Object),
}

impl End {
    fn name(&self) -> String {
        match self {
            Self::Local(path) => path.display().to_string(),
            Self::Remote(object) => object.name.clone(),
        }
    }
}

/// One file or object to copy.
struct Job {
    from: End,
    /// For a remote source: what's known about it.
    head: Option<Head>,
    to: End,
    size: u64,
}

/// What a command's jobs came to.
struct Outcome {
    started: Instant,
    copied: usize,
    bytes: u64,
    removed: usize,
    failed: Vec<Error>,
}

impl Outcome {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            copied: 0,
            bytes: 0,
            removed: 0,
            failed: Vec::new(),
        }
    }

    /// Reports a failure; the command carries on and fails at the end.
    fn fail(&mut self, err: Error) {
        ui::error(&err);
        self.failed.push(err);
    }
}

pub async fn copy(args: CopyArgs, remove_source: bool, aliases: &Aliases) -> Result<(), Error> {
    let (destination, sources) = args
        .paths
        .split_last()
        .expect("clap requires two paths or more");
    if destination == STDIO || sources.iter().any(|s| s == STDIO) {
        return stdio(&args, remove_source, aliases).await;
    }
    let destination = Target::parse(destination, aliases)?;
    let many = sources.len() > 1;
    let mut jobs = Vec::new();
    let mut planned = Outcome::new();
    for source in sources {
        let source = Target::parse(source, aliases)?;
        match plan_copy(
            &source,
            &destination,
            args.recursive,
            many,
            &mut jobs,
            &mut planned,
        )
        .await
        {
            Ok(()) => {}
            Err(err) if many => planned.fail(err),
            Err(err) => return Err(err),
        }
    }
    let verb = if remove_source { "Moved" } else { "Copied" };
    let outcome = run_jobs(args.transfer, jobs, remove_source, planned).await;
    finish(&outcome, verb)
}

/// `-`: standard input as a source, standard output as a destination.
const STDIO: &str = "-";

/// `cp - ALIAS/BUCKET/KEY` (standard input to an object) and `cp ALIAS/BUCKET/KEY -`
/// (an object to standard output).
async fn stdio(args: &CopyArgs, remove_source: bool, aliases: &Aliases) -> Result<(), Error> {
    let (destination, sources) = args.paths.split_last().expect("two paths or more");
    let usage = || {
        Error::usage(
            "`-` copies one stream: `teifs cp - ALIAS/BUCKET/KEY` or `teifs cp ALIAS/BUCKET/KEY -`",
        )
    };
    let [source] = sources else {
        return Err(usage());
    };
    if remove_source {
        return Err(Error::usage("a stream can't be moved: use `teifs cp`"));
    }
    if args.recursive || (source == STDIO) == (destination == STDIO) {
        return Err(usage());
    }
    if destination == STDIO {
        let remote = Target::parse(source, aliases)?.remote("copying to standard output")?;
        return super::commands::cat(remote).await;
    }
    let remote = Target::parse(destination, aliases)?.remote("copying standard input")?;
    remote.bucket()?;
    if remote.is_folder() {
        let example = remote.display(&format!("{}NAME", remote.folder_prefix()));
        return Err(Error::usage(format!(
            "standard input needs an object name, like `teifs cp - {example}`"
        )));
    }
    let to = object(&remote, &remote.key);
    let transfers = Transfers::new(args.transfer, ui::Progress::stream("Uploading"));
    let started = Instant::now();
    let sent = transfers.upload_stream(tokio::io::stdin(), &to).await;
    transfers.finish();
    let bytes = sent?;
    let elapsed = started.elapsed();
    ui::done(
        format!(
            "Copied standard input to {}: {} in {:.1} s ({})",
            to.name,
            size(bytes),
            elapsed.as_secs_f64(),
            rate(bytes, elapsed)
        ),
        || json!({"type": "copy", "from": STDIO, "to": to.name, "bytes": bytes}),
    );
    Ok(())
}

/// Adds the jobs that copy `source` to `destination`; a folder's entries that can't be
/// copied are reported in `planned` and the rest still go.
async fn plan_copy(
    source: &Target,
    destination: &Target,
    recursive: bool,
    many: bool,
    jobs: &mut Vec<Job>,
    planned: &mut Outcome,
) -> Result<(), Error> {
    if let (Target::Local(path), Target::Local(_)) = (source, destination) {
        return Err(Error::usage(format!(
            "{} and {} are both local: use your system's copy for that",
            path.display(),
            name_of(destination)
        )));
    }
    // A folder or a prefix: everything in it, to the same places below the destination.
    if recursive && let Some(entries) = folder_entries(source).await? {
        for entry in entries {
            if entry.relative.ends_with('/') && matches!(destination, Target::Local(_)) {
                // A folder marker: nothing to write as a file.
                continue;
            }
            match folder_job(source, destination, &entry) {
                Ok(job) => jobs.push(job),
                Err(err) => planned.fail(err),
            }
        }
        return Ok(());
    }
    // One file or object.
    let (from, head, name, size) = match source {
        Target::Local(path) => {
            let meta = std::fs::metadata(path).map_err(|e| {
                let kind = if e.kind() == std::io::ErrorKind::NotFound {
                    Kind::NotFound
                } else {
                    Kind::General
                };
                Error::new(kind, format!("can't read {}: {e}", path.display()))
            })?;
            if meta.is_dir() {
                return Err(Error::usage(format!(
                    "{} is a folder: add -r to copy what's in it",
                    path.display()
                )));
            }
            let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
                Error::usage(format!("{} has no name usable as a key", path.display()))
            })?;
            (End::Local(path.clone()), None, name.to_owned(), meta.len())
        }
        Target::Remote(from) => {
            let bucket = from.bucket()?;
            if from.is_folder() {
                return Err(Error::usage(format!(
                    "{} is a folder or a bucket: add -r to copy what's in it",
                    from.display(&from.key)
                )));
            }
            let object = object(from, &from.key);
            let head = match object.head().await {
                Ok(head) => head,
                Err(err) => {
                    let client = from.alias.client();
                    return Err(with_folder_hint(err, &client, bucket, from, "cp -r").await);
                }
            };
            let size = head.size;
            (
                End::Remote(object),
                Some(head),
                base_name(&from.key).to_owned(),
                size,
            )
        }
    };
    let into_folder = many
        || match destination {
            Target::Local(path) => path.is_dir() || ends_with_separator(path),
            Target::Remote(to) => to.is_folder(),
        };
    let to = if into_folder {
        end_at(destination, &name)?
    } else {
        match destination {
            Target::Local(path) => End::Local(path.clone()),
            Target::Remote(to) => {
                to.bucket()?;
                End::Remote(object(to, &to.key))
            }
        }
    };
    jobs.push(Job {
        from,
        head,
        to,
        size,
    });
    Ok(())
}

/// Everything below a local folder or a key prefix; `None` when `source` is one file,
/// or one object that nothing is below.
async fn folder_entries(source: &Target) -> Result<Option<Vec<Entry>>, Error> {
    match source {
        Target::Local(path) => {
            if path.is_dir() {
                listing::local(path).map(Some)
            } else {
                Ok(None)
            }
        }
        Target::Remote(from) => {
            let prefix = from.folder_prefix();
            let entries = listing::remote(
                &from.alias.client(),
                from.bucket()?,
                &prefix,
                &from.display(&prefix),
            )
            .await?;
            Ok((!entries.is_empty() || from.is_folder()).then_some(entries))
        }
    }
}

/// Where the path `relative` below the folder or prefix `target` is.
fn end_at(target: &Target, relative: &str) -> Result<End, Error> {
    match target {
        Target::Local(dir) => local_path(relative)
            .map(|path| End::Local(dir.join(path)))
            .map_err(Error::general),
        Target::Remote(remote) => {
            remote.bucket()?;
            let key = format!("{}{relative}", remote.folder_prefix());
            Ok(End::Remote(object(remote, &key)))
        }
    }
}

/// A job copying `entry`, listed below `source`, to the same place below `destination`.
fn folder_job(source: &Target, destination: &Target, entry: &Entry) -> Result<Job, Error> {
    let from = end_at(source, &entry.relative)?;
    let head = matches!(from, End::Remote(_)).then(|| Head {
        size: entry.size,
        etag: entry.etag.clone(),
        modified: entry.modified,
        output: None,
    });
    let to = end_at(destination, &entry.relative)
        .map_err(|e| Error::new(e.kind, format!("can't copy {}: {}", from.name(), e.message)))?;
    Ok(Job {
        from,
        head,
        to,
        size: entry.size,
    })
}

fn ends_with_separator(path: &Path) -> bool {
    let text = path.as_os_str().to_string_lossy();
    text.ends_with('/') || (cfg!(windows) && text.ends_with('\\'))
}

fn name_of(target: &Target) -> String {
    match target {
        Target::Local(path) => path.display().to_string(),
        Target::Remote(remote) => remote.display(&remote.key),
    }
}

/// Runs `jobs`, several at once, adding to what `outcome` already holds; a failed one
/// is reported and the rest carry on.
async fn run_jobs(
    args: TransferArgs,
    jobs: Vec<Job>,
    remove_source: bool,
    mut outcome: Outcome,
) -> Outcome {
    let total = jobs.iter().map(|job| job.size).sum();
    let label = if remove_source { "Moving" } else { "Copying" };
    let transfers = Transfers::new(args, ui::Progress::bytes(total, label));
    let transfers = &transfers;
    let mut results = stream::iter(jobs)
        .map(|job| async move {
            let result = run_job(transfers, &job, remove_source).await;
            (job.size, result)
        })
        .buffer_unordered(transfers.parallel());
    while let Some((size, result)) = results.next().await {
        match result {
            Ok(()) => {
                outcome.copied += 1;
                outcome.bytes += size;
            }
            Err(err) => outcome.fail(err),
        }
    }
    transfers.finish();
    outcome
}

async fn run_job(transfers: &Transfers, job: &Job, remove_source: bool) -> Result<(), Error> {
    let head = || job.head.as_ref().expect("remote sources have a head");
    match (&job.from, &job.to) {
        (End::Local(path), End::Remote(to)) => transfers.upload(path, job.size, to).await?,
        (End::Remote(from), End::Local(path)) => transfers.download(from, head(), path).await?,
        (End::Remote(from), End::Remote(to)) => transfers.copy(from, head(), to).await?,
        (End::Local(_), End::Local(_)) => unreachable!("local copies are refused when planned"),
    }
    if remove_source {
        remove(&job.from).await?;
    }
    let (from, to) = (job.from.name(), job.to.name());
    ui::done(format!("{from} → {to}"), || {
        json!({
            "type": if remove_source { "move" } else { "copy" },
            "source": from,
            "destination": to,
            "size": job.size,
        })
    });
    Ok(())
}

async fn remove(end: &End) -> Result<(), Error> {
    match end {
        End::Local(path) => tokio::fs::remove_file(path)
            .await
            .map_err(|e| Error::general(format!("can't remove {}: {e}", path.display()))),
        End::Remote(object) => object
            .client
            .delete_object()
            .bucket(&object.bucket)
            .key(&object.key)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| Error::s3(format!("can't remove {}", object.name), &e)),
    }
}

/// Prints a summary, and fails (with the first failure's kind) if anything did.
fn finish(outcome: &Outcome, verb: &str) -> Result<(), Error> {
    let elapsed = outcome.started.elapsed();
    let failed = outcome.failed.len();
    let mut said = Vec::new();
    if outcome.copied > 0 {
        said.push(format!(
            "{verb} {} file{}, {} in {:.1} s ({})",
            outcome.copied,
            plural(outcome.copied),
            size(outcome.bytes),
            elapsed.as_secs_f64(),
            rate(outcome.bytes, elapsed)
        ));
    }
    if outcome.removed > 0 {
        said.push(format!(
            "removed {} file{}",
            outcome.removed,
            plural(outcome.removed)
        ));
    }
    if said.is_empty() && failed == 0 {
        said.push("Nothing to do: already the same".to_owned());
    }
    if !said.is_empty() {
        let mut message = said.join("; ");
        if let Some(first) = message.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        ui::done(message, || {
            json!({
                "type": "summary",
                "action": verb.to_ascii_lowercase(),
                "copied": outcome.copied,
                "bytes": outcome.bytes,
                "removed": outcome.removed,
                "failed": failed,
                "seconds": elapsed.as_secs_f64(),
            })
        });
    }
    match outcome.failed.as_slice() {
        [] => Ok(()),
        // The one failure, already shown: only its exit code is left to give.
        [only] if outcome.copied == 0 && outcome.removed == 0 => {
            Err(Error::new(only.kind, only.message.clone()).shown())
        }
        [first, ..] => Err(Error::new(
            first.kind,
            format!(
                "{failed} of {} failed (shown above)",
                failed + outcome.copied + outcome.removed
            ),
        )),
    }
}

/// What a mirror changes.
struct MirrorPlan<'a> {
    copy: Vec<&'a Entry>,
    remove: Vec<&'a Entry>,
}

impl<'a> MirrorPlan<'a> {
    /// Copies what's missing, a different size, or newer at the source; removes (if
    /// `remove`) what the source doesn't have.
    fn new(wanted: &'a [Entry], present: &'a [Entry], remove: bool, to_local: bool) -> Self {
        let present_by_name: BTreeMap<&str, &Entry> =
            present.iter().map(|e| (e.relative.as_str(), e)).collect();
        let copy = wanted
            .iter()
            // Folder markers can't be files.
            .filter(|e| !(to_local && e.relative.ends_with('/')))
            .filter(|e| match present_by_name.get(e.relative.as_str()) {
                None => true,
                Some(there) => {
                    there.size != e.size
                        || matches!((e.modified, there.modified), (Some(new), Some(old)) if new > old)
                }
            })
            .collect();
        let wanted_names: BTreeSet<&str> = wanted.iter().map(|e| e.relative.as_str()).collect();
        let remove = if remove {
            present
                .iter()
                .filter(|e| !wanted_names.contains(e.relative.as_str()))
                .collect()
        } else {
            Vec::new()
        };
        Self { copy, remove }
    }
}

pub async fn mirror(
    source: Target,
    destination: Target,
    remove: bool,
    dry_run: bool,
    transfer: TransferArgs,
) -> Result<(), Error> {
    if matches!(
        (&source, &destination),
        (Target::Local(_), Target::Local(_))
    ) {
        return Err(Error::usage(
            "both are local: mirror copies between local folders and S3, or within S3",
        ));
    }
    let wanted = mirror_entries(&source, true).await?;
    let present = mirror_entries(&destination, false).await?;
    let to_local = matches!(destination, Target::Local(_));
    let plan = MirrorPlan::new(&wanted, &present, remove, to_local);
    if dry_run {
        let plans = plan
            .copy
            .iter()
            .map(|e| ("copy", e))
            .chain(plan.remove.iter().map(|e| ("remove", e)));
        for (action, entry) in plans {
            ui::item(
                || format!("would {action} {}", entry.relative),
                || json!({"type": "plan", "action": action, "path": entry.relative, "size": entry.size}),
            );
        }
        ui::note(format!(
            "{} to copy, {} to remove; nothing changed (--dry-run)",
            plan.copy.len(),
            plan.remove.len()
        ));
        return Ok(());
    }
    let mut planned = Outcome::new();
    let mut jobs = Vec::new();
    for entry in &plan.copy {
        match folder_job(&source, &destination, entry) {
            Ok(job) => jobs.push(job),
            Err(err) => planned.fail(err),
        }
    }
    let mut outcome = run_jobs(transfer, jobs, false, planned).await;
    if !outcome.failed.is_empty() && !plan.remove.is_empty() {
        ui::warn("nothing was removed, as some copies failed");
    } else {
        for entry in &plan.remove {
            // A name this system can't hold was never copied here: nothing to remove.
            let Ok(end) = end_at(&destination, &entry.relative) else {
                continue;
            };
            match self::remove(&end).await {
                Ok(()) => {
                    let name = end.name();
                    ui::done(
                        format!("Removed {name}"),
                        || json!({"type": "remove", "key": name, "count": 1}),
                    );
                    outcome.removed += 1;
                }
                Err(err) => outcome.fail(err),
            }
        }
    }
    finish(&outcome, "Copied")
}

/// What's under a mirror's source or destination. A destination folder that isn't
/// there yet is empty; a source must be there.
async fn mirror_entries(target: &Target, is_source: bool) -> Result<Vec<Entry>, Error> {
    if let Target::Local(dir) = target {
        if !is_source && !dir.exists() {
            return Ok(Vec::new());
        }
        if !dir.is_dir() {
            return Err(Error::usage(format!("{} isn't a folder", dir.display())));
        }
    }
    Ok(folder_entries(target).await?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    fn entry(relative: &str, size: u64, modified_secs: u64) -> Entry {
        Entry {
            relative: relative.to_owned(),
            size,
            modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(modified_secs)),
            etag: None,
        }
    }

    fn names(entries: &[&Entry]) -> Vec<String> {
        entries.iter().map(|e| e.relative.clone()).collect()
    }

    #[test]
    fn mirrors_copy_what_is_new_changed_or_newer_and_remove_what_is_gone() {
        let wanted = [
            entry("new.txt", 1, 10),
            entry("same.txt", 5, 10),
            entry("resized.txt", 6, 10),
            entry("newer.txt", 5, 20),
            entry("older.txt", 5, 5),
            entry("folder/", 0, 10),
        ];
        let present = [
            entry("same.txt", 5, 10),
            entry("resized.txt", 5, 10),
            entry("newer.txt", 5, 10),
            entry("older.txt", 5, 10),
            entry("gone.txt", 1, 10),
        ];
        let plan = MirrorPlan::new(&wanted, &present, true, false);
        assert_eq!(
            names(&plan.copy),
            ["new.txt", "resized.txt", "newer.txt", "folder/"]
        );
        assert_eq!(names(&plan.remove), ["gone.txt"]);

        let plan = MirrorPlan::new(&wanted, &present, false, true);
        assert_eq!(names(&plan.copy), ["new.txt", "resized.txt", "newer.txt"]);
        assert!(plan.remove.is_empty());
    }
}
