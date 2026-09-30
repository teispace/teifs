//! `teifs repair`: where a drive's metadata and its files disagree (after a restore to
//! an older snapshot, a lost index row or files moved by hand), reported, and with
//! `--apply` set right where that's safe.

use std::path::PathBuf;

use teifs_store::{Finding, Repair, RepairOptions, StoreError, Stray};

use crate::{error, open, plural, ui};

#[derive(clap::Args)]
pub struct RepairArgs {
    /// The drive's folder.
    #[arg(default_value = ".", env = "TEIFS_DIR")]
    dir: PathBuf,
    /// Set right what can be: give data files back their versions, remove what was
    /// replaced since and upload folders of no upload. Without it, only report.
    #[arg(long)]
    apply: bool,
    /// Also forget versions whose data file is missing (their bytes are lost).
    #[arg(long, requires = "apply")]
    forget_missing: bool,
}

pub async fn repair(args: RepairArgs) -> Result<(), error::Error> {
    let store = open(&args.dir)?;
    let options = RepairOptions {
        apply: args.apply,
        forget_missing: args.forget_missing,
    };
    let report = store.repair(options).await.map_err(|e| match e {
        StoreError::DamagedDatabase(_) => error::Error::general(e.to_string())
            .with_hint("restore one of its snapshots (`teifs restore --from`), then repair again"),
        e => error::Error::general(format!("can't repair the drive: {e}")),
    })?;
    for repair in &report.findings {
        tell(repair)?;
    }
    let found = report.findings.len() as u64;
    let left = report.findings.iter().filter(|r| !r.fixed).count() as u64;
    ui::done(
        format!(
            "Looked at {} data file{} and {} version{}: {found} problem{} found, {} set right",
            report.data_files,
            plural(report.data_files),
            report.versions,
            plural(report.versions),
            plural(found),
            found - left,
        ),
        || {
            serde_json::json!({
                "type": "repaired",
                "dataFiles": report.data_files,
                "versions": report.versions,
                "found": found,
                "left": left,
            })
        },
    );
    if left == 0 {
        return Ok(());
    }
    let error = error::Error::new(
        error::Kind::General,
        format!("{left} problem{} left", plural(left)),
    );
    let fixable = report.findings.iter().any(|r| can_fix(r, args.apply));
    Err(if fixable {
        error.with_hint(if args.apply {
            "add --forget-missing to forget versions whose bytes are lost"
        } else {
            "run it again with --apply to set right what can be"
        })
    } else {
        error.with_hint("what's left needs a person: see each warning")
    })
}

/// Whether running again with more options would set `repair` right.
const fn can_fix(repair: &Repair, applied: bool) -> bool {
    match repair.finding {
        _ if repair.fixed => false,
        Finding::Missing { .. } => true,
        Finding::Unlisted { .. } | Finding::Superseded { .. } | Finding::StrayUpload { .. } => {
            !applied
        }
        Finding::Stray { .. } | Finding::UnknownBucket { .. } => false,
    }
}

/// A `repair` record, or a line: a note for what was set right, a warning for the rest.
fn tell(repair: &Repair) -> Result<(), error::Error> {
    if ui::json() {
        let mut record = serde_json::to_value(repair).map_err(|e| e.to_string())?;
        record["type"] = "repair".into();
        ui::emit(&record);
    } else if repair.fixed {
        ui::note(line(repair));
    } else {
        ui::warn(line(repair));
    }
    Ok(())
}

/// What was found, and what was done or can be.
fn line(repair: &Repair) -> String {
    let fixed = repair.fixed;
    let done = |yes: &str, no: &str| if fixed { yes } else { no }.to_owned();
    match &repair.finding {
        Finding::Unlisted {
            bucket,
            key,
            version_id,
            ..
        } => format!(
            "{bucket}/{key}{}: its data file had no version; {}",
            version(version_id),
            done("given back", "--apply gives it back"),
        ),
        Finding::Superseded { bucket, key, .. } => format!(
            "{bucket}/{key}: a data file replaced since was left behind; {}",
            done("removed", "--apply removes it"),
        ),
        Finding::Missing {
            bucket,
            key,
            version_id,
            ..
        } => format!(
            "{bucket}/{key}{}: its data file is missing; {}",
            version(version_id),
            done(
                "forgotten",
                "restore it from a copy, or forget it with --apply --forget-missing"
            ),
        ),
        Finding::Stray { bucket, path, why } => {
            let why = match why {
                Stray::NoFooter => "it has nothing to rebuild a version from",
                Stray::Elsewhere => "it belongs to another bucket or file",
                Stray::VersionTaken => "its version belongs to another file",
            };
            format!(
                "{}: in {bucket}'s data but {why}; left alone",
                path.display()
            )
        }
        Finding::UnknownBucket { path, .. } => format!(
            "{}: data of a bucket this drive doesn't have; left alone",
            path.display()
        ),
        Finding::StrayUpload { path, .. } => format!(
            "{}: parts of an upload that doesn't exist; {}",
            path.display(),
            done("removed", "--apply removes them"),
        ),
    }
}

/// ` (version ID)`, or nothing for the `null` version.
fn version(id: &str) -> String {
    match id {
        "" | "null" => String::new(),
        id => format!(" (version {id})"),
    }
}
