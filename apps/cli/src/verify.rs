//! `teifs verify`: reads a drive's stored versions back and checks them against what
//! was recorded when they were written; and the words for what checks find, which
//! `teifs admin info` shows for a server's scrubs too.

use teifs_store::{Damage, Unverifiable, Verdict, VerifyCursor};
use teifs_types::verify::{Checked, ScrubPass};

use crate::{KeyringArgs, error, open, open_kms, plural, ui, units};

/// Versions checked between two looks at the progress.
const BATCH: usize = 256;

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Only this bucket.
    #[arg(long)]
    bucket: Option<String>,
    /// Where encrypted objects' keys are (without a keyring, they're reported as not
    /// checked).
    #[command(flatten)]
    keyring: KeyringArgs,
}

/// One pass over the drive, telling of each version that isn't intact.
pub async fn verify(args: VerifyArgs) -> Result<(), error::Error> {
    let store = open(&args.keyring.dir)?;
    if let Some((kms, _)) = open_kms(&args.keyring, Some(&store), false).await? {
        store.attach_kms(kms).map_err(|e| e.to_string())?;
    }
    if let Some(bucket) = &args.bucket {
        store.head_bucket(bucket).await.map_err(|e| match e {
            teifs_store::StoreError::NoSuchBucket => error::Error::new(
                error::Kind::NotFound,
                format!("there's no bucket {bucket} on this drive"),
            ),
            e => error::Error::general(e.to_string()),
        })?;
    }
    let progress = ui::Progress::stream("Verifying");
    let mut pass = ScrubPass::default();
    let mut cursor = VerifyCursor::default();
    loop {
        let checked = store
            .verify_next(&mut cursor, args.bucket.as_deref(), BATCH)
            .await
            .map_err(|e| {
                progress.finish();
                format!("can't go on checking: {e}")
            })?;
        if checked.is_empty() {
            break;
        }
        for item in checked {
            progress.add(item.size);
            report(&item)?;
            pass.record(item);
        }
    }
    progress.finish();
    ui::done(summary(&pass), || {
        serde_json::json!({
            "type": "verified",
            "versions": pass.versions,
            "bytes": pass.bytes,
            "damaged": pass.damaged,
            "unverifiable": pass.unverifiable,
        })
    });
    if pass.damaged > 0 {
        return Err(error::Error::new(
            error::Kind::General,
            format!("{} damaged version{}", pass.damaged, plural(pass.damaged)),
        )
        .with_hint("restore them from a copy, or delete them so clients stop getting them"));
    }
    Ok(())
}

/// Tells of `item` if it isn't intact: a warning for damage, a note for what couldn't
/// be checked, or a `verify` record.
fn report(item: &Checked) -> Result<(), error::Error> {
    if item.verdict == Verdict::Intact {
        return Ok(());
    }
    if ui::json() {
        let mut record = serde_json::to_value(item).map_err(|e| e.to_string())?;
        record["type"] = "verify".into();
        ui::emit(&record);
    } else if matches!(item.verdict, Verdict::Damaged { .. }) {
        ui::warn(format!("damaged: {}", line(item)));
    } else {
        ui::note(format!("not checked: {}", line(item)));
    }
    Ok(())
}

/// What a pass checked and found, in a sentence.
pub fn summary(pass: &ScrubPass) -> String {
    format!(
        "Checked {} version{} ({}): {} damaged, {} not checked",
        pass.versions,
        plural(pass.versions),
        units::size(pass.bytes),
        pass.damaged,
        pass.unverifiable,
    )
}

/// `bucket/key (version id): what the check found`.
pub fn line(item: &Checked) -> String {
    let version = match item.version_id.as_str() {
        "" | "null" => String::new(),
        id => format!(" (version {id})"),
    };
    let what = match &item.verdict {
        Verdict::Intact => "intact".to_owned(),
        Verdict::Damaged { damage } => damage_text(damage),
        Verdict::Unverifiable { reason } => unverifiable_text(*reason).to_owned(),
    };
    format!("{}/{}{version}: {what}", item.bucket, item.key)
}

fn damage_text(damage: &Damage) -> String {
    match damage {
        Damage::Missing => "its data is missing".into(),
        Damage::Truncated => "its data is cut short".into(),
        Damage::Tampered => "its encrypted data doesn't authenticate".into(),
        Damage::Etag => "its bytes don't match its ETag".into(),
        Damage::Checksum {
            algorithm,
            part: None,
        } => format!("its bytes don't match its {algorithm} checksum"),
        Damage::Checksum {
            algorithm,
            part: Some(part),
        } => format!("part {part}'s bytes don't match its {algorithm} checksum"),
    }
}

fn unverifiable_text(reason: Unverifiable) -> &'static str {
    match reason {
        Unverifiable::CustomerKey => "it's encrypted with a key its client keeps (SSE-C)",
        Unverifiable::NoKms => "it's encrypted, and the keyring isn't here (--kms-keyring)",
        Unverifiable::NothingToCompare => "it changed outside TeiFS, so nothing records its bytes",
        Unverifiable::ChangedMeanwhile => "it changed while it was being read",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked(version_id: &str, verdict: Verdict) -> Checked {
        Checked {
            bucket: "photos".into(),
            key: "2026/a.jpg".into(),
            version_id: version_id.into(),
            size: 1,
            verdict,
        }
    }

    #[test]
    fn findings_read_as_sentences() {
        let part = Damage::Checksum {
            algorithm: "CRC64NVME".into(),
            part: Some(3),
        };
        assert_eq!(
            line(&checked("null", part.into())),
            "photos/2026/a.jpg: part 3's bytes don't match its CRC64NVME checksum"
        );
        assert_eq!(
            line(&checked("v1", Damage::Etag.into())),
            "photos/2026/a.jpg (version v1): its bytes don't match its ETag"
        );
        assert_eq!(
            line(&checked("", Unverifiable::NoKms.into())),
            "photos/2026/a.jpg: it's encrypted, and the keyring isn't here (--kms-keyring)"
        );
        let mut pass = ScrubPass::default();
        pass.record(checked("", Damage::Missing.into()));
        assert_eq!(
            summary(&pass),
            "Checked 1 version (1 B): 1 damaged, 0 not checked"
        );
    }
}
