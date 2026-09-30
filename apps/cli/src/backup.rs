//! `teifs backup` and `teifs restore`: the drive's metadata (buckets, settings, IAM and
//! the object index) copied out, and put back, while no server has the drive open.

use std::path::{Path, PathBuf};

use teifs_store::StoreError;

use crate::{error, open, ui, units};

#[derive(clap::Args)]
pub struct BackupArgs {
    /// The drive's folder.
    #[arg(default_value = ".", env = "TEIFS_DIR")]
    dir: PathBuf,
    /// The folder to write the backup into (made if missing); each backup is a folder
    /// of its own in it, named for when it was taken.
    #[arg(long)]
    to: PathBuf,
}

#[derive(clap::Args)]
pub struct RestoreArgs {
    /// The drive's folder.
    #[arg(default_value = ".", env = "TEIFS_DIR")]
    dir: PathBuf,
    /// A backup's folder, or the name of one of the drive's own snapshots
    /// (`teifs admin snapshot ls`).
    #[arg(long)]
    from: String,
}

pub async fn backup(args: BackupArgs) -> Result<(), error::Error> {
    let store = open(&args.dir)?;
    let snapshot = store.back_up_to(&args.to).await.map_err(|e| match e {
        StoreError::StorageFull => error::Error::new(
            error::Kind::General,
            format!("there isn't room for the backup in {}", args.to.display()),
        ),
        e => error::Error::general(format!("can't back up the drive: {e}")),
    })?;
    let path = args.to.join(&snapshot.name);
    ui::done(
        format!(
            "Backed up the drive's metadata to {} ({})",
            path.display(),
            units::size(snapshot.bytes)
        ),
        || {
            serde_json::json!({
                "type": "backup",
                "path": path.display().to_string(),
                "name": snapshot.name,
                "createdMs": snapshot.created_ms,
                "bytes": snapshot.bytes,
            })
        },
    );
    ui::note(
        "Objects' bytes aren't in it: copy them too, and keep the KMS keyring safe \
         (encrypted objects and IAM secrets need it).",
    );
    Ok(())
}

pub fn restore(args: &RestoreArgs) -> Result<(), error::Error> {
    let from = source(&args.dir, &args.from)?;
    let question = format!(
        "Replace the drive's metadata with {}? What it has now is kept in .teifs/backups/",
        from.display()
    );
    if !ui::confirm(&question, "add --yes to restore without asking")? {
        return Err(error::Error::general("nothing was restored").shown());
    }
    let restored = teifs_store::restore(&args.dir, &from).map_err(|e| match e {
        StoreError::DriveInUse => error::Error::new(
            error::Kind::Conflict,
            format!(
                "the drive at {} is open in another TeiFS process",
                args.dir.display()
            ),
        )
        .with_hint("stop `teifs serve` first"),
        StoreError::Io(err) if err.kind() == std::io::ErrorKind::NotFound => error::Error::new(
            error::Kind::NotFound,
            format!("there's no drive at {}", args.dir.display()),
        ),
        e @ StoreError::BadSnapshot(_) => error::Error::new(error::Kind::Usage, e.to_string()),
        e => error::Error::general(format!("can't restore: {e}")),
    })?;
    let previous = restored.previous.display().to_string();
    ui::done(
        format!(
            "Restored the metadata of {}; what it replaced is in {previous}",
            restored.snapshot.name
        ),
        || {
            serde_json::json!({
                "type": "restore",
                "name": restored.snapshot.name,
                "createdMs": restored.snapshot.created_ms,
                "previous": previous,
            })
        },
    );
    ui::note(
        "Objects written since keep their bytes: folder buckets' files are indexed again \
         when the drive is next served.",
    );
    Ok(())
}

/// The folder `from` names: a path, or a snapshot of the drive's own.
fn source(dir: &Path, from: &str) -> Result<PathBuf, error::Error> {
    let path = PathBuf::from(from);
    if path.join("snapshot.json").is_file() {
        return Ok(path);
    }
    let own = dir.join(".teifs/backups/auto").join(from);
    if !from.contains(['/', '\\']) && own.join("snapshot.json").is_file() {
        return Ok(own);
    }
    Err(error::Error::new(
        error::Kind::NotFound,
        format!("{from} isn't a backup or one of the drive's snapshots"),
    )
    .with_hint("give a folder `teifs backup` made, or a name `teifs admin snapshot ls` lists"))
}
