//! `teifs doctor`: what would stop `teifs serve`, or make it serve badly, with the same
//! settings: the drive (its format, its databases, whether it's in use, whether it can be
//! written, whether it's on this machine), its disk's room, how its file system treats names, the root keys, the
//! keyring, the TLS certificates and the listen address. Each problem says what to do.
//! Nothing is changed: an older drive isn't upgraded, and checks that would get in a
//! running server's way are skipped while it runs. Exit code 1 when a check fails.

use std::{
    io,
    net::{SocketAddr, TcpListener},
    path::Path,
    time::SystemTime,
};

use teifs_server::{Tls, credentials, default_keyring};
use teifs_store::{Database, Diagnosis, Disk, FORMAT, SYSTEM_DIR};

use crate::{
    ServeArgs,
    checks::{self, Check, State},
    config, error, tls_source,
};

/// `teifs doctor`.
pub(crate) fn doctor(args: &ServeArgs) -> Result<(), error::Error> {
    let checks = checks(args, |name| std::env::var(name).ok());
    checks::finish(&checks, ("drive", &args.dir.display().to_string()))
}

/// Every check, in order, with `env` for the environment.
fn checks(args: &ServeArgs, env: impl Fn(&str) -> Option<String>) -> Vec<Check> {
    let mut checks = Vec::new();
    let dir = &args.dir;
    let diagnosis = if dir.is_dir() {
        teifs_store::diagnose(dir).ok()
    } else {
        checks.push(Check::new(
            "Drive",
            State::Failed,
            format!(
                "there's no folder at {}: make a drive with `teifs init {0}`",
                dir.display()
            ),
        ));
        return checks;
    };
    checks.extend(drive(dir, diagnosis.as_ref()));
    let in_use = diagnosis.as_ref().is_some_and(|d| d.in_use);
    checks.push(file_system(dir));
    checks.push(writable(dir, diagnosis.is_some()));
    checks.push(match Disk::at(dir) {
        Ok(disk) => Check::named(
            "Disk",
            checks::disk(
                &dir.display().to_string(),
                disk.total,
                disk.available,
                disk.reserve,
            ),
        ),
        Err(err) => Check::new(
            "Disk",
            State::Warning,
            format!("can't tell its room: {err}"),
        ),
    });
    checks.push(credentials_check(args, &env));
    let drive_id = diagnosis
        .as_ref()
        .and_then(|d| d.format.as_ref().ok())
        .map(|format| format.drive.clone());
    checks.push(keyring(args, drive_id.as_deref()));
    checks.extend(certificates(args));
    checks.push(listen(args.listen, in_use));
    checks
}

/// The drive: its format, whether it's in use, its databases and how names are told
/// apart; a folder that isn't a drive yet is one when it's first served.
fn drive(dir: &Path, diagnosis: Option<&Diagnosis>) -> Vec<Check> {
    let Some(diagnosis) = diagnosis else {
        return vec![Check::new(
            "Drive",
            State::Ok,
            format!(
                "{} isn't a drive yet: `teifs serve` makes it one",
                dir.display()
            ),
        )];
    };
    let mut checks = vec![match &diagnosis.format {
        Ok(found) if found.format > FORMAT => Check::new(
            "Drive",
            State::Failed,
            format!(
                "a newer TeiFS made it (format {}; this one reads up to {FORMAT}): upgrade teifs",
                found.format
            ),
        ),
        Ok(found) if found.format < FORMAT => Check::new(
            "Drive",
            State::Ok,
            format!(
                "format {}: upgraded to {FORMAT} when it's next served, after a backup",
                found.format
            ),
        ),
        Ok(found) => Check::new(
            "Drive",
            State::Ok,
            format!("{}: drive {}", dir.display(), found.drive),
        ),
        Err(err) => Check::new(
            "Drive",
            State::Failed,
            format!("its format can't be read ({err}): restore a backup (`teifs restore`)"),
        ),
    }];
    checks.push(Check::new(
        "In use",
        State::Ok,
        if diagnosis.in_use {
            "served by another process (a running `teifs serve`): what would get in its way \
             isn't checked"
        } else {
            "by nothing"
        },
    ));
    for (name, database) in [
        ("Index", diagnosis.index),
        ("System database", diagnosis.system),
    ] {
        checks.push(match database {
            Database::Intact => Check::new(name, State::Ok, "intact"),
            Database::Damaged => Check::new(
                name,
                State::Failed,
                "damaged: restore one of the drive's snapshots (`teifs restore --from`)",
            ),
            Database::Missing => Check::new(
                name,
                State::Failed,
                "missing: restore one of the drive's snapshots (`teifs restore --from`)",
            ),
        });
    }
    match diagnosis.case_sensitive {
        Some(true) => checks.push(Check::new("Names", State::Ok, "told apart by case")),
        Some(false) => checks.push(Check::new(
            "Names",
            State::Ok,
            "names that differ only in case are one file here: a folder bucket can't hold \
             keys that differ only in case (object buckets can)",
        )),
        None => {}
    }
    checks
}

/// Whether the drive's folder is on a file system of this machine: one over the network
/// or in user space may not lock, rename or sync files as the drive relies on.
fn file_system(dir: &Path) -> Check {
    match teifs_store::remote_file_system(dir) {
        Ok(None) => Check::new("File system", State::Ok, "on this machine"),
        Ok(Some(kind)) => Check::new(
            "File system",
            State::Warning,
            format!(
                "{kind}, over the network or in user space: its locks, renames and syncs may \
                 not hold as a drive needs; keep the drive on a disk of this machine"
            ),
        ),
        Err(err) => Check::new(
            "File system",
            State::Warning,
            format!("can't tell what it is ({err})"),
        ),
    }
}

/// Whether the drive's folder can be written: a file is made and removed again, where
/// the drive stages its writes (or in the folder, before it's a drive).
fn writable(dir: &Path, drive: bool) -> Check {
    let at = if drive {
        dir.join(SYSTEM_DIR).join("tmp")
    } else {
        dir.to_owned()
    };
    let probe = at.join(format!(".teifs-doctor-{}", std::process::id()));
    let written = std::fs::write(&probe, b"").and_then(|()| std::fs::remove_file(&probe));
    match written {
        Ok(()) => Check::new("Writable", State::Ok, "yes"),
        Err(err) => Check::new(
            "Writable",
            State::Failed,
            format!(
                "can't write to {} ({err}): check its owner and permissions",
                at.display()
            ),
        ),
    }
}

/// The root keys: given (and readable), or the drive's own file, which only its owner
/// should read.
fn credentials_check(args: &ServeArgs, env: &impl Fn(&str) -> Option<String>) -> Check {
    match config::keys(args, env) {
        Err(err) => Check::new("Root keys", State::Failed, err),
        Ok(Some(keys)) => match keys.secret.read() {
            Ok(_) => Check::new(
                "Root keys",
                State::Ok,
                format!("given, the secret {}", keys.secret.describe()),
            ),
            Err(err) => Check::new("Root keys", State::Failed, err),
        },
        Ok(None) => {
            let path = credentials::path(&args.dir);
            if path.exists() {
                private_file("Root keys", &path)
            } else {
                Check::new(
                    "Root keys",
                    State::Ok,
                    format!("made when it's first served, in {}", path.display()),
                )
            }
        }
    }
}

/// The keyring that seals the drive's encryption keys.
fn keyring(args: &ServeArgs, drive: Option<&str>) -> Check {
    if let Some(address) = &args.kms_transit {
        return Check::new(
            "Keyring",
            State::Ok,
            format!("the transit engine at {address} (not asked here)"),
        );
    }
    let path = match (&args.kms_keyring, drive) {
        (Some(path), _) => path.clone(),
        (None, Some(drive)) => match default_keyring(drive) {
            Ok(path) => path,
            Err(err) => return Check::new("Keyring", State::Failed, err.to_string()),
        },
        (None, None) => {
            return Check::new("Keyring", State::Ok, "made when the drive is first served");
        }
    };
    if path.exists() {
        private_file("Keyring", &path)
    } else if drive.is_some() {
        Check::new(
            "Keyring",
            State::Warning,
            format!(
                "there's none at {}: a new one is made when it's served, and objects \
                 encrypted with another can't be read; restore it if there was one",
                path.display()
            ),
        )
    } else {
        Check::new(
            "Keyring",
            State::Ok,
            format!("made when the drive is first served, at {}", path.display()),
        )
    }
}

/// A file holding secrets: only its owner should read it.
fn private_file(name: &'static str, path: &Path) -> Check {
    match readable_by_others(path) {
        Ok(false) => Check::new(name, State::Ok, format!("in {}", path.display())),
        Ok(true) => Check::new(
            name,
            State::Warning,
            format!("{0} can be read by others: `chmod 600 {0}`", path.display()),
        ),
        Err(err) => Check::new(
            name,
            State::Failed,
            format!("can't read {} ({err})", path.display()),
        ),
    }
}

#[cfg(unix)]
fn readable_by_others(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o077 != 0)
}

/// Windows gives a file its folder's access rules: a user's own folders are theirs.
#[cfg(not(unix))]
fn readable_by_others(path: &Path) -> io::Result<bool> {
    std::fs::metadata(path).map(|_| false)
}

/// The TLS certificates: they load (each with its key), and when each expires.
fn certificates(args: &ServeArgs) -> Vec<Check> {
    let source = match tls_source(args) {
        Ok(Some(source)) => source,
        Ok(None) => return Vec::new(),
        Err(err) => return vec![Check::new("Certificate", State::Failed, err)],
    };
    if let Err(err) = Tls::load(source.clone()) {
        return vec![Check::new("Certificate", State::Failed, err.to_string())];
    }
    match source.certificates() {
        Ok(found) => found
            .iter()
            .map(|(path, der)| {
                let (state, detail) = checks::expiry(checks::not_after(der), SystemTime::now());
                Check::new(
                    "Certificate",
                    state,
                    format!("{}: {detail}", path.display()),
                )
            })
            .collect(),
        Err(err) => vec![Check::new("Certificate", State::Failed, err.to_string())],
    }
}

/// Whether `teifs serve` could listen on `address`; not tried while a server runs.
fn listen(address: SocketAddr, in_use: bool) -> Check {
    if in_use {
        return Check::new(
            "Listen",
            State::Ok,
            format!("{address}: not tried while the drive is served"),
        );
    }
    match TcpListener::bind(address) {
        Ok(_) => Check::new("Listen", State::Ok, format!("{address} is free")),
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => Check::new(
            "Listen",
            State::Failed,
            format!("{address} is in use by another program: stop it, or pick another --listen"),
        ),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Check::new(
            "Listen",
            State::Failed,
            format!(
                "can't listen on {address} ({err}): ports below 1024 need privileges; pick \
                 another --listen"
            ),
        ),
        Err(err) => Check::new(
            "Listen",
            State::Failed,
            format!("can't listen on {address} ({err}): pick another --listen"),
        ),
    }
}
