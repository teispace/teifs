//! The drive's S3 credentials: from `TEIDRIVE_ACCESS_KEY` / `TEIDRIVE_SECRET_KEY`, or
//! generated once and kept in `.teidrive/credentials.json`, readable only by the owner.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// An access key and its secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

/// Where a drive keeps its generated credentials.
pub fn path(drive: &Path) -> PathBuf {
    drive
        .join(teidrive_store::SYSTEM_DIR)
        .join("credentials.json")
}

/// The credentials, and whether they were just created.
pub fn load_or_create(drive: &Path) -> io::Result<(Credentials, bool)> {
    let path = path(drive);
    match fs::read(&path) {
        Ok(bytes) => {
            let credentials = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok((credentials, false))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let credentials = generate();
            write_private(
                &path,
                &serde_json::to_vec_pretty(&credentials).expect("credentials serialize"),
            )?;
            Ok((credentials, true))
        }
        Err(err) => Err(err),
    }
}

fn generate() -> Credentials {
    let random = || uuid::Uuid::new_v4().simple().to_string();
    Credentials {
        // 20 characters, like AWS access keys.
        access_key: format!("TD{}", &random()[..18]).to_uppercase(),
        // 256 random bits.
        secret_key: format!("{}{}", random(), random()),
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // The drive's folder is the user's own; ACLs are inherited from it.
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_once_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(teidrive_store::SYSTEM_DIR)).unwrap();
        let (first, created) = load_or_create(dir.path()).unwrap();
        assert!(created);
        assert_eq!(first.access_key.len(), 20);
        assert_eq!(first.secret_key.len(), 64);
        let (second, created) = load_or_create(dir.path()).unwrap();
        assert!(!created);
        assert_eq!(second.secret_key, first.secret_key);
        assert!(!format!("{first:?}").contains(&first.secret_key));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path(dir.path())).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
