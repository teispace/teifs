//! The drive's S3 credentials: from `TEIFS_ACCESS_KEY` / `TEIFS_SECRET_KEY`, or
//! generated once and kept in `.teifs/credentials.json`, readable only by the owner.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// An access key and its secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    /// The access key id.
    pub access_key: String,
    /// The secret key. Never logged: `Debug` leaves it out.
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
#[must_use]
pub fn path(drive: &Path) -> PathBuf {
    drive.join(teifs_store::SYSTEM_DIR).join("credentials.json")
}

/// The credentials a drive generated, if it has.
pub fn load(drive: &Path) -> io::Result<Option<Credentials>> {
    match fs::read(path(drive)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// The credentials, and whether they were just created.
pub fn load_or_create(drive: &Path) -> io::Result<(Credentials, bool)> {
    if let Some(credentials) = load(drive)? {
        return Ok((credentials, false));
    }
    let credentials = generate();
    teifs_store::create_private(
        &path(drive),
        &serde_json::to_vec_pretty(&credentials).expect("credentials serialize"),
    )?;
    Ok((credentials, true))
}

/// The credentials a drive set generated, kept on each of its drives (`drives`, the
/// ones that are up): those of the first drive that has them, copied to the others
/// that don't; generated and written to all of them on first use.
pub fn load_or_create_on(drives: &[PathBuf]) -> io::Result<(Credentials, bool)> {
    // A damaged copy on one drive doesn't hide the others.
    let found = drives.iter().find_map(|drive| load(drive).ok().flatten());
    let created = found.is_none();
    let credentials = found.unwrap_or_else(generate);
    let json = zeroize::Zeroizing::new(
        serde_json::to_vec_pretty(&credentials).expect("credentials serialize"),
    );
    for drive in drives {
        if !matches!(load(drive), Ok(Some(_))) {
            teifs_store::replace_private(&path(drive), &json)?;
        }
    }
    Ok((credentials, created))
}

/// The drive's generated credentials, which the admin API may replace.
#[derive(Debug)]
pub(crate) struct DriveKeys {
    /// The drive's folder (on a drive set, every up drive's).
    pub(crate) drives: Vec<PathBuf>,
}

impl teifs_s3::RootKeyStore for DriveKeys {
    fn generate(&self) -> teifs_iam::RootKey {
        let credentials = generate();
        teifs_iam::RootKey {
            access_key: credentials.access_key,
            secret: zeroize::Zeroizing::new(credentials.secret_key),
        }
    }

    fn save(&self, key: &teifs_iam::RootKey) -> io::Result<()> {
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec_pretty(&Credentials {
                access_key: key.access_key.clone(),
                secret_key: key.secret.to_string(),
            })
            .expect("credentials serialize"),
        );
        for drive in &self.drives {
            teifs_store::replace_private(&path(drive), &json)?;
        }
        Ok(())
    }
}

fn generate() -> Credentials {
    let random = || uuid::Uuid::new_v4().simple().to_string();
    Credentials {
        // 20 characters, like AWS access keys.
        access_key: format!("TF{}", &random()[..18]).to_uppercase(),
        // 256 random bits.
        secret_key: format!("{}{}", random(), random()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_once_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(teifs_store::SYSTEM_DIR)).unwrap();
        let (first, created) = load_or_create(dir.path()).unwrap();
        assert!(created);
        assert_eq!(first.access_key.len(), 20);
        assert_eq!(first.secret_key.len(), 64);
        let (second, created) = load_or_create(dir.path()).unwrap();
        assert!(!created);
        assert_eq!(second.secret_key, first.secret_key);
        assert!(!format!("{first:?}").contains(&first.secret_key));
        // A replaced key is what the drive reads next time.
        let keys = DriveKeys {
            drives: vec![dir.path().to_owned()],
        };
        let new = teifs_s3::RootKeyStore::generate(&keys);
        assert_ne!(new.access_key, first.access_key);
        teifs_s3::RootKeyStore::save(&keys, &new).unwrap();
        let (third, created) = load_or_create(dir.path()).unwrap();
        assert!(!created);
        assert_eq!(
            (third.access_key.as_str(), third.secret_key.as_str()),
            (new.access_key.as_str(), new.secret.as_str())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path(dir.path())).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn a_drive_set_keeps_them_on_every_drive() {
        let dir = tempfile::tempdir().unwrap();
        let drives: Vec<PathBuf> = (0..3)
            .map(|i| {
                let d = dir.path().join(format!("d{i}"));
                fs::create_dir_all(d.join(teifs_store::SYSTEM_DIR)).unwrap();
                d
            })
            .collect();
        let (first, created) = load_or_create_on(&drives).unwrap();
        assert!(created);
        for d in &drives {
            assert_eq!(load(d).unwrap().unwrap().secret_key, first.secret_key);
        }
        // Lost from two drives (one replaced, one damaged): the third's are kept and
        // copied back.
        fs::remove_file(path(&drives[0])).unwrap();
        fs::write(path(&drives[1]), b"{").unwrap();
        let (again, created) = load_or_create_on(&drives).unwrap();
        assert!(!created);
        assert_eq!(again.secret_key, first.secret_key);
        for d in &drives {
            assert_eq!(load(d).unwrap().unwrap().secret_key, first.secret_key);
        }
    }
}
