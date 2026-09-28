//! Files only their owner can read: keyrings, credentials and client aliases.

use std::{fs, io, path::Path};

/// Writes `bytes` to a new file at `path` that only its owner can read (0600 on Unix; on
/// other systems it inherits the folder's permissions), synced to disk. Fails if `path`
/// exists.
pub fn create_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Replaces the file at `path` with `bytes`, owner-only as [`create_private`] makes it:
/// written beside it and renamed over it, so a crash leaves the old or the new contents.
pub fn replace_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    create_private(&tmp, bytes)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_are_owner_only_and_replaced_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        create_private(&path, b"one").unwrap();
        assert_eq!(
            create_private(&path, b"two").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        replace_private(&path, b"three").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"three");
        assert!(!path.with_extension("tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
