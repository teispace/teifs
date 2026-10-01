//! Whether a folder is on a file system a drive shouldn't live on: one reached over the
//! network (NFS, SMB, AFP, `WebDAV`, 9P, Ceph…) or one served in user space (FUSE). Their
//! locks, renames and `fsync` may not hold as the drive relies on them, and SQLite warns
//! against them for the same reason.

use std::{io, path::Path};

/// What kind of file system `path` is on, when it's reached over the network or served
/// in user space: its name (`nfs`, `smbfs`, `fuse`…); `None` when it's on this machine.
pub fn remote_file_system(path: &Path) -> io::Result<Option<String>> {
    remote(path)
}

#[cfg(target_os = "linux")]
fn remote(path: &Path) -> io::Result<Option<String>> {
    let stats = rustix::fs::statfs(path)?;
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::unnecessary_cast,
        reason = "the magic numbers are 32 bits; f_type's width differs by architecture"
    )]
    let magic = stats.f_type as u32;
    Ok(linux_kind(magic).map(str::to_owned))
}

/// The remote and user-space file systems by their `statfs` magic number
/// (`linux/magic.h`, `fs/smb/client/cifsglob.h`).
#[cfg(any(target_os = "linux", test))]
fn linux_kind(magic: u32) -> Option<&'static str> {
    Some(match magic {
        0x6969 => "nfs",
        0x517B | 0xFF53_4D42 | 0xFE53_4D42 => "smb",
        0x6573_5546 => "fuse",
        0x0102_1997 => "9p",
        0x00C3_6400 => "ceph",
        0x5346_414F => "afs",
        0x7375_7245 => "coda",
        0x564C => "ncp",
        0x0BD0_0BD0 => "lustre",
        0x4750_4653 => "gpfs",
        _ => return None,
    })
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn remote(path: &Path) -> io::Result<Option<String>> {
    /// `MNT_LOCAL` (`sys/mount.h`): the file system is on this machine.
    const MNT_LOCAL: u64 = 0x1000;
    let stats = rustix::fs::statfs(path)?;
    let name: Vec<u8> = stats
        .f_fstypename
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c.to_ne_bytes()[0])
        .collect();
    let name = String::from_utf8_lossy(&name).into_owned();
    Ok(bsd_kind(&name, u64::from(stats.f_flags) & MNT_LOCAL != 0).then_some(name))
}

/// Whether a BSD file system named `name`, marked local or not, is remote or FUSE's.
#[cfg(any(target_os = "macos", target_os = "freebsd", test))]
fn bsd_kind(name: &str, local: bool) -> bool {
    !local || name.contains("fuse")
}

/// Windows: a UNC path (`\\server\share`, `\\?\UNC\…`) is a share on the network.
#[cfg(windows)]
fn remote(path: &Path) -> io::Result<Option<String>> {
    use std::path::{Component, Prefix};
    std::fs::metadata(path)?;
    Ok(match path.components().next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::UNC(..) | Prefix::VerbatimUNC(..)) =>
        {
            Some("smb".to_owned())
        }
        _ => None,
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
fn remote(path: &Path) -> io::Result<Option<String>> {
    std::fs::metadata(path).map(|_| None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_here_is_on_this_machine() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(remote_file_system(dir.path()).unwrap(), None);
        assert!(remote_file_system(&dir.path().join("gone")).is_err());
    }

    #[test]
    fn remote_file_systems_are_told_apart() {
        assert_eq!(linux_kind(0x6969), Some("nfs"));
        assert_eq!(linux_kind(0xFF53_4D42), Some("smb"));
        assert_eq!(linux_kind(0x6573_5546), Some("fuse"));
        // ext4, XFS, btrfs, tmpfs, overlayfs.
        for local in [0xEF53, 0x5846_5342, 0x9123_683E, 0x0102_1994, 0x794C_7630] {
            assert_eq!(linux_kind(local), None);
        }
        assert!(bsd_kind("nfs", false));
        assert!(bsd_kind("macfuse", true));
        assert!(!bsd_kind("apfs", true));
    }
}
