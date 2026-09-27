//! Helpers shared by the store's tests.

use std::{fs, path::Path, time::SystemTime};

/// Sets a folder's modification time (to make it look settled, say).
pub(crate) fn set_folder_modified(path: &Path, time: SystemTime) {
    folder_handle(path).set_modified(time).unwrap();
}

#[cfg(windows)]
fn folder_handle(path: &Path) -> fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    // A folder opens only with backup semantics; setting its times needs write access
    // to its attributes.
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap()
}

#[cfg(not(windows))]
fn folder_handle(path: &Path) -> fs::File {
    fs::File::open(path).unwrap()
}
