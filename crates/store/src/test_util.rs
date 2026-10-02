//! Helpers shared by the store's tests.

use std::{fs, path::Path, time::SystemTime};

/// Runs each test (an `async fn(Layout)`, with `Layout` in scope) on an object bucket
/// and on a folder bucket.
macro_rules! in_both_layouts {
    ($($name:ident),* $(,)?) => {$(
        mod $name {
            #[tokio::test]
            async fn object_bucket() {
                super::$name(super::Layout::Object).await;
            }

            #[tokio::test]
            async fn folder_bucket() {
                super::$name(super::Layout::Folder).await;
            }
        }
    )*};
}
pub(crate) use in_both_layouts;

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

impl crate::Store {
    /// Opens the drive at `root` keeping every object in a file of its own, never in the
    /// index: for tests that look at, damage or lose the files.
    pub(crate) fn open_files(root: impl AsRef<Path>) -> crate::Result<Self> {
        let options = crate::StoreOptions {
            inline_max: Some(0),
            ..crate::StoreOptions::default()
        };
        Self::open_with(root, options)
    }
}
