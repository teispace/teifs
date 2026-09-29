//! TeiFS's metadata in SQLite, in two databases per drive:
//!
//! - the **index** (`index.db`): what S3 needs that a file system doesn't keep (ETags,
//!   content types, user metadata, checksums) and multipart uploads in progress. Files
//!   stay the source of truth: a row applies only while its file's [`Stamp`] matches, and
//!   the whole index can be rebuilt from the disk.
//! - the **system** database (`system.db`): what can't be rebuilt from files (bucket
//!   settings, and IAM's users, access keys, groups and policies). It's backed up before
//!   every migration.
//!
//! All SQL lives in this crate.
//!
//! [`Stamp`]: teifs_types::Stamp

mod db;
mod iam;
mod index;
mod system;
mod versions;

pub use db::backup;
pub use iam::{
    AccessKeyRow, GroupRow, IamRows, IamWrite, InlineRow, OidcProviderRow, PolicyRow,
    PolicyVersionRow, RoleRow, UserRow,
};
pub use index::{CompletedUpload, Index, Part, Row, Upload};
pub use system::{BucketRecord, Layout, System, Versioning};
pub use versions::{NULL_VERSION, VersionRow, VersionsFrom};

/// Why a metadata database failed.
#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    /// SQLite failed.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// The database was written by a newer TeiFS.
    #[error("the database has schema version {found}, newer than this TeiFS knows ({known})")]
    NewerSchema {
        /// The version in the file.
        found: i64,
        /// The newest version this build knows.
        known: i64,
    },
}

impl MetaError {
    /// Whether the disk (or the user's quota) is full.
    #[must_use]
    pub fn is_storage_full(&self) -> bool {
        matches!(
            self,
            Self::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DiskFull
        )
    }
}

/// A metadata result.
pub type Result<T, E = MetaError> = std::result::Result<T, E>;
