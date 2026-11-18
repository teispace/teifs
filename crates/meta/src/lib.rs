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
mod heal_queue;
mod iam;
mod index;
mod mirror;
mod replicated_deletes;
mod replication_resyncs;
#[cfg(test)]
mod schemas;
mod system;
mod usage;
mod versions;

pub use db::{backup, intact};
pub use heal_queue::{PARKED, QueuedHeal};
pub use iam::{
    AccessKeyRow, GroupRow, IamRows, IamWrite, InlineRow, LdapParentRow, LdapPolicyRow,
    LdapSessionRow, OidcProviderRow, PolicyRow, PolicyVersionRow, RevocationRow, RoleRow,
    SamlKeyRow, SamlProviderRow, ServiceAccountRow, UserRow,
};
pub use index::{CompletedUpload, Index, Part, Row, Upload};
pub use mirror::{Copies, CopyState, Opened};
pub use replicated_deletes::QueuedDelete;
pub use system::{BucketRecord, Layout, System, Versioning};
pub use usage::{Usage, Usages};
pub use versions::{NULL_VERSION, VersionRow, VersionsFrom, other_form, same_version};

/// Why a metadata database failed.
#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    /// SQLite failed.
    #[error(transparent)]
    Sqlite(rusqlite::Error),
    /// On a drive set, too few copies of the database are current for a change to be
    /// kept safely: it was refused, and nothing changed.
    #[error("too few of the drive set's copies of the database are current to change it")]
    TooFewCopies,
    /// The database was written by a newer TeiFS.
    #[error("the database has schema version {found}, newer than this TeiFS knows ({known})")]
    NewerSchema {
        /// The version in the file.
        found: i64,
        /// The newest version this build knows.
        known: i64,
    },
    /// Too few copies of a database (on a drive set) could be opened.
    #[error("only {found} copies of the database could be opened; {needed} are needed")]
    Copies {
        /// Copies opened.
        found: usize,
        /// Copies needed.
        needed: usize,
    },
    /// A change reached too few copies of a database: it's kept on those it reached.
    #[error("a change reached {current} copies of the database; {needed} are needed")]
    Quorum {
        /// Copies holding the change, the primary included.
        current: usize,
        /// Copies needed.
        needed: usize,
    },
    /// A table whose rows can't be copied (no key, or a key of more than 4 columns).
    #[error("table {0} can't be copied to other drives")]
    Unmirrorable(String),
    /// A file operation on a copy failed.
    #[error(transparent)]
    Io(std::io::Error),
}

impl From<rusqlite::Error> for MetaError {
    fn from(err: rusqlite::Error) -> Self {
        match &err {
            rusqlite::Error::SqliteFailure(_, Some(message)) if message == mirror::BLOCKED => {
                Self::TooFewCopies
            }
            _ => Self::Sqlite(err),
        }
    }
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
