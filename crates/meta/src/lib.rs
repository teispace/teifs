//! TeiFS's metadata in SQLite, in two databases per drive:
//!
//! - the **index** (`index.db`): what S3 needs that a file system doesn't keep (ETags,
//!   content types, user metadata, checksums) and multipart uploads in progress. Files
//!   stay the source of truth: a row applies only while its file's [`Stamp`] matches, and
//!   the whole index can be rebuilt from the disk.
//! - the **system** database (`system.db`): what can't be rebuilt from files (bucket
//!   settings now; users, keys and policies later). It's backed up before every
//!   migration.
//!
//! All SQL lives in this crate.
//!
//! [`Stamp`]: teifs_types::Stamp

mod db;
mod index;
mod system;
mod versions;

pub use db::backup;
pub use index::{Index, Part, Row, Upload};
pub use system::{BucketRecord, Layout, System};
pub use versions::{ListFrom, NULL_VERSION, VersionRow};

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

/// A metadata result.
pub type Result<T, E = MetaError> = std::result::Result<T, E>;
