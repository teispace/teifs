use std::io;

/// Why a storage operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The bucket doesn't exist.
    #[error("the bucket doesn't exist")]
    NoSuchBucket,
    /// The object doesn't exist.
    #[error("the object doesn't exist")]
    NoSuchKey,
    /// A bucket with that name already exists.
    #[error("a bucket with that name already exists")]
    BucketExists,
    /// The bucket still holds objects.
    #[error("the bucket isn't empty")]
    BucketNotEmpty,
    /// The name can't be a bucket name.
    #[error("invalid bucket name: {0}")]
    InvalidBucketName(&'static str),
    /// The key can't be stored as a file.
    #[error("invalid object key: {0}")]
    InvalidKey(&'static str),
    /// The key collides with something already on disk: a file where a folder is needed,
    /// a folder where a file is needed, or a name that differs only in letter case on a
    /// case-insensitive disk.
    #[error("the key conflicts with an existing object: {0}")]
    KeyConflict(&'static str),
    /// The multipart upload doesn't exist (finished, aborted or never started).
    #[error("the multipart upload doesn't exist")]
    NoSuchUpload,
    /// A part listed to complete an upload is missing or its ETag doesn't match.
    #[error("a part is missing or its ETag doesn't match")]
    InvalidPart,
    /// The parts to complete an upload aren't in ascending order.
    #[error("the parts must be listed in ascending order")]
    InvalidPartOrder,
    /// A part other than the last is smaller than the minimum part size.
    #[error("a part other than the last is smaller than 5 MiB")]
    EntityTooSmall,
    /// The request can't be done as asked.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// An `If-Match` / `If-None-Match` condition wasn't met.
    #[error("the precondition wasn't met")]
    PreconditionFailed,
    /// The disk failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The metadata database failed.
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
}

/// A storage result.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Maps "not found" to `err`, keeping other I/O errors.
pub(crate) fn not_found_as(err: io::Error, missing: StoreError) -> StoreError {
    if err.kind() == io::ErrorKind::NotFound {
        missing
    } else {
        StoreError::Io(err)
    }
}
