use std::io;

use teifs_meta::MetaError;
use teifs_types::NameError;

/// Why a storage operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The bucket doesn't exist.
    #[error("the bucket doesn't exist")]
    NoSuchBucket,
    /// The object doesn't exist.
    #[error("the object doesn't exist")]
    NoSuchKey,
    /// The version doesn't exist.
    #[error("the version doesn't exist")]
    NoSuchVersion,
    /// The version asked for, or the current one, is a delete marker, which has no
    /// content.
    #[error("the object's version is a delete marker")]
    DeleteMarker {
        /// The marker's version id (`None` where versions aren't named).
        version_id: Option<String>,
        /// When the marker was added.
        modified: std::time::SystemTime,
        /// Whether the request named the marker's version (else it's the current one).
        named: bool,
    },
    /// A bucket with that name already exists.
    #[error("a bucket with that name already exists")]
    BucketExists,
    /// The bucket still holds objects.
    #[error("the bucket isn't empty")]
    BucketNotEmpty,
    /// The bucket name or object key breaks the rules.
    #[error(transparent)]
    InvalidName(#[from] NameError),
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
    /// An upload's parts are larger, all together, than its creation allowed.
    #[error("the upload is larger than its size limit")]
    EntityTooLarge,
    /// The request can't be done as asked.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// TeiFS doesn't do this (yet).
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    /// Adding tags would leave more than this many.
    #[error("more than {0} tags")]
    TooManyTags(usize),
    /// The bucket's Object Ownership (`BucketOwnerEnforced`) disables ACLs.
    #[error("the bucket's Object Ownership disables ACLs")]
    AclsDisabled,
    /// `BucketOwnerEnforced` was asked for while the bucket's ACL grants someone besides
    /// the owner.
    #[error("the bucket's ACL grants others, so ACLs can't be disabled")]
    AclGrantsOthers,
    /// The bucket's state doesn't allow the change (Object Lock without versioning
    /// enabled, or suspending versioning under Object Lock).
    #[error("the bucket's state doesn't allow this: {0}")]
    InvalidBucketState(&'static str),
    /// Object Lock protects the version: a legal hold, or a retention that isn't
    /// bypassed.
    #[error("the object version is protected by Object Lock")]
    ObjectLocked,
    /// An `If-Match` / `If-None-Match` condition wasn't met.
    #[error("the precondition wasn't met")]
    PreconditionFailed,
    /// The object kept changing while it was being changed: trying again may work.
    #[error("the object changed while it was being changed; try again")]
    ChangedMeanwhile,
    /// The drive was formatted by a newer TeiFS.
    #[error(
        "this drive was formatted by a newer TeiFS (format {found}); upgrade TeiFS, or restore a backup made by this version"
    )]
    NewerFormat {
        /// The drive's format.
        found: u32,
    },
    /// `.teifs/format.json` can't be read.
    #[error("the drive's format file (.teifs/format.json) is damaged: {0}")]
    CorruptFormat(String),
    /// A snapshot can't be restored onto this drive.
    #[error("that snapshot can't be restored here: {0}")]
    BadSnapshot(String),
    /// The object is encrypted with a customer key (SSE-C) and the request has none.
    #[error("the object is encrypted with a customer-provided key; send that key")]
    CustomerKeyRequired,
    /// The customer key isn't the one the object was encrypted with.
    #[error("the customer-provided key isn't the object's key")]
    WrongCustomerKey,
    /// A customer key was sent for an object that isn't encrypted with one.
    #[error("the object isn't encrypted with a customer-provided key")]
    CustomerKeyNotApplicable,
    /// A client token was reused for a different request.
    #[error("the client token was already used for a different request")]
    IdempotencyMismatch,
    /// Encryption was asked for but no KMS is configured.
    #[error("encryption needs a KMS, and none is configured")]
    NoKms,
    /// Another process has the drive open (a running `teifs serve`, say).
    #[error("the drive is in use by another TeiFS process")]
    DriveInUse,
    /// The disk is too full for the write (TeiFS keeps a little room free so deletes
    /// keep working).
    #[error("the disk is full")]
    StorageFull,
    /// Recorded metadata can't be read (damaged or from a newer TeiFS).
    #[error("the object's recorded metadata is damaged")]
    CorruptMetadata,
    /// Encryption failed: a wrong key, damaged data, or a KMS error.
    #[error(transparent)]
    Crypto(#[from] teifs_crypto::CryptoError),
    /// The disk failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The metadata index failed.
    #[error(transparent)]
    Meta(#[from] MetaError),
}

impl StoreError {
    /// Whether the write failed for want of space: the disk, the user's quota, or the
    /// room TeiFS keeps free.
    #[must_use]
    pub fn is_storage_full(&self) -> bool {
        match self {
            Self::StorageFull => true,
            Self::Io(err) => matches!(
                err.kind(),
                io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded
            ),
            Self::Meta(err) => err.is_storage_full(),
            _ => false,
        }
    }
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
