//! Store errors as S3 errors, and request bodies that failed mid-stream.

use s3s::{S3Error, S3ErrorCode, StdError, s3_error, stream::upload_stream::UploadStreamError};
use teifs_store::{NameError, StoreError};

/// Maps a store error to the S3 error a client expects.
pub(crate) fn from_store(err: StoreError) -> S3Error {
    if err.is_storage_full() {
        tracing::warn!(error = %err, "the disk is full; writes are refused until space is freed");
        let mut full = S3Error::with_message(
            S3ErrorCode::Custom("XTeiFSStorageFull".into()),
            "The disk is full. Delete objects or free space on the drive, then retry.",
        );
        full.set_status_code(http::StatusCode::INSUFFICIENT_STORAGE);
        return full;
    }
    match err {
        StoreError::NoSuchBucket => s3_error!(NoSuchBucket),
        StoreError::NoSuchKey => s3_error!(NoSuchKey),
        StoreError::BucketExists => s3_error!(BucketAlreadyOwnedByYou),
        StoreError::BucketNotEmpty => s3_error!(BucketNotEmpty),
        StoreError::InvalidName(NameError::InvalidBucketName(why)) => {
            s3_error!(InvalidBucketName, "{why}")
        }
        StoreError::InvalidName(NameError::KeyTooLong) => s3_error!(KeyTooLongError),
        StoreError::InvalidName(NameError::InvalidKey(why)) => {
            s3_error!(InvalidArgument, "invalid key: {why}")
        }
        StoreError::KeyConflict(why) => {
            let mut err =
                S3Error::with_message(S3ErrorCode::Custom("XTeiFSKeyConflict".into()), why);
            err.set_status_code(http::StatusCode::CONFLICT);
            err
        }
        StoreError::NoSuchUpload => s3_error!(NoSuchUpload),
        StoreError::InvalidPart => s3_error!(InvalidPart),
        StoreError::InvalidPartOrder => s3_error!(InvalidPartOrder),
        StoreError::EntityTooSmall => s3_error!(EntityTooSmall),
        StoreError::EntityTooLarge => crate::caps::too_large(),
        StoreError::InvalidRequest(why) => s3_error!(InvalidRequest, "{why}"),
        StoreError::TooManyTags(max) => {
            s3_error!(InvalidTag, "The tag set can't have more than {max} tags")
        }
        StoreError::PreconditionFailed => s3_error!(PreconditionFailed),
        StoreError::AclsDisabled => crate::acl::not_supported(),
        StoreError::AclGrantsOthers => crate::acl::invalid_with_ownership(),
        StoreError::CustomerKeyRequired => s3_error!(
            InvalidRequest,
            "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object."
        ),
        StoreError::WrongCustomerKey => s3_error!(
            InvalidRequest,
            "The provided encryption parameters did not match the ones used originally to encrypt the object."
        ),
        StoreError::CustomerKeyNotApplicable => s3_error!(
            InvalidRequest,
            "The encryption parameters are not applicable to this object."
        ),
        StoreError::IdempotencyMismatch => {
            let mut err = S3Error::with_message(
                S3ErrorCode::Custom("IdempotencyParameterMismatch".into()),
                "Parameters on this idempotent request are inconsistent with parameters used in previous request(s).",
            );
            err.set_status_code(http::StatusCode::BAD_REQUEST);
            err
        }
        StoreError::NoKms => s3_error!(
            NotImplemented,
            "encryption at rest needs a KMS, and none is configured"
        ),
        StoreError::Crypto(teifs_store::CryptoError::NoSuchKey(key)) => {
            let mut err = S3Error::with_message(
                S3ErrorCode::Custom("KMS.NotFoundException".into()),
                format!("KMS key {key} doesn't exist"),
            );
            err.set_status_code(http::StatusCode::BAD_REQUEST);
            err
        }
        err @ (StoreError::Io(_)
        | StoreError::Meta(_)
        | StoreError::StorageFull
        | StoreError::DriveInUse
        | StoreError::Crypto(_)
        | StoreError::CorruptMetadata
        | StoreError::NewerFormat { .. }
        | StoreError::CorruptFormat(_)) => {
            tracing::error!(error = %err, "storage failed");
            S3Error::with_source(S3ErrorCode::InternalError, Box::new(err))
        }
    }
}

/// Maps an error reading a request body: a checksum or signature that didn't match, a
/// body cut short, too large, or stalled, keep their S3 codes.
pub(crate) fn from_body(err: StdError) -> S3Error {
    if crate::limits::is_stalled(&*err) {
        return S3Error::with_source(S3ErrorCode::RequestTimeout, err);
    }
    if err.is::<s3s::BodySizeLimitExceeded>() {
        return S3Error::with_source(S3ErrorCode::EntityTooLarge, err);
    }
    if let Some(e) = err.downcast_ref::<UploadStreamError>() {
        if matches!(e, UploadStreamError::Sha256Mismatch) {
            // AWS's answer when the body isn't what `x-amz-content-sha256` signed (s3s
            // would say `BadDigest`, which is about Content-MD5).
            let mut s3 = S3Error::with_message(
                S3ErrorCode::Custom("XAmzContentSHA256Mismatch".into()),
                "The provided 'x-amz-content-sha256' header does not match what was computed.",
            );
            s3.set_status_code(http::StatusCode::BAD_REQUEST);
            s3.set_source(err);
            return s3;
        }
        return S3Error::with_source(e.to_s3_error_code(), err);
    }
    if let Some(e) = err.downcast_ref::<s3s::stream::aws_chunked_stream::AwsChunkedStreamError>() {
        return S3Error::with_source(e.to_s3_error_code(), err);
    }
    S3Error::with_source(S3ErrorCode::IncompleteBody, err)
}

/// `?` for store results inside S3 handlers.
pub(crate) trait StoreResultExt<T> {
    fn s3(self) -> s3s::S3Result<T>;
}

impl<T> StoreResultExt<T> for Result<T, StoreError> {
    fn s3(self) -> s3s::S3Result<T> {
        self.map_err(from_store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_that_isnt_what_was_signed_is_awss_mismatch() {
        let s3 = from_body(Box::new(UploadStreamError::Sha256Mismatch));
        assert_eq!(s3.code().as_str(), "XAmzContentSHA256Mismatch");
        assert_eq!(s3.status_code(), Some(http::StatusCode::BAD_REQUEST));
        let short = from_body(Box::new(UploadStreamError::Incomplete));
        assert_eq!(short.code().as_str(), "IncompleteBody");
    }

    #[test]
    fn a_full_disk_is_507_whatever_noticed_it() {
        for err in [
            StoreError::StorageFull,
            StoreError::Io(std::io::Error::from(std::io::ErrorKind::StorageFull)),
            StoreError::Io(std::io::Error::from(std::io::ErrorKind::QuotaExceeded)),
        ] {
            let s3 = from_store(err);
            assert_eq!(s3.code().as_str(), "XTeiFSStorageFull");
            assert_eq!(
                s3.status_code(),
                Some(http::StatusCode::INSUFFICIENT_STORAGE)
            );
        }
        let other = from_store(StoreError::Io(std::io::Error::other("broken")));
        assert_eq!(other.code().as_str(), "InternalError");
    }
}
