//! Store errors as S3 errors, and request bodies that failed mid-stream.

use s3s::{S3Error, S3ErrorCode, StdError, s3_error};
use teidrive_store::StoreError;

/// Maps a store error to the S3 error a client expects.
pub(crate) fn from_store(err: StoreError) -> S3Error {
    match err {
        StoreError::NoSuchBucket => s3_error!(NoSuchBucket),
        StoreError::NoSuchKey => s3_error!(NoSuchKey),
        StoreError::BucketExists => s3_error!(BucketAlreadyOwnedByYou),
        StoreError::BucketNotEmpty => s3_error!(BucketNotEmpty),
        StoreError::InvalidBucketName(why) => s3_error!(InvalidBucketName, "{why}"),
        StoreError::InvalidKey(why) if why.contains("1024") => s3_error!(KeyTooLongError),
        StoreError::InvalidKey(why) => s3_error!(InvalidArgument, "invalid key: {why}"),
        StoreError::KeyConflict(why) => {
            let mut err =
                S3Error::with_message(S3ErrorCode::Custom("XTeiDriveKeyConflict".into()), why);
            err.set_status_code(http::StatusCode::CONFLICT);
            err
        }
        StoreError::NoSuchUpload => s3_error!(NoSuchUpload),
        StoreError::InvalidPart => s3_error!(InvalidPart),
        StoreError::InvalidPartOrder => s3_error!(InvalidPartOrder),
        StoreError::EntityTooSmall => s3_error!(EntityTooSmall),
        StoreError::InvalidRequest(why) => s3_error!(InvalidRequest, "{why}"),
        StoreError::PreconditionFailed => s3_error!(PreconditionFailed),
        err @ (StoreError::Io(_) | StoreError::Db(_)) => {
            tracing::error!(error = %err, "storage failed");
            S3Error::with_source(S3ErrorCode::InternalError, Box::new(err))
        }
    }
}

/// Maps an error reading a request body: a checksum or signature that didn't match, a
/// body cut short, or one too large, keep their S3 codes.
pub(crate) fn from_body(err: StdError) -> S3Error {
    if err.is::<s3s::BodySizeLimitExceeded>() {
        return S3Error::with_source(S3ErrorCode::EntityTooLarge, err);
    }
    if let Some(e) = err.downcast_ref::<s3s::stream::upload_stream::UploadStreamError>() {
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
