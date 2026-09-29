//! Shared TeiFS types with no I/O: bucket names and object keys with their rules, what
//! is known about an object, and ETags.

mod acl;
mod names;
mod object;

pub use acl::{Acl, AclGrant, Grantee, OWNER_ID, Permission};
pub use names::{
    BUCKET_STAGING, MAX_KEY_LEN, MAX_SEGMENT_LEN, NameError, ObjectKey, check_bucket,
    check_folder_bucket, check_object_key,
};
pub use object::{
    ChecksumType, ObjectAttrs, ObjectInfo, PartInfo, SseInfo, SseMode, Stamp, UploadChecksum,
    empty_etag, hex, md5_of_etag, multipart_etag, provisional_etag,
};
