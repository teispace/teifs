//! Shared TeiFS types with no I/O: bucket names and object keys with their rules, what
//! is known about an object, ETags, integrity checks' verdicts, and the admin API's messages.

mod acl;
pub mod admin;
pub mod audit;
pub mod caps;
pub mod config_kv;
pub mod configs;
pub mod logging;
mod names;
pub mod notify;
mod object;
pub mod replication;
pub mod verify;
pub mod website;

pub use acl::{Acl, AclCaller, AclGrant, Grantee, OWNER_ID, Permission};
pub use names::{
    BUCKET_STAGING, MAX_KEY_LEN, MAX_SEGMENT_LEN, NameError, ObjectKey, check_bucket,
    check_folder_bucket, check_object_key,
};
pub use object::{
    ChecksumType, LockMode, ObjectAttrs, ObjectInfo, PartInfo, Retention, SseInfo, SseMode, Stamp,
    UploadChecksum, empty_etag, hex, hex_byte, md5_of_etag, multipart_etag, provisional_etag,
    unhex,
};
