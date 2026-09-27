//! Shared TeiFS types with no I/O: bucket names and object keys with their rules, what
//! is known about an object, and ETags.

mod names;
mod object;

pub use names::{MAX_KEY_LEN, MAX_SEGMENT_LEN, NameError, ObjectKey, check_bucket};
pub use object::{
    ObjectAttrs, ObjectInfo, Stamp, empty_etag, hex, md5_of_etag, multipart_etag, provisional_etag,
};
