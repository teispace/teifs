//! Upload size caps a Signature V4 signed request can carry in its query, where the
//! signature covers them: the server enforces them and the command line signs them in.

/// On a `PutObject`: its body may be at most this many bytes.
pub const MAX_CONTENT_LENGTH: &str = "x-teifs-max-content-length";
/// On a `CreateMultipartUpload`: the upload's object, all parts together, may be at most
/// this many bytes.
pub const MAX_TOTAL_OBJECT_SIZE: &str = "x-teifs-max-total-object-size";
