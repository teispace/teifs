//! Size caps a presigned upload link carries: `x-teifs-max-content-length` on a `PutObject`
//! caps its body, and `x-teifs-max-total-object-size` on a `CreateMultipartUpload` caps the
//! whole upload, every part together. They're query parameters, so a Signature V4
//! signature covers them: whoever holds the link can't raise or remove them. They're
//! refused anywhere they wouldn't be signed or wouldn't apply, rather than ignored.

use s3s::{S3Result, s3_error};
use teifs_types::caps::{MAX_CONTENT_LENGTH, MAX_TOTAL_OBJECT_SIZE};

/// The caps a request carries, in its extensions for the operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Caps {
    /// A `PutObject`'s body may be at most this many bytes.
    pub content_length: Option<u64>,
    /// A multipart upload's object may be at most this many bytes.
    pub total_object_size: Option<u64>,
}

impl Caps {
    /// The caps in a request's query, checked against the operation they come with.
    /// `signed_v4`: the request is signed with Signature V4, whose signature covers the
    /// query (Signature V2's doesn't; an anonymous request has none).
    pub(crate) fn of(query: Option<&str>, operation: &str, signed_v4: bool) -> S3Result<Self> {
        let caps = Self::parse(query)?;
        if caps == Self::default() {
            return Ok(caps);
        }
        if !signed_v4 {
            return Err(s3_error!(
                InvalidRequest,
                "Upload size limits apply only to requests signed with Signature V4"
            ));
        }
        let misplaced = match (caps.content_length, caps.total_object_size) {
            (Some(_), _) if operation != "PutObject" => Some(MAX_CONTENT_LENGTH),
            (_, Some(_)) if operation != "CreateMultipartUpload" => Some(MAX_TOTAL_OBJECT_SIZE),
            _ => None,
        };
        match misplaced {
            Some(name) => Err(s3_error!(
                InvalidRequest,
                "{name} doesn't apply to {operation}"
            )),
            None => Ok(caps),
        }
    }

    /// Reads the caps: each at most once, spelled exactly, a whole number of bytes.
    fn parse(query: Option<&str>) -> S3Result<Self> {
        let mut caps = Self::default();
        for (name, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            let slot = if name == MAX_CONTENT_LENGTH {
                &mut caps.content_length
            } else if name == MAX_TOTAL_OBJECT_SIZE {
                &mut caps.total_object_size
            } else if [MAX_CONTENT_LENGTH, MAX_TOTAL_OBJECT_SIZE]
                .iter()
                .any(|cap| name.eq_ignore_ascii_case(cap))
            {
                return Err(s3_error!(
                    InvalidRequest,
                    "{name} must be spelled in lowercase"
                ));
            } else {
                continue;
            };
            let bytes = value
                .bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| value.parse::<u64>().ok())
                .flatten()
                .ok_or_else(|| {
                    s3_error!(InvalidRequest, "{name} must be a whole number of bytes")
                })?;
            if slot.replace(bytes).is_some() {
                return Err(s3_error!(InvalidRequest, "{name} may be given only once"));
            }
        }
        Ok(caps)
    }
}

/// The most one request uploads, as on AWS: a `PutObject`'s body, a part, or what a copy
/// reads from its source. Larger objects are uploaded, or copied, in parts.
pub(crate) const MAX_UPLOAD: u64 = 5 << 30;

/// The most bytes of a body read: its cap, when it has one, and never more than
/// [`MAX_UPLOAD`]. A body declared longer is refused before any of it is read.
pub(crate) fn body_limit(declared: Option<i64>, cap: Option<u64>) -> S3Result<u64> {
    if let Some(cap) = cap {
        admit(declared, cap)?;
    }
    if declared.and_then(|len| u64::try_from(len).ok()) > Some(MAX_UPLOAD) {
        return Err(too_large());
    }
    Ok(cap.map_or(MAX_UPLOAD, |cap| cap.min(MAX_UPLOAD)))
}

/// Refuses a copy that would read more than [`MAX_UPLOAD`] bytes of its source, as AWS
/// does.
pub(crate) fn copy_source(size: u64) -> S3Result<()> {
    if size > MAX_UPLOAD {
        return Err(s3_error!(
            InvalidRequest,
            "The specified copy source is larger than the maximum allowable size for a copy \
             source: {MAX_UPLOAD}"
        ));
    }
    Ok(())
}

/// Checks a body's declared length against a cap before any of it is read: the length
/// must be known, and within the cap.
pub(crate) fn admit(declared: Option<i64>, cap: u64) -> S3Result<()> {
    let declared = declared
        .and_then(|len| u64::try_from(len).ok())
        .ok_or_else(|| {
            s3_error!(
                MissingContentLength,
                "An upload with a size limit needs a Content-Length"
            )
        })?;
    if declared > cap {
        return Err(too_large());
    }
    Ok(())
}

/// AWS's answer to an upload larger than it may be.
pub(crate) fn too_large() -> s3s::S3Error {
    s3_error!(
        EntityTooLarge,
        "Your proposed upload exceeds the maximum allowed size"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(result: S3Result<Caps>) -> String {
        result.unwrap_err().code().as_str().to_owned()
    }

    #[test]
    fn caps_are_read_only_where_signed_and_where_they_apply() {
        let put = |query, v4| Caps::of(Some(query), "PutObject", v4);
        assert_eq!(
            put("x-teifs-max-content-length=10&X-Amz-Signature=s", true).unwrap(),
            Caps {
                content_length: Some(10),
                total_object_size: None
            }
        );
        assert_eq!(
            Caps::of(
                Some("uploads&x-teifs-max-total-object-size=0"),
                "CreateMultipartUpload",
                true
            )
            .unwrap(),
            Caps {
                content_length: None,
                total_object_size: Some(0)
            }
        );
        // Without caps, any request is as it was.
        assert_eq!(Caps::of(None, "GetObject", false).unwrap(), Caps::default());
        assert_eq!(put("partNumber=1", false).unwrap(), Caps::default());
        for (query, operation, v4) in [
            // Not signed, or signed without covering the query.
            ("x-teifs-max-content-length=10", "PutObject", false),
            // Where it doesn't apply.
            ("x-teifs-max-content-length=10", "UploadPart", true),
            ("x-teifs-max-content-length=10", "CopyObject", true),
            (
                "x-teifs-max-content-length=10",
                "CreateMultipartUpload",
                true,
            ),
            ("x-teifs-max-total-object-size=10", "PutObject", true),
            ("x-teifs-max-total-object-size=10", "UploadPart", true),
            (
                "x-teifs-max-total-object-size=10",
                "CompleteMultipartUpload",
                true,
            ),
            // Not a whole number of bytes, or given twice, or spelled otherwise.
            ("x-teifs-max-content-length=", "PutObject", true),
            ("x-teifs-max-content-length=-1", "PutObject", true),
            ("x-teifs-max-content-length=%2B1", "PutObject", true),
            ("x-teifs-max-content-length=1.5", "PutObject", true),
            (
                "x-teifs-max-content-length=18446744073709551616",
                "PutObject",
                true,
            ),
            (
                "x-teifs-max-content-length=1&x-teifs-max-content-length=1",
                "PutObject",
                true,
            ),
            ("X-Teifs-Max-Content-Length=10", "PutObject", true),
        ] {
            assert_eq!(
                code(Caps::of(Some(query), operation, v4)),
                "InvalidRequest",
                "{query}"
            );
        }
        assert_eq!(
            put("x-teifs-max-content-length=18446744073709551615", true)
                .unwrap()
                .content_length,
            Some(u64::MAX)
        );
    }

    #[test]
    fn a_capped_body_declares_its_length_within_the_cap() {
        assert!(admit(Some(10), 10).is_ok());
        assert!(admit(Some(0), 0).is_ok());
        assert_eq!(
            admit(Some(11), 10).unwrap_err().code().as_str(),
            "EntityTooLarge"
        );
        assert_eq!(
            admit(None, 10).unwrap_err().code().as_str(),
            "MissingContentLength"
        );
        assert_eq!(
            admit(Some(-1), 10).unwrap_err().code().as_str(),
            "MissingContentLength"
        );
    }

    #[test]
    fn nothing_uploads_more_than_s3_takes_at_once() {
        let max = i64::try_from(MAX_UPLOAD).unwrap();
        assert_eq!(MAX_UPLOAD, 5_368_709_120);
        assert_eq!(body_limit(Some(max), None).unwrap(), MAX_UPLOAD);
        assert_eq!(body_limit(None, None).unwrap(), MAX_UPLOAD);
        assert_eq!(body_limit(Some(3), Some(10)).unwrap(), 10);
        assert_eq!(body_limit(Some(3), Some(u64::MAX)).unwrap(), MAX_UPLOAD);
        for (declared, cap) in [(Some(max + 1), None), (Some(max + 1), Some(u64::MAX))] {
            let err = body_limit(declared, cap).unwrap_err();
            assert_eq!(
                err.code().as_str(),
                "EntityTooLarge",
                "{declared:?} {cap:?}"
            );
        }
        assert_eq!(
            body_limit(None, Some(10)).unwrap_err().code().as_str(),
            "MissingContentLength"
        );
        assert!(copy_source(MAX_UPLOAD).is_ok());
        let err = copy_source(MAX_UPLOAD + 1).unwrap_err();
        assert_eq!(err.code().as_str(), "InvalidRequest");
        assert_eq!(
            err.message(),
            Some(
                "The specified copy source is larger than the maximum allowable size for a \
                 copy source: 5368709120"
            )
        );
    }
}
