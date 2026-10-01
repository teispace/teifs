//! What a copy carries from an object to the new one: its headers and metadata and,
//! when they're asked for, its tags and Object Lock settings.

use aws_sdk_s3::{
    operation::head_object::HeadObjectOutput,
    primitives::DateTime,
    types::{ObjectLockLegalHoldStatus, ObjectLockMode},
};

use super::transfer::percent_encode;

/// What a copy sets on the new object, read from the source.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attributes {
    pub content_type: Option<String>,
    pub cache_control: Option<String>,
    pub content_disposition: Option<String>,
    pub content_encoding: Option<String>,
    pub content_language: Option<String>,
    pub expires: Option<String>,
    pub website_redirect_location: Option<String>,
    pub metadata: Option<std::collections::HashMap<String, String>>,
    /// As `x-amz-tagging` takes them: `key=value&…`, encoded.
    pub tagging: Option<String>,
    pub lock_mode: Option<ObjectLockMode>,
    pub retain_until: Option<DateTime>,
    pub legal_hold: Option<ObjectLockLegalHoldStatus>,
}

impl Attributes {
    /// What `head` says, with the object's tags. A retention that has already ended is
    /// left out: S3 only takes one in the future, and it no longer protects anything.
    pub fn of(head: &HeadObjectOutput, tags: &[(String, String)], now: DateTime) -> Self {
        let retain_until = head
            .object_lock_retain_until_date()
            .filter(|until| until.secs() > now.secs())
            .copied();
        Self {
            content_type: head.content_type().map(str::to_owned),
            cache_control: head.cache_control().map(str::to_owned),
            content_disposition: head.content_disposition().map(str::to_owned),
            content_encoding: head.content_encoding().map(str::to_owned),
            content_language: head.content_language().map(str::to_owned),
            expires: head.expires_string().map(str::to_owned),
            website_redirect_location: head.website_redirect_location().map(str::to_owned),
            metadata: head.metadata().filter(|m| !m.is_empty()).cloned(),
            tagging: (!tags.is_empty()).then(|| tagging(tags)),
            lock_mode: retain_until.and(head.object_lock_mode().cloned()),
            retain_until,
            legal_hold: head
                .object_lock_legal_hold_status()
                .filter(|status| **status == ObjectLockLegalHoldStatus::On)
                .cloned(),
        }
    }
}

impl Attributes {
    /// Only the headers and metadata: what `cp` carries, as a copy at one endpoint does.
    #[must_use]
    pub fn headers_only(self) -> Self {
        Self {
            tagging: None,
            lock_mode: None,
            retain_until: None,
            legal_hold: None,
            ..self
        }
    }
}

/// Tags as `x-amz-tagging` takes them.
fn tagging(tags: &[(String, String)]) -> String {
    let mut out = String::new();
    for (i, (key, value)) in tags.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        percent_encode(&mut out, key, b"-_.~");
        out.push('=');
        percent_encode(&mut out, value, b"-_.~");
    }
    out
}

/// Sets every attribute on a request that makes an object (`PutObject`,
/// `CreateMultipartUpload`, `CopyObject`: their builders share the setters' names).
macro_rules! with_attributes {
    ($request:expr, $attributes:expr) => {{
        let a: &$crate::client::attributes::Attributes = $attributes;
        $request
            .set_content_type(a.content_type.clone())
            .set_cache_control(a.cache_control.clone())
            .set_content_disposition(a.content_disposition.clone())
            .set_content_encoding(a.content_encoding.clone())
            .set_content_language(a.content_language.clone())
            .set_expires(a.expires.as_deref().and_then(|e| {
                aws_sdk_s3::primitives::DateTime::from_str(
                    e,
                    aws_sdk_s3::primitives::DateTimeFormat::HttpDate,
                )
                .ok()
            }))
            .set_website_redirect_location(a.website_redirect_location.clone())
            .set_metadata(a.metadata.clone())
            .set_tagging(a.tagging.clone())
            .set_object_lock_mode(a.lock_mode.clone())
            .set_object_lock_retain_until_date(a.retain_until)
            .set_object_lock_legal_hold_status(a.legal_hold.clone())
    }};
}

pub(crate) use with_attributes;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_keep_what_still_holds() {
        let now = DateTime::from_secs(1_000_000);
        let head = HeadObjectOutput::builder()
            .content_type("text/plain")
            .cache_control("max-age=60")
            .metadata("colour", "blue")
            .object_lock_mode(ObjectLockMode::Governance)
            .object_lock_retain_until_date(DateTime::from_secs(999_999))
            .object_lock_legal_hold_status(ObjectLockLegalHoldStatus::On)
            .build();
        let tags = [
            ("a b".to_owned(), "c&d".to_owned()),
            ("e".to_owned(), String::new()),
        ];
        let attributes = Attributes::of(&head, &tags, now);
        assert_eq!(attributes.content_type.as_deref(), Some("text/plain"));
        assert_eq!(attributes.cache_control.as_deref(), Some("max-age=60"));
        assert_eq!(attributes.tagging.as_deref(), Some("a%20b=c%26d&e="));
        // A retention that ended is left out, with its mode; a legal hold isn't.
        assert_eq!(
            (attributes.lock_mode, attributes.retain_until),
            (None, None)
        );
        assert_eq!(attributes.legal_hold, Some(ObjectLockLegalHoldStatus::On));
        let later = HeadObjectOutput::builder()
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from_secs(2_000_000))
            .object_lock_legal_hold_status(ObjectLockLegalHoldStatus::Off)
            .build();
        let attributes = Attributes::of(&later, &[], now);
        assert_eq!(attributes.lock_mode, Some(ObjectLockMode::Compliance));
        assert_eq!(attributes.legal_hold, None);
        assert_eq!(attributes.tagging, None);
    }
}
