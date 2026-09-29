//! Browser uploads (S3's `POST` with a form, PostObject): what the form says, read before
//! s3s takes the request. s3s checks the form's signature and policy and makes the upload;
//! TeiFS needs the form earlier, to authorize the key it names (the path names only the
//! bucket) and to apply the fields s3s doesn't map (`acl`, and `tagging` as XML).
//!
//! The fields come before the file, so only they are read, with s3s's own parser
//! (`s3s-multipart`, read field by field as s3s does), and the bytes read are put back in
//! front of the body: s3s parses exactly the same bytes, and both see the same fields. At
//! most [`MAX_FIELDS_BYTES`] are read.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http::{Method, Request, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, BodyStream, StreamBody};
use s3s::{Body, HttpResponse, S3Result, StdError, dto};

/// The most a form's fields (everything before the file) may take, as bytes on the wire.
/// AWS limits POST policies to 20 KB; this leaves room for the other fields.
pub const MAX_FIELDS_BYTES: usize = 64 * 1024;

/// The fields a form names, as s3s reads them (lowercased names; for a repeated field,
/// the value s3s takes), in the request's extensions for [`crate::access`] and the upload.
#[derive(Debug, Clone)]
pub(crate) struct Form(Arc<Fields>);

#[derive(Debug)]
struct Fields {
    /// Every field but the file, sorted by name as s3s sorts them, the key's
    /// `${filename}` replaced by the file's name as s3s replaces it.
    fields: Vec<(String, String)>,
}

impl Form {
    /// A field's value, as s3s would read it.
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        let fields = &self.0.fields;
        fields
            .get(index(fields, name)?)
            .map(|(_, value)| value.as_str())
    }

    /// The object the form uploads to.
    pub(crate) fn key(&self) -> Option<&str> {
        self.field("key")
    }

    /// The signature field a form that names a key or a policy lacks, as AWS names it: such
    /// a form is refused before its policy is looked at, rather than taken as anonymous.
    fn missing_signature(&self) -> Option<&'static str> {
        let v4 =
            self.field("x-amz-credential").is_some() || self.field("x-amz-algorithm").is_some();
        let v2 = self.field("awsaccesskeyid").is_some();
        let signed = self.field("x-amz-signature").is_some() || self.field("signature").is_some();
        if signed || !(v4 || v2 || self.field("policy").is_some()) {
            return None;
        }
        Some(if v4 { "X-Amz-Signature" } else { "Signature" })
    }

    /// Why the policy's expiration isn't one, if it isn't: AWS takes only ISO 8601 in UTC
    /// (`2026-01-01T00:00:00Z`, fractions of a second allowed), where s3s takes more.
    fn bad_expiration(&self) -> Option<String> {
        use base64::Engine;
        let policy = base64::engine::general_purpose::STANDARD
            .decode(self.field("policy")?)
            .ok()?;
        let policy: serde_json::Value = serde_json::from_slice(&policy).ok()?;
        let expiration = policy.get("expiration")?.as_str()?;
        (!is_utc_timestamp(expiration))
            .then(|| format!("Invalid Policy: Invalid 'expiration' value: '{expiration}'"))
    }

    /// Checks the form against its policy's `eq` and `starts-with` conditions, as AWS
    /// does: a field that doesn't meet one is refused with `403 AccessDenied` (s3s answers
    /// `400`). `bucket` is the bucket the request is for. A policy that doesn't parse, its
    /// expiry and the file's size are left to s3s, which checks them as AWS does.
    fn meets_policy(&self, bucket: Option<&str>) -> Result<(), String> {
        use s3s::post_policy::{PostPolicy, PostPolicyCondition};
        let Some(policy) = self
            .field("policy")
            .and_then(|policy| PostPolicy::from_base64(policy).ok())
        else {
            return Ok(());
        };
        for condition in &policy.conditions {
            let (field, met, text) = match condition {
                PostPolicyCondition::Eq { field, value } => {
                    let actual = self.condition_value(field, bucket);
                    (
                        field,
                        actual == Some(value.as_str()),
                        format!(r#"["eq", "${field}", "{value}"]"#),
                    )
                }
                PostPolicyCondition::StartsWith { field, prefix } => {
                    let actual = self.condition_value(field, bucket).unwrap_or_default();
                    (
                        field,
                        actual.starts_with(prefix.as_str()),
                        format!(r#"["starts-with", "${field}", "{prefix}"]"#),
                    )
                }
                PostPolicyCondition::ContentLengthRange { .. } => continue,
            };
            if !met {
                tracing::debug!(field, "a form doesn't meet its policy");
                return Err(format!(
                    "Invalid according to Policy: Policy Condition failed: {text}"
                ));
            }
        }
        Ok(())
    }

    /// What a condition on `field` tests: the bucket the request is for, else the field.
    fn condition_value<'a>(&'a self, field: &str, bucket: Option<&'a str>) -> Option<&'a str> {
        match (field, bucket) {
            ("bucket", Some(bucket)) => Some(bucket),
            _ => self.field(field),
        }
    }

    /// Whether the form is signed with Signature V4 (else V2, or not signed).
    pub(crate) fn signed_v4(&self) -> bool {
        self.field("x-amz-signature").is_some()
    }

    /// The canned ACL: AWS's `acl` field, else `x-amz-acl`.
    pub(crate) fn acl(&self) -> Option<&str> {
        self.field("acl").or_else(|| self.field("x-amz-acl"))
    }

    /// The tags: AWS's `tagging` field (an XML tag set), else `x-amz-tagging` (URL
    /// query parameters, as the header).
    pub(crate) fn tags(&self) -> S3Result<Option<Vec<(String, String)>>> {
        if let Some(xml) = self.field("tagging") {
            return crate::tagging::from_xml(xml.as_bytes()).map(Some);
        }
        self.field("x-amz-tagging")
            .map(crate::tagging::from_header)
            .transpose()
    }
}

/// Whether `text` is `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
fn is_utc_timestamp(text: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let Some((seconds, fraction)) = text
        .strip_suffix('Z')
        .map(|t| t.split_once('.').unwrap_or((t, "0")))
    else {
        return false;
    };
    let bytes = seconds.as_bytes();
    seconds.len() == 19
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b'T',
            13 | 16 => *b == b':',
            _ => b.is_ascii_digit(),
        })
        && digits(fraction)
}

/// The index s3s finds a field at: a binary search that finds the last of equal names.
fn index(fields: &[(String, String)], name: &str) -> Option<usize> {
    let i = fields
        .partition_point(|(n, _)| n.as_str() <= name)
        .checked_sub(1)?;
    (fields.get(i)?.0 == name).then_some(i)
}

/// The most parts a form may have; s3s is given the same limit.
pub const MAX_PARTS: usize = 1000;

/// A form post with its [`Form`] in its extensions; any other request as it is. `Err` is
/// the answer to a body that couldn't be read. A form whose fields don't parse within
/// [`MAX_FIELDS_BYTES`] is passed on without a [`Form`]: s3s answers a malformed one, and
/// one it can read is refused with [`too_large`] (an upload needs its [`Form`]).
pub(crate) async fn with_form(
    req: Request<Body>,
    bucket: Option<&str>,
) -> Result<Request<Body>, Box<HttpResponse>> {
    let Some(boundary) = boundary(&req) else {
        return Ok(req);
    };
    let (mut parts, mut body) = req.into_parts();
    let mut read = BytesMut::new();
    // Parsed again only when what's read has doubled, so a body sent a byte at a time
    // costs a few parses, not one per byte.
    let mut parse_at = 4 * 1024;
    let mut ended = false;
    let form = loop {
        if ended || read.len() >= parse_at {
            match parse(read.clone().freeze(), &boundary).await {
                Parsed::Form(form) => break Some(form),
                Parsed::TooLarge => {
                    let (status, code, message) = TOO_LARGE;
                    return Err(Box::new(crate::cors::error(status, code, message)));
                }
                Parsed::Not if ended || read.len() > MAX_FIELDS_BYTES => break None,
                Parsed::Not => parse_at = (parse_at * 2).min(MAX_FIELDS_BYTES + 1),
            }
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    read.extend_from_slice(&data);
                }
            }
            Some(Err(err)) => {
                let (status, code, message) =
                    crate::routes::unreadable(err.as_ref(), crate::routes::INCOMPLETE);
                return Err(Box::new(crate::cors::error(status, code, message)));
            }
            None => ended = true,
        }
    };
    if let Some(form) = form {
        if let Some(field) = form.missing_signature() {
            return Err(Box::new(crate::cors::error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &format!(
                    "Bucket POST must contain a field named '{field}'. If it is specified, please \
                     check the order of the fields."
                ),
            )));
        }
        if let Some(message) = form.bad_expiration() {
            return Err(Box::new(crate::cors::error(
                StatusCode::BAD_REQUEST,
                "InvalidPolicyDocument",
                &message,
            )));
        }
        if let Err(message) = form.meets_policy(bucket) {
            return Err(Box::new(crate::cors::error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                &message,
            )));
        }
        parts.extensions.insert(form);
    }
    let first = futures::stream::iter([Ok::<_, StdError>(Frame::data(read.freeze()))]);
    let body = StreamBody::new(first.chain(BodyStream::new(body)));
    Ok(Request::from_parts(parts, Body::http_body(body)))
}

/// AWS's answer to fields before the file that are too large.
const TOO_LARGE: (StatusCode, &str, &str) = (
    StatusCode::BAD_REQUEST,
    "MaxPostPreDataLengthExceeded",
    "Your POST request fields preceding the upload file were too large.",
);

/// The answer to an upload whose fields came to more than [`MAX_FIELDS_BYTES`].
pub(crate) fn too_large() -> s3s::S3Error {
    let (status, code, message) = TOO_LARGE;
    let mut err = s3s::S3Error::with_message(s3s::S3ErrorCode::Custom(code.into()), message);
    err.set_status_code(status);
    err
}

/// A form post's boundary, parsed as s3s parses it.
fn boundary<B>(req: &Request<B>) -> Option<String> {
    if req.method() != Method::POST {
        return None;
    }
    let mime: mime::Mime = req
        .headers()
        .get(header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .parse()
        .ok()?;
    (mime.type_() == mime::MULTIPART && mime.subtype() == mime::FORM_DATA)
        .then(|| {
            mime.get_param(mime::BOUNDARY)
                .map(|b| b.as_str().to_owned())
        })
        .flatten()
}

/// What reading a form's start found.
enum Parsed {
    /// All its fields, up to the file.
    Form(Form),
    /// Fields that are more than [`MAX_FIELDS_BYTES`].
    TooLarge,
    /// Not a form, or not all of it yet.
    Not,
}

/// The form's fields, if `read` holds all of them and the file part's start: read as
/// s3s's `transform_multipart` reads them (the last `Content-Disposition` wins, names
/// lowercased, then sorted, and the file's name for `${filename}` in the key).
async fn parse(read: Bytes, boundary: &str) -> Parsed {
    match fields(read, boundary).await {
        Ok(Some(form)) => Parsed::Form(form),
        Ok(None) => Parsed::Not,
        Err(TooLarge) => Parsed::TooLarge,
    }
}

struct TooLarge;

/// [`parse`]'s work: `Ok(None)` for what isn't a whole form start.
async fn fields(read: Bytes, boundary: &str) -> Result<Option<Form>, TooLarge> {
    let Ok(boundary) = s3s_multipart::Boundary::new(boundary.as_bytes()) else {
        return Ok(None);
    };
    let stream = futures::stream::iter([Ok::<_, s3s_multipart::Error>(read)]);
    let mut parser = s3s_multipart::Multipart::new(stream, &boundary, MAX_FIELDS_BYTES);
    let text = |bytes: &[u8]| std::str::from_utf8(bytes).ok().map(str::to_owned);
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut total = 0_usize;
    for _ in 0..MAX_PARTS {
        let mut part = match parser.next_part().await {
            Ok(Some(part)) => part,
            Err(s3s_multipart::Error::HeaderSizeExceeded { .. }) => return Err(TooLarge),
            Ok(None) | Err(_) => return Ok(None),
        };
        let (mut name, mut file_name) = (None, None);
        loop {
            let header = match part.next_header().await {
                Ok(Some(header)) => header,
                Ok(None) => break,
                Err(s3s_multipart::Error::HeaderSizeExceeded { .. }) => return Err(TooLarge),
                Err(_) => return Ok(None),
            };
            if header.name.eq_ignore_ascii_case("content-disposition") {
                let cd = s3s_multipart::parse_content_disposition(header.value);
                name = cd.and_then(|cd| cd.name).and_then(text);
                file_name = cd.and_then(|cd| cd.file_name).and_then(text);
            }
        }
        let Some(name) = name else {
            return Ok(None);
        };
        if name.eq_ignore_ascii_case("file") {
            for (field, _) in &mut fields {
                field.make_ascii_lowercase();
            }
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            let file_name = file_name.unwrap_or(name);
            if let Some(key) = index(&fields, "key").and_then(|i| fields.get_mut(i)) {
                key.1 = key.1.replace("${filename}", &file_name);
            }
            return Ok(Some(Form(Arc::new(Fields { fields }))));
        }
        let mut value = Vec::new();
        loop {
            match part.next_data().await {
                Ok(Some(chunk)) => {
                    value.extend_from_slice(&chunk);
                    total = total.saturating_add(chunk.len());
                    if value.len() > MAX_FIELDS_BYTES || total > MAX_FIELDS_BYTES {
                        return Err(TooLarge);
                    }
                }
                Ok(None) => break,
                Err(_) => return Ok(None),
            }
        }
        let Ok(value) = String::from_utf8(value) else {
            return Ok(None);
        };
        fields.push((name, value));
    }
    Err(TooLarge)
}

/// The upload a form asks for, as a `PutObject`: what s3s read, with the ACL and the
/// `tags` ([`Form::tags`]) from the form's own fields, which s3s doesn't map.
pub(crate) fn into_put(
    x: dto::PostObjectInput,
    form: &Form,
    tags: Option<Vec<(String, String)>>,
) -> dto::PutObjectInput {
    let tagging = tags.map(|tags| {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(tags)
            .finish()
    });
    dto::PutObjectInput {
        acl: form
            .acl()
            .map(|acl| dto::ObjectCannedACL::from(acl.to_owned())),
        tagging,
        body: x.body,
        bucket: x.bucket,
        bucket_key_enabled: x.bucket_key_enabled,
        cache_control: x.cache_control,
        checksum_algorithm: x.checksum_algorithm,
        checksum_crc32: x.checksum_crc32,
        checksum_crc32c: x.checksum_crc32c,
        checksum_crc64nvme: x.checksum_crc64nvme,
        checksum_md5: x.checksum_md5,
        checksum_sha1: x.checksum_sha1,
        checksum_sha256: x.checksum_sha256,
        checksum_sha512: x.checksum_sha512,
        checksum_xxhash128: x.checksum_xxhash128,
        checksum_xxhash3: x.checksum_xxhash3,
        checksum_xxhash64: x.checksum_xxhash64,
        content_disposition: x.content_disposition,
        content_encoding: x.content_encoding,
        content_language: x.content_language,
        content_length: x.content_length,
        content_md5: x.content_md5,
        content_type: x.content_type,
        expected_bucket_owner: x.expected_bucket_owner,
        expires: x.expires,
        grant_full_control: x.grant_full_control,
        grant_read: x.grant_read,
        grant_read_acp: x.grant_read_acp,
        grant_write_acp: x.grant_write_acp,
        if_match: x.if_match,
        if_none_match: x.if_none_match,
        key: x.key,
        metadata: x.metadata,
        object_lock_legal_hold_status: x.object_lock_legal_hold_status,
        object_lock_mode: x.object_lock_mode,
        object_lock_retain_until_date: x.object_lock_retain_until_date,
        request_payer: x.request_payer,
        sse_customer_algorithm: x.sse_customer_algorithm,
        sse_customer_key: x.sse_customer_key,
        sse_customer_key_md5: x.sse_customer_key_md5,
        ssekms_encryption_context: x.ssekms_encryption_context,
        ssekms_key_id: x.ssekms_key_id,
        server_side_encryption: x.server_side_encryption,
        storage_class: x.storage_class,
        website_redirect_location: x.website_redirect_location,
        write_offset_bytes: x.write_offset_bytes,
    }
}

/// A `PutObject`'s answer as the form upload's.
pub(crate) fn from_put(x: dto::PutObjectOutput) -> dto::PostObjectOutput {
    dto::PostObjectOutput {
        bucket_key_enabled: x.bucket_key_enabled,
        checksum_crc32: x.checksum_crc32,
        checksum_crc32c: x.checksum_crc32c,
        checksum_crc64nvme: x.checksum_crc64nvme,
        checksum_md5: x.checksum_md5,
        checksum_sha1: x.checksum_sha1,
        checksum_sha256: x.checksum_sha256,
        checksum_sha512: x.checksum_sha512,
        checksum_type: x.checksum_type,
        checksum_xxhash128: x.checksum_xxhash128,
        checksum_xxhash3: x.checksum_xxhash3,
        checksum_xxhash64: x.checksum_xxhash64,
        e_tag: x.e_tag,
        expiration: x.expiration,
        request_charged: x.request_charged,
        sse_customer_algorithm: x.sse_customer_algorithm,
        sse_customer_key_md5: x.sse_customer_key_md5,
        ssekms_encryption_context: x.ssekms_encryption_context,
        ssekms_key_id: x.ssekms_key_id,
        server_side_encryption: x.server_side_encryption,
        size: x.size,
        version_id: x.version_id,
    }
}

#[cfg(test)]
mod tests {
    use super::is_utc_timestamp;

    #[test]
    fn expirations_are_iso_8601_in_utc() {
        for good in ["2026-01-01T00:00:00Z", "2026-12-31T23:59:59.123Z"] {
            assert!(is_utc_timestamp(good), "{good}");
        }
        for bad in [
            "2026-01-01 00:00:00+00:00",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00+01:00",
            "2026-01-01T00:00:00.Z",
            "2026-1-01T00:00:00Z",
            "2026-01-01X00:00:00Z",
            "2026-01-01T00-00:00Z",
            "20260-01-01T00:00:00Z",
            "",
        ] {
            assert!(!is_utc_timestamp(bad), "{bad}");
        }
    }
}
