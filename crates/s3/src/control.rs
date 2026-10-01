//! S3 Control: the account's Block Public Access settings, which apply with every
//! bucket's (each setting on where either has it), as `aws s3control
//! get|put|delete-public-access-block` and the SDKs call them; and a bucket's tags, which
//! `TagResource` and `UntagResource` change one by one, the only way to change them
//! while they decide access (ABAC).
//!
//! The SDKs send the account in the host (`{account}.endpoint`) and in the
//! `x-amz-account-id` header; TeiFS reads the header, which must name the drive's
//! account. [`crate::routes`] decides who may call it.

use http::{HeaderMap, HeaderValue, Request, StatusCode, Uri, header};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use s3s::{
    Body, HttpError, HttpResponse, S3Error, S3ErrorCode, S3Request, S3Response, S3Result, dto,
    service::S3Service,
    xml::{DeError, Deserialize, Deserializer, SerializeContent, Serializer},
};
use teifs_policy::{Context, TagKind};
use teifs_store::Store;

use crate::{
    bucket_access::{Rules, block_from_dto, block_to_dto, no_public_access_block},
    errors::StoreResultExt,
    routes::{INCOMPLETE, s3_refusal, signed_body, unreadable},
    tagging::{self, MAX_BUCKET_TAGS, Tags},
};

/// Where S3 Control's operations are.
pub(crate) const PREFIX: &str = "/v20180820/";

/// The account's Block Public Access settings.
pub(crate) const PUBLIC_ACCESS_BLOCK: &str = "/v20180820/configuration/publicAccessBlock";

/// A resource's tags: the resource's ARN follows, URL-encoded.
pub(crate) const TAGS: &str = "/v20180820/tags/{resourceArn}";

/// The header that names the account.
pub(crate) const ACCOUNT_HEADER: &str = "x-amz-account-id";

/// S3 Control's XML namespace.
const NAMESPACE: &str = "http://awss3control.amazonaws.com/doc/2018-08-20/";

/// The largest body accepted: four booleans, or 50 tags, with room for whitespace.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// What Signature V4 leaves unencoded in a path: letters, digits, `- _ . ~` and `/`.
const PATH: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

/// A request whose path was encoded again to check its signature: its handler decodes it
/// twice.
#[derive(Debug, Clone, Copy)]
struct EncodedTwice;

/// Whether a request is S3 Control's with an encoded character in its path, which the
/// SDKs sign two ways ([`call_encoded`]).
pub(crate) fn has_encoded_path<B>(req: &Request<B>) -> bool {
    let path = req.uri().path();
    req.headers().contains_key(ACCOUNT_HEADER) && path.starts_with(PREFIX) && path.contains('%')
}

/// Calls the S3 service with an S3 Control request whose path has an encoded character
/// (a resource's ARN). botocore signs such a path as sent, as S3's; AWS's other SDKs
/// encode it again first, as for AWS's services other than S3, and s3s checks only the
/// first. So the request is tried as sent and, when its signature doesn't match, with its
/// path encoded again, which s3s then checks as those SDKs signed it. The body is small
/// and read first; nothing runs before a signature matches, so a failed try has no
/// effect.
pub(crate) async fn call_encoded(
    s3: &S3Service,
    mut req: Request<Body>,
) -> Result<HttpResponse, HttpError> {
    let body = match req.body_mut().store_all_limited(MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(err) => {
            let (status, code, message) = unreadable(err.as_ref(), INCOMPLETE);
            return Ok(crate::cors::error(status, code, message));
        }
    };
    let Some(uri) = encoded_again(req.uri()) else {
        return s3.call(req).await;
    };
    let mut again = Request::new(Body::from(body.clone()));
    *again.method_mut() = req.method().clone();
    *again.uri_mut() = uri;
    *again.version_mut() = req.version();
    *again.headers_mut() = req.headers().clone();
    if let Some(client) = req.extensions().get::<crate::Client>() {
        again.extensions_mut().insert(*client);
    }
    if let Some(certificates) = req.extensions().get::<crate::ClientCertificates>() {
        again.extensions_mut().insert(certificates.clone());
    }
    if let Some(seen) = req
        .extensions()
        .get::<std::sync::Arc<crate::observe::Seen>>()
    {
        again.extensions_mut().insert(std::sync::Arc::clone(seen));
    }
    again.extensions_mut().insert(EncodedTwice);
    *req.body_mut() = Body::from(body);

    let first = s3.call(req).await?;
    if first.status() != StatusCode::FORBIDDEN {
        return Ok(first);
    }
    let (parts, mut answer) = first.into_parts();
    let answer = answer
        .store_all_limited(MAX_BODY_BYTES)
        .await
        .map_err(HttpError::from_std_error)?;
    if !is_signature_mismatch(&answer) {
        return Ok(HttpResponse::from_parts(parts, Body::from(answer)));
    }
    s3.call(again).await
}

fn is_signature_mismatch(answer: &[u8]) -> bool {
    const CODE: &[u8] = b"<Code>SignatureDoesNotMatch</Code>";
    answer.windows(CODE.len()).any(|w| w == CODE)
}

/// `uri` with its path encoded again (always a valid URI: encoding leaves only
/// characters a path may have).
fn encoded_again(uri: &Uri) -> Option<Uri> {
    let path = utf8_percent_encode(uri.path(), PATH).to_string();
    let path_and_query = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().ok()?);
    Uri::from_parts(parts).ok()
}

/// An S3 Control error, which S3 Control wraps in `ErrorResponse` (unlike S3's).
pub(crate) fn error_response(err: &S3Error, request_id: &str) -> S3Response<Body> {
    let mut xml = Vec::new();
    let mut s = Serializer::new(&mut xml);
    let written = s.decl().and_then(|()| {
        s.element("ErrorResponse", |s| {
            s.element("Error", |s| {
                s.content("Code", err.code().as_str())?;
                s.content("Message", err.message().unwrap_or_default())
            })?;
            s.content("RequestId", request_id)
        })
    });
    debug_assert!(written.is_ok(), "writing to a Vec can't fail");
    let mut response = S3Response::new(Body::from(xml));
    response.status = Some(
        err.status_code()
            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
    );
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    if let Ok(id) = HeaderValue::from_str(request_id) {
        response.headers.insert("x-amz-request-id", id);
    }
    response
}

/// Refuses a request for another account than the drive's.
pub(crate) fn check_account(headers: &HeaderMap, account: &str) -> S3Result<()> {
    let named = headers.get(ACCOUNT_HEADER).and_then(|v| v.to_str().ok());
    if named == Some(account) {
        Ok(())
    } else {
        Err(s3s::s3_error!(
            AccessDenied,
            "Access Denied: x-amz-account-id doesn't name this drive's account"
        ))
    }
}

pub(crate) async fn get_public_access_block(store: &Store) -> S3Result<S3Response<Body>> {
    let block = store
        .account_public_access_block()
        .await
        .s3()?
        .ok_or_else(no_public_access_block)?;
    let mut xml = Vec::new();
    let mut s = Serializer::new(&mut xml);
    s.decl()
        .and_then(|()| {
            s.element_with_ns("PublicAccessBlockConfiguration", NAMESPACE, |s| {
                block_to_dto(block).serialize_content(s)
            })
        })
        .map_err(S3Error::internal_error)?;
    let mut response = S3Response::new(Body::from(xml));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    Ok(response)
}

pub(crate) async fn put_public_access_block(
    store: &Store,
    rules: &Rules,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let body = signed_body(&mut req, MAX_BODY_BYTES)
        .await
        .map_err(s3_refusal)?;
    let config = dto::PublicAccessBlockConfiguration::deserialize(&mut Deserializer::new(&body))
        .map_err(|_| {
            S3Error::with_message(
                S3ErrorCode::MalformedXML,
                "The body must be a PublicAccessBlockConfiguration.",
            )
        })?;
    store
        .set_account_public_access_block(Some(block_from_dto(&config)))
        .await
        .s3()?;
    rules.forget_all();
    Ok(S3Response::new(Body::empty()))
}

pub(crate) async fn delete_public_access_block(
    store: &Store,
    rules: &Rules,
) -> S3Result<S3Response<Body>> {
    store.set_account_public_access_block(None).await.s3()?;
    rules.forget_all();
    Ok(S3Response::new(Body::empty()))
}

/// What a call on a bucket's tags asks for, read before it's decided: the tags it adds or
/// the keys it removes are what policies test (`aws:RequestTag`, `aws:TagKeys`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TagCall {
    List,
    Tag(Tags),
    Untag(Vec<String>),
}

/// The bucket a tags path names (`/v20180820/tags/arn:aws:s3:::bucket`, URL-encoded):
/// general purpose buckets are the only resources TeiFS has tags on.
pub(crate) fn tagged_bucket<B>(req: &S3Request<B>) -> S3Result<String> {
    bucket_in(
        req.uri.path(),
        req.extensions.get::<EncodedTwice>().is_some(),
    )
}

fn bucket_in(path: &str, encoded_twice: bool) -> S3Result<String> {
    let decode = |text: &str| {
        percent_encoding::percent_decode_str(text)
            .decode_utf8_lossy()
            .into_owned()
    };
    let prefix = TAGS.trim_end_matches("{resourceArn}");
    let mut arn = decode(path.strip_prefix(prefix).unwrap_or_default());
    if encoded_twice {
        arn = decode(&arn);
    }
    arn.strip_prefix("arn:aws:s3:::")
        .filter(|bucket| !bucket.is_empty() && !bucket.contains(['/', ':']))
        .map(str::to_owned)
        .ok_or_else(|| {
            S3Error::with_message(
                S3ErrorCode::InvalidRequest,
                "The resource must be a bucket's ARN: arn:aws:s3:::bucket.",
            )
        })
}

impl TagCall {
    /// Reads a call: `TagResource`'s tags from its body, `UntagResource`'s keys from its
    /// query, each checked as a bucket's tags.
    pub(crate) async fn read(kind: TagCallKind, req: &mut S3Request<Body>) -> S3Result<Self> {
        Ok(match kind {
            TagCallKind::List => Self::List,
            TagCallKind::Tag => {
                let body = signed_body(req, MAX_BODY_BYTES).await.map_err(s3_refusal)?;
                Self::Tag(tagging::check(tags_of(&body)?, MAX_BUCKET_TAGS)?)
            }
            TagCallKind::Untag => {
                let query = req.uri.query().unwrap_or_default().as_bytes();
                let keys: Vec<String> = form_urlencoded::parse(query)
                    .filter(|(name, _)| name == "tagKeys")
                    .map(|(_, key)| key.into_owned())
                    .collect();
                if keys.is_empty() || keys.len() > MAX_BUCKET_TAGS {
                    return Err(S3Error::with_message(
                        S3ErrorCode::InvalidRequest,
                        "Name from 1 to 50 tag keys to remove, with tagKeys.",
                    ));
                }
                Self::Untag(keys)
            }
        })
    }

    /// `context` with what the call asks for, as its conditions see it.
    pub(crate) fn in_context(&self, mut context: Context) -> Context {
        match self {
            Self::List => {}
            Self::Tag(tags) => {
                for (key, value) in tags {
                    context = context.with_tag(TagKind::Request, key, value);
                }
            }
            Self::Untag(keys) => context = context.with_tag_keys(keys.iter().map(String::as_str)),
        }
        context
    }

    /// Makes the call on `bucket`: tags are added to (or replace the value of) the
    /// bucket's, keys it doesn't have are ignored, and the answer to either is empty.
    pub(crate) async fn call(
        self,
        store: &Store,
        rules: &Rules,
        bucket: &str,
    ) -> S3Result<S3Response<Body>> {
        let changed = match self {
            Self::List => return list_tags(store, bucket).await,
            Self::Tag(tags) => store.tag_bucket(bucket, tags, MAX_BUCKET_TAGS).await,
            Self::Untag(keys) => store.untag_bucket(bucket, keys).await,
        };
        changed.s3()?;
        rules.forget(bucket);
        let mut response = S3Response::new(Body::empty());
        response.status = Some(http::StatusCode::NO_CONTENT);
        Ok(response)
    }
}

/// Which call on a bucket's tags an endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagCallKind {
    List,
    Tag,
    Untag,
}

/// A `TagResourceRequest`'s tags.
fn tags_of(body: &[u8]) -> S3Result<Vec<(String, String)>> {
    let mut d = Deserializer::new(body);
    let tags = d
        .named_element("TagResourceRequest", |d| {
            let mut tags = None;
            d.for_each_element(|d, name| match name {
                b"Tags" if tags.is_none() => {
                    tags = Some(d.list_content::<dto::Tag>("Tag")?);
                    Ok(())
                }
                _ => Err(DeError::UnexpectedTagName),
            })?;
            tags.ok_or(DeError::MissingField)
        })
        .and_then(|tags| d.expect_eof().map(|()| tags))
        .map_err(|_| {
            S3Error::with_message(
                S3ErrorCode::MalformedXML,
                "The body must be a TagResourceRequest.",
            )
        })?;
    Ok(tags
        .into_iter()
        .map(|tag| (tag.key.unwrap_or_default(), tag.value.unwrap_or_default()))
        .collect())
}

async fn list_tags(store: &Store, bucket: &str) -> S3Result<S3Response<Body>> {
    let tags = store.bucket_tags(bucket).await.s3()?.unwrap_or_default();
    let mut xml = Vec::new();
    let mut s = Serializer::new(&mut xml);
    s.decl()
        .and_then(|()| {
            s.element_with_ns("ListTagsForResourceResult", NAMESPACE, |s| {
                s.list("Tags", "Tag", tagging::to_dto(&tags).iter())
            })
        })
        .map_err(S3Error::internal_error)?;
    let mut response = S3Response::new(Body::from(xml));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_drive_account_is_served() {
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(ACCOUNT_HEADER, HeaderValue::from_str(value).unwrap());
            headers
        };
        assert!(check_account(&with("123456789012"), "123456789012").is_ok());
        for other in ["210987654321", "123456789012 ", ""] {
            let err = check_account(&with(other), "123456789012").unwrap_err();
            assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{other:?}");
        }
        assert!(check_account(&HeaderMap::new(), "123456789012").is_err());
    }

    #[test]
    fn tags_are_on_buckets_named_by_their_arn() {
        let bucket = |arn: &str| bucket_in(&format!("/v20180820/tags/{arn}"), false);
        assert_eq!(bucket("arn%3Aaws%3As3%3A%3A%3Aphotos").unwrap(), "photos");
        assert_eq!(bucket("arn:aws:s3:::photos").unwrap(), "photos");
        for other in [
            "",
            "arn%3Aaws%3As3%3A%3A%3A",
            "arn%3Aaws%3As3%3A%3A%3Aphotos%2Fkey",
            "arn:aws:s3:::photos/key",
            "arn:aws:s3:us-east-1:123456789012:accesspoint/ap",
            "arn:aws:s3express:::photos",
            "arn:aws:iam::123456789012:user/alice",
        ] {
            let err = bucket(other).unwrap_err();
            assert_eq!(*err.code(), S3ErrorCode::InvalidRequest, "{other:?}");
        }
        let twice = "/v20180820/tags/arn%253Aaws%253As3%253A%253A%253Aphotos";
        assert_eq!(bucket_in(twice, true).unwrap(), "photos");
        assert!(bucket_in(twice, false).is_err());
    }

    #[test]
    fn paths_are_encoded_again_as_the_sdks_sign_them() {
        let uri: Uri = "http://h/v20180820/tags/arn%3Aaws%3As3%3A%3A%3Ab?tagKeys=a%20b"
            .parse()
            .unwrap();
        assert_eq!(
            encoded_again(&uri).unwrap().to_string(),
            "http://h/v20180820/tags/arn%253Aaws%253As3%253A%253A%253Ab?tagKeys=a%20b"
        );
        assert!(is_signature_mismatch(
            b"<Error><Code>SignatureDoesNotMatch</Code></Error>"
        ));
        assert!(!is_signature_mismatch(
            b"<Error><Code>AccessDenied</Code></Error>"
        ));
    }

    #[test]
    fn a_tag_resource_request_is_its_tags() {
        let body = br#"<?xml version="1.0" encoding="UTF-8"?><TagResourceRequest xmlns="http://awss3control.amazonaws.com/doc/2018-08-20/"><Tags><Tag><Key>team</Key><Value>blue</Value></Tag><Tag><Key>cost</Key><Value></Value></Tag></Tags></TagResourceRequest>"#;
        let tags = tags_of(body).unwrap();
        assert_eq!(
            tags,
            [
                ("team".into(), "blue".into()),
                ("cost".into(), String::new())
            ]
        );
        for malformed in [
            &b""[..],
            b"<TagResourceRequest></TagResourceRequest>",
            b"<Tagging><TagSet></TagSet></Tagging>",
            b"<TagResourceRequest><Tags></Tags><Tags></Tags></TagResourceRequest>",
            b"<TagResourceRequest><Tags></Tags><Other/></TagResourceRequest>",
            b"<TagResourceRequest><Tags></Tags></TagResourceRequest><More/>",
        ] {
            let err = tags_of(malformed).unwrap_err();
            assert_eq!(*err.code(), S3ErrorCode::MalformedXML);
        }
        assert!(
            tags_of(b"<TagResourceRequest><Tags></Tags></TagResourceRequest>")
                .unwrap()
                .is_empty()
        );
    }
}
