//! Signature V2 as AWS answers it where s3s answers differently: a header-signed request
//! (`Authorization: AWS key:signature`) needs a valid `Date` or `x-amz-date`, else it's
//! refused with `403 AccessDenied` (s3s says `400 InvalidRequest`). s3s still checks the
//! signature and how fresh the date is.
//!
//! And a path-style request for a whole bucket is signed over `/bucket/`, its canonical
//! resource, whether its path ends in `/` or not (botocore signs it so); s3s signs the path
//! as sent, so the path is given its `/` before s3s sees it.

use http::{HeaderMap, Request, StatusCode, Uri, header, uri::PathAndQuery};
use s3s::{
    HttpResponse,
    dto::{Timestamp, TimestampFormat},
};

/// The answer to a Signature V2 request without a date AWS would take; `None` for any
/// other request.
pub(crate) fn refusal(headers: &HeaderMap) -> Option<HttpResponse> {
    if !header_signed(headers) {
        return None;
    }
    let date = headers
        .get("x-amz-date")
        .or_else(|| headers.get(header::DATE));
    let valid = date
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Timestamp::parse(TimestampFormat::HttpDate, v).ok())
        .is_some_and(|t| time::OffsetDateTime::from(t).unix_timestamp() >= 0);
    (!valid).then(|| {
        crate::cors::error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "AWS authentication requires a valid Date or x-amz-date header",
        )
    })
}

/// Gives a path-style Signature V2 request for a whole bucket (`/bucket`) the `/` its
/// signature covers. `virtual_hosted` requests name the bucket in the host: their path is
/// a key, and stays as it is.
pub(crate) fn canonical_bucket_path<B>(req: &mut Request<B>, virtual_hosted: bool) {
    let uri = req.uri();
    let bucket_only = uri.path().len() > 1 && uri.path().rfind('/') == Some(0);
    if virtual_hosted || !bucket_only || !(header_signed(req.headers()) || presigned(uri)) {
        return;
    }
    let path = match uri.query() {
        Some(query) => format!("{}/?{query}", uri.path()),
        None => format!("{}/", uri.path()),
    };
    let mut parts = uri.clone().into_parts();
    let Ok(path) = PathAndQuery::try_from(path) else {
        return;
    };
    parts.path_and_query = Some(path);
    if let Ok(uri) = Uri::from_parts(parts) {
        *req.uri_mut() = uri;
    }
}

/// Whether a request is signed with Signature V2 in its `Authorization` header.
fn header_signed(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("AWS "))
}

/// Whether a request is a Signature V2 presigned URL.
fn presigned(uri: &Uri) -> bool {
    uri.query().is_some_and(|query| {
        let names = || form_urlencoded::parse(query.as_bytes()).map(|(name, _)| name);
        names().any(|name| name == "AWSAccessKeyId") && names().any(|name| name == "Signature")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| {
                (
                    http::HeaderName::from_static(name),
                    http::HeaderValue::from_static(value),
                )
            })
            .collect()
    }

    #[test]
    fn signature_v2_needs_a_date_aws_takes() {
        let v2 = ("authorization", "AWS key:signature");
        let good = "Tue, 29 Sep 2026 10:00:00 GMT";
        for pairs in [
            vec![v2],
            vec![v2, ("date", "")],
            vec![v2, ("date", "Bad Date")],
            vec![v2, ("x-amz-date", "Tue, 07 Jul 1950 21:53:04 GMT")],
            // `x-amz-date` wins over `Date`, as it does for the signature.
            vec![v2, ("date", good), ("x-amz-date", "Bad Date")],
        ] {
            let refused = refusal(&headers(&pairs)).map(|r| r.status());
            assert_eq!(refused, Some(StatusCode::FORBIDDEN), "{pairs:?}");
        }
        for pairs in [
            vec![v2, ("date", good)],
            vec![v2, ("x-amz-date", good)],
            // Not Signature V2: s3s decides.
            vec![("authorization", "AWS4-HMAC-SHA256 Credential=key")],
            vec![],
        ] {
            assert!(refusal(&headers(&pairs)).is_none(), "{pairs:?}");
        }
    }

    #[test]
    fn a_v2_bucket_request_is_signed_over_its_bucket_with_a_slash() {
        let path = |uri: &'static str, auth: &'static str, virtual_hosted: bool| {
            let mut req = Request::builder().uri(uri);
            if !auth.is_empty() {
                req = req.header("authorization", auth);
            }
            let mut req = req.body(()).unwrap();
            canonical_bucket_path(&mut req, virtual_hosted);
            req.uri().to_string()
        };
        let v2 = "AWS key:signature";
        assert_eq!(path("/photos", v2, false), "/photos/");
        assert_eq!(path("/photos?acl", v2, false), "/photos/?acl");
        assert_eq!(
            path("http://h:9000/photos?uploads", v2, false),
            "http://h:9000/photos/?uploads"
        );
        let link = "/photos?AWSAccessKeyId=k&Expires=1&Signature=s";
        assert_eq!(
            path(link, "", false),
            "/photos/?AWSAccessKeyId=k&Expires=1&Signature=s"
        );
        // Everything else stays as it was sent.
        for (uri, auth, virtual_hosted) in [
            ("/photos/", v2, false),
            ("/photos/cat.jpg", v2, false),
            ("/", v2, false),
            ("/cat.jpg", v2, true),
            ("/photos", "AWS4-HMAC-SHA256 Credential=key", false),
            ("/photos", "", false),
            ("/photos?AWSAccessKeyId=k", "", false),
        ] {
            assert_eq!(path(uri, auth, virtual_hosted), uri, "{uri} {auth}");
        }
    }
}
