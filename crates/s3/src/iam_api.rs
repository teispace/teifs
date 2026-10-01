//! IAM's and STS's APIs on the S3 endpoint, as MinIO and other S3-compatible servers
//! serve theirs: a signed `POST /` with a form body is an IAM request when its signature
//! is for service `iam`, an STS request for `sts`. `aws iam …` and the SDKs reach them
//! with `--endpoint-url` pointed at the drive.
//!
//! The Query protocol's clients don't send `x-amz-content-sha256`, which s3s needs to
//! check a signature, so [`with_payload_hash`] adds it from the body before s3s sees
//! the request; the signature then covers the body as the client sent it. The route
//! checks the hash against the body again itself, so a request whose body isn't what
//! was signed (or that says `UNSIGNED-PAYLOAD`) is refused whatever s3s does with it.
//!
//! `AssumeRoleWithWebIdentity` is the exception, as on AWS: its web identity token says
//! who is asking, so it's answered unsigned (the AWS CLI and SDKs send it so), and a
//! signature on it counts for nothing. So is MinIO's `AssumeRoleWithLDAPIdentity`, whose
//! user name and password say who is asking, and `AssumeRoleWithCertificate`, whose
//! connection's client certificate does. MinIO's clients send these with the parameters
//! in the query and no body (`POST /?Action=…`), which is taken as the form too.

use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header};
use s3s::{Body, S3Request, S3Response};
use teifs_iam::{AuthError, Call, Iam, Identity, Reply};

use crate::{
    access::{Client, ClientCertificates, base_context, security_token},
    routes::{INCOMPLETE, signed_body, unreadable},
};

/// The largest form accepted: AWS's largest (a policy document of 131 072 characters)
/// percent-encoded three times over, with room to spare.
pub(crate) const MAX_FORM_BYTES: usize = 512 * 1024;

pub(crate) const CONTENT_SHA256: &str = "x-amz-content-sha256";
const FORM: &str = "application/x-www-form-urlencoded";

/// Whether a request is a form posted to `/`: what the Query protocol sends; or a post
/// to `/` whose query names an action, as MinIO's clients send STS requests.
pub(crate) fn is_form_post(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    method == Method::POST
        && uri.path() == "/"
        && (headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case(FORM))
            || query_names_action(uri))
}

/// Whether `uri`'s query has an `Action` parameter.
fn query_names_action(uri: &Uri) -> bool {
    form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).any(|(n, _)| n == "Action")
}

/// The form: the body, or the query when the body is empty and the query names an
/// action.
fn form(body: bytes::Bytes, uri: &Uri) -> bytes::Bytes {
    if body.is_empty() && query_names_action(uri) {
        bytes::Bytes::copy_from_slice(uri.query().unwrap_or_default().as_bytes())
    } else {
        body
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    digest
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

/// A SigV4-signed form post without `x-amz-content-sha256`, with the header added from
/// its body (read up to [`MAX_FORM_BYTES`]); any other request as it is. `Err` is the
/// answer to a body that couldn't be read.
pub(crate) async fn with_payload_hash(
    mut req: Request<Body>,
) -> Result<Request<Body>, Box<s3s::HttpResponse>> {
    let signed_v4 = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 "));
    if !signed_v4
        || req.headers().contains_key(CONTENT_SHA256)
        || !is_form_post(req.method(), req.uri(), req.headers())
    {
        return Ok(req);
    }
    let bytes = match req.body_mut().store_all_limited(MAX_FORM_BYTES).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let (status, code, message) = unreadable(err.as_ref(), INCOMPLETE);
            return Err(Box::new(crate::cors::error(status, code, message)));
        }
    };
    let hash = HeaderValue::from_str(&sha256_hex(&bytes)).expect("hex is a valid header value");
    req.headers_mut().insert(CONTENT_SHA256, hash);
    Ok(req)
}

/// Answers an IAM or STS request, in the Query protocol's format.
pub(crate) async fn serve(iam: &Iam, mut req: S3Request<Body>) -> S3Response<Body> {
    let request_id = crate::observe::request_id(&req.extensions);
    let reply = answer(iam, &mut req, &request_id).await;
    let mut response = S3Response::new(crate::routes::unlogged(reply.body));
    response.status =
        Some(StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    response
        .headers
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/xml"));
    if let Ok(id) = HeaderValue::from_str(&request_id) {
        response.headers.insert("x-amzn-requestid", id);
    }
    response
}

async fn answer(iam: &Iam, req: &mut S3Request<Body>, request_id: &str) -> Reply {
    let refuse = |status: StatusCode, code: &str, message: &str| Reply {
        status: status.as_u16(),
        body: format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ErrorResponse><Error><Type>Sender</Type>\
                 <Code>{code}</Code><Message>{message}</Message></Error>\
                 <RequestId>{request_id}</RequestId></ErrorResponse>"
        ),
    };
    let Some(access_key) = req.credentials.as_ref().map(|c| c.access_key.clone()) else {
        // Unsigned: only a request that carries its own proof of who's asking.
        let body = match req.input.store_all_limited(MAX_FORM_BYTES).await {
            Ok(body) => form(body, &req.uri),
            Err(err) => {
                let (status, code, message) = unreadable(err.as_ref(), INCOMPLETE);
                return refuse(status, code, message);
            }
        };
        if !Iam::proves_itself(&body) {
            return refuse(
                StatusCode::FORBIDDEN,
                "MissingAuthenticationToken",
                "Request is missing Authentication Token",
            );
        }
        return self_proving(iam, req, &body, request_id).await;
    };
    let body = match signed_body(req, MAX_FORM_BYTES).await {
        Ok(body) => form(body, &req.uri),
        Err((status, code, message)) => return refuse(status, code, message),
    };
    // Whoever signed it has no part in a request that carries its own proof.
    if req.service.as_deref() == Some("sts") && Iam::proves_itself(&body) {
        return self_proving(iam, req, &body, request_id).await;
    }
    // A key deleted since its signature was checked is refused like any other, as is a
    // session whose user or role is gone.
    let token = security_token(&req.headers, &req.uri);
    let identity = match iam.identify(&access_key, token.as_deref()) {
        Ok(identity) => identity,
        Err(AuthError::ExpiredToken) => {
            return refuse(
                StatusCode::FORBIDDEN,
                "ExpiredToken",
                "The security token included in the request is expired",
            );
        }
        Err(AuthError::UnknownKey | AuthError::InvalidToken | AuthError::Revoked) => {
            return refuse(
                StatusCode::FORBIDDEN,
                "InvalidClientTokenId",
                "The security token included in the request is invalid.",
            );
        }
    };
    let client = req.extensions.get::<Client>().copied().unwrap_or_default();
    let context = base_context(&identity, &req.headers, client, &iam.account());
    let call = Call {
        identity: &identity,
        context: &context,
        body: &body,
        request_id,
        certificates: &[],
    };
    match req.service.as_deref() {
        Some("iam") => iam.serve_iam(&call),
        Some("sts") => iam.serve_sts(&call),
        _ => refuse(
            StatusCode::BAD_REQUEST,
            "InvalidAction",
            "A form posted to / is an IAM or STS request, signed for service iam or sts.",
        ),
    }
}

/// Answers a request that carries its own proof of who's asking
/// (`AssumeRoleWithWebIdentity`'s token, `AssumeRoleWithLDAPIdentity`'s password, the
/// connection's client certificate), as the anonymous caller it is.
async fn self_proving(iam: &Iam, req: &S3Request<Body>, body: &[u8], request_id: &str) -> Reply {
    let identity = Identity::anonymous();
    let client = req.extensions.get::<Client>().copied().unwrap_or_default();
    let certificates = req
        .extensions
        .get::<ClientCertificates>()
        .cloned()
        .unwrap_or_default();
    let context = base_context(&identity, &req.headers, client, &iam.account());
    iam.serve_self_proving(&Call {
        identity: &identity,
        context: &context,
        body,
        request_id,
        certificates: &certificates.0,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_posts_to_the_root_are_the_query_protocol() {
        let headers = |value: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
            h
        };
        let root: Uri = "/".parse().unwrap();
        for value in [
            FORM,
            "application/x-www-form-urlencoded; charset=utf-8",
            "Application/X-WWW-Form-Urlencoded",
        ] {
            assert!(
                is_form_post(&Method::POST, &root, &headers(value)),
                "{value}"
            );
        }
        assert!(!is_form_post(&Method::GET, &root, &headers(FORM)));
        assert!(!is_form_post(
            &Method::POST,
            &"/bucket".parse().unwrap(),
            &headers(FORM)
        ));
        assert!(!is_form_post(
            &Method::POST,
            &root,
            &headers("multipart/form-data; boundary=x")
        ));
        assert!(!is_form_post(&Method::POST, &root, &HeaderMap::new()));
        // MinIO's clients: the parameters in the query, no body.
        let query: Uri = "/?Action=AssumeRoleWithCertificate&Version=2011-06-15"
            .parse()
            .unwrap();
        assert!(is_form_post(&Method::POST, &query, &HeaderMap::new()));
        assert!(!is_form_post(&Method::GET, &query, &HeaderMap::new()));
        let other: Uri = "/?uploads".parse().unwrap();
        assert!(!is_form_post(&Method::POST, &other, &HeaderMap::new()));
        assert_eq!(
            form(bytes::Bytes::new(), &query).as_ref(),
            b"Action=AssumeRoleWithCertificate&Version=2011-06-15"
        );
        assert_eq!(
            form(bytes::Bytes::from_static(b"a=b"), &query).as_ref(),
            b"a=b"
        );
        assert!(form(bytes::Bytes::new(), &other).is_empty());
    }

    #[test]
    fn hashes_are_lowercase_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
