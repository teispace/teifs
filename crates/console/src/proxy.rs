//! Passing the page's calls on to the S3 service: each is rebuilt from the headers it
//! may carry, signed with the session's key, and sent over an in-memory HTTP/1.1
//! connection to the S3 service, which answers it as it would any client's.

use std::time::SystemTime;

use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        UriPathNormalizationMode, sign,
    },
    sign::v4,
};
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use md5::Digest as _;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use s3s::HttpResponse;
use teifs_s3::Client;

use crate::{
    Shared,
    sessions::{Key, Session},
};

/// The region requests are signed for (TeiFS takes any).
const REGION: &str = "us-east-1";
/// Bodies up to this size are read, hashed and signed; bigger ones (object uploads) are
/// streamed unsigned (`UNSIGNED-PAYLOAD`), which only S3 accepts.
pub(crate) const MAX_BUFFERED: usize = 1024 * 1024;
/// The in-memory connection's buffer.
const PIPE_BYTES: usize = 256 * 1024;
/// The largest STS answer a sign-in reads.
const MAX_STS_ANSWER: usize = 64 * 1024;

/// The headers the page may send on: what S3's operations read. Never cookies,
/// `Authorization`, the proxies' `X-Forwarded-*`, nor the signature's own headers.
const FORWARDED: &[&str] = &[
    "content-type",
    "content-length",
    "content-md5",
    "content-encoding",
    "content-language",
    "content-disposition",
    "cache-control",
    "expires",
    "range",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
];
/// The `x-amz-` headers the signature sets itself.
const SIGNATURE_HEADERS: &[&str] = &[
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
    "x-amz-decoded-content-length",
];
/// Query parameters that would make a request a presigned one.
const PRESIGNED: &[&str] = &[
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-signature",
    "x-amz-signedheaders",
    "x-amz-date",
    "x-amz-expires",
    "x-amz-security-token",
    "awsaccesskeyid",
    "signature",
];

/// What Signature V4 leaves unencoded in a path segment: RFC 3986's unreserved characters.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// `path` (as the page sent it) in Signature V4's canonical form: each segment decoded,
/// then encoded once, so what's signed is what the S3 service checks.
pub(crate) fn canonical_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            let raw: Vec<u8> = percent_decode_str(segment).collect();
            percent_encoding::percent_encode(&raw, SEGMENT).to_string()
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether `query` holds a presigned URL's parameters.
fn presigned(query: &str) -> bool {
    form_urlencoded::parse(query.as_bytes())
        .any(|(name, _)| PRESIGNED.contains(&name.to_ascii_lowercase().as_str()))
}

/// The headers of the page's request that go on to the S3 service.
fn forwarded(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        let name_str = name.as_str();
        let allowed = FORWARDED.contains(&name_str)
            || (name_str.starts_with("x-amz-") && !SIGNATURE_HEADERS.contains(&name_str));
        if allowed && value.to_str().is_ok() {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// A request's body: read whole (small), or streamed as it came (an upload).
enum Payload {
    Read(Bytes),
    Streamed(Incoming),
}

/// Why a page's call wasn't passed on.
fn refused(status: StatusCode, code: &str, message: &str) -> HttpResponse {
    crate::error(status, code, message)
}

/// Reads the body if it's small, else keeps it to stream (S3 only).
async fn payload(
    body: Incoming,
    length: Option<u64>,
    service: &str,
) -> Result<Payload, Box<HttpResponse>> {
    let too_big = || {
        refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            "TooLarge",
            "That request's body is too big for the console to send.",
        )
    };
    match length {
        Some(length) if length > MAX_BUFFERED as u64 => {
            if service == "s3" {
                Ok(Payload::Streamed(body))
            } else {
                Err(Box::new(too_big()))
            }
        }
        _ => match http_body_util::Limited::new(body, MAX_BUFFERED)
            .collect()
            .await
        {
            Ok(collected) => Ok(Payload::Read(collected.to_bytes())),
            Err(err) if err.is::<http_body_util::LengthLimitError>() => Err(Box::new(too_big())),
            Err(_) => Err(Box::new(refused(
                StatusCode::BAD_REQUEST,
                "IncompleteBody",
                "The request's body didn't all arrive.",
            ))),
        },
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
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

/// Signs a request for `service` with `key`: adds `Authorization`, `X-Amz-Date`,
/// `X-Amz-Content-Sha256` (`hash`, or `UNSIGNED-PAYLOAD` for `None`) and the session
/// token, if any.
pub(crate) fn sign_request(
    method: &Method,
    url: &str,
    headers: &mut HeaderMap,
    key: &Key,
    service: &str,
    hash: Option<&str>,
) -> Result<(), String> {
    let identity = aws_credential_types::Credentials::new(
        &key.id,
        key.secret.as_str(),
        key.token.as_deref().cloned(),
        None,
        "teifs-console",
    )
    .into();
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    // S3 signs the path as it's sent, encoded once; so do IAM and STS at `/`.
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(REGION)
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|e| e.to_string())?
        .into();
    let pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(n, v)| Some((n.as_str().to_owned(), v.to_str().ok()?.to_owned())))
        .collect();
    let body = match hash {
        Some(hash) => SignableBody::Precomputed(hash.to_owned()),
        None => SignableBody::UnsignedPayload,
    };
    let signable = SignableRequest::new(
        method.as_str(),
        url,
        pairs.iter().map(|(n, v)| (n.as_str(), v.as_str())),
        body,
    )
    .map_err(|e| e.to_string())?;
    let (instructions, _) = sign(signable, &params)
        .map_err(|e| e.to_string())?
        .into_parts();
    for (name, value) in instructions.headers() {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| e.to_string())?;
        let value = HeaderValue::from_str(value).map_err(|e| e.to_string())?;
        headers.insert(name, value);
    }
    Ok(())
}

/// Sends `req` to the S3 service as `client`'s, over a fresh in-memory connection.
pub(crate) async fn call(
    s3: &teifs_s3::Service,
    client: Client,
    req: Request<s3s::Body>,
) -> Result<Response<Incoming>, String> {
    let (near, far) = tokio::io::duplex(PIPE_BYTES);
    let service = s3.for_client(client);
    tokio::spawn(async move {
        let mut http = hyper::server::conn::http1::Builder::new();
        http.timer(TokioTimer::new());
        if let Err(err) = http.serve_connection(TokioIo::new(far), service).await {
            tracing::debug!(error = %err, "the console's connection to S3 ended with an error");
        }
    });
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(near))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender.send_request(req).await.map_err(|e| e.to_string())
}

/// Builds, signs and sends one request to the S3 service.
async fn send(
    shared: &Shared,
    key: &Key,
    client: Client,
    (method, path_and_query): (Method, String),
    mut headers: HeaderMap,
    service: &str,
    payload: Payload,
) -> Result<Response<Incoming>, String> {
    headers.insert(
        header::HOST,
        HeaderValue::from_str(&shared.host).map_err(|e| e.to_string())?,
    );
    let url = format!("http://{}{path_and_query}", shared.host);
    let (body, hash) = match payload {
        Payload::Read(bytes) => {
            if !bytes.is_empty() && !headers.contains_key("content-md5") {
                let md5 = md5::Md5::digest(&bytes);
                let value = base64::engine::general_purpose::STANDARD.encode(md5);
                headers.insert(
                    "content-md5",
                    HeaderValue::from_str(&value).map_err(|e| e.to_string())?,
                );
            }
            if !bytes.is_empty() || matches!(method, Method::POST | Method::PUT) {
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
            }
            let hash = sha256_hex(&bytes);
            (s3s::Body::from(bytes), Some(hash))
        }
        Payload::Streamed(incoming) => (s3s::Body::from(incoming), None),
    };
    sign_request(&method, &url, &mut headers, key, service, hash.as_deref())?;
    let mut req = Request::new(body);
    *req.method_mut() = method;
    *req.uri_mut() = path_and_query
        .parse()
        .map_err(|e: http::uri::InvalidUri| e.to_string())?;
    *req.headers_mut() = headers;
    call(&shared.s3, client, req).await
}

/// The S3 service's answer, as the page gets it: its own cookies, if any, never.
fn answer(response: Response<Incoming>) -> HttpResponse {
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(header::SET_COOKIE);
    Response::from_parts(parts, s3s::Body::from(body))
}

fn unreachable_s3(why: &str) -> HttpResponse {
    tracing::warn!(error = %why, "the console couldn't reach the S3 service");
    refused(
        StatusCode::BAD_GATEWAY,
        "Unreachable",
        "The console couldn't reach the S3 service.",
    )
}

/// Passes on one of the page's calls, for `service` at `path`, signed by the session.
pub(crate) async fn forward(
    shared: &Shared,
    session: &Session,
    client: Client,
    req: Request<Incoming>,
    service: &str,
    path: &str,
) -> HttpResponse {
    let query = req.uri().query().unwrap_or_default().to_owned();
    if presigned(&query) {
        return refused(
            StatusCode::BAD_REQUEST,
            "Presigned",
            "The console signs requests itself: send no signature in the query.",
        );
    }
    let (parts, body) = req.into_parts();
    let headers = forwarded(&parts.headers);
    let length = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    let payload = match payload(body, length, service).await {
        Ok(payload) => payload,
        Err(refused) => return *refused,
    };
    let mut target = canonical_path(path);
    if !query.is_empty() {
        target.push('?');
        target.push_str(&query);
    }
    match send(
        shared,
        &session.key,
        client,
        (parts.method, target),
        headers,
        service,
        payload,
    )
    .await
    {
        Ok(response) => answer(response),
        Err(why) => unreachable_s3(&why),
    }
}

/// Gets an object for a plain link: `path` is `/BUCKET/KEY`; of the query, only
/// `versionId` goes on.
pub(crate) async fn download(
    shared: &Shared,
    session: &Session,
    client: Client,
    req: Request<Incoming>,
    path: &str,
) -> HttpResponse {
    let version = req.uri().query().and_then(|query| {
        form_urlencoded::parse(query.as_bytes())
            .find(|(name, _)| name == "versionId")
            .map(|(_, value)| value.into_owned())
    });
    let mut target = canonical_path(path);
    if let Some(version) = version {
        target.push_str("?versionId=");
        target.push_str(&utf8_percent_encode(&version, SEGMENT).to_string());
    }
    let mut headers = HeaderMap::new();
    for name in ["range", "if-match", "if-none-match"] {
        if let Some(value) = req.headers().get(name) {
            headers.insert(name, value.clone());
        }
    }
    let method = req.method().clone();
    match send(
        shared,
        &session.key,
        client,
        (method, target),
        headers,
        "s3",
        Payload::Read(Bytes::new()),
    )
    .await
    {
        Ok(response) => answer(response),
        Err(why) => unreachable_s3(&why),
    }
}

/// The last segment of an object's key (as the link encodes it), decoded: the name a
/// download is saved as.
pub(crate) fn file_name(key: &str) -> String {
    let last = key
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("download");
    let name = percent_decode_str(last).decode_utf8_lossy().into_owned();
    if name.is_empty() {
        "download".into()
    } else {
        name
    }
}

/// Makes a download an attachment named `name`, whatever the object's own
/// `Content-Disposition` says.
pub(crate) fn attachment(headers: &mut HeaderMap, name: &str) {
    let ascii: String = name
        .chars()
        .map(|c| {
            if (c.is_ascii_graphic() && c != '"' && c != '\\') || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let encoded = utf8_percent_encode(name, SEGMENT);
    let value = format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}");
    if let Ok(value) = HeaderValue::from_str(&value) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
}

/// Why a sign-in failed.
#[derive(Debug)]
pub(crate) enum SignInError {
    /// The key doesn't sign in.
    Refused,
    /// The server couldn't be asked.
    Unavailable(String),
}

/// Who `key` is, by STS `GetCallerIdentity`: its ARN and account. Any key that signs
/// may call it, so a refusal means the key doesn't sign.
pub(crate) async fn caller_identity(
    shared: &Shared,
    client: Client,
    key: &Key,
) -> Result<(String, String), SignInError> {
    let form = Bytes::from_static(b"Action=GetCallerIdentity&Version=2011-06-15");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
    );
    let response = send(
        shared,
        key,
        client,
        (Method::POST, "/".into()),
        headers,
        "sts",
        Payload::Read(form),
    )
    .await
    .map_err(SignInError::Unavailable)?;
    let status = response.status();
    let body = http_body_util::Limited::new(response.into_body(), MAX_STS_ANSWER)
        .collect()
        .await
        .map_err(|e| SignInError::Unavailable(e.to_string()))?
        .to_bytes();
    if status.is_server_error() {
        return Err(SignInError::Unavailable(format!("STS answered {status}")));
    }
    if !status.is_success() {
        return Err(SignInError::Refused);
    }
    let xml = String::from_utf8_lossy(&body);
    match (element(&xml, "Arn"), element(&xml, "Account")) {
        (Some(arn), Some(account)) => Ok((arn, account)),
        _ => Err(SignInError::Unavailable(
            "STS's answer has no Arn or Account".into(),
        )),
    }
}

/// The text of the first `<name>` element in `xml`, unescaped.
fn element(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(
        xml[start..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_encoded_once_as_sigv4_signs_them() {
        assert_eq!(canonical_path("/b/a b.txt"), "/b/a%20b.txt");
        assert_eq!(canonical_path("/b/a%20b.txt"), "/b/a%20b.txt");
        assert_eq!(canonical_path("/b/x!(y)*'"), "/b/x%21%28y%29%2A%27");
        assert_eq!(canonical_path("/b/caf%C3%A9/"), "/b/caf%C3%A9/");
        assert_eq!(
            canonical_path("/b/a%2Fb"),
            "/b/a%2Fb",
            "an encoded slash stays one"
        );
        assert_eq!(canonical_path("/b/~a-b_c.d"), "/b/~a-b_c.d");
        assert_eq!(canonical_path("/"), "/");
    }

    #[test]
    fn only_s3s_headers_go_on() {
        let mut sent = HeaderMap::new();
        for (name, value) in [
            ("cookie", "teifs-console=secret"),
            ("authorization", "AWS4-HMAC-SHA256 forged"),
            ("x-forwarded-for", "10.0.0.1"),
            ("x-amz-security-token", "forged"),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("x-amz-date", "20200101T000000Z"),
            ("x-teifs-console", "1"),
            ("origin", "http://127.0.0.1:9001"),
            ("content-type", "text/plain"),
            ("x-amz-meta-colour", "blue"),
            ("x-amz-checksum-sha256", "abc="),
            ("range", "bytes=0-9"),
        ] {
            sent.insert(name, HeaderValue::from_static(value));
        }
        let out = forwarded(&sent);
        let mut names: Vec<&str> = out.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "content-type",
                "range",
                "x-amz-checksum-sha256",
                "x-amz-meta-colour"
            ]
        );
    }

    #[test]
    fn presigned_queries_are_seen_in_any_case() {
        assert!(presigned("X-Amz-Signature=abc"));
        assert!(presigned("prefix=a&x-amz-credential=abc"));
        assert!(presigned("AWSAccessKeyId=a&Signature=b"));
        assert!(!presigned("list-type=2&prefix=x-amz-signature"));
        assert!(!presigned(""));
    }

    #[test]
    fn downloads_are_named_after_the_key() {
        assert_eq!(file_name("photos/2024/caf%C3%A9.jpg"), "café.jpg");
        assert_eq!(file_name("folder/"), "folder");
        assert_eq!(file_name(""), "download");
        let mut headers = HeaderMap::new();
        attachment(&mut headers, "a \"b\".txt");
        assert_eq!(
            headers["content-disposition"],
            "attachment; filename=\"a _b_.txt\"; filename*=UTF-8''a%20%22b%22.txt"
        );
        attachment(&mut headers, "café\r\n.html");
        let value = headers["content-disposition"].to_str().unwrap();
        assert!(
            value.starts_with("attachment; filename=\"caf___.html\""),
            "{value}"
        );
    }

    #[test]
    fn sts_answers_are_read() {
        let xml = "<GetCallerIdentityResponse><GetCallerIdentityResult>\
            <Arn>arn:aws:iam::123456789012:user/a&amp;b</Arn><UserId>X</UserId>\
            <Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>";
        assert_eq!(
            element(xml, "Arn").as_deref(),
            Some("arn:aws:iam::123456789012:user/a&b")
        );
        assert_eq!(element(xml, "Account").as_deref(), Some("123456789012"));
        assert_eq!(element(xml, "Missing"), None);
    }
}
