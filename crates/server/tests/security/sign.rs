//! Signature V4 requests built by hand, so a test can change any part of one after it's
//! signed: headers, the query, each chunk of a streamed body, its trailer.

use std::time::{Duration, SystemTime};

use aws_lc_rs::digest::{SHA256, digest};
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, SignableBody, SignableRequest, SignatureLocation, SigningSettings,
        sign,
    },
    sign::v4,
};
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::common::Server;

const REGION: &str = "us-east-1";

/// What a request's `x-amz-content-sha256` says about its body.
#[derive(Clone, Copy)]
pub enum Payload<'a> {
    /// The body itself, hashed.
    Bytes(&'a [u8]),
    /// `STREAMING-…`: the body comes in chunks (or unsigned with a trailer).
    Streaming(&'static str),
}

/// A request signed as `key` signs it, ready to send as it is or changed.
pub struct Signed {
    pub method: reqwest::Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// The request's signature: the first link of a streamed body's chain.
    pub signature: String,
    secret: String,
    time: SystemTime,
}

/// Signs `method path` with `headers` (`host` is added) as `key`.
pub fn signed(
    server: &Server,
    key: (&str, &str),
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    payload: Payload<'_>,
) -> Signed {
    Signing::new(server, key).sign(method, path, headers, payload)
}

/// [`signed`] as of `time`.
pub fn signed_at(
    server: &Server,
    key: (&str, &str),
    (method, path): (&str, &str),
    payload: Payload<'_>,
    time: SystemTime,
) -> Signed {
    let mut signing = Signing::new(server, key);
    signing.time = time;
    signing.sign(method, path, &[], payload)
}

/// [`signed`] in the query, as a presigned link is, valid for a minute.
pub fn presigned(
    server: &Server,
    key: (&str, &str),
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    payload: Payload<'_>,
) -> Signed {
    let mut signing = Signing::new(server, key);
    signing.expires = Some(Duration::from_secs(60));
    signing.sign(method, path, headers, payload)
}

/// Who signs, when, and whether in the query.
struct Signing<'a> {
    server: &'a Server,
    key: (&'a str, &'a str),
    time: SystemTime,
    /// In the query, valid for so long; else in the headers.
    expires: Option<Duration>,
}

impl<'a> Signing<'a> {
    fn new(server: &'a Server, key: (&'a str, &'a str)) -> Self {
        Self {
            server,
            key,
            time: SystemTime::now(),
            expires: None,
        }
    }

    fn sign(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        payload: Payload<'_>,
    ) -> Signed {
        let (access_key, secret) = self.key;
        let url = format!("{}{path}", self.server.endpoint);
        let host = self
            .server
            .endpoint
            .trim_start_matches("http://")
            .to_owned();
        let mut all: Vec<(&str, &str)> = headers.to_vec();
        all.push(("host", &host));
        let identity =
            aws_credential_types::Credentials::new(access_key, secret, None, None, "tests").into();
        let mut settings = SigningSettings::default();
        if let Some(expires) = self.expires {
            settings.signature_location = SignatureLocation::QueryParams;
            settings.expires_in = Some(expires);
        } else {
            settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        }
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(REGION)
            .name("s3")
            .time(self.time)
            .settings(settings)
            .build()
            .unwrap()
            .into();
        let body = match payload {
            Payload::Bytes(bytes) => SignableBody::Bytes(bytes),
            Payload::Streaming(kind) => SignableBody::Precomputed(kind.to_owned()),
        };
        let signable = SignableRequest::new(method, &url, all.iter().copied(), body).unwrap();
        let (instructions, signature) = sign(signable, &params).unwrap().into_parts();
        let mut signed_headers: Vec<(String, String)> = all
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        signed_headers.extend(
            instructions
                .headers()
                .map(|(name, value)| (name.to_owned(), value.to_owned())),
        );
        let mut url = reqwest::Url::parse(&url).unwrap();
        for (name, value) in instructions.params() {
            url.query_pairs_mut().append_pair(name, value);
        }
        Signed {
            method: reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            url: url.to_string(),
            headers: signed_headers,
            signature,
            secret: secret.to_owned(),
            time: self.time,
        }
    }
}

impl Signed {
    /// Sends it with `extra` headers added after signing, and `body`.
    pub async fn send(&self, extra: &[(&str, &str)], body: impl Into<reqwest::Body>) -> Answer {
        let mut request = reqwest::Client::new()
            .request(self.method.clone(), &self.url)
            .body(body);
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        Answer::from(request.send().await.unwrap()).await
    }

    /// Its headers with `name` set to `value` instead.
    pub fn with_header(&self, name: &str, value: &str) -> Vec<(String, String)> {
        self.headers
            .iter()
            .map(|(n, v)| {
                let v = if n.eq_ignore_ascii_case(name) {
                    value
                } else {
                    v
                };
                (n.clone(), v.to_owned())
            })
            .collect()
    }

    /// Sends it with `headers` in place of the signed ones.
    pub async fn send_headers(&self, headers: &[(String, String)], body: Vec<u8>) -> Answer {
        let mut request = reqwest::Client::new()
            .request(self.method.clone(), &self.url)
            .body(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        Answer::from(request.send().await.unwrap()).await
    }

    /// The frames of an `aws-chunked` body carrying `chunks`, each signed after the one
    /// before (the request's signature first), the empty last chunk included; then, with
    /// `trailer`, the trailing checksum header and its signature.
    pub fn chunks(&self, chunks: &[&[u8]], trailer: Option<(&str, &str)>) -> Vec<Vec<u8>> {
        let mut chain = self.signature.clone();
        let mut frames = Vec::new();
        for chunk in chunks.iter().copied().chain([&b""[..]]) {
            let hash = format!("{}\n{}", sha256_hex(b""), sha256_hex(chunk));
            chain = self.link("AWS4-HMAC-SHA256-PAYLOAD", &chain, &hash);
            let mut frame = format!("{:x};chunk-signature={chain}\r\n", chunk.len()).into_bytes();
            frame.extend_from_slice(chunk);
            if !chunk.is_empty() || trailer.is_none() {
                frame.extend_from_slice(b"\r\n");
            }
            frames.push(frame);
        }
        if let Some((name, value)) = trailer {
            let hash = sha256_hex(format!("{name}:{value}\n").as_bytes());
            let signature = self.link("AWS4-HMAC-SHA256-TRAILER", &chain, &hash);
            frames.push(
                format!("{name}:{value}\r\nx-amz-trailer-signature:{signature}\r\n\r\n")
                    .into_bytes(),
            );
        }
        frames
    }

    /// The next signature of a streamed body's chain.
    fn link(&self, algorithm: &str, previous: &str, hash: &str) -> String {
        let (date, time) = stamp(self.time);
        let scope = format!("{date}/{REGION}/s3/aws4_request");
        let key = v4::generate_signing_key(&self.secret, self.time, REGION, "s3");
        let to_sign = format!("{algorithm}\n{date}T{time}Z\n{scope}\n{previous}\n{hash}");
        v4::calculate_signature(key, to_sign.as_bytes())
    }
}

/// The frames of an unsigned `aws-chunked` body with a trailing checksum header.
pub fn unsigned_chunks(chunks: &[&[u8]], (name, value): (&str, &str)) -> Vec<u8> {
    let mut body = Vec::new();
    for chunk in chunks {
        body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        body.extend_from_slice(chunk);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("0\r\n{name}:{value}\r\n\r\n").as_bytes());
    body
}

/// Changes the hex digit right after `marker` in `frame`, as a forger would.
pub fn flip_after(frame: &mut [u8], marker: &str) {
    let at = frame
        .windows(marker.len())
        .position(|w| w == marker.as_bytes())
        .unwrap()
        + marker.len();
    frame[at] = if frame[at] == b'0' { b'1' } else { b'0' };
}

/// The base64 SHA-256 of `data`, as `x-amz-checksum-sha256` has it.
pub fn sha256_base64(data: &[u8]) -> String {
    STANDARD.encode(digest(&SHA256, data))
}

fn sha256_hex(data: &[u8]) -> String {
    hex(digest(&SHA256, data).as_ref())
}

/// `bytes` in lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// `YYYYMMDD` and `HHMMSS` of `time`, in UTC.
fn stamp(time: SystemTime) -> (String, String) {
    let t = time::OffsetDateTime::from(time);
    (
        format!("{:04}{:02}{:02}", t.year(), u8::from(t.month()), t.day()),
        format!("{:02}{:02}{:02}", t.hour(), t.minute(), t.second()),
    )
}

/// A response's status, headers, S3 error code (if any) and body.
pub struct Answer {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub code: String,
    pub body: String,
}

impl Answer {
    pub async fn from(response: reqwest::Response) -> Self {
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap();
        let code = body
            .split_once("<Code>")
            .and_then(|(_, rest)| rest.split_once("</Code>"))
            .map_or_else(String::new, |(code, _)| code.to_owned());
        Self {
            status,
            headers,
            code,
            body,
        }
    }
}
