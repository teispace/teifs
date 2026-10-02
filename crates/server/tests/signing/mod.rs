//! Requests signed the way any Signature V4 tool signs them, for endpoints the SDKs don't call.

#![allow(dead_code, reason = "each test binary uses a different part")]

use aws_sigv4::http_request::PercentEncodingMode;

/// A request signed with Signature V4 for service `s3`, as any tool can make one: the status and
/// body of the answer. A `host` among `headers` is sent (and signed) instead of the server's, as
/// a virtual-hosted-style request would be, without needing the name to resolve.
pub async fn signed(
    server: &crate::common::Server,
    key: (&str, &str),
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    let response = signed_response(server, key, method, path, headers, body).await;
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

/// [`signed`], answering the whole response.
pub async fn signed_response(
    server: &crate::common::Server,
    key: (&str, &str),
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> reqwest::Response {
    send(
        &reqwest::Client::new(),
        server,
        (key.0, key.1, None),
        (method, path),
        headers,
        body,
        PercentEncodingMode::Double,
    )
    .await
}

/// [`signed`], sent by `client` (one that trusts a test CA, say).
pub async fn signed_over(
    client: &reqwest::Client,
    server: &crate::common::Server,
    key: (&str, &str),
    method: &str,
    path: &str,
) -> (u16, String) {
    let response = send(
        client,
        server,
        (key.0, key.1, None),
        (method, path),
        &[],
        b"",
        PercentEncodingMode::Double,
    )
    .await;
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

/// [`signed`], with temporary credentials: (access key, secret, session token).
pub async fn signed_session(
    server: &crate::common::Server,
    (access_key, secret, token): (&str, &str, &str),
    method: &str,
    path: &str,
) -> (u16, String) {
    let response = send(
        &reqwest::Client::new(),
        server,
        (access_key, secret, Some(token)),
        (method, path),
        &[],
        b"",
        PercentEncodingMode::Double,
    )
    .await;
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

/// [`signed`], with the path signed as sent, as botocore signs S3's (AWS's other SDKs
/// encode it again first).
pub async fn signed_as_sent(
    server: &crate::common::Server,
    key: (&str, &str),
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    let response = send(
        &reqwest::Client::new(),
        server,
        (key.0, key.1, None),
        (method, path),
        headers,
        body,
        PercentEncodingMode::Single,
    )
    .await;
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

async fn send(
    client: &reqwest::Client,
    server: &crate::common::Server,
    (access_key, secret, token): (&str, &str, Option<&str>),
    (method, path): (&str, &str),
    headers: &[(&str, &str)],
    body: &[u8],
    encoding: PercentEncodingMode,
) -> reqwest::Response {
    use aws_sigv4::{
        http_request::{PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign},
        sign::v4,
    };
    let url = format!("{}{path}", server.endpoint);
    let host = server
        .endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_owned();
    let mut all: Vec<(&str, &str)> = headers.to_vec();
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        all.push(("host", &host));
    }
    let identity = aws_credential_types::Credentials::new(
        access_key,
        secret,
        token.map(str::to_owned),
        None,
        "tests",
    )
    .into();
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    settings.percent_encoding_mode = encoding;
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("s3")
        .time(std::time::SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let signable =
        SignableRequest::new(method, &url, all.iter().copied(), SignableBody::Bytes(body)).unwrap();
    let (instructions, _) = sign(signable, &params).unwrap().into_parts();
    let mut request = client
        .request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            &url,
        )
        .body(body.to_vec());
    for (name, value) in headers.iter().copied().chain(instructions.headers()) {
        request = request.header(name, value);
    }
    request.send().await.unwrap()
}
