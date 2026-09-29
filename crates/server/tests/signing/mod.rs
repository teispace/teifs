//! Requests signed the way any Signature V4 tool signs them, for endpoints the SDKs don't call.

/// A request signed with Signature V4 for service `s3`, as any tool can make one: the status and
/// body of the answer. A `host` among `headers` is sent (and signed) instead of the server's, as
/// a virtual-hosted-style request would be, without needing the name to resolve.
pub async fn signed(
    server: &crate::common::Server,
    (access_key, secret): (&str, &str),
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    use aws_sigv4::{
        http_request::{PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign},
        sign::v4,
    };
    let url = format!("{}{path}", server.endpoint);
    let host = server.endpoint.trim_start_matches("http://").to_owned();
    let mut all: Vec<(&str, &str)> = headers.to_vec();
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        all.push(("host", &host));
    }
    let identity =
        aws_credential_types::Credentials::new(access_key, secret, None, None, "tests").into();
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
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
    let mut request = reqwest::Client::new()
        .request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            &url,
        )
        .body(body.to_vec());
    for (name, value) in headers.iter().copied().chain(instructions.headers()) {
        request = request.header(name, value);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}
