//! Behind a reverse proxy: only a trusted proxy's word on who the client is
//! (`aws:SourceIp`) and whether it came over HTTPS (`aws:SecureTransport`, SSE-C) is
//! believed, and only from the header the proxy adds to.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use aws_sdk_s3::{Client, error::ProvideErrorMetadata, primitives::ByteStream};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{SECRET_KEY, Server, client, start_with};
use md5::{Digest, Md5};
use teifs_server::{ProxyHeader, TrustedProxies};

/// A server that trusts proxies on this machine (as the tests connect from), naming
/// clients in `header`; none trusted when `header` is `None`.
async fn behind_proxy(header: Option<ProxyHeader>) -> Server {
    start_with(|config| {
        config.trusted_proxies = header.map_or_else(TrustedProxies::default, |header| {
            TrustedProxies::new(&["127.0.0.1", "::1"], header).unwrap()
        });
        config.default_layout = teifs_store::Layout::Object;
    })
    .await
}

const FROM_ONE_NETWORK: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::office/*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}"#;

async fn office(server: &Server) {
    let s3 = client(server, SECRET_KEY);
    s3.create_bucket().bucket("office").send().await.unwrap();
    s3.put_object()
        .bucket("office")
        .key("memo")
        .body(ByteStream::from_static(b"memo"))
        .send()
        .await
        .unwrap();
    s3.put_bucket_policy()
        .bucket("office")
        .policy(FROM_ONE_NETWORK)
        .send()
        .await
        .unwrap();
}

/// The status of an anonymous read of the memo with `headers`.
async fn read(server: &Server, headers: &[(&str, &str)]) -> u16 {
    let mut request = reqwest::Client::new().get(format!("{}/office/memo", server.endpoint));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn source_ip_is_the_client_a_trusted_proxy_names() {
    let server = behind_proxy(Some(ProxyHeader::XForwardedFor)).await;
    office(&server).await;
    let xff = |v| [("x-forwarded-for", v)];
    assert_eq!(read(&server, &xff("203.0.113.9")).await, 200);
    assert_eq!(read(&server, &xff("198.51.100.1")).await, 403);
    // What the client wrote itself, left of what the proxy added, doesn't count.
    assert_eq!(read(&server, &xff("203.0.113.9, 198.51.100.1")).await, 403);
    assert_eq!(read(&server, &xff("198.51.100.1, 203.0.113.9")).await, 200);
    // Nor does a header the proxy doesn't add to.
    assert_eq!(
        read(&server, &[("forwarded", "for=203.0.113.9")]).await,
        403
    );
    assert_eq!(read(&server, &[("x-real-ip", "203.0.113.9")]).await, 403);
    assert_eq!(read(&server, &[]).await, 403);

    // RFC 7239 when the proxies speak it.
    let server = behind_proxy(Some(ProxyHeader::Forwarded)).await;
    office(&server).await;
    let fwd = [(
        "forwarded",
        r#"for="[2001:db8::1]", for=203.0.113.9;proto=https"#,
    )];
    assert_eq!(read(&server, &fwd).await, 200);
    assert_eq!(
        read(&server, &[("x-forwarded-for", "203.0.113.9")]).await,
        403
    );
}

#[tokio::test]
async fn nobody_else_can_say_who_the_client_is() {
    let server = behind_proxy(None).await;
    office(&server).await;
    for header in ["x-forwarded-for", "x-real-ip"] {
        assert_eq!(read(&server, &[(header, "203.0.113.9")]).await, 403);
    }
    assert_eq!(
        read(&server, &[("forwarded", "for=203.0.113.9")]).await,
        403
    );
}

const DENY_PLAIN_HTTP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::guarded","arn:aws:s3:::guarded/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}"#;

/// Puts an object, the request carrying `headers` as a proxy would add them.
async fn put(s3: &Client, key: &str, headers: &'static [(&'static str, &'static str)]) -> String {
    let result = s3
        .put_object()
        .bucket("guarded")
        .key(key)
        .body(ByteStream::from_static(b"a"))
        .customize()
        .mutate_request(move |request| {
            for (name, value) in headers {
                request.headers_mut().insert(*name, *value);
            }
        })
        .send()
        .await;
    common::code(result)
}

#[tokio::test]
async fn secure_transport_is_what_a_trusted_proxy_says() {
    let server = behind_proxy(Some(ProxyHeader::XForwardedFor)).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("guarded").send().await.unwrap();
    s3.put_bucket_policy()
        .bucket("guarded")
        .policy(DENY_PLAIN_HTTP)
        .send()
        .await
        .unwrap();
    assert_eq!(put(&s3, "a", &[("x-forwarded-proto", "https")]).await, "ok");
    assert_eq!(
        put(&s3, "a", &[("x-forwarded-proto", "http")]).await,
        "AccessDenied"
    );
    assert_eq!(put(&s3, "a", &[]).await, "AccessDenied");

    // Untrusted, the header changes nothing.
    let server = behind_proxy(None).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("guarded").send().await.unwrap();
    s3.put_bucket_policy()
        .bucket("guarded")
        .policy(DENY_PLAIN_HTTP)
        .send()
        .await
        .unwrap();
    assert_eq!(
        put(&s3, "a", &[("x-forwarded-proto", "https")]).await,
        "AccessDenied"
    );
}

#[tokio::test]
async fn sse_c_behind_a_proxy_needs_https_to_the_proxy() {
    // Listening on this machine with a proxy trusted: the proxy may be passing on
    // plain HTTP from anywhere, so only its word counts.
    let server = behind_proxy(Some(ProxyHeader::XForwardedFor)).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("keys").send().await.unwrap();
    let key = [42u8; 32];
    let (k, m) = (STANDARD.encode(key), STANDARD.encode(Md5::digest(key)));
    let with_key = |proto: Option<&'static str>| {
        s3.put_object()
            .bucket("keys")
            .key("c")
            .sse_customer_algorithm("AES256")
            .sse_customer_key(&k)
            .sse_customer_key_md5(&m)
            .body(ByteStream::from_static(b"mine"))
            .customize()
            .mutate_request(move |request| {
                if let Some(proto) = proto {
                    request.headers_mut().insert("x-forwarded-proto", proto);
                }
            })
            .send()
    };
    assert_eq!(common::code(with_key(Some("https")).await), "ok");
    let refused = with_key(None).await.unwrap_err();
    assert_eq!(refused.code(), Some("InvalidRequest"));
    assert_eq!(common::code(with_key(Some("http")).await), "InvalidRequest");
}
