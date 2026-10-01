//! HTTPS: certificates chosen by the name a client asks for, reloaded when their files
//! change, plain HTTP on the HTTPS port answered with a hint, `aws:SecureTransport`,
//! `s3:TlsVersion` and SSE-C keys decided by the connection.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use std::{fs, net::SocketAddr, path::Path};

use aws_sdk_s3::{error::ProvideErrorMetadata, primitives::ByteStream};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{Server, certs::Authority, start_with};
use md5::{Digest, Md5};
use teifs_server::TlsSource;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// A server on HTTPS with the certificates in `dir`, and its address.
async fn https(dir: &Path, plain_http_is_secure: Option<bool>) -> (Server, SocketAddr) {
    let source = TlsSource::Dir(dir.to_owned());
    let server = start_with(|config| {
        config.tls = Some(source);
        config.plain_http_is_secure = plain_http_is_secure;
        config.default_layout = teifs_store::Layout::Object;
    })
    .await;
    let address = server
        .endpoint
        .strip_prefix("https://")
        .unwrap()
        .parse()
        .unwrap();
    (server, address)
}

#[tokio::test]
async fn each_name_gets_its_certificate() {
    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    let default = ca.issue_into(certs.path(), &["localhost", "127.0.0.1"]);
    let named = ca.issue_into(
        &certs.path().join("example"),
        &["s3.example.test", "*.s3.example.test"],
    );
    // Folders a Kubernetes secret has, and a CAs folder, aren't certificates.
    fs::create_dir(certs.path().join("..data")).unwrap();
    fs::create_dir(certs.path().join("CAs")).unwrap();
    let (server, address) = https(certs.path(), None).await;
    assert!(server.endpoint.starts_with("https://"));

    for (name, expected) in [
        ("s3.example.test", &named),
        ("photos.s3.example.test", &named),
        ("localhost", &default),
        // No SNI for an IP address: the default.
        ("127.0.0.1", &default),
    ] {
        let (presented, _) = ca.handshake(address, name, &[]).await.unwrap();
        assert_eq!(presented, expected.der, "{name}");
    }
    // A name no certificate has gets the default, which the client refuses.
    assert!(ca.handshake(address, "other.test", &[]).await.is_err());
    // HTTP/2 when the client offers it.
    let (_, alpn) = ca
        .handshake(address, "localhost", &["h2", "http/1.1"])
        .await
        .unwrap();
    assert_eq!(alpn.as_deref(), Some(&b"h2"[..]));

    // Requests work over it, with HTTP/2 too.
    let s3 = ca.client(&server);
    s3.create_bucket().bucket("tls").send().await.unwrap();
    s3.put_object()
        .bucket("tls")
        .key("a")
        .body(ByteStream::from_static(b"over TLS"))
        .send()
        .await
        .unwrap();
    let health = ca
        .reqwest()
        .get(format!("{}/.teifs/health", server.endpoint))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
}

#[tokio::test]
async fn plain_http_on_the_https_port_is_told_to_use_https() {
    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    ca.issue_into(certs.path(), &["localhost"]);
    let (_server, address) = https(certs.path(), None).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    socket.read_to_string(&mut answer).await.unwrap();
    assert!(
        answer.starts_with("HTTP/1.0 400 Bad Request\r\n"),
        "{answer}"
    );
    assert!(
        answer.ends_with("Client sent an HTTP request to an HTTPS server.\n"),
        "{answer}"
    );
}

#[tokio::test]
async fn certificates_reload_when_their_files_change() {
    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    let first = ca.issue_into(certs.path(), &["localhost"]);
    let (server, address) = https(certs.path(), None).await;
    let tls = server.tls.clone().unwrap();
    assert!(!tls.reload(false).unwrap(), "nothing changed");

    let second = ca.issue_into(certs.path(), &["localhost"]);
    assert!(tls.reload(false).unwrap());
    let (presented, _) = ca.handshake(address, "localhost", &[]).await.unwrap();
    assert_eq!(presented, second.der);
    assert_ne!(presented, first.der);

    // A new folder counts too.
    let added = ca.issue_into(&certs.path().join("more"), &["more.test"]);
    assert!(tls.reload(false).unwrap());
    let (presented, _) = ca.handshake(address, "more.test", &[]).await.unwrap();
    assert_eq!(presented, added.der);

    // A broken certificate is refused, and the ones in use stay.
    fs::write(certs.path().join("private.key"), first.key).unwrap();
    let err = tls.reload(false).unwrap_err().to_string();
    assert!(err.contains("isn't the key of"), "{err}");
    let (presented, _) = ca.handshake(address, "localhost", &[]).await.unwrap();
    assert_eq!(presented, second.der);
    // It's reported once, not at every check, unless forced.
    assert!(!tls.reload(false).unwrap());
    assert!(tls.reload(true).is_err());
    // Put back as loaded: nothing to do; forcing reads them anyway.
    fs::write(certs.path().join("private.key"), &second.key).unwrap();
    assert!(!tls.reload(false).unwrap());
    assert!(tls.reload(true).unwrap());
    // Fixed differently from before: loaded.
    let third = ca.issue_into(certs.path(), &["localhost"]);
    assert!(tls.reload(false).unwrap());
    let (presented, _) = ca.handshake(address, "localhost", &[]).await.unwrap();
    assert_eq!(presented, third.der);
}

const DENY_PLAIN_HTTP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::guarded","arn:aws:s3:::guarded/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}"#;

#[tokio::test]
async fn https_requests_are_secure_transport() {
    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    ca.issue_into(certs.path(), &["127.0.0.1"]);
    let (server, _) = https(certs.path(), None).await;
    let s3 = ca.client(&server);
    s3.create_bucket().bucket("guarded").send().await.unwrap();
    s3.put_bucket_policy()
        .bucket("guarded")
        .policy(DENY_PLAIN_HTTP)
        .send()
        .await
        .unwrap();
    s3.put_object()
        .bucket("guarded")
        .key("a")
        .body(ByteStream::from_static(b"a"))
        .send()
        .await
        .unwrap();
    // `mc admin info` says so too.
    let (status, text) = signing::signed_over(
        &ca.reqwest(),
        &server,
        (common::ACCESS_KEY, common::SECRET_KEY),
        "GET",
        "/minio/admin/v3/info",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let info: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(info["servers"][0]["scheme"], "https");

    // The same policy on plain HTTP denies everyone, the root user too.
    let plain = common::start().await;
    let s3 = common::client(&plain, common::SECRET_KEY);
    s3.create_bucket().bucket("guarded").send().await.unwrap();
    s3.put_bucket_policy()
        .bucket("guarded")
        .policy(DENY_PLAIN_HTTP)
        .send()
        .await
        .unwrap();
    let denied = s3
        .put_object()
        .bucket("guarded")
        .key("a")
        .body(ByteStream::from_static(b"a"))
        .send()
        .await;
    assert_eq!(denied.unwrap_err().code(), Some("AccessDenied"));
}

/// Anyone may read `open/*` over TLS 1.3 or later.
const TLS_13_ONLY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::open/*","Condition":{"NumericGreaterThanEquals":{"s3:TlsVersion":"1.3"}}}]}"#;

/// A bucket `open` with an object `a` that `TLS_13_ONLY` governs.
async fn tls_13_only(s3: &aws_sdk_s3::Client) {
    s3.create_bucket().bucket("open").send().await.unwrap();
    s3.delete_public_access_block()
        .bucket("open")
        .send()
        .await
        .unwrap();
    s3.put_bucket_policy()
        .bucket("open")
        .policy(TLS_13_ONLY)
        .send()
        .await
        .unwrap();
    s3.put_object()
        .bucket("open")
        .key("a")
        .body(ByteStream::from_static(b"a"))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn policies_see_the_tls_version() {
    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    ca.issue_into(certs.path(), &["127.0.0.1"]);
    let (server, _) = https(certs.path(), None).await;
    tls_13_only(&ca.client(&server)).await;
    let url = format!("{}/open/a", server.endpoint);
    let status = |client: reqwest::Client| {
        let url = url.clone();
        async move { client.get(url).send().await.unwrap().status().as_u16() }
    };
    assert_eq!(status(ca.reqwest()).await, 200);
    let tls_12 = ca
        .reqwest_builder()
        .tls_version_max(reqwest::tls::Version::TLS_1_2)
        .build()
        .unwrap();
    assert_eq!(status(tls_12).await, 403);

    // Plain HTTP has no TLS version, so a condition on it isn't met.
    let plain = common::start().await;
    tls_13_only(&common::client(&plain, common::SECRET_KEY)).await;
    let answer = reqwest::get(format!("{}/open/a", plain.endpoint))
        .await
        .unwrap();
    assert_eq!(answer.status().as_u16(), 403);
}

#[tokio::test]
async fn sse_c_keys_need_a_secure_connection_for_every_request() {
    let key = [42u8; 32];
    let (k, m) = (STANDARD.encode(key), STANDARD.encode(Md5::digest(key)));

    // Over HTTPS, keys may travel.
    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    ca.issue_into(certs.path(), &["127.0.0.1"]);
    let (server, _) = https(certs.path(), Some(false)).await;
    let s3 = ca.client(&server);
    s3.create_bucket().bucket("keys").send().await.unwrap();
    s3.put_object()
        .bucket("keys")
        .key("c")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .body(ByteStream::from_static(b"mine"))
        .send()
        .await
        .unwrap();
    let got = s3
        .get_object()
        .bucket("keys")
        .key("c")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .send()
        .await
        .unwrap();
    assert_eq!(&got.body.collect().await.unwrap().into_bytes()[..], b"mine");

    // Over plain HTTP that isn't trusted, no request may carry one: not a write, a
    // read, a HEAD or a copy's source key.
    let plain = start_with(|config| {
        config.plain_http_is_secure = Some(false);
        config.default_layout = teifs_store::Layout::Object;
    })
    .await;
    let s3 = common::client(&plain, common::SECRET_KEY);
    s3.create_bucket().bucket("keys").send().await.unwrap();
    s3.put_object()
        .bucket("keys")
        .key("plain")
        .body(ByteStream::from_static(b"plain"))
        .send()
        .await
        .unwrap();
    let put = s3
        .put_object()
        .bucket("keys")
        .key("c")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .body(ByteStream::from_static(b"mine"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(put.code(), Some("InvalidRequest"));
    assert!(put.message().unwrap().contains("secure connection"));
    let get = s3
        .get_object()
        .bucket("keys")
        .key("plain")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .send()
        .await;
    assert_eq!(get.unwrap_err().code(), Some("InvalidRequest"));
    let head = s3
        .head_object()
        .bucket("keys")
        .key("plain")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .send()
        .await;
    assert!(head.is_err());
    let copy = s3
        .copy_object()
        .bucket("keys")
        .key("copy")
        .copy_source("keys/plain")
        .copy_source_sse_customer_algorithm("AES256")
        .copy_source_sse_customer_key(&k)
        .copy_source_sse_customer_key_md5(&m)
        .send()
        .await
        .unwrap_err();
    assert_eq!(copy.code(), Some("InvalidRequest"));
    assert!(copy.message().unwrap().contains("secure connection"));
    // Requests without a key are served as ever.
    s3.get_object()
        .bucket("keys")
        .key("plain")
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn a_stalled_handshake_is_closed() {
    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    ca.issue_into(certs.path(), &["localhost"]);
    let source = TlsSource::Dir(certs.path().to_owned());
    let server = start_with(|config| {
        config.tls = Some(source);
        config.limits.header_timeout = std::time::Duration::from_millis(500);
    })
    .await;
    let address: SocketAddr = server.endpoint[8..].parse().unwrap();
    // The first byte of a handshake, then nothing.
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(&[0x16]).await.unwrap();
    let started = std::time::Instant::now();
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.read_to_end(&mut rest),
    )
    .await;
    assert!(closed.is_ok(), "still open");
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
}
