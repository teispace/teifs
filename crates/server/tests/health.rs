//! The health check answers without a signature, only at its own path, and never on a
//! virtual-hosted bucket's host, where the path is an object's key.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use common::start_with;
use teifs_server::HEALTH_PATH;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Sends one `method` request for `path` with `host` and returns the whole response.
async fn request(endpoint: &str, method: &str, host: &str, path: &str) -> String {
    let mut socket = TcpStream::connect(endpoint.trim_start_matches("http://"))
        .await
        .unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    socket.write_all(head.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    socket.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn health_checks_answer_without_keys_only_at_their_path() {
    let server = start_with(|config| config.domains = vec!["s3.test".to_owned()]).await;
    let endpoint = &server.endpoint;

    let ok = request(endpoint, "GET", "s3.test", HEALTH_PATH).await;
    assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
    assert!(
        ok.to_ascii_lowercase().contains("cache-control: no-store"),
        "{ok}"
    );
    assert!(ok.ends_with("\r\n\r\nOK\n"), "{ok}");
    let head = request(endpoint, "HEAD", "127.0.0.1", HEALTH_PATH).await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");

    // Anything else still needs keys.
    for (method, host, path) in [
        ("GET", "s3.test", "/"),
        ("PUT", "s3.test", HEALTH_PATH),
        ("GET", "s3.test", "/.teifs/health/x"),
        ("GET", "s3.test", "/.teifs/"),
        // On a bucket's own host the path is a key in that bucket.
        ("GET", "photos.s3.test", HEALTH_PATH),
    ] {
        let refused = request(endpoint, method, host, path).await;
        assert!(
            !refused.starts_with("HTTP/1.1 200"),
            "{method} {host}{path}: {refused}"
        );
    }
}
