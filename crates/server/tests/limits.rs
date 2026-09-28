//! What one client can make the server hold, over raw connections: silent and slow
//! clients are cut off, stalled uploads fail as S3 does, connections are capped, and
//! oversized headers and metadata are refused.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use std::time::{Duration, Instant};

use aws_sdk_s3::{
    error::ProvideErrorMetadata, presigning::PresigningConfig, primitives::ByteStream,
};
use common::{SECRET_KEY, Server, client, start_with};
use teifs_server::Limits;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SHORT: Duration = Duration::from_millis(500);

async fn server(max_connections: usize) -> Server {
    start_with(|config| {
        config.limits = Limits {
            header_timeout: SHORT,
            body_timeout: SHORT,
            max_connections,
        };
    })
    .await
}

async fn connect(server: &Server) -> TcpStream {
    TcpStream::connect(server.endpoint.trim_start_matches("http://"))
        .await
        .unwrap()
}

/// Reads until the server closes the connection (or `within` passes: a failure).
async fn read_to_close(socket: &mut TcpStream, within: Duration) -> String {
    let mut out = Vec::new();
    tokio::time::timeout(within, socket.read_to_end(&mut out))
        .await
        .expect("the server should have closed the connection")
        .ok();
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn silent_and_slow_clients_are_cut_off() {
    let server = server(16).await;
    // Connects and says nothing.
    let started = Instant::now();
    let mut silent = connect(&server).await;
    read_to_close(&mut silent, Duration::from_secs(5)).await;
    assert!(
        started.elapsed() >= Duration::from_millis(450),
        "closed too early"
    );

    // Starts a request and never finishes its headers.
    let mut slow = connect(&server).await;
    slow.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    read_to_close(&mut slow, Duration::from_secs(5)).await;
}

#[tokio::test]
async fn idle_connections_close_after_a_response() {
    let server = server(16).await;
    let mut socket = connect(&server).await;
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let answer = read_to_close(&mut socket, Duration::from_secs(5)).await;
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
}

#[tokio::test]
async fn stalled_uploads_fail_with_request_timeout() {
    let server = server(16).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("stall").send().await.unwrap();
    let link = s3
        .put_object()
        .bucket("stall")
        .key("half")
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap();
    let (authority, path) = link
        .uri()
        .trim_start_matches("http://")
        .split_once('/')
        .unwrap();
    let request = format!(
        "PUT /{path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 100\r\n\r\nonly part of it"
    );
    let mut socket = connect(&server).await;
    socket.write_all(request.as_bytes()).await.unwrap();
    let answer = read_to_close(&mut socket, Duration::from_secs(5)).await;
    assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
    assert!(answer.contains("<Code>RequestTimeout</Code>"), "{answer}");
    // Nothing was stored.
    let head = s3.head_object().bucket("stall").key("half").send().await;
    assert!(head.is_err());
}

#[tokio::test]
async fn connections_beyond_the_limit_wait_for_a_free_one() {
    let server = start_with(|config| config.limits.max_connections = 1).await;
    let mut first = connect(&server).await;
    first
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    let mut second = connect(&server).await;
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0; 64];
    let waited = tokio::time::timeout(Duration::from_millis(500), second.read(&mut buf)).await;
    assert!(
        waited.is_err(),
        "the second connection was served while the first held the slot"
    );
    drop(first);
    let answer = read_to_close(&mut second, Duration::from_secs(5)).await;
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
}

#[tokio::test]
async fn oversized_headers_and_metadata_are_refused() {
    let server = server(16).await;
    let mut socket = connect(&server).await;
    let big = "b".repeat(teifs_s3::MAX_HEADER_BYTES);
    socket
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nX-Big: {big}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let answer = read_to_close(&mut socket, Duration::from_secs(5)).await;
    assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
    assert!(answer.contains("RequestHeaderSectionTooLarge"), "{answer}");

    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("meta").send().await.unwrap();
    // "k" and its value: 2 KiB at most, as S3 counts it.
    let put = |value: String| {
        s3.put_object()
            .bucket("meta")
            .key("m")
            .metadata("k", value)
            .body(ByteStream::from_static(b"x"))
            .send()
    };
    put("v".repeat(2047)).await.unwrap();
    let over = put("v".repeat(2048)).await.unwrap_err();
    assert_eq!(over.code(), Some("MetadataTooLarge"));
}
