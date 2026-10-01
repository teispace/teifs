//! The health checks answer without a signature, only at their own paths, and never on a
//! virtual-hosted bucket's host, where the path is an object's key.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use aws_sdk_s3::primitives::ByteStream;
use common::{SECRET_KEY, client, start_with};
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

/// A response's header, lowercased names.
fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.split("\r\n\r\n").next()?.lines().find_map(|line| {
        let (found, value) = line.split_once(':')?;
        found.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// `MinIO`'s probes answer as a single-drive `MinIO` does, so probes set up for it work.
#[tokio::test]
async fn minios_health_checks_answer_as_minio_does() {
    let server = start_with(|config| config.domains = vec!["s3.test".to_owned()]).await;
    let endpoint = &server.endpoint;
    let get = |path: &'static str| request(endpoint, "GET", "s3.test", path);
    for path in ["/minio/health/live", "/minio/health/ready"] {
        let ok = get(path).await;
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{path}: {ok}");
        assert!(ok.ends_with("\r\n\r\n"), "{path}: {ok}");
        assert_eq!(header(&ok, "minio-serverstatus"), None, "{path}");
    }
    let write = get("/minio/health/cluster").await;
    assert!(write.starts_with("HTTP/1.1 200 OK\r\n"), "{write}");
    assert_eq!(header(&write, "minio-writequorum"), Some("1"));
    assert_eq!(header(&write, "minio-storageclassdefaults"), Some("true"));
    let read = request(endpoint, "HEAD", "s3.test", "/minio/health/cluster/read").await;
    assert!(read.starts_with("HTTP/1.1 200 OK\r\n"), "{read}");
    assert_eq!(header(&read, "minio-readquorum"), Some("1"));
    let asked = get("/minio/health/cluster?maintenance=false").await;
    assert!(asked.starts_with("HTTP/1.1 200 OK\r\n"), "{asked}");
    // The only node can't be taken down for maintenance.
    for path in [
        "/minio/health/cluster?maintenance=true",
        "/minio/health/cluster/read?maintenance=true",
    ] {
        let refused = get(path).await;
        assert!(refused.starts_with("HTTP/1.1 412"), "{path}: {refused}");
    }
    // Not on a bucket's host, and not for other paths or methods.
    for (method, host, path) in [
        ("GET", "photos.s3.test", "/minio/health/live"),
        ("GET", "s3.test", "/minio/health/other"),
        ("POST", "s3.test", "/minio/health/live"),
    ] {
        let refused = request(endpoint, method, host, path).await;
        assert!(
            !refused.starts_with("HTTP/1.1 200"),
            "{method} {host}{path}: {refused}"
        );
    }
}

/// A signed request for a probe's path reaches a bucket named `minio`.
#[tokio::test]
async fn a_bucket_named_minio_keeps_its_health_keys() {
    let server = start_with(|_| {}).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("minio").send().await.unwrap();
    s3.put_object()
        .bucket("minio")
        .key("health/live")
        .body(ByteStream::from_static(b"mine"))
        .send()
        .await
        .unwrap();
    let got = s3
        .get_object()
        .bucket("minio")
        .key("health/live")
        .send()
        .await
        .unwrap();
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.as_ref(), b"mine");
}

/// A drive whose folder went away (an unmounted disk) is live but can't serve.
// Windows can't move a folder with open files in it.
#[cfg(not(windows))]
#[tokio::test]
async fn a_drive_that_went_away_is_not_ready() {
    let server = start_with(|_| {}).await;
    let endpoint = &server.endpoint;
    let system = server.dir.path().join(".teifs");
    let moved = server.dir.path().join("moved");
    // Where writes are staged is gone: reads are served, writes aren't.
    let staging = server.dir.path().join("staging");
    std::fs::rename(system.join("tmp"), &staging).unwrap();
    for (path, status) in [
        ("/minio/health/ready", "200"),
        ("/minio/health/cluster/read", "200"),
        ("/minio/health/cluster", "503"),
    ] {
        let answer = request(endpoint, "GET", "127.0.0.1", path).await;
        assert!(
            answer.starts_with(&format!("HTTP/1.1 {status}")),
            "{path}: {answer}"
        );
    }
    std::fs::rename(&staging, system.join("tmp")).unwrap();
    std::fs::rename(&system, &moved).unwrap();
    let live = request(endpoint, "GET", "127.0.0.1", "/minio/health/live").await;
    assert!(live.starts_with("HTTP/1.1 200"), "{live}");
    let ready = request(endpoint, "GET", "127.0.0.1", "/minio/health/ready").await;
    assert!(ready.starts_with("HTTP/1.1 503"), "{ready}");
    assert_eq!(header(&ready, "minio-serverstatus"), Some("offline"));
    for path in ["/minio/health/cluster", "/minio/health/cluster/read"] {
        let down = request(endpoint, "GET", "127.0.0.1", path).await;
        assert!(down.starts_with("HTTP/1.1 503"), "{path}: {down}");
    }
    std::fs::rename(&moved, &system).unwrap();
    let back = request(endpoint, "GET", "127.0.0.1", "/minio/health/cluster").await;
    assert!(back.starts_with("HTTP/1.1 200"), "{back}");
}

/// `systemctl reload` sends `SIGHUP`: a server with nothing to reload (no TLS, no audit
/// file) keeps serving, rather than stopping as a process does by default.
#[cfg(unix)]
#[tokio::test]
async fn a_hangup_never_stops_the_server() {
    let server = start_with(|_| {}).await;
    let health = format!("{}{HEALTH_PATH}", server.endpoint);
    // Serving, so the server is running.
    assert!(reqwest::get(&health).await.unwrap().status().is_success());
    let sent = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(reqwest::get(&health).await.unwrap().status().is_success());
}
