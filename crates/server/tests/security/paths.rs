//! Class 7: a key can't reach outside its bucket, however the path is written.
//!
//! Also proved elsewhere: keys other systems can't hold are refused in folder buckets
//! (`sdk.rs`, `folder_buckets_refuse_names_other_systems_cant_hold`), and the key parser
//! and path mapping (`crates/store`, `crates/types`).

use std::time::Duration;

use aws_sdk_s3::primitives::ByteStream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::common::{SECRET_KEY, Server, client, start_with};

/// A request line sent exactly as written, which an HTTP client would tidy up first:
/// the status and the whole answer.
async fn raw_get(server: &Server, path: &str) -> (u16, String) {
    let host = server.endpoint.trim_start_matches("http://");
    let mut socket = TcpStream::connect(host).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut answer))
        .await
        .unwrap()
        .unwrap();
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let status = answer
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, answer)
}

/// CVE-2025-68705 (RustFS), CVE-2023-28433 and CVE-2026-42600 (MinIO: keys with `..`,
/// Windows separators or encoded slashes reached files outside their bucket): in a
/// bucket anyone may read, no spelling of a path reads another bucket, the drive's own
/// files, or what a link in the bucket points to.
#[tokio::test]
async fn no_path_leaves_its_bucket() {
    let server = start_with(|config| config.default_layout = teifs_store::Layout::Folder).await;
    let root = client(&server, SECRET_KEY);
    for bucket in ["open", "vault"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    for (bucket, key, body) in [
        ("open", "readme", "welcome"),
        ("vault", "secret", "vault-only"),
    ] {
        root.put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from_static(body.as_bytes()))
            .send()
            .await
            .unwrap();
    }
    root.delete_public_access_block()
        .bucket("open")
        .send()
        .await
        .unwrap();
    root.put_bucket_policy()
        .bucket("open")
        // Listing too, so a missing key is `NoSuchKey`, not hidden behind a refusal.
        .policy(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::open","arn:aws:s3:::open/*"]}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(raw_get(&server, "/open/readme").await.0, 200);
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        server.dir.path().join("vault"),
        server.dir.path().join("open/link"),
    )
    .unwrap();

    let format = std::fs::read_to_string(server.dir.path().join(".teifs/format.json")).unwrap();
    for path in [
        "/open/../vault/secret",
        "/open/%2e%2e/vault/secret",
        "/open/%2E%2E%2Fvault%2Fsecret",
        "/open/..%2Fvault%2Fsecret",
        "/open/..%5Cvault%5Csecret",
        "/open/..\\vault\\secret",
        "/open/./../vault/secret",
        "/open//../vault/secret",
        "/open/link/secret",
        "/open/../.teifs/format.json",
        "/open/%2e%2e%2f.teifs%2fformat.json",
        "/open/.teifs/format.json",
        "/.teifs/format.json",
        "/open/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ] {
        let (status, answer) = raw_get(&server, path).await;
        assert_ne!(status, 200, "{path}: {answer}");
        assert!(!answer.contains("vault-only"), "{path}: {answer}");
        assert!(!answer.contains(format.trim()), "{path}: {answer}");
        assert!(!answer.contains("root:"), "{path}: {answer}");
    }
}
