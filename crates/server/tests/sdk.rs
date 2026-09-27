//! TeiFS as the official AWS SDK sees it: a real server on a local port, signed
//! requests, default SDK behaviour (CRC32 checksums in trailers, chunked bodies).

#![allow(clippy::unwrap_used, reason = "test helpers fail the test on any error")]

use std::time::Duration;

use aws_sdk_s3::{
    Client,
    config::{Credentials, Region},
    error::ProvideErrorMetadata,
    presigning::PresigningConfig,
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart, Delete, MetadataDirective, ObjectIdentifier},
};
use teifs_server::{Config, Credentials as DriveCredentials, Server as TeiFS};
use tempfile::TempDir;
use tokio::sync::oneshot;

const ACCESS_KEY: &str = "teifs-test";
const SECRET_KEY: &str = "not-a-real-secret-only-for-tests";

struct Server {
    dir: TempDir,
    endpoint: String,
    _stop: oneshot::Sender<()>,
}

async fn start() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let server = TeiFS::bind(Config {
        dir: dir.path().to_owned(),
        listen: "127.0.0.1:0".parse().unwrap(),
        domains: Vec::new(),
        credentials: Some(DriveCredentials {
            access_key: ACCESS_KEY.into(),
            secret_key: SECRET_KEY.into(),
        }),
    })
    .await
    .unwrap();
    let endpoint = format!("http://{}", server.local_addr().unwrap());
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    Server {
        dir,
        endpoint,
        _stop: stop,
    }
}

fn client(server: &Server, secret: &str) -> Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .endpoint_url(&server.endpoint)
        .credentials_provider(Credentials::new(ACCESS_KEY, secret, None, None, "tests"))
        .force_path_style(true)
        .build();
    Client::from_conf(config)
}

async fn body(output: aws_sdk_s3::operation::get_object::GetObjectOutput) -> Vec<u8> {
    output.body.collect().await.unwrap().into_bytes().to_vec()
}

#[tokio::test]
async fn objects_round_trip_as_plain_files() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("docs").send().await.unwrap();

    let put = s3
        .put_object()
        .bucket("docs")
        .key("2026/notes/hello world+ü.txt")
        .body(ByteStream::from_static(b"hello, drive"))
        .content_type("text/plain; charset=utf-8")
        .metadata("owner", "krishna")
        .send()
        .await
        .unwrap();
    assert_eq!(put.e_tag(), Some("\"2cd1d71805e0fb7e71b4c27c9c8c198c\""));

    // The object is a plain file where its key says.
    let on_disk =
        std::fs::read(server.dir.path().join("docs/2026/notes/hello world+ü.txt")).unwrap();
    assert_eq!(on_disk, b"hello, drive");

    let head = s3
        .head_object()
        .bucket("docs")
        .key("2026/notes/hello world+ü.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(12));
    assert_eq!(head.content_type(), Some("text/plain; charset=utf-8"));
    assert_eq!(
        head.metadata().unwrap().get("owner").map(String::as_str),
        Some("krishna")
    );
    assert_eq!(head.e_tag(), put.e_tag());

    let got = s3
        .get_object()
        .bucket("docs")
        .key("2026/notes/hello world+ü.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(body(got).await, b"hello, drive");

    let range = s3
        .get_object()
        .bucket("docs")
        .key("2026/notes/hello world+ü.txt")
        .range("bytes=7-11")
        .send()
        .await
        .unwrap();
    assert_eq!(range.content_range(), Some("bytes 7-11/12"));
    assert_eq!(body(range).await, b"drive");

    let listing = s3
        .list_objects_v2()
        .bucket("docs")
        .delimiter("/")
        .send()
        .await
        .unwrap();
    assert_eq!(
        listing
            .common_prefixes()
            .iter()
            .filter_map(|p| p.prefix())
            .collect::<Vec<_>>(),
        ["2026/"]
    );
    let deep = s3
        .list_objects_v2()
        .bucket("docs")
        .prefix("2026/")
        .send()
        .await
        .unwrap();
    assert_eq!(
        deep.contents()
            .iter()
            .filter_map(|o| o.key())
            .collect::<Vec<_>>(),
        ["2026/notes/hello world+ü.txt"]
    );

    s3.delete_object()
        .bucket("docs")
        .key("2026/notes/hello world+ü.txt")
        .send()
        .await
        .unwrap();
    s3.delete_bucket().bucket("docs").send().await.unwrap();
    assert!(!server.dir.path().join("docs").exists());
}

#[tokio::test]
async fn listing_pages_through_many_keys() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("many").send().await.unwrap();
    for i in 0..25 {
        s3.put_object()
            .bucket("many")
            .key(format!("k/{i:03}"))
            .body(ByteStream::from_static(b"x"))
            .send()
            .await
            .unwrap();
    }
    let mut keys = Vec::new();
    let mut pages = s3
        .list_objects_v2()
        .bucket("many")
        .max_keys(10)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        keys.extend(
            page.unwrap()
                .contents()
                .iter()
                .filter_map(|o| o.key().map(str::to_owned)),
        );
    }
    assert_eq!(keys.len(), 25);
    assert!(keys.windows(2).all(|w| w[0] < w[1]));
}

#[tokio::test]
async fn multipart_uploads_complete_into_one_file() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("big").send().await.unwrap();
    let upload = s3
        .create_multipart_upload()
        .bucket("big")
        .key("video.bin")
        .content_type("video/mp4")
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();

    let first = vec![7u8; 5 * 1024 * 1024];
    let mut parts = Vec::new();
    for (number, bytes) in [(1, first.clone()), (2, b"the end".to_vec())] {
        let part = s3
            .upload_part()
            .bucket("big")
            .key("video.bin")
            .upload_id(id)
            .part_number(number)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .unwrap();
        parts.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(part.e_tag().unwrap())
                .build(),
        );
    }
    let listed = s3
        .list_parts()
        .bucket("big")
        .key("video.bin")
        .upload_id(id)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.parts().len(), 2);

    let done = s3
        .complete_multipart_upload()
        .bucket("big")
        .key("video.bin")
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(done.e_tag().unwrap().ends_with("-2\""));

    let head = s3
        .head_object()
        .bucket("big")
        .key("video.bin")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(5 * 1024 * 1024 + 7));
    assert_eq!(head.content_type(), Some("video/mp4"));
    assert_eq!(
        std::fs::metadata(server.dir.path().join("big/video.bin"))
            .unwrap()
            .len(),
        5 * 1024 * 1024 + 7
    );
    let uploads = s3
        .list_multipart_uploads()
        .bucket("big")
        .send()
        .await
        .unwrap();
    assert!(uploads.uploads().is_empty());
}

#[tokio::test]
async fn copies_keep_or_replace_metadata() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("src").send().await.unwrap();
    s3.put_object()
        .bucket("src")
        .key("a.txt")
        .body(ByteStream::from_static(b"abc"))
        .metadata("tag", "one")
        .send()
        .await
        .unwrap();

    s3.copy_object()
        .bucket("src")
        .key("b.txt")
        .copy_source("src/a.txt")
        .send()
        .await
        .unwrap();
    let copy = s3
        .head_object()
        .bucket("src")
        .key("b.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        copy.metadata().unwrap().get("tag").map(String::as_str),
        Some("one")
    );

    s3.copy_object()
        .bucket("src")
        .key("a.txt")
        .copy_source("src/a.txt")
        .metadata_directive(MetadataDirective::Replace)
        .metadata("tag", "two")
        .send()
        .await
        .unwrap();
    let replaced = s3
        .head_object()
        .bucket("src")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        replaced.metadata().unwrap().get("tag").map(String::as_str),
        Some("two")
    );
    let got = s3
        .get_object()
        .bucket("src")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(body(got).await, b"abc");
}

#[tokio::test]
async fn deletes_many_at_once() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("trash").send().await.unwrap();
    for key in ["a", "b/c", "d"] {
        s3.put_object()
            .bucket("trash")
            .key(key)
            .body(ByteStream::from_static(b"1"))
            .send()
            .await
            .unwrap();
    }
    let objects: Vec<_> = ["a", "b/c", "missing"]
        .iter()
        .map(|k| ObjectIdentifier::builder().key(*k).build().unwrap())
        .collect();
    let out = s3
        .delete_objects()
        .bucket("trash")
        .delete(
            Delete::builder()
                .set_objects(Some(objects))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(out.deleted().len(), 3);
    let left = s3.list_objects_v2().bucket("trash").send().await.unwrap();
    assert_eq!(
        left.contents()
            .iter()
            .filter_map(|o| o.key())
            .collect::<Vec<_>>(),
        ["d"]
    );
    assert!(!server.dir.path().join("trash/b").exists());
}

#[tokio::test]
async fn conditions_are_honoured() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("cas").send().await.unwrap();
    let first = s3
        .put_object()
        .bucket("cas")
        .key("lock")
        .if_none_match("*")
        .body(ByteStream::from_static(b"1"))
        .send()
        .await
        .unwrap();
    let again = s3
        .put_object()
        .bucket("cas")
        .key("lock")
        .if_none_match("*")
        .body(ByteStream::from_static(b"2"))
        .send()
        .await;
    assert_eq!(again.unwrap_err().code(), Some("PreconditionFailed"));

    let not_modified = s3
        .get_object()
        .bucket("cas")
        .key("lock")
        .if_none_match(first.e_tag().unwrap())
        .send()
        .await;
    assert!(not_modified.is_err());
    let wrong = s3
        .get_object()
        .bucket("cas")
        .key("lock")
        .if_match("\"nope\"")
        .send()
        .await;
    assert_eq!(wrong.unwrap_err().code(), Some("PreconditionFailed"));
}

#[tokio::test]
async fn checksums_are_verified() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("sums").send().await.unwrap();
    let bad = s3
        .put_object()
        .bucket("sums")
        .key("x")
        .checksum_crc32("AAAAAA==")
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await;
    assert!(bad.is_err());
    assert!(!server.dir.path().join("sums/x").exists());

    s3.put_object()
        .bucket("sums")
        .key("y")
        .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256)
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await
        .unwrap();
    let head = s3
        .head_object()
        .bucket("sums")
        .key("y")
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.checksum_sha256(),
        Some("LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=")
    );
}

#[tokio::test]
async fn unsigned_or_wrongly_signed_requests_are_refused() {
    let server = start().await;
    let wrong = client(&server, "wrong-secret");
    let err = wrong.list_buckets().send().await.unwrap_err();
    assert_eq!(err.code(), Some("SignatureDoesNotMatch"));
    let anonymous = reqwest::get(format!("{}/", server.endpoint)).await.unwrap();
    assert_eq!(anonymous.status(), 403);
}

#[tokio::test]
async fn presigned_links_work_without_credentials() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("share").send().await.unwrap();
    s3.put_object()
        .bucket("share")
        .key("photo.jpg")
        .body(ByteStream::from_static(b"jpeg"))
        .send()
        .await
        .unwrap();
    let link = s3
        .get_object()
        .bucket("share")
        .key("photo.jpg")
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap();
    let response = reqwest::get(link.uri()).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "image/jpeg");
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"jpeg");
}

#[tokio::test]
async fn files_added_by_hand_are_objects() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("hand").send().await.unwrap();
    std::fs::create_dir_all(server.dir.path().join("hand/from-finder")).unwrap();
    std::fs::write(
        server.dir.path().join("hand/from-finder/report.pdf"),
        b"%PDF",
    )
    .unwrap();
    let head = s3
        .head_object()
        .bucket("hand")
        .key("from-finder/report.pdf")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_type(), Some("application/pdf"));
    assert!(head.e_tag().unwrap().ends_with("-1\""));
    let got = s3
        .get_object()
        .bucket("hand")
        .key("from-finder/report.pdf")
        .send()
        .await
        .unwrap();
    assert_eq!(body(got).await, b"%PDF");
}
