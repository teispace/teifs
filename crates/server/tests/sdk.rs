//! TeiFS as the official AWS SDK sees it: a real server on a local port, signed
//! requests, default SDK behaviour (CRC32 checksums in trailers, chunked bodies).

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::Duration;

use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,
    presigning::PresigningConfig,
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart, Delete, MetadataDirective, ObjectIdentifier},
};

mod common;

use common::{SECRET_KEY, client, start};

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
async fn presigned_uploads_take_only_the_headers_they_signed() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("inbox").send().await.unwrap();
    let link = s3
        .put_object()
        .bucket("inbox")
        .key("upload.txt")
        .content_type("text/plain")
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap();
    let put = |extra: Option<(&'static str, &'static str)>| {
        let mut request = reqwest::Client::new()
            .put(link.uri())
            .header("content-type", "text/plain")
            .body("hello");
        if let Some((name, value)) = extra {
            request = request.header(name, value);
        }
        request.send()
    };
    // Whoever holds the link can't make the upload public, tag it or add metadata.
    for extra in [
        ("x-amz-acl", "public-read"),
        ("x-amz-tagging", "a=b"),
        ("x-amz-meta-note", "added"),
        ("x-amz-server-side-encryption", "aws:kms"),
    ] {
        let response = put(Some(extra)).await.unwrap();
        assert_eq!(response.status(), 403, "{extra:?}");
        assert!(
            response.text().await.unwrap().contains("AccessDenied"),
            "{extra:?}"
        );
    }
    assert_eq!(put(None).await.unwrap().status(), 200);
    let head = s3
        .head_object()
        .bucket("inbox")
        .key("upload.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_type(), Some("text/plain"));
    assert!(
        head.metadata()
            .is_none_or(std::collections::HashMap::is_empty)
    );
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

#[tokio::test]
async fn unversioned_buckets_have_null_versions() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("plain").send().await.unwrap();
    for key in ["a", "dir/b", "dir/c", "z"] {
        s3.put_object()
            .bucket("plain")
            .key(key)
            .body(ByteStream::from_static(b"x"))
            .send()
            .await
            .unwrap();
    }

    // Every object is listed once, as the latest and only version, `null`.
    let page = s3
        .list_object_versions()
        .bucket("plain")
        .max_keys(2)
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = page.versions().iter().map(|v| v.key().unwrap()).collect();
    assert_eq!(keys, ["a", "dir/b"]);
    assert!(
        page.versions()
            .iter()
            .all(|v| v.version_id() == Some("null") && v.is_latest() == Some(true))
    );
    assert_eq!(page.is_truncated(), Some(true));
    let rest = s3
        .list_object_versions()
        .bucket("plain")
        .key_marker(page.next_key_marker().unwrap())
        .version_id_marker(page.next_version_id_marker().unwrap())
        .delimiter("/")
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = rest.versions().iter().map(|v| v.key().unwrap()).collect();
    assert_eq!(keys, ["z"]);
    assert_eq!(rest.is_truncated(), Some(false));

    // `null` names the current object; any other version id is invalid.
    let got = s3
        .get_object()
        .bucket("plain")
        .key("a")
        .version_id("null")
        .send()
        .await
        .unwrap();
    assert_eq!(body(got).await, b"x");
    let bad = s3
        .get_object()
        .bucket("plain")
        .key("a")
        .version_id("3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY")
        .send()
        .await;
    assert_eq!(bad.unwrap_err().code(), Some("InvalidArgument"));

    // Deleting everything by version, the way cleanup tools do, empties the bucket.
    let all = s3
        .list_object_versions()
        .bucket("plain")
        .send()
        .await
        .unwrap();
    let ids: Vec<ObjectIdentifier> = all
        .versions()
        .iter()
        .map(|v| {
            ObjectIdentifier::builder()
                .key(v.key().unwrap())
                .version_id(v.version_id().unwrap())
                .build()
                .unwrap()
        })
        .collect();
    let deleted = s3
        .delete_objects()
        .bucket("plain")
        .delete(Delete::builder().set_objects(Some(ids)).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.deleted().len(), 4);
    assert!(deleted.errors().is_empty());
    s3.delete_bucket().bucket("plain").send().await.unwrap();
}

#[tokio::test]
async fn object_buckets_hold_any_key() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket()
        .bucket("anykey")
        .customize()
        .mutate_request(|request| {
            request
                .headers_mut()
                .insert(teifs_s3::LAYOUT_HEADER, "object");
        })
        .send()
        .await
        .unwrap();
    for key in ["a", "a/b", "a/../b", "a//b", "Readme", "README"] {
        s3.put_object()
            .bucket("anykey")
            .key(key)
            .body(ByteStream::from(key.as_bytes().to_vec()))
            .send()
            .await
            .unwrap();
    }
    for key in ["a", "a/b", "a/../b", "a//b", "Readme", "README"] {
        let got = s3
            .get_object()
            .bucket("anykey")
            .key(key)
            .send()
            .await
            .unwrap();
        assert_eq!(body(got).await, key.as_bytes(), "{key}");
    }
    let listed = s3
        .list_objects_v2()
        .bucket("anykey")
        .delimiter("/")
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = listed.contents().iter().map(|o| o.key().unwrap()).collect();
    let prefixes: Vec<_> = listed
        .common_prefixes()
        .iter()
        .map(|p| p.prefix().unwrap())
        .collect();
    assert_eq!(
        (keys, prefixes),
        (vec!["README", "Readme", "a"], vec!["a/"])
    );
    // Nothing appears in the drive's folder: the bucket lives under .teifs.
    assert!(!server.dir.path().join("anykey").exists());

    let bad = s3
        .create_bucket()
        .bucket("badlayout")
        .customize()
        .mutate_request(|request| {
            request
                .headers_mut()
                .insert(teifs_s3::LAYOUT_HEADER, "sideways");
        })
        .send()
        .await;
    assert_eq!(bad.unwrap_err().code(), Some("InvalidArgument"));
}

async fn object_bucket(s3: &Client, name: &str) {
    s3.create_bucket()
        .bucket(name)
        .customize()
        .mutate_request(|request| {
            request
                .headers_mut()
                .insert(teifs_s3::LAYOUT_HEADER, "object");
        })
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn objects_are_encrypted_at_rest_by_default() {
    use aws_sdk_s3::types::ServerSideEncryption;
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    object_bucket(&s3, "secure").await;

    // Nothing asked: the bucket's default, SSE-S3, as on AWS.
    let put = s3
        .put_object()
        .bucket("secure")
        .key("a")
        .body(ByteStream::from_static(b"top secret"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.server_side_encryption(),
        Some(&ServerSideEncryption::Aes256)
    );
    let got = s3
        .get_object()
        .bucket("secure")
        .key("a")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.server_side_encryption(),
        Some(&ServerSideEncryption::Aes256)
    );
    assert_eq!(body(got).await, b"top secret");
    let head = s3
        .head_object()
        .bucket("secure")
        .key("a")
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.server_side_encryption(),
        Some(&ServerSideEncryption::Aes256)
    );

    // SSE-KMS with the managed key.
    let kms = s3
        .put_object()
        .bucket("secure")
        .key("k")
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .body(ByteStream::from_static(b"kms"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        kms.server_side_encryption(),
        Some(&ServerSideEncryption::AwsKms)
    );
    assert_eq!(kms.ssekms_key_id(), Some("teifs-default"));

    let config = s3
        .get_bucket_encryption()
        .bucket("secure")
        .send()
        .await
        .unwrap();
    let rule = &config
        .server_side_encryption_configuration()
        .unwrap()
        .rules()[0];
    assert_eq!(
        rule.apply_server_side_encryption_by_default()
            .unwrap()
            .sse_algorithm(),
        &ServerSideEncryption::Aes256
    );
}

#[tokio::test]
async fn sse_c_objects_need_their_key() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use md5::{Digest, Md5};
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    object_bucket(&s3, "customer").await;
    let key = [42u8; 32];
    let (k, m) = (STANDARD.encode(key), STANDARD.encode(Md5::digest(key)));
    let other = [7u8; 32];
    let (ok, om) = (STANDARD.encode(other), STANDARD.encode(Md5::digest(other)));

    let put = s3
        .put_object()
        .bucket("customer")
        .key("c")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .body(ByteStream::from_static(b"mine"))
        .send()
        .await
        .unwrap();
    assert_eq!(put.sse_customer_key_md5(), Some(m.as_str()));

    let missing = s3.get_object().bucket("customer").key("c").send().await;
    assert_eq!(missing.unwrap_err().code(), Some("InvalidRequest"));
    let wrong = s3
        .get_object()
        .bucket("customer")
        .key("c")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&ok)
        .sse_customer_key_md5(&om)
        .send()
        .await;
    assert_eq!(wrong.unwrap_err().code(), Some("InvalidRequest"));
    let right = s3
        .get_object()
        .bucket("customer")
        .key("c")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .send()
        .await
        .unwrap();
    assert_eq!(body(right).await, b"mine");

    // Copy to SSE-S3 with the source's key.
    s3.copy_object()
        .bucket("customer")
        .key("copy")
        .copy_source("customer/c")
        .copy_source_sse_customer_algorithm("AES256")
        .copy_source_sse_customer_key(&k)
        .copy_source_sse_customer_key_md5(&m)
        .send()
        .await
        .unwrap();
    let copy = s3
        .get_object()
        .bucket("customer")
        .key("copy")
        .send()
        .await
        .unwrap();
    assert_eq!(body(copy).await, b"mine");
}

#[tokio::test]
async fn blocked_sse_c_and_bucket_encryption_settings() {
    use aws_sdk_s3::types::{
        BlockedEncryptionTypes, EncryptionType, ServerSideEncryption,
        ServerSideEncryptionByDefault, ServerSideEncryptionConfiguration, ServerSideEncryptionRule,
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use md5::{Digest, Md5};
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    object_bucket(&s3, "blocking").await;
    let rule = |blocked: EncryptionType| {
        ServerSideEncryptionConfiguration::builder()
            .rules(
                ServerSideEncryptionRule::builder()
                    .apply_server_side_encryption_by_default(
                        ServerSideEncryptionByDefault::builder()
                            .sse_algorithm(ServerSideEncryption::AwsKms)
                            .build()
                            .unwrap(),
                    )
                    .blocked_encryption_types(
                        BlockedEncryptionTypes::builder()
                            .encryption_type(blocked)
                            .build(),
                    )
                    .build(),
            )
            .build()
            .unwrap()
    };
    s3.put_bucket_encryption()
        .bucket("blocking")
        .server_side_encryption_configuration(rule(EncryptionType::SseC))
        .send()
        .await
        .unwrap();
    let key = [1u8; 32];
    let (k, m) = (STANDARD.encode(key), STANDARD.encode(Md5::digest(key)));
    let blocked = s3
        .put_object()
        .bucket("blocking")
        .key("x")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .body(ByteStream::from_static(b"x"))
        .send()
        .await;
    assert_eq!(blocked.unwrap_err().code(), Some("AccessDenied"));
    // The new default applies to writes that don't ask.
    let put = s3
        .put_object()
        .bucket("blocking")
        .key("d")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.server_side_encryption(),
        Some(&ServerSideEncryption::AwsKms)
    );

    s3.delete_bucket_encryption()
        .bucket("blocking")
        .send()
        .await
        .unwrap();
    // Folder buckets have no encryption.
    s3.create_bucket()
        .bucket("plainfolder")
        .send()
        .await
        .unwrap();
    let none = s3
        .get_bucket_encryption()
        .bucket("plainfolder")
        .send()
        .await;
    assert_eq!(
        none.unwrap_err().code(),
        Some("ServerSideEncryptionConfigurationNotFoundError")
    );
}

#[tokio::test]
async fn multipart_uploads_are_encrypted_too() {
    use aws_sdk_s3::types::ServerSideEncryption;
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    object_bucket(&s3, "bigsecure").await;
    let create = s3
        .create_multipart_upload()
        .bucket("bigsecure")
        .key("video")
        .send()
        .await
        .unwrap();
    assert_eq!(
        create.server_side_encryption(),
        Some(&ServerSideEncryption::Aes256)
    );
    let upload_id = create.upload_id().unwrap();
    let first = vec![3u8; 5 * 1024 * 1024 + 1];
    let second = b"the end".to_vec();
    let mut parts = Vec::new();
    for (number, bytes) in [(1, first.clone()), (2, second.clone())] {
        let part = s3
            .upload_part()
            .bucket("bigsecure")
            .key("video")
            .upload_id(upload_id)
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
    s3.complete_multipart_upload()
        .bucket("bigsecure")
        .key("video")
        .upload_id(upload_id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let got = s3
        .get_object()
        .bucket("bigsecure")
        .key("video")
        .range("bytes=5242870-5242885")
        .send()
        .await
        .unwrap();
    let mut whole = first;
    whole.extend_from_slice(&second);
    assert_eq!(body(got).await, &whole[5_242_870..=5_242_885]);
}

#[tokio::test]
async fn conditional_deletes_and_writes_on_missing_objects() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    object_bucket(&s3, "conditional").await;
    let missing = s3
        .put_object()
        .bucket("conditional")
        .key("k")
        .if_match("*")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await;
    assert_eq!(missing.unwrap_err().code(), Some("NoSuchKey"));
    let etag = s3
        .put_object()
        .bucket("conditional")
        .key("k")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap()
        .e_tag()
        .unwrap()
        .to_owned();
    let wrong = s3
        .delete_object()
        .bucket("conditional")
        .key("k")
        .if_match("\"nope\"")
        .send()
        .await;
    assert_eq!(wrong.unwrap_err().code(), Some("PreconditionFailed"));
    s3.delete_object()
        .bucket("conditional")
        .key("k")
        .if_match(&etag)
        .send()
        .await
        .unwrap();
    // Gone already: succeeds whatever the condition.
    s3.delete_object()
        .bucket("conditional")
        .key("k")
        .if_match("\"nope\"")
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn objects_can_be_renamed() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    for (bucket, object) in [("renamefolder", false), ("renameobject", true)] {
        if object {
            object_bucket(&s3, bucket).await;
        } else {
            s3.create_bucket().bucket(bucket).send().await.unwrap();
        }
        s3.put_object()
            .bucket(bucket)
            .key("old name.txt")
            .body(ByteStream::from_static(b"moved"))
            .send()
            .await
            .unwrap();
        s3.rename_object()
            .bucket(bucket)
            .key("new/name.txt")
            .rename_source(format!("{bucket}/old%20name.txt"))
            .destination_if_none_match("*")
            .send()
            .await
            .unwrap();
        let got = s3
            .get_object()
            .bucket(bucket)
            .key("new/name.txt")
            .send()
            .await
            .unwrap();
        assert_eq!(body(got).await, b"moved");
        let gone = s3
            .head_object()
            .bucket(bucket)
            .key("old name.txt")
            .send()
            .await;
        assert!(gone.is_err());
    }
    assert!(
        server
            .dir
            .path()
            .join("renamefolder/new/name.txt")
            .is_file()
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn parts_and_ranges_can_be_read_and_described() {
    use aws_sdk_s3::types::ObjectAttributes;

    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("files").send().await.unwrap();
    object_bucket(&s3, "objects").await;
    let first = vec![b'a'; 5 * 1024 * 1024];
    for bucket in ["files", "objects"] {
        let upload = s3
            .create_multipart_upload()
            .bucket(bucket)
            .key("two")
            .send()
            .await
            .unwrap();
        let id = upload.upload_id().unwrap();
        let mut parts = Vec::new();
        for (number, bytes) in [(1, first.clone()), (2, b"the end".to_vec())] {
            let part = s3
                .upload_part()
                .bucket(bucket)
                .key("two")
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
        let done = s3
            .complete_multipart_upload()
            .bucket(bucket)
            .key("two")
            .upload_id(id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .await
            .unwrap();

        // One part, by number: its bytes, the object's ETag and how many parts it has.
        let part = s3
            .get_object()
            .bucket(bucket)
            .key("two")
            .part_number(2)
            .send()
            .await
            .unwrap();
        assert_eq!(part.parts_count(), Some(2), "{bucket}");
        assert_eq!(part.e_tag(), done.e_tag());
        assert_eq!(part.content_range(), Some("bytes 5242880-5242886/5242887"));
        assert_eq!(body(part).await, b"the end");
        let head = s3
            .head_object()
            .bucket(bucket)
            .key("two")
            .part_number(1)
            .send()
            .await
            .unwrap();
        assert_eq!(head.content_length(), Some(5 * 1024 * 1024));
        assert_eq!(head.parts_count(), Some(2));
        let err = s3
            .get_object()
            .bucket(bucket)
            .key("two")
            .part_number(3)
            .send()
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some("InvalidPart"));
        let err = s3
            .get_object()
            .bucket(bucket)
            .key("two")
            .part_number(1)
            .range("bytes=0-1")
            .send()
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some("InvalidRequest"));

        // HEAD takes a range, as GET does.
        let head = s3
            .head_object()
            .bucket(bucket)
            .key("two")
            .range("bytes=-3")
            .send()
            .await
            .unwrap();
        assert_eq!(head.content_length(), Some(3));
        assert_eq!(head.content_range(), Some("bytes 5242884-5242886/5242887"));

        let attributes = s3
            .get_object_attributes()
            .bucket(bucket)
            .key("two")
            .object_attributes(ObjectAttributes::ObjectParts)
            .object_attributes(ObjectAttributes::ObjectSize)
            .object_attributes(ObjectAttributes::Etag)
            .max_parts(1)
            .send()
            .await
            .unwrap();
        assert_eq!(attributes.object_size(), Some(5 * 1024 * 1024 + 7));
        assert_eq!(
            attributes.e_tag(),
            done.e_tag().map(|e| e.trim_matches('"'))
        );
        let listed = attributes.object_parts().unwrap();
        assert_eq!(listed.total_parts_count(), Some(2));
        assert_eq!(listed.is_truncated(), Some(true));
        assert_eq!(listed.next_part_number_marker(), Some("1"));
        assert_eq!(listed.parts().len(), 1);
        assert_eq!(listed.parts()[0].size(), Some(5 * 1024 * 1024));
    }

    // An object put in one piece is its own part 1, and has no parts to describe.
    s3.put_object()
        .bucket("objects")
        .key("one")
        .body(ByteStream::from_static(b"body"))
        .send()
        .await
        .unwrap();
    let whole = s3
        .get_object()
        .bucket("objects")
        .key("one")
        .part_number(1)
        .send()
        .await
        .unwrap();
    assert_eq!(whole.parts_count(), None);
    assert_eq!(body(whole).await, b"body");
    let attributes = s3
        .get_object_attributes()
        .bucket("objects")
        .key("one")
        .object_attributes(ObjectAttributes::ObjectParts)
        .object_attributes(ObjectAttributes::StorageClass)
        .send()
        .await
        .unwrap();
    assert!(attributes.object_parts().is_none());
    assert_eq!(
        attributes
            .storage_class()
            .map(aws_sdk_s3::types::StorageClass::as_str),
        Some("STANDARD")
    );
}

/// A checksum of `bytes` as S3 sends it (base64).
fn checksum(algorithm: &str, bytes: &[u8]) -> String {
    let mut hasher = s3s::checksum::ChecksumHasher::default();
    match algorithm {
        "CRC32" => hasher.crc32 = Some(s3s::crypto::Crc32::default()),
        "CRC64NVME" => hasher.crc64nvme = Some(s3s::crypto::Crc64Nvme::default()),
        _ => hasher.sha256 = Some(s3s::crypto::Sha256::default()),
    }
    hasher.update(bytes);
    let sums = hasher.finalize();
    sums.checksum_crc32
        .or(sums.checksum_crc64nvme)
        .or(sums.checksum_sha256)
        .unwrap()
}

/// Uploads `parts` to a new upload of `key` with the given checksum settings, and returns
/// its id and the completed parts (with their checksums, as SDKs send them).
async fn upload_parts(
    s3: &Client,
    bucket: &str,
    key: &str,
    algorithm: Option<aws_sdk_s3::types::ChecksumAlgorithm>,
    kind: Option<aws_sdk_s3::types::ChecksumType>,
    parts: &[Vec<u8>],
) -> (String, Vec<CompletedPart>) {
    let created = s3
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .set_checksum_algorithm(algorithm.clone())
        .set_checksum_type(kind.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(created.checksum_algorithm(), algorithm.as_ref());
    if kind.is_some() {
        assert_eq!(created.checksum_type(), kind.as_ref());
    }
    let id = created.upload_id().unwrap().to_owned();
    let mut done = Vec::new();
    for (index, bytes) in parts.iter().enumerate() {
        let number = i32::try_from(index + 1).unwrap();
        let part = s3
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(&id)
            .part_number(number)
            .set_checksum_algorithm(algorithm.clone())
            .body(ByteStream::from(bytes.clone()))
            .send()
            .await
            .unwrap();
        done.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(part.e_tag().unwrap())
                .set_checksum_crc32(part.checksum_crc32().map(str::to_owned))
                .set_checksum_sha256(part.checksum_sha256().map(str::to_owned))
                .build(),
        );
    }
    (id, done)
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn multipart_objects_get_full_object_and_composite_checksums() {
    use aws_sdk_s3::types::{ChecksumAlgorithm, ChecksumMode, ChecksumType};

    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    object_bucket(&s3, "sums").await;
    let parts = vec![vec![b'x'; 5 * 1024 * 1024], b"and the rest".to_vec()];
    let whole = parts.concat();

    // Full object: the CRC32 of all the bytes, combined from the parts'.
    let (id, done) = upload_parts(
        &s3,
        "sums",
        "full",
        Some(ChecksumAlgorithm::Crc32),
        Some(ChecksumType::FullObject),
        &parts,
    )
    .await;
    let complete = |checksum: &str| {
        s3.complete_multipart_upload()
            .bucket("sums")
            .key("full")
            .upload_id(&id)
            .checksum_crc32(checksum)
            .checksum_type(ChecksumType::FullObject)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(done.clone()))
                    .build(),
            )
            .send()
    };
    let err = complete("AAAAAA==").await.unwrap_err();
    assert_eq!(err.code(), Some("BadDigest"));
    let full = checksum("CRC32", &whole);
    let finished = complete(&full).await.unwrap();
    assert_eq!(finished.checksum_crc32(), Some(full.as_str()));
    assert_eq!(finished.checksum_type(), Some(&ChecksumType::FullObject));
    // A retried Complete gets the same answer.
    let again = complete(&full).await.unwrap();
    assert_eq!(again.e_tag(), finished.e_tag());
    assert_eq!(again.checksum_crc32(), finished.checksum_crc32());
    let head = s3
        .head_object()
        .bucket("sums")
        .key("full")
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(head.checksum_crc32(), Some(full.as_str()));
    assert_eq!(head.checksum_type(), Some(&ChecksumType::FullObject));

    // Composite: the checksum of the parts' checksums, with `-N`; each part keeps its own.
    let (id, done) = upload_parts(
        &s3,
        "sums",
        "composite",
        Some(ChecksumAlgorithm::Sha256),
        None,
        &parts,
    )
    .await;
    let finished = s3
        .complete_multipart_upload()
        .bucket("sums")
        .key("composite")
        .upload_id(&id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(done.clone()))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let composite = finished.checksum_sha256().unwrap().to_owned();
    assert!(composite.ends_with("-2"), "{composite}");
    assert_eq!(finished.checksum_type(), Some(&ChecksumType::Composite));
    let part = s3
        .get_object()
        .bucket("sums")
        .key("composite")
        .part_number(2)
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(
        part.checksum_sha256(),
        Some(checksum("SHA256", &parts[1]).as_str())
    );

    // A part checksum of another algorithm than the upload's is refused.
    let err = s3
        .upload_part()
        .bucket("sums")
        .key("composite2")
        .upload_id(
            s3.create_multipart_upload()
                .bucket("sums")
                .key("composite2")
                .checksum_algorithm(ChecksumAlgorithm::Sha256)
                .send()
                .await
                .unwrap()
                .upload_id()
                .unwrap(),
        )
        .part_number(1)
        .checksum_algorithm(ChecksumAlgorithm::Crc32)
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidRequest"));

    // Without a choice, the object gets S3's default: CRC64NVME of the whole object.
    let (id, done) = upload_parts(&s3, "sums", "default", None, None, &parts).await;
    s3.complete_multipart_upload()
        .bucket("sums")
        .key("default")
        .upload_id(&id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(done))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let head = s3
        .head_object()
        .bucket("sums")
        .key("default")
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.checksum_crc64_nvme(),
        Some(checksum("CRC64NVME", &whole).as_str())
    );
}

#[tokio::test]
async fn objects_and_buckets_take_tags() {
    use aws_sdk_s3::types::{Tag, Tagging, TaggingDirective};

    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    object_bucket(&s3, "tags").await;
    let tag_keys = |set: &[Tag]| set.iter().map(|t| t.key().to_owned()).collect::<Vec<_>>();

    s3.put_object()
        .bucket("tags")
        .key("a")
        .tagging("project=blue&classified")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    let head = s3
        .head_object()
        .bucket("tags")
        .key("a")
        .send()
        .await
        .unwrap();
    assert_eq!(head.tag_count(), Some(2));
    let get = s3
        .get_object()
        .bucket("tags")
        .key("a")
        .send()
        .await
        .unwrap();
    assert_eq!(get.tag_count(), Some(2));
    let set = s3
        .get_object_tagging()
        .bucket("tags")
        .key("a")
        .send()
        .await
        .unwrap();
    assert_eq!(tag_keys(set.tag_set()), ["classified", "project"]);

    // Copies keep the source's tags unless the request replaces them.
    s3.copy_object()
        .bucket("tags")
        .key("kept")
        .copy_source("tags/a")
        .send()
        .await
        .unwrap();
    s3.copy_object()
        .bucket("tags")
        .key("replaced")
        .copy_source("tags/a")
        .tagging_directive(TaggingDirective::Replace)
        .tagging("new=1")
        .send()
        .await
        .unwrap();
    for (key, expected) in [
        ("kept", vec!["classified", "project"]),
        ("replaced", vec!["new"]),
    ] {
        let set = s3
            .get_object_tagging()
            .bucket("tags")
            .key(key)
            .send()
            .await
            .unwrap();
        assert_eq!(tag_keys(set.tag_set()), expected);
    }

    let err = s3
        .put_object_tagging()
        .bucket("tags")
        .key("a")
        .tagging(
            Tagging::builder()
                .tag_set(Tag::builder().key("aws:mine").value("v").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidTag"));

    let err = s3
        .get_bucket_tagging()
        .bucket("tags")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("NoSuchTagSet"));
    s3.put_bucket_tagging()
        .bucket("tags")
        .tagging(
            Tagging::builder()
                .tag_set(Tag::builder().key("team").value("storage").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let set = s3.get_bucket_tagging().bucket("tags").send().await.unwrap();
    assert_eq!(tag_keys(set.tag_set()), ["team"]);
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn cors_rules_answer_browsers() {
    use aws_sdk_s3::types::{CorsConfiguration, CorsRule};

    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("web").send().await.unwrap();
    let http = reqwest::Client::new();
    let url = format!("{}/web/page.html", server.endpoint);
    let preflight = |origin: &'static str, method: &'static str, headers: Option<&'static str>| {
        let mut request = http
            .request(reqwest::Method::OPTIONS, &url)
            .header("Origin", origin)
            .header("Access-Control-Request-Method", method);
        if let Some(headers) = headers {
            request = request.header("Access-Control-Request-Headers", headers);
        }
        request.send()
    };
    let header = |r: &reqwest::Response, name: &str| {
        r.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    };

    // No rules yet: browsers are refused.
    assert_eq!(
        preflight("https://app.example", "GET", None)
            .await
            .unwrap()
            .status(),
        403
    );
    let no_method = http
        .request(reqwest::Method::OPTIONS, &url)
        .header("Origin", "https://app.example")
        .send()
        .await
        .unwrap();
    assert_eq!(no_method.status(), 400);

    s3.put_bucket_cors()
        .bucket("web")
        .cors_configuration(
            CorsConfiguration::builder()
                .cors_rules(
                    CorsRule::builder()
                        .allowed_origins("https://*.example")
                        .allowed_methods("GET")
                        .allowed_methods("PUT")
                        .allowed_headers("x-amz-*")
                        .allowed_headers("Content-Type")
                        .expose_headers("ETag")
                        .max_age_seconds(600)
                        .build()
                        .unwrap(),
                )
                .cors_rules(
                    CorsRule::builder()
                        .allowed_origins("*")
                        .allowed_methods("GET")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let rules = s3.get_bucket_cors().bucket("web").send().await.unwrap();
    assert_eq!(rules.cors_rules().len(), 2);

    let ok = preflight(
        "https://app.example",
        "PUT",
        Some("content-type, x-amz-date"),
    )
    .await
    .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(
        header(&ok, "access-control-allow-origin").as_deref(),
        Some("https://app.example")
    );
    assert_eq!(
        header(&ok, "access-control-allow-methods").as_deref(),
        Some("GET, PUT")
    );
    assert_eq!(
        header(&ok, "access-control-allow-headers").as_deref(),
        Some("content-type, x-amz-date")
    );
    assert_eq!(
        header(&ok, "access-control-max-age").as_deref(),
        Some("600")
    );
    assert_eq!(
        header(&ok, "access-control-allow-credentials").as_deref(),
        Some("true")
    );
    // A header no rule allows, or a method: refused.
    assert_eq!(
        preflight("https://app.example", "PUT", Some("x-secret"))
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        preflight("https://other.site", "PUT", None)
            .await
            .unwrap()
            .status(),
        403
    );
    // Any origin may GET, and gets `*`.
    let any = preflight("https://other.site", "GET", None).await.unwrap();
    assert_eq!(
        header(&any, "access-control-allow-origin").as_deref(),
        Some("*")
    );
    assert_eq!(header(&any, "access-control-allow-credentials"), None);

    // Actual requests get the headers too, even when they fail (this one isn't signed).
    let actual = http
        .get(&url)
        .header("Origin", "https://app.example")
        .send()
        .await
        .unwrap();
    assert_eq!(actual.status(), 403);
    assert_eq!(
        header(&actual, "access-control-allow-origin").as_deref(),
        Some("https://app.example")
    );
    assert_eq!(
        header(&actual, "access-control-expose-headers").as_deref(),
        Some("ETag")
    );

    s3.delete_bucket_cors().bucket("web").send().await.unwrap();
    let err = s3.get_bucket_cors().bucket("web").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchCORSConfiguration"));
}

#[tokio::test]
async fn bucket_lists_page_and_filter() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    for name in ["logs-b", "logs-a", "photos", "logs-c"] {
        s3.create_bucket().bucket(name).send().await.unwrap();
    }
    let names = |out: &aws_sdk_s3::operation::list_buckets::ListBucketsOutput| {
        out.buckets()
            .iter()
            .map(|b| b.name().unwrap().to_owned())
            .collect::<Vec<_>>()
    };

    let all = s3.list_buckets().send().await.unwrap();
    assert_eq!(names(&all), ["logs-a", "logs-b", "logs-c", "photos"]);
    assert_eq!(all.continuation_token(), None);
    assert_eq!(all.buckets()[0].bucket_region(), Some("us-east-1"));

    // Pages of two with a prefix, until no token comes back.
    let mut seen = Vec::new();
    let mut token = None;
    loop {
        let page = s3
            .list_buckets()
            .prefix("logs-")
            .max_buckets(2)
            .set_continuation_token(token)
            .send()
            .await
            .unwrap();
        assert_eq!(page.prefix(), Some("logs-"));
        seen.extend(names(&page));
        token = page.continuation_token().map(str::to_owned);
        if token.is_none() {
            break;
        }
    }
    assert_eq!(seen, ["logs-a", "logs-b", "logs-c"]);

    let other_region = s3
        .list_buckets()
        .bucket_region("eu-west-1")
        .send()
        .await
        .unwrap();
    assert!(other_region.buckets().is_empty());
    for bad in [0, 10_001] {
        let err = s3.list_buckets().max_buckets(bad).send().await.unwrap_err();
        assert_eq!(err.code(), Some("InvalidArgument"), "{bad}");
    }
    let err = s3
        .list_buckets()
        .continuation_token("not-a-token")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidArgument"));
}

#[tokio::test]
async fn folder_buckets_refuse_names_other_systems_cant_hold() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("portable").send().await.unwrap();
    for key in ["NUL.txt", "a/b:c", "trailing./x"] {
        let put = s3
            .put_object()
            .bucket("portable")
            .key(key)
            .body(ByteStream::from_static(b"x"))
            .send()
            .await;
        assert_eq!(put.unwrap_err().code(), Some("InvalidArgument"), "{key}");
    }
    assert_eq!(
        std::fs::read_dir(server.dir.path().join("portable"))
            .unwrap()
            .count(),
        0,
        "nothing was written"
    );
    let device = s3.create_bucket().bucket("aux").send().await;
    assert_eq!(device.unwrap_err().code(), Some("InvalidBucketName"));
}

/// A Signature Version 2 presigned GET link to `path`, signed over `resource`, as boto3
/// makes by default.
fn sig_v2_link(server: &common::Server, path: &str, resource: &str) -> String {
    use aws_lc_rs::hmac;
    use base64::Engine as _;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let signed = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, SECRET_KEY.as_bytes()),
        format!("GET\n\n\n{expires}\n{resource}").as_bytes(),
    );
    let signature = base64::engine::general_purpose::STANDARD.encode(signed.as_ref());
    let signature: String = signature
        .bytes()
        .map(|b| match b {
            b'+' => "%2B".to_owned(),
            b'/' => "%2F".to_owned(),
            b'=' => "%3D".to_owned(),
            b => char::from(b).to_string(),
        })
        .collect();
    format!(
        "{}{path}?AWSAccessKeyId={}&Expires={expires}&Signature={signature}",
        server.endpoint,
        common::ACCESS_KEY
    )
}

#[tokio::test]
async fn signature_v2_is_refused_unless_allowed() {
    for allowed in [false, true] {
        let server = common::start_with(|config| config.allow_sig_v2 = allowed).await;
        let s3 = client(&server, SECRET_KEY);
        s3.create_bucket().bucket("legacy").send().await.unwrap();
        s3.put_object()
            .bucket("legacy")
            .key("v2.txt")
            .body(ByteStream::from_static(b"old client"))
            .send()
            .await
            .unwrap();
        let object = "/legacy/v2.txt";
        let answer = reqwest::get(sig_v2_link(&server, object, object))
            .await
            .unwrap();
        if allowed {
            assert_eq!(answer.status(), 200);
            assert_eq!(answer.text().await.unwrap(), "old client");
            // A bucket's resource is `/bucket/`, whether its path ends in `/` or not, as
            // botocore signs it.
            for path in ["/legacy", "/legacy/"] {
                let answer = reqwest::get(sig_v2_link(&server, path, "/legacy/"))
                    .await
                    .unwrap();
                assert_eq!(answer.status(), 200, "{path}");
                assert!(answer.text().await.unwrap().contains("<Key>v2.txt</Key>"));
            }
        } else {
            assert_eq!(answer.status(), 403);
            assert!(answer.text().await.unwrap().contains("Signature Version 2"));
        }
    }
}
