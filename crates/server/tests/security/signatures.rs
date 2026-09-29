//! Class 4: what a signature covers can't be changed, added to or left out.
//!
//! Also proved elsewhere: presigned uploads refuse unsigned `x-amz-acl`, tagging, metadata
//! and encryption headers (`sdk.rs`, `presigned_uploads_take_only_the_headers_they_signed`);
//! browser forms must match their signed policy, in the bucket, key, fields, size,
//! expiry and signature (`post_object.rs`, `the_policy_decides_what_may_be_sent`);
//! presigned size caps (`presign_caps.rs`); Signature V2 off by default (`sdk.rs`).

use std::time::{Duration, SystemTime};

use aws_sdk_s3::{Client, presigning::PresigningConfig, primitives::ByteStream};

use crate::{
    common::{ACCESS_KEY, SECRET_KEY, client, code, start, user},
    sign::{Payload, flip_after, presigned, sha256_base64, signed, signed_at, unsigned_chunks},
};

const KEY: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

/// A bucket with an object someone may want, and one to write into.
async fn victim_and_target(s3: &Client) {
    for bucket in ["victim", "target"] {
        s3.create_bucket().bucket(bucket).send().await.unwrap();
    }
    for (bucket, key, body) in [("victim", "secret", "victim data"), ("target", "k", "mine")] {
        s3.put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from_static(body.as_bytes()))
            .send()
            .await
            .unwrap();
    }
}

async fn read(s3: &Client, bucket: &str, key: &str) -> Option<Vec<u8>> {
    let object = s3.get_object().bucket(bucket).key(key).send().await.ok()?;
    Some(object.body.collect().await.unwrap().to_vec())
}

async fn presigned_put(s3: &Client, bucket: &str, key: &str) -> String {
    s3.put_object()
        .bucket(bucket)
        .key(key)
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap()
        .uri()
        .to_owned()
}

async fn put_url(url: &str, headers: &[(&str, &str)], body: &'static str) -> (u16, String) {
    let mut request = reqwest::Client::new().put(url).body(body);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    (response.status().as_u16(), response.text().await.unwrap())
}

/// s3s GHSA-94jf-pgr5-43m6, and the same flaw in MinIO (CVE-2026-97731), Ceph RGW
/// (CVE-2026-54330), OpenStack Swift (CVE-2026-71191), RustFS (GHSA-g8w9-qw9q-fghr) and
/// NooBaa (CVE-2026-94368): an `x-amz-*` header the signature doesn't cover turned a
/// presigned upload into a copy of any object the signer could read.
#[tokio::test]
async fn unsigned_amz_headers_cant_turn_an_upload_into_a_copy() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    victim_and_target(&s3).await;
    let copy = [("x-amz-copy-source", "/victim/secret")];

    // A presigned upload signs only `host`.
    let url = presigned_put(&s3, "target", "k").await;
    let (status, body) = put_url(&url, &copy, "mine too").await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("AccessDenied"), "{body}");
    // Nor can headers that change what a copy or upload does be added.
    for extra in [
        ("x-amz-metadata-directive", "REPLACE"),
        ("x-amz-website-redirect-location", "/elsewhere"),
        ("x-amz-storage-class", "STANDARD"),
        ("x-amz-object-lock-mode", "GOVERNANCE"),
        (
            "x-amz-grant-read",
            "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
        ),
    ] {
        assert_eq!(put_url(&url, &[extra], "x").await.0, 403, "{extra:?}");
    }

    // A request signed in its headers, with one added on the way.
    let put = signed(
        &server,
        KEY,
        "PUT",
        "/target/k",
        &[],
        Payload::Bytes(b"mine too"),
    );
    let answer = put.send(&copy, "mine too").await;
    assert_eq!((answer.status, answer.code.as_str()), (403, "AccessDenied"));
    // Streaming headers must be signed too (s3s 0.16.1 narrowed its exemption).
    for extra in [
        ("x-amz-decoded-content-length", "8"),
        ("x-amz-trailer", "x-amz-checksum-crc32"),
        ("x-amz-checksum-algorithm", "SHA256"),
    ] {
        assert_eq!(
            put.send(&[extra], "mine too").await.status,
            403,
            "{extra:?}"
        );
    }
    assert_eq!(read(&s3, "target", "k").await.unwrap(), b"mine");

    // As signed, both work; `x-amz-content-sha256` may be added after presigning, as
    // the AWS SDKs do.
    assert_eq!(
        put_url(
            &url,
            &[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")],
            "via link"
        )
        .await
        .0,
        200
    );
    assert_eq!(read(&s3, "target", "k").await.unwrap(), b"via link");
    assert_eq!(put.send(&[], "mine too").await.status, 200);
    assert_eq!(read(&s3, "target", "k").await.unwrap(), b"mine too");
}

/// CVE-2021-21390 (MinIO) and the general rule: every signed part of a request is
/// checked, so changing any of them after signing is refused.
#[tokio::test]
async fn nothing_a_signature_covers_can_change() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("uploads").send().await.unwrap();
    let put = signed(
        &server,
        KEY,
        "PUT",
        "/uploads/k",
        &[
            ("x-amz-meta-owner", "alice"),
            ("content-type", "text/plain"),
        ],
        Payload::Bytes(b"signed body"),
    );
    // A signed header's value, and a signed header left out.
    for (name, value) in [
        ("x-amz-meta-owner", "mallory"),
        ("content-type", "text/html"),
    ] {
        let answer = put
            .send_headers(&put.with_header(name, value), b"signed body".to_vec())
            .await;
        assert_eq!(
            answer.code, "SignatureDoesNotMatch",
            "{name}: {}",
            answer.body
        );
    }
    let without: Vec<_> = put
        .headers
        .iter()
        .filter(|(name, _)| name != "x-amz-meta-owner")
        .cloned()
        .collect();
    let answer = put.send_headers(&without, b"signed body".to_vec()).await;
    assert_eq!(answer.code, "SignatureDoesNotMatch", "{}", answer.body);
    // The body its hash names.
    let answer = put.send(&[], "other body!").await;
    assert_eq!(answer.code, "XAmzContentSHA256Mismatch", "{}", answer.body);
    // The path, the query and the method.
    for (method, url) in [
        (
            reqwest::Method::PUT,
            put.url.replace("/uploads/k", "/uploads/other"),
        ),
        (reqwest::Method::PUT, format!("{}?tagging", put.url)),
        (reqwest::Method::POST, put.url.clone()),
    ] {
        let mut request = reqwest::Client::new()
            .request(method.clone(), &url)
            .body("signed body");
        for (name, value) in &put.headers {
            request = request.header(name, value);
        }
        let status = request.send().await.unwrap().status().as_u16();
        assert_eq!(status, 403, "{method} {url}");
    }
    // Signed too long ago.
    let old = signed_at(
        &server,
        KEY,
        ("GET", "/uploads/k"),
        Payload::Bytes(b""),
        SystemTime::now() - Duration::from_mins(20),
    );
    assert_eq!(old.send(&[], "").await.code, "RequestTimeTooSkewed");
    assert!(
        read(&s3, "uploads", "k").await.is_none(),
        "nothing was written"
    );
    assert_eq!(put.send(&[], "signed body").await.status, 200);
}

/// A presigned link's query is signed: its expiry, what it signed and what it asks for
/// can't be edited, and it stops working when it expires.
#[tokio::test]
async fn presigned_links_cant_be_edited_or_outlive_their_expiry() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    victim_and_target(&s3).await;
    let link = s3
        .get_object()
        .bucket("target")
        .key("k")
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap();
    let url = link.uri().to_owned();
    let get = |url: String| async move {
        let response = reqwest::get(url).await.unwrap();
        (response.status().as_u16(), response.text().await.unwrap())
    };
    assert_eq!(get(url.clone()).await, (200, "mine".to_owned()));
    for edited in [
        url.replace("X-Amz-Expires=60", "X-Amz-Expires=604800"),
        url.replace("/target/k", "/victim/secret"),
        format!("{url}&response-content-type=text%2Fhtml"),
        url.replace(
            "X-Amz-SignedHeaders=host",
            "X-Amz-SignedHeaders=host%3Brange",
        ),
    ] {
        let (status, body) = get(edited.clone()).await;
        assert_eq!(status, 403, "{edited}: {body}");
        assert!(!body.contains("victim data"));
    }
    let short = s3
        .get_object()
        .bucket("target")
        .key("k")
        .presigned(PresigningConfig::expires_in(Duration::from_secs(1)).unwrap())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (status, body) = get(short.uri().to_owned()).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("AccessDenied") && body.contains("expired"),
        "{body}"
    );
}

/// CVE-2021-21390 (MinIO: a chunked body's signatures not always checked): each chunk is
/// signed after the one before, so none can be changed, dropped, repeated or reordered,
/// and a body that fails is never stored.
#[tokio::test]
async fn each_chunk_of_a_streamed_upload_is_signed() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("uploads").send().await.unwrap();
    let chunks: [&[u8]; 2] = [&[b'a'; 8192], b"tail"];
    let put = signed(
        &server,
        KEY,
        "PUT",
        "/uploads/streamed",
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "8196"),
        ],
        Payload::Streaming("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
    );
    let frames = put.chunks(&chunks, None);
    let body = |frames: &[Vec<u8>]| frames.concat();

    let mut changed = frames.clone();
    let last = changed[0].len() - 3;
    changed[0][last] = b'b';
    let mut bad_signature = frames.clone();
    flip_after(&mut bad_signature[1], "chunk-signature=");
    let reordered = [frames[1].clone(), frames[0].clone(), frames[2].clone()];
    let repeated = [frames[0].clone(), frames[0].clone(), frames[2].clone()];
    // (A body without its empty last chunk is taken, as s3s reads it: every byte of it
    // is signed, and its signed length stops a chunk being left out.)
    let left_out = [frames[1].clone(), frames[2].clone()];
    for (what, body) in [
        ("a changed byte", body(&changed)),
        ("a changed signature", body(&bad_signature)),
        ("chunks in another order", body(&reordered)),
        ("a repeated chunk", body(&repeated)),
        ("a chunk left out", body(&left_out)),
    ] {
        let answer = put.send(&[], body).await;
        assert!(answer.status >= 400, "{what}: {}", answer.body);
        assert!(
            read(&s3, "uploads", "streamed").await.is_none(),
            "{what} was stored"
        );
    }
    // Longer than declared.
    let longer = put.chunks(&[&[b'a'; 8192], b"tail!"], None);
    assert!(put.send(&[], body(&longer)).await.status >= 400);
    assert!(read(&s3, "uploads", "streamed").await.is_none());

    let answer = put.send(&[], body(&frames)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(
        read(&s3, "uploads", "streamed").await.unwrap(),
        chunks.concat()
    );
}

/// CVE-2025-31489 and CVE-2026-41145 (MinIO: uploads with a trailer skipped part of the
/// signature check, also with the credentials in the query): a trailer's checksum and
/// signature are checked, and an unsigned body still needs the request's signature.
#[tokio::test]
async fn trailers_and_unsigned_bodies_are_still_checked() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("uploads").send().await.unwrap();
    let data = b"with a trailer";
    let checksum = sha256_base64(data);
    let wrong = sha256_base64(b"something else");
    let headers = [
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", "14"),
        ("x-amz-trailer", "x-amz-checksum-sha256"),
    ];

    // Signed chunks and a signed trailer.
    let put = signed(
        &server,
        KEY,
        "PUT",
        "/uploads/signed",
        &headers,
        Payload::Streaming("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"),
    );
    let good = put.chunks(&[data], Some(("x-amz-checksum-sha256", &checksum)));
    let mut wrong_signature = good.clone();
    flip_after(&mut wrong_signature[2], "x-amz-trailer-signature:");
    for (what, frames) in [
        // A checksum that doesn't match, signed as it is.
        (
            "wrong checksum",
            put.chunks(&[data], Some(("x-amz-checksum-sha256", &wrong))),
        ),
        // The right checksum with a signature that isn't the trailer's.
        ("wrong trailer signature", wrong_signature),
    ] {
        let answer = put.send(&[], frames.concat()).await;
        assert!(answer.status >= 400, "{what}: {}", answer.body);
        assert!(
            read(&s3, "uploads", "signed").await.is_none(),
            "{what} was stored"
        );
    }
    assert_eq!(put.send(&[], good.concat()).await.status, 200);
    assert_eq!(read(&s3, "uploads", "signed").await.unwrap(), data);

    // An unsigned body with a trailer: the request itself must still be signed right.
    let body = unsigned_chunks(&[data], ("x-amz-checksum-sha256", &checksum));
    let unsigned = signed(
        &server,
        KEY,
        "PUT",
        "/uploads/unsigned",
        &headers,
        Payload::Streaming("STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
    );
    let forged = unsigned.with_header(
        "authorization",
        &unsigned
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .unwrap()
            .1
            .replace(&unsigned.signature, &"0".repeat(64)),
    );
    let answer = unsigned.send_headers(&forged, body.clone()).await;
    assert_eq!(answer.code, "SignatureDoesNotMatch", "{}", answer.body);
    let bad = unsigned_chunks(&[data], ("x-amz-checksum-sha256", &wrong));
    assert!(unsigned.send(&[], bad).await.status >= 400);
    assert!(read(&s3, "uploads", "unsigned").await.is_none());
    assert_eq!(unsigned.send(&[], body.clone()).await.status, 200);

    // Through a presigned link, a streamed body isn't taken at all, signed right or not
    // (MinIO skipped the signature check there).
    let mut link = presigned(
        &server,
        KEY,
        "PUT",
        "/uploads/linked",
        &headers,
        Payload::Streaming("STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
    );
    let streaming = [("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")];
    let answer = link.send(&streaming, body.clone()).await;
    assert_eq!(answer.code, "NotImplemented", "{}", answer.body);
    let mut tampered = link.url.clone().into_bytes();
    flip_after(&mut tampered, "X-Amz-Signature=");
    link.url = String::from_utf8(tampered).unwrap();
    assert!(link.send(&streaming, body).await.status >= 400);
    assert!(read(&s3, "uploads", "linked").await.is_none());
}

/// CVE-2026-45042 and CVE-2026-39360 (RustFS: `UploadPartCopy` skipped the source's and
/// the destination's policies): a copy needs read on its source and write on its
/// destination, whichever operation makes it.
#[tokio::test]
async fn copies_need_read_on_the_source_and_write_on_the_destination() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    victim_and_target(&s3).await;
    let allow =
        |statements: &str| format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
    let write_target = r#"{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":"arn:aws:s3:::target/*"}"#;
    let read_victim =
        r#"{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::victim/*"}"#;
    let writer = user(&server, "writer", Some(&allow(write_target)));
    let reader = user(&server, "reader", Some(&allow(read_victim)));
    let both = user(
        &server,
        "both",
        Some(&allow(&format!("{write_target},{read_victim}"))),
    );

    let copy = |who: &Client, to: &str| {
        who.copy_object()
            .bucket("target")
            .key(to)
            .copy_source("victim/secret")
            .send()
    };
    let part_copy = |who: Client, to: &'static str| async move {
        let upload = s3_upload(&who, to).await?;
        who.upload_part_copy()
            .bucket("target")
            .key(to)
            .upload_id(&upload)
            .part_number(1)
            .copy_source("victim/secret")
            .send()
            .await
            .map(|_| ())
            .map_err(|e| code::<(), _>(Err(e)))
    };
    for (who, name) in [(&writer, "writer"), (&reader, "reader")] {
        assert_eq!(code(copy(who, "copied").await), "AccessDenied", "{name}");
    }
    assert_eq!(
        part_copy(writer.clone(), "parts").await.unwrap_err(),
        "AccessDenied"
    );
    assert!(read(&s3, "target", "copied").await.is_none());
    assert_eq!(code(copy(&both, "copied").await), "ok");
    part_copy(both.clone(), "parts").await.unwrap();
}

async fn s3_upload(who: &Client, key: &str) -> Result<String, String> {
    who.create_multipart_upload()
        .bucket("target")
        .key(key)
        .send()
        .await
        .map(|upload| upload.upload_id().unwrap().to_owned())
        .map_err(|e| code::<(), _>(Err(e)))
}
