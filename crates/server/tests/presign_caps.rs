//! Upload size caps: a link signed with `x-teifs-max-content-length` takes a body of at
//! most that many bytes, and a multipart upload created with
//! `x-teifs-max-total-object-size` takes parts adding up to at most that. The caps are
//! part of the signed query, so whoever holds a link can't raise or remove them.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::Duration;

use aws_sdk_s3::{
    Client,
    config::http::HttpRequest,
    presigning::{PresignedRequest, PresigningConfig},
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

use common::{SECRET_KEY, Server, client, start};

const MIB: usize = 1024 * 1024;

/// Adds `name=value` to a request's query before it's signed.
fn with_query(name: &'static str, value: u64) -> impl Fn(&mut HttpRequest) + Send + Sync {
    move |req| {
        let uri = req.uri().to_owned();
        let sep = if uri.contains('?') { '&' } else { '?' };
        req.set_uri(format!("{uri}{sep}{name}={value}")).unwrap();
    }
}

/// A presigned PUT link to `inbox/upload.bin` that takes at most `cap` bytes.
async fn capped_link(s3: &Client, cap: u64) -> PresignedRequest {
    s3.put_object()
        .bucket("inbox")
        .key("upload.bin")
        .customize()
        .mutate_request(with_query("x-teifs-max-content-length", cap))
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap()
}

/// Sends `body` to `uri` with PUT: the status and the error code, if any.
async fn put(uri: &str, body: reqwest::Body) -> (u16, String) {
    let response = reqwest::Client::new()
        .put(uri)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, code(&response.text().await.unwrap()))
}

/// Sends `body` to `uri` with PUT as one chunk of a chunked body, so its length isn't
/// declared: the status line.
async fn put_chunked(uri: &str, body: &str) -> String {
    let rest = uri.trim_start_matches("http://");
    let (address, target) = rest.split_at(rest.find('/').unwrap());
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "PUT {target} HTTP/1.1\r\nHost: {address}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    answer.lines().next().unwrap_or_default().to_owned()
}

fn code(body: &str) -> String {
    body.split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| code.to_owned())
        .unwrap_or_default()
}

async fn inbox() -> (Server, Client) {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("inbox").send().await.unwrap();
    (server, s3)
}

#[tokio::test]
async fn a_capped_link_takes_only_so_many_bytes() {
    let (_server, s3) = inbox().await;
    let link = capped_link(&s3, 10).await;
    let uri = link.uri();
    assert_eq!(put(uri, "0123456789".into()).await, (200, String::new()));
    let size = s3
        .head_object()
        .bucket("inbox")
        .key("upload.bin")
        .send()
        .await
        .unwrap()
        .content_length();
    assert_eq!(size, Some(10));
    // One byte more is refused before it's stored, and the object is as it was.
    assert_eq!(
        put(uri, "0123456789!".into()).await,
        (400, "EntityTooLarge".into())
    );
    // A body of unknown length can't be checked before it's read.
    assert_eq!(
        put_chunked(uri, "tiny").await,
        "HTTP/1.1 411 Length Required"
    );
    // The cap is signed: without it or raised, the link doesn't work.
    for tampered in [
        uri.replace("x-teifs-max-content-length=10&", ""),
        uri.replace(
            "x-teifs-max-content-length=10",
            "x-teifs-max-content-length=99",
        ),
    ] {
        assert_ne!(tampered, uri);
        let (status, code) = put(&tampered, "0123456789!".into()).await;
        assert_eq!(
            (status, code.as_str()),
            (403, "SignatureDoesNotMatch"),
            "{tampered}"
        );
    }
    let head = s3.head_object().bucket("inbox").key("upload.bin");
    assert_eq!(head.send().await.unwrap().content_length(), Some(10));
    // A zero cap takes only an empty body.
    let empty = capped_link(&s3, 0).await;
    assert_eq!(put(empty.uri(), "".into()).await.0, 200);
    assert_eq!(
        put(empty.uri(), "x".into()).await,
        (400, "EntityTooLarge".into())
    );
}

#[tokio::test]
async fn caps_are_refused_where_they_would_not_hold() {
    let (server, s3) = inbox().await;
    // A header-signed request's query is signed too, so the cap holds there as well.
    let capped = s3
        .put_object()
        .bucket("inbox")
        .key("signed.bin")
        .body(ByteStream::from_static(b"too long"))
        .customize()
        .mutate_request(with_query("x-teifs-max-content-length", 3))
        .send()
        .await;
    assert_eq!(
        capped.unwrap_err().into_service_error().meta().code(),
        Some("EntityTooLarge")
    );
    // On an operation it doesn't apply to, a cap is refused rather than ignored.
    let get = s3
        .get_object()
        .bucket("inbox")
        .key("signed.bin")
        .customize()
        .mutate_request(with_query("x-teifs-max-content-length", 3))
        .send()
        .await;
    assert_eq!(
        get.unwrap_err().into_service_error().meta().code(),
        Some("InvalidRequest")
    );
    let upload = s3
        .create_multipart_upload()
        .bucket("inbox")
        .key("big.bin")
        .customize()
        .mutate_request(with_query("x-teifs-max-content-length", 3))
        .send()
        .await;
    assert_eq!(
        upload.unwrap_err().into_service_error().meta().code(),
        Some("InvalidRequest")
    );
    // Unsigned, a cap could be taken off by anyone, so it isn't taken at all.
    let anonymous = format!(
        "{}/inbox/anon.bin?x-teifs-max-content-length=3",
        server.endpoint
    );
    let (status, code) = put(&anonymous, "abc".into()).await;
    assert_eq!((status, code.as_str()), (400, "InvalidRequest"));
}

#[tokio::test]
async fn a_capped_upload_takes_parts_up_to_its_total() {
    let (_server, s3) = inbox().await;
    let cap = u64::try_from(6 * MIB).unwrap();
    let id = s3
        .create_multipart_upload()
        .bucket("inbox")
        .key("big.bin")
        .customize()
        .mutate_request(with_query("x-teifs-max-total-object-size", cap))
        .send()
        .await
        .unwrap()
        .upload_id
        .unwrap();
    let part = |number: i32, size: usize| {
        s3.upload_part()
            .bucket("inbox")
            .key("big.bin")
            .upload_id(&id)
            .part_number(number)
            .body(ByteStream::from(vec![b'x'; size]))
            .send()
    };
    let refused = |result: Result<_, aws_sdk_s3::error::SdkError<_, _>>| {
        let err: aws_sdk_s3::operation::upload_part::UploadPartError =
            result.unwrap_err().into_service_error();
        err.meta().code().map(str::to_owned)
    };
    part(1, 5 * MIB).await.unwrap();
    // A replaced part doesn't count twice.
    let first = part(1, 5 * MIB).await.unwrap().e_tag.unwrap();
    assert_eq!(
        refused(part(2, MIB + 1).await).as_deref(),
        Some("EntityTooLarge")
    );
    // A copied part counts as much as a sent one.
    s3.put_object()
        .bucket("inbox")
        .key("source.bin")
        .body(ByteStream::from(vec![b's'; 2 * MIB]))
        .send()
        .await
        .unwrap();
    let copied = s3
        .upload_part_copy()
        .bucket("inbox")
        .key("big.bin")
        .upload_id(&id)
        .part_number(3)
        .copy_source("inbox/source.bin")
        .send()
        .await;
    assert_eq!(
        copied.unwrap_err().into_service_error().meta().code(),
        Some("EntityTooLarge")
    );
    let second = part(2, MIB).await.unwrap().e_tag.unwrap();
    let parts = s3
        .list_parts()
        .bucket("inbox")
        .key("big.bin")
        .upload_id(&id)
        .send()
        .await
        .unwrap();
    assert_eq!(parts.parts().len(), 2, "refused parts aren't kept");
    let done = s3
        .complete_multipart_upload()
        .bucket("inbox")
        .key("big.bin")
        .upload_id(&id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(CompletedPart::builder().part_number(1).e_tag(first).build())
                .parts(
                    CompletedPart::builder()
                        .part_number(2)
                        .e_tag(second)
                        .build(),
                )
                .build(),
        )
        .send()
        .await;
    assert!(done.is_ok(), "{done:?}");
    let head = s3.head_object().bucket("inbox").key("big.bin");
    assert_eq!(
        head.send().await.unwrap().content_length(),
        Some(i64::try_from(6 * MIB).unwrap())
    );
}

#[tokio::test]
async fn uploads_created_without_a_cap_take_parts_as_before() {
    let (_server, s3) = inbox().await;
    let open = s3
        .create_multipart_upload()
        .bucket("inbox")
        .key("open.bin")
        .send()
        .await
        .unwrap()
        .upload_id
        .unwrap();
    s3.upload_part()
        .bucket("inbox")
        .key("open.bin")
        .upload_id(&open)
        .part_number(1)
        .body(ByteStream::from(vec![b'x'; 7 * MIB]))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn a_capped_uploads_parts_declare_their_length() {
    let (_server, s3) = inbox().await;
    let id = s3
        .create_multipart_upload()
        .bucket("inbox")
        .key("big.bin")
        .customize()
        .mutate_request(with_query("x-teifs-max-total-object-size", 100))
        .send()
        .await
        .unwrap()
        .upload_id
        .unwrap();
    let link = s3
        .upload_part()
        .bucket("inbox")
        .key("big.bin")
        .upload_id(&id)
        .part_number(1)
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap();
    // A part of unknown length can't be admitted before it's read.
    assert_eq!(
        put_chunked(link.uri(), "part").await,
        "HTTP/1.1 411 Length Required"
    );
    assert_eq!(put(link.uri(), "part".into()).await.0, 200);
}
