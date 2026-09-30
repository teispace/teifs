//! `UpdateObjectEncryption` as the official AWS SDK sees it: an SSE-S3 object moves to a KMS
//! key without its data, ETag, modification time or checksum changing, and requests S3
//! refuses are refused here too.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    primitives::ByteStream,
    types::{
        ChecksumAlgorithm, ChecksumMode, ObjectEncryption, ServerSideEncryption, SsekmsEncryption,
    },
};

mod common;

use common::{SECRET_KEY, client, code, sig_v2_link, start_with, user};

const DEFAULT_ARN: &str = "arn:aws:kms:us-east-1:000000000000:key/teifs-default";

async fn update(s3: &Client, key: &str, arn: &str, bucket_key: bool) -> String {
    code(
        s3.update_object_encryption()
            .bucket("vault")
            .key(key)
            .object_encryption(ObjectEncryption::Ssekms(
                SsekmsEncryption::builder()
                    .kms_key_arn(arn)
                    .bucket_key_enabled(bucket_key)
                    .build()
                    .unwrap(),
            ))
            .send()
            .await,
    )
}

#[tokio::test]
async fn an_object_moves_to_a_kms_key_in_place() {
    let server = start_with(|c| c.default_layout = teifs_store::Layout::Object).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("vault").send().await.unwrap();
    let put = s3
        .put_object()
        .bucket("vault")
        .key("a")
        .checksum_algorithm(ChecksumAlgorithm::Sha256)
        .body(ByteStream::from_static(b"top secret"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.server_side_encryption(),
        Some(&ServerSideEncryption::Aes256)
    );
    let before = s3
        .head_object()
        .bucket("vault")
        .key("a")
        .send()
        .await
        .unwrap();

    assert_eq!(update(&s3, "a", DEFAULT_ARN, true).await, "ok");
    let got = s3
        .get_object()
        .bucket("vault")
        .key("a")
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.server_side_encryption(),
        Some(&ServerSideEncryption::AwsKms)
    );
    assert_eq!(got.ssekms_key_id(), Some("teifs-default"));
    assert_eq!(got.bucket_key_enabled(), Some(true));
    assert_eq!(
        (got.e_tag(), got.last_modified()),
        (before.e_tag(), before.last_modified())
    );
    assert_eq!(got.checksum_sha256(), put.checksum_sha256());
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(&bytes[..], b"top secret");

    // As S3 refuses them.
    assert_eq!(
        update(&s3, "a", "teifs-default", false).await,
        "InvalidRequest"
    );
    assert_eq!(
        update(
            &s3,
            "a",
            "arn:aws:kms:us-east-1:000000000000:alias/x",
            false
        )
        .await,
        "InvalidRequest"
    );
    assert_eq!(
        update(
            &s3,
            "a",
            "arn:aws:kms:us-east-1:000000000000:key/nope",
            false
        )
        .await,
        "KMS.NotFoundException"
    );
    assert_eq!(update(&s3, "gone", DEFAULT_ARN, false).await, "NoSuchKey");
    let reader = user(
        &server,
        "reader",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        ),
    );
    assert_eq!(
        update(&reader, "a", DEFAULT_ARN, false).await,
        "AccessDenied"
    );
    // Still as the last update left it.
    let head = s3
        .head_object()
        .bucket("vault")
        .key("a")
        .send()
        .await
        .unwrap();
    assert_eq!(head.bucket_key_enabled(), Some(true));
}

#[tokio::test]
async fn signature_v4_is_required() {
    let server = start_with(|c| {
        c.default_layout = teifs_store::Layout::Object;
        c.allow_sig_v2 = true;
    })
    .await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("vault").send().await.unwrap();
    s3.put_object()
        .bucket("vault")
        .key("a")
        .body(ByteStream::from_static(b"a"))
        .send()
        .await
        .unwrap();
    let body = format!(
        "<ObjectEncryption><SSE-KMS><KMSKeyArn>{DEFAULT_ARN}</KMSKeyArn></SSE-KMS></ObjectEncryption>"
    );
    // `encryption` isn't among the subresources Signature V2 signs (botocore's list).
    let link = sig_v2_link(&server, "PUT", "/vault/a?encryption", "/vault/a");
    let answer = reqwest::Client::new()
        .put(link)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = answer.status();
    let text = answer.text().await.unwrap();
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("Signature Version 4"), "{text}");
    let head = s3
        .head_object()
        .bucket("vault")
        .key("a")
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.server_side_encryption(),
        Some(&ServerSideEncryption::Aes256)
    );
}
