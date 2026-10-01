//! Bucket quotas, as `MinIO`'s: set, read and cleared through `MinIO`'s admin API as
//! `mc quota` calls it, and writes that would reach a quota refused with `MinIO`'s error.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{Client, error::ProvideErrorMetadata, primitives::ByteStream};
use serde_json::{Value, json};

#[macro_use]
mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, code, start, start_with};
use signing::signed;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

/// `mc quota set` (`--size`), as madmin sends it: the older field.
fn hard(bytes: u64) -> String {
    json!({"quota": bytes, "quotatype": "hard"}).to_string()
}

async fn set(server: &Server, key: (&str, &str), bucket: &str, body: &str) -> (u16, String) {
    let path = format!("/minio/admin/v3/set-bucket-quota?bucket={bucket}");
    signed(server, key, "PUT", &path, &[], body.as_bytes()).await
}

async fn get(server: &Server, key: (&str, &str), bucket: &str) -> (u16, Value) {
    let path = format!("/minio/admin/v3/get-bucket-quota?bucket={bucket}");
    let (status, body) = signed(server, key, "GET", &path, &[], b"").await;
    (
        status,
        serde_json::from_str(&body).unwrap_or(Value::String(body)),
    )
}

#[tokio::test]
async fn quotas_are_set_read_and_cleared_as_minio_answers() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    let none = json!({"quota": 0, "size": 0, "rate": 0, "requests": 0});
    assert_eq!(get(&server, ROOT, "photos").await, (200, none.clone()));
    assert_eq!(set(&server, ROOT, "photos", &hard(1024)).await.0, 200);
    let set_quota =
        json!({"quota": 1024, "size": 1024, "rate": 0, "requests": 0, "quotatype": "hard"});
    assert_eq!(get(&server, ROOT, "photos").await, (200, set_quota));
    // Newer clients: `size`, and `v4`.
    let newer = json!({"size": 2048, "quotatype": "hard"}).to_string();
    let path = "/minio/admin/v4/set-bucket-quota?bucket=photos";
    assert_eq!(
        signed(&server, ROOT, "PUT", path, &[], newer.as_bytes())
            .await
            .0,
        200
    );
    let (_, answer) = get(&server, ROOT, "photos").await;
    assert_eq!(answer["size"], 2048);
    // `mc quota clear`.
    let clear = json!({"quota": 0, "size": 0, "rate": 0, "requests": 0}).to_string();
    assert_eq!(set(&server, ROOT, "photos", &clear).await.0, 200);
    assert_eq!(get(&server, ROOT, "photos").await, (200, none));
    // Errors, as JSON madmin reads.
    let (status, answer) = get(&server, ROOT, "nothing").await;
    assert_eq!((status, &answer["Code"]), (404, &json!("NoSuchBucket")));
    for bad in [r#"{"size":1}"#, r#"{"size":1,"quotatype":"fifo"}"#, "nope"] {
        let (status, body) = set(&server, ROOT, "photos", bad).await;
        let answer: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            (status, &answer["Code"]),
            (400, &json!("InvalidArgument")),
            "{bad}"
        );
    }
    let path = "/minio/admin/v3/get-bucket-quota";
    let (status, _) = signed(&server, ROOT, "GET", path, &[], b"").await;
    assert_eq!(status, 400, "no bucket");
    assert_eq!(
        get(&server, ROOT, "photos").await.1["size"],
        0,
        "nothing changed"
    );
}

/// A user with an inline policy, and their access key and secret.
fn keys(server: &Server, name: &str, policy: &str) -> (String, String) {
    server.iam.create_user(name, None, &[], None).unwrap();
    server
        .iam
        .put_inline(teifs_iam::Owner::User(name), "policy", policy)
        .unwrap();
    let key = server.iam.create_access_key(name).unwrap();
    (key.info.id, key.secret.to_string())
}

#[tokio::test]
async fn quotas_take_minios_admin_permissions_on_the_bucket() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    for bucket in ["photos", "other"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    let reader = keys(
        &server,
        "reader",
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"admin:GetBucketQuota","Resource":"arn:aws:s3:::photos"}}"#,
    );
    let reader = (reader.0.as_str(), reader.1.as_str());
    assert_eq!(get(&server, reader, "photos").await.0, 200);
    let (status, answer) = get(&server, reader, "other").await;
    assert_eq!((status, &answer["Code"]), (403, &json!("AccessDenied")));
    assert_eq!(set(&server, reader, "photos", &hard(1)).await.0, 403);
    // `s3:*` grants none of MinIO's admin actions.
    let s3_only = keys(
        &server,
        "everything",
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}"#,
    );
    let s3_only = (s3_only.0.as_str(), s3_only.1.as_str());
    assert_eq!(get(&server, s3_only, "photos").await.0, 403);
    // Unsigned: refused.
    let url = format!(
        "{}/minio/admin/v3/get-bucket-quota?bucket=photos",
        server.endpoint
    );
    let status = reqwest::get(url).await.unwrap().status().as_u16();
    assert_eq!(status, 403);
}

#[tokio::test]
async fn a_bucket_named_minio_keeps_its_keys() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("minio").send().await.unwrap();
    let key = "admin/v3/not-a-call";
    root.put_object()
        .bucket("minio")
        .key(key)
        .body(ByteStream::from_static(b"mine"))
        .send()
        .await
        .unwrap();
    let object = root
        .get_object()
        .bucket("minio")
        .key(key)
        .send()
        .await
        .unwrap();
    let bytes = object.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.as_ref(), b"mine");
}

/// The error code and status a write answers.
fn refusal<T, E: ProvideErrorMetadata>(
    result: Result<T, aws_sdk_s3::error::SdkError<E>>,
) -> (String, u16) {
    let err = result.err().unwrap();
    let status = err.raw_response().unwrap().status().as_u16();
    (err.code().unwrap_or_default().to_owned(), status)
}

async fn put(s3: &Client, key: &str, bytes: &'static [u8]) -> String {
    code(
        s3.put_object()
            .bucket("photos")
            .key(key)
            .body(ByteStream::from_static(bytes))
            .send()
            .await,
    )
}

in_both_layouts!(writes_that_would_reach_a_quota_are_refused);

async fn writes_that_would_reach_a_quota_are_refused(layout: teifs_store::Layout) {
    let server = start_with(|config| config.default_layout = layout).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("photos").send().await.unwrap();
    put(&s3, "big", b"0123456789ABCDEF").await;
    // A quota below what the bucket holds: no more writes, however small.
    assert_eq!(set(&server, ROOT, "photos", &hard(10)).await.0, 200);
    let exceeded = ("XMinioAdminBucketQuotaExceeded".to_owned(), 400);
    let small = s3
        .put_object()
        .bucket("photos")
        .key("small")
        .body(ByteStream::from_static(b"1"))
        .send()
        .await;
    assert_eq!(refusal(small), exceeded);
    s3.delete_object()
        .bucket("photos")
        .key("big")
        .send()
        .await
        .unwrap();
    // As on MinIO, what's held and what's written must stay below the quota.
    assert_eq!(put(&s3, "a", b"0123").await, "ok");
    assert_eq!(put(&s3, "b", b"01234").await, "ok");
    assert_eq!(put(&s3, "c", b"0").await, "XMinioAdminBucketQuotaExceeded");
    // Copies and parts, of a copy's source size and a part's.
    let copy = s3
        .copy_object()
        .bucket("photos")
        .key("copy")
        .copy_source("photos/b")
        .send()
        .await;
    assert_eq!(refusal(copy), exceeded.clone());
    let upload = s3
        .create_multipart_upload()
        .bucket("photos")
        .key("parts")
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let part = s3
        .upload_part()
        .bucket("photos")
        .key("parts")
        .upload_id(id)
        .part_number(1)
        .body(ByteStream::from_static(b"0123456789"))
        .send()
        .await;
    assert_eq!(refusal(part), exceeded.clone());
    let part_copy = s3
        .upload_part_copy()
        .bucket("photos")
        .key("parts")
        .upload_id(id)
        .part_number(1)
        .copy_source("photos/b")
        .send()
        .await;
    assert_eq!(refusal(part_copy), exceeded);
    // Cleared: writes are taken again.
    assert_eq!(set(&server, ROOT, "photos", "{}").await.0, 200);
    assert_eq!(put(&s3, "c", b"0123456789").await, "ok");
}
