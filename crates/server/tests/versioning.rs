//! Versioning as the official AWS SDK sees it: versions stack, delete markers hide
//! objects and answer as S3's do, versions are listed in pages, and a suspended bucket
//! writes `null`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    error::SdkError,
    primitives::ByteStream,
    types::{BucketVersioningStatus, Delete, MfaDelete, ObjectIdentifier, VersioningConfiguration},
};

mod common;

use common::{SECRET_KEY, client, code, start_with};

async fn object_drive() -> (common::Server, Client) {
    let server = start_with(|c| c.default_layout = teifs_store::Layout::Object).await;
    let s3 = client(&server, SECRET_KEY);
    (server, s3)
}

async fn set_versioning(s3: &Client, bucket: &str, status: BucketVersioningStatus) -> String {
    let config = VersioningConfiguration::builder().status(status).build();
    let put = s3
        .put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(config);
    code(put.send().await)
}

async fn put(s3: &Client, key: &str, body: &'static [u8]) -> Option<String> {
    let put = s3
        .put_object()
        .bucket("docs")
        .key(key)
        .body(ByteStream::from_static(body));
    put.send().await.unwrap().version_id().map(str::to_owned)
}

async fn get(s3: &Client, key: &str, version_id: Option<&str>) -> Vec<u8> {
    let got = s3
        .get_object()
        .bucket("docs")
        .key(key)
        .set_version_id(version_id.map(str::to_owned))
        .send()
        .await
        .unwrap();
    assert_eq!(got.version_id(), version_id.or(got.version_id()));
    got.body.collect().await.unwrap().into_bytes().to_vec()
}

/// The status and the headers S3 names a delete marker with, of a failed call.
fn marker_headers<E>(
    err: &SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> (u16, Option<String>, Option<String>, bool) {
    let raw = err.raw_response().unwrap();
    let header = |name: &str| raw.headers().get(name).map(str::to_owned);
    (
        raw.status().as_u16(),
        header("x-amz-delete-marker"),
        header("x-amz-version-id"),
        header("last-modified").is_some(),
    )
}

#[tokio::test]
async fn versions_stack_and_each_stays_readable() {
    let (_server, s3) = object_drive().await;
    s3.create_bucket().bucket("docs").send().await.unwrap();
    let status = s3.get_bucket_versioning().bucket("docs").send().await;
    assert_eq!(status.unwrap().status(), None);
    // Before versioning, nothing is named.
    assert_eq!(put(&s3, "a.txt", b"zero").await, None);

    assert_eq!(
        set_versioning(&s3, "docs", BucketVersioningStatus::Enabled).await,
        "ok"
    );
    let status = s3.get_bucket_versioning().bucket("docs").send().await;
    assert_eq!(
        status.unwrap().status(),
        Some(&BucketVersioningStatus::Enabled)
    );
    let v1 = put(&s3, "a.txt", b"one").await.unwrap();
    let v2 = put(&s3, "a.txt", b"two").await.unwrap();
    assert_ne!(v1, v2);
    assert_eq!(get(&s3, "a.txt", None).await, b"two");
    assert_eq!(get(&s3, "a.txt", Some(&v1)).await, b"one");
    assert_eq!(get(&s3, "a.txt", Some("null")).await, b"zero");
    let head = s3
        .head_object()
        .bucket("docs")
        .key("a.txt")
        .version_id(&v1)
        .send()
        .await
        .unwrap();
    assert_eq!(head.version_id(), Some(v1.as_str()));
    assert_eq!(head.content_length(), Some(3));

    // A version id TeiFS couldn't have made is refused; one it could, not there, is 404.
    let bad = s3
        .get_object()
        .bucket("docs")
        .key("a.txt")
        .version_id("nope");
    assert_eq!(code(bad.send().await), "InvalidArgument");
    let missing = s3
        .get_object()
        .bucket("docs")
        .key("a.txt")
        .version_id("0".repeat(32));
    assert_eq!(code(missing.send().await), "NoSuchVersion");

    // Tags belong to a version.
    let tagging = aws_sdk_s3::types::Tagging::builder()
        .tag_set(
            aws_sdk_s3::types::Tag::builder()
                .key("k")
                .value("v")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let tagged = s3
        .put_object_tagging()
        .bucket("docs")
        .key("a.txt")
        .version_id(&v1)
        .tagging(tagging)
        .send()
        .await
        .unwrap();
    assert_eq!(tagged.version_id(), Some(v1.as_str()));
    let tags = |version: Option<String>| {
        s3.get_object_tagging()
            .bucket("docs")
            .key("a.txt")
            .set_version_id(version)
            .send()
    };
    assert_eq!(tags(Some(v1.clone())).await.unwrap().tag_set().len(), 1);
    let current = tags(None).await.unwrap();
    assert!(current.tag_set().is_empty());
    assert_eq!(current.version_id(), Some(v2.as_str()));

    // Restoring a version: copy it onto its key.
    let copy = s3
        .copy_object()
        .bucket("docs")
        .key("a.txt")
        .copy_source(format!("docs/a.txt?versionId={v1}"))
        .send()
        .await
        .unwrap();
    assert_eq!(copy.copy_source_version_id(), Some(v1.as_str()));
    let v3 = copy.version_id().unwrap();
    assert!(v3 != v1 && v3 != v2);
    assert_eq!(get(&s3, "a.txt", None).await, b"one");
}

#[tokio::test]
async fn delete_markers_hide_objects_as_on_s3() {
    let (_server, s3) = object_drive().await;
    s3.create_bucket().bucket("docs").send().await.unwrap();
    set_versioning(&s3, "docs", BucketVersioningStatus::Enabled).await;
    let v1 = put(&s3, "a.txt", b"one").await.unwrap();
    let deleted = s3
        .delete_object()
        .bucket("docs")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.delete_marker(), Some(true));
    let marker = deleted.version_id().unwrap().to_owned();

    // The current version is a marker: 404, saying so.
    let err = s3.get_object().bucket("docs").key("a.txt").send().await;
    let err = err.unwrap_err();
    assert_eq!(
        marker_headers(&err),
        (404, Some("true".into()), Some(marker.clone()), false)
    );
    let err = s3.head_object().bucket("docs").key("a.txt").send().await;
    assert_eq!(marker_headers(&err.unwrap_err()).0, 404);
    // Naming the marker: 405, with when it was added.
    let named = s3
        .get_object()
        .bucket("docs")
        .key("a.txt")
        .version_id(&marker)
        .send()
        .await;
    let err = named.unwrap_err();
    assert_eq!(
        marker_headers(&err),
        (405, Some("true".into()), Some(marker.clone()), true)
    );
    assert_eq!(get(&s3, "a.txt", Some(&v1)).await, b"one");
    let listed = s3.list_objects_v2().bucket("docs").send().await.unwrap();
    assert_eq!(listed.key_count(), Some(0));
    let delete_bucket = s3.delete_bucket().bucket("docs").send().await;
    assert_eq!(code(delete_bucket), "BucketNotEmpty");

    // Removing the marker brings the object back.
    let removed = s3
        .delete_object()
        .bucket("docs")
        .key("a.txt")
        .version_id(&marker)
        .send()
        .await
        .unwrap();
    assert_eq!(removed.version_id(), Some(marker.as_str()));
    assert_eq!(removed.delete_marker(), Some(true));
    assert_eq!(get(&s3, "a.txt", None).await, b"one");

    // DeleteObjects: a marker for one key, a version for good for another.
    let v2 = put(&s3, "b.txt", b"two").await.unwrap();
    let id = |key: &str, version: Option<&str>| {
        ObjectIdentifier::builder()
            .key(key)
            .set_version_id(version.map(str::to_owned))
            .build()
            .unwrap()
    };
    let delete = Delete::builder()
        .objects(id("a.txt", None))
        .objects(id("b.txt", Some(&v2)))
        .objects(id("c.txt", Some("bad")))
        .build()
        .unwrap();
    let out = s3
        .delete_objects()
        .bucket("docs")
        .delete(delete)
        .send()
        .await
        .unwrap();
    let a = &out.deleted()[0];
    assert_eq!(
        (a.key(), a.delete_marker(), a.version_id()),
        (Some("a.txt"), Some(true), None)
    );
    assert!(a.delete_marker_version_id().is_some());
    let b = &out.deleted()[1];
    assert_eq!(
        (b.key(), b.delete_marker(), b.version_id()),
        (Some("b.txt"), None, Some(v2.as_str()))
    );
    assert_eq!(out.errors()[0].code(), Some("InvalidArgument"));
    let b = s3.head_object().bucket("docs").key("b.txt").send().await;
    assert_eq!(code(b), "NotFound");
}

#[tokio::test]
async fn versions_list_in_pages_newest_first() {
    let (_server, s3) = object_drive().await;
    s3.create_bucket().bucket("docs").send().await.unwrap();
    set_versioning(&s3, "docs", BucketVersioningStatus::Enabled).await;
    let a1 = put(&s3, "a", b"1").await.unwrap();
    let a2 = put(&s3, "a", b"2").await.unwrap();
    put(&s3, "dir/x", b"x").await;
    let marker = s3.delete_object().bucket("docs").key("e").send().await;
    let marker = marker.unwrap().version_id().unwrap().to_owned();

    let list = |key_marker: Option<String>, version_marker: Option<String>| {
        s3.list_object_versions()
            .bucket("docs")
            .delimiter("/")
            .max_keys(2)
            .set_key_marker(key_marker)
            .set_version_id_marker(version_marker)
            .send()
    };
    let first = list(None, None).await.unwrap();
    let ids: Vec<_> = first.versions().iter().map(|v| v.version_id()).collect();
    assert_eq!(ids, [Some(a2.as_str()), Some(a1.as_str())]);
    assert_eq!(first.versions()[0].is_latest(), Some(true));
    assert_eq!(first.versions()[1].is_latest(), Some(false));
    assert_eq!(first.is_truncated(), Some(true));
    assert_eq!(first.next_key_marker(), Some("a"));
    assert_eq!(first.next_version_id_marker(), Some(a1.as_str()));

    let second = list(Some("a".into()), Some(a1.clone())).await.unwrap();
    assert!(second.versions().is_empty());
    assert_eq!(second.common_prefixes()[0].prefix(), Some("dir/"));
    let markers = second.delete_markers();
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].version_id(), Some(marker.as_str()));
    assert_eq!(markers[0].is_latest(), Some(true));
    assert_eq!(second.is_truncated(), Some(false));

    let without_key = list(None, Some(a1.clone())).await;
    assert_eq!(code(without_key), "InvalidArgument");
}

#[tokio::test]
async fn suspended_buckets_write_null_versions() {
    let (_server, s3) = object_drive().await;
    s3.create_bucket().bucket("docs").send().await.unwrap();
    set_versioning(&s3, "docs", BucketVersioningStatus::Enabled).await;
    let v1 = put(&s3, "a.txt", b"one").await.unwrap();
    set_versioning(&s3, "docs", BucketVersioningStatus::Suspended).await;
    // MFA delete needs devices TeiFS doesn't have.
    let config = VersioningConfiguration::builder()
        .status(BucketVersioningStatus::Enabled)
        .mfa_delete(MfaDelete::Enabled)
        .build();
    let mfa = s3
        .put_bucket_versioning()
        .bucket("docs")
        .versioning_configuration(config);
    assert_eq!(code(mfa.send().await), "NotImplemented");
    let status = s3.get_bucket_versioning().bucket("docs").send().await;
    assert_eq!(
        status.unwrap().status(),
        Some(&BucketVersioningStatus::Suspended)
    );
    // A write names no version when it's `null`; reads do.
    assert_eq!(put(&s3, "a.txt", b"two").await, None);
    assert_eq!(put(&s3, "a.txt", b"three").await, None);
    let head = s3.head_object().bucket("docs").key("a.txt").send().await;
    assert_eq!(head.unwrap().version_id(), Some("null"));
    let deleted = s3
        .delete_object()
        .bucket("docs")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        (deleted.version_id(), deleted.delete_marker()),
        (Some("null"), Some(true))
    );
    let versions = s3
        .list_object_versions()
        .bucket("docs")
        .send()
        .await
        .unwrap();
    assert_eq!(versions.versions().len(), 1);
    assert_eq!(versions.versions()[0].version_id(), Some(v1.as_str()));
    assert_eq!(versions.delete_markers()[0].version_id(), Some("null"));
}

#[tokio::test]
async fn what_teifs_cant_version_is_refused() {
    let server = start_with(|_| {}).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("files").send().await.unwrap();
    // Folder buckets keep plain files: not yet.
    assert_eq!(
        set_versioning(&s3, "files", BucketVersioningStatus::Enabled).await,
        "NotImplemented"
    );
    let status = s3.get_bucket_versioning().bucket("files").send().await;
    assert_eq!(status.unwrap().status(), None);
    assert_eq!(
        set_versioning(&s3, "missing", BucketVersioningStatus::Enabled).await,
        "NoSuchBucket"
    );
}
