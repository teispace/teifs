//! Object Lock as the official AWS SDK sees it: a bucket's lock configuration, versions
//! kept by retention and legal holds, and governance bypassed only by those allowed to.
//! Each test runs on an object bucket and on a folder bucket.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    config::RequestChecksumCalculation,
    primitives::{ByteStream, DateTime},
    types::{
        BucketVersioningStatus, CompletedMultipartUpload, CompletedPart, DefaultRetention, Delete,
        ObjectIdentifier, ObjectLockConfiguration, ObjectLockEnabled, ObjectLockLegalHold,
        ObjectLockLegalHoldStatus, ObjectLockMode, ObjectLockRetention, ObjectLockRetentionMode,
        ObjectLockRule, VersioningConfiguration,
    },
};

#[macro_use]
mod common;

use common::{SECRET_KEY, client, code, start_with, user};
use teifs_store::Layout;

in_both_layouts!(
    the_lock_configuration_needs_versioning_and_keeps_it,
    retention_keeps_versions_until_governance_is_bypassed,
    legal_holds_keep_versions_until_lifted,
    the_default_retention_applies_and_a_write_can_override_it,
    many_keys_are_decided_one_by_one,
    locked_writes_need_a_checksum_and_uploads_keep_their_lock,
);

/// 2 January 2100: far enough away for any test run.
const LATER: i64 = 4_102_531_200;

async fn drive(layout: Layout) -> (common::Server, Client) {
    let server = start_with(|c| c.default_layout = layout).await;
    let s3 = client(&server, SECRET_KEY);
    (server, s3)
}

async fn locked_bucket(s3: &Client, name: &str) {
    s3.create_bucket()
        .bucket(name)
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
}

fn lock_config(mode: ObjectLockRetentionMode, days: i32) -> ObjectLockConfiguration {
    ObjectLockConfiguration::builder()
        .object_lock_enabled(ObjectLockEnabled::Enabled)
        .rule(
            ObjectLockRule::builder()
                .default_retention(DefaultRetention::builder().mode(mode).days(days).build())
                .build(),
        )
        .build()
}

async fn put(s3: &Client, key: &str) -> String {
    let put = s3
        .put_object()
        .bucket("vault")
        .key(key)
        .body(ByteStream::from_static(b"kept"));
    put.send().await.unwrap().version_id().unwrap().to_owned()
}

/// Writes `key` with a retention in `mode` until [`LATER`]; its version id.
async fn put_locked(s3: &Client, key: &str, mode: ObjectLockMode) -> String {
    let put = s3
        .put_object()
        .bucket("vault")
        .key(key)
        .object_lock_mode(mode)
        .object_lock_retain_until_date(DateTime::from_secs(LATER))
        .body(ByteStream::from_static(b"kept"));
    put.send().await.unwrap().version_id().unwrap().to_owned()
}

async fn remove(s3: &Client, key: &str, version: &str, bypass: bool) -> String {
    let delete = s3
        .delete_object()
        .bucket("vault")
        .key(key)
        .version_id(version)
        .set_bypass_governance_retention(bypass.then_some(true));
    code(delete.send().await)
}

fn retention(mode: ObjectLockRetentionMode, secs: i64) -> ObjectLockRetention {
    ObjectLockRetention::builder()
        .mode(mode)
        .retain_until_date(DateTime::from_secs(secs))
        .build()
}

async fn set_retention(
    s3: &Client,
    key: &str,
    retention: ObjectLockRetention,
    bypass: bool,
) -> String {
    let put = s3
        .put_object_retention()
        .bucket("vault")
        .key(key)
        .retention(retention)
        .set_bypass_governance_retention(bypass.then_some(true));
    code(put.send().await)
}

async fn the_lock_configuration_needs_versioning_and_keeps_it(layout: Layout) {
    let (_server, s3) = drive(layout).await;
    locked_bucket(&s3, "vault").await;
    let versioning = s3.get_bucket_versioning().bucket("vault").send().await;
    assert_eq!(
        versioning.unwrap().status(),
        Some(&BucketVersioningStatus::Enabled)
    );
    let got = s3
        .get_object_lock_configuration()
        .bucket("vault")
        .send()
        .await
        .unwrap();
    let config = got.object_lock_configuration().unwrap();
    assert_eq!(
        config.object_lock_enabled(),
        Some(&ObjectLockEnabled::Enabled)
    );
    assert!(config.rule().is_none());

    let wanted = lock_config(ObjectLockRetentionMode::Governance, 1);
    s3.put_object_lock_configuration()
        .bucket("vault")
        .object_lock_configuration(wanted.clone())
        .send()
        .await
        .unwrap();
    let got = s3
        .get_object_lock_configuration()
        .bucket("vault")
        .send()
        .await
        .unwrap();
    assert_eq!(got.object_lock_configuration(), Some(&wanted));

    let suspend = VersioningConfiguration::builder()
        .status(BucketVersioningStatus::Suspended)
        .build();
    let suspended = s3
        .put_bucket_versioning()
        .bucket("vault")
        .versioning_configuration(suspend)
        .send()
        .await;
    assert_eq!(code(suspended), "InvalidBucketState");

    // A bucket without versioning can't take it, and has none to show.
    s3.create_bucket().bucket("plain").send().await.unwrap();
    let put = s3
        .put_object_lock_configuration()
        .bucket("plain")
        .object_lock_configuration(wanted)
        .send()
        .await;
    assert_eq!(code(put), "InvalidBucketState");
    let got = s3
        .get_object_lock_configuration()
        .bucket("plain")
        .send()
        .await;
    assert_eq!(code(got), "ObjectLockConfigurationNotFoundError");
    let got = s3
        .get_object_retention()
        .bucket("plain")
        .key("a")
        .send()
        .await;
    assert_eq!(code(got), "InvalidRequest");
}

async fn retention_keeps_versions_until_governance_is_bypassed(layout: Layout) {
    let (_server, s3) = drive(layout).await;
    locked_bucket(&s3, "vault").await;
    let gov = put_locked(&s3, "gov.txt", ObjectLockMode::Governance).await;
    let head = s3
        .head_object()
        .bucket("vault")
        .key("gov.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(head.object_lock_mode(), Some(&ObjectLockMode::Governance));
    assert_eq!(
        head.object_lock_retain_until_date(),
        Some(&DateTime::from_secs(LATER))
    );
    assert_eq!(head.object_lock_legal_hold_status(), None);
    let got = s3
        .get_object_retention()
        .bucket("vault")
        .key("gov.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.retention(),
        Some(&retention(ObjectLockRetentionMode::Governance, LATER))
    );

    assert_eq!(remove(&s3, "gov.txt", &gov, false).await, "AccessDenied");
    // A simple delete adds a marker; the version stays.
    s3.delete_object()
        .bucket("vault")
        .key("gov.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(remove(&s3, "gov.txt", &gov, false).await, "AccessDenied");

    // Shortening needs the bypass; extending doesn't.
    let shorter = retention(ObjectLockRetentionMode::Governance, LATER - 86_400);
    let longer = retention(ObjectLockRetentionMode::Governance, LATER + 86_400);
    let put_on = |r| {
        let s3 = s3.clone();
        let gov = gov.clone();
        async move {
            let put = s3
                .put_object_retention()
                .bucket("vault")
                .key("gov.txt")
                .version_id(gov)
                .retention(r);
            code(put.send().await)
        }
    };
    assert_eq!(put_on(shorter.clone()).await, "AccessDenied");
    assert_eq!(put_on(longer).await, "ok");

    // Compliance can't be bypassed, shortened or turned into governance.
    let comp = put_locked(&s3, "comp.txt", ObjectLockMode::Compliance).await;
    assert_eq!(remove(&s3, "comp.txt", &comp, true).await, "AccessDenied");
    let governance = retention(ObjectLockRetentionMode::Governance, LATER);
    assert_eq!(
        set_retention(&s3, "comp.txt", governance, true).await,
        "AccessDenied"
    );
}

async fn legal_holds_keep_versions_until_lifted(layout: Layout) {
    let (_server, s3) = drive(layout).await;
    locked_bucket(&s3, "vault").await;
    let v1 = put(&s3, "a.txt").await;
    let got = s3
        .get_object_legal_hold()
        .bucket("vault")
        .key("a.txt")
        .send()
        .await;
    assert_eq!(code(got), "NoSuchObjectLockConfiguration");
    let hold = |status| {
        let s3 = s3.clone();
        async move {
            s3.put_object_legal_hold()
                .bucket("vault")
                .key("a.txt")
                .legal_hold(ObjectLockLegalHold::builder().status(status).build())
                .send()
                .await
                .unwrap();
        }
    };
    hold(ObjectLockLegalHoldStatus::On).await;
    let head = s3
        .head_object()
        .bucket("vault")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.object_lock_legal_hold_status(),
        Some(&ObjectLockLegalHoldStatus::On)
    );
    assert_eq!(remove(&s3, "a.txt", &v1, true).await, "AccessDenied");
    hold(ObjectLockLegalHoldStatus::Off).await;
    let got = s3
        .get_object_legal_hold()
        .bucket("vault")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.legal_hold().unwrap().status(),
        Some(&ObjectLockLegalHoldStatus::Off)
    );
    assert_eq!(remove(&s3, "a.txt", &v1, false).await, "ok");
}

async fn the_default_retention_applies_and_a_write_can_override_it(layout: Layout) {
    let (_server, s3) = drive(layout).await;
    locked_bucket(&s3, "vault").await;
    s3.put_object_lock_configuration()
        .bucket("vault")
        .object_lock_configuration(lock_config(ObjectLockRetentionMode::Compliance, 1))
        .send()
        .await
        .unwrap();
    put(&s3, "a.txt").await;
    let got = s3
        .get_object_retention()
        .bucket("vault")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    let given = got.retention().unwrap();
    assert_eq!(given.mode(), Some(&ObjectLockRetentionMode::Compliance));
    let until = given.retain_until_date().unwrap().secs();
    let now = DateTime::from(std::time::SystemTime::now()).secs();
    assert!((now + 86_000..=now + 86_400).contains(&until));

    // A copy gets the default (not its source's lock) or what it asks for.
    let copy = s3
        .copy_object()
        .bucket("vault")
        .key("b.txt")
        .copy_source("vault/a.txt")
        .object_lock_mode(ObjectLockMode::Governance)
        .object_lock_retain_until_date(DateTime::from_secs(LATER))
        .send()
        .await
        .unwrap();
    assert!(copy.version_id().is_some());
    let got = s3
        .get_object_retention()
        .bucket("vault")
        .key("b.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.retention(),
        Some(&retention(ObjectLockRetentionMode::Governance, LATER))
    );
    // A date in the past is refused.
    let in_the_past = s3
        .put_object()
        .bucket("vault")
        .key("c.txt")
        .object_lock_mode(ObjectLockMode::Governance)
        .object_lock_retain_until_date(DateTime::from_secs(1_000))
        .body(ByteStream::from_static(b"x"))
        .send()
        .await;
    assert_eq!(code(in_the_past), "InvalidArgument");
}

async fn many_keys_are_decided_one_by_one(layout: Layout) {
    let (_server, s3) = drive(layout).await;
    locked_bucket(&s3, "vault").await;
    let gov = put_locked(&s3, "gov.txt", ObjectLockMode::Governance).await;
    let free = put(&s3, "free.txt").await;
    let objects = [("gov.txt", &gov), ("free.txt", &free)].map(|(key, id)| {
        ObjectIdentifier::builder()
            .key(key)
            .version_id(id)
            .build()
            .unwrap()
    });
    let delete = Delete::builder()
        .set_objects(Some(objects.to_vec()))
        .build()
        .unwrap();
    let out = s3
        .delete_objects()
        .bucket("vault")
        .delete(delete.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(out.deleted().len(), 1);
    assert_eq!(out.deleted()[0].key(), Some("free.txt"));
    let refused = &out.errors()[0];
    assert_eq!(
        (refused.code(), refused.key(), refused.version_id()),
        (Some("AccessDenied"), Some("gov.txt"), Some(gov.as_str()))
    );
    let out = s3
        .delete_objects()
        .bucket("vault")
        .delete(delete)
        .bypass_governance_retention(true)
        .send()
        .await
        .unwrap();
    assert!(out.errors().is_empty());
}

async fn locked_writes_need_a_checksum_and_uploads_keep_their_lock(layout: Layout) {
    let (_server, s3) = drive(layout).await;
    locked_bucket(&s3, "vault").await;
    // Bytes that come with a lock must come with a checksum or Content-MD5.
    let config = s3
        .config()
        .to_builder()
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .build();
    let unchecked = Client::from_conf(config);
    let put = unchecked
        .put_object()
        .bucket("vault")
        .key("d.txt")
        .object_lock_legal_hold_status(ObjectLockLegalHoldStatus::On)
        .body(ByteStream::from_static(b"x"))
        .send()
        .await;
    assert_eq!(code(put), "InvalidRequest");
    let put = unchecked
        .put_object()
        .bucket("vault")
        .key("d.txt")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await;
    assert_eq!(code(put), "ok");

    // An upload in parts gets the lock it was started with.
    let upload = s3
        .create_multipart_upload()
        .bucket("vault")
        .key("big.bin")
        .object_lock_legal_hold_status(ObjectLockLegalHoldStatus::On)
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let uploaded = s3
        .upload_part()
        .bucket("vault")
        .key("big.bin")
        .upload_id(id)
        .part_number(1)
        .body(ByteStream::from_static(b"part"))
        .send()
        .await
        .unwrap();
    let parts = CompletedMultipartUpload::builder()
        .parts(
            CompletedPart::builder()
                .part_number(1)
                .e_tag(uploaded.e_tag().unwrap())
                .set_checksum_crc32(uploaded.checksum_crc32().map(str::to_owned))
                .build(),
        )
        .build();
    s3.complete_multipart_upload()
        .bucket("vault")
        .key("big.bin")
        .upload_id(id)
        .multipart_upload(parts)
        .send()
        .await
        .unwrap();
    let head = s3
        .head_object()
        .bucket("vault")
        .key("big.bin")
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.object_lock_legal_hold_status(),
        Some(&ObjectLockLegalHoldStatus::On)
    );
    assert_eq!(head.object_lock_mode(), None);
}

#[tokio::test]
async fn bypassing_governance_and_reading_locks_need_their_own_permissions() {
    let server = start_with(|_| {}).await;
    let root = client(&server, SECRET_KEY);
    locked_bucket(&root, "vault").await;
    let written = root
        .put_object()
        .bucket("vault")
        .key("a.txt")
        .object_lock_mode(ObjectLockMode::Governance)
        .object_lock_retain_until_date(DateTime::from_secs(LATER))
        .object_lock_legal_hold_status(ObjectLockLegalHoldStatus::Off)
        .body(ByteStream::from_static(b"kept"))
        .send()
        .await
        .unwrap();
    let version = written.version_id().unwrap().to_owned();
    let policy = |actions: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":["arn:aws:s3:::vault","arn:aws:s3:::vault/*"]}}]}}"#
        )
    };
    let plain = user(
        &server,
        "plain",
        Some(&policy(r#"["s3:GetObject","s3:DeleteObjectVersion"]"#)),
    );
    let head = plain
        .head_object()
        .bucket("vault")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.object_lock_mode(),
        None,
        "no retention without s3:GetObjectRetention"
    );
    assert_eq!(head.object_lock_retain_until_date(), None);
    assert_eq!(head.object_lock_legal_hold_status(), None);
    assert_eq!(
        remove(&plain, "a.txt", &version, true).await,
        "AccessDenied"
    );

    let bypasser = user(
        &server,
        "bypasser",
        Some(&policy(
            r#"["s3:GetObject","s3:GetObjectRetention","s3:GetObjectLegalHold","s3:DeleteObjectVersion","s3:BypassGovernanceRetention"]"#,
        )),
    );
    let head = bypasser
        .head_object()
        .bucket("vault")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(head.object_lock_mode(), Some(&ObjectLockMode::Governance));
    assert_eq!(
        head.object_lock_legal_hold_status(),
        Some(&ObjectLockLegalHoldStatus::Off)
    );
    assert_eq!(
        remove(&bypasser, "a.txt", &version, false).await,
        "AccessDenied"
    );
    // Many keys at once: the bypass counts only where the caller may bypass.
    let delete = Delete::builder()
        .objects(
            ObjectIdentifier::builder()
                .key("a.txt")
                .version_id(&version)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let out = plain
        .delete_objects()
        .bucket("vault")
        .delete(delete.clone())
        .bypass_governance_retention(true)
        .send()
        .await
        .unwrap();
    assert_eq!(out.errors()[0].code(), Some("AccessDenied"));
    let out = bypasser
        .delete_objects()
        .bucket("vault")
        .delete(delete)
        .bypass_governance_retention(true)
        .send()
        .await
        .unwrap();
    assert!(out.errors().is_empty());
    assert_eq!(out.deleted()[0].version_id(), Some(version.as_str()));
}
