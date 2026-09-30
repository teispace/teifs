//! Lifecycle as the official AWS SDK sees it: a bucket's rules round-trip and are
//! checked, answers say when objects expire and uploads are aborted, and the rules are
//! applied. Each test runs on an object bucket and on a folder bucket.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::Duration;

use aws_sdk_s3::{
    Client,
    primitives::ByteStream,
    types::{
        AbortIncompleteMultipartUpload, BucketLifecycleConfiguration, BucketVersioningStatus,
        ExpirationStatus, LifecycleExpiration, LifecycleRule, LifecycleRuleAndOperator,
        LifecycleRuleFilter, NoncurrentVersionExpiration, Tag, Transition, TransitionStorageClass,
        VersioningConfiguration,
    },
};

#[macro_use]
mod common;

use common::{SECRET_KEY, client, code, start_with, user};
use teifs_store::Layout;

in_both_layouts!(
    rules_round_trip,
    bad_rules_are_refused_and_change_nothing,
    answers_say_when_objects_expire,
    uploads_say_when_they_are_aborted,
    the_server_applies_the_rules,
);

async fn drive(layout: Layout, day: Option<Duration>) -> (common::Server, Client) {
    let server = start_with(|c| {
        c.default_layout = layout;
        c.lifecycle_day = day;
    })
    .await;
    let s3 = client(&server, SECRET_KEY);
    (server, s3)
}

fn rule(
    id: &str,
    filter: LifecycleRuleFilter,
) -> aws_sdk_s3::types::builders::LifecycleRuleBuilder {
    LifecycleRule::builder()
        .id(id)
        .status(ExpirationStatus::Enabled)
        .filter(filter)
}

fn prefix(prefix: &str) -> LifecycleRuleFilter {
    LifecycleRuleFilter::builder().prefix(prefix).build()
}

fn days(days: i32) -> LifecycleExpiration {
    LifecycleExpiration::builder().days(days).build()
}

async fn set(s3: &Client, bucket: &str, rules: Vec<LifecycleRule>) -> String {
    code(
        s3.put_bucket_lifecycle_configuration()
            .bucket(bucket)
            .lifecycle_configuration(
                BucketLifecycleConfiguration::builder()
                    .set_rules(Some(rules))
                    .build()
                    .unwrap(),
            )
            .send()
            .await,
    )
}

/// Rules of every kind, set on `bkt`.
async fn set_valid_rules(s3: &Client) -> Vec<LifecycleRule> {
    s3.create_bucket().bucket("bkt").send().await.unwrap();
    assert_eq!(
        code(
            s3.get_bucket_lifecycle_configuration()
                .bucket("bkt")
                .send()
                .await
        ),
        "NoSuchLifecycleConfiguration"
    );
    // Deleting none succeeds.
    s3.delete_bucket_lifecycle()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    let tagged = LifecycleRuleFilter::builder()
        .and(
            LifecycleRuleAndOperator::builder()
                .prefix("logs/")
                .tags(Tag::builder().key("tmp").value("yes").build().unwrap())
                .object_size_greater_than(10)
                .build(),
        )
        .build();
    let rules = vec![
        rule("logs", prefix("logs/"))
            .expiration(days(30))
            .noncurrent_version_expiration(
                NoncurrentVersionExpiration::builder()
                    .noncurrent_days(7)
                    .newer_noncurrent_versions(2)
                    .build(),
            )
            .abort_incomplete_multipart_upload(
                AbortIncompleteMultipartUpload::builder()
                    .days_after_initiation(3)
                    .build(),
            )
            .build()
            .unwrap(),
        rule("tagged", tagged)
            .status(ExpirationStatus::Disabled)
            .expiration(days(1))
            .build()
            .unwrap(),
    ];
    assert_eq!(set(s3, "bkt", rules.clone()).await, "ok");
    rules
}

async fn rules_round_trip(layout: Layout) {
    let (server, s3) = drive(layout, None).await;
    let rules = set_valid_rules(&s3).await;
    let got = s3
        .get_bucket_lifecycle_configuration()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    assert_eq!(got.rules(), rules.as_slice());
    assert_eq!(
        got.transition_default_minimum_object_size()
            .unwrap()
            .as_str(),
        "all_storage_classes_128K"
    );

    // Only those allowed to.
    let reader = user(
        &server,
        "reader",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetLifecycleConfiguration","Resource":"*"}]}"#,
        ),
    );
    assert_eq!(
        code(
            reader
                .get_bucket_lifecycle_configuration()
                .bucket("bkt")
                .send()
                .await
        ),
        "ok"
    );
    assert_eq!(
        code(reader.delete_bucket_lifecycle().bucket("bkt").send().await),
        "AccessDenied"
    );

    s3.delete_bucket_lifecycle()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(
            s3.get_bucket_lifecycle_configuration()
                .bucket("bkt")
                .send()
                .await
        ),
        "NoSuchLifecycleConfiguration"
    );
}

async fn bad_rules_are_refused_and_change_nothing(layout: Layout) {
    let (_server, s3) = drive(layout, None).await;
    let rules = set_valid_rules(&s3).await;
    // Checked as S3 checks them; a refused configuration leaves the old one.
    let bad = |r: aws_sdk_s3::types::builders::LifecycleRuleBuilder| vec![r.build().unwrap()];
    assert_eq!(
        set(
            &s3,
            "bkt",
            bad(rule("zero", prefix("")).expiration(days(0)))
        )
        .await,
        "InvalidArgument"
    );
    assert_eq!(
        set(&s3, "bkt", bad(rule("none", prefix("")))).await,
        "InvalidRequest"
    );
    let glacier = Transition::builder()
        .days(30)
        .storage_class(TransitionStorageClass::Glacier)
        .build();
    assert_eq!(
        set(
            &s3,
            "bkt",
            bad(rule("cold", prefix("")).transitions(glacier))
        )
        .await,
        "InvalidStorageClass"
    );
    let same = rule("same", prefix(""))
        .expiration(days(1))
        .build()
        .unwrap();
    assert_eq!(
        set(&s3, "bkt", vec![same.clone(), same]).await,
        "InvalidArgument"
    );
    let got = s3
        .get_bucket_lifecycle_configuration()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    assert_eq!(got.rules(), rules.as_slice());
}

/// The date an `x-amz-expiration` header names, and its rule.
fn expiration(header: Option<&str>) -> Option<(String, String)> {
    let header = header?;
    let date = header.split("expiry-date=\"").nth(1)?.split('"').next()?;
    let rule = header.split("rule-id=\"").nth(1)?.split('"').next()?;
    Some((date.to_owned(), rule.to_owned()))
}

/// A drive whose bucket `bkt` expires `logs/` after two days and aborts uploads there
/// after one.
async fn logs_rule(layout: Layout) -> (common::Server, Client) {
    let (server, s3) = drive(layout, None).await;
    s3.create_bucket().bucket("bkt").send().await.unwrap();
    let rules = vec![
        rule("logs", prefix("logs/"))
            .expiration(days(2))
            .abort_incomplete_multipart_upload(
                AbortIncompleteMultipartUpload::builder()
                    .days_after_initiation(1)
                    .build(),
            )
            .build()
            .unwrap(),
    ];
    assert_eq!(set(&s3, "bkt", rules).await, "ok");
    (server, s3)
}

async fn answers_say_when_objects_expire(layout: Layout) {
    let (_server, s3) = logs_rule(layout).await;
    let put = s3
        .put_object()
        .bucket("bkt")
        .key("logs/a")
        .body(ByteStream::from_static(b"a"))
        .send()
        .await
        .unwrap();
    let (date, rule_id) = expiration(put.expiration()).unwrap();
    assert_eq!(rule_id, "logs");
    // Two days on, at midnight UTC.
    let expected = time::OffsetDateTime::now_utc()
        .date()
        .next_day()
        .unwrap()
        .next_day()
        .unwrap()
        .next_day()
        .unwrap();
    let parsed = time::PrimitiveDateTime::parse(
        &date,
        time::macros::format_description!(
            "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
        ),
    )
    .unwrap();
    assert_eq!(
        (parsed.date(), parsed.time()),
        (expected, time::Time::MIDNIGHT)
    );
    let head = s3
        .head_object()
        .bucket("bkt")
        .key("logs/a")
        .send()
        .await
        .unwrap();
    assert_eq!(
        expiration(head.expiration()),
        Some((date.clone(), "logs".into()))
    );
    let get = s3
        .get_object()
        .bucket("bkt")
        .key("logs/a")
        .send()
        .await
        .unwrap();
    assert_eq!(
        expiration(get.expiration()),
        Some((date.clone(), "logs".into()))
    );
    let copy = s3
        .copy_object()
        .bucket("bkt")
        .key("logs/b")
        .copy_source("bkt/logs/a")
        .send()
        .await
        .unwrap();
    assert!(copy.expiration().is_some());
    // Outside the rule: no header.
    let other = s3
        .put_object()
        .bucket("bkt")
        .key("keep")
        .body(ByteStream::from_static(b"k"))
        .send()
        .await
        .unwrap();
    assert_eq!(other.expiration(), None);
}

async fn uploads_say_when_they_are_aborted(layout: Layout) {
    let (_server, s3) = logs_rule(layout).await;
    let upload = s3
        .create_multipart_upload()
        .bucket("bkt")
        .key("logs/big")
        .send()
        .await
        .unwrap();
    assert_eq!(upload.abort_rule_id(), Some("logs"));
    let abort = upload.abort_date().unwrap();
    let parts = s3
        .list_parts()
        .bucket("bkt")
        .key("logs/big")
        .upload_id(upload.upload_id().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(parts.abort_date(), Some(abort));
    assert_eq!(parts.abort_rule_id(), Some("logs"));
    assert_eq!(abort.secs() % 86_400, 0);
    let elsewhere = s3
        .create_multipart_upload()
        .bucket("bkt")
        .key("big")
        .send()
        .await
        .unwrap();
    assert_eq!(elsewhere.abort_date(), None);
}

async fn the_server_applies_the_rules(layout: Layout) {
    let (_server, s3) = drive(layout, Some(Duration::from_millis(300))).await;
    s3.create_bucket().bucket("bkt").send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("bkt")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let rules = vec![
        rule("tmp", prefix("tmp/"))
            .expiration(days(1))
            .noncurrent_version_expiration(
                NoncurrentVersionExpiration::builder()
                    .noncurrent_days(1)
                    .build(),
            )
            .build()
            .unwrap(),
    ];
    assert_eq!(set(&s3, "bkt", rules).await, "ok");
    for key in ["tmp/a", "keep"] {
        s3.put_object()
            .bucket("bkt")
            .key(key)
            .body(ByteStream::from_static(b"x"))
            .send()
            .await
            .unwrap();
    }
    // A marker, then the version behind it, then the marker left alone.
    let mut left = usize::MAX;
    for _ in 0..100 {
        let listed = s3
            .list_object_versions()
            .bucket("bkt")
            .prefix("tmp/")
            .send()
            .await
            .unwrap();
        left = listed.versions().len() + listed.delete_markers().len();
        if left == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(left, 0);
    s3.head_object()
        .bucket("bkt")
        .key("keep")
        .send()
        .await
        .unwrap();
}
