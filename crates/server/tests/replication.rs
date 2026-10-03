//! Bucket replication's configuration, through the AWS SDK for Rust: kept and answered
//! as given, checked as S3 checks it, holding versioning on, and carried by admin
//! exports and imports.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,
    types::{
        AccessControlTranslation, BucketVersioningStatus, DeleteMarkerReplication,
        DeleteMarkerReplicationStatus, Destination, EncryptionConfiguration,
        ExistingObjectReplication, ExistingObjectReplicationStatus, Metrics, MetricsStatus,
        OwnerOverride, ReplicationConfiguration, ReplicationRule, ReplicationRuleAndOperator,
        ReplicationRuleFilter, ReplicationRuleStatus, ReplicationTime, ReplicationTimeStatus,
        ReplicationTimeValue, SourceSelectionCriteria, SseKmsEncryptedObjects,
        SseKmsEncryptedObjectsStatus, StorageClass, Tag, VersioningConfiguration,
    },
};
use common::{ACCESS_KEY, SECRET_KEY, client, start};
use teifs_types::admin::{ADMIN_BUCKETS, BucketsExport, BucketsImportReport};

const ROLE: &str = "arn:aws:iam::123456789012:role/replication";

async fn versioned(s3: &Client, bucket: &str, status: BucketVersioningStatus) {
    s3.put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(VersioningConfiguration::builder().status(status).build())
        .send()
        .await
        .unwrap();
}

/// A source and a destination bucket, both keeping versions.
async fn buckets(s3: &Client) {
    for bucket in ["source", "copy"] {
        s3.create_bucket().bucket(bucket).send().await.unwrap();
        versioned(s3, bucket, BucketVersioningStatus::Enabled).await;
    }
}

fn to(bucket: &str) -> Destination {
    Destination::builder()
        .bucket(format!("arn:aws:s3:::{bucket}"))
        .build()
        .unwrap()
}

/// A rule of the configuration's later version: every object to `copy`.
fn rule(id: &str, priority: i32) -> aws_sdk_s3::types::builders::ReplicationRuleBuilder {
    ReplicationRule::builder()
        .id(id)
        .priority(priority)
        .status(ReplicationRuleStatus::Enabled)
        .filter(ReplicationRuleFilter::builder().build())
        .delete_marker_replication(
            DeleteMarkerReplication::builder()
                .status(DeleteMarkerReplicationStatus::Disabled)
                .build(),
        )
        .destination(to("copy"))
}

fn config(rules: Vec<ReplicationRule>) -> ReplicationConfiguration {
    ReplicationConfiguration::builder()
        .role(ROLE)
        .set_rules(Some(rules))
        .build()
        .unwrap()
}

/// Puts `config` on `source`, answering the error's code and message.
async fn put(s3: &Client, config: ReplicationConfiguration) -> Result<(), (String, String)> {
    s3.put_bucket_replication()
        .bucket("source")
        .replication_configuration(config)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| {
            let e = e.into_service_error();
            (
                e.code().unwrap_or_default().to_owned(),
                e.message().unwrap_or_default().to_owned(),
            )
        })
}

fn refused(result: Result<(), (String, String)>) -> (String, String) {
    result.unwrap_err()
}

fn request(message: &str) -> (String, String) {
    ("InvalidRequest".to_owned(), message.to_owned())
}

fn argument(message: &str) -> (String, String) {
    ("InvalidArgument".to_owned(), message.to_owned())
}

fn malformed((code, message): (String, String)) {
    assert_eq!(code, "MalformedXML", "{message}");
}

#[tokio::test]
async fn configurations_are_kept_and_answered_as_given() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    buckets(&s3).await;
    let missing = s3
        .get_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(
        missing.code(),
        Some("ReplicationConfigurationNotFoundError")
    );
    assert_eq!(
        missing.message(),
        Some("The replication configuration was not found")
    );

    let tag = |key: &str, value: &str| Tag::builder().key(key).value(value).build().unwrap();
    let given = config(vec![
        rule("docs", 2)
            .filter(
                ReplicationRuleFilter::builder()
                    .and(
                        ReplicationRuleAndOperator::builder()
                            .prefix("docs/")
                            .tags(tag("team", "red"))
                            .tags(tag("kind", "report"))
                            .build(),
                    )
                    .build(),
            )
            .existing_object_replication(
                ExistingObjectReplication::builder()
                    .status(ExistingObjectReplicationStatus::Enabled)
                    .build()
                    .unwrap(),
            )
            .source_selection_criteria(
                SourceSelectionCriteria::builder()
                    .sse_kms_encrypted_objects(
                        SseKmsEncryptedObjects::builder()
                            .status(SseKmsEncryptedObjectsStatus::Enabled)
                            .build()
                            .unwrap(),
                    )
                    .build(),
            )
            .destination(
                Destination::builder()
                    .bucket("arn:aws:s3:::copy")
                    .account("123456789012")
                    .storage_class(StorageClass::StandardIa)
                    .access_control_translation(
                        AccessControlTranslation::builder()
                            .owner(OwnerOverride::Destination)
                            .build()
                            .unwrap(),
                    )
                    .encryption_configuration(
                        EncryptionConfiguration::builder()
                            .replica_kms_key_id("teifs-default")
                            .build(),
                    )
                    .replication_time(
                        ReplicationTime::builder()
                            .status(ReplicationTimeStatus::Enabled)
                            .time(ReplicationTimeValue::builder().minutes(15).build())
                            .build()
                            .unwrap(),
                    )
                    .metrics(
                        Metrics::builder()
                            .status(MetricsStatus::Enabled)
                            .event_threshold(ReplicationTimeValue::builder().minutes(15).build())
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap(),
        rule("everything", 1).build().unwrap(),
    ]);
    put(&s3, given.clone()).await.unwrap();
    let answer = s3
        .get_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap();
    assert_eq!(answer.replication_configuration, Some(given));
}

#[tokio::test]
async fn rules_without_ids_get_one_and_the_first_version_is_kept() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    buckets(&s3).await;
    // A rule without an id gets one.
    let mut unnamed = rule("", 1).build().unwrap();
    unnamed.id = None;
    put(&s3, config(vec![unnamed])).await.unwrap();
    let answer = s3
        .get_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap();
    let rules = answer.replication_configuration.unwrap().rules;
    assert!(rules[0].id.as_ref().is_some_and(|id| !id.is_empty()));

    // The first version: a prefix beside the rule, no priority.
    #[allow(
        deprecated,
        reason = "the configuration's first version is what's tested"
    )]
    let v1 = ReplicationRule::builder()
        .id("v1")
        .prefix("logs/")
        .status(ReplicationRuleStatus::Disabled)
        .destination(to("copy"))
        .build()
        .unwrap();
    put(&s3, config(vec![v1.clone()])).await.unwrap();
    let answer = s3
        .get_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap();
    assert_eq!(answer.replication_configuration.unwrap().rules, [v1]);

    s3.delete_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap();
    let gone = s3
        .get_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(gone.code(), Some("ReplicationConfigurationNotFoundError"));
}

#[tokio::test]
async fn destinations_are_checked_as_s3_checks_them() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    buckets(&s3).await;
    for bucket in ["unversioned", "suspended"] {
        s3.create_bucket().bucket(bucket).send().await.unwrap();
    }
    versioned(&s3, "suspended", BucketVersioningStatus::Suspended).await;

    // Where objects go.
    for (bucket, message) in [
        ("missing", "Destination bucket must exist."),
        (
            "unversioned",
            "Destination bucket must have versioning enabled.",
        ),
        (
            "suspended",
            "Destination bucket must have versioning enabled.",
        ),
        (
            "source",
            "Destination bucket cannot be the same as the source bucket.",
        ),
    ] {
        let given = config(vec![rule("r", 1).destination(to(bucket)).build().unwrap()]);
        assert_eq!(refused(put(&s3, given).await), request(message), "{bucket}");
    }
    let bad_arn = Destination::builder().bucket("copy").build().unwrap();
    let given = config(vec![rule("r", 1).destination(bad_arn).build().unwrap()]);
    assert_eq!(refused(put(&s3, given).await), argument("Invalid ARN"));
    let remote = Destination::builder()
        .bucket("arn:minio:replication::f00d:copy")
        .build()
        .unwrap();
    let given = config(vec![rule("r", 1).destination(remote).build().unwrap()]);
    assert_eq!(refused(put(&s3, given).await).0, "InvalidRequest");
}

#[tokio::test]
async fn rules_are_checked_as_s3_checks_them() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    buckets(&s3).await;
    let given = config(vec![
        rule("a", 1).build().unwrap(),
        rule("a", 2).build().unwrap(),
    ]);
    assert_eq!(
        refused(put(&s3, given).await),
        argument("Rule Id must be unique")
    );
    let given = config(vec![
        rule("a", 1).build().unwrap(),
        rule("b", 1).build().unwrap(),
    ]);
    assert_eq!(
        refused(put(&s3, given).await),
        request("Found duplicate priority. Rule priorities must be unique")
    );
    let long = "x".repeat(256);
    let given = config(vec![rule(&long, 1).build().unwrap()]);
    assert_eq!(
        refused(put(&s3, given).await),
        argument("ID length should not exceed allowed limit of 255")
    );
    let tagged = ReplicationRuleFilter::builder()
        .tag(Tag::builder().key("k").value("v").build().unwrap())
        .build();
    let markers = DeleteMarkerReplication::builder()
        .status(DeleteMarkerReplicationStatus::Enabled)
        .build();
    let given = config(vec![
        rule("r", 1)
            .filter(tagged)
            .delete_marker_replication(markers)
            .build()
            .unwrap(),
    ]);
    assert_eq!(refused(put(&s3, given).await).0, "InvalidRequest");
    // A rule with a filter needs a priority and says whether delete markers go; the
    // two versions don't mix.
    let mut no_priority = rule("r", 1).build().unwrap();
    no_priority.priority = None;
    malformed(refused(put(&s3, config(vec![no_priority])).await));
    let mut no_markers = rule("r", 1).build().unwrap();
    no_markers.delete_marker_replication = None;
    malformed(refused(put(&s3, config(vec![no_markers])).await));
    #[allow(
        deprecated,
        reason = "the configuration's first version is what's tested"
    )]
    let v1 = ReplicationRule::builder()
        .id("v1")
        .prefix("a/")
        .status(ReplicationRuleStatus::Enabled)
        .destination(to("copy"))
        .build()
        .unwrap();
    malformed(refused(
        put(&s3, config(vec![v1, rule("v2", 1).build().unwrap()])).await,
    ));
}

#[tokio::test]
async fn time_control_and_kms_need_what_s3_needs() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    buckets(&s3).await;
    // Replication Time Control: 15 minutes, with metrics.
    let rtc = |minutes: i32, metrics: bool| {
        let mut destination = Destination::builder()
            .bucket("arn:aws:s3:::copy")
            .replication_time(
                ReplicationTime::builder()
                    .status(ReplicationTimeStatus::Enabled)
                    .time(ReplicationTimeValue::builder().minutes(minutes).build())
                    .build()
                    .unwrap(),
            );
        if metrics {
            destination = destination.metrics(
                Metrics::builder()
                    .status(MetricsStatus::Enabled)
                    .event_threshold(ReplicationTimeValue::builder().minutes(15).build())
                    .build()
                    .unwrap(),
            );
        }
        config(vec![
            rule("r", 1)
                .destination(destination.build().unwrap())
                .build()
                .unwrap(),
        ])
    };
    assert_eq!(refused(put(&s3, rtc(10, true)).await).0, "InvalidArgument");
    assert_eq!(refused(put(&s3, rtc(15, false)).await).0, "InvalidRequest");
    put(&s3, rtc(15, true)).await.unwrap();
    // SSE-KMS objects go only with a key for the replicas.
    let kms = SourceSelectionCriteria::builder()
        .sse_kms_encrypted_objects(
            SseKmsEncryptedObjects::builder()
                .status(SseKmsEncryptedObjectsStatus::Enabled)
                .build()
                .unwrap(),
        )
        .build();
    let given = config(vec![
        rule("r", 1).source_selection_criteria(kms).build().unwrap(),
    ]);
    assert_eq!(
        refused(put(&s3, given).await),
        request("ReplicaKmsKeyID must be specified if SseKmsEncryptedObjects tag is present.")
    );

    // The source keeps every version.
    s3.delete_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap();
    versioned(&s3, "source", BucketVersioningStatus::Suspended).await;
    let given = config(vec![rule("r", 1).build().unwrap()]);
    assert_eq!(
        refused(put(&s3, given).await),
        request("Versioning must be 'Enabled' on the bucket to apply a replication configuration")
    );
}

#[tokio::test]
async fn versioning_stays_on_while_a_bucket_replicates() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    buckets(&s3).await;
    put(&s3, config(vec![rule("r", 1).build().unwrap()]))
        .await
        .unwrap();
    let refused = s3
        .put_bucket_versioning()
        .bucket("source")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Suspended)
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(refused.raw_response().unwrap().status().as_u16(), 409);
    assert_eq!(
        refused.into_service_error().code(),
        Some("InvalidBucketState")
    );
    // Enabling it again changes nothing, and is fine.
    versioned(&s3, "source", BucketVersioningStatus::Enabled).await;
    s3.delete_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap();
    versioned(&s3, "source", BucketVersioningStatus::Suspended).await;
}

#[tokio::test]
async fn exports_carry_replication_to_another_server() {
    let from = start().await;
    let s3 = client(&from, SECRET_KEY);
    buckets(&s3).await;
    let given = config(vec![rule("r", 1).build().unwrap()]);
    put(&s3, given.clone()).await.unwrap();
    let root = (ACCESS_KEY, SECRET_KEY);
    let (status, export) = signing::signed(&from, root, "GET", ADMIN_BUCKETS, &[], b"").await;
    assert_eq!(status, 200, "{export}");
    let export: BucketsExport = serde_json::from_str(&export).unwrap();

    // `copy` comes after `source` in the export: replication waits for every bucket.
    let to = start().await;
    let body = serde_json::to_vec(&export).unwrap();
    let (status, answer) = signing::signed(&to, root, "PUT", ADMIN_BUCKETS, &[], &body).await;
    assert_eq!(status, 200, "{answer}");
    let report: BucketsImportReport = serde_json::from_str(&answer).unwrap();
    assert!(
        report
            .items
            .iter()
            .any(|i| i.item == "replication" && i.outcome == "applied"),
        "{answer}"
    );
    let answer = client(&to, SECRET_KEY)
        .get_bucket_replication()
        .bucket("source")
        .send()
        .await
        .unwrap();
    assert_eq!(answer.replication_configuration, Some(given));
}
