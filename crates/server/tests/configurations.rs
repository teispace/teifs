//! Requester Pays, and the inventory, analytics, metrics and Intelligent-Tiering
//! configurations, through the AWS SDK as S3 answers them.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,
    primitives::ByteStream,
    types::{
        AnalyticsConfiguration, AnalyticsExportDestination, AnalyticsFilter,
        AnalyticsS3BucketDestination, AnalyticsS3ExportFileFormat, BucketLoggingStatus,
        IntelligentTieringAccessTier, IntelligentTieringConfiguration, IntelligentTieringFilter,
        IntelligentTieringStatus, InventoryConfiguration, InventoryDestination, InventoryFilter,
        InventoryFormat, InventoryFrequency, InventoryIncludedObjectVersions,
        InventoryOptionalField, InventoryS3BucketDestination, InventorySchedule, LoggingEnabled,
        MetricsConfiguration, MetricsFilter, Payer, RequestPaymentConfiguration,
        StorageClassAnalysis, StorageClassAnalysisDataExport, StorageClassAnalysisSchemaVersion,
        Tag, Tiering,
    },
};
use reqwest::Method;

#[macro_use]
mod common;

use common::{SECRET_KEY, Server, anonymous, client, code, start};

fn inventory(id: &str, format: InventoryFormat) -> InventoryConfiguration {
    InventoryConfiguration::builder()
        .id(id)
        .is_enabled(true)
        .filter(InventoryFilter::builder().prefix("docs/").build().unwrap())
        .destination(
            InventoryDestination::builder()
                .s3_bucket_destination(
                    InventoryS3BucketDestination::builder()
                        .bucket("arn:aws:s3:::reports")
                        .format(format)
                        .prefix("inventory")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .included_object_versions(InventoryIncludedObjectVersions::All)
        .optional_fields(InventoryOptionalField::Size)
        .optional_fields(InventoryOptionalField::ETag)
        .schedule(
            InventorySchedule::builder()
                .frequency(InventoryFrequency::Daily)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

/// The status of an unsigned copy of `source` to `reports/copied`.
async fn anonymous_copy(server: &Server, source: &str) -> u16 {
    reqwest::Client::new()
        .put(format!("{}/reports/copied", server.endpoint))
        .header("x-amz-copy-source", source)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn buckets(server: &Server) -> Client {
    let root = client(server, SECRET_KEY);
    for bucket in ["data", "reports"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    root
}

#[tokio::test]
async fn inventory_configurations_are_kept_listed_and_removed() {
    let server = start().await;
    let root = buckets(&server).await;
    let given = inventory("daily", InventoryFormat::Csv);
    root.put_bucket_inventory_configuration()
        .bucket("data")
        .id("daily")
        .inventory_configuration(given.clone())
        .send()
        .await
        .unwrap();
    let got = root
        .get_bucket_inventory_configuration()
        .bucket("data")
        .id("daily")
        .send()
        .await
        .unwrap();
    assert_eq!(got.inventory_configuration(), Some(&given));

    // The id in the URL and the body must agree; a bad field or ARN is refused.
    let other = root
        .put_bucket_inventory_configuration()
        .bucket("data")
        .id("weekly")
        .inventory_configuration(given.clone())
        .send()
        .await;
    assert_eq!(code(other), "InvalidArgument");
    let mut not_arn = inventory("bad", InventoryFormat::Csv);
    not_arn.destination = Some(
        InventoryDestination::builder()
            .s3_bucket_destination(
                InventoryS3BucketDestination::builder()
                    .bucket("reports")
                    .format(InventoryFormat::Csv)
                    .build()
                    .unwrap(),
            )
            .build(),
    );
    let refused = root
        .put_bucket_inventory_configuration()
        .bucket("data")
        .id("bad")
        .inventory_configuration(not_arn)
        .send()
        .await;
    assert_eq!(code(refused), "InvalidArgument");

    root.delete_bucket_inventory_configuration()
        .bucket("data")
        .id("daily")
        .send()
        .await
        .unwrap();
    let gone = root
        .get_bucket_inventory_configuration()
        .bucket("data")
        .id("daily")
        .send()
        .await;
    assert_eq!(code(gone), "NoSuchConfiguration");
    let again = root
        .delete_bucket_inventory_configuration()
        .bucket("data")
        .id("daily")
        .send()
        .await;
    assert_eq!(code(again), "NoSuchConfiguration");
    // Of a bucket that isn't there.
    let missing = root
        .list_bucket_inventory_configurations()
        .bucket("nothing")
        .send()
        .await;
    assert_eq!(code(missing), "NoSuchBucket");
}

#[tokio::test]
async fn listings_go_a_hundred_at_a_time() {
    let server = start().await;
    let root = buckets(&server).await;
    root.put_bucket_inventory_configuration()
        .bucket("data")
        .id("daily")
        .inventory_configuration(inventory("daily", InventoryFormat::Csv))
        .send()
        .await
        .unwrap();
    // 150 configurations list as two pages.
    for n in 0..150 {
        let id = format!("report-{n:03}");
        root.put_bucket_inventory_configuration()
            .bucket("data")
            .id(&id)
            .inventory_configuration(inventory(&id, InventoryFormat::Parquet))
            .send()
            .await
            .unwrap();
    }
    let first = root
        .list_bucket_inventory_configurations()
        .bucket("data")
        .send()
        .await
        .unwrap();
    assert_eq!(first.inventory_configuration_list().len(), 100);
    assert_eq!(first.is_truncated(), Some(true));
    let second = root
        .list_bucket_inventory_configurations()
        .bucket("data")
        .continuation_token(first.next_continuation_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(second.inventory_configuration_list().len(), 51);
    assert_eq!(second.is_truncated(), Some(false));
    assert_eq!(second.next_continuation_token(), None);
    let ids: Vec<&str> = first
        .inventory_configuration_list()
        .iter()
        .chain(second.inventory_configuration_list())
        .map(InventoryConfiguration::id)
        .collect();
    assert!(ids.contains(&"daily") && ids.contains(&"report-149"));
}

#[tokio::test]
async fn a_kind_holds_at_most_a_thousand() {
    let server = start().await;
    let root = buckets(&server).await;
    let metrics = |id: &str| MetricsConfiguration::builder().id(id).build().unwrap();
    for n in 0..1_000 {
        let id = format!("m{n}");
        root.put_bucket_metrics_configuration()
            .bucket("data")
            .id(&id)
            .metrics_configuration(metrics(&id))
            .send()
            .await
            .unwrap();
    }
    let one_more = root
        .put_bucket_metrics_configuration()
        .bucket("data")
        .id("m1000")
        .metrics_configuration(metrics("m1000"))
        .send()
        .await;
    assert_eq!(code(one_more), "TooManyConfigurations");
    // Replacing one is still allowed, and other kinds are counted on their own.
    root.put_bucket_metrics_configuration()
        .bucket("data")
        .id("m0")
        .metrics_configuration(metrics("m0"))
        .send()
        .await
        .unwrap();
    root.put_bucket_inventory_configuration()
        .bucket("data")
        .id("daily")
        .inventory_configuration(inventory("daily", InventoryFormat::Orc))
        .send()
        .await
        .unwrap();
}

/// A storage class analysis by tag, exported to `reports`.
fn analytics() -> AnalyticsConfiguration {
    let tag = Tag::builder().key("team").value("blue").build().unwrap();
    AnalyticsConfiguration::builder()
        .id("by-team")
        .filter(AnalyticsFilter::Tag(tag))
        .storage_class_analysis(
            StorageClassAnalysis::builder()
                .data_export(
                    StorageClassAnalysisDataExport::builder()
                        .output_schema_version(StorageClassAnalysisSchemaVersion::V1)
                        .destination(
                            AnalyticsExportDestination::builder()
                                .s3_bucket_destination(
                                    AnalyticsS3BucketDestination::builder()
                                        .bucket("arn:aws:s3:::reports")
                                        .format(AnalyticsS3ExportFileFormat::Csv)
                                        .prefix("analytics")
                                        .build()
                                        .unwrap(),
                                )
                                .build(),
                        )
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn analytics_metrics_and_tiering_are_answered_as_given() {
    let server = start().await;
    let root = buckets(&server).await;
    let analytics = analytics();
    root.put_bucket_analytics_configuration()
        .bucket("data")
        .id("by-team")
        .analytics_configuration(analytics.clone())
        .send()
        .await
        .unwrap();
    let got = root
        .get_bucket_analytics_configuration()
        .bucket("data")
        .id("by-team")
        .send()
        .await
        .unwrap();
    assert_eq!(got.analytics_configuration(), Some(&analytics));

    let metrics = MetricsConfiguration::builder()
        .id("docs")
        .filter(MetricsFilter::Prefix("docs/".into()))
        .build()
        .unwrap();
    root.put_bucket_metrics_configuration()
        .bucket("data")
        .id("docs")
        .metrics_configuration(metrics.clone())
        .send()
        .await
        .unwrap();
    let listed = root
        .list_bucket_metrics_configurations()
        .bucket("data")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.metrics_configuration_list(), [metrics]);

    let tiering = |days: i32| {
        IntelligentTieringConfiguration::builder()
            .id("cold")
            .status(IntelligentTieringStatus::Enabled)
            .filter(IntelligentTieringFilter::builder().prefix("cold/").build())
            .tierings(
                Tiering::builder()
                    .access_tier(IntelligentTieringAccessTier::ArchiveAccess)
                    .days(days)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    };
    root.put_bucket_intelligent_tiering_configuration()
        .bucket("data")
        .id("cold")
        .intelligent_tiering_configuration(tiering(90))
        .send()
        .await
        .unwrap();
    let got = root
        .get_bucket_intelligent_tiering_configuration()
        .bucket("data")
        .id("cold")
        .send()
        .await
        .unwrap();
    assert_eq!(got.intelligent_tiering_configuration(), Some(&tiering(90)));
    let too_soon = root
        .put_bucket_intelligent_tiering_configuration()
        .bucket("data")
        .id("cold")
        .intelligent_tiering_configuration(tiering(30))
        .send()
        .await;
    assert_eq!(code(too_soon), "InvalidArgument");
}

#[tokio::test]
async fn requester_pays_buckets_refuse_anonymous_requests() {
    let server = start().await;
    let root = buckets(&server).await;
    let payer = root
        .get_bucket_request_payment()
        .bucket("data")
        .send()
        .await
        .unwrap();
    assert_eq!(payer.payer(), Some(&Payer::BucketOwner));

    // A public bucket answers anyone…
    root.delete_public_access_block()
        .bucket("data")
        .send()
        .await
        .unwrap();
    root.put_bucket_policy()
        .bucket("data")
        .policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    root.put_object()
        .bucket("data")
        .key("open.txt")
        .body(ByteStream::from_static(b"open"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous(&server, Method::GET, "/data/open.txt").await, 200);

    // …until its requesters pay: then only signed requests are answered.
    let requester = |payer: Payer| {
        RequestPaymentConfiguration::builder()
            .payer(payer)
            .build()
            .unwrap()
    };
    root.put_bucket_request_payment()
        .bucket("data")
        .request_payment_configuration(requester(Payer::Requester))
        .send()
        .await
        .unwrap();
    let payer = root
        .get_bucket_request_payment()
        .bucket("data")
        .send()
        .await
        .unwrap();
    assert_eq!(payer.payer(), Some(&Payer::Requester));
    assert_eq!(anonymous(&server, Method::GET, "/data/open.txt").await, 403);
    root.get_object()
        .bucket("data")
        .key("open.txt")
        .request_payer(aws_sdk_s3::types::RequestPayer::Requester)
        .send()
        .await
        .unwrap();

    // It can't receive a bucket's access log.
    let logging = root
        .put_bucket_logging()
        .bucket("reports")
        .bucket_logging_status(
            BucketLoggingStatus::builder()
                .logging_enabled(
                    LoggingEnabled::builder()
                        .target_bucket("data")
                        .target_prefix("logs/")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await;
    let refused = logging.unwrap_err();
    assert_eq!(refused.code(), Some("InvalidTargetBucketForLogging"));
    assert!(
        refused.message().unwrap().contains("Requester Pays"),
        "{refused:?}"
    );

    // Nor be an anonymous copy's source, into a bucket anyone may write.
    root.delete_public_access_block()
        .bucket("reports")
        .send()
        .await
        .unwrap();
    root.put_bucket_policy()
        .bucket("reports")
        .policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::reports/*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous_copy(&server, "data/open.txt").await, 403);

    root.put_bucket_request_payment()
        .bucket("data")
        .request_payment_configuration(requester(Payer::BucketOwner))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous(&server, Method::GET, "/data/open.txt").await, 200);
    assert_eq!(anonymous_copy(&server, "data/open.txt").await, 200);
}
