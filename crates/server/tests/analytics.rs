//! Storage class analysis exports as S3 writes them: each day's figures added to a CSV
//! by `s3.amazonaws.com`, in a destination whose policy lets it in.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::Duration;

use aws_sdk_s3::{
    primitives::ByteStream,
    types::{
        AnalyticsConfiguration, AnalyticsExportDestination, AnalyticsFilter,
        AnalyticsS3BucketDestination, AnalyticsS3ExportFileFormat, StorageClassAnalysis,
        StorageClassAnalysisDataExport, StorageClassAnalysisSchemaVersion,
    },
};

mod common;

use common::{SECRET_KEY, client, start_with};

/// A policy on `target` letting S3 write exports of `source`, as AWS's documentation
/// writes it.
fn analytics_policy(target: &str, source: &str, account: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",
        "Principal":{{"Service":"s3.amazonaws.com"}},"Action":"s3:PutObject",
        "Resource":"arn:aws:s3:::{target}/*",
        "Condition":{{"ArnLike":{{"aws:SourceArn":"arn:aws:s3:::{source}"}},
        "StringEquals":{{"aws:SourceAccount":"{account}",
        "s3:x-amz-acl":"bucket-owner-full-control"}}}}}}]}}"#
    )
}

fn exported(id: &str, target: &str) -> AnalyticsConfiguration {
    let destination = AnalyticsS3BucketDestination::builder()
        .format(AnalyticsS3ExportFileFormat::Csv)
        .bucket(format!("arn:aws:s3:::{target}"))
        .prefix("analytics")
        .build()
        .unwrap();
    AnalyticsConfiguration::builder()
        .id(id)
        .filter(AnalyticsFilter::Prefix("docs/".to_owned()))
        .storage_class_analysis(
            StorageClassAnalysis::builder()
                .data_export(
                    StorageClassAnalysisDataExport::builder()
                        .output_schema_version(StorageClassAnalysisSchemaVersion::V1)
                        .destination(
                            AnalyticsExportDestination::builder()
                                .s3_bucket_destination(destination)
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
async fn each_days_figures_are_added_to_the_export() {
    let server = start_with(|config| {
        config.lifecycle_day = Some(Duration::from_millis(1500));
    })
    .await;
    let s3 = client(&server, SECRET_KEY);
    for bucket in ["data", "exports", "refusing"] {
        s3.create_bucket().bucket(bucket).send().await.unwrap();
    }
    let policy = analytics_policy("exports", "data", &server.iam.account());
    s3.put_bucket_policy()
        .bucket("exports")
        .policy(policy)
        .send()
        .await
        .unwrap();
    for (id, target) in [("docs", "exports"), ("refused", "refusing")] {
        s3.put_bucket_analytics_configuration()
            .bucket("data")
            .id(id)
            .analytics_configuration(exported(id, target))
            .send()
            .await
            .unwrap();
    }
    s3.put_object()
        .bucket("data")
        .key("docs/a")
        .body(ByteStream::from(vec![7; 200 * 1024]))
        .send()
        .await
        .unwrap();
    let got = s3
        .get_object()
        .bucket("data")
        .key("docs/a")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.body.collect().await.unwrap().into_bytes().len(),
        200 * 1024
    );

    // The day the requests were counted on is exported once it's over.
    let counted = |text: &str| {
        text.lines()
            .filter(|line| line.split(',').nth(4) == Some("ALL"))
            .map(|line| line.split(',').nth(9).unwrap().parse::<u64>().unwrap())
            .sum::<u64>()
    };
    let mut text = String::new();
    for _ in 0..200 {
        if let Ok(object) = s3
            .get_object()
            .bucket("exports")
            .key("analytics/data/docs.csv")
            .send()
            .await
        {
            assert_eq!(object.content_type(), Some("text/csv"));
            let body = object.body.collect().await.unwrap().into_bytes();
            text = String::from_utf8(body.to_vec()).unwrap();
            if counted(&text) >= 2 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(counted(&text), 2, "{text}");
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some(
            "Date,ConfigId,Filter,StorageClass,ObjectAge,ObjectCount,DataUploaded_MB,Storage_MB,\
             DataRetrieved_MB,GetRequestCount,CumulativeAccessRatio,ObjectAgeForSIATransition,\
             RecommendedObjectAgeForSIATransition"
        )
    );
    // The day's rows, unless the requests straddled two of the test's short days.
    let busy: Vec<&str> = text
        .lines()
        .filter(|line| line.contains(",ALL,") && !line.contains(",0,0,,"))
        .collect();
    if busy.len() == 1 {
        assert!(
            text.lines()
                .any(|line| line.ends_with(",docs,,STANDARD,000-014,,,0.195312,0.195312,2,1,,")),
            "{text}"
        );
        // One object, uploaded and retrieved once that day.
        assert!(
            busy[0].ends_with(",docs,,STANDARD,ALL,1,0.195312,0.195312,0.195312,2,1,,"),
            "{text}"
        );
    }
    // A destination that doesn't let S3 in gets nothing.
    let refused = s3
        .list_objects_v2()
        .bucket("refusing")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.key_count(), Some(0));
}
