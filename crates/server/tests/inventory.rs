//! Inventory reports as S3 Inventory delivers them: gzipped CSV data files, a Hive
//! symlink, and a manifest with its checksum, written by `s3.amazonaws.com` into a
//! destination whose policy lets it in.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{io::Read, time::Duration};

use aws_sdk_s3::{
    Client,
    primitives::ByteStream,
    types::{
        BucketVersioningStatus, InventoryConfiguration, InventoryDestination, InventoryEncryption,
        InventoryFilter, InventoryFormat, InventoryFrequency, InventoryIncludedObjectVersions,
        InventoryOptionalField, InventoryS3BucketDestination, InventorySchedule, Sses3,
        VersioningConfiguration,
    },
};
use md5::{Digest, Md5};

mod common;

use common::{SECRET_KEY, Server, client, start_with};

/// A policy on `target` letting S3 Inventory write reports of `source`, as AWS's
/// documentation writes it.
fn inventory_policy(target: &str, source: &str, account: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",
        "Principal":{{"Service":"s3.amazonaws.com"}},"Action":"s3:PutObject",
        "Resource":"arn:aws:s3:::{target}/*",
        "Condition":{{"ArnLike":{{"aws:SourceArn":"arn:aws:s3:::{source}"}},
        "StringEquals":{{"aws:SourceAccount":"{account}",
        "s3:x-amz-acl":"bucket-owner-full-control"}}}}}}]}}"#
    )
}

fn config(
    id: &str,
    target: &str,
    versions: InventoryIncludedObjectVersions,
    frequency: InventoryFrequency,
) -> InventoryConfiguration {
    InventoryConfiguration::builder()
        .id(id)
        .is_enabled(true)
        .filter(InventoryFilter::builder().prefix("docs/").build().unwrap())
        .destination(
            InventoryDestination::builder()
                .s3_bucket_destination(
                    InventoryS3BucketDestination::builder()
                        .bucket(format!("arn:aws:s3:::{target}"))
                        .format(InventoryFormat::Csv)
                        .prefix("inventory")
                        .encryption(
                            InventoryEncryption::builder()
                                .sses3(Sses3::builder().build())
                                .build(),
                        )
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .included_object_versions(versions)
        .optional_fields(InventoryOptionalField::ETag)
        .optional_fields(InventoryOptionalField::Size)
        .schedule(
            InventorySchedule::builder()
                .frequency(frequency)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

async fn configure(root: &Client, config: InventoryConfiguration) {
    root.put_bucket_inventory_configuration()
        .bucket("data")
        .id(config.id())
        .inventory_configuration(config)
        .send()
        .await
        .unwrap();
}

/// A server whose days last `day`, with object buckets `data` (versioned, holding
/// `docs/a`, a deleted `docs/b` and `other/c`) and `reports`, open to S3 Inventory.
async fn setup(day: Duration) -> (Server, Client) {
    let server = start_with(|config| {
        config.lifecycle_day = Some(day);
        config.default_layout = teifs_store::Layout::Object;
    })
    .await;
    let root = client(&server, SECRET_KEY);
    for bucket in ["data", "reports", "closed"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    root.put_bucket_versioning()
        .bucket("data")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    for key in ["docs/a b", "docs/b", "other/c"] {
        root.put_object()
            .bucket("data")
            .key(key)
            .body(ByteStream::from_static(b"hello"))
            .send()
            .await
            .unwrap();
    }
    root.delete_object()
        .bucket("data")
        .key("docs/b")
        .send()
        .await
        .unwrap();
    let policy = inventory_policy("reports", "data", &server.iam.account());
    root.put_bucket_policy()
        .bucket("reports")
        .policy(policy)
        .send()
        .await
        .unwrap();
    (server, root)
}

async fn keys(root: &Client, bucket: &str, prefix: &str) -> Vec<String> {
    root.list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .send()
        .await
        .unwrap()
        .contents()
        .iter()
        .filter_map(|object| object.key().map(str::to_owned))
        .collect()
}

async fn read(root: &Client, bucket: &str, key: &str) -> Vec<u8> {
    let object = root
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap();
    object.body.collect().await.unwrap().into_bytes().to_vec()
}

/// The keys under `prefix` that end so, once there are `at_least`.
async fn wait_for(root: &Client, prefix: &str, suffix: &str, at_least: usize) -> Vec<String> {
    for _ in 0..200 {
        let found: Vec<String> = keys(root, "reports", prefix)
            .await
            .into_iter()
            .filter(|key| key.ends_with(suffix))
            .collect();
        if found.len() >= at_least {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no {suffix} under {prefix}");
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

fn gunzip(data: &[u8]) -> String {
    let mut text = String::new();
    flate2::read::GzDecoder::new(data)
        .read_to_string(&mut text)
        .unwrap();
    text
}

#[tokio::test]
async fn a_report_is_delivered_as_s3_writes_it() {
    // A minute-long day: the first report at once, the next in another minute.
    let (_server, root) = setup(Duration::from_secs(60)).await;
    configure(
        &root,
        config(
            "all",
            "reports",
            InventoryIncludedObjectVersions::All,
            InventoryFrequency::Daily,
        ),
    )
    .await;
    let checksum = wait_for(&root, "inventory/data/all/", "/manifest.checksum", 1).await;
    let folder = checksum[0].strip_suffix("manifest.checksum").unwrap();
    let manifest = read(&root, "reports", &format!("{folder}manifest.json")).await;
    let md5 = hex(&Md5::digest(&manifest));
    assert_eq!(read(&root, "reports", &checksum[0]).await, md5.as_bytes());

    let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(manifest["sourceBucket"], "data");
    assert_eq!(manifest["destinationBucket"], "arn:aws:s3:::reports");
    assert_eq!(manifest["version"], "2016-11-30");
    assert_eq!(manifest["fileFormat"], "CSV");
    assert_eq!(
        manifest["fileSchema"],
        "Bucket, Key, VersionId, IsLatest, IsDeleteMarker, Size, ETag"
    );
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    let key = files[0]["key"].as_str().unwrap();
    assert!(
        key.starts_with("inventory/data/all/data/") && key.ends_with(".csv.gz"),
        "{key}"
    );
    let data = read(&root, "reports", key).await;
    assert_eq!(files[0]["size"], data.len());
    let md5 = hex(&Md5::digest(&data));
    assert_eq!(files[0]["MD5checksum"], md5);
    let head = root
        .head_object()
        .bucket("reports")
        .key(key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.server_side_encryption()
            .map(aws_sdk_s3::types::ServerSideEncryption::as_str),
        Some("AES256")
    );

    // Every version under the prefix, the delete marker's without size or ETag.
    let rows = gunzip(&data);
    let rows: Vec<Vec<&str>> = rows
        .lines()
        .map(|line| line.split(',').map(|v| v.trim_matches('"')).collect())
        .collect();
    let etag = "5d41402abc4b2a76b9719d911017c592";
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(
        [&rows[0][..2], &rows[0][3..]].concat(),
        ["data", "docs/a%20b", "true", "false", "5", etag]
    );
    assert_eq!(
        [&rows[1][..2], &rows[1][3..]].concat(),
        ["data", "docs/b", "true", "true", "", ""]
    );
    assert_eq!(
        [&rows[2][..2], &rows[2][3..]].concat(),
        ["data", "docs/b", "false", "false", "5", etag]
    );
    assert!(rows.iter().all(|row| !row[2].is_empty()), "version ids");

    // The Hive symlink lists the data files.
    let symlink = wait_for(&root, "inventory/data/all/hive/dt=", "/symlink.txt", 1).await;
    let symlink = String::from_utf8(read(&root, "reports", &symlink[0]).await).unwrap();
    assert_eq!(symlink, format!("s3://reports/{key}\n"));
}

#[tokio::test]
async fn a_destination_that_doesnt_let_s3_in_gets_nothing() {
    // A day of a second: a report every second.
    let (_server, root) = setup(Duration::from_secs(1)).await;
    for (id, target) in [("a-closed", "closed"), ("b-open", "reports")] {
        let config = config(
            id,
            target,
            InventoryIncludedObjectVersions::Current,
            InventoryFrequency::Daily,
        );
        configure(&root, config).await;
    }
    // Two reports to the open destination: the closed one was tried as often.
    let data = wait_for(&root, "inventory/data/b-open/data/", ".csv.gz", 2).await;
    assert!(keys(&root, "closed", "").await.is_empty());
    // Only current objects, with the fields asked for.
    let rows = gunzip(&read(&root, "reports", &data[0]).await);
    assert_eq!(
        rows,
        "\"data\",\"docs/a%20b\",\"5\",\"5d41402abc4b2a76b9719d911017c592\"\n"
    );
}

#[tokio::test]
async fn a_restart_neither_repeats_nor_skips_a_report() {
    let day = Duration::from_secs(60);
    let (dir, keyring) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let run = || {
        let mut config = common::config(dir.path(), keyring.path());
        config.lifecycle_day = Some(day);
        config.default_layout = teifs_store::Layout::Object;
        async move {
            let server = teifs_server::Server::bind(config).await.unwrap();
            let endpoint = format!("http://{}", server.local_addr().unwrap());
            let account = server.iam().account();
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let running = tokio::spawn(server.run(async {
                let _ = stopped.await;
            }));
            (endpoint, account, stop, running)
        }
    };
    // Weeks of seven such days begin on "Sundays": stay clear of the next.
    let week = 7 * day.as_millis();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let into_week = (now + 4 * day.as_millis()) % week;
    if week - into_week < 10_000 {
        tokio::time::sleep(Duration::from_millis(
            u64::try_from(week - into_week).unwrap() + 100,
        ))
        .await;
    }

    let (endpoint, account, stop, running) = run().await;
    let root = common::client_at(&endpoint, common::ACCESS_KEY, SECRET_KEY);
    for bucket in ["data", "reports"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    root.put_object()
        .bucket("data")
        .key("docs/a")
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await
        .unwrap();
    root.put_bucket_policy()
        .bucket("reports")
        .policy(inventory_policy("reports", "data", &account))
        .send()
        .await
        .unwrap();
    let weekly = config(
        "weekly",
        "reports",
        InventoryIncludedObjectVersions::Current,
        InventoryFrequency::Weekly,
    );
    configure(&root, weekly).await;
    wait_for(&root, "inventory/data/weekly/", "/manifest.checksum", 1).await;
    drop(stop);
    running.await.unwrap();

    // The week's report was made: the next start doesn't make it again.
    let (endpoint, _, _stop, _running) = run().await;
    let root = common::client_at(&endpoint, common::ACCESS_KEY, SECRET_KEY);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let data = keys(&root, "reports", "inventory/data/weekly/data/").await;
    assert_eq!(data.len(), 1, "{data:?}");
}
