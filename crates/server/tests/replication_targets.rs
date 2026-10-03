//! Replication targets through `MinIO`'s admin API, as madmin-go (and so `mc replicate`)
//! calls it: added with the secret key encrypted, answered without it, named by
//! replication rules, and kept while a rule names them.

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
        BucketVersioningStatus, DeleteMarkerReplication, DeleteMarkerReplicationStatus,
        Destination, ReplicationConfiguration, ReplicationRule, ReplicationRuleFilter,
        ReplicationRuleStatus, VersioningConfiguration,
    },
};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start};
use serde_json::{Value, json};
use signing::{signed, signed_response};
use teifs_crypto::madmin;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);
const ADMIN: &str = "/minio/admin/v3/";
const TARGET_SECRET: &str = "dummy-target-secret-0001";

/// A target as madmin-go's `SetRemoteTarget` sends it for `mc replicate add`.
fn target(bucket: &str, target_bucket: &str) -> Value {
    json!({
        "sourcebucket": bucket,
        "endpoint": "backup.example.com:9000",
        "credentials": {"accessKey": "replicator", "secretKey": TARGET_SECRET},
        "targetbucket": target_bucket,
        "secure": true,
        "type": "replication",
        "region": "us-east-1",
        "replicationSync": false,
        "healthCheckDuration": 60_000_000_000_i64,
        "disableProxy": false,
        "insecureTLS": false,
    })
}

/// Sets a target with the body encrypted for `key`, answering the status and the answer.
async fn set(server: &Server, key: (&str, &str), query: &str, body: &Value) -> (u16, Value) {
    let body = madmin::encrypt(key.1, body.to_string().as_bytes());
    let response = signed_response(
        server,
        key,
        "PUT",
        &format!("{ADMIN}set-remote-target?{query}"),
        &[],
        &body,
    )
    .await;
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

async fn call(server: &Server, method: &str, path: &str) -> (u16, String) {
    signed(server, ROOT, method, &format!("{ADMIN}{path}"), &[], b"").await
}

async fn versioned(s3: &Client, bucket: &str) {
    s3.create_bucket().bucket(bucket).send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
}

/// Puts a rule replicating every object of `bucket` to `arn`.
async fn replicate(s3: &Client, bucket: &str, arn: &str) -> Result<(), String> {
    let rule = ReplicationRule::builder()
        .id("r")
        .priority(1)
        .status(ReplicationRuleStatus::Enabled)
        .filter(ReplicationRuleFilter::builder().build())
        .delete_marker_replication(
            DeleteMarkerReplication::builder()
                .status(DeleteMarkerReplicationStatus::Disabled)
                .build(),
        )
        .destination(Destination::builder().bucket(arn).build().unwrap())
        .build()
        .unwrap();
    s3.put_bucket_replication()
        .bucket(bucket)
        .replication_configuration(
            ReplicationConfiguration::builder()
                .role("")
                .rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .map(|_| ())
        .map_err(|e| {
            e.into_service_error()
                .message()
                .unwrap_or_default()
                .to_owned()
        })
}

#[tokio::test]
async fn targets_are_added_listed_named_by_rules_and_removed() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    versioned(&s3, "photos").await;
    versioned(&s3, "music").await;

    let (status, arn) = set(&server, ROOT, "bucket=photos", &target("photos", "copy")).await;
    assert_eq!(status, 200, "{arn}");
    let arn = arn.as_str().unwrap().to_owned();
    assert!(arn.starts_with("arn:minio:replication:us-east-1:"), "{arn}");
    assert!(arn.ends_with(":copy"), "{arn}");
    // The same place again is the same target.
    let (_, again) = set(&server, ROOT, "bucket=photos", &target("photos", "copy")).await;
    assert_eq!(again, json!(arn));

    // Listed as `MinIO` lists them, never with the secret key.
    let (status, text) = call(
        &server,
        "GET",
        "list-remote-targets?bucket=photos&type=replication",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(!text.contains(TARGET_SECRET), "{text}");
    let listed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["arn"], json!(arn));
    assert_eq!(listed[0]["targetbucket"], "copy");
    assert_eq!(listed[0]["credentials"]["accessKey"], "replicator");
    assert_eq!(listed[0]["healthCheckDuration"], 60_000_000_000_i64);
    let (_, other) = call(&server, "GET", "list-remote-targets?bucket=music").await;
    assert_eq!(other, "[]");

    // Rules may name the bucket's own targets, not another bucket's.
    replicate(&s3, "photos", &arn).await.unwrap();
    let refused = replicate(&s3, "music", &arn).await.unwrap_err();
    assert!(refused.contains("isn't a replication target"), "{refused}");

    // Kept while a rule names it.
    let remove = format!("remove-remote-target?bucket=photos&arn={arn}");
    let (status, text) = call(&server, "DELETE", &remove).await;
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("XMinioAdminRemoteRemoveDisallowed"), "{text}");
    s3.delete_bucket_replication()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(call(&server, "DELETE", &remove).await.0, 204);
    let (status, text) = call(&server, "DELETE", &remove).await;
    assert_eq!(status, 404, "{text}");
    assert!(
        text.contains("XMinioAdminRemoteTargetNotFoundError"),
        "{text}"
    );
}

#[tokio::test]
async fn edits_change_the_target_the_arn_names() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    versioned(&s3, "photos").await;
    let (_, arn) = set(&server, ROOT, "bucket=photos", &target("photos", "copy")).await;

    // `UpdateRemoteTarget` sends the target back with what changes, without secrets.
    let mut edit = target("photos", "copy");
    edit["arn"] = arn.clone();
    edit["replicationSync"] = json!(true);
    edit["credentials"] = json!({"accessKey": "replicator"});
    let (status, answer) = set(&server, ROOT, "bucket=photos&update=true&sync=true", &edit).await;
    assert_eq!((status, &answer), (200, &arn));
    let (_, text) = call(&server, "GET", "list-remote-targets?bucket=photos").await;
    let listed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(listed[0]["replicationSync"], true);

    // New credentials need the secret; an unknown ARN isn't there.
    let (status, _) = set(&server, ROOT, "bucket=photos&update=true&creds=true", &edit).await;
    assert_eq!(status, 400);
    edit["arn"] = json!("arn:minio:replication::unknown:copy");
    let (status, answer) = set(&server, ROOT, "bucket=photos&update=true", &edit).await;
    assert_eq!(status, 404, "{answer}");
}

#[tokio::test]
async fn targets_need_their_admin_actions() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    versioned(&s3, "photos").await;
    // Everything on S3, nothing on the admin API.
    server.iam.create_user("worker", None, &[], None).unwrap();
    server
        .iam
        .put_inline(
            teifs_iam::Owner::User("worker"),
            "policy",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
        )
        .unwrap();
    let key = server.iam.create_access_key("worker").unwrap();
    let reader = (key.info.id.as_str(), key.secret.as_str());
    let (status, _) = set(&server, reader, "bucket=photos", &target("photos", "copy")).await;
    assert_eq!(status, 403);
    let (status, _) = signed(
        &server,
        reader,
        "GET",
        &format!("{ADMIN}list-remote-targets?bucket=photos"),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, 403);
    // The bucket must be there.
    let (status, _) = set(&server, ROOT, "bucket=missing", &target("missing", "copy")).await;
    assert_eq!(status, 404);
}
