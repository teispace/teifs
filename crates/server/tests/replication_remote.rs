//! Replication to a target on another S3 service, here a second TeiFS: the replica
//! keeps the version's id, time, ETag and what describes it, when the target's keys
//! may `s3:ReplicateObject`; keys that may only write fail the version.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use aws_sdk_s3::{
    Client,
    types::{
        BucketVersioningStatus, DeleteMarkerReplication, DeleteMarkerReplicationStatus,
        Destination, ExistingObjectReplication, ExistingObjectReplicationStatus,
        ReplicationConfiguration, ReplicationRule, ReplicationRuleFilter, ReplicationRuleStatus,
        ReplicationStatus, VersioningConfiguration,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start_with};
use md5::{Digest, Md5};
use serde_json::json;
use signing::{signed, signed_response};
use teifs_crypto::madmin;
use teifs_store::Layout;

async fn object_server() -> Server {
    start_with(|c| c.default_layout = Layout::Object).await
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

/// `source`'s target on `to` (its bucket `copy`), signed in with `keys`; its ARN.
async fn target(from: &Server, to: &Server, keys: (&str, &str)) -> String {
    let endpoint = to.endpoint.strip_prefix("http://").unwrap();
    let target = json!({
        "sourcebucket": "source",
        "endpoint": endpoint,
        "credentials": {"accessKey": keys.0, "secretKey": keys.1},
        "targetbucket": "copy",
        "secure": false,
        "type": "replication",
    });
    let body = madmin::encrypt(SECRET_KEY, target.to_string().as_bytes());
    let response = signed_response(
        from,
        (ACCESS_KEY, SECRET_KEY),
        "PUT",
        "/minio/admin/v3/set-remote-target?bucket=source",
        &[],
        &body,
    )
    .await;
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

/// Replicates every object of `source` to `arn`.
async fn replicate(s3: &Client, arn: &str) {
    replicate_with(s3, arn, false).await;
}

/// Replicates every object of `source` to `arn`, those already there too when
/// `existing`.
async fn replicate_with(s3: &Client, arn: &str, existing: bool) {
    let status = if existing {
        ExistingObjectReplicationStatus::Enabled
    } else {
        ExistingObjectReplicationStatus::Disabled
    };
    let rule = ReplicationRule::builder()
        .existing_object_replication(
            ExistingObjectReplication::builder()
                .status(status)
                .build()
                .unwrap(),
        )
        .id("r")
        .priority(1)
        .status(ReplicationRuleStatus::Enabled)
        .filter(ReplicationRuleFilter::builder().build())
        .delete_marker_replication(
            DeleteMarkerReplication::builder()
                .status(DeleteMarkerReplicationStatus::Enabled)
                .build(),
        )
        .destination(Destination::builder().bucket(arn).build().unwrap())
        .build()
        .unwrap();
    s3.put_bucket_replication()
        .bucket("source")
        .replication_configuration(
            ReplicationConfiguration::builder()
                .role("")
                .rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
}

/// The replication status of `key`, once it's no longer `PENDING`.
async fn settled(s3: &Client, key: &str) -> Option<ReplicationStatus> {
    for _ in 0..400 {
        let status = s3
            .head_object()
            .bucket("source")
            .key(key)
            .send()
            .await
            .unwrap()
            .replication_status;
        if status != Some(ReplicationStatus::Pending) {
            return status;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    Some(ReplicationStatus::Pending)
}

/// Two servers, the first's `source` replicating to the second's `copy` with its root
/// keys; their clients (the servers stop when dropped).
async fn replicating() -> ((Server, Server), Client, Client) {
    let (from, to) = (object_server().await, object_server().await);
    let (source, copy) = (client(&from, SECRET_KEY), client(&to, SECRET_KEY));
    versioned(&source, "source").await;
    versioned(&copy, "copy").await;
    let arn = target(&from, &to, (ACCESS_KEY, SECRET_KEY)).await;
    replicate(&source, &arn).await;
    ((from, to), source, copy)
}

#[tokio::test]
async fn versions_reach_another_teifs_as_they_are() {
    let (_servers, source, copy) = replicating().await;

    let put = source
        .put_object()
        .bucket("source")
        .key("docs/a.txt")
        .body(b"hello".to_vec().into())
        .content_type("text/plain")
        .cache_control("max-age=60")
        .metadata("owner", "ana")
        .tagging("team=red&year=2026")
        .send()
        .await
        .unwrap();
    assert_eq!(
        settled(&source, "docs/a.txt").await,
        Some(ReplicationStatus::Completed)
    );
    let head = source
        .head_object()
        .bucket("source")
        .key("docs/a.txt")
        .send()
        .await
        .unwrap();
    let replica = copy
        .get_object()
        .bucket("copy")
        .key("docs/a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(replica.version_id(), put.version_id());
    assert_eq!(replica.replication_status, Some(ReplicationStatus::Replica));
    assert_eq!(replica.last_modified(), head.last_modified());
    assert_eq!(replica.e_tag(), head.e_tag());
    assert_eq!(replica.content_type(), Some("text/plain"));
    assert_eq!(replica.cache_control(), Some("max-age=60"));
    assert_eq!(
        replica
            .metadata()
            .and_then(|m| m.get("owner"))
            .map(String::as_str),
        Some("ana")
    );
    assert_eq!(replica.tag_count(), Some(2));
    let body = replica.body.collect().await.unwrap().into_bytes();
    assert_eq!(&body[..], b"hello");
}

#[tokio::test]
async fn objects_from_before_the_rule_go_when_it_replicates_existing_ones() {
    let (from, to) = (object_server().await, object_server().await);
    let (source, copy) = (client(&from, SECRET_KEY), client(&to, SECRET_KEY));
    versioned(&source, "source").await;
    versioned(&copy, "copy").await;
    let put = source
        .put_object()
        .bucket("source")
        .key("old.txt")
        .body(b"from before".to_vec().into())
        .send()
        .await
        .unwrap();
    let arn = target(&from, &to, (ACCESS_KEY, SECRET_KEY)).await;
    replicate(&source, &arn).await;
    assert_eq!(settled(&source, "old.txt").await, None);

    // Sent at once (not at the next look round), with its version.
    replicate_with(&source, &arn, true).await;
    let mut status = None;
    for _ in 0..400 {
        status = settled(&source, "old.txt").await;
        if status.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(status, Some(ReplicationStatus::Completed));
    let replica = copy
        .head_object()
        .bucket("copy")
        .key("old.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(replica.version_id(), put.version_id());
    assert_eq!(replica.replication_status, Some(ReplicationStatus::Replica));
}

#[tokio::test]
async fn empty_objects_and_uploads_in_parts_go_too() {
    let (_servers, source, copy) = replicating().await;
    // An upload's ETag (not its bytes' MD5) goes with it.
    source
        .put_object()
        .bucket("source")
        .key("empty")
        .body(Vec::new().into())
        .send()
        .await
        .unwrap();
    let upload = source
        .create_multipart_upload()
        .bucket("source")
        .key("parts")
        .send()
        .await
        .unwrap();
    let part = source
        .upload_part()
        .bucket("source")
        .key("parts")
        .upload_id(upload.upload_id().unwrap())
        .part_number(1)
        .body(vec![7; 1024].into())
        .send()
        .await
        .unwrap();
    let done = source
        .complete_multipart_upload()
        .bucket("source")
        .key("parts")
        .upload_id(upload.upload_id().unwrap())
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .set_e_tag(part.e_tag)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    for key in ["empty", "parts"] {
        assert_eq!(
            settled(&source, key).await,
            Some(ReplicationStatus::Completed),
            "{key}"
        );
    }
    let parts = copy
        .head_object()
        .bucket("copy")
        .key("parts")
        .send()
        .await
        .unwrap();
    assert_eq!(parts.e_tag(), done.e_tag());
    assert_eq!(parts.content_length(), Some(1024));
    // Sent in parts too, it keeps its id and time.
    assert_eq!(parts.version_id(), done.version_id());
    let there = source
        .head_object()
        .bucket("source")
        .key("parts")
        .send()
        .await
        .unwrap();
    assert_eq!(parts.last_modified(), there.last_modified());
    assert_eq!(parts.replication_status, Some(ReplicationStatus::Replica));
}

#[tokio::test]
async fn keys_that_may_not_replicate_fail_the_version() {
    let (from, to) = (object_server().await, object_server().await);
    let (source, copy) = (client(&from, SECRET_KEY), client(&to, SECRET_KEY));
    versioned(&source, "source").await;
    versioned(&copy, "copy").await;
    // Writes, but not replicas.
    to.iam.create_user("writer", None, &[], None).unwrap();
    to.iam
        .put_inline(
            teifs_iam::Owner::User("writer"),
            "policy",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#,
        )
        .unwrap();
    let key = to.iam.create_access_key("writer").unwrap();
    let arn = target(&from, &to, (key.info.id.as_str(), key.secret.as_str())).await;
    replicate(&source, &arn).await;
    source
        .put_object()
        .bucket("source")
        .key("a.txt")
        .body(b"hello".to_vec().into())
        .send()
        .await
        .unwrap();
    assert_eq!(
        settled(&source, "a.txt").await,
        Some(ReplicationStatus::Failed)
    );
    assert!(
        copy.head_object()
            .bucket("copy")
            .key("a.txt")
            .send()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn delete_markers_reach_another_teifs_with_their_ids() {
    let (_servers, source, copy) = replicating().await;
    source
        .put_object()
        .bucket("source")
        .key("a.txt")
        .body(b"hello".to_vec().into())
        .send()
        .await
        .unwrap();
    assert_eq!(
        settled(&source, "a.txt").await,
        Some(ReplicationStatus::Completed)
    );
    let deleted = source
        .delete_object()
        .bucket("source")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    let mut there = Vec::new();
    for _ in 0..200 {
        there = copy
            .list_object_versions()
            .bucket("copy")
            .send()
            .await
            .unwrap()
            .delete_markers()
            .iter()
            .map(|m| m.version_id().unwrap().to_owned())
            .collect();
        if !there.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(there, [deleted.version_id().unwrap()]);
    assert!(
        copy.head_object()
            .bucket("copy")
            .key("a.txt")
            .send()
            .await
            .is_err()
    );
}

/// Replicates every object of `source` to `arn`, removals of versions too (`MinIO`'s
/// `DeleteReplication`, which the SDK can't write).
async fn replicate_removals(from: &Server, arn: &str) {
    let body = format!(
        "<ReplicationConfiguration><Role></Role><Rule><ID>r</ID><Status>Enabled</Status>\
         <Priority>1</Priority><DeleteMarkerReplication><Status>Enabled</Status>\
         </DeleteMarkerReplication><DeleteReplication><Status>Enabled</Status>\
         </DeleteReplication><Filter><Prefix></Prefix></Filter>\
         <Destination><Bucket>{arn}</Bucket></Destination></Rule>\
         </ReplicationConfiguration>"
    );
    let md5 = STANDARD.encode(Md5::digest(body.as_bytes()));
    let (status, text) = signed(
        from,
        (ACCESS_KEY, SECRET_KEY),
        "PUT",
        "/source?replication",
        &[("content-md5", &md5)],
        body.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "{text}");
}

#[tokio::test]
async fn removed_versions_leave_another_teifs_too() {
    let (from, to) = (object_server().await, object_server().await);
    let (source, copy) = (client(&from, SECRET_KEY), client(&to, SECRET_KEY));
    versioned(&source, "source").await;
    versioned(&copy, "copy").await;
    let arn = target(&from, &to, (ACCESS_KEY, SECRET_KEY)).await;
    replicate_removals(&from, &arn).await;
    let mut ids = Vec::new();
    for body in ["one", "two"] {
        let put = source
            .put_object()
            .bucket("source")
            .key("a.txt")
            .body(body.as_bytes().to_vec().into())
            .send()
            .await
            .unwrap();
        ids.push(put.version_id.unwrap());
        assert_eq!(
            settled(&source, "a.txt").await,
            Some(ReplicationStatus::Completed)
        );
    }
    source
        .delete_object()
        .bucket("source")
        .key("a.txt")
        .version_id(&ids[1])
        .send()
        .await
        .unwrap();
    let mut current = None;
    for _ in 0..200 {
        current = copy
            .head_object()
            .bucket("copy")
            .key("a.txt")
            .send()
            .await
            .unwrap()
            .version_id;
        if current.as_ref() == Some(&ids[0]) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(current.as_ref(), Some(&ids[0]));
    let versions = copy
        .list_object_versions()
        .bucket("copy")
        .send()
        .await
        .unwrap();
    assert_eq!(versions.versions().len(), 1);
}

#[tokio::test]
async fn changed_tags_reach_another_teifs_in_place() {
    let (from, to) = (object_server().await, object_server().await);
    let (source, copy) = (client(&from, SECRET_KEY), client(&to, SECRET_KEY));
    versioned(&source, "source").await;
    versioned(&copy, "copy").await;
    // A replication user as `MinIO` documents one: no `s3:PutObjectTagging`.
    to.iam.create_user("replicator", None, &[], None).unwrap();
    to.iam
        .put_inline(
            teifs_iam::Owner::User("replicator"),
            "policy",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[
                "s3:GetObject","s3:GetObjectVersion","s3:PutObject","s3:ReplicateObject",
                "s3:ReplicateTags","s3:DeleteObject","s3:ReplicateDelete",
                "s3:GetBucketVersioning","s3:ListBucket"],"Resource":"*"}]}"#,
        )
        .unwrap();
    let key = to.iam.create_access_key("replicator").unwrap();
    let arn = target(&from, &to, (key.info.id.as_str(), key.secret.as_str())).await;
    replicate(&source, &arn).await;
    let put = source
        .put_object()
        .bucket("source")
        .key("a.txt")
        .body(b"hello".to_vec().into())
        .tagging("team=red")
        .send()
        .await
        .unwrap();
    assert_eq!(
        settled(&source, "a.txt").await,
        Some(ReplicationStatus::Completed)
    );
    source
        .put_object_tagging()
        .bucket("source")
        .key("a.txt")
        .tagging(
            aws_sdk_s3::types::Tagging::builder()
                .tag_set(
                    aws_sdk_s3::types::Tag::builder()
                        .key("team")
                        .value("blue")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        settled(&source, "a.txt").await,
        Some(ReplicationStatus::Completed)
    );
    let tags = copy
        .get_object_tagging()
        .bucket("copy")
        .key("a.txt")
        .version_id(put.version_id().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tag_set()[0].value(), "blue");
    let versions = copy
        .list_object_versions()
        .bucket("copy")
        .send()
        .await
        .unwrap();
    assert_eq!(versions.versions().len(), 1);
}
