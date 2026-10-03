//! `MinIO`'s extensions of S3's XML, sent as minio-go (and so `mc`) marshals them:
//! replication rules with `DeleteReplication` and every filter element written, the
//! answer `mc replicate rm` takes, and the lifecycle and versioning extensions TeiFS
//! doesn't carry out yet, refused rather than ignored.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use base64::{Engine, engine::general_purpose::STANDARD};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start};
use md5::{Digest, Md5};
use serde_json::json;
use signing::{signed, signed_response};
use teifs_crypto::madmin;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

/// A request with a body, its `Content-MD5` given as minio-go gives it.
async fn send(server: &Server, method: &str, path: &str, body: &str) -> (u16, String) {
    let md5 = STANDARD.encode(Md5::digest(body.as_bytes()));
    signed(
        server,
        ROOT,
        method,
        path,
        &[("content-md5", &md5)],
        body.as_bytes(),
    )
    .await
}

/// A versioned bucket with a replication target, answering the target's ARN.
async fn bucket_with_target(server: &Server, bucket: &str) -> String {
    let s3 = client(server, SECRET_KEY);
    s3.create_bucket().bucket(bucket).send().await.unwrap();
    let versioning = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    let (status, text) = send(server, "PUT", &format!("/{bucket}?versioning"), versioning).await;
    assert_eq!(status, 200, "{text}");
    let target = json!({
        "sourcebucket": bucket,
        "endpoint": "backup.example.com:9000",
        "credentials": {"accessKey": "replicator", "secretKey": "dummy-target-secret"},
        "targetbucket": "copy",
        "type": "replication",
    });
    let body = madmin::encrypt(SECRET_KEY, target.to_string().as_bytes());
    let response = signed_response(
        server,
        ROOT,
        "PUT",
        &format!("/minio/admin/v3/set-remote-target?bucket={bucket}"),
        &[],
        &body,
    )
    .await;
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

/// A rule as minio-go's `replication.Config.AddRule` writes it for `mc replicate add`.
fn minio_go_rule(arn: &str, filter: &str) -> String {
    format!(
        "<ReplicationConfiguration><Rule><ID>cu9bgsn2k1d0</ID><Status>Enabled</Status>\
         <Priority>1</Priority><DeleteMarkerReplication><Status>Enabled</Status>\
         </DeleteMarkerReplication><DeleteReplication><Status>Enabled</Status>\
         </DeleteReplication><Destination><Bucket>{arn}</Bucket></Destination>\
         <Filter>{filter}</Filter><SourceSelectionCriteria><ReplicaModifications>\
         <Status>Enabled</Status></ReplicaModifications></SourceSelectionCriteria>\
         <ExistingObjectReplication><Status>Enabled</Status></ExistingObjectReplication>\
         </Rule><Role></Role></ReplicationConfiguration>"
    )
}

#[tokio::test]
async fn replication_rules_are_taken_as_minio_go_writes_them() {
    let server = start().await;
    let arn = bucket_with_target(&server, "photos").await;

    // Every object: an empty prefix, an empty And and an empty Tag.
    let every = minio_go_rule(&arn, "<Prefix></Prefix><And></And><Tag></Tag>");
    let (status, text) = send(&server, "PUT", "/photos?replication", &every).await;
    assert_eq!(status, 200, "{text}");
    let (status, kept) = signed(&server, ROOT, "GET", "/photos?replication", &[], b"").await;
    assert_eq!(status, 200, "{kept}");
    assert!(
        kept.contains("<DeleteReplication><Status>Enabled</Status></DeleteReplication>"),
        "{kept}"
    );
    assert!(
        kept.contains("<Filter><Prefix></Prefix></Filter>"),
        "{kept}"
    );

    // A prefix and a tag: minio-go puts them in And, beside an empty Prefix and Tag.
    let tagged = minio_go_rule(
        &arn,
        "<Prefix></Prefix><And><Prefix>docs/</Prefix><Tag><Key>team</Key><Value>red</Value>\
         </Tag></And><Tag></Tag>",
    )
    .replace(
        "<DeleteMarkerReplication><Status>Enabled</Status>",
        "<DeleteMarkerReplication><Status>Disabled</Status>",
    );
    let (status, text) = send(&server, "PUT", "/photos?replication", &tagged).await;
    assert_eq!(status, 200, "{text}");
    let (_, kept) = signed(&server, ROOT, "GET", "/photos?replication", &[], b"").await;
    assert!(
        kept.contains("<And><Prefix>docs/</Prefix><Tag><Key>team</Key><Value>red</Value>"),
        "{kept}"
    );

    // Two conditions that each say something are still one too many.
    let both = minio_go_rule(
        &arn,
        "<Prefix>a/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag>",
    );
    let (status, text) = send(&server, "PUT", "/photos?replication", &both).await;
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("MalformedXML"), "{text}");

    // minio-go takes only 200 for a removed configuration (`mc replicate rm`).
    let (status, text) = signed(&server, ROOT, "DELETE", "/photos?replication", &[], b"").await;
    assert_eq!(status, 200, "{text}");
    let (status, _) = signed(&server, ROOT, "GET", "/photos?replication", &[], b"").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn minio_extensions_not_carried_out_are_refused() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("photos").send().await.unwrap();
    for (path, body, what) in [
        (
            "/photos?lifecycle",
            "<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status><Filter></Filter>\
             <DelMarkerExpiration><Days>3</Days></DelMarkerExpiration></Rule>\
             </LifecycleConfiguration>",
            "DelMarkerExpiration",
        ),
        (
            "/photos?lifecycle",
            "<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status><Filter></Filter>\
             <Expiration><Days>3</Days><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions>\
             </Expiration></Rule></LifecycleConfiguration>",
            "ExpiredObjectAllVersions",
        ),
        (
            "/photos?versioning",
            "<VersioningConfiguration><Status>Enabled</Status><ExcludedPrefixes><Prefix>tmp/\
             </Prefix></ExcludedPrefixes></VersioningConfiguration>",
            "ExcludedPrefixes",
        ),
        (
            "/photos?versioning",
            "<VersioningConfiguration><Status>Enabled</Status><ExcludeFolders>true\
             </ExcludeFolders></VersioningConfiguration>",
            "ExcludeFolders",
        ),
    ] {
        let (status, text) = send(&server, "PUT", path, body).await;
        assert_eq!(status, 501, "{what}: {text}");
        assert!(text.contains(what), "{text}");
    }
    // Nothing was changed.
    let versioning = s3
        .get_bucket_versioning()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert!(versioning.status().is_none());
}
