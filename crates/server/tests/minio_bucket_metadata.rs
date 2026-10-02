//! `MinIO`'s bucket metadata export and import (`mc admin cluster bucket export|import`):
//! a zip of `<bucket>/<file>`, each a setting as S3's calls take it.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::io::{Read as _, Write as _};

use aws_sdk_s3::types::{
    BucketLifecycleConfiguration, BucketVersioningStatus, ExpirationStatus, LifecycleExpiration,
    LifecycleRule, LifecycleRuleFilter, ServerSideEncryption, ServerSideEncryptionByDefault,
    ServerSideEncryptionConfiguration, ServerSideEncryptionRule, Tag, Tagging,
    VersioningConfiguration,
};
use serde_json::{Value, json};

#[macro_use]
mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, start, start_with, user};
use signing::{signed, signed_response};

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);
const ADMIN: &str = "/minio/admin/v3/";

async fn export(server: &Server, query: &str) -> reqwest::Response {
    let path = format!("{ADMIN}export-bucket-metadata{query}");
    signed_response(server, ROOT, "GET", &path, &[], &[]).await
}

async fn import(server: &Server, zip: &[u8]) -> (u16, Value) {
    let path = format!("{ADMIN}import-bucket-metadata");
    let (status, text) = signed(server, ROOT, "PUT", &path, &[], zip).await;
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// The files of a zip, by name.
fn unzip(bytes: &[u8]) -> Vec<(String, String)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    (0..archive.len())
        .map(|i| {
            let mut file = archive.by_index(i).unwrap();
            let mut text = String::new();
            file.read_to_string(&mut text).unwrap();
            (file.name().to_owned(), text)
        })
        .collect()
}

fn zipped(files: &[(&str, &str)]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, text) in files {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(text.as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// A bucket with versioning, tags, a policy, a lifecycle rule and a quota.
async fn photos(server: &Server) {
    let s3 = client(server, SECRET_KEY);
    s3.create_bucket().bucket("photos").send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("photos")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let tag = Tag::builder().key("team").value("web").build().unwrap();
    s3.put_bucket_tagging()
        .bucket("photos")
        .tagging(Tagging::builder().tag_set(tag).build().unwrap())
        .send()
        .await
        .unwrap();
    let policy = json!({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]}, "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::photos/*"]}]});
    s3.put_bucket_policy()
        .bucket("photos")
        .policy(policy.to_string())
        .send()
        .await
        .unwrap();
    let rule = LifecycleRule::builder()
        .id("old")
        .status(ExpirationStatus::Enabled)
        .filter(LifecycleRuleFilter::builder().prefix("tmp/").build())
        .expiration(LifecycleExpiration::builder().days(30).build())
        .build()
        .unwrap();
    s3.put_bucket_lifecycle_configuration()
        .bucket("photos")
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let by_default = ServerSideEncryptionByDefault::builder()
        .sse_algorithm(ServerSideEncryption::Aes256)
        .build()
        .unwrap();
    let rule = ServerSideEncryptionRule::builder()
        .apply_server_side_encryption_by_default(by_default)
        .bucket_key_enabled(true)
        .build();
    s3.put_bucket_encryption()
        .bucket("photos")
        .server_side_encryption_configuration(
            ServerSideEncryptionConfiguration::builder()
                .rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let quota = json!({"quota": 1_048_576, "quotatype": "hard"}).to_string();
    let path = format!("{ADMIN}set-bucket-quota?bucket=photos");
    assert_eq!(
        signed(server, ROOT, "PUT", &path, &[], quota.as_bytes())
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn an_export_moves_buckets_settings_to_another_server() {
    let from = start_with(|c| c.default_layout = teifs_store::Layout::Object).await;
    photos(&from).await;
    let response = export(&from, "").await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/zip");
    let zip = response.bytes().await.unwrap();
    let files = unzip(&zip);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    for name in [
        "photos/policy.json",
        "photos/lifecycle.xml",
        "photos/bucket-encryption.xml",
        "photos/tagging.xml",
        "photos/quota.json",
        "photos/versioning.xml",
    ] {
        assert!(names.contains(&name), "{name} in {names:?}");
    }
    let file = |name: &str| &files.iter().find(|(n, _)| n == name).unwrap().1;
    assert!(file("photos/versioning.xml").contains("<Status>Enabled</Status>"));
    assert!(file("photos/tagging.xml").contains("<Key>team</Key>"));
    let quota: Value = serde_json::from_str(file("photos/quota.json")).unwrap();
    assert_eq!(
        (&quota["size"], &quota["quotatype"]),
        (&json!(1_048_576), &json!("hard"))
    );

    // A bucket the zip makes is an object bucket, whatever the server's default.
    let to = start().await;
    let (status, report) = import(&to, &zip).await;
    assert_eq!(status, 200, "{report}");
    let photos = &report["buckets"]["photos"];
    for setting in [
        "versioning",
        "policy",
        "tagging",
        "sse",
        "lifecycle",
        "quota",
    ] {
        assert_eq!(
            photos[setting],
            json!({"isSet": true}),
            "{setting}: {report}"
        );
    }
    assert_eq!(photos["olock"], json!({"isSet": false}));
    assert!(photos.get("error").is_none(), "{report}");

    let s3 = client(&to, SECRET_KEY);
    let versioning = s3
        .get_bucket_versioning()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(versioning.status(), Some(&BucketVersioningStatus::Enabled));
    let tags = s3
        .get_bucket_tagging()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tag_set()[0].value(), "web");
    let lifecycle = s3
        .get_bucket_lifecycle_configuration()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(lifecycle.rules()[0].id(), Some("old"));
    assert!(s3.get_bucket_policy().bucket("photos").send().await.is_ok());
    let encryption = s3
        .get_bucket_encryption()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    let rules = encryption
        .server_side_encryption_configuration()
        .unwrap()
        .rules();
    assert_eq!(rules[0].bucket_key_enabled(), Some(true));

    // One bucket alone, and one that isn't there.
    let response = export(&from, "?bucket=photos").await;
    assert_eq!(unzip(&response.bytes().await.unwrap()).len(), files.len());
    let response = export(&from, "?bucket=missing").await;
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn minio_s_files_are_read_and_bad_ones_reported() {
    let server = start().await;
    // As `MinIO`'s Go `xml.Marshal` writes them.
    let lock = r#"<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>"#;
    let versioning = r#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>"#;
    let zip = zipped(&[
        ("locked/object-lock.xml", lock),
        ("locked/versioning.xml", versioning),
        ("locked/lifecycle.xml", "<LifecycleConfiguration>"),
        ("locked/replication.xml", "<ReplicationConfiguration/>"),
        ("not-a-bucket-file", "{}"),
    ]);
    let (status, report) = import(&server, &zip).await;
    assert_eq!(status, 200, "{report}");
    let locked = &report["buckets"]["locked"];
    assert_eq!(locked["olock"], json!({"isSet": true}), "{report}");
    assert_eq!(locked["versioning"], json!({"isSet": true}), "{report}");
    assert_eq!(locked["lifecycle"]["isSet"], true);
    assert!(locked["lifecycle"]["error"].as_str().is_some(), "{report}");
    assert!(
        report["buckets"]["not-a-bucket-file"]["error"]
            .as_str()
            .unwrap()
            .contains("malformed zip")
    );
    let s3 = client(&server, SECRET_KEY);
    let lock = s3
        .get_object_lock_configuration()
        .bucket("locked")
        .send()
        .await
        .unwrap();
    let rule = lock.object_lock_configuration().unwrap().rule().unwrap();
    assert_eq!(rule.default_retention().unwrap().days(), Some(1));

    let (status, error) = import(&server, b"not a zip").await;
    assert_eq!((status, &error["Code"]), (400, &json!("InvalidRequest")));
}

#[tokio::test]
async fn the_calls_need_minio_s_admin_actions() {
    let server = start().await;
    let reader = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
    user(&server, "alice", Some(reader));
    let key = server.iam.create_access_key("alice").unwrap();
    let alice = (key.info.id.as_str(), key.secret.as_str());
    let path = format!("{ADMIN}export-bucket-metadata");
    assert_eq!(signed(&server, alice, "GET", &path, &[], &[]).await.0, 403);
    let path = format!("{ADMIN}import-bucket-metadata");
    assert_eq!(
        signed(&server, alice, "PUT", &path, &[], &zipped(&[]))
            .await
            .0,
        403
    );
}
