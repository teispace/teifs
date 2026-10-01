//! TeiFS with a real external KMS: a Vault or OpenBao transit engine, KES, or AWS KMS (or
//! a service that speaks its API). Each test runs when the environment names that KMS
//! (nightly CI starts OpenBao, KES and Moto for them) and is skipped otherwise:
//!
//! - transit: `TEIFS_TEST_TRANSIT_ADDR` (an engine in dev mode) and `VAULT_TOKEN`;
//! - KES: `TEIFS_TEST_KES_ENDPOINT`, `TEIFS_TEST_KES_CA` (its CA file) and
//!   `TEIFS_KMS_KES_API_KEY` (an identity KES's policy allows to create keys);
//! - AWS KMS: `TEIFS_TEST_AWS_KMS_ENDPOINT`, with AWS's usual credential and region
//!   variables.
//!
//! Key names are new for each run, and the default key is renamed to one of them, so
//! runs against the same KMS don't meet.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{path::PathBuf, sync::Arc};

use aws_sdk_s3::{Client, primitives::ByteStream, types::ServerSideEncryption};
use teifs_server::{AwsKmsConfig, ExternalKms, Kes, Transit};
use teifs_store::Kms;

mod common;

use common::{SECRET_KEY, client, start_with};

/// A key name no other run uses.
fn fresh(name: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("teifs-{name}-{}-{nanos}", std::process::id())
}

async fn put(s3: &Client, key: &str, kms_key: Option<&str>) {
    let put = s3
        .put_object()
        .bucket("sealed")
        .key(key)
        .set_server_side_encryption(kms_key.map(|_| ServerSideEncryption::AwsKms))
        .set_ssekms_key_id(kms_key.map(str::to_owned))
        .body(ByteStream::from(
            format!("{key}, sealed by the KMS").into_bytes(),
        ))
        .send()
        .await
        .unwrap();
    assert!(put.server_side_encryption().is_some(), "{key}");
}

async fn get(s3: &Client, key: &str) {
    let got = s3
        .get_object()
        .bucket("sealed")
        .key(key)
        .send()
        .await
        .unwrap();
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(
        bytes,
        format!("{key}, sealed by the KMS").as_bytes(),
        "{key}"
    );
}

/// Serves with `external`, its default key renamed to `default`: objects sealed under
/// the default key and under `named` read back, and a missing key is refused. When the
/// KMS `can_rotate` keys, objects sealed before and after a rotation both read back; else
/// rotating is refused.
async fn objects_are_sealed(external: ExternalKms, default: &str, named: &str, can_rotate: bool) {
    let (kms, _) = teifs_server::open_external(&external).await.unwrap();
    kms.create_key(default).await.unwrap();
    kms.create_key(named).await.unwrap();
    let server = start_with(|config| {
        config.default_layout = teifs_store::Layout::Object;
        config.kms_external = Some(external);
        config.kms_default_key = Some(default.to_owned());
    })
    .await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("sealed").send().await.unwrap();
    put(&s3, "default", None).await;
    put(&s3, "named", Some(named)).await;
    get(&s3, "default").await;
    get(&s3, "named").await;
    let missing = s3
        .put_object()
        .bucket("sealed")
        .key("x")
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .ssekms_key_id(fresh("missing"))
        .body(ByteStream::from_static(b"x"))
        .send()
        .await;
    assert!(missing.is_err());
    let listed: Vec<String> = kms
        .keys()
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.name)
        .collect();
    assert!(listed.iter().any(|n| n == named), "{listed:?}");
    let rotated = kms.rotate_key(named).await;
    assert_eq!(rotated.is_ok(), can_rotate, "{rotated:?}");
    if let Ok(rotated) = rotated {
        assert_eq!(rotated.version, 2);
        put(&s3, "after-rotation", Some(named)).await;
        get(&s3, "named").await;
        get(&s3, "after-rotation").await;
    }
}

#[tokio::test]
async fn objects_are_sealed_by_the_transit_engine() {
    let Ok(address) = std::env::var("TEIFS_TEST_TRANSIT_ADDR") else {
        eprintln!("skipped: TEIFS_TEST_TRANSIT_ADDR isn't set");
        return;
    };
    let token = std::env::var("VAULT_TOKEN").unwrap();
    // A fresh transit mount for this run.
    let mount = fresh("transit");
    let enabled = reqwest::Client::new()
        .post(format!("{address}/v1/sys/mounts/{mount}"))
        .header("X-Vault-Token", &token)
        .json(&serde_json::json!({ "type": "transit" }))
        .send()
        .await
        .unwrap();
    assert!(enabled.status().is_success(), "{}", enabled.status());
    let external = ExternalKms::Transit(Transit {
        address,
        mount,
        namespace: None,
    });
    objects_are_sealed(external, "teifs-default", "photos", true).await;
}

#[tokio::test]
async fn objects_are_sealed_by_kes() {
    let Ok(endpoint) = std::env::var("TEIFS_TEST_KES_ENDPOINT") else {
        eprintln!("skipped: TEIFS_TEST_KES_ENDPOINT isn't set");
        return;
    };
    let external = ExternalKms::Kes(Kes {
        endpoints: vec![endpoint],
        client_cert: None,
        ca: std::env::var("TEIFS_TEST_KES_CA").ok().map(PathBuf::from),
    });
    let (kms, location) = teifs_server::open_external(&external).await.unwrap();
    assert!(location.describe().contains("identity"));
    drop::<Arc<dyn Kms>>(kms);
    objects_are_sealed(external, &fresh("default"), &fresh("photos"), false).await;
}

#[tokio::test]
async fn objects_are_sealed_by_aws_kms() {
    let Ok(endpoint) = std::env::var("TEIFS_TEST_AWS_KMS_ENDPOINT") else {
        eprintln!("skipped: TEIFS_TEST_AWS_KMS_ENDPOINT isn't set");
        return;
    };
    let external = ExternalKms::Aws(AwsKmsConfig {
        region: Some("us-east-1".to_owned()),
        endpoint: Some(endpoint),
    });
    objects_are_sealed(external, &fresh("default"), &fresh("photos"), true).await;
}
