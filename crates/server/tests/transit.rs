//! TeiFS with a real Vault or OpenBao transit engine as its KMS. Runs when
//! `TEIFS_TEST_TRANSIT_ADDR` names an engine in dev mode and `VAULT_TOKEN` its root token
//! (nightly CI starts OpenBao for it); skipped otherwise.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    config::{Credentials, Region},
    primitives::ByteStream,
    types::ServerSideEncryption,
};
use teifs_server::{Config, Credentials as DriveCredentials, Server, Transit};
use teifs_store::{Kms, TransitKms};

const ACCESS_KEY: &str = "teifs-test";
const SECRET_KEY: &str = "not-a-real-secret-only-for-tests";

#[tokio::test]
async fn objects_are_sealed_by_the_transit_engine() {
    let Ok(address) = std::env::var("TEIFS_TEST_TRANSIT_ADDR") else {
        eprintln!("skipped: TEIFS_TEST_TRANSIT_ADDR isn't set");
        return;
    };
    let token = std::env::var("VAULT_TOKEN").unwrap();
    // A fresh transit mount for this run.
    let mount = format!("teifs-{}", std::process::id());
    let http = reqwest::Client::new();
    let enabled = http
        .post(format!("{address}/v1/sys/mounts/{mount}"))
        .header("X-Vault-Token", &token)
        .json(&serde_json::json!({ "type": "transit" }))
        .send()
        .await
        .unwrap();
    assert!(enabled.status().is_success(), "{}", enabled.status());
    let kms = TransitKms::new(&address, &mount, token.clone(), None).unwrap();
    kms.create_key("teifs-default").await.unwrap();
    kms.create_key("photos").await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let server = Server::bind(Config {
        dir: dir.path().to_owned(),
        listen: "127.0.0.1:0".parse().unwrap(),
        domains: Vec::new(),
        credentials: Some(DriveCredentials {
            access_key: ACCESS_KEY.into(),
            secret_key: SECRET_KEY.into(),
        }),
        default_layout: teifs_store::Layout::Object,
        kms_keyring: None,
        kms_transit: Some(Transit {
            address,
            mount,
            namespace: None,
        }),
        allow_sse_c: false,
        plain_http_is_secure: None,
        tls: None,
        trusted_proxies: teifs_server::TrustedProxies::default(),
        jobs: teifs_server::JobOptions::default(),
        durability: teifs_server::Durability::Strict,
        key_rules: teifs_server::KeyRules::Portable,
        allow_sig_v2: false,
        legacy_bucket_defaults: false,
        limits: teifs_server::Limits::default(),
    })
    .await
    .unwrap();
    let endpoint = format!("http://{}", server.local_addr().unwrap());
    tokio::spawn(server.run(std::future::pending()));
    let s3 = Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .credentials_provider(Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "t"))
            .force_path_style(true)
            .build(),
    );
    s3.create_bucket().bucket("sealed").send().await.unwrap();
    for (key, sse, kms_key) in [
        ("default", None, None),
        ("named", Some(ServerSideEncryption::AwsKms), Some("photos")),
    ] {
        let put = s3
            .put_object()
            .bucket("sealed")
            .key(key)
            .set_server_side_encryption(sse)
            .set_ssekms_key_id(kms_key.map(str::to_owned))
            .body(ByteStream::from_static(b"sealed by the engine"))
            .send()
            .await
            .unwrap();
        assert!(put.server_side_encryption().is_some());
        let got = s3
            .get_object()
            .bucket("sealed")
            .key(key)
            .send()
            .await
            .unwrap();
        let bytes = got.body.collect().await.unwrap().into_bytes();
        assert_eq!(&bytes[..], b"sealed by the engine");
    }
    let missing = s3
        .put_object()
        .bucket("sealed")
        .key("x")
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .ssekms_key_id("no-such-key")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await;
    assert!(missing.is_err());
}
