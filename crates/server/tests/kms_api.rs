//! `MinIO`'s KMS API (`mc admin kms`) and the KMS calls of its admin API, on the
//! server's KMS.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use aws_sdk_s3::{primitives::ByteStream, types::ServerSideEncryption};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start, start_with, user};
use serde_json::{Value, json};
use signing::signed;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

async fn call(server: &Server, key: (&str, &str), method: &str, path: &str) -> (u16, String) {
    signed(server, key, method, path, &[], b"").await
}

async fn json_of(server: &Server, key: (&str, &str), method: &str, path: &str) -> Value {
    let (status, answer) = call(server, key, method, path).await;
    assert_eq!(status, 200, "{path}: {answer}");
    serde_json::from_str(&answer).unwrap()
}

fn names(listed: &Value) -> Vec<&str> {
    listed
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["name"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn the_kms_describes_itself() {
    let server = start().await;
    for (method, path) in [
        ("GET", "/minio/kms/v1/status"),
        ("POST", "/minio/admin/v3/kms/status"),
    ] {
        let status = json_of(&server, ROOT, method, path).await;
        assert_eq!(status["name"], "TeiFS keyring", "{status}");
        assert_eq!(status["default-key-id"], "teifs-default");
        assert_eq!(status["endpoints"], json!({"local": "online"}));
        assert_eq!(status["state"]["KeyStoreReachable"], true);
    }
    let version = json_of(&server, ROOT, "GET", "/minio/kms/v1/version").await;
    assert_eq!(version, json!({"version": env!("CARGO_PKG_VERSION")}));
    let apis = json_of(&server, ROOT, "GET", "/minio/kms/v1/apis").await;
    assert!(
        apis.as_array().unwrap().contains(
            &json!({"Method": "GET", "Path": "/minio/kms/v1/key/list", "MaxBody": 0, "Timeout": 0})
        ),
        "{apis}"
    );
}

#[tokio::test]
async fn keys_are_created_listed_and_checked() {
    // Encrypted objects are in object buckets.
    let server = start_with(|config| config.default_layout = teifs_store::Layout::Object).await;
    for path in [
        "/minio/kms/v1/key/create?key-id=app-1",
        "/minio/admin/v3/kms/key/create?key-id=app-2",
    ] {
        let (status, answer) = call(&server, ROOT, "POST", path).await;
        assert_eq!((status, answer.as_str()), (200, ""), "{path}");
    }
    for (path, status, code) in [
        (
            "/minio/kms/v1/key/create?key-id=app-1",
            409,
            "kms:KeyAlreadyExists",
        ),
        (
            "/minio/kms/v1/key/create?key-id=no%2Fslash",
            400,
            "kms:InvalidKeyName",
        ),
        ("/minio/kms/v1/key/create", 400, "InvalidRequest"),
        (
            "/minio/admin/v3/kms/key/create?key-id=",
            400,
            "InvalidRequest",
        ),
    ] {
        let (got, answer) = call(&server, ROOT, "POST", path).await;
        assert_eq!(got, status, "{path}: {answer}");
        assert!(answer.contains(code), "{path}: {answer}");
    }

    let listed = json_of(&server, ROOT, "GET", "/minio/kms/v1/key/list?pattern=app").await;
    assert_eq!(names(&listed), ["app-1", "app-2"]);
    assert!(
        listed[0]["createdAt"].as_str().unwrap().ends_with('Z'),
        "{listed}"
    );
    for pattern in ["*", ""] {
        let all = json_of(
            &server,
            ROOT,
            "GET",
            &format!("/minio/kms/v1/key/list?pattern={pattern}"),
        )
        .await;
        assert_eq!(
            names(&all),
            ["app-1", "app-2", "teifs-default"],
            "{pattern}"
        );
    }

    for path in ["/minio/kms/v1/key/status", "/minio/admin/v3/kms/key/status"] {
        let named = json_of(&server, ROOT, "GET", &format!("{path}?key-id=app-1")).await;
        assert_eq!(named, json!({"key-id": "app-1"}));
        let default = json_of(&server, ROOT, "GET", path).await;
        assert_eq!(default, json!({"key-id": "teifs-default"}));
        // What fails is in the answer.
        let missing = json_of(&server, ROOT, "GET", &format!("{path}?key-id=missing")).await;
        assert_eq!(missing["key-id"], "missing");
        assert!(
            missing["encryption-error"]
                .as_str()
                .unwrap()
                .contains("missing")
        );
        assert!(missing.get("decryption-error").is_none());
    }

    // A created key encrypts objects.
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    let put = root
        .put_object()
        .bucket("photos")
        .key("a.txt")
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .ssekms_key_id("app-1")
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(put.ssekms_key_id(), Some("app-1"));

    // Every call that used a key was counted: refused ones too.
    let metrics = json_of(&server, ROOT, "GET", "/minio/kms/v1/metrics").await;
    let count = |name: &str| metrics[name].as_u64().unwrap();
    assert!(count("kms_req_success") >= 6, "{metrics}");
    assert_eq!(count("kms_req_error"), 4, "{metrics}");
    assert_eq!(count("kms_req_failure"), 0, "{metrics}");
    let latency = metrics["kms_resp_time"].as_object().unwrap();
    assert_eq!(latency.len(), 10, "{metrics}");
    assert_eq!(
        latency["10000000000"].as_u64().unwrap(),
        count("kms_req_success") + count("kms_req_error"),
        "{metrics}"
    );
}

#[tokio::test]
async fn kms_calls_are_decided_per_key() {
    let server = start().await;
    call(
        &server,
        ROOT,
        "POST",
        "/minio/kms/v1/key/create?key-id=other",
    )
    .await;
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kms:CreateKey","kms:KeyStatus","kms:ListKeys"],"Resource":"arn:minio:kms:::app-*"}]}"#;
    user(&server, "apps", Some(policy));
    let key = server.iam.create_access_key("apps").unwrap();
    let apps = (key.info.id.as_str(), key.secret.as_str());
    for (method, path, status) in [
        ("POST", "/minio/kms/v1/key/create?key-id=app-1", 200),
        ("POST", "/minio/kms/v1/key/create?key-id=nope", 403),
        ("GET", "/minio/kms/v1/key/status?key-id=app-1", 200),
        ("GET", "/minio/kms/v1/key/status?key-id=other", 403),
        // The default key isn't an app's.
        ("GET", "/minio/kms/v1/key/status", 403),
        ("GET", "/minio/kms/v1/status", 403),
        // The admin API's KMS calls need its own actions.
        ("POST", "/minio/admin/v3/kms/key/create?key-id=app-2", 403),
        ("GET", "/minio/admin/v3/kms/key/status?key-id=app-1", 403),
    ] {
        let (got, answer) = call(&server, apps, method, path).await;
        assert_eq!(got, status, "{path}: {answer}");
    }
    // Only the keys it may list.
    let listed = json_of(&server, apps, "GET", "/minio/kms/v1/key/list?pattern=*").await;
    assert_eq!(names(&listed), ["app-1"]);

    // As on MinIO, a call is decided on no key first: a Deny of some keys denies
    // every key's.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*"},{"Effect":"Deny","Action":"kms:KeyStatus","Resource":"arn:minio:kms:::secret-*"}]}"#;
    user(&server, "most", Some(policy));
    let key = server.iam.create_access_key("most").unwrap();
    let most = (key.info.id.as_str(), key.secret.as_str());
    for (method, path, status) in [
        ("GET", "/minio/kms/v1/key/status?key-id=other", 403),
        ("POST", "/minio/kms/v1/key/create?key-id=secret-1", 200),
    ] {
        let (got, answer) = call(&server, most, method, path).await;
        assert_eq!(got, status, "{path}: {answer}");
    }

    // The admin API's actions decide on any key.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"admin:KMSKeyStatus"}]}"#;
    user(&server, "ops", Some(policy));
    let key = server.iam.create_access_key("ops").unwrap();
    let ops = (key.info.id.as_str(), key.secret.as_str());
    for (method, path, status) in [
        ("GET", "/minio/admin/v3/kms/key/status?key-id=other", 200),
        ("POST", "/minio/admin/v3/kms/status", 200),
        ("POST", "/minio/admin/v3/kms/key/create?key-id=app-3", 403),
        ("GET", "/minio/kms/v1/key/status?key-id=other", 403),
    ] {
        let (got, answer) = call(&server, ops, method, path).await;
        assert_eq!(got, status, "{path}: {answer}");
    }
}

#[tokio::test]
async fn a_bucket_named_minio_keeps_its_other_kms_keys() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("minio").send().await.unwrap();
    root.put_object()
        .bucket("minio")
        .key("kms/v1/notes.txt")
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await
        .unwrap();
    let got = root
        .get_object()
        .bucket("minio")
        .key("kms/v1/notes.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.body.collect().await.unwrap().into_bytes().as_ref(),
        b"hello"
    );
}
