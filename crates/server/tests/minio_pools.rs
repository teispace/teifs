//! `MinIO`'s pools (`mc admin decommission`, `mc admin rebalance`) on a one-drive server.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, start};
use serde_json::Value;
use signing::signed;

#[tokio::test]
async fn the_drive_is_the_only_pool() {
    let server = start().await;
    let root = (ACCESS_KEY, SECRET_KEY);
    let (status, body) = signed(&server, root, "GET", "/minio/admin/v3/pools/list", &[], &[]).await;
    assert_eq!(status, 200, "{body}");
    let pools: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(pools.as_array().unwrap().len(), 1);
    assert_eq!(pools[0]["id"], 0);
    assert!(pools[0].get("decommissionInfo").is_none());
    let name = pools[0]["cmdline"].as_str().unwrap().to_owned();
    let last_update = pools[0]["lastUpdate"].as_str().unwrap();
    assert!(
        time::OffsetDateTime::parse(last_update, &time::format_description::well_known::Rfc3339)
            .is_ok()
    );

    // A temporary folder's path has no character but `/` to encode.
    let query = |pool: &str| format!("pool={}", pool.replace('/', "%2F"));
    for asked in [query(&name), "pool=0&by-id=true".to_owned()] {
        let path = format!("/minio/admin/v3/pools/status?{asked}");
        let (status, body) = signed(&server, root, "GET", &path, &[], &[]).await;
        assert_eq!(status, 200, "{asked}: {body}");
        let pool: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(pool["cmdline"], name.as_str());
    }
    let (status, body) = signed(
        &server,
        root,
        "GET",
        "/minio/admin/v3/pools/status?pool=elsewhere",
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 400);
    assert!(body.contains("XMinioAdminInvalidArgument") && body.contains("'elsewhere'"));

    let path = format!("/minio/admin/v3/pools/decommission?{}", query(&name));
    let (status, body) = signed(&server, root, "POST", &path, &[], &[]).await;
    assert_eq!(status, 501, "{body}");
    assert!(body.contains("only pool"));
    let (status, _) = signed(
        &server,
        root,
        "POST",
        "/minio/admin/v3/rebalance/start",
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 501);
    let (status, body) = signed(
        &server,
        root,
        "GET",
        "/minio/admin/v3/rebalance/status",
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 404);
    assert!(body.contains("XMinioAdminRebalanceNotStarted"));
}

#[tokio::test]
async fn pools_are_listed_with_either_action() {
    let server = start().await;
    let mut keys = Vec::new();
    for (name, action) in [
        ("info", "admin:ServerInfo"),
        ("decom", "admin:Decommission"),
    ] {
        server.iam.create_user(name, None, &[], None).unwrap();
        let policy = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"{action}","Resource":"*"}}]}}"#
        );
        server
            .iam
            .put_inline(teifs_iam::Owner::User(name), "policy", &policy)
            .unwrap();
        let key = server.iam.create_access_key(name).unwrap();
        keys.push((key.info.id.clone(), key.secret.clone()));
    }
    for (id, secret) in &keys {
        let (status, _) = signed(
            &server,
            (id, secret),
            "GET",
            "/minio/admin/v3/pools/list",
            &[],
            &[],
        )
        .await;
        assert_eq!(status, 200);
    }
    // Server info alone doesn't start a decommission.
    let (id, secret) = &keys[0];
    let (status, _) = signed(
        &server,
        (id, secret),
        "POST",
        "/minio/admin/v3/pools/decommission?pool=0&by-id=true",
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 403);
}
