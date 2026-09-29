//! TeiFS's admin API, called as any Signature V4 tool calls it: what it reports, who may
//! call it, and that it never takes a bucket's keys.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::{Duration, Instant};

use aws_sdk_s3::primitives::ByteStream;
use teifs_types::admin::{
    ADMIN_CONFIG, ADMIN_INFO, AdminError, KmsConfig, ServerConfig, ServerInfo,
};

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, start, start_with, user};
use signing::signed;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

async fn get(server: &Server, key: (&str, &str), path: &str) -> (u16, String) {
    signed(server, key, "GET", path, &[], b"").await
}

fn error(answer: &str) -> AdminError {
    serde_json::from_str(answer).unwrap_or_else(|e| panic!("{e}: {answer}"))
}

#[tokio::test]
async fn info_reports_the_drive_and_its_jobs() {
    let server = start().await;
    // The jobs start with the server; each reports once it has run a step.
    let deadline = Instant::now() + Duration::from_secs(10);
    let info = loop {
        let (status, answer) = get(&server, ROOT, ADMIN_INFO).await;
        assert_eq!(status, 200, "{answer}");
        let info: ServerInfo = serde_json::from_str(&answer).unwrap();
        if info
            .jobs
            .get("housekeeping")
            .is_some_and(|job| job.steps > 0)
        {
            break info;
        }
        assert!(Instant::now() < deadline, "no job reported: {answer}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.account, server.iam.account());
    let format = std::fs::read_to_string(server.dir.path().join(".teifs/format.json")).unwrap();
    assert!(
        !info.drive.is_empty() && format.contains(&info.drive),
        "{format}"
    );
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    assert!(info.started_ms <= now_ms && info.started_ms > now_ms - 60_000);
    assert!(info.uptime_seconds < 60);
    assert!(info.jobs.contains_key("sweep-staging"), "{:?}", info.jobs);
}

#[tokio::test]
async fn config_reports_how_the_server_started_without_secrets() {
    let server = start_with(|config| {
        config.domains = vec!["s3.test".into()];
        config.durability = teifs_server::Durability::Relaxed;
        config.default_layout = teifs_store::Layout::Object;
        config.legacy_bucket_defaults = true;
        config.jobs.upload_expiry = None;
    })
    .await;
    let (status, answer) = get(&server, ROOT, ADMIN_CONFIG).await;
    assert_eq!(status, 200, "{answer}");
    assert!(!answer.contains(SECRET_KEY), "{answer}");
    let config: ServerConfig = serde_json::from_str(&answer).unwrap();
    assert_eq!(config.domains, ["s3.test"]);
    assert_eq!(
        (
            config.durability.as_str(),
            config.default_layout.as_str(),
            config.key_names.as_str(),
            config.root_credentials.as_str()
        ),
        ("relaxed", "object", "portable", "given")
    );
    assert!(config.legacy_bucket_defaults && config.allow_sse_c && !config.allow_sig_v2);
    // Plain HTTP on loopback counts as secure.
    assert!(config.plain_http_is_secure);
    assert_eq!(config.upload_expiry_seconds, None);
    assert_eq!(config.listen, server.endpoint.trim_start_matches("http://"));
    assert!(
        matches!(config.kms, KmsConfig::Keyring { ref path } if path.ends_with("keyring.json"))
    );
    assert_eq!(
        config.max_connections,
        teifs_server::Limits::default().max_connections
    );
}

#[tokio::test]
async fn users_need_teifs_actions() {
    let server = start().await;
    let info_only = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"teifs:GetServerInfo","Resource":"*"}}"#;
    user(&server, "watcher", Some(info_only));
    let watcher = server.iam.create_access_key("watcher").unwrap();
    let watcher = (watcher.info.id.as_str(), watcher.secret.as_str());
    assert_eq!(get(&server, watcher, ADMIN_INFO).await.0, 200);
    let (status, answer) = get(&server, watcher, ADMIN_CONFIG).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (403, "AccessDenied")
    );
    // A wildcard grants both; a Deny takes one away again.
    let all_but_config = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"teifs:*","Resource":"*"},{"Effect":"Deny","Action":"teifs:GetServerConfig","Resource":"*"}]}"#;
    user(&server, "admin", Some(all_but_config));
    let admin = server.iam.create_access_key("admin").unwrap();
    let admin = (admin.info.id.as_str(), admin.secret.as_str());
    assert_eq!(get(&server, admin, ADMIN_INFO).await.0, 200);
    assert_eq!(get(&server, admin, ADMIN_CONFIG).await.0, 403);
    // s3:* isn't the admin API's.
    let s3_admin =
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}"#;
    user(&server, "storage", Some(s3_admin));
    let storage = server.iam.create_access_key("storage").unwrap();
    let storage = (storage.info.id.as_str(), storage.secret.as_str());
    assert_eq!(get(&server, storage, ADMIN_INFO).await.0, 403);
}

#[tokio::test]
async fn unknown_paths_are_not_found_and_errors_are_json() {
    let server = start().await;
    let (status, answer) = get(&server, ROOT, "/.teifs/admin/v1/nothing").await;
    assert_eq!((status, error(&answer).code.as_str()), (404, "NotFound"));
    let (status, answer) = signed(&server, ROOT, "DELETE", ADMIN_INFO, &[], b"").await;
    assert_eq!((status, error(&answer).code.as_str()), (404, "NotFound"));
    // Unsigned, even what isn't served is refused before anything else.
    for path in [ADMIN_INFO, "/.teifs/admin/v1/nothing"] {
        let answer = reqwest::get(format!("{}{path}", server.endpoint))
            .await
            .unwrap();
        assert_eq!(answer.status().as_u16(), 403);
        let answer = error(&answer.text().await.unwrap());
        assert_eq!(answer.code, "AccessDenied");
        assert!(!answer.request_id.is_empty());
    }
}

#[tokio::test]
async fn a_bucket_keeps_keys_that_look_like_the_admin_api() {
    let server = start_with(|config| config.domains = vec!["s3.test".into()]).await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    let key = ADMIN_INFO.trim_start_matches('/');
    root.put_object()
        .bucket("photos")
        .key(key)
        .body(ByteStream::from_static(b"an object"))
        .send()
        .await
        .unwrap();
    // Virtual-hosted style, the path is a key in the host's bucket.
    let port = server.endpoint.rsplit(':').next().unwrap();
    let host = format!("photos.s3.test:{port}");
    let (status, answer) = signed(&server, ROOT, "GET", ADMIN_INFO, &[("host", &host)], b"").await;
    assert_eq!((status, answer.as_str()), (200, "an object"));
    // Path style, with the domain or without, it's the admin API.
    let host = format!("s3.test:{port}");
    let (status, answer) = signed(&server, ROOT, "GET", ADMIN_INFO, &[("host", &host)], b"").await;
    assert_eq!(status, 200);
    assert!(
        serde_json::from_str::<ServerInfo>(&answer).is_ok(),
        "{answer}"
    );
}
