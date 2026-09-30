//! TeiFS's admin API, called as any Signature V4 tool calls it: what it reports, who may
//! call it, and that it never takes a bucket's keys.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::{Duration, Instant};

use aws_sdk_s3::primitives::ByteStream;
use teifs_types::admin::{
    ADMIN_CONFIG, ADMIN_IAM, ADMIN_IAM_SECRETS, ADMIN_INFO, ADMIN_ROOT_KEY, ADMIN_SNAPSHOTS,
    AdminError, IamExport, ImportReport, KmsConfig, RootKeyRotated, ServerConfig, ServerInfo,
    Snapshot,
};

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, client_as, start, start_with, user};
use signing::{signed, signed_response};

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
        config.jobs.scrub_every = Some(std::time::Duration::from_hours(24));
        config.jobs.snapshots = 0;
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
    assert_eq!(config.scrub_every_seconds, Some(86_400));
    assert_eq!(config.snapshots, 0);
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

const READER: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:ListAllMyBuckets","s3:ListBucket"],"Resource":"*"}}"#;

async fn import(server: &Server, query: &str, body: &[u8]) -> (u16, String) {
    let path = format!("{ADMIN_IAM}{query}");
    signed(server, ROOT, "PUT", &path, &[], body).await
}

#[tokio::test]
async fn iam_moves_to_another_server_and_its_keys_keep_working() {
    let (from, to) = (start().await, start().await);
    user(&from, "reader", Some(READER));
    let key = from.iam.create_access_key("reader").unwrap();
    client(&from, SECRET_KEY)
        .create_bucket()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    let (status, exported) = get(&from, ROOT, ADMIN_IAM_SECRETS).await;
    assert_eq!(status, 200, "{exported}");
    assert!(exported.contains(key.secret.as_str()));

    let (status, answer) = import(&to, "?account=adopt", exported.as_bytes()).await;
    assert_eq!(status, 200, "{answer}");
    let report: ImportReport = serde_json::from_str(&answer).unwrap();
    assert_eq!((report.users, report.access_keys), (1, 2));
    assert_eq!(report.account, from.iam.account());
    assert_eq!(to.iam.account(), from.iam.account());
    // The user signs on the new server with the same key, with the same permissions.
    to.iam.create_user("someone-else", None, &[], None).unwrap();
    client(&to, SECRET_KEY)
        .create_bucket()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    let reader = client_as(&to, &key.info.id, &key.secret);
    let listed = reader.list_objects_v2().bucket("photos").send().await;
    assert!(listed.is_ok(), "{listed:?}");
    let put = reader.create_bucket().bucket("other").send().await;
    assert_eq!(common::code(put), "AccessDenied");
    // Exports without secrets match, but for the user created since.
    let (_, before) = get(&from, ROOT, ADMIN_IAM).await;
    let (_, after) = get(&to, ROOT, ADMIN_IAM).await;
    let (before, mut after): (IamExport, IamExport) = (
        serde_json::from_str(&before).unwrap(),
        serde_json::from_str(&after).unwrap(),
    );
    after.users.retain(|u| u.name != "someone-else");
    assert_eq!(before, after);
}

#[tokio::test]
async fn only_the_root_user_sees_secrets_or_imports() {
    let server = start().await;
    let everything = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["teifs:*","iam:*"],"Resource":"*"}}"#;
    user(&server, "admin", Some(everything));
    let admin = server.iam.create_access_key("admin").unwrap();
    let admin = (admin.info.id.as_str(), admin.secret.as_str());
    let (status, answer) = get(&server, admin, ADMIN_IAM).await;
    assert_eq!(status, 200, "{answer}");
    assert!(!answer.contains("\"secret\""), "{answer}");
    let (status, answer) = get(&server, admin, ADMIN_IAM_SECRETS).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (403, "AccessDenied")
    );
    let (status, answer) = signed(&server, admin, "PUT", ADMIN_IAM, &[], answer.as_bytes()).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (403, "AccessDenied")
    );
    // The root user's export isn't kept by caches on the way.
    let answer = signed_response(&server, ROOT, "GET", ADMIN_IAM_SECRETS, &[], b"").await;
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(answer.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn imports_are_checked_before_anything_changes() {
    let server = start().await;
    let (_, empty) = get(&server, ROOT, ADMIN_IAM_SECRETS).await;
    let (status, answer) = import(&server, "", b"{not json").await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (400, "MalformedJSON")
    );
    let (status, answer) = import(&server, "?account=take", empty.as_bytes()).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (400, "InvalidArgument")
    );
    let mut export: IamExport = serde_json::from_str(&empty).unwrap();
    export.format = "teifs-iam/9".into();
    let body = serde_json::to_vec(&export).unwrap();
    let (status, answer) = import(&server, "", &body).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (400, "InvalidInput")
    );
    // A user whose policy doesn't parse: nothing is made.
    let with_user = r#"{"format":"teifs-iam/1","account":"123456789012","policies":[],"groups":[],
        "users":[{"name":"a","path":"/"},{"name":"b","path":"/","inline":{"p":"{}"}}]}"#;
    let (status, answer) = import(&server, "", with_user.as_bytes()).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (400, "MalformedPolicyDocument")
    );
    assert!(server.iam.users(None).unwrap().is_empty());
    // Into an IAM that has users, never.
    server.iam.create_user("carol", None, &[], None).unwrap();
    let (status, answer) = import(&server, "", empty.as_bytes()).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (409, "EntityAlreadyExists")
    );
    let (_, now) = get(&server, ROOT, ADMIN_IAM_SECRETS).await;
    assert!(now.contains("carol"));
}

#[tokio::test]
async fn a_generated_root_key_is_replaced_at_once_and_on_the_drive() {
    let server = start_with(|config| config.credentials = None).await;
    let old = teifs_server::credentials::load(server.dir.path())
        .unwrap()
        .unwrap();
    let old = (old.access_key.as_str(), old.secret_key.as_str());
    user(
        &server,
        "admin",
        Some(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"teifs:*","Resource":"*"}}"#,
        ),
    );
    let admin = server.iam.create_access_key("admin").unwrap();
    let admin = (admin.info.id.as_str(), admin.secret.as_str());
    let (status, answer) = signed(&server, admin, "POST", ADMIN_ROOT_KEY, &[], b"").await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (403, "AccessDenied")
    );

    let answer = signed_response(&server, old, "POST", ADMIN_ROOT_KEY, &[], b"").await;
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(answer.headers()["cache-control"], "no-store");
    let new: RootKeyRotated = answer.json().await.unwrap();
    assert_ne!(new.access_key, old.0);
    // The drive keeps the new key for the next start...
    let kept = teifs_server::credentials::load(server.dir.path())
        .unwrap()
        .unwrap();
    assert_eq!(
        (kept.access_key.as_str(), kept.secret_key.as_str()),
        (new.access_key.as_str(), new.secret_key.as_str())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = teifs_server::credentials::path(server.dir.path());
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // ...the old one stops working now, and users' keys keep working.
    let refused = client_as(&server, old.0, old.1).list_buckets().send().await;
    assert_eq!(common::code(refused), "InvalidAccessKeyId");
    let root = client_as(&server, &new.access_key, &new.secret_key);
    root.create_bucket().bucket("photos").send().await.unwrap();
    let new = (new.access_key.as_str(), new.secret_key.as_str());
    assert_eq!(get(&server, new, ADMIN_INFO).await.0, 200);
    assert_eq!(get(&server, admin, ADMIN_INFO).await.0, 200);
}

#[tokio::test]
async fn a_given_root_key_is_changed_where_it_was_given() {
    let server = start().await;
    let (status, answer) = signed(&server, ROOT, "POST", ADMIN_ROOT_KEY, &[], b"").await;
    let answer = error(&answer);
    assert_eq!(
        (status, answer.code.as_str()),
        (409, "RootKeyManagedElsewhere")
    );
    assert!(answer.message.contains("environment"), "{}", answer.message);
    assert_eq!(get(&server, ROOT, ADMIN_INFO).await.0, 200);
    assert!(
        teifs_server::credentials::load(server.dir.path())
            .unwrap()
            .is_none()
    );
}

/// Temporary credentials from STS, asked for by `key`: the access key, secret and token.
async fn temporary(
    server: &Server,
    key: (&str, &str),
    ask: impl AsyncFnOnce(&aws_sdk_sts::Client) -> Option<aws_sdk_sts::types::Credentials>,
) -> (String, String, String) {
    let sts = aws_sdk_sts::Client::from_conf(
        aws_sdk_sts::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_sts::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .credentials_provider(aws_sdk_sts::config::Credentials::new(
                key.0, key.1, None, None, "tests",
            ))
            .build(),
    );
    let credentials = ask(&sts).await.unwrap();
    (
        credentials.access_key_id().to_owned(),
        credentials.secret_access_key().to_owned(),
        credentials.session_token().to_owned(),
    )
}

#[tokio::test]
async fn role_sessions_manage_the_drive_and_other_sessions_do_not() {
    let server = start().await;
    let account = server.iam.account();
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{account}"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    server
        .iam
        .create_role(
            "operator",
            &teifs_iam::NewRole {
                trust: &trust,
                ..teifs_iam::NewRole::default()
            },
        )
        .unwrap();
    let info_only = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["teifs:GetServerInfo","sts:AssumeRole"],"Resource":"*"}}"#;
    server
        .iam
        .put_inline(teifs_iam::Owner::Role("operator"), "info", info_only)
        .unwrap();
    user(&server, "ops", Some(info_only));
    let ops = server.iam.create_access_key("ops").unwrap();
    let ops = (ops.info.id.as_str(), ops.secret.as_str());
    let role = format!("arn:aws:iam::{account}:role/operator");

    let (id, secret, token) = temporary(&server, ops, async |sts| {
        let out = sts
            .assume_role()
            .role_arn(&role)
            .role_session_name("ops-1")
            .send()
            .await;
        out.unwrap().credentials
    })
    .await;
    let session = (id.as_str(), secret.as_str());
    let with_token = [("x-amz-security-token", token.as_str())];
    let (status, _) = signed(&server, session, "GET", ADMIN_INFO, &with_token, b"").await;
    assert_eq!(status, 200);
    let (status, answer) = signed(&server, session, "GET", ADMIN_CONFIG, &with_token, b"").await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (403, "AccessDenied")
    );
    // Without its token, or with a wrong one, the key isn't accepted.
    let (status, _) = get(&server, session, ADMIN_INFO).await;
    assert_eq!(status, 400);
    let wrong = [("x-amz-security-token", "Zm9v")];
    let (status, _) = signed(&server, session, "GET", ADMIN_INFO, &wrong, b"").await;
    assert_eq!(status, 400);

    // GetSessionToken's credentials don't manage the drive, even the root user's.
    for key in [ops, ROOT] {
        let (id, secret, token) = temporary(&server, key, async |sts| {
            sts.get_session_token().send().await.unwrap().credentials
        })
        .await;
        let with_token = [("x-amz-security-token", token.as_str())];
        let (status, _) = signed(
            &server,
            (id.as_str(), secret.as_str()),
            "GET",
            ADMIN_INFO,
            &with_token,
            b"",
        )
        .await;
        assert_eq!(status, 403, "{}", key.0);
    }
}

#[tokio::test]
async fn snapshots_are_taken_on_request_and_listed() {
    let server = start().await;
    let (status, answer) = signed(&server, ROOT, "POST", ADMIN_SNAPSHOTS, &[], b"").await;
    assert_eq!(status, 200, "{answer}");
    let taken: Snapshot = serde_json::from_str(&answer).unwrap();
    assert!(taken.bytes > 0);
    let copy = server
        .dir
        .path()
        .join(".teifs/backups/auto")
        .join(&taken.name);
    assert!(copy.join("system.db").is_file() && copy.join("index.db").is_file());
    let (status, answer) = get(&server, ROOT, ADMIN_SNAPSHOTS).await;
    assert_eq!(status, 200, "{answer}");
    let listed: Vec<Snapshot> = serde_json::from_str(&answer).unwrap();
    assert!(listed.contains(&taken), "{answer}");
    // Listing and taking are separate permissions.
    let list_only = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"teifs:ListSnapshots","Resource":"*"}}"#;
    user(&server, "auditor", Some(list_only));
    let auditor = server.iam.create_access_key("auditor").unwrap();
    let auditor = (auditor.info.id.as_str(), auditor.secret.as_str());
    assert_eq!(get(&server, auditor, ADMIN_SNAPSHOTS).await.0, 200);
    let (status, answer) = signed(&server, auditor, "POST", ADMIN_SNAPSHOTS, &[], b"").await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (403, "AccessDenied")
    );
}
