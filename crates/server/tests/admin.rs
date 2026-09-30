//! TeiFS's admin API, called as any Signature V4 tool calls it: what it reports, who may
//! call it, and that it never takes a bucket's keys.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::{Duration, Instant};

use aws_sdk_s3::primitives::ByteStream;
use teifs_types::admin::{
    ADMIN_BUCKETS, ADMIN_CONFIG, ADMIN_IAM, ADMIN_IAM_SECRETS, ADMIN_INFO, ADMIN_ROOT_KEY,
    ADMIN_SNAPSHOTS, AdminError, BUCKETS_EXPORT_FORMAT, BucketsExport, BucketsImportReport,
    ExportedBucket, IamExport, ImportReport, KmsConfig, RootKeyRotated, ServerConfig, ServerInfo,
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

/// Sets `bucket` up through S3 with a setting of every kind.
async fn configured(server: &Server, bucket: &str) {
    use aws_sdk_s3::types::{
        BucketLifecycleConfiguration, CorsConfiguration, CorsRule, DefaultRetention,
        ExpirationStatus, LifecycleExpiration, LifecycleRule, LifecycleRuleFilter,
        ObjectLockConfiguration, ObjectLockEnabled, ObjectLockRetentionMode, ObjectLockRule, Tag,
        Tagging,
    };
    let s3 = client(server, SECRET_KEY);
    s3.create_bucket()
        .bucket(bucket)
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
    s3.put_object_lock_configuration()
        .bucket(bucket)
        .object_lock_configuration(
            ObjectLockConfiguration::builder()
                .object_lock_enabled(ObjectLockEnabled::Enabled)
                .rule(
                    ObjectLockRule::builder()
                        .default_retention(
                            DefaultRetention::builder()
                                .mode(ObjectLockRetentionMode::Governance)
                                .days(3)
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    s3.put_bucket_tagging()
        .bucket(bucket)
        .tagging(
            Tagging::builder()
                .tag_set(Tag::builder().key("team").value("ops").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    s3.put_bucket_cors()
        .bucket(bucket)
        .cors_configuration(
            CorsConfiguration::builder()
                .cors_rules(
                    CorsRule::builder()
                        .allowed_methods("GET")
                        .allowed_origins("https://example.com")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    s3.put_bucket_lifecycle_configuration()
        .bucket(bucket)
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(
                    LifecycleRule::builder()
                        .id("old-logs")
                        .status(ExpirationStatus::Enabled)
                        .filter(LifecycleRuleFilter::builder().prefix("logs/").build())
                        .expiration(LifecycleExpiration::builder().days(30).build())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::{bucket}"}}]}}"#
    );
    s3.put_bucket_policy()
        .bucket(bucket)
        .policy(policy)
        .send()
        .await
        .unwrap();
}

fn items(report: &BucketsImportReport) -> Vec<(&str, &str)> {
    report
        .items
        .iter()
        .map(|i| (i.item.as_str(), i.outcome.as_str()))
        .collect()
}

#[tokio::test]
async fn buckets_move_to_another_drive_with_their_settings() {
    let from = start().await;
    configured(&from, "logs").await;
    client(&from, SECRET_KEY)
        .create_bucket()
        .bucket("plain")
        .send()
        .await
        .unwrap();
    let (status, answer) = get(&from, ROOT, ADMIN_BUCKETS).await;
    assert_eq!(status, 200, "{answer}");
    let export: BucketsExport = serde_json::from_str(&answer).unwrap();
    assert_eq!(export.format, BUCKETS_EXPORT_FORMAT);
    let names: Vec<&str> = export.buckets.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, ["logs", "plain"]);
    let logs = &export.buckets[0];
    // The test server's default layout.
    assert_eq!(
        (logs.versioning.as_str(), logs.layout.as_str()),
        ("enabled", "folder")
    );
    // One bucket alone.
    let (status, one) = get(&from, ROOT, &format!("{ADMIN_BUCKETS}?bucket=plain")).await;
    assert_eq!(status, 200, "{one}");
    let one: BucketsExport = serde_json::from_str(&one).unwrap();
    assert_eq!(one.buckets, export.buckets[1..]);
    let (status, missing) = get(&from, ROOT, &format!("{ADMIN_BUCKETS}?bucket=nope")).await;
    assert_eq!(
        (status, error(&missing).code.as_str()),
        (404, "NoSuchBucket")
    );

    let to = start().await;
    let body = serde_json::to_vec(&export).unwrap();
    let (status, answer) = signed(&to, ROOT, "PUT", ADMIN_BUCKETS, &[], &body).await;
    assert_eq!(status, 200, "{answer}");
    let report: BucketsImportReport = serde_json::from_str(&answer).unwrap();
    assert!(
        report.items.iter().all(|i| i.outcome != "failed"),
        "{answer}"
    );
    assert!(items(&report).contains(&("bucket", "created")));
    assert!(items(&report).contains(&("lifecycle", "applied")));
    // The other drive now exports the same.
    let (_, again) = get(&to, ROOT, ADMIN_BUCKETS).await;
    let again: BucketsExport = serde_json::from_str(&again).unwrap();
    assert_eq!(again.buckets, export.buckets);
    // And S3 answers with it.
    let s3 = client(&to, SECRET_KEY);
    let lock = s3
        .get_object_lock_configuration()
        .bucket("logs")
        .send()
        .await
        .unwrap();
    let retention = lock.object_lock_configuration().unwrap().rule().unwrap();
    assert_eq!(retention.default_retention().unwrap().days(), Some(3));
    let tags = s3.get_bucket_tagging().bucket("logs").send().await.unwrap();
    assert_eq!(tags.tag_set()[0].value(), "ops");

    // Again onto the same drive: nothing to create, everything applied.
    let (status, answer) = signed(&to, ROOT, "PUT", ADMIN_BUCKETS, &[], &body).await;
    assert_eq!(status, 200, "{answer}");
    let report: BucketsImportReport = serde_json::from_str(&answer).unwrap();
    assert!(!items(&report).contains(&("bucket", "created")), "{answer}");
    assert!(
        report.items.iter().all(|i| i.outcome == "applied"),
        "{answer}"
    );
}

#[tokio::test]
async fn an_import_checks_each_setting_as_s3_does() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    for bucket in ["here", "versioned"] {
        s3.create_bucket().bucket(bucket).send().await.unwrap();
    }
    s3.put_bucket_versioning()
        .bucket("versioned")
        .versioning_configuration(
            aws_sdk_s3::types::VersioningConfiguration::builder()
                .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let export = serde_json::json!({
        "format": BUCKETS_EXPORT_FORMAT,
        "exportedMs": 0,
        "buckets": [
            {
                "name": "here",
                "layout": "object",
                "versioning": "unversioned",
                "settings": {
                    // Names another bucket.
                    "policy": r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::elsewhere"}]}"#,
                    "tags": {"": "no key"},
                    "shinyNewThing": true,
                }
            },
            {
                "name": "versioned",
                "layout": "folder",
                "versioning": "unversioned",
                "settings": {"objectLock": {"defaultRetention": {"mode": "GOVERNANCE", "period": {"days": 0}}}}
            },
            {"name": "Bad_Name", "layout": "object", "versioning": "unversioned"},
            {"name": "sideways", "layout": "diagonal", "versioning": "unversioned"},
            {
                "name": "fresh",
                "layout": "object",
                "versioning": "enabled",
                "settings": {"cors": [{"allowedMethods": ["FETCH"], "allowedOrigins": ["*"]}]}
            },
        ]
    });
    let body = serde_json::to_vec(&export).unwrap();
    let (status, answer) = signed(&server, ROOT, "PUT", ADMIN_BUCKETS, &[], &body).await;
    assert_eq!(status, 200, "{answer}");
    let report: BucketsImportReport = serde_json::from_str(&answer).unwrap();
    let outcomes: Vec<(&str, &str, &str)> = report
        .items
        .iter()
        .map(|i| (i.bucket.as_str(), i.item.as_str(), i.outcome.as_str()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("here", "layout", "failed"),
            ("here", "versioning", "applied"),
            ("here", "tags", "failed"),
            ("here", "policy", "failed"),
            ("here", "shinyNewThing", "failed"),
            ("versioned", "versioning", "failed"),
            ("versioned", "objectLock", "failed"),
            ("Bad_Name", "bucket", "failed"),
            ("sideways", "bucket", "failed"),
            ("fresh", "bucket", "created"),
            ("fresh", "versioning", "applied"),
            ("fresh", "cors", "failed"),
        ],
        "{answer}"
    );
    assert!(
        report
            .items
            .iter()
            .all(|i| (i.outcome == "failed") == i.error.is_some())
    );
    assert!(s3.get_bucket_policy().bucket("here").send().await.is_err());
}

#[tokio::test]
async fn an_import_is_refused_whole_or_not_allowed() {
    let server = start().await;
    // Another format, or not an export at all, is refused whole.
    let later = serde_json::json!({"format": 2, "exportedMs": 0, "buckets": []});
    let body = serde_json::to_vec(&later).unwrap();
    let (status, answer) = signed(&server, ROOT, "PUT", ADMIN_BUCKETS, &[], &body).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (400, "UnsupportedFormat")
    );
    let (status, answer) = signed(&server, ROOT, "PUT", ADMIN_BUCKETS, &[], b"[]").await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (400, "MalformedJSON")
    );

    // Exporting and importing are separate permissions.
    let export_only = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"teifs:ExportBucketMetadata","Resource":"*"}}"#;
    user(&server, "archivist", Some(export_only));
    let archivist = server.iam.create_access_key("archivist").unwrap();
    let archivist = (archivist.info.id.as_str(), archivist.secret.as_str());
    assert_eq!(get(&server, archivist, ADMIN_BUCKETS).await.0, 200);
    let (status, answer) = signed(&server, archivist, "PUT", ADMIN_BUCKETS, &[], &body).await;
    assert_eq!(
        (status, error(&answer).code.as_str()),
        (403, "AccessDenied")
    );
}

#[tokio::test]
async fn access_settings_and_encryption_move_too() {
    use aws_sdk_s3::types::{
        BucketCannedAcl, ServerSideEncryption, ServerSideEncryptionByDefault,
        ServerSideEncryptionConfiguration, ServerSideEncryptionRule,
    };
    let object = |config: &mut teifs_server::Config| {
        config.default_layout = teifs_store::Layout::Object;
    };
    let from = start_with(object).await;
    let s3 = client(&from, SECRET_KEY);
    s3.create_bucket()
        .bucket("shared")
        .object_ownership(aws_sdk_s3::types::ObjectOwnership::ObjectWriter)
        .send()
        .await
        .unwrap();
    s3.delete_public_access_block()
        .bucket("shared")
        .send()
        .await
        .unwrap();
    s3.put_bucket_acl()
        .bucket("shared")
        .acl(BucketCannedAcl::PublicRead)
        .send()
        .await
        .unwrap();
    s3.put_bucket_encryption()
        .bucket("shared")
        .server_side_encryption_configuration(
            ServerSideEncryptionConfiguration::builder()
                .rules(
                    ServerSideEncryptionRule::builder()
                        .apply_server_side_encryption_by_default(
                            ServerSideEncryptionByDefault::builder()
                                .sse_algorithm(ServerSideEncryption::AwsKms)
                                .build()
                                .unwrap(),
                        )
                        .bucket_key_enabled(true)
                        .build(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let (_, answer) = get(&from, ROOT, ADMIN_BUCKETS).await;
    let mut export: BucketsExport = serde_json::from_str(&answer).unwrap();
    // With tags that decide access (ABAC), which only TagResource changes.
    let settings = &mut export.buckets[0].settings;
    settings.insert("tags".into(), serde_json::json!({"team": "a"}));
    settings.insert("abac".into(), true.into());

    let to = start_with(object).await;
    let import = |export: &BucketsExport| {
        let body = serde_json::to_vec(export).unwrap();
        let to = &to;
        async move {
            let (status, answer) = signed(to, ROOT, "PUT", ADMIN_BUCKETS, &[], &body).await;
            assert_eq!(status, 200, "{answer}");
            serde_json::from_str::<BucketsImportReport>(&answer).unwrap()
        }
    };
    let report = import(&export).await;
    assert!(
        report.items.iter().all(|i| i.outcome != "failed"),
        "{report:?}"
    );
    let exported = |server| async move {
        let (_, answer) = get(server, ROOT, ADMIN_BUCKETS).await;
        serde_json::from_str::<BucketsExport>(&answer)
            .unwrap()
            .buckets
    };
    assert_eq!(exported(&to).await, export.buckets);
    // Tags are replaced even while ABAC is on, which stays on.
    export.buckets[0]
        .settings
        .insert("tags".into(), serde_json::json!({"team": "b"}));
    let report = import(&export).await;
    assert!(
        report.items.iter().all(|i| i.outcome != "failed"),
        "{report:?}"
    );
    assert_eq!(exported(&to).await, export.buckets);
    // Without ABAC in the export, the bucket keeps it on.
    let settings = &mut export.buckets[0].settings;
    settings.remove("abac");
    settings.insert("tags".into(), serde_json::json!({"team": "c"}));
    import(&export).await;
    export.buckets[0]
        .settings
        .insert("abac".into(), true.into());
    assert_eq!(exported(&to).await, export.buckets);
}

#[tokio::test]
async fn an_import_keeps_to_block_public_access_and_object_ownership() {
    let to = start_with(|config| config.default_layout = teifs_store::Layout::Object).await;
    let import = |export: &BucketsExport| {
        let body = serde_json::to_vec(export).unwrap();
        let to = &to;
        async move {
            let (status, answer) = signed(to, ROOT, "PUT", ADMIN_BUCKETS, &[], &body).await;
            assert_eq!(status, 200, "{answer}");
            serde_json::from_str::<BucketsImportReport>(&answer).unwrap()
        }
    };
    // A public ACL where Block Public Access refuses it.
    client(&to, SECRET_KEY)
        .create_bucket()
        .bucket("guarded")
        .object_ownership(aws_sdk_s3::types::ObjectOwnership::ObjectWriter)
        .send()
        .await
        .unwrap();
    // public-read.
    let acl = serde_json::json!({"grants": [
        {"grantee": "owner", "permission": "FULL_CONTROL"},
        {"grantee": "allUsers", "permission": "READ"},
    ]});
    let mut guarded = ExportedBucket {
        name: "guarded".into(),
        layout: "object".into(),
        versioning: "unversioned".into(),
        settings: serde_json::Map::new(),
    };
    guarded.settings.insert("acl".into(), acl);
    let mut export = BucketsExport {
        format: BUCKETS_EXPORT_FORMAT,
        exported_ms: 0,
        buckets: Vec::new(),
    };
    // And a public policy.
    let public = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::guarded/*"}]}"#;
    guarded.settings.insert("policy".into(), public.into());
    export.buckets = vec![guarded.clone()];
    let report = import(&export).await;
    let failed = |item: &str| {
        let found = report.items.iter().find(|i| i.item == item).unwrap();
        assert_eq!(found.outcome, "failed", "{found:?}");
        found.error.clone().unwrap()
    };
    assert!(failed("acl").contains("BlockPublicAcls"));
    assert!(failed("policy").contains("BlockPublicPolicy"));
    // Read (and so cached) by S3 first, then opened up by the import: the ACL follows
    // the Block Public Access it imported, not the one read before.
    let s3 = client(&to, SECRET_KEY);
    s3.get_bucket_acl().bucket("guarded").send().await.unwrap();
    let mut open = export.clone();
    open.buckets[0].settings.remove("policy");
    open.buckets[0].settings.insert(
        "publicAccessBlock".into(),
        serde_json::json!({"blockPublicAcls": false, "blockPublicPolicy": false, "ignorePublicAcls": false, "restrictPublicBuckets": false}),
    );
    let report = import(&open).await;
    assert!(
        report.items.iter().all(|i| i.outcome == "applied"),
        "{report:?}"
    );
    let mut guarded = open.buckets[0].clone();
    // ACLs that grant others where Object Ownership disables them.
    guarded
        .settings
        .insert("ownership".into(), "BucketOwnerEnforced".into());
    export.buckets = vec![guarded];
    let report = import(&export).await;
    let refused: Vec<&str> = report
        .items
        .iter()
        .filter(|i| i.outcome == "failed")
        .map(|i| i.item.as_str())
        .collect();
    assert_eq!(refused, ["ownership", "acl"], "{report:?}");
}
