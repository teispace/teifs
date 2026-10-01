//! A TeiFS server on a local port for tests, and an SDK client for it.

#![allow(dead_code, reason = "each test binary uses a different part")]

pub mod certs;
pub mod idp;

use aws_sdk_s3::{
    Client,
    config::{Credentials, Region},
    error::ProvideErrorMetadata,
};
use teifs_server::{Config, Credentials as DriveCredentials, Server as TeiFS};
use tempfile::TempDir;
use tokio::sync::oneshot;

pub const ACCESS_KEY: &str = "teifs-test";
pub const SECRET_KEY: &str = "not-a-real-secret-only-for-tests";

pub struct Server {
    pub dir: TempDir,
    pub iam: std::sync::Arc<teifs_iam::Iam>,
    _keys: TempDir,
    pub endpoint: String,
    /// The listener's TLS, when it serves HTTPS.
    pub tls: Option<std::sync::Arc<teifs_server::Tls>>,
    _stop: oneshot::Sender<()>,
}

pub async fn start() -> Server {
    start_with(|_| {}).await
}

/// A server's configuration: its drive in `dir`, its keyring in `keys`.
pub fn config(dir: &std::path::Path, keys: &std::path::Path) -> Config {
    Config {
        dir: dir.to_owned(),
        listen: "127.0.0.1:0".parse().unwrap(),
        domains: Vec::new(),
        website_domains: Vec::new(),
        notify: Vec::new(),
        access_log_interval: None,
        credentials: Some(DriveCredentials {
            access_key: ACCESS_KEY.into(),
            secret_key: SECRET_KEY.into(),
        }),
        default_layout: teifs_store::Layout::Folder,
        kms_keyring: Some(keys.join("keyring.json")),
        kms_external: None,
        kms_default_key: None,
        allow_sse_c: true,
        plain_http_is_secure: None,
        tls: None,
        trusted_proxies: teifs_server::TrustedProxies::default(),
        jobs: teifs_server::JobOptions::default(),
        durability: teifs_server::Durability::Strict,
        key_rules: teifs_server::KeyRules::Portable,
        lifecycle_day: None,
        allow_sig_v2: false,
        legacy_bucket_defaults: false,
        public_metrics: false,
        audit: Vec::new(),
        limits: teifs_server::Limits::default(),
        ldap: None,
        client_certificates: None,
        identity_plugin: None,
        openid: Vec::new(),
    }
}

/// A server whose configuration `adjust` changes first.
pub async fn start_with(adjust: impl FnOnce(&mut Config)) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let mut config = config(dir.path(), keys.path());
    adjust(&mut config);
    // Boxed: a server's start is a large future, and so would every test's be.
    let server = Box::pin(TeiFS::bind(config)).await.unwrap();
    let endpoint = format!("{}://{}", server.scheme(), server.local_addr().unwrap());
    let iam = server.iam().clone();
    let tls = server.tls().cloned();
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    Server {
        dir,
        iam,
        _keys: keys,
        endpoint,
        tls,
        _stop: stop,
    }
}

pub fn client(server: &Server, secret: &str) -> Client {
    client_as(server, ACCESS_KEY, secret)
}

/// A client signing with another access key (an IAM user's).
pub fn client_as(server: &Server, access_key: &str, secret: &str) -> Client {
    client_at(&server.endpoint, access_key, secret)
}

/// A client of the server at `endpoint`.
pub fn client_at(endpoint: &str, access_key: &str, secret: &str) -> Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .credentials_provider(Credentials::new(access_key, secret, None, None, "tests"))
        .force_path_style(true)
        .build();
    Client::from_conf(config)
}

/// The error code of a failed SDK call, or `ok`.
pub fn code<T, E: ProvideErrorMetadata>(result: Result<T, E>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(err) => err.code().unwrap_or("?").to_owned(),
    }
}

/// A user with an optional inline policy, and a client signing as them.
pub fn user(server: &Server, name: &str, identity_policy: Option<&str>) -> Client {
    server.iam.create_user(name, None, &[], None).unwrap();
    if let Some(identity_policy) = identity_policy {
        server
            .iam
            .put_inline(teifs_iam::Owner::User(name), "policy", identity_policy)
            .unwrap();
    }
    let key = server.iam.create_access_key(name).unwrap();
    client_as(server, &key.info.id, &key.secret)
}

/// The status of an unsigned request.
pub async fn anonymous(server: &Server, method: reqwest::Method, path: &str) -> u16 {
    reqwest::Client::new()
        .request(method, format!("{}{path}", server.endpoint))
        .header("x-amz-object-attributes", "ETag")
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Runs each test (an `async fn(Layout)`) on a drive whose new buckets are object
/// buckets, and on one whose new buckets are folder buckets.
#[allow(unused_macros, reason = "only some tests run in both layouts")]
macro_rules! in_both_layouts {
    ($($name:ident),* $(,)?) => {$(
        mod $name {
            #[tokio::test]
            async fn object_bucket() {
                super::$name(teifs_store::Layout::Object).await;
            }

            #[tokio::test]
            async fn folder_bucket() {
                super::$name(teifs_store::Layout::Folder).await;
            }
        }
    )*};
}

/// A Signature Version 2 presigned link for `method` on `path` (with its query, if any),
/// signed over `resource`, as boto3 makes by default.
#[allow(dead_code, reason = "not every test file signs with Signature V2")]
pub fn sig_v2_link(server: &Server, method: &str, path: &str, resource: &str) -> String {
    use aws_lc_rs::hmac;
    use base64::Engine as _;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let signed = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, SECRET_KEY.as_bytes()),
        format!("{method}\n\n\n{expires}\n{resource}").as_bytes(),
    );
    let signature = base64::engine::general_purpose::STANDARD.encode(signed.as_ref());
    let signature: String = signature
        .bytes()
        .map(|b| match b {
            b'+' => "%2B".to_owned(),
            b'/' => "%2F".to_owned(),
            b'=' => "%3D".to_owned(),
            b => char::from(b).to_string(),
        })
        .collect();
    let join = if path.contains('?') { '&' } else { '?' };
    format!(
        "{}{path}{join}AWSAccessKeyId={ACCESS_KEY}&Expires={expires}&Signature={signature}",
        server.endpoint
    )
}

/// Waits until the server counts `count` events sent to the notification target
/// `arn:teifs:sqs::ID:KIND`.
pub async fn sent(server: &Server, kind: &str, id: &str, count: u64) {
    let token = teifs_iam::metrics_token(ACCESS_KEY, SECRET_KEY, None);
    let wanted =
        format!("teifs_notify_sent_total{{target=\"arn:teifs:sqs::{id}:{kind}\"}} {count}\n");
    let mut scraped = String::new();
    for _ in 0..300 {
        scraped = reqwest::Client::new()
            .get(format!(
                "{}{}",
                server.endpoint,
                teifs_types::admin::METRICS_PATH
            ))
            .bearer_auth(token.as_str())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        if scraped.contains(&wanted) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("{id} never sent {count} events: {scraped}");
}
