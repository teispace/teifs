//! A TeiFS server on a local port for tests, and an SDK client for it.

#![allow(dead_code, reason = "each test binary uses a different part")]

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
    _stop: oneshot::Sender<()>,
}

pub async fn start() -> Server {
    start_with(|_| {}).await
}

/// A server whose configuration `adjust` changes first.
pub async fn start_with(adjust: impl FnOnce(&mut Config)) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let mut config = Config {
        dir: dir.path().to_owned(),
        listen: "127.0.0.1:0".parse().unwrap(),
        domains: Vec::new(),
        credentials: Some(DriveCredentials {
            access_key: ACCESS_KEY.into(),
            secret_key: SECRET_KEY.into(),
        }),
        default_layout: teifs_store::Layout::Folder,
        kms_keyring: Some(keys.path().join("keyring.json")),
        kms_transit: None,
        allow_sse_c: true,
        plain_http_is_secure: None,
        jobs: teifs_server::JobOptions::default(),
        durability: teifs_server::Durability::Strict,
        key_rules: teifs_server::KeyRules::Portable,
        allow_sig_v2: false,
        legacy_bucket_defaults: false,
        limits: teifs_server::Limits::default(),
    };
    adjust(&mut config);
    let server = TeiFS::bind(config).await.unwrap();
    let endpoint = format!("http://{}", server.local_addr().unwrap());
    let iam = server.iam().clone();
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    Server {
        dir,
        iam,
        _keys: keys,
        endpoint,
        _stop: stop,
    }
}

pub fn client(server: &Server, secret: &str) -> Client {
    client_as(server, ACCESS_KEY, secret)
}

/// A client signing with another access key (an IAM user's).
pub fn client_as(server: &Server, access_key: &str, secret: &str) -> Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .endpoint_url(&server.endpoint)
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
