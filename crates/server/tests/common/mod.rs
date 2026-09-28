//! A TeiFS server on a local port for tests, and an SDK client for it.

#![allow(dead_code, reason = "each test binary uses a different part")]

use aws_sdk_s3::{
    Client,
    config::{Credentials, Region},
};
use teifs_server::{Config, Credentials as DriveCredentials, Server as TeiFS};
use tempfile::TempDir;
use tokio::sync::oneshot;

pub const ACCESS_KEY: &str = "teifs-test";
pub const SECRET_KEY: &str = "not-a-real-secret-only-for-tests";

pub struct Server {
    pub dir: TempDir,
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
        limits: teifs_server::Limits::default(),
    };
    adjust(&mut config);
    let server = TeiFS::bind(config).await.unwrap();
    let endpoint = format!("http://{}", server.local_addr().unwrap());
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    Server {
        dir,
        _keys: keys,
        endpoint,
        _stop: stop,
    }
}

pub fn client(server: &Server, secret: &str) -> Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .endpoint_url(&server.endpoint)
        .credentials_provider(Credentials::new(ACCESS_KEY, secret, None, None, "tests"))
        .force_path_style(true)
        .build();
    Client::from_conf(config)
}
