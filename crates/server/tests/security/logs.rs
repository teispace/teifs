//! Class 6: secrets never reach the logs, whatever the level.
//!
//! Also proved elsewhere: secrets are redacted in `Debug` output (`crates/crypto`,
//! `crates/iam`), the settings report leaves them out (`admin.rs`,
//! `config_reports_how_the_server_started_without_secrets`).

use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use aws_credential_types::Credentials;
use aws_sdk_s3::{operation::RequestId, primitives::ByteStream};
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use tracing_subscriber::{
    filter::{LevelFilter, filter_fn},
    fmt,
    prelude::*,
};

use crate::{
    common::{ACCESS_KEY, SECRET_KEY, Server, client, client_as, start_with},
    sign::hex,
};

/// Everything logged in this process, at every level.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn region() -> aws_sdk_s3::config::Region {
    aws_sdk_s3::config::Region::new("us-east-1")
}

fn iam(server: &Server, credentials: Credentials) -> aws_sdk_iam::Client {
    aws_sdk_iam::Client::from_conf(
        aws_sdk_iam::Config::builder()
            .behavior_version_latest()
            .region(region())
            .endpoint_url(&server.endpoint)
            .credentials_provider(credentials)
            .build(),
    )
}

fn sts(server: &Server, credentials: Credentials) -> aws_sdk_sts::Client {
    aws_sdk_sts::Client::from_conf(
        aws_sdk_sts::Config::builder()
            .behavior_version_latest()
            .region(region())
            .endpoint_url(&server.endpoint)
            .credentials_provider(credentials)
            .build(),
    )
}

fn s3(server: &Server, credentials: Credentials) -> aws_sdk_s3::Client {
    aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(region())
            .endpoint_url(&server.endpoint)
            .credentials_provider(credentials)
            .force_path_style(true)
            .build(),
    )
}

/// Today's Signature V4 signing key for `secret`, which signs as the key for a day.
fn signing_key(secret: &str) -> String {
    let key =
        aws_sigv4::sign::v4::generate_signing_key(secret, SystemTime::now(), "us-east-1", "s3");
    hex(key.as_ref())
}

/// What a secret is, and the secret.
type Secrets = Vec<(&'static str, String)>;

/// Writes and reads an object with a customer's own key: the key.
async fn sse_c(server: &Server) -> Secrets {
    let root = client(server, SECRET_KEY);
    root.create_bucket().bucket("vault").send().await.unwrap();
    let customer_key = [7u8; 32];
    let (key64, md5) = (
        STANDARD.encode(customer_key),
        STANDARD.encode(Md5::digest(customer_key)),
    );
    root.put_object()
        .bucket("vault")
        .key("sealed")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&key64)
        .sse_customer_key_md5(&md5)
        .body(ByteStream::from_static(b"sealed"))
        .send()
        .await
        .unwrap();
    root.get_object()
        .bucket("vault")
        .key("sealed")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&key64)
        .sse_customer_key_md5(&md5)
        .send()
        .await
        .unwrap();
    vec![
        ("an SSE-C key", key64),
        ("an SSE-C key, in hex", hex(&customer_key)),
    ]
}

/// Makes a user and their key through the IAM API, uses the key, then a session made
/// with it and its token: the user's key and the session's secret and token.
async fn user_and_session(server: &Server) -> (String, Secrets) {
    let admin = iam(
        server,
        Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "tests"),
    );
    admin.create_user().user_name("carol").send().await.unwrap();
    admin
        .put_user_policy()
        .user_name("carol")
        .policy_name("all")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","sts:*"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    let made = admin
        .create_access_key()
        .user_name("carol")
        .send()
        .await
        .unwrap();
    let carol_key = made.access_key().unwrap();
    let (carol_id, carol_secret) = (carol_key.access_key_id(), carol_key.secret_access_key());
    client_as(server, carol_id, carol_secret)
        .put_object()
        .bucket("vault")
        .key("carol")
        .body(ByteStream::from_static(b"hers"))
        .send()
        .await
        .unwrap();

    let carol_credentials = Credentials::new(carol_id, carol_secret, None, None, "tests");
    let session = sts(server, carol_credentials)
        .get_session_token()
        .send()
        .await
        .unwrap();
    let session = session.credentials().unwrap();
    let temporary = Credentials::new(
        session.access_key_id(),
        session.secret_access_key(),
        Some(session.session_token().to_owned()),
        None,
        "tests",
    );
    s3(server, temporary.clone())
        .list_objects_v2()
        .bucket("vault")
        .send()
        .await
        .unwrap();
    sts(server, temporary)
        .get_caller_identity()
        .send()
        .await
        .unwrap();
    (
        carol_id.to_owned(),
        vec![
            ("a user's key", carol_secret.to_owned()),
            ("a user's signing key", signing_key(carol_secret)),
            ("a session's key", session.secret_access_key().to_owned()),
            ("a session token", session.session_token().to_owned()),
        ],
    )
}

/// Exports IAM with every secret and imports it into another drive.
async fn export_and_import(server: &Server) {
    let client = |endpoint: &str| {
        teifs_client::Client::new(
            endpoint,
            ACCESS_KEY,
            teifs_client::Zeroizing::new(SECRET_KEY.to_owned()),
        )
        .unwrap()
    };
    let export = client(&server.endpoint).export_iam(true).await.unwrap();
    let other = start_with(|_| {}).await;
    client(&other.endpoint)
        .import_iam(&export, false)
        .await
        .unwrap();
}

/// CVE-2026-45040, CVE-2026-24762 and CVE-2026-22782 (RustFS: session tokens, secret
/// keys and shared secrets written to debug logs): a full cycle logged at TRACE (the
/// root key, a user's key made through IAM, a session's secret and token, an SSE-C key,
/// an IAM export with secrets, a wrong signature) leaves none of them, nor the signing
/// keys they give, in the log.
#[tokio::test]
async fn secrets_never_reach_the_logs() {
    let log = Captured::default();
    let writer = log.clone();
    // The test's own clients (the AWS SDKs, which no server crate uses) log what they
    // send, as clients; what the server logs is the subject.
    let servers_only = filter_fn(|meta| !meta.target().starts_with("aws_"));
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_filter(LevelFilter::TRACE)
                .with_filter(servers_only),
        )
        .try_init()
        .expect("this test is the only one to log");

    let server = start_with(|config| config.default_layout = teifs_store::Layout::Object).await;
    let mut secrets = vec![
        ("the root key", SECRET_KEY.to_owned()),
        ("the root key's signing key", signing_key(SECRET_KEY)),
    ];
    secrets.extend(sse_c(&server).await);
    let (carol, theirs) = user_and_session(&server).await;
    secrets.extend(theirs);
    export_and_import(&server).await;
    let wrong = client_as(&server, &carol, "a-wrong-secret-of-the-right-length-40ch");
    assert!(wrong.list_buckets().send().await.is_err());
    let listed = client(&server, SECRET_KEY)
        .list_buckets()
        .send()
        .await
        .unwrap();

    let text = log.text();
    // What's logged while answering names the request, as the answer does.
    let id = listed.request_id().unwrap();
    assert!(
        text.contains(&format!("request{{id={id}}}")),
        "{id} isn't logged"
    );
    assert!(
        text.contains("TRACE") || text.contains("DEBUG"),
        "the log was captured"
    );
    for (what, secret) in secrets {
        // Whole, or cut short.
        let start = &secret[..secret.len().min(20)];
        assert!(!text.contains(start), "{what} was logged");
    }
}
