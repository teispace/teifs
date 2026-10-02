//! `teifs serve` with the notification and audit targets `MinIO`'s variables and settings
//! name, through the real binary.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Output, Stdio},
};

use teifs_notify::testing::Receiver;

const USER: &str = "notifier";
const PASSWORD: &str = "not-a-real-secret-only-for-tests";

/// The server, stopped when the test ends.
struct Serving(Child);

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `teifs ARGS` against alias `s`, the server at `endpoint`.
fn teifs(home: &Path, endpoint: &str, args: &[&str]) -> Output {
    let alias = endpoint.replace("http://", &format!("http://{USER}:{PASSWORD}@"));
    let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
    command
        .args(args)
        .env_clear()
        .env("TEIFS_ALIAS_S", alias)
        .env("TEIFS_CLIENT_CONFIG", home.join("aliases.toml"))
        .stdin(Stdio::null());
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn targets_minio_names_are_served() {
    let events = Receiver::start(0).await;
    let audit = Receiver::start(0).await;
    let home = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
    command
        .args([
            "--json",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--kms-keyring",
        ])
        .args([home.path().join("keys.json"), home.path().join("drive")])
        .env_clear()
        .env("MINIO_ROOT_USER", USER)
        .env("MINIO_ROOT_PASSWORD", PASSWORD)
        .env("MINIO_NOTIFY_WEBHOOK_ENABLE_HOOK", "on")
        .env("MINIO_NOTIFY_WEBHOOK_ENDPOINT_HOOK", events.url())
        .env("MINIO_NOTIFY_WEBHOOK_AUTH_TOKEN_HOOK", "t0k")
        .env("MINIO_AUDIT_WEBHOOK_ENABLE", "on")
        .env("MINIO_AUDIT_WEBHOOK_ENDPOINT", audit.url())
        .env("MINIO_AUDIT_WEBHOOK_AUTH_TOKEN", "Audit a0k")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    let mut serving = Serving(command.spawn().unwrap());
    let mut line = String::new();
    BufReader::new(serving.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let announced: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(announced["type"], "serving", "{line}");
    let endpoint = announced["endpoint"].as_str().unwrap().to_owned();
    let run = |args: &[&str]| teifs(home.path(), &endpoint, args);

    let made = run(&["mb", "s/events"]);
    assert!(made.status.success(), "{}", text(&made.stderr));
    // The rule's target is tested as it's added: with the token MinIO's variable gives.
    let added = run(&[
        "event",
        "add",
        "s/events",
        "arn:teifs:sqs::HOOK:webhook",
        "--event",
        "put",
    ]);
    assert!(added.status.success(), "{}", text(&added.stderr));
    let posts = events.posts(1).await;
    assert_eq!(posts[0].authorization, "Bearer t0k");
    let logged = audit.posts(1).await;
    assert_eq!(logged[0].authorization, "Audit a0k");

    // A target the server wouldn't start with isn't kept.
    let refused = run(&[
        "admin",
        "config",
        "set",
        "s",
        "notify_nsq:q",
        "nsqd_address=nsq.example.com:4150",
        "topic=t",
        "tls_skip_verify=on",
    ]);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    assert!(
        text(&refused.stderr).contains("notify_nsq:q in MinIO's settings"),
        "{}",
        text(&refused.stderr)
    );
    let kept = run(&[
        "admin",
        "config",
        "set",
        "s",
        "notify_webhook:later",
        &format!("endpoint={}", events.url()),
        "auth_token=t1k",
    ]);
    assert!(kept.status.success(), "{}", text(&kept.stderr));
    let got = run(&["admin", "config", "get", "s", "notify_webhook"]);
    let got = text(&got.stdout);
    assert!(
        got.contains("notify_webhook:later endpoint=")
            && !got.contains("t0k")
            && !got.contains("t1k"),
        "{got}"
    );
}

#[test]
fn minio_s_root_access_off_refuses_the_root_key() {
    let home = tempfile::tempdir().unwrap();
    let serve = |root_access: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
        command
            .args(["--json", "serve", "--listen", "127.0.0.1:0"])
            .arg(home.path().join("drive"))
            .env_clear()
            .env("MINIO_ROOT_USER", USER)
            .env("MINIO_ROOT_PASSWORD", PASSWORD)
            .env("MINIO_API_ROOT_ACCESS", root_access)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        command
    };

    // A value MinIO wouldn't take stops the server before it starts.
    let refused = serve("maybe").output().unwrap();
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    assert!(
        text(&refused.stderr).contains("api root_access"),
        "{}",
        text(&refused.stderr)
    );

    let mut serving = Serving(serve("off").spawn().unwrap());
    let mut line = String::new();
    BufReader::new(serving.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let announced: serde_json::Value = serde_json::from_str(&line).unwrap();
    let endpoint = announced["endpoint"].as_str().unwrap();
    let listed = teifs(home.path(), endpoint, &["ls", "s"]);
    assert!(!listed.status.success());
    assert!(
        text(&listed.stderr).contains("InvalidAccessKeyId"),
        "{}",
        text(&listed.stderr)
    );
}
