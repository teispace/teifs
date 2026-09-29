//! `teifs serve` over HTTPS through the real binary: certificates from a folder or
//! files (also named in the settings file), the announced `https://` endpoint, `teifs
//! health` against it, reloading on SIGHUP, and certificates refused before starting.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;

use std::{
    fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use common::certs::Authority;

fn teifs(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
    command
        .env_clear()
        .env("TEIFS_CLIENT_CONFIG", home.join("aliases.toml"))
        .envs(std::env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
        .stdin(Stdio::null());
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    teifs(home).args(args).output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `teifs --json serve` on a free port with `args`: the process and its endpoint.
fn serve(home: &Path, args: &[&str]) -> (Child, String) {
    let mut child = teifs(home)
        .args([
            "--json",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--kms-keyring",
        ])
        .arg(home.join("keys.json"))
        .arg(home.join("drive"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let serving: serde_json::Value = serde_json::from_str(&line).unwrap();
    (child, serving["endpoint"].as_str().unwrap().to_owned())
}

fn address(endpoint: &str) -> SocketAddr {
    endpoint.strip_prefix("https://").unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_speaks_https_and_reloads_its_certificates() {
    let home = tempfile::tempdir().unwrap();
    let ca = Authority::new();
    let certs = home.path().join("certs");
    let first = ca.issue_into(&certs, &["127.0.0.1", "localhost"]);
    let (mut child, endpoint) = serve(home.path(), &["--certs-dir", certs.to_str().unwrap()]);
    let address = address(&endpoint);
    let (presented, _) = ca.handshake(address, "127.0.0.1", &[]).await.unwrap();
    assert_eq!(presented, first.der);

    // A container's health check: the address alone finds out it's HTTPS.
    let listen = address.to_string();
    for target in [listen.as_str(), endpoint.as_str()] {
        let healthy = run(home.path(), &["--json", "health", target]);
        assert!(healthy.status.success(), "{}", text(&healthy.stderr));
        let record: serde_json::Value = serde_json::from_slice(&healthy.stdout).unwrap();
        assert!(
            record["url"].as_str().unwrap().starts_with("https://"),
            "{record}"
        );
    }

    // New certificates, and a hangup to use them at once.
    #[cfg(unix)]
    {
        let second = ca.issue_into(&certs, &["127.0.0.1", "localhost"]);
        let hup = Command::new("kill")
            .args(["-HUP", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(hup.success());
        let started = Instant::now();
        loop {
            let (presented, _) = ca.handshake(address, "127.0.0.1", &[]).await.unwrap();
            if presented == second.der {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "not reloaded");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "SIGHUP doesn't stop it"
        );
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_files_come_from_flags_or_the_settings_file() {
    let home = tempfile::tempdir().unwrap();
    let ca = Authority::new();
    let issued = ca.issue_into(&home.path().join("tls"), &["127.0.0.1"]);
    // Relative paths in the settings file are relative to it.
    let settings = home.path().join("settings.toml");
    fs::write(
        &settings,
        "tls-cert = \"tls/public.crt\"\ntls-key = \"tls/private.key\"\n",
    )
    .unwrap();
    let (mut child, endpoint) = serve(home.path(), &["--config", settings.to_str().unwrap()]);
    let (presented, _) = ca
        .handshake(address(&endpoint), "127.0.0.1", &[])
        .await
        .unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(presented, issued.der);
}

#[test]
fn broken_certificates_stop_it_before_it_starts() {
    let home = tempfile::tempdir().unwrap();
    let ca = Authority::new();
    let certs = home.path().join("certs");
    let first = ca.issue_into(&certs, &["127.0.0.1"]);
    let second = ca.issue(&["127.0.0.1"]);
    fs::write(certs.join("private.key"), second.key).unwrap();
    let serve = |args: &[&str]| {
        teifs(home.path())
            .args(["serve", "--listen", "127.0.0.1:0", "--kms-keyring"])
            .arg(home.path().join("keys.json"))
            .arg(home.path().join("drive"))
            .args(args)
            .output()
            .unwrap()
    };
    let out = serve(&["--certs-dir", certs.to_str().unwrap()]);
    assert!(!out.status.success());
    let err = text(&out.stderr);
    assert!(err.contains("isn't the key of"), "{err}");
    assert!(!home.path().join("drive").exists(), "nothing was made");

    let empty = home.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let out = serve(&["--certs-dir", empty.to_str().unwrap()]);
    assert!(text(&out.stderr).contains("public.crt and private.key"));

    let cert = certs.join("public.crt");
    let out = serve(&["--tls-cert", cert.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    // The settings file can't leave out the key either.
    let settings = home.path().join("settings.toml");
    fs::write(&settings, "tls-cert = \"certs/public.crt\"\n").unwrap();
    let out = serve(&["--config", settings.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("tls-cert needs tls-key"),
        "{}",
        text(&out.stderr)
    );
    let out = serve(&[
        "--certs-dir",
        certs.to_str().unwrap(),
        "--tls-cert",
        cert.to_str().unwrap(),
        "--tls-key",
        cert.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    drop(first);
}
