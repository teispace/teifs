//! `teifs serve` over HTTPS through the real binary: certificates from a folder or
//! files (also named in the settings file), the announced `https://` endpoint, `teifs
//! health` against it, reloading on SIGHUP, and certificates refused before starting.
//! And the client: aliases that trust a private CA for S3, IAM, STS and the admin API.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;
mod harness;

use std::{
    fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use common::{ACCESS_KEY, SECRET_KEY, certs::Authority, start_with};
use harness::records;

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

fn args(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
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

#[tokio::test(flavor = "multi_thread")]
async fn aliases_trust_a_private_ca() {
    // Shaped like the CAs people make with openssl, which macOS's own verifier refuses
    // (so every client must check them as the AWS SDKs do).
    let ca = Authority::like_openssl();
    let certs = tempfile::tempdir().unwrap();
    ca.issue_into(certs.path(), &["127.0.0.1", "localhost"]);
    let source = teifs_server::TlsSource::Dir(certs.path().to_owned());
    let server = start_with(|config| config.tls = Some(source)).await;
    let mut cli = harness::Client::new(&server);
    cli.env
        .retain(|(name, _)| !name.starts_with("TEIFS_ALIAS_"));
    let ca_file = cli.path("ca.pem");
    fs::write(&ca_file, &ca.pem).unwrap();
    let ca_path = ca_file.to_str().unwrap();
    let endpoint = server.endpoint.clone();
    let set = |extra: &[&str]| {
        let mut args = vec![
            "alias",
            "set",
            "s",
            endpoint.as_str(),
            "--access-key",
            ACCESS_KEY,
            "--secret-key-stdin",
        ];
        args.extend_from_slice(extra);
        args.into_iter().map(str::to_owned).collect::<Vec<_>>()
    };

    // Not trusted: said so, with what to do.
    let refused = cli.run_with(&args(&set(&[])), SECRET_KEY).await;
    assert_eq!(refused.code, 3, "{}", refused.stderr);
    assert!(refused.stderr.contains("--ca-cert"), "{}", refused.stderr);
    // A file that isn't a certificate is refused before anything's saved.
    let not_pem = cli.path("not.pem");
    fs::write(&not_pem, "nonsense").unwrap();
    let bad = cli
        .run_with(
            &args(&set(&["--ca-cert", not_pem.to_str().unwrap()])),
            SECRET_KEY,
        )
        .await;
    assert_eq!(bad.code, 2, "{}", bad.stderr);

    // Trusted: S3, the admin API, IAM and STS all work over it.
    let saved = cli
        .run_with(&args(&set(&["--ca-cert", "ca.pem"])), SECRET_KEY)
        .await;
    assert_eq!(saved.code, 0, "{}", saved.stderr);
    let aliases = records(&cli.ok(&["--json", "alias", "ls"]).await);
    let saved = Path::new(aliases[0]["caCert"].as_str().unwrap());
    assert!(saved.is_absolute(), "{saved:?}");
    assert_eq!(
        saved.canonicalize().unwrap(),
        ca_file.canonicalize().unwrap()
    );
    cli.ok(&["mb", "s/photos"]).await;
    let file = cli.path("a.txt");
    fs::write(&file, "over TLS").unwrap();
    cli.ok(&["cp", file.to_str().unwrap(), "s/photos/a.txt"])
        .await;
    assert_eq!(cli.ok(&["cat", "s/photos/a.txt"]).await, "over TLS");
    cli.ok(&["admin", "info", "s"]).await;
    let checks = records(&cli.ok(&["--json", "status", "s"]).await);
    let certificate = checks.iter().find(|c| c["name"] == "Certificate").unwrap();
    assert_eq!(certificate["state"], "ok", "{certificate}");
    assert!(
        certificate["detail"]
            .as_str()
            .unwrap()
            .starts_with("valid until ")
    );
    cli.ok(&["sts", "whoami", "s"]).await;
    // A user's alias is for the same server, so it trusts the same CA.
    cli.ok(&[
        "admin",
        "user",
        "add",
        "s",
        "bob",
        "--policy",
        "readonly",
        "--save-alias",
        "bob",
    ])
    .await;
    cli.ok(&["ls", "bob/photos"]).await;

    for_every_alias(&mut cli, &endpoint, ca_path, &not_pem).await;

    // A CA file that went away is reported, before any request.
    fs::remove_file(&ca_file).unwrap();
    let err = cli.fails(&["ls", "s"], 2).await;
    assert!(err.contains("can't read the CA certificate"), "{err}");
    let err = cli.fails(&["admin", "info", "s"], 2).await;
    assert!(err.contains("ca.pem"), "{err}");
}

/// `TEIFS_CA_CERT`: the CA for aliases that don't name one, environment aliases and
/// web identity exchanges with a server's URL among them.
async fn for_every_alias(cli: &mut harness::Client, endpoint: &str, ca_path: &str, not_pem: &Path) {
    // For one run: an alias in the environment, and the CA for every alias.
    cli.env.push((
        "TEIFS_ALIAS_E".to_owned(),
        endpoint.replace("https://", &format!("https://{ACCESS_KEY}:{SECRET_KEY}@")),
    ));
    cli.fails(&["ls", "e"], 3).await;
    // An alias's own CA wins over the one for all.
    cli.env.push((
        "TEIFS_CA_CERT".to_owned(),
        not_pem.to_str().unwrap().to_owned(),
    ));
    cli.fails(&["ls", "e"], 2).await;
    cli.ok(&["ls", "s"]).await;
    cli.env.pop();
    // A web identity exchange with the server's URL uses the one for all.
    let token = cli.path("token");
    fs::write(&token, "not.a.token").unwrap();
    let web = [
        "sts",
        "assume-web",
        endpoint,
        "--role",
        "arn:aws:iam::000000000000:role/ci",
        "--token-file",
        token.to_str().unwrap(),
        "-o",
        "-",
    ];
    assert_eq!(cli.run(&web).await.code, 3, "untrusted");
    cli.env.push((
        "TEIFS_CA_CERT".to_owned(),
        not_pem.to_str().unwrap().to_owned(),
    ));
    let err = cli.fails(&web, 2).await;
    assert!(
        err.contains("isn't a PEM certificate") || err.contains("has no certificate"),
        "{err}"
    );
    cli.env.pop();
    cli.env
        .push(("TEIFS_CA_CERT".to_owned(), ca_path.to_owned()));
    let answered = cli.run(&web).await;
    assert_ne!(
        answered.code, 3,
        "the server answered over TLS: {}",
        answered.stderr
    );
    assert_ne!(answered.code, 0, "{}", answered.stderr);
    cli.ok(&["ls", "e"]).await;
}
