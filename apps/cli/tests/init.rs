//! `teifs init`, `teifs serve`'s announcement and `teifs health`, through the real binary
//! with a clean environment: what they create, what they refuse, and what programs read.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Command, Output, Stdio},
};

/// `teifs ARGS` with only the client's settings file (in `home`) in the environment.
fn teifs(home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
    command
        .args(args)
        .env_clear()
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

fn json(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", text(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn init_sets_up_a_drive_its_settings_and_an_alias() {
    let home = tempfile::tempdir().unwrap();
    let drive = home.path().join("drive");
    let keyring = home.path().join("keys").join("drive.json");
    let (drive_arg, keyring_arg) = (drive.to_str().unwrap(), keyring.to_str().unwrap());

    let out = teifs(
        home.path(),
        &[
            "init",
            drive_arg,
            "--kms-keyring",
            keyring_arg,
            "--listen",
            "0.0.0.0:9555",
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(stdout, "", "people's summary goes to stderr");
    assert!(stderr.starts_with("✓ Drive ready at "), "{stderr}");
    assert!(
        stderr.contains("teifs serve ") && stderr.contains("teifs ls local"),
        "{stderr}"
    );
    assert!(stderr.contains("back it up"), "{stderr}");
    assert!(keyring.is_file() && drive.join(".teifs/credentials.json").is_file());

    // The secret is in the drive's file only, and the alias has it.
    let secret: serde_json::Value =
        serde_json::from_slice(&std::fs::read(drive.join(".teifs/credentials.json")).unwrap())
            .unwrap();
    let secret = secret["secretKey"].as_str().unwrap();
    assert!(!stderr.contains(secret));
    let aliases = std::fs::read_to_string(home.path().join("aliases.toml")).unwrap();
    assert!(
        aliases.contains("[aliases.local]") && aliases.contains("http://127.0.0.1:9555"),
        "{aliases}"
    );

    // `teifs serve DIR` (and `config show DIR`) read the drive's settings.
    let shown = teifs(home.path(), &["config", "show", drive_arg]);
    let shown = text(&shown.stdout);
    assert!(
        shown.contains("listen = \"0.0.0.0:9555\"  # file"),
        "{shown}"
    );
    assert!(
        shown.contains("default-layout = \"object\"  # file"),
        "{shown}"
    );

    // Running it again changes nothing unless asked.
    let again = teifs(
        home.path(),
        &["init", drive_arg, "--kms-keyring", keyring_arg],
    );
    assert_eq!(again.status.code(), Some(2), "{}", text(&again.stderr));
    assert!(text(&again.stderr).contains("--force"));
    let forced = json(&teifs(
        home.path(),
        &[
            "--json",
            "init",
            drive_arg,
            "--kms-keyring",
            keyring_arg,
            "--default-layout",
            "folder",
            "--no-alias",
            "--force",
        ],
    ));
    assert_eq!(forced["type"], "init");
    assert_eq!(forced["defaultLayout"], "folder");
    assert_eq!(forced["endpoint"], "http://127.0.0.1:9000");
    assert!(forced["alias"].is_null());
    assert!(forced.get("secretKey").is_none(), "{forced}");
}

#[test]
fn init_keeps_the_keyring_off_the_drive() {
    let home = tempfile::tempdir().unwrap();
    let drive = home.path().join("drive");
    let on_drive = drive.join("keys.json");
    let out = teifs(
        home.path(),
        &[
            "init",
            drive.to_str().unwrap(),
            "--kms-keyring",
            on_drive.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("off the drive"));
    assert!(!on_drive.exists());
}

#[test]
fn serve_announces_where_it_listens_for_programs() {
    let home = tempfile::tempdir().unwrap();
    let drive = home.path().join("drive");
    let keyring = home.path().join("keys.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_teifs"))
        .args([
            "--json",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--kms-keyring",
        ])
        .args([&keyring, &drive])
        .env_clear()
        .envs(std::env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let serving: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(serving["type"], "serving", "{line}");
    let endpoint = serving["endpoint"].as_str().unwrap();
    // What a container's health check runs.
    let healthy = teifs(home.path(), &["-q", "health", endpoint]);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(healthy.status.success(), "{}", text(&healthy.stderr));
    let down = teifs(home.path(), &["health", endpoint, "--timeout", "2s"]);
    assert_eq!(down.status.code(), Some(3), "{}", text(&down.stderr));
    assert!(endpoint.starts_with("http://127.0.0.1:"), "{endpoint}");
    assert!(!endpoint.ends_with(":0"), "the real port: {endpoint}");
    assert_eq!(serving["durability"], "strict");
    assert!(serving["accessKey"].as_str().unwrap().starts_with("TF"));
}
