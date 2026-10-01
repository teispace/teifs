//! `teifs config show` and the settings file, through the real binary with a clean
//! environment.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{path::Path, process::Command};

const SECRET: &str = "never-print-this-secret";

/// Runs `teifs config show` with only `env` set; its output, and whether it succeeded.
fn show(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_teifs"))
        .args(["config", "show"])
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains(SECRET), "a secret was printed:\n{text}");
    (output.status.success(), text)
}

fn settings(dir: &Path, text: &str) -> String {
    let path = dir.join("teifs.toml");
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_owned()
}

fn line<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find(|l| l.starts_with(&format!("{key} = ")))
        .unwrap_or_else(|| panic!("no {key} in:\n{text}"))
}

#[test]
fn flags_beat_the_environment_which_beats_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = settings(
        dir.path(),
        r#"
        listen = "0.0.0.0:9100"
        durability = "relaxed"
        key-names = "host"
        domains = ["s3.example.com", "files.example.com"]
        allow-sse-c = true
        upload-expiry = "12h"
        "#,
    );
    let (ok, out) = show(
        &["--config", &file, "--listen", "127.0.0.1:9200"],
        &[("TEIFS_DURABILITY", "none")],
    );
    assert!(ok, "{out}");
    assert!(out.contains(&file), "{out}");
    assert_eq!(line(&out, "listen"), r#"listen = "127.0.0.1:9200"  # flag"#);
    assert_eq!(
        line(&out, "durability"),
        r#"durability = "none"  # environment"#
    );
    assert_eq!(line(&out, "key-names"), r#"key-names = "host"  # file"#);
    assert_eq!(
        line(&out, "domains"),
        r#"domains = ["s3.example.com", "files.example.com"]  # file"#
    );
    assert_eq!(line(&out, "allow-sse-c"), "allow-sse-c = true  # file");
    assert_eq!(
        line(&out, "upload-expiry"),
        r#"upload-expiry = "12h"  # file"#
    );
    assert_eq!(
        line(&out, "sse-c-over-http"),
        "sse-c-over-http = false  # default"
    );
    assert!(out.contains("# access-key: not set"), "{out}");
    assert!(out.contains("the drive's own"), "{out}");
}

#[test]
fn relative_paths_are_relative_to_the_settings_file() {
    let dir = tempfile::tempdir().unwrap();
    let quoted = |path: &Path| toml::Value::String(path.to_str().unwrap().to_owned());
    let keyring = dir.path().join("elsewhere/keys.json");
    let file = settings(
        dir.path(),
        &format!("dir = \"drive\"\nkms-keyring = {}\n", quoted(&keyring)),
    );
    let (ok, out) = show(&["--config", &file], &[]);
    assert!(ok, "{out}");
    let drive = quoted(&dir.path().join("drive"));
    assert_eq!(line(&out, "dir"), format!("dir = {drive}  # file"));
    assert_eq!(
        line(&out, "kms-keyring"),
        format!("kms-keyring = {}  # file", quoted(&keyring))
    );
}

#[test]
fn external_kms_settings_go_in_the_file_too() {
    let dir = tempfile::tempdir().unwrap();
    let quoted = |path: &Path| toml::Value::String(path.to_str().unwrap().to_owned());
    let file = settings(
        dir.path(),
        "kms-kes = [\"https://kes1:7373\", \"https://kes2:7373\"]\n\
         kms-kes-ca = \"certs/ca.pem\"\n\
         kms-default-key = \"minio-default\"\n",
    );
    let (ok, out) = show(&["--config", &file], &[("TEIFS_KMS_KES_API_KEY", SECRET)]);
    assert!(ok, "{out}");
    assert_eq!(
        line(&out, "kms-kes"),
        r#"kms-kes = ["https://kes1:7373", "https://kes2:7373"]  # file"#
    );
    assert_eq!(
        line(&out, "kms-kes-ca"),
        format!(
            "kms-kes-ca = {}  # file",
            quoted(&dir.path().join("certs/ca.pem"))
        )
    );
    assert_eq!(
        line(&out, "kms-default-key"),
        r#"kms-default-key = "minio-default"  # file"#
    );
}

#[test]
fn one_external_kms_at_a_time() {
    for (args, expected) in [
        (
            &["--kms-kes", "https://kes:7373", "--kms-aws"][..],
            "cannot be used with",
        ),
        (
            &[
                "--kms-transit",
                "https://vault:8200",
                "--kms-kes",
                "https://kes:7373",
            ],
            "cannot be used with",
        ),
        (
            &["--kms-aws", "--kms-keyring", "k.json"],
            "cannot be used with",
        ),
        (&["--kms-aws-region", "eu-west-1"], "--kms-aws"),
        (
            &["--kms-kes", "https://kes:7373", "--kms-kes-cert", "c.pem"],
            "--kms-kes-key",
        ),
    ] {
        let (ok, out) = show(args, &[]);
        assert!(!ok, "{args:?} was accepted:\n{out}");
        assert!(out.contains(expected), "{args:?}: {out}");
    }
}

#[test]
fn without_a_file_the_defaults_show() {
    let (ok, out) = show(&[], &[]);
    assert!(ok, "{out}");
    assert!(out.contains("(no settings file)"), "{out}");
    assert_eq!(
        line(&out, "listen"),
        r#"listen = "127.0.0.1:9000"  # default"#
    );
    assert_eq!(
        line(&out, "durability"),
        r#"durability = "strict"  # default"#
    );
}

#[test]
fn the_settings_file_is_checked_like_flags() {
    let dir = tempfile::tempdir().unwrap();
    for (text, expected) in [
        ("listne = \"x\"", "`listne`: isn't a setting"),
        (
            "durability = \"fast\"",
            "`durability`: invalid value 'fast'",
        ),
        ("listen = \"nowhere\"", "`listen`: invalid value 'nowhere'"),
        (
            "upload-expiry = \"0d\"",
            "`upload-expiry`: invalid value '0d'",
        ),
        ("listen = [\"a\"]", "`listen`: takes one value, not a list"),
        (
            "domains = [{ a = 1 }]",
            "`domains`: the list may only hold strings",
        ),
        ("listen = { a = 1 }", "`listen`: must be a string"),
        (
            "allow-sse-c = \"maybe\"",
            "`allow-sse-c`: invalid value 'maybe'",
        ),
        ("config = \"other.toml\"", "`config`: isn't a setting"),
        ("listen = ", "isn't valid TOML"),
    ] {
        let file = settings(dir.path(), text);
        let (ok, out) = show(&["--config", &file], &[]);
        assert!(!ok, "{text} was accepted:\n{out}");
        assert!(out.contains(expected), "{text}: {out}");
    }
    let (ok, out) = show(&["--config", "/no/such/teifs.toml"], &[]);
    assert!(!ok && out.contains("can't read the settings file"), "{out}");
}

#[test]
fn secrets_never_go_in_the_settings_file() {
    let dir = tempfile::tempdir().unwrap();
    for key in ["secret-key", "secret_key"] {
        let file = settings(dir.path(), &format!("{key} = \"{SECRET}\""));
        let (ok, out) = show(&["--config", &file], &[]);
        assert!(!ok, "{out}");
        assert!(out.contains("secret-key-file"), "{out}");
    }
}

#[test]
fn secrets_come_from_the_environment_or_a_file_and_never_show() {
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("secret");
    std::fs::write(&secret_file, format!("{SECRET}\n")).unwrap();
    let file = settings(
        dir.path(),
        &format!(
            "access-key = \"teifsadmin\"\nsecret-key-file = {:?}\n",
            secret_file.to_str().unwrap()
        ),
    );
    let (ok, out) = show(&["--config", &file], &[]);
    assert!(ok, "{out}");
    assert_eq!(
        line(&out, "access-key"),
        r#"access-key = "teifsadmin"  # file"#
    );
    assert!(out.contains("secret key from the file"), "{out}");

    let (ok, out) = show(
        &["--access-key", "teifsadmin"],
        &[("TEIFS_SECRET_KEY", SECRET)],
    );
    assert!(ok, "{out}");
    assert!(out.contains("secret key from TEIFS_SECRET_KEY"), "{out}");

    let (ok, out) = show(&["--config", &file], &[("TEIFS_SECRET_KEY", SECRET)]);
    assert!(!ok && out.contains("set twice"), "{out}");
}

#[test]
fn minio_root_credentials_are_a_fallback() {
    let minio = [
        ("MINIO_ROOT_USER", "minioadmin"),
        ("MINIO_ROOT_PASSWORD", SECRET),
    ];
    let (ok, out) = show(&[], &minio);
    assert!(ok, "{out}");
    assert!(out.contains("access key from MINIO_ROOT_USER"), "{out}");
    assert!(out.contains("secret key from MINIO_ROOT_PASSWORD"), "{out}");

    let (ok, out) = show(&[], &minio[..1]);
    assert!(!ok && out.contains("MINIO_ROOT_PASSWORD"), "{out}");
}

#[test]
fn proxies_and_certificates_are_settings_too() {
    let dir = tempfile::tempdir().unwrap();
    let file = settings(
        dir.path(),
        r#"
        trusted-proxies = ["10.0.0.0/8", "fd00::/8"]
        proxy-header = "forwarded"
        certs-dir = "certs"
        "#,
    );
    let (ok, out) = show(&["--config", &file], &[]);
    assert!(ok, "{out}");
    assert_eq!(
        line(&out, "trusted-proxies"),
        r#"trusted-proxies = ["10.0.0.0/8", "fd00::/8"]  # file"#
    );
    assert_eq!(
        line(&out, "proxy-header"),
        r#"proxy-header = "forwarded"  # file"#
    );
    // Relative to the settings file.
    let certs = dir.path().join("certs");
    assert!(
        line(&out, "certs-dir").contains(certs.to_str().unwrap()),
        "{out}"
    );
    let (ok, out) = show(&[], &[("TEIFS_TRUSTED_PROXIES", "192.0.2.7,10.1.0.0/16")]);
    assert!(ok, "{out}");
    assert!(
        line(&out, "trusted-proxies").contains("10.1.0.0/16"),
        "{out}"
    );

    for (args, env) in [
        (vec!["--trusted-proxy", "proxy.local"], vec![]),
        (vec!["--trusted-proxy", "10.0.0.0/33"], vec![]),
        (vec!["--proxy-header", "via"], vec![]),
        (vec![], vec![("TEIFS_PROXY_HEADER", "x-client-ip")]),
    ] {
        let (ok, out) = show(&args, &env);
        assert!(!ok, "{args:?} {env:?} was accepted:\n{out}");
    }
    let file = settings(dir.path(), "trusted-proxies = [\"everyone\"]\n");
    let (ok, out) = show(&["--config", &file], &[]);
    assert!(!ok, "{out}");
    assert!(out.contains("everyone"), "{out}");
}
