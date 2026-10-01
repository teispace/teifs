//! `teifs doctor`, through the real binary: a drive's problems found without opening it,
//! each with what to do, the drive's own settings used, and exit code 1 when a check
//! fails.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{
    path::Path,
    process::{Command, Output, Stdio},
};

use serde_json::Value;
use teifs_store::Store;

/// `teifs --json doctor ARGS` with only `env` (and a home of its own) set.
fn doctor(home: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, Vec<Value>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
    command
        .args(["--json", "doctor"])
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .envs(env.iter().copied())
        .stdin(Stdio::null());
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    let output: Output = command.output().unwrap();
    let records = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (output.status.code().unwrap(), records)
}

/// The first check named `name`: its state and detail.
fn check<'a>(checks: &'a [Value], name: &str) -> (&'a str, &'a str) {
    let found = checks
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} check in {checks:?}"));
    (
        found["state"].as_str().unwrap(),
        found["detail"].as_str().unwrap(),
    )
}

const FREE: &str = "127.0.0.1:0";

#[test]
fn a_folder_and_a_drive_are_checked_without_being_changed() {
    let home = tempfile::tempdir().unwrap();
    let folder = home.path().join("folder");
    std::fs::create_dir(&folder).unwrap();
    let f = folder.to_str().unwrap();
    let (code, checks) = doctor(home.path(), &[f, "--listen", FREE], &[]);
    assert_eq!(code, 0, "{checks:?}");
    assert!(check(&checks, "Drive").1.contains("isn't a drive yet"));
    assert_eq!(check(&checks, "Writable"), ("ok", "yes"));
    assert_eq!(check(&checks, "File system"), ("ok", "on this machine"));
    assert_eq!(check(&checks, "Listen").0, "ok");
    for record in &checks {
        assert_eq!(record["type"], "check");
        assert_eq!(record["drive"], f);
    }
    // Nothing was made: it's still not a drive.
    assert_eq!(std::fs::read_dir(&folder).unwrap().count(), 0);

    drop(Store::open(&folder).unwrap());
    let (code, checks) = doctor(home.path(), &[f, "--listen", FREE], &[]);
    assert_eq!(code, 0, "{checks:?}");
    assert!(check(&checks, "Drive").1.contains("drive "), "{checks:?}");
    assert_eq!(check(&checks, "In use"), ("ok", "by nothing"));
    assert_eq!(check(&checks, "Index"), ("ok", "intact"));
    assert_eq!(check(&checks, "System database"), ("ok", "intact"));
    assert_eq!(check(&checks, "Names").0, "ok");
    assert!(
        check(&checks, "Root keys")
            .1
            .starts_with("made when it's first served")
    );
    // A drive whose keyring isn't where it'd be looked for.
    let (state, detail) = check(&checks, "Keyring");
    assert_eq!(state, "warning");
    assert!(detail.contains("restore it if there was one"), "{detail}");

    // Being served: what would get in the way isn't tried.
    let store = Store::open(&folder).unwrap();
    let (code, checks) = doctor(home.path(), &[f], &[]);
    assert_eq!(code, 0, "{checks:?}");
    assert!(
        check(&checks, "In use")
            .1
            .starts_with("served by another process")
    );
    assert!(
        check(&checks, "Listen")
            .1
            .ends_with("not tried while the drive is served")
    );
    drop(store);

    // A folder that isn't there.
    let gone = home.path().join("gone");
    let (code, checks) = doctor(home.path(), &[gone.to_str().unwrap()], &[]);
    assert_eq!(code, 1);
    assert_eq!(checks.len(), 1);
    let (state, detail) = check(&checks, "Drive");
    assert_eq!(state, "failed");
    assert!(detail.contains("teifs init"), "{detail}");
}

#[test]
fn problems_are_found_with_what_to_do() {
    let home = tempfile::tempdir().unwrap();
    let drive = home.path().join("drive");
    std::fs::create_dir(&drive).unwrap();
    drop(Store::open(&drive).unwrap());
    let d = drive.to_str().unwrap();
    let system = drive.join(".teifs");

    // Its own settings are used, as `teifs serve DIR` uses them: a port in use.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = taken.local_addr().unwrap().to_string();
    std::fs::write(
        system.join("settings.toml"),
        format!("listen = \"{address}\"\n"),
    )
    .unwrap();
    let (code, checks) = doctor(home.path(), &[d], &[]);
    assert_eq!(code, 1, "{checks:?}");
    let (state, detail) = check(&checks, "Listen");
    assert_eq!(state, "failed");
    assert!(
        detail.starts_with(&format!("{address} is in use")),
        "{detail}"
    );
    drop(taken);

    // Keys given halfway, a keyring others can read, a damaged index.
    let keyring = home.path().join("keyring.json");
    std::fs::write(&keyring, "{}").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Readable by its group alone is readable by others too.
        std::fs::set_permissions(&keyring, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
    std::fs::write(system.join("index.db"), vec![7u8; 8192]).unwrap();
    let k = keyring.to_str().unwrap();
    let (code, checks) = doctor(
        home.path(),
        &[d, "--listen", FREE, "--kms-keyring", k],
        &[("TEIFS_ACCESS_KEY", "someone")],
    );
    assert_eq!(code, 1);
    assert_eq!(check(&checks, "Root keys").0, "failed");
    let (state, detail) = check(&checks, "Index");
    assert_eq!(state, "failed");
    assert!(detail.contains("teifs restore --from"), "{detail}");
    if cfg!(unix) {
        let (state, detail) = check(&checks, "Keyring");
        assert_eq!(state, "warning");
        assert!(detail.contains("chmod 600"), "{detail}");
    }

    // A drive a newer TeiFS made.
    let format = system.join("format.json");
    let mut recorded: Value = serde_json::from_slice(&std::fs::read(&format).unwrap()).unwrap();
    recorded["format"] = (recorded["format"].as_u64().unwrap() + 1).into();
    std::fs::write(&format, recorded.to_string()).unwrap();
    let (code, checks) = doctor(home.path(), &[d, "--listen", FREE], &[]);
    assert_eq!(code, 1);
    let (state, detail) = check(&checks, "Drive");
    assert_eq!(state, "failed");
    assert!(detail.ends_with("upgrade teifs"), "{detail}");
}

#[test]
fn certificates_are_loaded_and_their_expiry_told() {
    let home = tempfile::tempdir().unwrap();
    let drive = home.path().join("drive");
    std::fs::create_dir(&drive).unwrap();
    let d = drive.to_str().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["s3.test".to_owned()]).unwrap();
    let soon = time::OffsetDateTime::now_utc() + time::Duration::days(3);
    params.not_after = soon;
    let cert = home.path().join("cert.pem");
    let key_file = home.path().join("key.pem");
    std::fs::write(&cert, params.self_signed(&key).unwrap().pem()).unwrap();
    std::fs::write(&key_file, key.serialize_pem()).unwrap();
    let (c, k) = (cert.to_str().unwrap(), key_file.to_str().unwrap());
    let (code, checks) = doctor(
        home.path(),
        &[d, "--listen", FREE, "--tls-cert", c, "--tls-key", k],
        &[],
    );
    assert_eq!(code, 0, "{checks:?}");
    let (state, detail) = check(&checks, "Certificate");
    assert_eq!(state, "warning");
    assert!(detail.starts_with(&format!("{c}: expires ")), "{detail}");
    assert!(detail.ends_with("renew it"), "{detail}");
    // A key that isn't the certificate's.
    let other = rcgen::KeyPair::generate().unwrap();
    std::fs::write(&key_file, other.serialize_pem()).unwrap();
    let (code, checks) = doctor(
        home.path(),
        &[d, "--listen", FREE, "--tls-cert", c, "--tls-key", k],
        &[],
    );
    assert_eq!(code, 1);
    assert_eq!(check(&checks, "Certificate").0, "failed");
    // Half of a pair is refused as `teifs serve` refuses it, before anything's checked.
    let (code, checks) = doctor(home.path(), &[d, "--listen", FREE, "--tls-cert", c], &[]);
    assert_eq!((code, checks.len()), (2, 0));
}

#[test]
fn keys_and_folders_are_checked() {
    let home = tempfile::tempdir().unwrap();
    let drive = home.path().join("drive");
    std::fs::create_dir(&drive).unwrap();
    drop(Store::open(&drive).unwrap());
    let d = drive.to_str().unwrap();
    #[cfg(unix)]
    let system = drive.join(".teifs");

    // The drive's own keys, which only its owner should read, and a staging folder that
    // can't be written.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let credentials = system.join("credentials.json");
        std::fs::write(&credentials, "{}").unwrap();
        mode(&credentials, 0o604);
        let (_, checks) = doctor(home.path(), &[d, "--listen", FREE], &[]);
        let (state, detail) = check(&checks, "Root keys");
        assert_eq!(state, "warning");
        assert!(detail.contains("chmod 600"), "{detail}");
        mode(&credentials, 0o600);
        let tmp = system.join("tmp");
        mode(&tmp, 0o500);
        let (code, checks) = doctor(home.path(), &[d, "--listen", FREE], &[]);
        mode(&tmp, 0o700);
        assert_eq!(code, 1, "{checks:?}");
        assert!(check(&checks, "Root keys").1.starts_with("in "));
        let (state, detail) = check(&checks, "Writable");
        assert_eq!(state, "failed");
        assert!(detail.contains(&tmp.display().to_string()), "{detail}");
    }

    // Keys given in full, and given with a secret that can't be read.
    let (_, checks) = doctor(
        home.path(),
        &[d, "--listen", FREE],
        &[
            ("TEIFS_ACCESS_KEY", "someone"),
            ("TEIFS_SECRET_KEY", "a-long-enough-secret"),
        ],
    );
    assert_eq!(check(&checks, "Root keys").0, "ok");
    let missing = home.path().join("missing-secret");
    let (code, checks) = doctor(
        home.path(),
        &[
            d,
            "--listen",
            FREE,
            "--secret-key-file",
            missing.to_str().unwrap(),
        ],
        &[("TEIFS_ACCESS_KEY", "someone")],
    );
    assert_eq!(code, 1);
    assert_eq!(check(&checks, "Root keys").0, "failed");
}

#[test]
fn an_external_kms_is_asked() {
    let home = tempfile::tempdir().unwrap();
    let folder = home.path().join("folder");
    std::fs::create_dir(&folder).unwrap();
    let f = folder.to_str().unwrap();
    // A KES server that isn't there.
    let gone = std::net::TcpListener::bind(FREE).unwrap();
    let endpoint = format!("https://{}", gone.local_addr().unwrap());
    drop(gone);
    // kes-go's published example key: not a secret.
    let api_key = (
        "TEIFS_KMS_KES_API_KEY",
        "kes:v1:AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs",
    );
    let (code, checks) = doctor(
        home.path(),
        &[f, "--listen", FREE, "--kms-kes", &endpoint],
        &[api_key],
    );
    assert_eq!(code, 1);
    let (state, detail) = check(&checks, "KMS");
    assert_eq!(state, "failed");
    assert!(
        detail.starts_with(&format!("KES at {endpoint}: can't reach KES")),
        "{detail}"
    );
    // Without a way to sign in, it says how to give one.
    let (_, checks) = doctor(
        home.path(),
        &[f, "--listen", FREE, "--kms-kes", &endpoint],
        &[],
    );
    let (state, detail) = check(&checks, "KMS");
    assert_eq!(state, "failed");
    assert!(detail.contains("set TEIFS_KMS_KES_API_KEY"), "{detail}");
    // MinIO's variables name it too.
    let (_, checks) = doctor(
        home.path(),
        &[f, "--listen", FREE],
        &[
            ("MINIO_KMS_KES_ENDPOINT", &endpoint),
            ("MINIO_KMS_KES_API_KEY", api_key.1),
        ],
    );
    let (_, detail) = check(&checks, "KMS");
    assert!(
        detail.starts_with(&format!("KES at {endpoint}: can't reach KES")),
        "{detail}"
    );
}

#[test]
fn the_ldap_directory_is_asked() {
    let home = tempfile::tempdir().unwrap();
    let folder = home.path().join("folder");
    std::fs::create_dir(&folder).unwrap();
    let f = folder.to_str().unwrap();
    let gone = std::net::TcpListener::bind(FREE).unwrap();
    let server = gone.local_addr().unwrap().to_string();
    drop(gone);
    let ldap = [
        "--ldap-server",
        &server,
        "--ldap-insecure",
        "--ldap-lookup-bind-dn",
        "cn=admin,dc=min,dc=io",
        "--ldap-user-base-dn",
        "ou=people,dc=min,dc=io",
        "--ldap-user-filter",
        "(uid=%s)",
    ];
    let args: Vec<&str> = [f, "--listen", FREE].into_iter().chain(ldap).collect();
    let (code, checks) = doctor(
        home.path(),
        &args,
        &[("TEIFS_LDAP_LOOKUP_BIND_PASSWORD", "admin")],
    );
    assert_eq!(code, 1);
    let (state, detail) = check(&checks, "LDAP");
    assert_eq!(state, "failed");
    assert!(
        detail.starts_with(&format!("LDAP at {server}: can't reach the LDAP server")),
        "{detail}"
    );
    // Settings that can't work say so without asking.
    let args: Vec<&str> = [f, "--listen", FREE]
        .into_iter()
        .chain(ldap[..7].iter().copied())
        .collect();
    let (_, checks) = doctor(
        home.path(),
        &args,
        &[("TEIFS_LDAP_LOOKUP_BIND_PASSWORD", "admin")],
    );
    let (state, detail) = check(&checks, "LDAP");
    assert_eq!(state, "failed");
    assert!(detail.contains("filter"), "{detail}");
    // Without LDAP, there's no check.
    let (_, checks) = doctor(home.path(), &[f, "--listen", FREE], &[]);
    assert!(checks.iter().all(|c| c["name"] != "LDAP"));
}
