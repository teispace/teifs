//! `teifs key`, through the real binary against a drive and a keyring made here: keys
//! are listed, rotated, and the objects older versions sealed are sealed again.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{
    path::Path,
    process::{Command, Output, Stdio},
    sync::Arc,
};

use teifs_store::{Encryption, Layout, LocalKms, ObjectAttrs, Precondition, Store, StoreOptions};
use tokio::io::AsyncReadExt;

/// The drive's managed key, which SSE-S3 uses.
const DEFAULT_KEY: &str = "teifs-default";

/// `teifs ARGS --dir DRIVE --kms-keyring KEYRING`.
fn teifs(drive: &Path, keyring: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
    command
        .args(args)
        .arg("--dir")
        .arg(drive)
        .arg("--kms-keyring")
        .arg(keyring)
        .env_clear()
        .stdin(Stdio::null());
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command.output().unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// The drive at `drive` with the keyring at `keyring`.
fn store(drive: &Path, keyring: &Path) -> Store {
    let kms = Arc::new(LocalKms::open(keyring).unwrap());
    Store::open_with(
        drive,
        StoreOptions {
            kms: Some(kms),
            ..StoreOptions::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn keys_rotate_and_older_versions_seals_are_rewrapped() {
    let home = tempfile::tempdir().unwrap();
    let (drive, keyring) = (home.path().join("drive"), home.path().join("keyring.json"));
    std::fs::create_dir(&drive).unwrap();
    {
        let store = store(&drive, &keyring);
        store.create_bucket("vault", Layout::Object).await.unwrap();
        let mut staged = store.stage_for("vault", &Encryption::S3).await.unwrap();
        staged.write(b"secret").await.unwrap();
        store
            .commit(
                "vault",
                "k",
                staged,
                ObjectAttrs::default(),
                Precondition::default(),
            )
            .await
            .unwrap();
    }

    let rotated = json(&teifs(
        &drive,
        &keyring,
        &["--json", "key", "rotate", DEFAULT_KEY],
    ));
    assert_eq!(rotated["version"], 2);
    let rewrap = |dry: bool| {
        let mut args = vec!["--json", "key", "rewrap", DEFAULT_KEY];
        if dry {
            args.push("--dry-run");
        }
        json(&teifs(&drive, &keyring, &args))
    };
    let counted = rewrap(true);
    assert_eq!(
        (&counted["versions"], &counted["newest"], &counted["dryRun"]),
        (&1.into(), &2.into(), &true.into())
    );
    let out = teifs(&drive, &keyring, &["key", "rewrap", DEFAULT_KEY]);
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        said.contains("Sealed 1 object version and 0 uploads again under teifs-default version 2"),
        "{said}"
    );
    assert_eq!(rewrap(false)["versions"], 0);

    let listed = json(&teifs(&drive, &keyring, &["--json", "key", "list"]));
    assert_eq!(listed["version"], 2);
    // The object still reads, with its key sealed by version 2.
    let store = store(&drive, &keyring);
    let (_, body) = store.read("vault", "k").await.unwrap();
    let mut bytes = Vec::new();
    body.unwrap()
        .all()
        .await
        .unwrap()
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    assert_eq!(bytes, b"secret");
    drop(store);

    let out = teifs(&drive, &keyring, &["key", "rewrap", "nope"]);
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("can't rewrap nope") && said.contains("no key named nope"),
        "{said}"
    );
}
