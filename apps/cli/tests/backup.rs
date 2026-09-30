//! `teifs backup` and `teifs restore`, through the real binary against a drive made
//! here: metadata copied out and put back, from a backup or the drive's own snapshots.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{
    path::Path,
    process::{Command, Output, Stdio},
};

use teifs_store::{Layout, ObjectAttrs, Store, StoreError};

fn teifs(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
    command.args(args).env_clear().stdin(Stdio::null());
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command.output().unwrap()
}

fn record(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

async fn put(drive: &Path, key: &str) {
    let store = Store::open(drive).unwrap();
    if store.head_bucket("obj").await.is_err() {
        store.create_bucket("obj", Layout::Object).await.unwrap();
    }
    store
        .put_bytes("obj", key, b"x", ObjectAttrs::default())
        .await
        .unwrap();
}

async fn has(drive: &Path, key: &str) -> bool {
    let store = Store::open(drive).unwrap();
    match store.head("obj", key).await {
        Ok(_) => true,
        Err(StoreError::NoSuchKey) => false,
        Err(err) => panic!("{err}"),
    }
}

#[tokio::test]
async fn metadata_goes_out_and_comes_back() {
    let home = tempfile::tempdir().unwrap();
    let (drive, backups) = (home.path().join("drive"), home.path().join("backups"));
    let d = drive.to_str().unwrap();
    std::fs::create_dir(&drive).unwrap();
    put(&drive, "a").await;
    let backup = record(&teifs(&[
        "--json",
        "backup",
        d,
        "--to",
        backups.to_str().unwrap(),
    ]));
    assert_eq!(backup["type"], "backup");
    let path = backup["path"].as_str().unwrap().to_owned();
    put(&drive, "b").await;

    // Asked first: without a terminal to ask on, only with --yes.
    let unasked = teifs(&["restore", d, "--from", &path]);
    assert_eq!(unasked.status.code(), Some(2));
    assert!(has(&drive, "b").await);
    let restored = record(&teifs(&["--json", "-y", "restore", d, "--from", &path]));
    assert_eq!(restored["type"], "restore");
    assert_eq!(restored["name"], backup["name"]);
    assert!(Path::new(restored["previous"].as_str().unwrap()).is_dir());
    assert!(has(&drive, "a").await && !has(&drive, "b").await);

    // One of the drive's own snapshots, by name.
    let snapshot = Store::open(&drive).unwrap().take_snapshot().await.unwrap();
    put(&drive, "c").await;
    let out = teifs(&["-y", "restore", d, "--from", &snapshot.name]);
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("Restored the metadata of"));
    assert!(!has(&drive, "c").await);

    let missing = teifs(&["-y", "restore", d, "--from", "20200101T000000.000Z"]);
    assert_eq!(missing.status.code(), Some(5));
    // Another drive's backup is refused.
    let other = home.path().join("other");
    std::fs::create_dir(&other).unwrap();
    put(&other, "z").await;
    let theirs = record(&teifs(&[
        "--json",
        "backup",
        other.to_str().unwrap(),
        "--to",
        backups.to_str().unwrap(),
    ]));
    let refused = teifs(&[
        "-y",
        "restore",
        d,
        "--from",
        theirs["path"].as_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("another drive"));
    // Not while the drive is open.
    let _open = Store::open(&drive).unwrap();
    let busy = teifs(&["-y", "restore", d, "--from", &path]);
    assert_eq!(busy.status.code(), Some(6));
}
