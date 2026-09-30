//! `teifs repair`, through the real binary against a drive made here: after restoring
//! an older backup, objects written since are reported and, with `--apply`, given back.

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

/// Every JSON record printed.
fn records(output: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
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
async fn objects_written_after_a_restored_backup_are_given_back() {
    let home = tempfile::tempdir().unwrap();
    let drive = home.path().join("drive");
    let d = drive.to_str().unwrap();
    std::fs::create_dir(&drive).unwrap();
    put(&drive, "a").await;
    let backup = Store::open(&drive).unwrap().take_snapshot().await.unwrap();
    put(&drive, "b").await;
    let restored = teifs(&["-y", "restore", d, "--from", &backup.name]);
    assert!(restored.status.success(), "{restored:?}");
    assert!(!has(&drive, "b").await);

    // Reported, and left as it is.
    let report = teifs(&["repair", d]);
    assert_eq!(report.status.code(), Some(1), "{report:?}");
    let stderr = String::from_utf8_lossy(&report.stderr);
    assert!(stderr.contains("obj/b: its data file had no version; --apply gives it back"));
    assert!(stderr.contains("run it again with --apply"));
    assert!(!has(&drive, "b").await);
    let json = records(&teifs(&["--json", "repair", d]));
    assert_eq!(json[0]["type"], "repair");
    assert_eq!(json[0]["finding"], "unlisted");
    assert_eq!(json[0]["key"], "b");
    assert_eq!(json[0]["fixed"], false);
    assert_eq!(json[1]["type"], "repaired");
    assert_eq!(
        (json[1]["found"].as_u64(), json[1]["left"].as_u64()),
        (Some(1), Some(1))
    );

    // Only with --apply do versions get forgotten.
    let usage = teifs(&["repair", d, "--forget-missing"]);
    assert_eq!(usage.status.code(), Some(2));

    let applied = teifs(&["--json", "repair", d, "--apply"]);
    assert!(applied.status.success(), "{applied:?}");
    let json = records(&applied);
    assert_eq!(json[0]["fixed"], true);
    assert_eq!(json[1]["left"], 0);
    assert!(has(&drive, "b").await);
    let clean = teifs(&["repair", d]);
    assert!(clean.status.success(), "{clean:?}");
    assert!(String::from_utf8_lossy(&clean.stdout).contains("0 problems found"));

    // Not while the drive is open.
    let _open = Store::open(&drive).unwrap();
    let busy = teifs(&["repair", d]);
    assert_eq!(busy.status.code(), Some(6));
}
