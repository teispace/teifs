//! `teifs verify`, through the real binary against a drive made here: damage planted on
//! the disk is reported and fails the command; what can't be checked is told apart.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
    sync::Arc,
};

use teifs_store::{Encryption, Layout, LocalKms, ObjectAttrs, Precondition, Store, StoreOptions};

/// `teifs --json verify ARGS --dir DRIVE --kms-keyring KEYRING`.
fn verify(drive: &Path, keyring: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_teifs"));
    command
        .args(["--json", "verify"])
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

/// The JSON lines `output` printed.
fn records(output: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The summary record.
fn summary(output: &Output) -> serde_json::Value {
    records(output)
        .into_iter()
        .find(|r| r["type"] == "verified")
        .unwrap()
}

async fn put(store: &Store, bucket: &str, key: &str, encryption: &Encryption) {
    let mut staged = store.stage_for(bucket, encryption).await.unwrap();
    staged.write(&[b'x'; 5000]).await.unwrap();
    store
        .commit(
            bucket,
            key,
            staged,
            ObjectAttrs::default(),
            Precondition::default(),
        )
        .await
        .unwrap();
}

/// Flips one bit of the file at `path`, keeping its size and modification time, as rot
/// on the disk would.
fn rot(path: &Path) {
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let mut bytes = fs::read(path).unwrap();
    bytes[100] ^= 1;
    fs::write(path, bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
}

#[tokio::test]
async fn damage_fails_the_command_and_is_named() {
    let home = tempfile::tempdir().unwrap();
    let (drive, keyring) = (home.path().join("drive"), home.path().join("keyring.json"));
    fs::create_dir(&drive).unwrap();
    {
        let kms = Arc::new(LocalKms::open(&keyring).unwrap());
        let options = StoreOptions {
            kms: Some(kms),
            ..StoreOptions::default()
        };
        let store = Store::open_with(&drive, options).unwrap();
        store.create_bucket("dir", Layout::Folder).await.unwrap();
        store.create_bucket("obj", Layout::Object).await.unwrap();
        put(&store, "dir", "a.txt", &Encryption::None).await;
        put(&store, "dir", "b.txt", &Encryption::None).await;
        put(&store, "obj", "sealed", &Encryption::S3).await;
    }

    let clean = verify(&drive, &keyring, &[]);
    assert!(clean.status.success(), "{clean:?}");
    let all = summary(&clean);
    assert_eq!((&all["versions"], &all["damaged"]), (&3.into(), &0.into()));
    assert_eq!(all["bytes"], 15_000);

    // Without the keyring, the encrypted object isn't checked, and no keyring is made.
    let elsewhere = home.path().join("elsewhere.json");
    let unsealed = verify(&drive, &elsewhere, &[]);
    assert!(unsealed.status.success());
    assert!(!elsewhere.exists());
    let problems = records(&unsealed);
    assert_eq!(
        (&problems[0]["key"], &problems[0]["reason"]),
        (&"sealed".into(), &"noKms".into())
    );
    assert_eq!(summary(&unsealed)["unverifiable"], 1);

    rot(&drive.join("dir").join("a.txt"));
    let damaged = verify(&drive, &keyring, &[]);
    assert_eq!(damaged.status.code(), Some(1));
    let problems = records(&damaged);
    assert_eq!(problems[0]["type"], "verify");
    assert_eq!(
        (&problems[0]["bucket"], &problems[0]["key"]),
        (&"dir".into(), &"a.txt".into())
    );
    assert_eq!(
        (&problems[0]["verdict"], &problems[0]["problem"]),
        (&"damaged".into(), &"etag".into())
    );
    assert_eq!(summary(&damaged)["damaged"], 1);
    assert!(problems.iter().any(|r| r["type"] == "error"));

    // One bucket: the other's damage isn't looked at.
    let one = verify(&drive, &keyring, &["--bucket", "obj"]);
    assert!(one.status.success());
    assert_eq!(summary(&one)["versions"], 1);
    let missing = verify(&drive, &keyring, &["--bucket", "nope"]);
    assert_eq!(missing.status.code(), Some(5));
}
