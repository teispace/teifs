//! `teifs admin` through the real binary against TeiFS servers: info and configuration,
//! moving IAM between servers, and replacing a root key, with the exit codes and JSON
//! records scripts rely on.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;
mod harness;

use std::{fs, time::Duration};

use common::{ACCESS_KEY, SECRET_KEY, start, start_with, user};
use harness::{Client, records};

#[tokio::test(flavor = "multi_thread")]
async fn info_and_configuration_for_people_and_programs() {
    let server = start().await;
    let cli = Client::new(&server);
    let out = cli.ok(&["admin", "info", "t"]).await;
    assert!(out.contains(&server.iam.account()), "{out}");
    assert!(
        out.contains("0 B in 0 buckets: 0 objects, 0 versions, 0 delete markers"),
        "{out}"
    );
    assert!(out.contains("housekeeping") || out.contains("JOB"), "{out}");
    let drive = std::fs::canonicalize(server.dir.path()).unwrap();
    assert!(
        out.contains("Disk") && out.contains(&format!("{}: ", drive.display())),
        "{out}"
    );
    assert!(out.contains("kept free for deletes"), "{out}");
    let info = records(&cli.ok(&["--json", "admin", "info", "t"]).await);
    assert_eq!(info[0]["type"], "server");
    assert_eq!(info[0]["account"], server.iam.account());
    assert_eq!(info[0]["usage"]["buckets"], 0);
    let disk = &info[0]["disks"][0];
    assert_eq!(disk["path"], drive.display().to_string());
    assert!(disk["total"].as_u64().unwrap() >= disk["free"].as_u64().unwrap());
    assert!(disk["reserved"].as_u64().unwrap() >= 64 << 20);
    let out = cli.ok(&["admin", "config", "t"]).await;
    assert!(
        out.contains("given by environment") && out.contains("folder"),
        "{out}"
    );
    let config = records(&cli.ok(&["--json", "admin", "config", "t"]).await);
    assert_eq!(config[0]["type"], "serverConfig");
    assert_eq!(config[0]["rootCredentials"], "given");
    // An alias that doesn't exist, and keys that don't allow it.
    cli.fails(&["admin", "info", "nope"], 5).await;
    user(&server, "nobody", None);
    let key = server.iam.create_access_key("nobody").unwrap();
    let address = server.endpoint.trim_start_matches("http://");
    let mut other = Client::new(&server);
    other.env.push((
        "TEIFS_ALIAS_N".to_owned(),
        format!("http://{}:{}@{address}", key.info.id, key.secret.as_str()),
    ));
    let err = other.fails(&["admin", "info", "n"], 4).await;
    assert!(err.contains("AccessDenied"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn iam_moves_between_servers_through_a_file() {
    let (from, to) = (start().await, start().await);
    user(&from, "alice", None);
    let alice = from.iam.create_access_key("alice").unwrap();
    let cli = Client::new(&from);
    // Without secrets, to standard output.
    let out = cli.ok(&["admin", "iam", "export", "t"]).await;
    let export: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(export["users"][0]["name"], "alice");
    assert!(!out.contains(alice.secret.as_str()));
    // Secrets never go to the terminal; to a file, readable only by its owner.
    let err = cli
        .fails(&["admin", "iam", "export", "t", "--secrets"], 2)
        .await;
    assert!(err.contains("--output"), "{err}");
    let file = cli.path("iam.json");
    let path = file.to_str().unwrap();
    let run = cli
        .run(&["admin", "iam", "export", "t", "--secrets", "-o", path])
        .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(!run.stdout.contains(alice.secret.as_str()));
    assert!(
        fs::read_to_string(&file)
            .unwrap()
            .contains(alice.secret.as_str())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    cli.fails(&["admin", "iam", "export", "t", "--secrets", "-o", path], 6)
        .await;
    cli.ok(&[
        "admin",
        "iam",
        "export",
        "t",
        "--secrets",
        "-o",
        path,
        "--force",
    ])
    .await;

    let target = Client::new(&to);
    let imported = records(
        &target
            .ok(&[
                "--json",
                "admin",
                "iam",
                "import",
                "t",
                path,
                "--adopt-account",
            ])
            .await,
    );
    assert_eq!(imported[0]["type"], "iamImport");
    assert_eq!(
        (
            imported[0]["users"].as_u64(),
            imported[0]["accessKeys"].as_u64()
        ),
        (Some(1), Some(2))
    );
    assert_eq!(to.iam.account(), from.iam.account());
    assert!(to.iam.credential(&alice.info.id).is_some());
    // Only into an empty IAM; and only an export.
    target
        .fails(&["admin", "iam", "import", "t", path], 6)
        .await;
    fs::write(cli.path("junk.json"), "{}").unwrap();
    let junk = cli.path("junk.json");
    target
        .fails(&["admin", "iam", "import", "t", junk.to_str().unwrap()], 2)
        .await;
    target
        .fails(&["admin", "iam", "import", "t", "missing.json"], 5)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_generated_root_key_is_replaced_and_the_alias_follows() {
    let server = start_with(|config| config.credentials = None).await;
    let cli = Client::new(&server);
    let drive = server.dir.path().to_str().unwrap();
    cli.ok(&["alias", "set", "r", &server.endpoint, "--drive", drive])
        .await;
    // It asks first, and without a terminal to ask on it doesn't guess.
    let err = cli.fails(&["admin", "root-key", "rotate", "r"], 2).await;
    assert!(err.contains("--yes"), "{err}");
    let done = records(
        &cli.ok(&["--json", "-y", "admin", "root-key", "rotate", "r"])
            .await,
    );
    let kept = teifs_server::credentials::load(server.dir.path())
        .unwrap()
        .unwrap();
    assert_eq!(done[0]["type"], "rootKey");
    assert_eq!(done[0]["accessKey"], kept.access_key.as_str());
    assert_eq!(done[0]["aliasUpdated"], true);
    assert!(!done[0].to_string().contains(&kept.secret_key));
    let aliases = fs::read_to_string(cli.path("aliases.toml")).unwrap();
    assert!(aliases.contains(&kept.access_key) && aliases.contains(&kept.secret_key));
    cli.ok(&["admin", "info", "r"]).await;
    // A root key the server was given is changed where it was given.
    let given = start().await;
    let cli = Client::new(&given);
    let err = cli
        .fails(&["-y", "admin", "root-key", "rotate", "t"], 6)
        .await;
    assert!(err.contains("TEIFS_ACCESS_KEY"), "{err}");
    let root = common::client(&given, SECRET_KEY);
    assert!(
        root.list_buckets().send().await.is_ok(),
        "{ACCESS_KEY} still works"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn a_user_with_a_policy_and_a_key_in_one_step() {
    let server = start().await;
    let cli = Client::new(&server);
    for bucket in ["photos", "other"] {
        cli.ok(&["mb", &format!("t/{bucket}")]).await;
    }
    fs::write(cli.path("note.txt"), "hello").unwrap();
    // Read and write in one bucket, the key saved as an alias.
    let added = records(
        &cli.ok(&[
            "--json",
            "admin",
            "user",
            "add",
            "t",
            "alice",
            "--policy",
            "readwrite",
            "--bucket",
            "photos",
            "--save-alias",
            "alice",
        ])
        .await,
    );
    assert_eq!(added[0]["type"], "accessKey");
    assert!(added[0].get("secretKey").is_none(), "{}", added[0]);
    cli.ok(&["cp", "note.txt", "alice/photos/note.txt"]).await;
    cli.ok(&["ls", "alice"]).await;
    cli.fails(&["cp", "note.txt", "alice/other/note.txt"], 4)
        .await;
    // Read only, the key in a file only its owner reads.
    let file = cli.path("bob.json");
    let path = file.to_str().unwrap();
    cli.ok(&[
        "admin", "user", "add", "t", "bob", "--policy", "readonly", "-o", path,
    ])
    .await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let bob: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(
        (bob["user"].as_str(), bob["endpoint"].as_str()),
        (Some("bob"), Some(server.endpoint.as_str()))
    );
    let address = server.endpoint.trim_start_matches("http://");
    let mut as_bob = Client::new(&server);
    as_bob.env.push((
        "TEIFS_ALIAS_B".to_owned(),
        format!(
            "http://{}:{}@{address}",
            bob["accessKey"].as_str().unwrap(),
            bob["secretKey"].as_str().unwrap()
        ),
    ));
    fs::write(as_bob.path("note.txt"), "hello").unwrap();
    as_bob.ok(&["cat", "b/photos/note.txt"]).await;
    as_bob
        .fails(&["cp", "note.txt", "b/photos/bob.txt"], 4)
        .await;
    // A new policy takes effect at once.
    cli.ok(&[
        "admin",
        "user",
        "policy",
        "t",
        "bob",
        "--policy",
        "readwrite",
    ])
    .await;
    as_bob.ok(&["cp", "note.txt", "b/other/bob.txt"]).await;
    // Standard output, when asked for.
    let out = cli
        .ok(&["admin", "user", "key", "add", "t", "bob", "--output", "-"])
        .await;
    let printed = records(&out);
    assert!(printed[0]["secretKey"].is_string());
    let keys = records(
        &cli.ok(&["--json", "admin", "user", "key", "ls", "t", "bob"])
            .await,
    );
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter()
            .all(|k| k["status"] == "Active" && k.get("secretKey").is_none())
    );
    let listed = records(&cli.ok(&["--json", "admin", "user", "ls", "t"]).await);
    let names: Vec<_> = listed.iter().map(|u| u["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["alice", "bob"]);
    assert_eq!(listed[1]["policies"], serde_json::json!(["teifs-access"]));
    let table = cli.ok(&["admin", "user", "ls", "t"]).await;
    assert!(
        table.contains("teifs-access") && table.contains("bob"),
        "{table}"
    );
    // Deleting a key, then the user with everything it has.
    let second = printed[0]["accessKey"].as_str().unwrap();
    cli.ok(&["admin", "user", "key", "rm", "t", "bob", second])
        .await;
    assert!(server.iam.credential(second).is_none());
    cli.fails(&["admin", "user", "key", "rm", "t", "bob", second], 5)
        .await;
    server.iam.create_group("team", None).unwrap();
    server.iam.add_user_to_group("team", "bob").unwrap();
    let err = cli.fails(&["admin", "user", "rm", "t", "bob"], 2).await;
    assert!(err.contains("--yes"), "{err}");
    let removed = records(
        &cli.ok(&["--json", "-y", "admin", "user", "rm", "t", "bob"])
            .await,
    );
    assert_eq!(removed[0]["type"], "userDeleted");
    assert!(server.iam.user("bob").is_err());
    as_bob.fails(&["ls", "b"], 4).await;
    cli.fails(&["-y", "admin", "user", "rm", "t", "bob"], 5)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn a_user_is_added_whole_or_not_at_all() {
    let server = start().await;
    let cli = Client::new(&server);
    let add = |extra: &'static [&'static str]| {
        let mut args = vec!["admin", "user", "add", "t", "carol"];
        args.extend_from_slice(extra);
        args
    };
    // Refused before anything changes.
    for (args, code, says) in [
        (
            &["--policy", "admin", "--bucket", "b", "-o", "k.json"][..],
            2,
            "an admin",
        ),
        (
            &["--policy", "mine.json", "--bucket", "b", "-o", "k.json"][..],
            2,
            "--bucket is for",
        ),
        (
            &["--policy", "missing.json", "-o", "k.json"][..],
            5,
            "missing.json",
        ),
        (&["--policy", "readonly"][..], 2, "--output"),
        (
            &["--policy", "readonly", "-o", "k.json", "--save-alias", "c"][..],
            2,
            "cannot be used with",
        ),
        (
            &["--policy", "readonly", "--save-alias", "t"][..],
            6,
            "alias `t`",
        ),
        (
            &["--policy", "readonly", "--save-alias", "no/good"][..],
            2,
            "no/good",
        ),
    ] {
        let mut full = add(&[]);
        full.extend_from_slice(args);
        let err = cli.fails(&full, code).await;
        assert!(err.contains(says), "{args:?}: {err}");
    }
    assert!(server.iam.user("carol").is_err());
    fs::write(cli.path("taken.json"), "").unwrap();
    cli.fails(&add(&["--policy", "readonly", "-o", "taken.json"]), 6)
        .await;
    fs::write(cli.path("mine.json"), "{").unwrap();
    // A policy the server refuses, after the user was made: the user goes again.
    let err = cli
        .fails(&add(&["--policy", "mine.json", "-o", "k.json"]), 2)
        .await;
    assert!(err.contains("MalformedPolicyDocument"), "{err}");
    assert!(server.iam.user("carol").is_err());
    assert!(!cli.path("k.json").exists());
    // A user that's there already.
    user(&server, "carol", None);
    cli.fails(&add(&["--policy", "readonly", "-o", "k.json"]), 6)
        .await;
    assert!(server.iam.user("carol").is_ok());
    // A key that can't be written isn't kept: nobody would have its secret.
    cli.fails(
        &[
            "admin",
            "user",
            "key",
            "add",
            "t",
            "carol",
            "-o",
            "no/such/dir/k.json",
        ],
        1,
    )
    .await;
    let keys = records(
        &cli.ok(&["--json", "admin", "user", "key", "ls", "t", "carol"])
            .await,
    );
    assert_eq!(keys.len(), 1, "only the one it had: {keys:?}");
    // A policy from a file.
    fs::write(
        cli.path("mine.json"),
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}}"#,
    )
    .unwrap();
    cli.ok(&[
        "admin",
        "user",
        "policy",
        "t",
        "carol",
        "--policy",
        "mine.json",
    ])
    .await;
    cli.fails(
        &[
            "admin", "user", "policy", "t", "nobody", "--policy", "readonly",
        ],
        5,
    )
    .await;
}

/// Flips one bit of the file at `path`, keeping its size and modification time, as rot
/// on the disk would.
fn rot(path: &std::path::Path) {
    use std::io::Write as _;
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let first = fs::read(path).unwrap()[0];
    // In place, without truncating: a scrub between a truncation and the write would
    // find the file cut short instead.
    let mut file = fs::File::options().write(true).open(path).unwrap();
    file.write_all(&[first ^ 1]).unwrap();
    file.set_modified(modified).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn info_tells_what_scrubs_found() {
    let server = start_with(|config| {
        config.jobs.scrub_every = Some(std::time::Duration::from_millis(50));
    })
    .await;
    let cli = Client::new(&server);
    cli.ok(&["mb", "t/files"]).await;
    fs::write(cli.path("a.txt"), "hello").unwrap();
    cli.ok(&["cp", "a.txt", "t/files/a.txt"]).await;
    rot(&server.dir.path().join("files").join("a.txt"));
    // Passes come every 50 ms; one after the rot finds it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let scrub = loop {
        let info = records(&cli.ok(&["--json", "admin", "info", "t"]).await);
        let scrub = info[0]["scrub"].clone();
        if scrub["last"]["damaged"] == 1 {
            break scrub;
        }
        assert!(std::time::Instant::now() < deadline, "{scrub}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(scrub["last"]["findings"][0]["key"], "a.txt");
    // Uploaded through S3, it has a checksum (the SDK's CRC32), which is compared first.
    assert_eq!(scrub["last"]["findings"][0]["problem"], "checksum");
    assert_eq!(scrub["last"]["findings"][0]["algorithm"], "CRC32");
    let run = cli.run_with(&["admin", "info", "t"], "").await;
    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("Last scrub"), "{}", run.stdout);
    assert!(
        run.stderr
            .contains("damaged: files/a.txt: its bytes don't match its CRC32 checksum"),
        "{}",
        run.stderr
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshots_from_the_command_line() {
    let server = start().await;
    let cli = Client::new(&server);
    let out = cli.ok(&["admin", "snapshot", "take", "t"]).await;
    assert!(
        out.contains("Snapshotted the drive's metadata as "),
        "{out}"
    );
    let taken = records(&cli.ok(&["--json", "admin", "snapshot", "take", "t"]).await);
    assert_eq!(taken[0]["type"], "snapshot");
    let listed = records(&cli.ok(&["--json", "admin", "snapshot", "ls", "t"]).await);
    assert!(listed.iter().any(|r| r["name"] == taken[0]["name"]));
    let out = cli.ok(&["admin", "snapshot", "ls", "t"]).await;
    assert!(out.contains("NAME") && out.contains("TAKEN"), "{out}");
    let out = cli.ok(&["admin", "config", "t"]).await;
    assert!(
        out.contains("Snapshots kept") && out.contains("3, one a day"),
        "{out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn kms_keys_from_the_command_line() {
    let server = start().await;
    let cli = Client::new(&server);
    let out = cli.ok(&["admin", "kms", "status", "t"]).await;
    assert!(
        out.contains("TeiFS keyring")
            && out.contains("teifs-default")
            && out.contains("local (online)"),
        "{out}"
    );
    let out = cli
        .ok(&["admin", "kms", "key", "create", "t", "app-1"])
        .await;
    assert!(out.contains("Created key app-1 at t"), "{out}");
    let err = cli
        .fails(&["admin", "kms", "key", "create", "t", "app-1"], 6)
        .await;
    assert!(err.contains("already exists"), "{err}");
    let listed = records(
        &cli.ok(&["--json", "admin", "kms", "key", "list", "t", "app"])
            .await,
    );
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (&listed[0]["type"], &listed[0]["name"]),
        (&"kmsKey".into(), &"app-1".into())
    );
    let out = cli.ok(&["admin", "kms", "key", "list", "t"]).await;
    assert!(
        out.contains("app-1") && out.contains("teifs-default"),
        "{out}"
    );
    let out = cli
        .ok(&["admin", "kms", "key", "status", "t", "app-1"])
        .await;
    assert!(out.contains("Sealing") && out.contains("ok"), "{out}");
    let checked = records(
        &cli.ok(&["--json", "admin", "kms", "key", "status", "t"])
            .await,
    );
    assert_eq!(checked[0]["name"], "teifs-default");
    // A key that doesn't work fails the command.
    let err = cli
        .fails(&["admin", "kms", "key", "status", "t", "missing"], 1)
        .await;
    assert!(
        err.contains("key missing doesn't seal and unseal data keys"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn minio_settings_from_the_command_line() {
    let server = start().await;
    let cli = Client::new(&server);
    let out = cli
        .ok(&[
            "admin",
            "config",
            "set",
            "t",
            "identity_ldap",
            "server_addr=ldap.example.com:636",
            "lookup_bind_dn=cn=admin, dc=example",
            "lookup_bind_password=pw-1",
        ])
        .await;
    assert!(out.contains("Changed identity_ldap at t"), "{out}");
    let out = cli
        .ok(&["admin", "config", "get", "t", "identity_ldap"])
        .await;
    assert!(
        out.contains("server_addr=ldap.example.com:636")
            && out.contains("lookup_bind_dn=\"cn=admin, dc=example\"")
            && !out.contains("pw-1"),
        "{out}"
    );
    // The show stays as it was.
    let out = cli.ok(&["admin", "config", "t"]).await;
    assert!(out.contains("given by environment"), "{out}");
    let err = cli
        .fails(
            &[
                "admin",
                "config",
                "set",
                "t",
                "storage_class",
                "standard=EC:2",
            ],
            1,
        )
        .await;
    assert!(err.contains("storage_class"), "{err}");

    let keys = records(
        &cli.ok(&["--json", "admin", "config", "keys", "t", "identity_ldap"])
            .await,
    );
    assert!(keys.iter().any(|k| k["key"] == "server_addr"), "{keys:?}");

    let history = records(&cli.ok(&["--json", "admin", "config", "history", "t"]).await);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["targets"][0], "identity_ldap");
    assert!(
        !history[0].to_string().contains("pw-1"),
        "secrets aren't listed"
    );
    let id = history[0]["id"].as_str().unwrap().to_owned();

    cli.ok(&["admin", "config", "reset", "t", "identity_ldap"])
        .await;
    let out = cli
        .ok(&["admin", "config", "get", "t", "identity_ldap"])
        .await;
    assert!(!out.contains("ldap.example.com"), "{out}");
    cli.ok(&["admin", "config", "restore", "t", &id]).await;
    let out = cli
        .ok(&["admin", "config", "get", "t", "identity_ldap"])
        .await;
    assert!(out.contains("ldap.example.com"), "{out}");

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.txt");
    let path = file.to_str().unwrap();
    cli.ok(&["admin", "config", "export", "t", "-o", path])
        .await;
    let exported = fs::read_to_string(&file).unwrap();
    assert!(exported.contains("lookup_bind_password=pw-1"), "{exported}");
    cli.fails(&["admin", "config", "export", "t", "-o", path], 6)
        .await;
    fs::write(
        &file,
        "identity_plugin url=https://plugin.example.com role_policy=readonly\n",
    )
    .unwrap();
    cli.ok(&["admin", "config", "import", "t", path]).await;
    let out = cli.ok(&["admin", "config", "get", "t"]).await;
    assert!(
        out.contains("identity_plugin url=https://plugin.example.com")
            && !out.contains("ldap.example.com"),
        "{out}"
    );
    cli.ok(&["admin", "config", "clear-history", "t", "all"])
        .await;
    let out = cli.ok(&["admin", "config", "history", "t"]).await;
    assert!(!out.contains("identity_"), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn buckets_move_between_servers_through_a_file() {
    let (from, to) = (start().await, start().await);
    let cli = Client::new(&from);
    cli.ok(&["mb", "t/logs"]).await;
    cli.ok(&["mb", "t/other"]).await;
    cli.ok(&["version", "enable", "t/logs"]).await;
    // To standard output, all of them or one.
    let out = cli.ok(&["admin", "bucket", "export", "t"]).await;
    assert!(out.ends_with("}\n"), "{out}");
    let all: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(all["buckets"].as_array().unwrap().len(), 2);
    let one: serde_json::Value =
        serde_json::from_str(&cli.ok(&["admin", "bucket", "export", "t/logs"]).await).unwrap();
    assert_eq!(one["buckets"][0]["versioning"], "enabled");
    assert_eq!(one["buckets"].as_array().unwrap().len(), 1);
    cli.fails(&["admin", "bucket", "export", "t/nope"], 5).await;
    cli.fails(&["admin", "bucket", "export", "t/Bad_Name"], 2)
        .await;
    // To a file.
    let file = cli.path("buckets.json");
    let path = file.to_str().unwrap();
    let out = cli
        .ok(&["admin", "bucket", "export", "t", "-o", path])
        .await;
    assert!(out.contains("Exported 2 buckets to"), "{out}");
    cli.fails(&["admin", "bucket", "export", "t", "-o", path], 6)
        .await;

    let target = Client::new(&to);
    let out = target.ok(&["admin", "bucket", "import", "t", path]).await;
    assert!(
        out.contains("Imported 2 buckets: 2 created,") && out.contains("0 failed"),
        "{out}"
    );
    let again: serde_json::Value =
        serde_json::from_str(&target.ok(&["admin", "bucket", "export", "t"]).await).unwrap();
    assert_eq!(again["buckets"], all["buckets"]);
    let items = records(
        &target
            .ok(&["--json", "admin", "bucket", "import", "t", path])
            .await,
    );
    assert!(
        items[..items.len() - 1]
            .iter()
            .all(|r| r["type"] == "bucketImport" && r["outcome"] == "applied")
    );
    assert_eq!(items.last().unwrap()["type"], "bucketsImported");

    // An item that can't be applied is named, and the exit code says so.
    let mut broken = all.clone();
    broken["buckets"][0]["settings"]["policy"] = "not a policy".into();
    fs::write(cli.path("broken.json"), broken.to_string()).unwrap();
    let broken = cli.path("broken.json");
    let err = target
        .fails(
            &["admin", "bucket", "import", "t", broken.to_str().unwrap()],
            1,
        )
        .await;
    assert!(err.contains("logs: policy: "), "{err}");
    fs::write(cli.path("junk.json"), "{}").unwrap();
    let junk = cli.path("junk.json");
    target
        .fails(
            &["admin", "bucket", "import", "t", junk.to_str().unwrap()],
            2,
        )
        .await;
}

/// The token in a generated scrape configuration's `credentials: "…"` line.
fn token_in(config: &str) -> String {
    let line = config
        .lines()
        .find_map(|line| line.trim().strip_prefix("credentials: "))
        .unwrap();
    serde_json::from_str(line).unwrap()
}

async fn scrape(server: &common::Server, token: &str) -> u16 {
    reqwest::Client::new()
        .get(format!("{}/.teifs/metrics", server.endpoint))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn prometheus_scrapes_with_a_generated_configuration() {
    let server = start().await;
    let cli = Client::new(&server);
    let address = server.endpoint.trim_start_matches("http://");
    let config = cli.ok(&["admin", "prometheus", "generate", "t"]).await;
    assert!(
        config.starts_with("scrape_configs:\n  - job_name: teifs\n"),
        "{config}"
    );
    assert!(config.contains("    metrics_path: /.teifs/metrics\n    scheme: http\n"));
    assert!(
        config.ends_with(&format!("      - targets: [\"{address}\"]\n")),
        "{config}"
    );
    assert_eq!(scrape(&server, &token_in(&config)).await, 200);
    let config = cli
        .ok(&["admin", "prometheus", "generate", "t", "--buckets"])
        .await;
    assert!(
        config.contains("    metrics_path: /.teifs/metrics\n    params:\n      buckets: [\"1\"]\n    scheme: http\n"),
        "{config}"
    );

    // In a file of its own, which the configuration names; one that expires.
    let file = cli.path("token");
    let path = file.to_str().unwrap();
    let config = cli
        .ok(&[
            "admin",
            "prometheus",
            "generate",
            "t",
            "--expires",
            "1h",
            "--token-file",
            path,
        ])
        .await;
    assert!(config.contains("credentials_file: \""), "{config}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        scrape(&server, &fs::read_to_string(&file).unwrap()).await,
        200
    );
    cli.fails(
        &["admin", "prometheus", "generate", "t", "--token-file", path],
        6,
    )
    .await;
    let json = records(
        &cli.ok(&[
            "--json",
            "admin",
            "prometheus",
            "generate",
            "t",
            "--expires",
            "1d",
        ])
        .await,
    );
    assert_eq!(json[0]["type"], "prometheusConfig");
    assert!(json[0]["expires"].as_i64().unwrap() > 0);

    // A key that may not scrape makes a token that's refused.
    user(&server, "nobody", None);
    let key = server.iam.create_access_key("nobody").unwrap();
    let mut other = Client::new(&server);
    other.env.push((
        "TEIFS_ALIAS_N".to_owned(),
        format!("http://{}:{}@{address}", key.info.id, key.secret.as_str()),
    ));
    let config = other.ok(&["admin", "prometheus", "generate", "n"]).await;
    assert_eq!(scrape(&server, &token_in(&config)).await, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn trace_prints_requests_until_the_server_stops() {
    let server = start_with(|config| config.public_metrics = true).await;
    let endpoint = server.endpoint.clone();
    let cli = Client::new(&server);
    let tracing = tokio::spawn(async move {
        cli.run(&[
            "--json", "admin", "trace", "t", "--bucket", "traced", "--errors",
        ])
        .await
    });
    // The trace is a request in flight while it lasts.
    let scrape = format!("{endpoint}/.teifs/metrics");
    let mut watched = false;
    for _ in 0..1000 {
        let text = reqwest::get(&scrape).await.unwrap().text().await.unwrap();
        watched = text.contains("teifs_s3_requests_inflight 1");
        if watched {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(watched, "the trace never started");
    let s3 = common::client(&server, SECRET_KEY);
    s3.create_bucket().bucket("traced").send().await.unwrap();
    s3.get_object()
        .bucket("traced")
        .key("gone")
        .send()
        .await
        .unwrap_err();
    s3.head_bucket()
        .bucket("elsewhere")
        .send()
        .await
        .unwrap_err();
    // Entries reach the trace just after their answers.
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(server);
    let run = tracing.await.unwrap();
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    let traced = records(&run.stdout);
    assert_eq!(traced.len(), 1, "{}", run.stdout);
    assert_eq!(traced[0]["type"], "trace");
    assert_eq!(traced[0]["api"]["name"], "GetObject");
    assert_eq!(traced[0]["error"], "NoSuchKey");
}

/// `teifs status`: each check, for people and programs, with exit code 1 when one fails.
#[tokio::test(flavor = "multi_thread")]
async fn status_checks_a_server() {
    let server = start().await;
    let cli = Client::new(&server);
    let out = cli.ok(&["status", "t"]).await;
    for line in ["Server", "Clock", "Drive", "Writes", "Version", "Disk"] {
        assert!(out.contains(line), "{line}: {out}");
    }
    assert!(!out.contains("failed"), "{out}");
    let checks = records(&cli.ok(&["--json", "status", "t"]).await);
    let names: Vec<&str> = checks.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        ["Server", "Clock", "Drive", "Writes", "Version", "Disk"]
    );
    for check in &checks {
        assert_eq!(check["type"], "check");
        // How full this machine's disk is isn't the test's to choose.
        let expected: &[&str] = if check["name"] == "Disk" {
            &["ok", "warning"]
        } else {
            &["ok"]
        };
        assert!(
            expected.contains(&check["state"].as_str().unwrap()),
            "{check}"
        );
        assert_eq!(check["server"], server.endpoint);
    }
    // Keys that may not read the server's info: what can be checked without them.
    user(&server, "nobody", None);
    let key = server.iam.create_access_key("nobody").unwrap();
    let address = server.endpoint.trim_start_matches("http://");
    let mut other = Client::new(&server);
    other.env.push((
        "TEIFS_ALIAS_N".to_owned(),
        format!("http://{}:{}@{address}", key.info.id, key.secret.as_str()),
    ));
    let checks = records(&other.ok(&["--json", "status", "n"]).await);
    let last = checks.last().unwrap();
    assert_eq!(
        (&last["name"], &last["state"]),
        (&"Server info".into(), &"warning".into())
    );
    // A server that doesn't answer: a failure.
    let mut gone = Client::new(&server);
    gone.env.push((
        "TEIFS_ALIAS_G".to_owned(),
        format!("http://{ACCESS_KEY}:{SECRET_KEY}@127.0.0.1:9"),
    ));
    let run = gone.run(&["--json", "status", "g"]).await;
    assert_eq!(run.code, 1, "{}", run.stderr);
    let checks = records(&run.stdout);
    assert_eq!(checks.len(), 1);
    assert_eq!(
        (&checks[0]["name"], &checks[0]["state"]),
        (&"Server".into(), &"failed".into())
    );
    cli.fails(&["status", "nope"], 5).await;
}
