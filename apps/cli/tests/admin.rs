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

use std::fs;

use common::{ACCESS_KEY, SECRET_KEY, start, start_with, user};
use harness::{Client, records};

#[tokio::test(flavor = "multi_thread")]
async fn info_and_configuration_for_people_and_programs() {
    let server = start().await;
    let cli = Client::new(&server);
    let out = cli.ok(&["admin", "info", "t"]).await;
    assert!(out.contains(&server.iam.account()), "{out}");
    assert!(out.contains("housekeeping") || out.contains("JOB"), "{out}");
    let info = records(&cli.ok(&["--json", "admin", "info", "t"]).await);
    assert_eq!(info[0]["type"], "server");
    assert_eq!(info[0]["account"], server.iam.account());
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
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let mut bytes = fs::read(path).unwrap();
    bytes[0] ^= 1;
    fs::write(path, bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
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
