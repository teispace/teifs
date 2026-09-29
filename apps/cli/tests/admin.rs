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
