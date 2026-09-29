//! `teifs sts` through the real binary against a TeiFS server: whom an alias signs as,
//! roles' sessions and MinIO's sessions saved as aliases or written as AWS's
//! `credential_process` output, CI tokens exchanged for credentials, and aliases whose
//! credentials have expired.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;
mod harness;

use std::fs;

use common::{Server, idp::Idp, start, user};
use harness::{Client, records};
use teifs_iam::{NewRole, Owner};

const ALLOW_ALL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

/// A role the account's principals may assume if their policies let them; it may do
/// anything.
fn role(server: &Server, name: &str, trust: &str) {
    server
        .iam
        .create_role(
            name,
            &NewRole {
                trust,
                ..NewRole::default()
            },
        )
        .unwrap();
    server
        .iam
        .put_inline(Owner::Role(name), "all", ALLOW_ALL)
        .unwrap();
}

/// A client with alias `a` for a user who may do anything.
fn as_user(server: &Server) -> Client {
    user(server, "alice", Some(ALLOW_ALL));
    let key = server.iam.create_access_key("alice").unwrap();
    let mut cli = Client::new(server);
    let address = server.endpoint.trim_start_matches("http://");
    cli.env.push((
        "TEIFS_ALIAS_A".to_owned(),
        format!("http://{}:{}@{address}", key.info.id, key.secret.as_str()),
    ));
    cli
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn role_sessions_become_aliases_and_credential_processes() {
    let server = start().await;
    let account = server.iam.account();
    role(
        &server,
        "deploy",
        &format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:root"}},"Action":["sts:AssumeRole","sts:TagSession"]}}]}}"#
        ),
    );
    let cli = as_user(&server);
    cli.ok(&["mb", "t/photos"]).await;

    let me = records(&cli.ok(&["--json", "sts", "whoami", "a"]).await);
    assert_eq!(me[0]["arn"], format!("arn:aws:iam::{account}:user/alice"));
    assert_eq!(me[0]["account"], account);

    // A role by name, saved as an alias that works for S3, IAM and the admin API.
    let out = cli
        .ok(&[
            "sts",
            "assume",
            "a",
            "deploy",
            "--session-name",
            "ci",
            "--duration",
            "15m",
            "--tag",
            "team=web",
            "--save-alias",
            "d",
        ])
        .await;
    assert!(out.contains("alias `d`"), "{out}");
    let session = records(&cli.ok(&["--json", "sts", "whoami", "d"]).await);
    assert_eq!(
        session[0]["arn"],
        format!("arn:aws:sts::{account}:assumed-role/deploy/ci")
    );
    let file = cli.path("hello.txt");
    fs::write(&file, "hello").unwrap();
    cli.ok(&["cp", file.to_str().unwrap(), "d/photos/hello.txt"])
        .await;
    assert_eq!(cli.ok(&["cat", "d/photos/hello.txt"]).await, "hello");
    cli.ok(&["admin", "info", "d"]).await;
    assert!(
        cli.ok(&["admin", "user", "ls", "d"])
            .await
            .contains("alice")
    );
    // A user added through the session gets an alias of its own long-term key.
    cli.ok(&[
        "admin",
        "user",
        "add",
        "d",
        "bob",
        "--policy",
        "readonly",
        "--save-alias",
        "b",
    ])
    .await;
    let bob = records(&cli.ok(&["--json", "sts", "whoami", "b"]).await);
    assert_eq!(bob[0]["arn"], format!("arn:aws:iam::{account}:user/bob"));
    let listed = records(&cli.ok(&["--json", "alias", "ls"]).await);
    let d = listed.iter().find(|r| r["name"] == "d").unwrap();
    assert_eq!(d["temporary"], true);
    let left = d["expiresMs"].as_i64().unwrap() - now_ms();
    assert!((800_000..=900_000).contains(&left), "{left}");
    // The file keeps the token and when it expires, never shows them.
    let saved = fs::read_to_string(cli.path("aliases.toml")).unwrap();
    assert!(
        saved.contains("session-token = ") && saved.contains("expires = "),
        "{saved}"
    );
    assert!(!cli.ok(&["alias", "ls"]).await.contains("session"));
    // Assuming again refreshes it; a long-term alias is never replaced.
    cli.ok(&["sts", "assume", "a", "deploy", "--save-alias", "d"])
        .await;
    let set = cli
        .run_with(
            &[
                "alias",
                "set",
                "keep",
                &server.endpoint,
                "--access-key",
                "x",
                "--no-check",
                "--secret-key-stdin",
            ],
            "long-term-secret\n",
        )
        .await;
    assert_eq!(set.code, 0, "{}", set.stderr);
    let err = cli
        .fails(&["sts", "assume", "a", "deploy", "--save-alias", "keep"], 6)
        .await;
    assert!(err.contains("long-term keys"), "{err}");

    // As the AWS CLI's credential_process: to standard output when asked, or a file.
    let process: serde_json::Value = serde_json::from_str(
        &cli.ok(&[
            "sts",
            "assume",
            "a",
            &format!("arn:aws:iam::{account}:role/deploy"),
            "-o",
            "-",
        ])
        .await,
    )
    .unwrap();
    assert_eq!(process["Version"], 1);
    for field in [
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "Expiration",
    ] {
        assert!(
            process[field].as_str().is_some_and(|v| !v.is_empty()),
            "{field}"
        );
    }
    let out_file = cli.path("creds.json");
    cli.ok(&[
        "sts",
        "assume",
        "a",
        "deploy",
        "-o",
        out_file.to_str().unwrap(),
    ])
    .await;
    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out_file).unwrap()).unwrap();
    assert_eq!(written["Version"], 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&out_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // MinIO's way, without a role: the user's own permissions, narrowed.
    let readonly = cli.path("readonly.json");
    fs::write(
        &readonly,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}"#,
    )
    .unwrap();
    cli.ok(&[
        "sts",
        "assume",
        "a",
        "--policy",
        readonly.to_str().unwrap(),
        "--save-alias",
        "r",
    ])
    .await;
    assert_eq!(cli.ok(&["cat", "r/photos/hello.txt"]).await, "hello");
    let err = cli
        .fails(&["cp", file.to_str().unwrap(), "r/photos/other.txt"], 4)
        .await;
    assert!(err.contains("AccessDenied"), "{err}");
    let err = cli
        .fails(&["sts", "assume", "a", "--tag", "k=v", "-o", "-"], 2)
        .await;
    assert!(err.contains("for a role"), "{err}");

    // A role that doesn't trust the caller, and one that isn't there.
    let err = cli
        .fails(&["sts", "assume", "t", "deploy", "-o", "-"], 4)
        .await;
    assert!(err.contains("AccessDenied"), "{err}");
    cli.fails(&["sts", "assume", "a", "nobody", "-o", "-"], 4)
        .await;

    // Once expired, an alias is refused before any request, with what to do.
    let expired = fs::read_to_string(cli.path("aliases.toml"))
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("expires = ") {
                "expires = 2001-02-03T04:05:06Z".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(cli.path("aliases.toml"), expired).unwrap();
    let err = cli.fails(&["ls", "d/photos"], 4).await;
    assert!(
        err.contains("expired at 2001-02-03 04:05:06 UTC") && err.contains("teifs sts assume"),
        "{err}"
    );
    cli.fails(&["admin", "info", "d"], 4).await;
    cli.fails(&["sts", "whoami", "d"], 4).await;
    assert!(cli.ok(&["alias", "ls"]).await.contains("expired"));
}

#[tokio::test(flavor = "multi_thread")]
async fn ci_tokens_become_credentials() {
    let server = start().await;
    let account = server.iam.account();
    let idp = Idp::start().await;
    let provider = server
        .iam
        .create_oidc_provider(&teifs_iam::NewOidcProvider {
            url: &idp.url,
            client_ids: &["sts.amazonaws.com".to_owned()],
            ..teifs_iam::NewOidcProvider::default()
        })
        .unwrap()
        .arn;
    role(
        &server,
        "ci",
        &format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Federated":"{provider}"}},"Action":"sts:AssumeRoleWithWebIdentity"}}]}}"#
        ),
    );
    let mut cli = Client::new(&server);
    let token = cli.path("token");
    fs::write(&token, idp.token("repo:acme/site", "")).unwrap();
    // As a CI job has it: the role and the token's file in AWS's variables, and only
    // the server's address.
    cli.env.extend([
        (
            "AWS_ROLE_ARN".to_owned(),
            format!("arn:aws:iam::{account}:role/ci"),
        ),
        (
            "AWS_WEB_IDENTITY_TOKEN_FILE".to_owned(),
            token.display().to_string(),
        ),
    ]);
    cli.ok(&["sts", "assume-web", &server.endpoint, "--save-alias", "ci"])
        .await;
    let me = records(&cli.ok(&["--json", "sts", "whoami", "ci"]).await);
    assert_eq!(
        me[0]["arn"],
        format!("arn:aws:sts::{account}:assumed-role/ci/teifs")
    );
    cli.ok(&["mb", "ci/built"]).await;
    // An alias names the server too; its keys have no part, even wrong ones.
    let address = server.endpoint.trim_start_matches("http://");
    cli.env.push((
        "TEIFS_ALIAS_WRONG".to_owned(),
        format!("http://nobody:wrong-secret@{address}"),
    ));
    cli.ok(&["sts", "assume-web", "wrong", "-o", "-"]).await;

    fs::write(&token, "not-a-token").unwrap();
    let err = cli
        .fails(&["sts", "assume-web", &server.endpoint, "-o", "-"], 1)
        .await;
    assert!(err.contains("InvalidIdentityToken"), "{err}");
    fs::remove_file(&token).unwrap();
    cli.fails(&["sts", "assume-web", &server.endpoint, "-o", "-"], 5)
        .await;
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}
