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

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn roles_and_providers_in_one_step() {
    let server = start().await;
    let account = server.iam.account();
    let mut cli = as_user(&server);
    user(&server, "bob", Some(ALLOW_ALL));
    let bob = server.iam.create_access_key("bob").unwrap();
    let address = server.endpoint.trim_start_matches("http://");
    cli.env.push((
        "TEIFS_ALIAS_B".to_owned(),
        format!("http://{}:{}@{address}", bob.info.id, bob.secret.as_str()),
    ));
    cli.ok(&["mb", "t/photos"]).await;
    cli.ok(&["mb", "t/other"]).await;
    let file = cli.path("a.txt");
    fs::write(&file, "a").unwrap();
    let file = file.to_str().unwrap();

    // Trusting the account, for one bucket, with longer sessions.
    cli.ok(&[
        "admin",
        "role",
        "add",
        "t",
        "deploy",
        "--trust",
        "account",
        "--policy",
        "readwrite",
        "--bucket",
        "photos",
        "--max-session",
        "2h",
    ])
    .await;
    cli.ok(&[
        "sts",
        "assume",
        "a",
        "deploy",
        "--duration",
        "2h",
        "--save-alias",
        "d",
    ])
    .await;
    cli.ok(&["cp", file, "d/photos/a.txt"]).await;
    cli.fails(&["cp", file, "d/other/a.txt"], 4).await;
    // Trusting one user.
    cli.ok(&[
        "admin",
        "role",
        "add",
        "t",
        "solo",
        "--trust",
        "user:alice",
        "--policy",
        "readonly",
    ])
    .await;
    cli.ok(&["sts", "assume", "a", "solo", "-o", "-"]).await;
    cli.fails(&["sts", "assume", "b", "solo", "-o", "-"], 4)
        .await;
    let roles = records(&cli.ok(&["--json", "admin", "role", "ls", "t"]).await);
    let deploy = roles.iter().find(|r| r["name"] == "deploy").unwrap();
    assert_eq!(deploy["trusts"], serde_json::json!(["account"]));
    assert_eq!(deploy["policies"], serde_json::json!(["teifs-access"]));
    assert_eq!(deploy["maxSessionSeconds"], 7200);
    let solo = roles.iter().find(|r| r["name"] == "solo").unwrap();
    assert_eq!(solo["trusts"], serde_json::json!(["user/alice"]));
    assert!(
        cli.ok(&["admin", "role", "ls", "t"])
            .await
            .contains("user/alice")
    );

    // Changing what it may do and whom it trusts.
    cli.ok(&[
        "admin", "role", "policy", "t", "deploy", "--policy", "readonly",
    ])
    .await;
    cli.fails(&["cp", file, "d/photos/b.txt"], 4).await;
    cli.ok(&["admin", "role", "trust", "t", "solo", "--trust", "account"])
        .await;
    cli.ok(&["sts", "assume", "b", "solo", "-o", "-"]).await;

    // Refused before anything changes.
    let err = cli
        .fails(
            &[
                "admin",
                "role",
                "add",
                "t",
                "x",
                "--trust",
                "user:nobody",
                "--policy",
                "readonly",
            ],
            5,
        )
        .await;
    assert!(err.contains("nobody"), "{err}");
    let err = cli
        .fails(
            &[
                "admin",
                "role",
                "add",
                "t",
                "x",
                "--trust",
                "nothing.json",
                "--policy",
                "readonly",
            ],
            5,
        )
        .await;
    assert!(err.contains("github:OWNER/REPO"), "{err}");
    cli.fails(
        &[
            "admin", "role", "add", "t", "x", "--trust", "account", "--sub", "a", "--policy",
            "readonly",
        ],
        2,
    )
    .await;
    let err = cli
        .fails(
            &[
                "admin",
                "role",
                "add",
                "t",
                "x",
                "--trust",
                "github:acme/site",
                "--policy",
                "readonly",
            ],
            5,
        )
        .await;
    assert!(err.contains("teifs admin oidc add"), "{err}");
    // A policy the server refuses leaves no half-made role behind.
    let bad = cli.path("bad-policy.json");
    fs::write(
        &bad,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Maybe"}]}"#,
    )
    .unwrap();
    cli.fails(
        &[
            "admin",
            "role",
            "add",
            "t",
            "x",
            "--trust",
            "account",
            "--policy",
            bad.to_str().unwrap(),
        ],
        2,
    )
    .await;
    assert_eq!(
        records(&cli.ok(&["--json", "admin", "role", "ls", "t"]).await).len(),
        2
    );

    // An OpenID Connect provider, and a role for some of its subjects.
    let idp = Idp::start().await;
    let host = idp.url.trim_start_matches("http://").to_owned();
    cli.ok(&[
        "admin",
        "oidc",
        "add",
        "t",
        "https://0.idp.example.com",
        "--client-id",
        "other",
    ])
    .await;
    cli.ok(&[
        "admin",
        "oidc",
        "add",
        "t",
        &idp.url,
        "--client-id",
        "sts.amazonaws.com",
        "--policy-claim",
    ])
    .await;
    let providers = records(&cli.ok(&["--json", "admin", "oidc", "ls", "t"]).await);
    let ours = providers
        .iter()
        .find(|p| p["url"] == host.as_str())
        .unwrap();
    assert_eq!(ours["policyClaim"], "policy");
    assert_eq!(providers.len(), 2);
    cli.fails(
        &[
            "admin",
            "role",
            "add",
            "t",
            "ci",
            "--trust",
            &format!("oidc:{host}"),
            "--policy",
            "readwrite",
        ],
        2,
    )
    .await;
    cli.ok(&[
        "admin",
        "role",
        "add",
        "t",
        "ci",
        "--trust",
        &format!("oidc:{host}"),
        "--sub",
        "repo:acme/*",
        "--policy",
        "readwrite",
    ])
    .await;
    let role = format!("arn:aws:iam::{account}:role/ci");
    let token = cli.path("token");
    let token_path = token.to_str().unwrap();
    for (sub, works) in [("repo:acme/site", true), ("repo:evil/site", false)] {
        fs::write(&token, idp.token(sub, "")).unwrap();
        let args = [
            "sts",
            "assume-web",
            &server.endpoint,
            "--role",
            &role,
            "--token-file",
            token_path,
            "-o",
            "-",
        ];
        if works {
            cli.ok(&args).await;
        } else {
            cli.fails(&args, 4).await;
        }
    }
    // The provider lets its tokens name policies, for sessions without a role.
    fs::write(&token, idp.token("anyone", r#","policy":"nothing""#)).unwrap();
    let err = cli
        .fails(
            &[
                "sts",
                "assume-web",
                &server.endpoint,
                "--token-file",
                token_path,
                "-o",
                "-",
            ],
            1,
        )
        .await;
    assert!(err.contains("None of the given policies"), "{err}");

    // Deleting asks first, and without a terminal to ask on it doesn't guess.
    let err = cli.fails(&["admin", "role", "rm", "t", "deploy"], 2).await;
    assert!(err.contains("--yes"), "{err}");
    let err = cli.fails(&["admin", "oidc", "rm", "t", &host], 2).await;
    assert!(err.contains("--yes"), "{err}");
    assert_eq!(
        records(&cli.ok(&["--json", "admin", "oidc", "ls", "t"]).await).len(),
        2
    );

    // Deleting a role ends its sessions, whatever policies it has; deleting a provider,
    // its tokens' use.
    let extra = server
        .iam
        .create_policy("extra", None, None, ALLOW_ALL, &[])
        .unwrap();
    server
        .iam
        .attach(Owner::Role("deploy"), &extra.arn)
        .unwrap();
    cli.ok(&["-y", "admin", "role", "rm", "t", "deploy"]).await;
    cli.fails(&["ls", "d/photos"], 4).await;
    cli.ok(&["-y", "admin", "role", "rm", "t", "ci"]).await;
    cli.ok(&["-y", "admin", "oidc", "rm", "t", &idp.url]).await;
    let providers = records(&cli.ok(&["--json", "admin", "oidc", "ls", "t"]).await);
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["url"], "0.idp.example.com");
    cli.fails(&["-y", "admin", "oidc", "rm", "t", &host], 5)
        .await;
}
