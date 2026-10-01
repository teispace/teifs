//! `teifs sts assume-custom` through the real binary, against a server that checks
//! custom tokens with the fake identity plugin.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;
mod harness;

use common::start_with;
use harness::{Client, records};
use teifs_iam::plugin::fake::FakePlugin;

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn a_plugins_token_gets_a_session_with_the_roles_policies() {
    let plugin = FakePlugin::start().await;
    let settings = plugin.settings(&["read-photos"]);
    let server = start_with(|config| config.identity_plugin = Some(settings)).await;
    server
        .iam
        .create_policy("read-photos", None, None, READ_PHOTOS, &[])
        .unwrap();
    let mut cli = Client::new(&server);
    cli.ok(&["mb", "t/photos"]).await;
    let info = cli.ok(&["admin", "config", "t"]).await;
    assert!(info.contains("idmp-tests (read-photos)"), "{info}");
    let role = "arn:minio:iam:::role/idmp-tests";
    plugin.vouch("good-token", "alice", 3600);

    // The token from standard input; the session saved as an alias.
    let run = cli
        .run_with(
            &[
                "sts",
                "assume-custom",
                &server.endpoint,
                "--role-arn",
                role,
                "--token-stdin",
                "--save-alias",
                "a",
            ],
            "good-token\n",
        )
        .await;
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    let me = records(&cli.ok(&["--json", "sts", "whoami", "a"]).await);
    assert_eq!(
        me[0]["arn"],
        format!("arn:aws:sts::{}:federated-user/alice", server.iam.account())
    );
    cli.ok(&["ls", "a/photos"]).await;
    cli.fails(&["mb", "a/other"], 4).await;

    // From the environment, written as AWS's `credential_process` output.
    cli.env
        .push(("TEIFS_STS_CUSTOM_TOKEN".to_owned(), "good-token".to_owned()));
    let args = [
        "sts",
        "assume-custom",
        &server.endpoint,
        "--role-arn",
        role,
        "-o",
        "-",
    ];
    let out = cli.ok(&args).await;
    let process: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(
        process["SessionToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    cli.env.pop();
    cli.env
        .push(("TEIFS_STS_CUSTOM_TOKEN".to_owned(), "wrong".to_owned()));
    let err = cli.fails(&args, 4).await;
    assert!(err.contains("AccessDenied"), "{err}");
    assert!(!err.contains("wrong"), "the token is shown: {err}");
    cli.env.pop();
    // Without a token, and nobody to ask for one.
    let err = cli.fails(&args, 2).await;
    assert!(
        err.contains("give the token with --token-stdin or TEIFS_STS_CUSTOM_TOKEN"),
        "{err}"
    );
}
