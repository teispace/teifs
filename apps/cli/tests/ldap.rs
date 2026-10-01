//! `teifs admin ldap policy` and `teifs sts assume-ldap` through the real binary,
//! against a server that signs users in with the fake LDAP directory.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;
mod harness;

use common::start_with;
use harness::{Client, records};
use teifs_iam::ldap::fake::FakeLdap;

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}"#;
const PROJECT_A: &str = "cn=projecta,ou=groups,dc=min,dc=io";

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn ldap_users_get_sessions_with_their_mapped_policies() {
    let fake = FakeLdap::start().await;
    let settings = fake.settings();
    let server = start_with(|config| config.ldap = Some(settings)).await;
    server
        .iam
        .create_policy("read-photos", None, None, READ_PHOTOS, &[])
        .unwrap();
    let mut cli = Client::new(&server);
    cli.ok(&["mb", "t/photos"]).await;

    let out = cli
        .ok(&[
            "admin",
            "ldap",
            "policy",
            "attach",
            "t",
            "read-photos",
            "--group",
            "CN=ProjectA,OU=Groups,DC=min,DC=io",
        ])
        .await;
    assert!(
        out.contains(&format!("Attached read-photos for group {PROJECT_A}")),
        "{out}"
    );
    let listed = records(
        &cli.ok(&["--json", "admin", "ldap", "policy", "ls", "t"])
            .await,
    );
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["dn"], PROJECT_A);
    assert_eq!(listed[0]["entity"], "group");
    let users = cli
        .ok(&["admin", "ldap", "policy", "ls", "t", "--user", PROJECT_A])
        .await;
    assert!(!users.contains(PROJECT_A), "{users}");
    let err = cli
        .fails(
            &[
                "admin",
                "ldap",
                "policy",
                "attach",
                "t",
                "read-photos",
                "--user",
                "uid=nobody,ou=people,dc=min,dc=io",
            ],
            5,
        )
        .await;
    assert!(err.contains("NoSuchEntity"), "{err}");

    // The password from standard input; the session saved as an alias.
    let run = cli
        .run_with(
            &[
                "sts",
                "assume-ldap",
                &server.endpoint,
                "-u",
                "dillon",
                "--password-stdin",
                "--save-alias",
                "d",
            ],
            "dillon-password\n",
        )
        .await;
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    let me = records(&cli.ok(&["--json", "sts", "whoami", "d"]).await);
    assert_eq!(
        me[0]["arn"],
        format!(
            "arn:aws:sts::{}:federated-user/dillon",
            server.iam.account()
        )
    );
    cli.ok(&["ls", "d/photos"]).await;
    cli.fails(&["mb", "d/other"], 4).await;

    // From the environment, written as AWS's `credential_process` output.
    cli.env.push((
        "TEIFS_LDAP_PASSWORD".to_owned(),
        "dillon-password".to_owned(),
    ));
    let out = cli
        .ok(&[
            "sts",
            "assume-ldap",
            &server.endpoint,
            "-u",
            "dillon",
            "-o",
            "-",
        ])
        .await;
    let process: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(process["Version"], 1);
    assert!(
        process["SessionToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    cli.env.pop();
    cli.env
        .push(("TEIFS_LDAP_PASSWORD".to_owned(), "wrong".to_owned()));
    let err = cli
        .fails(
            &[
                "sts",
                "assume-ldap",
                &server.endpoint,
                "-u",
                "dillon",
                "-o",
                "-",
            ],
            1,
        )
        .await;
    assert!(err.contains("InvalidParameterValue"), "{err}");

    let out = cli
        .ok(&[
            "admin",
            "ldap",
            "policy",
            "detach",
            "t",
            "read-photos",
            "--group",
            PROJECT_A,
        ])
        .await;
    assert!(out.contains("no policy now"), "{out}");
    let none = cli.ok(&["admin", "ldap", "policy", "ls", "t"]).await;
    assert!(!none.contains(PROJECT_A), "{none}");
    let config = cli.ok(&["admin", "config", "t"]).await;
    assert!(
        config.contains("(plain), users in ou=people,dc=min,dc=io"),
        "{config}"
    );
    drop(fake);
}
