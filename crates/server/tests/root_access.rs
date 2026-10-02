//! `MinIO`'s `root_access=off`: the root key, the service accounts it made and the
//! sessions it started stop signing; IAM's users go on.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use aws_sdk_s3::config::{Credentials, Region};
use common::{ACCESS_KEY, SECRET_KEY, client, client_as, code, restart, start};
use teifs_iam::NewServiceAccount;

const ALL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;

/// A client signing with temporary credentials.
fn session_client(
    endpoint: &str,
    (id, secret, token): &(String, String, String),
) -> aws_sdk_s3::Client {
    aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .credentials_provider(Credentials::new(
                id,
                secret,
                Some(token.clone()),
                None,
                "tests",
            ))
            .force_path_style(true)
            .build(),
    )
}

#[tokio::test]
async fn without_root_access_only_iam_s_users_sign() {
    let server = start().await;
    let sts = aws_sdk_sts::Client::from_conf(
        aws_sdk_sts::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_sts::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .credentials_provider(aws_sdk_sts::config::Credentials::new(
                ACCESS_KEY, SECRET_KEY, None, None, "tests",
            ))
            .build(),
    );
    let session = sts.get_session_token().send().await.unwrap();
    let session = session.credentials.unwrap();
    let session = (
        session.access_key_id,
        session.secret_access_key,
        session.session_token,
    );
    assert_eq!(
        code(
            session_client(&server.endpoint, &session)
                .list_buckets()
                .send()
                .await
        ),
        "ok"
    );
    let roots = server
        .iam
        .minio_add_service_account(ACCESS_KEY, NewServiceAccount::default())
        .unwrap();
    server.iam.create_user("alice", None, &[], None).unwrap();
    server
        .iam
        .put_inline(teifs_iam::Owner::User("alice"), "policy", ALL)
        .unwrap();
    let alice = server.iam.create_access_key("alice").unwrap();

    let server = restart(server, |config| config.root_access = false).await;
    let refused = [
        client(&server, SECRET_KEY),
        client_as(&server, &roots.access_key, &roots.secret),
        session_client(&server.endpoint, &session),
    ];
    let mut codes = Vec::new();
    for client in refused {
        codes.push(code(client.list_buckets().send().await));
    }
    // A session whose identity is gone is refused as one whose user was deleted is.
    assert_eq!(
        codes,
        ["InvalidAccessKeyId", "InvalidAccessKeyId", "AccessDenied"]
    );
    let alice = client_as(&server, &alice.info.id, &alice.secret);
    assert_eq!(code(alice.list_buckets().send().await), "ok");

    // On again, it signs again.
    let server = restart(server, |_| {}).await;
    assert_eq!(
        code(client(&server, SECRET_KEY).list_buckets().send().await),
        "ok"
    );
}
