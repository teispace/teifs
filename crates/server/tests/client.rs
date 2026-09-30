//! `teifs-client` against a real server: each admin call, and errors as the client
//! reports them.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use teifs_client::{Client, ClientError, Zeroizing};

mod common;

use common::{ACCESS_KEY, SECRET_KEY, Server, start, start_with, user};

fn as_root(server: &Server) -> Client {
    Client::new(
        &server.endpoint,
        ACCESS_KEY,
        Zeroizing::new(SECRET_KEY.to_owned()),
    )
    .unwrap()
}

#[tokio::test]
async fn every_call_works_for_the_root_user() {
    let (from, to) = (start().await, start().await);
    let client = as_root(&from);
    let info = client.info().await.unwrap();
    assert_eq!(info.account, from.iam.account());
    let config = client.config().await.unwrap();
    assert_eq!(config.root_credentials, "given");

    user(&from, "alice", None);
    let export = client.export_iam(true).await.unwrap();
    assert!(export.users[0].access_keys[0].secret.is_some());
    let without = client.export_iam(false).await.unwrap();
    assert!(without.users[0].access_keys[0].secret.is_none());
    let report = as_root(&to).import_iam(&export, true).await.unwrap();
    assert_eq!((report.users, report.access_keys), (1, 1));
    assert_eq!(to.iam.account(), from.iam.account());
    // Another region signs just as well.
    let elsewhere = as_root(&to).with_region("eu-west-1");
    assert_eq!(elsewhere.export_iam(false).await.unwrap(), without);
}

#[tokio::test]
async fn errors_carry_the_servers_code() {
    let server = start().await;
    let err = as_root(&server).rotate_root_key().await.unwrap_err();
    assert_eq!(err.code(), Some("RootKeyManagedElsewhere"));
    assert!(matches!(
        err,
        ClientError::Api {
            status: 409,
            request_id: Some(_),
            ..
        }
    ));
    user(&server, "nobody", None);
    let key = server.iam.create_access_key("nobody").unwrap();
    let nobody = Client::new(&server.endpoint, &key.info.id, key.secret).unwrap();
    assert_eq!(
        nobody.info().await.unwrap_err().code(),
        Some("AccessDenied")
    );
    let wrong = Client::new(
        &server.endpoint,
        ACCESS_KEY,
        Zeroizing::new("not-the-secret".into()),
    )
    .unwrap();
    assert_eq!(
        wrong.info().await.unwrap_err().code(),
        Some("SignatureDoesNotMatch")
    );
    let nowhere = Client::new("http://127.0.0.1:9", ACCESS_KEY, Zeroizing::new("s".into()));
    let err = nowhere.unwrap().info().await.unwrap_err();
    assert!(matches!(err, ClientError::Transport(_)), "{err}");
}

#[tokio::test]
async fn bucket_quotas_are_set_read_and_cleared() {
    let server = start().await;
    let client = as_root(&server);
    let s3 = common::client(&server, SECRET_KEY);
    s3.create_bucket().bucket("photos").send().await.unwrap();
    assert_eq!(client.bucket_quota("photos").await.unwrap(), None);
    client.set_bucket_quota("photos", Some(5)).await.unwrap();
    assert_eq!(client.bucket_quota("photos").await.unwrap(), Some(5));
    client.set_bucket_quota("photos", None).await.unwrap();
    assert_eq!(client.bucket_quota("photos").await.unwrap(), None);
    // MinIO's errors, as JSON.
    let err = client.bucket_quota("nothing").await.unwrap_err();
    assert!(
        matches!(
            &err,
            ClientError::Api {
                status: 404,
                request_id: Some(_),
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(err.code(), Some("NoSuchBucket"));
    let err = client
        .set_bucket_quota("nothing", Some(1))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("NoSuchBucket"));
}

#[tokio::test]
async fn the_root_key_is_rotated_and_the_new_one_signs() {
    let server = start_with(|config| config.credentials = None).await;
    let old = teifs_server::credentials::load(server.dir.path())
        .unwrap()
        .unwrap();
    let client = Client::new(
        &server.endpoint,
        &old.access_key,
        Zeroizing::new(old.secret_key),
    )
    .unwrap();
    let new = client.rotate_root_key().await.unwrap();
    assert_eq!(
        client.info().await.unwrap_err().code(),
        Some("InvalidAccessKeyId")
    );
    let client = Client::new(
        &server.endpoint,
        &new.access_key,
        Zeroizing::new(new.secret_key),
    )
    .unwrap();
    assert!(client.info().await.is_ok());
}
