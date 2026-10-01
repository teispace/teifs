//! Signing in with a token an identity plugin vouches for (MinIO's
//! `AssumeRoleWithCustomToken`) through a real server, against the fake plugin: the
//! session has the plugin role's policies, the token reaches the plugin and nowhere
//! else, and MinIO's clients' query form works too.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{config::Credentials, primitives::ByteStream};
use teifs_client::{Client, ClientError, Zeroizing};
use teifs_iam::plugin::fake::FakePlugin;

mod common;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, code, start_with};

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;

/// A server that checks custom tokens with `plugin`, its role having `read-photos`, and
/// a bucket with a photo in it.
async fn server(plugin: &FakePlugin) -> Server {
    let settings = plugin.settings(&["read-photos"]);
    let server = start_with(|config| config.identity_plugin = Some(settings)).await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    root.put_object()
        .bucket("photos")
        .key("cat.jpg")
        .body(ByteStream::from_static(b"meow"))
        .send()
        .await
        .unwrap();
    server
        .iam
        .create_policy("read-photos", None, None, READ_PHOTOS, &[])
        .unwrap();
    server
}

fn signed(server: &Server) -> Client {
    Client::new(
        &server.endpoint,
        ACCESS_KEY,
        Zeroizing::new(SECRET_KEY.to_owned()),
    )
    .unwrap()
}

fn unsigned(server: &Server) -> Client {
    Client::new(&server.endpoint, "", Zeroizing::new(String::new())).unwrap()
}

fn session_client(
    server: &Server,
    access_key: &str,
    secret: &str,
    token: &str,
) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(&server.endpoint)
        .force_path_style(true)
        .credentials_provider(Credentials::new(
            access_key,
            secret,
            Some(token.to_owned()),
            None,
            "test",
        ))
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

fn refusal(err: &ClientError) -> (u16, &str, &str) {
    match err {
        ClientError::Api {
            status,
            code,
            message,
            ..
        } => (*status, code, message),
        other => panic!("not an API error: {other}"),
    }
}

#[tokio::test]
async fn a_token_the_plugin_vouches_for_signs_in() {
    let plugin = FakePlugin::start().await;
    let server = server(&plugin).await;
    let shown = signed(&server)
        .config()
        .await
        .unwrap()
        .identity_plugin
        .unwrap();
    assert_eq!(shown.url, plugin.url().split('?').next().unwrap());
    assert!(
        shown.role_arn.starts_with("arn:minio:iam:::role/idmp-"),
        "{}",
        shown.role_arn
    );
    assert_eq!(shown.role_policies, ["read-photos"]);

    plugin.vouch("good-token", "alice", 3600);
    let credentials = unsigned(&server)
        .assume_role_with_custom_token(&shown.role_arn, "good-token", None, Some(900))
        .await
        .unwrap();
    let left = credentials
        .expires
        .duration_since(std::time::SystemTime::now())
        .unwrap();
    assert!(left.as_secs() > 800 && left.as_secs() <= 900);
    let session = session_client(
        &server,
        &credentials.access_key,
        &credentials.secret_key,
        &credentials.session_token,
    );
    let object = session
        .get_object()
        .bucket("photos")
        .key("cat.jpg")
        .send()
        .await
        .unwrap();
    assert_eq!(object.body.collect().await.unwrap().into_bytes(), "meow");
    let put = session
        .put_object()
        .bucket("photos")
        .key("dog.jpg")
        .body(ByteStream::from_static(b"woof"))
        .send()
        .await;
    assert_eq!(code(put), "AccessDenied");
    let seen = plugin.seen();
    // The server asked once at start (`HEAD`), then with the token.
    assert_eq!(seen.last().unwrap().token.as_deref(), Some("good-token"));

    // MinIO's clients send the parameters in the query of an empty POST.
    let url = format!(
        "{}/?Action=AssumeRoleWithCustomToken&Version=2011-06-15&RoleArn={}&Token=good-token",
        server.endpoint, shown.role_arn
    );
    let answer = reqwest::Client::new().post(url).send().await.unwrap();
    assert_eq!(answer.status(), 200);
    let body = answer.text().await.unwrap();
    assert!(
        body.contains("<AssumedUser>custom:alice</AssumedUser>"),
        "{body}"
    );

    let err = unsigned(&server)
        .assume_role_with_custom_token(&shown.role_arn, "wrong", None, None)
        .await
        .unwrap_err();
    assert_eq!(refusal(&err), (403, "AccessDenied", "unknown token"));
}

#[tokio::test]
async fn a_server_without_a_plugin_says_so() {
    let server = start_with(|_| {}).await;
    assert!(
        signed(&server)
            .config()
            .await
            .unwrap()
            .identity_plugin
            .is_none()
    );
    let err = unsigned(&server)
        .assume_role_with_custom_token("arn:minio:iam:::role/idmp-x", "t", None, None)
        .await
        .unwrap_err();
    assert_eq!(refusal(&err).0, 503);
    assert_eq!(refusal(&err).1, "STSNotInitialized");
}

#[tokio::test]
async fn wrong_plugin_settings_stop_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let mut config = common::config(dir.path(), keys.path());
    config.identity_plugin = Some(teifs_server::PluginSettings {
        url: "ftp://idp.example".into(),
        role_policies: vec!["read-photos".into()],
        ..teifs_server::PluginSettings::default()
    });
    let err = teifs_server::Server::bind(config)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        err.contains("the identity plugin's settings are wrong"),
        "{err}"
    );
}
