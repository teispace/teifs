//! STS on the S3 endpoint, driven by the AWS SDKs: temporary credentials, and S3, IAM and
//! STS requests signed with them.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::{Duration, SystemTime};

use aws_sdk_s3::{presigning::PresigningConfig, primitives::ByteStream};
use aws_sdk_sts::{
    config::{
        ConfigBag, Intercept, RuntimeComponents, interceptors::BeforeTransmitInterceptorContextMut,
    },
    error::BoxError,
};

mod common;

use common::{ACCESS_KEY, SECRET_KEY, Server, code, start};

/// An access key, its secret, and a session token for temporary ones.
#[derive(Clone)]
struct Keys {
    id: String,
    secret: String,
    token: Option<String>,
}

impl Keys {
    fn root() -> Self {
        Self {
            id: ACCESS_KEY.into(),
            secret: SECRET_KEY.into(),
            token: None,
        }
    }

    fn user(server: &Server, name: &str, policy: &str) -> Self {
        server.iam.create_user(name, None, &[], None).unwrap();
        server
            .iam
            .put_inline(teifs_iam::Owner::User(name), "policy", policy)
            .unwrap();
        let key = server.iam.create_access_key(name).unwrap();
        Self {
            id: key.info.id,
            secret: key.secret.to_string(),
            token: None,
        }
    }

    fn temporary(credentials: &aws_sdk_sts::types::Credentials) -> Self {
        Self {
            id: credentials.access_key_id().to_owned(),
            secret: credentials.secret_access_key().to_owned(),
            token: Some(credentials.session_token().to_owned()),
        }
    }

    fn with_token(&self, token: Option<&str>) -> Self {
        Self {
            token: token.map(str::to_owned),
            ..self.clone()
        }
    }

    fn credentials(&self) -> aws_sdk_s3::config::Credentials {
        aws_sdk_s3::config::Credentials::new(
            &self.id,
            &self.secret,
            self.token.clone(),
            None,
            "tests",
        )
    }
}

fn s3(server: &Server, keys: &Keys) -> aws_sdk_s3::Client {
    aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .credentials_provider(keys.credentials())
            .force_path_style(true)
            .build(),
    )
}

fn iam(server: &Server, keys: &Keys) -> aws_sdk_iam::Client {
    aws_sdk_iam::Client::from_conf(
        aws_sdk_iam::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_iam::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .credentials_provider(keys.credentials())
            .build(),
    )
}

fn sts(server: &Server, keys: &Keys) -> aws_sdk_sts::Client {
    sts_with(server, keys, None)
}

fn sts_with(server: &Server, keys: &Keys, form: Option<MinioForm>) -> aws_sdk_sts::Client {
    let mut config = aws_sdk_sts::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_sts::config::Region::new("us-east-1"))
        .endpoint_url(&server.endpoint)
        .credentials_provider(keys.credentials());
    if let Some(form) = form {
        config = config.interceptor(form);
    }
    aws_sdk_sts::Client::from_conf(config.build())
}

/// Sends MinIO's `AssumeRole` form, which has no `RoleArn` or `RoleSessionName` (the
/// SDK won't build a request without them), signed as the SDK signs its own.
#[derive(Debug)]
struct MinioForm(&'static str);

impl Intercept for MinioForm {
    fn name(&self) -> &'static str {
        "minio-form"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        _: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let request = context.request_mut();
        request
            .headers_mut()
            .insert("content-length", self.0.len().to_string());
        *request.body_mut() = aws_sdk_s3::primitives::SdkBody::from(self.0);
        Ok(())
    }
}

async fn put(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> String {
    code(
        client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from_static(b"hello"))
            .send()
            .await,
    )
}

async fn get(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> String {
    code(client.get_object().bucket(bucket).key(key).send().await)
}

/// Seconds from now until `time`.
fn seconds_until(time: &aws_sdk_sts::primitives::DateTime) -> i64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    time.secs() - i64::try_from(now).unwrap()
}

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}"#;

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn assumed_roles_sign_s3_iam_and_sts_requests() {
    let server = start().await;
    let account = server.iam.account();
    let root = s3(&server, &Keys::root());
    root.create_bucket().bucket("photos").send().await.unwrap();
    assert_eq!(put(&root, "photos", "a.txt").await, "ok");
    let alice = Keys::user(
        &server,
        "alice",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#,
    );
    let admin = iam(&server, &Keys::root());
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:user/alice"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    let role = admin
        .create_role()
        .role_name("reader")
        .assume_role_policy_document(&trust)
        .send()
        .await
        .unwrap();
    let role_arn = role.role().unwrap().arn().to_owned();
    admin
        .put_role_policy()
        .role_name("reader")
        .policy_name("photos")
        .policy_document(READ_PHOTOS)
        .send()
        .await
        .unwrap();

    let out = sts(&server, &alice)
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name("alice-app")
        .duration_seconds(900)
        .send()
        .await
        .unwrap();
    let credentials = out.credentials().unwrap();
    assert!(credentials.access_key_id().starts_with("TSIA"));
    assert!((890..=900).contains(&seconds_until(credentials.expiration())));
    let user = out.assumed_role_user().unwrap();
    assert_eq!(
        user.arn(),
        format!("arn:aws:sts::{account}:assumed-role/reader/alice-app")
    );
    let session = Keys::temporary(credentials);

    // The role's permissions, not alice's.
    let photos = s3(&server, &session);
    assert_eq!(get(&photos, "photos", "a.txt").await, "ok");
    assert_eq!(put(&photos, "photos", "b.txt").await, "AccessDenied");
    // A missing key is NoSuchKey to a session that may list the bucket.
    assert_eq!(get(&photos, "photos", "nothing").await, "NoSuchKey");
    let me = sts(&server, &session)
        .get_caller_identity()
        .send()
        .await
        .unwrap();
    assert_eq!(me.arn(), Some(user.arn()));
    assert_eq!(me.user_id(), Some(user.assumed_role_id()));

    // A presigned link carries the token in its query.
    let link = photos
        .get_object()
        .bucket("photos")
        .key("a.txt")
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap();
    assert!(
        link.uri().contains("X-Amz-Security-Token="),
        "{}",
        link.uri()
    );
    let response = reqwest::get(link.uri()).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.unwrap(), "hello");

    // The key needs its own token, whole.
    let other = sts(&server, &alice)
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name("other")
        .send()
        .await
        .unwrap();
    let other_token = other.credentials().unwrap().session_token().to_owned();
    for token in [None, Some(other_token.as_str()), Some("Zm9v")] {
        let keys = session.with_token(token);
        assert_eq!(
            get(&s3(&server, &keys), "photos", "a.txt").await,
            "InvalidToken",
            "{token:?}"
        );
        let err = code(iam(&server, &keys).list_roles().send().await);
        assert_eq!(err, "InvalidClientTokenId", "{token:?}");
    }
    // A long-term key with a token is refused too.
    let alice_with_token = alice.with_token(Some(&other_token));
    assert_eq!(
        put(&s3(&server, &alice_with_token), "photos", "c.txt").await,
        "InvalidToken"
    );

    // A role's session uses IAM as far as the role may.
    assert_eq!(
        code(iam(&server, &session).list_users().send().await),
        "AccessDenied"
    );
    // Session policies narrow a session to what they allow.
    let narrow = sts(&server, &alice)
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name("narrow")
        .policy(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    assert!(
        narrow
            .session_token_utilization()
            .is_some_and(|p| (1..100).contains(&p))
    );
    assert!(narrow.session_token_size().is_some_and(|n| n > 100));
    let narrow = s3(&server, &Keys::temporary(narrow.credentials().unwrap()));
    assert_eq!(get(&narrow, "photos", "a.txt").await, "AccessDenied");
    assert_eq!(
        code(narrow.list_objects_v2().bucket("photos").send().await),
        "ok"
    );

    // Deleting the role ends its sessions.
    admin
        .delete_role_policy()
        .role_name("reader")
        .policy_name("photos")
        .send()
        .await
        .unwrap();
    admin
        .delete_role()
        .role_name("reader")
        .send()
        .await
        .unwrap();
    assert_eq!(get(&photos, "photos", "a.txt").await, "AccessDenied");
    assert_eq!(
        code(sts(&server, &session).get_caller_identity().send().await),
        "InvalidClientTokenId"
    );
}

#[tokio::test]
async fn session_tokens_and_federated_users_are_limited_as_on_aws() {
    let server = start().await;
    let account = server.iam.account();
    let root = s3(&server, &Keys::root());
    root.create_bucket().bucket("photos").send().await.unwrap();
    assert_eq!(put(&root, "photos", "a.txt").await, "ok");
    let alice = Keys::user(
        &server,
        "alice",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","iam:ListUsers","sts:GetFederationToken"],"Resource":"*"}]}"#,
    );

    let out = sts(&server, &alice)
        .get_session_token()
        .send()
        .await
        .unwrap();
    let credentials = out.credentials().unwrap();
    assert!((43_190..=43_200).contains(&seconds_until(credentials.expiration())));
    let token = Keys::temporary(credentials);
    assert_eq!(put(&s3(&server, &token), "photos", "b.txt").await, "ok");
    let me = sts(&server, &token)
        .get_caller_identity()
        .send()
        .await
        .unwrap();
    assert_eq!(
        me.arn(),
        Some(format!("arn:aws:iam::{account}:user/alice").as_str())
    );
    assert_eq!(code(iam(&server, &alice).list_users().send().await), "ok");
    assert_eq!(
        code(iam(&server, &token).list_users().send().await),
        "InvalidClientTokenId"
    );
    assert_eq!(
        code(sts(&server, &token).get_session_token().send().await),
        "AccessDenied"
    );

    let out = sts(&server, &alice)
        .get_federation_token()
        .name("visitor")
        .policy(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#)
        .send()
        .await
        .unwrap();
    let federated = out.federated_user().unwrap();
    assert_eq!(
        federated.arn(),
        format!("arn:aws:sts::{account}:federated-user/visitor")
    );
    assert_eq!(federated.federated_user_id(), format!("{account}:visitor"));
    let visitor = Keys::temporary(out.credentials().unwrap());
    let photos = s3(&server, &visitor);
    assert_eq!(get(&photos, "photos", "a.txt").await, "ok");
    assert_eq!(put(&photos, "photos", "c.txt").await, "AccessDenied");
    assert_eq!(
        code(iam(&server, &visitor).list_users().send().await),
        "InvalidClientTokenId"
    );
    let me = sts(&server, &visitor)
        .get_caller_identity()
        .send()
        .await
        .unwrap();
    assert_eq!(me.arn(), Some(federated.arn()));

    let info = sts(&server, &Keys::root())
        .get_access_key_info()
        .access_key_id(&alice.id)
        .send()
        .await
        .unwrap();
    assert_eq!(info.account(), Some(account.as_str()));
}

#[tokio::test]
async fn minio_assume_role_gives_a_users_own_permissions_narrowed() {
    let server = start().await;
    let root = s3(&server, &Keys::root());
    root.create_bucket().bucket("photos").send().await.unwrap();
    assert_eq!(put(&root, "photos", "a.txt").await, "ok");
    let alice = Keys::user(
        &server,
        "alice",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
    );
    let form = MinioForm(
        "Action=AssumeRole&Version=2011-06-15&DurationSeconds=86400&Policy=%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22*%22%7D%5D%7D",
    );
    let out = sts_with(&server, &alice, Some(form))
        .assume_role()
        .role_arn("ignored-by-the-form")
        .role_session_name("ignored")
        .send()
        .await
        .unwrap();
    assert!(out.assumed_role_user().is_none());
    let credentials = out.credentials().unwrap();
    assert!((86_390..=86_400).contains(&seconds_until(credentials.expiration())));
    let session = s3(&server, &Keys::temporary(credentials));
    assert_eq!(get(&session, "photos", "a.txt").await, "ok");
    assert_eq!(put(&session, "photos", "b.txt").await, "AccessDenied");
}
