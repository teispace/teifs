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

use common::{ACCESS_KEY, SECRET_KEY, Server, code, idp::Idp, start};

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

/// A form posted to STS, signed with the root key as other clients sign it (with the
/// body's hash in `x-amz-content-sha256`): the answer's status and body.
async fn signed_sts(server: &Server, form: &str) -> (u16, String) {
    use aws_sigv4::{
        http_request::{PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign},
        sign::v4,
    };
    let url = format!("{}/", server.endpoint);
    let host = url
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned();
    let identity =
        aws_credential_types::Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "tests").into();
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("sts")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let content_type = "application/x-www-form-urlencoded";
    let headers = [("host", host.as_str()), ("content-type", content_type)];
    let signable = SignableRequest::new(
        "POST",
        &url,
        headers.into_iter(),
        SignableBody::Bytes(form.as_bytes()),
    )
    .unwrap();
    let (instructions, _) = sign(signable, &params).unwrap().into_parts();
    let mut request = reqwest::Client::new()
        .post(&url)
        .header("content-type", content_type)
        .body(form.to_owned());
    for (name, value) in instructions.headers() {
        request = request.header(name, value);
    }
    let response = request.send().await.unwrap();
    (response.status().as_u16(), response.text().await.unwrap())
}

/// An STS client with no credentials at all, as a CI job has before it assumes a role.
fn sts_unsigned(server: &Server) -> aws_sdk_sts::Client {
    aws_sdk_sts::Client::from_conf(
        aws_sdk_sts::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_sts::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .build(),
    )
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn web_identities_assume_roles_through_the_aws_sdk() {
    let server = start().await;
    let account = server.iam.account();
    let idp = Idp::start().await;
    let admin = iam(&server, &Keys::root());
    let provider = admin
        .create_open_id_connect_provider()
        .url(&idp.url)
        .client_id_list("sts.amazonaws.com")
        .send()
        .await
        .unwrap()
        .open_id_connect_provider_arn
        .unwrap();
    let name = idp.url.trim_start_matches("http://");
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Federated":"{provider}"}},"Action":["sts:AssumeRoleWithWebIdentity","sts:TagSession"],"Condition":{{"StringEquals":{{"{name}:aud":"sts.amazonaws.com"}},"StringLike":{{"{name}:sub":"repo:acme/*"}}}}}}]}}"#
    );
    admin
        .create_role()
        .role_name("deploy")
        .assume_role_policy_document(&trust)
        .send()
        .await
        .unwrap();
    admin
        .put_role_policy()
        .role_name("deploy")
        .policy_name("photos")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"],"Condition":{"StringEquals":{"aws:PrincipalTag/team":"web"}}}]}"#,
        )
        .send()
        .await
        .unwrap();
    s3(&server, &Keys::root())
        .create_bucket()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    let role_arn = format!("arn:aws:iam::{account}:role/deploy");

    // Unsigned, as the SDK sends it: the token is the proof.
    let anonymous = sts_unsigned(&server);
    let token = idp.token(
        "repo:acme/site:ref:refs/heads/main",
        r#","https://aws.amazon.com/tags":{"principal_tags":{"team":["web"]}}"#,
    );
    // Signed (the SDK never signs it; others may), the signature counts for nothing,
    // and the first request fetches the provider's keys as an unsigned one does.
    let form = format!(
        "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn={role_arn}\
         &RoleSessionName=signed&WebIdentityToken={token}"
    );
    let (status, body) = signed_sts(&server, &form).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("<AssumedRoleUser>"), "{body}");
    let answer = anonymous
        .assume_role_with_web_identity()
        .role_arn(&role_arn)
        .role_session_name("ci-42")
        .web_identity_token(&token)
        .duration_seconds(900)
        .minimum_session_token_size(2048)
        .send()
        .await
        .unwrap();
    assert_eq!(
        answer.subject_from_web_identity_token(),
        Some("repo:acme/site:ref:refs/heads/main")
    );
    assert_eq!(answer.provider(), Some(provider.as_str()));
    assert_eq!(answer.audience(), Some("sts.amazonaws.com"));
    assert_eq!(
        answer.assumed_role_user().unwrap().arn(),
        format!("arn:aws:sts::{account}:assumed-role/deploy/ci-42")
    );
    let credentials = answer.credentials().unwrap();
    assert!((890..=900).contains(&seconds_until(credentials.expiration())));
    assert!(credentials.session_token().len() >= 2048);
    assert_eq!(
        answer.session_token_size(),
        Some(i32::try_from(credentials.session_token().len()).unwrap())
    );

    // The session signs S3 requests as the role, with the token's session tags.
    let keys = Keys::temporary(credentials);
    let session = s3(&server, &keys);
    assert_eq!(put(&session, "photos", "a.jpg").await, "ok");
    assert_eq!(get(&session, "photos", "a.jpg").await, "ok");
    let caller = sts(&server, &keys)
        .get_caller_identity()
        .send()
        .await
        .unwrap();
    assert_eq!(
        caller.arn(),
        Some(format!("arn:aws:sts::{account}:assumed-role/deploy/ci-42").as_str())
    );

    // Signed or not, a subject the trust policy doesn't name is refused.
    let other = idp.token("repo:evil/site:ref:refs/heads/main", "");
    for client in [sts_unsigned(&server), sts(&server, &Keys::root())] {
        let err = client
            .assume_role_with_web_identity()
            .role_arn(&role_arn)
            .role_session_name("ci-43")
            .web_identity_token(&other)
            .send()
            .await
            .unwrap_err();
        assert_eq!(code::<(), _>(Err(err)), "AccessDenied");
    }
    // A forged token is refused as AWS refuses it.
    let forged = format!("{}x", &token[..token.len() - 1]);
    let err = anonymous
        .assume_role_with_web_identity()
        .role_arn(&role_arn)
        .role_session_name("ci-44")
        .web_identity_token(forged)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code::<(), _>(Err(err)), "InvalidIdentityToken");
}

/// The text between `start` and `end` in `body`.
fn between<'a>(body: &'a str, start: &str, end: &str) -> &'a str {
    let from = body.find(start).unwrap() + start.len();
    &body[from..from + body[from..].find(end).unwrap()]
}

#[tokio::test]
async fn minio_web_identities_take_the_policies_their_tokens_name() {
    let server = start().await;
    let idp = Idp::start().await;
    let admin = iam(&server, &Keys::root());
    let provider = admin
        .create_open_id_connect_provider()
        .url(&idp.url)
        .client_id_list("sts.amazonaws.com")
        .tags(
            aws_sdk_iam::types::Tag::builder()
                .key("teifs:policy-claim")
                .value("")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .open_id_connect_provider_arn
        .unwrap();
    admin
        .create_policy()
        .policy_name("photos-read")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let root = s3(&server, &Keys::root());
    root.create_bucket().bucket("photos").send().await.unwrap();
    assert_eq!(put(&root, "photos", "a.jpg").await, "ok");

    // As MinIO's clients send it: an unsigned form with no role.
    let token = idp.token("alice", r#","policy":"photos-read""#);
    let response = reqwest::Client::new()
        .post(format!("{}/", server.endpoint))
        .header("content-type", "application/x-www-form-urlencoded")
        // A token is URL-safe as it is.
        .body(format!(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&DurationSeconds=86400\
             &WebIdentityToken={token}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("<SubjectFromWebIdentityToken>alice<"),
        "{body}"
    );
    assert!(
        body.contains(&format!("<Provider>{provider}</Provider>")),
        "{body}"
    );
    let keys = Keys {
        id: between(&body, "<AccessKeyId>", "<").to_owned(),
        secret: between(&body, "<SecretAccessKey>", "<").to_owned(),
        token: Some(between(&body, "<SessionToken>", "<").to_owned()),
    };
    let session = s3(&server, &keys);
    assert_eq!(get(&session, "photos", "a.jpg").await, "ok");
    assert_eq!(put(&session, "photos", "b.jpg").await, "AccessDenied");
    let caller = sts(&server, &keys)
        .get_caller_identity()
        .send()
        .await
        .unwrap();
    assert_eq!(caller.user_id(), Some(format!("{provider}:alice").as_str()));
    assert_eq!(caller.account(), Some(server.iam.account().as_str()));

    // A token that names no policy the account has gets nothing.
    let err = sts_unsigned(&server)
        .assume_role_with_web_identity()
        .web_identity_token(idp.token("bob", r#","policy":"nothing""#))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code::<(), _>(Err(err)), "InvalidParameterValue");
}
