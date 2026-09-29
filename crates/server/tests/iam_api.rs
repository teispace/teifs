//! IAM's API on the S3 endpoint, driven by the AWS SDK as `aws iam` would drive it.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_iam::{
    config::{
        ConfigBag, Credentials, Intercept, Region, RuntimeComponents,
        interceptors::BeforeTransmitInterceptorContextMut,
    },
    error::{BoxError, ProvideErrorMetadata},
    types::{SummaryKeyType, Tag},
};
use aws_sdk_s3::primitives::ByteStream;

mod common;

use common::{ACCESS_KEY, SECRET_KEY, Server, client_as, start};

fn iam_as(server: &Server, access_key: &str, secret: &str) -> aws_sdk_iam::Client {
    iam_with(server, access_key, secret, None)
}

fn iam_with(
    server: &Server,
    access_key: &str,
    secret: &str,
    tamper: Option<Tamper>,
) -> aws_sdk_iam::Client {
    let mut config = aws_sdk_iam::Config::builder()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .endpoint_url(&server.endpoint)
        .credentials_provider(Credentials::new(access_key, secret, None, None, "tests"));
    if let Some(tamper) = tamper {
        config = config.interceptor(tamper);
    }
    aws_sdk_iam::Client::from_conf(config.build())
}

fn sts_as(server: &Server, access_key: &str, secret: &str) -> aws_sdk_sts::Client {
    aws_sdk_sts::Client::from_conf(
        aws_sdk_sts::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_sts::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .credentials_provider(aws_sdk_sts::config::Credentials::new(
                access_key, secret, None, None, "tests",
            ))
            .build(),
    )
}

fn tag(key: &str, value: &str) -> Tag {
    Tag::builder().key(key).value(value).build().unwrap()
}

const READ_PHOTOS: &str = r#"{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::photos/*"}]
}"#;

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn the_aws_sdk_manages_iam_on_the_s3_endpoint() {
    let server = start().await;
    let iam = iam_as(&server, ACCESS_KEY, SECRET_KEY);
    let account = server.iam.account();

    // Users, with paths, tags and pages.
    let alice = iam
        .create_user()
        .user_name("alice")
        .path("/team/")
        .tags(tag("dept", "R D"))
        .send()
        .await
        .unwrap();
    let alice = alice.user().unwrap();
    assert_eq!(
        alice.arn(),
        format!("arn:aws:iam::{account}:user/team/alice")
    );
    assert!(alice.user_id().starts_with("AIDA"));
    for name in ["bob", "carol"] {
        iam.create_user().user_name(name).send().await.unwrap();
    }
    let names: Vec<String> = iam
        .list_users()
        .max_items(1)
        .into_paginator()
        .items()
        .send()
        .collect::<Result<Vec<_>, _>>()
        .await
        .unwrap()
        .iter()
        .map(|u| u.user_name().to_owned())
        .collect();
    assert_eq!(names, ["alice", "bob", "carol"]);
    let err = iam
        .create_user()
        .user_name("ALICE")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("EntityAlreadyExists"));
    let err = iam.get_user().user_name("nobody").send().await.unwrap_err();
    assert!(err.into_service_error().is_no_such_entity_exception());

    // A managed policy, attached; its document comes back as it went in.
    let policy = iam
        .create_policy()
        .policy_name("photos")
        .policy_document(READ_PHOTOS)
        .description("Reads & writes photos")
        .tags(tag("owner", "ops"))
        .send()
        .await
        .unwrap();
    let arn = policy.policy().unwrap().arn().unwrap().to_owned();
    let version = iam
        .get_policy_version()
        .policy_arn(&arn)
        .version_id("v1")
        .send()
        .await
        .unwrap();
    let document = version.policy_version().unwrap().document().unwrap();
    let decoded = percent_decode(document);
    assert_eq!(decoded, READ_PHOTOS);
    iam.attach_user_policy()
        .user_name("alice")
        .policy_arn(&arn)
        .send()
        .await
        .unwrap();
    let attached = iam
        .list_attached_user_policies()
        .user_name("alice")
        .send()
        .await
        .unwrap();
    assert_eq!(
        attached.attached_policies()[0].policy_arn(),
        Some(arn.as_str())
    );
    let tags = iam
        .list_policy_tags()
        .policy_arn(&arn)
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tags()[0].key(), "owner");

    // A key for alice works on S3 as her policy says.
    let key = iam
        .create_access_key()
        .user_name("alice")
        .send()
        .await
        .unwrap();
    let key = key.access_key().unwrap();
    let s3 = client_as(&server, key.access_key_id(), key.secret_access_key());
    common::client(&server, SECRET_KEY)
        .create_bucket()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    s3.put_object()
        .bucket("photos")
        .key("a.jpg")
        .body(ByteStream::from_static(b"jpg"))
        .send()
        .await
        .unwrap();
    let err = s3.list_buckets().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // STS says who signed.
    let me = sts_as(&server, key.access_key_id(), key.secret_access_key())
        .get_caller_identity()
        .send()
        .await
        .unwrap();
    assert_eq!(me.arn(), Some(alice.arn()));
    assert_eq!(me.account(), Some(account.as_str()));
    let root = sts_as(&server, ACCESS_KEY, SECRET_KEY)
        .get_caller_identity()
        .send()
        .await
        .unwrap();
    assert_eq!(
        root.arn(),
        Some(format!("arn:aws:iam::{account}:root").as_str())
    );

    // Alice may not manage IAM.
    let as_alice = iam_as(&server, key.access_key_id(), key.secret_access_key());
    let err = as_alice.list_users().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(err.message().unwrap().contains("iam:ListUsers"));

    // Groups, inline policies, tags, versions, boundaries.
    iam.create_group().group_name("staff").send().await.unwrap();
    iam.add_user_to_group()
        .group_name("staff")
        .user_name("bob")
        .send()
        .await
        .unwrap();
    let group = iam.get_group().group_name("staff").send().await.unwrap();
    assert_eq!(group.users()[0].user_name(), "bob");
    let groups = iam
        .list_groups_for_user()
        .user_name("bob")
        .send()
        .await
        .unwrap();
    assert_eq!(groups.groups()[0].group_name(), "staff");
    iam.put_group_policy()
        .group_name("staff")
        .policy_name("read")
        .policy_document(READ_PHOTOS)
        .send()
        .await
        .unwrap();
    let inline = iam
        .get_group_policy()
        .group_name("staff")
        .policy_name("read")
        .send()
        .await
        .unwrap();
    assert_eq!(percent_decode(inline.policy_document()), READ_PHOTOS);
    iam.tag_user()
        .user_name("bob")
        .tags(tag("team", "b"))
        .send()
        .await
        .unwrap();
    iam.untag_user()
        .user_name("alice")
        .tag_keys("DEPT")
        .send()
        .await
        .unwrap();
    assert!(
        iam.list_user_tags()
            .user_name("alice")
            .send()
            .await
            .unwrap()
            .tags()
            .is_empty()
    );
    let v2 = iam
        .create_policy_version()
        .policy_arn(&arn)
        .policy_document(READ_PHOTOS)
        .set_as_default(true)
        .send()
        .await
        .unwrap();
    assert_eq!(v2.policy_version().unwrap().version_id(), Some("v2"));
    let versions = iam
        .list_policy_versions()
        .policy_arn(&arn)
        .send()
        .await
        .unwrap();
    assert_eq!(versions.versions().len(), 2);
    iam.put_user_permissions_boundary()
        .user_name("carol")
        .permissions_boundary(&arn)
        .send()
        .await
        .unwrap();
    let carol = iam.get_user().user_name("carol").send().await.unwrap();
    assert_eq!(
        carol
            .user()
            .unwrap()
            .permissions_boundary()
            .unwrap()
            .permissions_boundary_arn(),
        Some(arn.as_str())
    );
    let entities = iam
        .list_entities_for_policy()
        .policy_arn(&arn)
        .send()
        .await
        .unwrap();
    let users: Vec<_> = entities
        .policy_users()
        .iter()
        .filter_map(|u| u.user_name())
        .collect();
    assert_eq!(users, ["alice", "carol"]);
    let summary = iam.get_account_summary().send().await.unwrap();
    assert_eq!(summary.summary_map().unwrap()[&SummaryKeyType::Users], 3);
    assert_eq!(summary.summary_map().unwrap()[&SummaryKeyType::Policies], 1);

    // Taking it all down, in the order IAM insists on.
    let err = iam
        .delete_user()
        .user_name("alice")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("DeleteConflict"));
    iam.delete_access_key()
        .user_name("alice")
        .access_key_id(key.access_key_id())
        .send()
        .await
        .unwrap();
    iam.detach_user_policy()
        .user_name("alice")
        .policy_arn(&arn)
        .send()
        .await
        .unwrap();
    iam.delete_user().user_name("alice").send().await.unwrap();
    iam.delete_user_permissions_boundary()
        .user_name("carol")
        .send()
        .await
        .unwrap();
    iam.delete_policy_version()
        .policy_arn(&arn)
        .version_id("v1")
        .send()
        .await
        .unwrap();
    iam.delete_policy().policy_arn(&arn).send().await.unwrap();
    // The deleted key signs nothing any more.
    let err = s3
        .list_objects_v2()
        .bucket("photos")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidAccessKeyId"));
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn the_aws_sdk_manages_roles() {
    let server = start().await;
    let iam = iam_as(&server, ACCESS_KEY, SECRET_KEY);
    let account = server.iam.account();
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{{"AWS":"arn:aws:iam::{account}:root"}}}}]}}"#
    );
    let policy = iam
        .create_policy()
        .policy_name("read")
        .policy_document(READ_PHOTOS)
        .send()
        .await
        .unwrap()
        .policy
        .unwrap()
        .arn
        .unwrap();
    let role = iam
        .create_role()
        .role_name("reader")
        .path("/svc/")
        .assume_role_policy_document(&trust)
        .description("reads photos")
        .max_session_duration(7200)
        .permissions_boundary(&policy)
        .tags(tag("team", "a"))
        .send()
        .await
        .unwrap()
        .role
        .unwrap();
    assert_eq!(role.arn, format!("arn:aws:iam::{account}:role/svc/reader"));
    assert!(role.role_id.starts_with("AROA"), "{}", role.role_id);
    assert_eq!(role.max_session_duration, Some(7200));
    assert_eq!(
        percent_decode(role.assume_role_policy_document.as_deref().unwrap()),
        trust
    );

    let got = iam
        .get_role()
        .role_name("READER")
        .send()
        .await
        .unwrap()
        .role
        .unwrap();
    assert_eq!(got.description.as_deref(), Some("reads photos"));
    assert_eq!(
        got.permissions_boundary
            .as_ref()
            .and_then(|b| b.permissions_boundary_arn.as_deref()),
        Some(policy.as_str())
    );
    assert_eq!(got.tags().len(), 1);
    iam.update_role()
        .role_name("reader")
        .max_session_duration(43_200)
        .send()
        .await
        .unwrap();
    let updated = iam
        .update_role_description()
        .role_name("reader")
        .description("reads more")
        .send()
        .await
        .unwrap()
        .role
        .unwrap();
    assert_eq!(
        (updated.description.as_deref(), updated.max_session_duration),
        (Some("reads more"), Some(43_200))
    );
    let listed = iam.list_roles().path_prefix("/svc/").send().await.unwrap();
    assert_eq!(listed.roles().len(), 1);
    assert!(listed.roles()[0].tags().is_empty(), "lists leave tags out");

    iam.put_role_policy()
        .role_name("reader")
        .policy_name("inline")
        .policy_document(READ_PHOTOS)
        .send()
        .await
        .unwrap();
    let inline = iam
        .get_role_policy()
        .role_name("reader")
        .policy_name("inline")
        .send()
        .await
        .unwrap();
    assert_eq!(percent_decode(&inline.policy_document), READ_PHOTOS);
    iam.attach_role_policy()
        .role_name("reader")
        .policy_arn(&policy)
        .send()
        .await
        .unwrap();
    let entities = iam
        .list_entities_for_policy()
        .policy_arn(&policy)
        .send()
        .await
        .unwrap();
    assert_eq!(
        entities
            .policy_roles()
            .iter()
            .map(|r| r.role_name.as_deref())
            .collect::<Vec<_>>(),
        [Some("reader")]
    );
    let conflict = iam
        .delete_role()
        .role_name("reader")
        .send()
        .await
        .unwrap_err();
    assert_eq!(conflict.code(), Some("DeleteConflict"));

    iam.update_assume_role_policy()
        .role_name("reader")
        .policy_document(trust.replace("sts:AssumeRole", "sts:TagSession"))
        .send()
        .await
        .unwrap();
    let malformed = iam
        .update_assume_role_policy()
        .role_name("reader")
        .policy_document(READ_PHOTOS)
        .send()
        .await
        .unwrap_err();
    assert_eq!(malformed.code(), Some("MalformedPolicyDocument"));
    iam.untag_role()
        .role_name("reader")
        .tag_keys("TEAM")
        .send()
        .await
        .unwrap();
    assert!(
        iam.list_role_tags()
            .role_name("reader")
            .send()
            .await
            .unwrap()
            .tags()
            .is_empty()
    );
    let summary = iam.get_account_summary().send().await.unwrap();
    assert_eq!(
        summary.summary_map().unwrap().get(&SummaryKeyType::Roles),
        Some(&1)
    );

    iam.delete_role_policy()
        .role_name("reader")
        .policy_name("inline")
        .send()
        .await
        .unwrap();
    iam.detach_role_policy()
        .role_name("reader")
        .policy_arn(&policy)
        .send()
        .await
        .unwrap();
    iam.delete_role_permissions_boundary()
        .role_name("reader")
        .send()
        .await
        .unwrap();
    iam.delete_role().role_name("reader").send().await.unwrap();
    let missing = iam.get_role().role_name("reader").send().await.unwrap_err();
    assert_eq!(missing.code(), Some("NoSuchEntity"));
}

#[tokio::test]
async fn the_aws_sdk_manages_openid_connect_providers() {
    let server = start().await;
    let iam = iam_as(&server, ACCESS_KEY, SECRET_KEY);
    let account = server.iam.account();
    let thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1";
    let created = iam
        .create_open_id_connect_provider()
        .url("https://token.actions.githubusercontent.com")
        .client_id_list("sts.amazonaws.com")
        .thumbprint_list(thumbprint)
        .tags(tag("team", "ci"))
        .send()
        .await
        .unwrap();
    let arn = created.open_id_connect_provider_arn.unwrap();
    assert_eq!(
        arn,
        format!("arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com")
    );
    assert_eq!(created.tags.unwrap().len(), 1);

    iam.add_client_id_to_open_id_connect_provider()
        .open_id_connect_provider_arn(&arn)
        .client_id("app")
        .send()
        .await
        .unwrap();
    iam.update_open_id_connect_provider_thumbprint()
        .open_id_connect_provider_arn(&arn)
        .thumbprint_list(thumbprint)
        .thumbprint_list("a".repeat(40))
        .send()
        .await
        .unwrap();
    let got = iam
        .get_open_id_connect_provider()
        .open_id_connect_provider_arn(&arn)
        .send()
        .await
        .unwrap();
    assert_eq!(got.url(), Some("token.actions.githubusercontent.com"));
    assert_eq!(got.client_id_list(), ["sts.amazonaws.com", "app"]);
    assert_eq!(got.thumbprint_list().len(), 2);
    assert!(got.create_date().is_some());
    assert_eq!(got.tags().len(), 1);

    let listed = iam.list_open_id_connect_providers().send().await.unwrap();
    let arns: Vec<_> = listed
        .open_id_connect_provider_list()
        .iter()
        .filter_map(|p| p.arn())
        .collect();
    assert_eq!(arns, [arn.as_str()]);

    iam.untag_open_id_connect_provider()
        .open_id_connect_provider_arn(&arn)
        .tag_keys("TEAM")
        .send()
        .await
        .unwrap();
    let tags = iam
        .list_open_id_connect_provider_tags()
        .open_id_connect_provider_arn(&arn)
        .send()
        .await
        .unwrap();
    assert!(tags.tags().is_empty() && !tags.is_truncated());

    let taken = iam
        .create_open_id_connect_provider()
        .url("https://token.actions.githubusercontent.com")
        .send()
        .await
        .unwrap_err();
    assert_eq!(taken.code(), Some("EntityAlreadyExists"));

    for _ in 0..2 {
        iam.delete_open_id_connect_provider()
            .open_id_connect_provider_arn(&arn)
            .send()
            .await
            .unwrap();
    }
    let missing = iam
        .get_open_id_connect_provider()
        .open_id_connect_provider_arn(&arn)
        .send()
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Some("NoSuchEntity"));
}

#[tokio::test]
async fn users_manage_their_own_keys() {
    let server = start().await;
    let iam = iam_as(&server, ACCESS_KEY, SECRET_KEY);
    iam.create_user().user_name("dev").send().await.unwrap();
    iam.put_user_policy()
        .user_name("dev")
        .policy_name("own-keys")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                "Action":["iam:*AccessKey*","iam:GetUser"],
                "Resource":"arn:aws:iam::*:user/${aws:username}"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let first = iam
        .create_access_key()
        .user_name("dev")
        .send()
        .await
        .unwrap();
    let first = first.access_key().unwrap();
    let dev = iam_as(&server, first.access_key_id(), first.secret_access_key());

    // No UserName: the caller.
    let me = dev.get_user().send().await.unwrap();
    assert_eq!(me.user().unwrap().user_name(), "dev");
    let second = dev.create_access_key().send().await.unwrap();
    let second = second.access_key().unwrap();
    assert_eq!(second.user_name(), "dev");
    let keys = dev.list_access_keys().send().await.unwrap();
    assert_eq!(keys.access_key_metadata().len(), 2);
    let rotated = iam_as(&server, second.access_key_id(), second.secret_access_key());
    rotated
        .delete_access_key()
        .access_key_id(first.access_key_id())
        .send()
        .await
        .unwrap();
    let err = dev.get_user().send().await.unwrap_err();
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 403);
    let last_used = rotated
        .get_access_key_last_used()
        .access_key_id(second.access_key_id())
        .send()
        .await
        .unwrap();
    assert_eq!(last_used.user_name(), Some("dev"));

    // Nobody else's.
    let err = rotated
        .create_access_key()
        .user_name("someone")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    // The root user's key belongs to the drive's configuration.
    let err = iam.create_access_key().send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidInput"));
    let root = iam.get_user().send().await.unwrap();
    assert!(root.user().unwrap().arn().ends_with(":root"));
}

/// Changes a request after the SDK signed it.
#[derive(Debug)]
enum Tamper {
    /// The same length of body, one character different.
    Body,
    /// Claims the body isn't signed.
    Unsigned,
    /// Signs the body's hash in `x-amz-content-sha256`, as S3 clients do.
    SignedHash,
    /// Signs the body's hash, then sends another body.
    SignedHashThenBody,
}

fn sha256_hex(bytes: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .fold(String::new(), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

impl Intercept for Tamper {
    fn name(&self) -> &'static str {
        "tamper"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        _: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        if matches!(self, Self::SignedHash | Self::SignedHashThenBody) {
            let request = context.request_mut();
            let hash = sha256_hex(request.body().bytes().unwrap());
            request.headers_mut().insert("x-amz-content-sha256", hash);
        }
        Ok(())
    }

    fn modify_before_transmit(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        _: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let request = context.request_mut();
        match self {
            Self::SignedHash => {}
            Self::Body | Self::SignedHashThenBody => {
                let body = std::str::from_utf8(request.body().bytes().unwrap())
                    .unwrap()
                    .replace("MaxItems=5", "MaxItems=6");
                *request.body_mut() = aws_sdk_s3::primitives::SdkBody::from(body);
            }
            Self::Unsigned => {
                request
                    .headers_mut()
                    .insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn only_the_body_that_was_signed_is_accepted() {
    let server = start().await;
    // A body whose hash is signed, as S3 clients sign theirs, is accepted as it is.
    let iam = iam_with(&server, ACCESS_KEY, SECRET_KEY, Some(Tamper::SignedHash));
    iam.list_users().max_items(5).send().await.unwrap();
    for tamper in [Tamper::Body, Tamper::Unsigned, Tamper::SignedHashThenBody] {
        let name = format!("{tamper:?}");
        let iam = iam_with(&server, ACCESS_KEY, SECRET_KEY, Some(tamper));
        let err = iam.list_users().max_items(5).send().await.unwrap_err();
        let response = err.raw_response().unwrap();
        assert_eq!(response.status().as_u16(), 403, "{name}");
        let body = std::str::from_utf8(response.body().bytes().unwrap()).unwrap();
        assert!(
            body.contains("<Code>SignatureDoesNotMatch</Code>"),
            "{name}: {body}"
        );
    }
    // Unsigned, only a web identity token is answered.
    let reply = reqwest::Client::new()
        .post(&server.endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=ListUsers&Version=2010-05-08")
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status().as_u16(), 403);
    assert!(
        reply
            .text()
            .await
            .unwrap()
            .contains("<Code>MissingAuthenticationToken</Code>")
    );
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}
