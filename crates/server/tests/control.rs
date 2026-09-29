//! S3 Control's account-level Block Public Access over the official SDK, as AWS applies
//! it (with every bucket's own settings, the most restrictive winning), and the table of
//! everything served besides S3's operations: each endpoint refuses anonymous callers
//! and users without its permission.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{Client, primitives::ByteStream, types::ObjectCannedAcl};
use aws_sdk_s3control::{
    config::{
        Credentials, Region,
        endpoint::{Endpoint, EndpointFuture, Params, ResolveEndpoint},
    },
    types::PublicAccessBlockConfiguration,
};
use reqwest::Method;

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, anonymous, client, code, start, user};
use signing::signed;

/// Sends every request to the server, where AWS's SDKs would put the account in the
/// host name.
#[derive(Debug)]
struct Direct(String);

impl ResolveEndpoint for Direct {
    fn resolve_endpoint<'a>(&'a self, _: &'a Params) -> EndpointFuture<'a> {
        EndpointFuture::ready(Ok(Endpoint::builder().url(self.0.clone()).build()))
    }
}

fn control(server: &Server, access_key: &str, secret: &str) -> aws_sdk_s3control::Client {
    let config = aws_sdk_s3control::Config::builder()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .endpoint_resolver(Direct(server.endpoint.clone()))
        .credentials_provider(Credentials::new(access_key, secret, None, None, "tests"))
        .build();
    aws_sdk_s3control::Client::from_conf(config)
}

fn settings(
    restrict: bool,
    block_policy: bool,
    block_acls: bool,
) -> PublicAccessBlockConfiguration {
    PublicAccessBlockConfiguration::builder()
        .restrict_public_buckets(restrict)
        .block_public_policy(block_policy)
        .block_public_acls(block_acls)
        .ignore_public_acls(false)
        .build()
}

/// A bucket open to the public as far as its own settings go: ACLs enabled, no Block
/// Public Access, a public policy, and an object `a.txt`.
async fn open_bucket(root: &Client) {
    root.create_bucket()
        .bucket("site")
        .object_ownership(aws_sdk_s3::types::ObjectOwnership::ObjectWriter)
        .send()
        .await
        .unwrap();
    root.delete_public_access_block()
        .bucket("site")
        .send()
        .await
        .unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::site/*"}}"#;
    root.put_bucket_policy()
        .bucket("site")
        .policy(policy)
        .send()
        .await
        .unwrap();
    root.put_object()
        .bucket("site")
        .key("a.txt")
        .body(ByteStream::from_static(b"hi"))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn account_settings_round_trip() {
    let server = start().await;
    let account = server.iam.account();
    let s3control = control(&server, ACCESS_KEY, SECRET_KEY);
    let get = || {
        s3control
            .get_public_access_block()
            .account_id(&account)
            .send()
    };
    assert_eq!(code(get().await), "NoSuchPublicAccessBlockConfiguration");
    s3control
        .put_public_access_block()
        .account_id(&account)
        .public_access_block_configuration(settings(true, false, true))
        .send()
        .await
        .unwrap();
    let got = get().await.unwrap();
    let got = got.public_access_block_configuration().unwrap();
    assert_eq!(
        (
            got.restrict_public_buckets(),
            got.block_public_policy(),
            got.block_public_acls(),
            got.ignore_public_acls()
        ),
        (Some(true), Some(false), Some(true), Some(false))
    );
    s3control
        .delete_public_access_block()
        .account_id(&account)
        .send()
        .await
        .unwrap();
    assert_eq!(code(get().await), "NoSuchPublicAccessBlockConfiguration");
    // Another account's settings aren't this drive's to show.
    let other = s3control
        .get_public_access_block()
        .account_id("000000000000")
        .send()
        .await;
    assert_eq!(code(other), "AccessDenied");
}

#[tokio::test]
async fn account_settings_apply_to_every_bucket() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    let s3control = control(&server, ACCESS_KEY, SECRET_KEY);
    open_bucket(&root).await;
    assert_eq!(anonymous(&server, Method::GET, "/site/a.txt").await, 200);
    let put = |config| {
        s3control
            .put_public_access_block()
            .account_id(&account)
            .public_access_block_configuration(config)
            .send()
    };
    put(settings(true, true, true)).await.unwrap();
    // RestrictPublicBuckets closes the bucket's public policy at once...
    assert_eq!(anonymous(&server, Method::GET, "/site/a.txt").await, 403);
    // ...BlockPublicPolicy refuses a public policy and BlockPublicAcls a public ACL...
    let policy = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::site"}}"#;
    let refused = root
        .put_bucket_policy()
        .bucket("site")
        .policy(policy)
        .send();
    assert_eq!(code(refused.await), "AccessDenied");
    let acl = root
        .put_object()
        .bucket("site")
        .key("b.txt")
        .acl(ObjectCannedAcl::PublicRead)
        .body(ByteStream::from_static(b"hi"))
        .send();
    assert_eq!(code(acl.await), "AccessDenied");
    // ...while the bucket still reports only its own settings.
    let own = root.get_public_access_block().bucket("site").send().await;
    assert_eq!(code(own), "NoSuchPublicAccessBlockConfiguration");
    // Settings the account turns off are the bucket's own again.
    put(settings(false, false, false)).await.unwrap();
    assert_eq!(anonymous(&server, Method::GET, "/site/a.txt").await, 200);
    put(settings(true, false, false)).await.unwrap();
    assert_eq!(anonymous(&server, Method::GET, "/site/a.txt").await, 403);
    s3control
        .delete_public_access_block()
        .account_id(&account)
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous(&server, Method::GET, "/site/a.txt").await, 200);
}

#[tokio::test]
async fn users_need_the_permission() {
    let server = start().await;
    let account = server.iam.account();
    let reader = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetAccountPublicAccessBlock","Resource":"*"}}"#;
    user(&server, "reader", Some(reader));
    let key = server.iam.create_access_key("reader").unwrap();
    let s3control = control(&server, &key.info.id, &key.secret);
    let get = s3control
        .get_public_access_block()
        .account_id(&account)
        .send();
    assert_eq!(code(get.await), "NoSuchPublicAccessBlockConfiguration");
    let put = s3control
        .put_public_access_block()
        .account_id(&account)
        .public_access_block_configuration(settings(true, true, true))
        .send();
    assert_eq!(code(put.await), "AccessDenied");
    let delete = s3control
        .delete_public_access_block()
        .account_id(&account)
        .send();
    assert_eq!(code(delete.await), "AccessDenied");
}

#[tokio::test]
async fn every_endpoint_refuses_anonymous_callers_and_users_without_permission() {
    let server = start().await;
    let account = server.iam.account();
    user(&server, "nobody", None);
    let key = server.iam.create_access_key("nobody").unwrap();
    let mut walked = 0;
    for endpoint in teifs_s3::endpoints() {
        let mut headers = vec![("content-type", "application/x-www-form-urlencoded")];
        if endpoint.control {
            headers = vec![("x-amz-account-id", account.as_str())];
        }
        let body: &[u8] = if endpoint.control {
            b""
        } else {
            b"Action=ListUsers&Version=2010-05-08"
        };
        let method = Method::from_bytes(endpoint.method.as_bytes()).unwrap();
        let mut unsigned = reqwest::Client::new()
            .request(method, format!("{}{}", server.endpoint, endpoint.path))
            .body(body.to_vec());
        for (name, value) in &headers {
            unsigned = unsigned.header(*name, *value);
        }
        let status = unsigned.send().await.unwrap().status().as_u16();
        assert_eq!(status, 403, "anonymous {endpoint:?}");
        let (status, answer) = signed(
            &server,
            (&key.info.id, &key.secret),
            endpoint.method,
            endpoint.path,
            &headers,
            body,
        )
        .await;
        // IAM's Query API names its action in the body (s3 isn't its signing service).
        if endpoint.action.is_some() {
            assert_eq!(status, 403, "{endpoint:?}: {answer}");
            assert!(answer.contains("AccessDenied"), "{endpoint:?}: {answer}");
        } else {
            assert!(status >= 400, "{endpoint:?}: {answer}");
        }
        walked += 1;
    }
    assert!(walked >= 4);
}

#[tokio::test]
async fn s3_control_is_told_apart_from_a_bucket() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    // Without x-amz-account-id, /v20180820/… is a bucket and its keys.
    root.create_bucket()
        .bucket("v20180820")
        .send()
        .await
        .unwrap();
    let key = "configuration/publicAccessBlock";
    root.put_object()
        .bucket("v20180820")
        .key(key)
        .body(ByteStream::from_static(b"an object"))
        .send()
        .await
        .unwrap();
    let object = root.get_object().bucket("v20180820").key(key).send();
    let bytes = object.await.unwrap().body.collect().await.unwrap();
    assert_eq!(bytes.into_bytes().as_ref(), b"an object");

    let account = server.iam.account();
    let root_key = (ACCESS_KEY, SECRET_KEY);
    let headers = [("x-amz-account-id", account.as_str())];
    let (status, answer) = signed(&server, root_key, "GET", "/v20180820/jobs", &headers, b"").await;
    assert_eq!(status, 501, "{answer}");
    // Unsigned, even what isn't served is refused before anything else.
    let unsigned = reqwest::Client::new()
        .get(format!("{}/v20180820/jobs", server.endpoint))
        .header("x-amz-account-id", account.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status().as_u16(), 403);
    let (status, answer) = signed(
        &server,
        root_key,
        "PUT",
        "/v20180820/configuration/publicAccessBlock",
        &headers,
        b"<NotTheSettings/>",
    )
    .await;
    assert_eq!(status, 400, "{answer}");
    assert!(answer.contains("MalformedXML"), "{answer}");
}
