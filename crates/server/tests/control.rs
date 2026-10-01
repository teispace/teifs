//! S3 Control's account-level Block Public Access over the official SDK, as AWS applies
//! it (with every bucket's own settings, the most restrictive winning), and the table of
//! everything served besides S3's operations (IAM, STS, S3 Control, the admin API): each
//! endpoint refuses anonymous callers and users without its permission.

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
use signing::{signed, signed_as_sent};
use teifs_s3::Api;

/// A `TagResource` body: `team=blue`.
const TAG_BLUE: &str = r#"<TagResourceRequest xmlns="http://awss3control.amazonaws.com/doc/2018-08-20/"><Tags><Tag><Key>team</Key><Value>blue</Value></Tag></Tags></TagResourceRequest>"#;

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
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    user(&server, "nobody", None);
    let key = server.iam.create_access_key("nobody").unwrap();
    let mut walked = 0;
    for endpoint in teifs_s3::endpoints() {
        let (headers, body): (Vec<(&str, &str)>, &[u8]) = match endpoint.api {
            Api::Query => (
                vec![("content-type", "application/x-www-form-urlencoded")],
                b"Action=ListUsers&Version=2010-05-08",
            ),
            Api::Control if endpoint.method == "POST" => (
                vec![("x-amz-account-id", account.as_str())],
                TAG_BLUE.as_bytes(),
            ),
            Api::Control => (vec![("x-amz-account-id", account.as_str())], b""),
            Api::Admin | Api::Minio => (Vec::new(), b""),
        };
        let method = Method::from_bytes(endpoint.method.as_bytes()).unwrap();
        // A bucket's tags: a real bucket, and a key to remove.
        let path = endpoint
            .path
            .replace("{resourceArn}", "arn:aws:s3:::photos");
        let path = if endpoint.method == "DELETE" && path.contains("/tags/") {
            format!("{path}?tagKeys=team")
        } else if endpoint.api == Api::Minio {
            format!("{path}?bucket=photos")
        } else {
            path
        };
        let mut unsigned = reqwest::Client::new()
            .request(method, format!("{}{path}", server.endpoint))
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
            &path,
            &headers,
            body,
        )
        .await;
        // IAM's Query API names its action in the body (s3 isn't its signing service).
        // A call on one's own key needs no permission (`change-my-password`): it fails on
        // what it's sent instead.
        if (endpoint.action.is_some() && !endpoint.own_key) || endpoint.root_only {
            assert_eq!(status, 403, "{endpoint:?}: {answer}");
            assert!(answer.contains("AccessDenied"), "{endpoint:?}: {answer}");
        } else {
            assert!(status >= 400, "{endpoint:?}: {answer}");
        }
        walked += 1;
    }
    assert!(walked >= 9);
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

/// A bucket's tags through S3 Control, which changes them one by one whether or not they
/// decide access (ABAC), and decides each call on the bucket: the tags a call adds, the
/// keys it removes, the bucket's own tags while ABAC is on, and its bucket policy.
#[tokio::test]
async fn bucket_tags_change_one_by_one_through_s3_control() {
    use aws_sdk_s3::types::{AbacStatus, BucketAbacStatus};
    use aws_sdk_s3control::types::Tag;

    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    let s3control = control(&server, ACCESS_KEY, SECRET_KEY);
    let arn = "arn:aws:s3:::photos";
    let tag = |key: &str, value: &str| Tag::builder().key(key).value(value).build().unwrap();
    let tags_of = |s3control: &aws_sdk_s3control::Client, arn: &str| {
        let list = s3control.list_tags_for_resource().account_id(&account);
        list.resource_arn(arn).send()
    };
    let tag_with = |s3control: &aws_sdk_s3control::Client, tags: Vec<Tag>| {
        let call = s3control
            .tag_resource()
            .account_id(&account)
            .resource_arn(arn);
        call.set_tags(Some(tags)).send()
    };
    let untag = |s3control: &aws_sdk_s3control::Client, key: &str| {
        let call = s3control
            .untag_resource()
            .account_id(&account)
            .resource_arn(arn);
        call.tag_keys(key).send()
    };
    let listed = async |s3control: &aws_sdk_s3control::Client| {
        let tags = tags_of(s3control, arn).await.unwrap();
        let tags = tags
            .tags()
            .iter()
            .map(|t| format!("{}={}", t.key(), t.value()));
        tags.collect::<Vec<_>>()
    };
    let abac = async |status: BucketAbacStatus| {
        let status = AbacStatus::builder().status(status).build();
        let put = root.put_bucket_abac().bucket("photos").abac_status(status);
        put.send().await.unwrap();
    };

    assert!(listed(&s3control).await.is_empty());
    abac(BucketAbacStatus::Enabled).await;
    let two = vec![tag("team", "blue"), tag("cost", "low")];
    tag_with(&s3control, two).await.unwrap();
    assert_eq!(listed(&s3control).await, ["cost=low", "team=blue"]);
    tag_with(&s3control, vec![tag("cost", "high")])
        .await
        .unwrap();
    untag(&s3control, "team").await.unwrap();
    untag(&s3control, "absent").await.unwrap();
    assert_eq!(listed(&s3control).await, ["cost=high"]);
    let s3 = root.get_bucket_tagging().bucket("photos").send().await;
    assert_eq!(s3.unwrap().tag_set().len(), 1);

    // Checked as a bucket's tags, on a bucket that exists.
    let reserved = tag_with(&s3control, vec![tag("aws:team", "x")]).await;
    assert_eq!(code(reserved), "InvalidTag");
    let fifty = (0..50).map(|i| tag(&format!("k{i}"), "v")).collect();
    assert_eq!(code(tag_with(&s3control, fifty).await), "InvalidTag");
    assert_eq!(
        code(tags_of(&s3control, "arn:aws:s3:::missing").await),
        "NoSuchBucket"
    );
    let object = tags_of(&s3control, "arn:aws:s3:::photos/a.txt").await;
    assert_eq!(code(object), "InvalidRequest");

    // Policies decide on what a call asks for, and on the bucket's own tags.
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"s3:TagResource","Resource":"arn:aws:s3:::photos","Condition":{"StringEquals":{"aws:RequestTag/team":["blue","red"]},"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}},
        {"Effect":"Allow","Action":"s3:UntagResource","Resource":"arn:aws:s3:::photos","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["cost"]}}},
        {"Effect":"Allow","Action":"s3:ListTagsForResource","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"blue"}}}]}"#;
    user(&server, "tagger", Some(policy));
    let key = server.iam.create_access_key("tagger").unwrap();
    let tagger = control(&server, &key.info.id, &key.secret);
    assert_eq!(code(tags_of(&tagger, arn).await), "AccessDenied");
    tag_with(&tagger, vec![tag("team", "red")]).await.unwrap();
    for refused in [
        vec![tag("team", "green")],
        vec![tag("team", "blue"), tag("cost", "x")],
    ] {
        assert_eq!(code(tag_with(&tagger, refused).await), "AccessDenied");
    }
    assert_eq!(code(untag(&tagger, "team").await), "AccessDenied");
    untag(&tagger, "cost").await.unwrap();
    assert_eq!(code(tags_of(&tagger, arn).await), "AccessDenied");
    tag_with(&tagger, vec![tag("team", "blue")]).await.unwrap();
    assert_eq!(listed(&tagger).await, ["team=blue"]);
    abac(BucketAbacStatus::Disabled).await;
    assert_eq!(code(tags_of(&tagger, arn).await), "AccessDenied");

    // A bucket policy's Deny binds the root user too.
    let frozen = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:TagResource","s3:UntagResource"],"Resource":"arn:aws:s3:::photos"}]}"#;
    let put = root.put_bucket_policy().bucket("photos").policy(frozen);
    put.send().await.unwrap();
    let denied = tag_with(&s3control, vec![tag("team", "red")]).await;
    assert_eq!(code(denied), "AccessDenied");
    assert_eq!(code(untag(&s3control, "team").await), "AccessDenied");
    assert_eq!(listed(&s3control).await, ["team=blue"]);
}

/// S3 Control's paths carry an ARN, which botocore (the AWS CLI) signs as sent and AWS's
/// other SDKs encode again first: both are checked, and a signature that matches
/// neither way is refused.
#[tokio::test]
async fn an_arn_in_the_path_is_signed_as_every_sdk_signs_it() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    let tagging = aws_sdk_s3::types::Tagging::builder()
        .tag_set(
            aws_sdk_s3::types::Tag::builder()
                .key("team")
                .value("blue")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let put = root.put_bucket_tagging().bucket("photos").tagging(tagging);
    put.send().await.unwrap();

    let path = "/v20180820/tags/arn%3Aaws%3As3%3A%3A%3Aphotos";
    let headers = [("x-amz-account-id", account.as_str())];
    let root_key = (ACCESS_KEY, SECRET_KEY);
    for (status, answer) in [
        signed_as_sent(&server, root_key, "GET", path, &headers, b"").await,
        signed(&server, root_key, "GET", path, &headers, b"").await,
    ] {
        assert_eq!(status, 200, "{answer}");
        assert!(
            answer.contains("<Key>team</Key><Value>blue</Value>"),
            "{answer}"
        );
    }
    let wrong = (ACCESS_KEY, "not-the-secret-key-at-all-just-wrong");
    for (status, answer) in [
        signed_as_sent(&server, wrong, "GET", path, &headers, b"").await,
        signed(&server, wrong, "GET", path, &headers, b"").await,
    ] {
        assert_eq!(status, 403, "{answer}");
        assert!(answer.contains("SignatureDoesNotMatch"), "{answer}");
    }
}
