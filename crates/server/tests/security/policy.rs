//! Class 2: policies decide as AWS decides them, from facts the server establishes.
//!
//! Also proved elsewhere: the evaluator against AWS's documented results
//! (`crates/policy/tests/corpus.json`); conditions on the connection and the request
//! (`iam.rs`, `conditions_see_the_connection_and_the_request`); `RestrictPublicBuckets` on
//! every read and list, versions and uploads included (`bucket_policy.rs`,
//! `restrict_public_buckets_closes_every_read_and_list`); session policies only narrow
//! (`sts.rs`); a trust policy is the only way into a role (`crates/iam`,
//! `trust_policies_decide_who_may_assume_a_role`).

use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client, presigning::PresigningConfig, primitives::ByteStream, types::Tag, types::Tagging,
};

use crate::{
    common::{SECRET_KEY, Server, client, code, start, user},
    sign::{Payload, signed},
};

fn policy(statements: &str) -> String {
    format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#)
}

async fn put(s3: &Client, bucket: &str, key: &str, tags: Option<&str>) -> String {
    let mut put = s3
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(b"data"));
    if let Some(tags) = tags {
        put = put.tagging(tags);
    }
    code(put.send().await)
}

async fn get(s3: &Client, bucket: &str, key: &str) -> String {
    code(s3.get_object().bucket(bucket).key(key).send().await)
}

/// A user's access key, for requests signed by hand.
fn key_of(server: &Server, name: &str) -> (String, String) {
    let key = server.iam.create_access_key(name).unwrap();
    (key.info.id.clone(), key.secret.to_string())
}

/// CVE-2026-73286 (RustFS: request headers were folded into the condition keys, so a
/// `userid:` header made `aws:userid` match another principal): what a policy tests
/// about who is asking comes from the credentials, never from the request.
#[tokio::test]
async fn request_headers_cant_say_who_is_asking() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("shared").send().await.unwrap();
    put(&root, "shared", "alice.txt", None).await;
    // A condition on who's asking doesn't make a policy for everyone private.
    root.delete_public_access_block()
        .bucket("shared")
        .send()
        .await
        .unwrap();
    let alice_only = policy(
        r#"{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*","Condition":{"StringEquals":{"aws:username":"alice"}}},
           {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*","Condition":{"StringEquals":{"aws:PrincipalType":"AssumedRole"}}}"#,
    );
    root.put_bucket_policy()
        .bucket("shared")
        .policy(alice_only)
        .send()
        .await
        .unwrap();
    let alice = user(&server, "alice", None);
    assert_eq!(get(&alice, "shared", "alice.txt").await, "ok");
    server.iam.create_user("bob", None, &[], None).unwrap();
    let bob = key_of(&server, "bob");
    let alice_id = server.iam.user("alice").unwrap().id;
    let spoofed = [
        ("username", "alice"),
        ("userid", alice_id.as_str()),
        ("aws-username", "alice"),
        ("x-amz-username", "alice"),
        ("principaltype", "AssumedRole"),
        ("x-amz-meta-username", "alice"),
    ];
    for header in spoofed {
        let request = signed(
            &server,
            (&bob.0, &bob.1),
            "GET",
            "/shared/alice.txt",
            &[header],
            Payload::Bytes(b""),
        );
        let answer = request.send(&[], "").await;
        assert_eq!(answer.code, "AccessDenied", "{header:?}: {}", answer.body);
    }
    // Nor in the query, signed or not, nor for someone anonymous.
    let query = signed(
        &server,
        (&bob.0, &bob.1),
        "GET",
        "/shared/alice.txt?username=alice&aws%3Ausername=alice",
        &[],
        Payload::Bytes(b""),
    );
    assert_eq!(query.send(&[], "").await.code, "AccessDenied");
    let anonymous = reqwest::Client::new()
        .get(format!("{}/shared/alice.txt", server.endpoint))
        .header("username", "alice")
        .header("principaltype", "AssumedRole")
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 403);
}

/// CVE-2026-73289 (RustFS: `ForAllValues` and `ForAnyValue` with a negated operator had
/// each other's meaning): with a set that partly overlaps, as AWS decides it.
#[tokio::test]
async fn negated_set_conditions_mean_what_aws_says() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("tagged").send().await.unwrap();
    // No tag key may be `secret` (for all values, none equals it)...
    let none_secret = r#"{"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectTagging"],"Resource":"arn:aws:s3:::tagged/*","Condition":{"ForAllValues:StringNotEquals":{"s3:RequestObjectTagKeys":["secret"]}}}"#;
    // ...and every one must be `team` or `owner` (deny if any value is neither).
    let only_known = r#"{"Effect":"Deny","Action":"s3:PutObject","Resource":"arn:aws:s3:::tagged/*","Condition":{"ForAnyValue:StringNotEquals":{"s3:RequestObjectTagKeys":["team","owner"]}}}"#;
    let writer = user(
        &server,
        "writer",
        Some(&policy(&format!("{none_secret},{only_known}"))),
    );
    assert_eq!(put(&writer, "tagged", "a", Some("team=x")).await, "ok");
    assert_eq!(
        put(&writer, "tagged", "b", Some("team=x&owner=y")).await,
        "ok"
    );
    // Partly overlapping sets are where the two meanings differ.
    assert_eq!(
        put(&writer, "tagged", "c", Some("team=x&secret=y")).await,
        "AccessDenied"
    );
    assert_eq!(
        put(&writer, "tagged", "d", Some("team=x&other=y")).await,
        "AccessDenied"
    );
    // No tags: `ForAllValues` holds for an empty set, `ForAnyValue` doesn't.
    assert_eq!(put(&writer, "tagged", "e", None).await, "ok");
}

/// CVE-2026-73265 (RustFS: reading a named version was authorized as reading the
/// object): a version is read, copied, tagged or deleted with the version's action.
#[tokio::test]
async fn a_named_version_needs_the_version_action() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("history").send().await.unwrap();
    put(&root, "history", "doc", None).await;
    let current_only = policy(
        r#"{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:GetObjectTagging"],"Resource":"arn:aws:s3:::history/*"}"#,
    );
    let reader = user(&server, "reader", Some(&current_only));
    assert_eq!(get(&reader, "history", "doc").await, "ok");
    let version = |s3: &Client| {
        s3.get_object()
            .bucket("history")
            .key("doc")
            .version_id("null")
            .send()
    };
    assert_eq!(code(version(&reader).await), "AccessDenied");
    let tags = reader
        .get_object_tagging()
        .bucket("history")
        .key("doc")
        .version_id("null")
        .send();
    assert_eq!(code(tags.await), "AccessDenied");
    let copy = reader
        .copy_object()
        .bucket("history")
        .key("copy")
        .copy_source("history/doc?versionId=null")
        .send();
    assert_eq!(code(copy.await), "AccessDenied");
    let delete = reader
        .delete_object()
        .bucket("history")
        .key("doc")
        .version_id("null")
        .send();
    assert_eq!(code(delete.await), "AccessDenied");
    assert_eq!(
        get(&root, "history", "doc").await,
        "ok",
        "nothing was deleted"
    );

    let versions = policy(
        r#"{"Effect":"Allow","Action":["s3:GetObjectVersion","s3:PutObject"],"Resource":"arn:aws:s3:::history/*"}"#,
    );
    let historian = user(&server, "historian", Some(&versions));
    assert_eq!(code(version(&historian).await), "ok");
    // Without `s3:GetObject`, the current object isn't the version's to read.
    assert_eq!(get(&historian, "history", "doc").await, "AccessDenied");
}

/// CVE-2026-73285 (RustFS: an authorization plugin dropped `s3:ExistingObjectTag`): an
/// object's own tags decide what policies say they decide: reads, copies from it and
/// changes to its tags, so a denied object can't be retagged into an allowed one.
#[tokio::test]
async fn an_objects_own_tags_decide_what_policies_say() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("records").send().await.unwrap();
    for (key, tags) in [
        ("public.txt", Some("visibility=public")),
        ("secret.txt", Some("visibility=secret")),
        ("untagged.txt", None),
    ] {
        assert_eq!(put(&root, "records", key, tags).await, "ok");
    }
    // Everything, except what's tagged secret.
    let guarded = policy(
        r#"{"Effect":"Deny","Principal":"*","Action":["s3:GetObject","s3:GetObjectTagging","s3:PutObjectTagging","s3:DeleteObjectTagging"],"Resource":"arn:aws:s3:::records/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/visibility":"secret"}}}"#,
    );
    root.put_bucket_policy()
        .bucket("records")
        .policy(guarded)
        .send()
        .await
        .unwrap();
    let everything = policy(r#"{"Effect":"Allow","Action":"s3:*","Resource":"*"}"#);
    let staff = user(&server, "staff", Some(&everything));
    assert_eq!(get(&staff, "records", "public.txt").await, "ok");
    assert_eq!(get(&staff, "records", "untagged.txt").await, "ok");
    assert_eq!(get(&staff, "records", "secret.txt").await, "AccessDenied");
    let head = staff
        .head_object()
        .bucket("records")
        .key("secret.txt")
        .send();
    let refused = head.await.unwrap_err();
    assert_eq!(refused.raw_response().unwrap().status().as_u16(), 403);
    let copy = staff
        .copy_object()
        .bucket("records")
        .key("leaked.txt")
        .copy_source("records/secret.txt")
        .send();
    assert_eq!(code(copy.await), "AccessDenied");
    let public = Tagging::builder()
        .tag_set(
            Tag::builder()
                .key("visibility")
                .value("public")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let retag = staff
        .put_object_tagging()
        .bucket("records")
        .key("secret.txt")
        .tagging(public.clone())
        .send();
    assert_eq!(code(retag.await), "AccessDenied");
    let untag = staff
        .delete_object_tagging()
        .bucket("records")
        .key("secret.txt")
        .send();
    assert_eq!(code(untag.await), "AccessDenied");
    assert_eq!(get(&staff, "records", "secret.txt").await, "AccessDenied");

    // An allow that needs a tag: only what's tagged public, in a bucket whose own
    // policy tests no tags.
    root.create_bucket().bucket("open").send().await.unwrap();
    for (key, tags) in [
        ("public.txt", Some("visibility=public")),
        ("untagged.txt", None),
    ] {
        assert_eq!(put(&root, "open", key, tags).await, "ok");
    }
    let tagged_public = policy(
        r#"{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"s3:ExistingObjectTag/visibility":"public"}}}"#,
    );
    let visitor = user(&server, "visitor", Some(&tagged_public));
    assert_eq!(get(&visitor, "open", "public.txt").await, "ok");
    assert_eq!(get(&visitor, "open", "untagged.txt").await, "AccessDenied");
    assert_eq!(get(&visitor, "open", "missing.txt").await, "AccessDenied");
    // A permissions boundary that tests them, over a policy that doesn't.
    let boundary = server
        .iam
        .create_policy("public-reads", None, None, &tagged_public, &[])
        .unwrap();
    let bounded = user(&server, "bounded", Some(&everything));
    server
        .iam
        .set_user_boundary("bounded", Some(&boundary.arn))
        .unwrap();
    assert_eq!(get(&bounded, "open", "public.txt").await, "ok");
    assert_eq!(get(&bounded, "open", "untagged.txt").await, "AccessDenied");
    // A session policy that tests them, over a user's policy that doesn't.
    let guest = federated(&server, &tagged_public).await;
    assert_eq!(get(&guest, "open", "public.txt").await, "ok");
    assert_eq!(get(&guest, "open", "untagged.txt").await, "AccessDenied");

    // The Deny binds the root user too; the object's tags when a request is made decide
    // it, so once it's replaced by one tagged public, it's readable.
    let retag = root
        .put_object_tagging()
        .bucket("records")
        .key("secret.txt")
        .tagging(public)
        .send();
    assert_eq!(code(retag.await), "AccessDenied");
    assert_eq!(
        put(&root, "records", "secret.txt", Some("visibility=public")).await,
        "ok"
    );
    assert_eq!(get(&staff, "records", "secret.txt").await, "ok");
    assert_eq!(get(&visitor, "records", "secret.txt").await, "ok");
}

/// A presigned link's age is how long ago it was signed, as AWS measures it for
/// `s3:signatureAge`: a Deny on old links refuses one signed twenty minutes ago however
/// long it's valid, and headers signed now have no age to test.
#[tokio::test]
async fn a_presigned_links_age_is_when_it_was_signed() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("aged").send().await.unwrap();
    put(&root, "aged", "a", None).await;
    root.put_bucket_policy()
        .bucket("aged")
        .policy(policy(
            r#"{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::aged/*","Condition":{"NumericGreaterThan":{"s3:signatureAge":"600000"}}}"#,
        ))
        .send()
        .await
        .unwrap();
    let link = |age: Duration| {
        let root = root.clone();
        async move {
            let config = PresigningConfig::builder()
                .start_time(SystemTime::now() - age)
                .expires_in(Duration::from_hours(1))
                .build()
                .unwrap();
            let link = root
                .get_object()
                .bucket("aged")
                .key("a")
                .presigned(config)
                .await
                .unwrap();
            reqwest::get(link.uri()).await.unwrap().status().as_u16()
        }
    };
    assert_eq!(link(Duration::ZERO).await, 200);
    assert_eq!(link(Duration::from_mins(9)).await, 200);
    assert_eq!(link(Duration::from_mins(20)).await, 403);
    root.get_object()
        .bucket("aged")
        .key("a")
        .send()
        .await
        .unwrap();
}

/// An S3 client for a federated user whose session `policy` narrows a user allowed
/// everything.
async fn federated(server: &Server, policy_text: &str) -> Client {
    let everything =
        policy(r#"{"Effect":"Allow","Action":["s3:*","sts:GetFederationToken"],"Resource":"*"}"#);
    server
        .iam
        .create_user("federator", None, &[], None)
        .unwrap();
    server
        .iam
        .put_inline(teifs_iam::Owner::User("federator"), "policy", &everything)
        .unwrap();
    let (id, secret) = key_of(server, "federator");
    let region = aws_sdk_sts::config::Region::new("us-east-1");
    let sts = aws_sdk_sts::Client::from_conf(
        aws_sdk_sts::Config::builder()
            .behavior_version_latest()
            .region(region.clone())
            .endpoint_url(&server.endpoint)
            .credentials_provider(Credentials::new(id, secret, None, None, "tests"))
            .build(),
    );
    let session = sts
        .get_federation_token()
        .name("guest")
        .policy(policy_text)
        .send()
        .await
        .unwrap();
    let keys = session.credentials().unwrap();
    Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .credentials_provider(Credentials::new(
                keys.access_key_id(),
                keys.secret_access_key(),
                Some(keys.session_token().to_owned()),
                None,
                "tests",
            ))
            .force_path_style(true)
            .build(),
    )
}
