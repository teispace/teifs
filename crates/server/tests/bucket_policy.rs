//! Bucket policies and Block Public Access over the S3 API, as AWS applies them: to IAM
//! users, the root user and anonymous requests.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{Client, primitives::ByteStream, types::PublicAccessBlockConfiguration};
use reqwest::Method;

mod common;

use common::{SECRET_KEY, Server, anonymous, client, code, start, user};

fn statement(effect: &str, principal: &str, actions: &str, resources: &str) -> String {
    format!(
        r#"{{"Effect":"{effect}","Principal":{principal},"Action":{actions},"Resource":{resources}}}"#
    )
}

fn policy(statements: &[String]) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{}]}}"#,
        statements.join(",")
    )
}

/// A policy that lets anyone read `photos`' objects and list it.
fn public_read() -> String {
    policy(&[statement(
        "Allow",
        r#""*""#,
        r#"["s3:GetObject","s3:ListBucket"]"#,
        r#"["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]"#,
    )])
}

async fn put(s3: &Client, bucket: &str, key: &str) -> String {
    code(
        s3.put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from_static(b"data"))
            .send()
            .await,
    )
}

async fn get(s3: &Client, bucket: &str, key: &str) -> String {
    code(s3.get_object().bucket(bucket).key(key).send().await)
}

/// A bucket `photos` with `a.jpg` and `public/b.jpg`, created by the root user.
async fn setup(server: &Server) -> Client {
    let root = client(server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    for key in ["a.jpg", "public/b.jpg"] {
        assert_eq!(put(&root, "photos", key).await, "ok");
    }
    root
}

async fn put_policy(root: &Client, text: &str) -> String {
    code(
        root.put_bucket_policy()
            .bucket("photos")
            .policy(text)
            .send()
            .await,
    )
}

async fn put_block(root: &Client, restrict: bool) {
    root.put_public_access_block()
        .bucket("photos")
        .public_access_block_configuration(
            PublicAccessBlockConfiguration::builder()
                .restrict_public_buckets(restrict)
                .build(),
        )
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn policies_and_settings_round_trip() {
    let server = start().await;
    let root = setup(&server).await;
    // A new bucket blocks public access, and has no policy.
    let block = root
        .get_public_access_block()
        .bucket("photos")
        .send()
        .await
        .unwrap()
        .public_access_block_configuration
        .unwrap();
    assert_eq!(
        (
            block.block_public_acls(),
            block.ignore_public_acls(),
            block.block_public_policy(),
            block.restrict_public_buckets()
        ),
        (Some(true), Some(true), Some(true), Some(true))
    );
    let no_policy = "NoSuchBucketPolicy";
    assert_eq!(
        code(root.get_bucket_policy().bucket("photos").send().await),
        no_policy
    );
    assert_eq!(
        code(
            root.get_bucket_policy_status()
                .bucket("photos")
                .send()
                .await
        ),
        no_policy
    );
    // BlockPublicPolicy refuses a public policy, not a private one.
    assert_eq!(put_policy(&root, &public_read()).await, "AccessDenied");
    let account = server.iam.account();
    let private = public_read().replace(r#""*""#, &format!(r#"{{"AWS":"{account}"}}"#));
    assert_eq!(put_policy(&root, &private).await, "ok");
    let stored = root
        .get_bucket_policy()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(stored.policy(), Some(private.as_str()));
    let status = root
        .get_bucket_policy_status()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(status.policy_status().unwrap().is_public(), Some(false));

    root.delete_public_access_block()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(root.get_public_access_block().bucket("photos").send().await),
        "NoSuchPublicAccessBlockConfiguration"
    );
    assert_eq!(put_policy(&root, &public_read()).await, "ok");
    let status = root
        .get_bucket_policy_status()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(status.policy_status().unwrap().is_public(), Some(true));
    root.delete_bucket_policy()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(root.get_bucket_policy().bucket("photos").send().await),
        no_policy
    );
}

#[tokio::test]
async fn malformed_policies_and_missing_buckets_are_refused() {
    let server = start().await;
    let root = setup(&server).await;
    let account = server.iam.account();
    let private = public_read().replace(r#""*""#, &format!(r#"{{"AWS":"{account}"}}"#));
    for malformed in [
        "{".to_owned(),
        public_read().replace("photos", "other"),
        public_read().replace(r#""Principal":"*","#, ""),
        public_read().replace("s3:GetObject", "s3:MadeUp"),
        public_read().replace(
            "{\"Version\"",
            &format!("{}{{\"Version\"", " ".repeat(20 * 1024)),
        ),
    ] {
        assert_eq!(put_policy(&root, &malformed).await, "MalformedPolicy");
    }
    assert_eq!(
        code(root.get_bucket_policy().bucket("nope").send().await),
        "NoSuchBucket"
    );
    assert_eq!(
        code(
            root.put_bucket_policy()
                .bucket("nope")
                .policy(private)
                .send()
                .await
        ),
        "NoSuchBucket"
    );
}

#[tokio::test]
async fn a_deleted_bucket_forgets_its_policy() {
    let server = start().await;
    let root = setup(&server).await;
    let no_policy = "NoSuchBucketPolicy";
    root.delete_public_access_block()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    // A bucket deleted and made again starts afresh, even as a folder made by hand.
    assert_eq!(put_policy(&root, &public_read()).await, "ok");
    assert_eq!(anonymous(&server, Method::GET, "/photos").await, 200);
    for key in ["a.jpg", "public/b.jpg"] {
        root.delete_object()
            .bucket("photos")
            .key(key)
            .send()
            .await
            .unwrap();
    }
    root.delete_bucket().bucket("photos").send().await.unwrap();
    std::fs::create_dir(server.dir.path().join("photos")).unwrap();
    for _ in 0..2 {
        assert_eq!(
            code(root.get_bucket_policy().bucket("photos").send().await),
            no_policy
        );
        assert_eq!(anonymous(&server, Method::GET, "/photos").await, 403);
        root.delete_bucket().bucket("photos").send().await.unwrap();
        root.create_bucket().bucket("photos").send().await.unwrap();
    }
}

#[tokio::test]
async fn anonymous_requests_get_only_what_a_public_policy_allows() {
    let server = start().await;
    let root = setup(&server).await;
    // Without a policy, nothing.
    assert_eq!(
        anonymous(&server, Method::GET, "/photos/public/b.jpg").await,
        403
    );
    root.delete_public_access_block()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    let objects = policy(&[statement(
        "Allow",
        r#""*""#,
        r#""s3:GetObject""#,
        r#""arn:aws:s3:::photos/public/*""#,
    )]);
    assert_eq!(put_policy(&root, &objects).await, "ok");
    assert_eq!(
        anonymous(&server, Method::GET, "/photos/public/b.jpg").await,
        200
    );
    assert_eq!(
        anonymous(&server, Method::HEAD, "/photos/public/b.jpg").await,
        200
    );
    assert_eq!(anonymous(&server, Method::GET, "/photos/a.jpg").await, 403);
    // Missing keys are hidden from whoever can't list.
    assert_eq!(
        anonymous(&server, Method::GET, "/photos/public/none").await,
        403
    );
    assert_eq!(anonymous(&server, Method::GET, "/photos").await, 403);
    assert_eq!(
        anonymous(&server, Method::PUT, "/photos/public/c.jpg").await,
        403
    );
    assert_eq!(
        anonymous(&server, Method::DELETE, "/photos/public/b.jpg").await,
        403
    );
    assert_eq!(anonymous(&server, Method::GET, "/").await, 403);
    // The policy itself is the owner's alone, whatever it says.
    let owner_only = policy(&[statement(
        "Allow",
        r#""*""#,
        r#""s3:*""#,
        r#"["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]"#,
    )]);
    assert_eq!(put_policy(&root, &owner_only).await, "ok");
    assert_eq!(
        anonymous(&server, Method::GET, "/photos/public/none").await,
        404
    );
    assert_eq!(anonymous(&server, Method::GET, "/photos").await, 200);
    assert_eq!(anonymous(&server, Method::GET, "/photos?policy").await, 403);
    assert_eq!(
        anonymous(&server, Method::DELETE, "/photos?policy").await,
        403
    );
    assert_eq!(get(&root, "photos", "a.jpg").await, "ok");
}

#[tokio::test]
async fn restrict_public_buckets_closes_every_read_and_list() {
    let server = start().await;
    let root = setup(&server).await;
    root.delete_public_access_block()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    let everything = policy(&[statement(
        "Allow",
        r#""*""#,
        r#""s3:*""#,
        r#"["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]"#,
    )]);
    assert_eq!(put_policy(&root, &everything).await, "ok");
    let reads = [
        (Method::GET, "/photos/a.jpg"),
        (Method::HEAD, "/photos/a.jpg"),
        (Method::GET, "/photos/a.jpg?tagging"),
        (Method::GET, "/photos/a.jpg?attributes"),
        (Method::GET, "/photos"),
        (Method::HEAD, "/photos"),
        (Method::GET, "/photos?list-type=2"),
        (Method::GET, "/photos?versions"),
        (Method::GET, "/photos?uploads"),
        (Method::GET, "/photos?location"),
        (Method::GET, "/photos?versioning"),
        (Method::GET, "/photos?tagging"),
        (Method::GET, "/photos?cors"),
        (Method::GET, "/photos?encryption"),
        (Method::GET, "/photos?policyStatus"),
        (Method::GET, "/photos?publicAccessBlock"),
    ];
    for (method, path) in &reads {
        let status = anonymous(&server, method.clone(), path).await;
        assert_ne!(status, 403, "{method} {path} while public");
    }
    put_block(&root, true).await;
    for (method, path) in &reads {
        let status = anonymous(&server, method.clone(), path).await;
        assert_eq!(status, 403, "{method} {path} while restricted");
    }
    assert_eq!(
        anonymous(&server, Method::PUT, "/photos/new.jpg").await,
        403
    );
    // The account's own users still get what the policy gives them.
    let alice = user(&server, "alice", None);
    assert_eq!(get(&alice, "photos", "a.jpg").await, "ok");
    // Off again, the policy is public again.
    put_block(&root, false).await;
    assert_eq!(
        anonymous(&server, Method::GET, "/photos?versions").await,
        200
    );
}

#[tokio::test]
async fn a_policy_deny_binds_everyone_but_the_root_keeps_the_policy() {
    let server = start().await;
    let root = setup(&server).await;
    let admin = user(
        &server,
        "admin",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
        ),
    );
    let no_deletes = policy(&[statement(
        "Deny",
        r#""*""#,
        r#""s3:DeleteObject""#,
        r#""arn:aws:s3:::photos/*""#,
    )]);
    assert_eq!(put_policy(&root, &no_deletes).await, "ok");
    for s3 in [&root, &admin] {
        let deleted = s3
            .delete_object()
            .bucket("photos")
            .key("a.jpg")
            .send()
            .await;
        assert_eq!(code(deleted), "AccessDenied");
        assert_eq!(get(s3, "photos", "a.jpg").await, "ok");
    }
    // A policy that shuts everyone out still lets the root user read, replace and delete it.
    let lockout = policy(&[statement(
        "Deny",
        r#""*""#,
        r#""s3:*""#,
        r#"["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]"#,
    )]);
    assert_eq!(put_policy(&root, &lockout).await, "ok");
    assert_eq!(get(&root, "photos", "a.jpg").await, "AccessDenied");
    assert_eq!(get(&admin, "photos", "a.jpg").await, "AccessDenied");
    assert_eq!(
        code(admin.get_bucket_policy().bucket("photos").send().await),
        "AccessDenied"
    );
    assert_eq!(put_policy(&admin, &no_deletes).await, "AccessDenied");
    assert_eq!(
        code(root.get_bucket_policy().bucket("photos").send().await),
        "ok"
    );
    assert_eq!(put_policy(&root, &no_deletes).await, "ok");
    assert_eq!(get(&root, "photos", "a.jpg").await, "ok");

    // A copy reads its source under the source bucket's policy.
    root.create_bucket().bucket("other").send().await.unwrap();
    let no_reads = policy(&[statement(
        "Deny",
        r#""*""#,
        r#""s3:GetObject""#,
        r#""arn:aws:s3:::photos/*""#,
    )]);
    assert_eq!(put_policy(&root, &no_reads).await, "ok");
    let copied = admin
        .copy_object()
        .bucket("other")
        .key("copy.jpg")
        .copy_source("photos/a.jpg")
        .send()
        .await;
    assert_eq!(code(copied), "AccessDenied");
    root.delete_bucket_policy()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    let copied = admin
        .copy_object()
        .bucket("other")
        .key("copy.jpg")
        .copy_source("photos/a.jpg")
        .send()
        .await;
    assert_eq!(code(copied), "ok");
}

#[tokio::test]
async fn a_policy_grants_users_it_names() {
    let server = start().await;
    let root = setup(&server).await;
    let bob = user(&server, "bob", None);
    let carol = user(&server, "carol", None);
    assert_eq!(get(&bob, "photos", "a.jpg").await, "AccessDenied");
    let arn = server.iam.user("bob").unwrap().arn;
    let account = server.iam.account();
    let grants = policy(&[
        statement(
            "Allow",
            &format!(r#"{{"AWS":"{arn}"}}"#),
            r#""s3:GetObject""#,
            r#""arn:aws:s3:::photos/*""#,
        ),
        // Naming the account grants nothing by itself: its users need their own policy.
        statement(
            "Allow",
            &format!(r#"{{"AWS":"{account}"}}"#),
            r#""s3:PutObject""#,
            r#""arn:aws:s3:::photos/*""#,
        ),
    ]);
    assert_eq!(put_policy(&root, &grants).await, "ok");
    assert_eq!(get(&bob, "photos", "a.jpg").await, "ok");
    assert_eq!(get(&carol, "photos", "a.jpg").await, "AccessDenied");
    assert_eq!(put(&bob, "photos", "b.jpg").await, "AccessDenied");
    // DeleteObjects decides each key with the bucket's policy too.
    let deleted = bob
        .delete_objects()
        .bucket("photos")
        .delete(
            aws_sdk_s3::types::Delete::builder()
                .objects(
                    aws_sdk_s3::types::ObjectIdentifier::builder()
                        .key("a.jpg")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.errors()[0].code(), Some("AccessDenied"));
}
