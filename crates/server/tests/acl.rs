//! Object Ownership and ACLs over the S3 API, as AWS has them: disabled on new buckets,
//! and where a bucket enables them, grants to everyone (or to every signed request) that
//! open what they name, under Block Public Access and the policies' denies.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    primitives::ByteStream,
    types::{
        AccessControlPolicy, BucketCannedAcl, Grant, Grantee, ObjectCannedAcl, ObjectOwnership,
        OwnershipControls, OwnershipControlsRule, Permission, PublicAccessBlockConfiguration, Type,
    },
};
use reqwest::Method;
use teifs_store::Layout;

mod common;

use common::{SECRET_KEY, Server, anonymous, client, code, start, start_with, user};

const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

async fn servers() -> [Server; 2] {
    [
        start().await,
        start_with(|config| config.default_layout = Layout::Object).await,
    ]
}

/// A bucket with ACLs enabled (`ObjectWriter`) and Block Public Access off.
async fn open_bucket(root: &Client, bucket: &str) {
    root.create_bucket()
        .bucket(bucket)
        .object_ownership(ObjectOwnership::ObjectWriter)
        .send()
        .await
        .unwrap();
    root.delete_public_access_block()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
}

async fn put_with(root: &Client, bucket: &str, key: &str, acl: Option<ObjectCannedAcl>) -> String {
    code(
        root.put_object()
            .bucket(bucket)
            .key(key)
            .set_acl(acl)
            .body(ByteStream::from_static(b"data"))
            .send()
            .await,
    )
}

async fn set_ownership(root: &Client, bucket: &str, ownership: ObjectOwnership) -> String {
    let controls = OwnershipControls::builder()
        .rules(
            OwnershipControlsRule::builder()
                .object_ownership(ownership)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    code(
        root.put_bucket_ownership_controls()
            .bucket(bucket)
            .ownership_controls(controls)
            .send()
            .await,
    )
}

async fn set_bucket_acl(root: &Client, bucket: &str, acl: BucketCannedAcl) -> String {
    code(root.put_bucket_acl().bucket(bucket).acl(acl).send().await)
}

/// The grants of an ACL as (grantee id or group URI, permission).
fn grants(grants: &[Grant]) -> Vec<(String, String)> {
    grants
        .iter()
        .map(|g| {
            let grantee = g.grantee().unwrap();
            let who = grantee.id().or(grantee.uri()).unwrap().to_owned();
            (who, g.permission().unwrap().as_str().to_owned())
        })
        .collect()
}

fn owner_full_control() -> Vec<(String, String)> {
    vec![("teifs".into(), "FULL_CONTROL".into())]
}

#[tokio::test]
async fn new_buckets_disable_acls_as_aws_does() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("bkt").send().await.unwrap();
    let controls = root
        .get_bucket_ownership_controls()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    let rules = controls.ownership_controls().unwrap().rules();
    assert_eq!(rules[0].object_ownership().as_str(), "BucketOwnerEnforced");
    let acl = root.get_bucket_acl().bucket("bkt").send().await.unwrap();
    assert_eq!(grants(acl.grants()), owner_full_control());
    assert_eq!(acl.owner().unwrap().id(), Some("teifs"));

    // Only no ACL, or the bucket owner's full control, is accepted.
    assert_eq!(put_with(&root, "bkt", "k", None).await, "ok");
    let owner = Some(ObjectCannedAcl::BucketOwnerFullControl);
    assert_eq!(put_with(&root, "bkt", "k", owner).await, "ok");
    for refused in [ObjectCannedAcl::Private, ObjectCannedAcl::PublicRead] {
        assert_eq!(
            put_with(&root, "bkt", "k", Some(refused)).await,
            "AccessControlListNotSupported"
        );
    }
    let upload = root
        .create_multipart_upload()
        .bucket("bkt")
        .key("m")
        .acl(ObjectCannedAcl::PublicRead)
        .send()
        .await;
    assert_eq!(code(upload), "AccessControlListNotSupported");
    let copy = root
        .copy_object()
        .bucket("bkt")
        .key("c")
        .copy_source("bkt/k")
        .acl(ObjectCannedAcl::Private)
        .send()
        .await;
    assert_eq!(code(copy), "AccessControlListNotSupported");
    assert_eq!(
        set_bucket_acl(&root, "bkt", BucketCannedAcl::Private).await,
        "AccessControlListNotSupported"
    );
    let put_acl = root
        .put_object_acl()
        .bucket("bkt")
        .key("k")
        .acl(ObjectCannedAcl::Private)
        .send()
        .await;
    assert_eq!(code(put_acl), "AccessControlListNotSupported");
    let acl = root.get_object_acl().bucket("bkt").key("k").send().await;
    assert_eq!(grants(acl.unwrap().grants()), owner_full_control());
    // A missing bucket is reported as missing, not as refusing ACLs.
    let missing = root
        .create_multipart_upload()
        .bucket("missing")
        .key("m")
        .acl(ObjectCannedAcl::Private)
        .send()
        .await;
    assert_eq!(code(missing), "NoSuchBucket");
}

#[tokio::test]
async fn ownership_controls_round_trip() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("bkt").send().await.unwrap();
    for ownership in [
        ObjectOwnership::ObjectWriter,
        ObjectOwnership::BucketOwnerPreferred,
        ObjectOwnership::BucketOwnerEnforced,
    ] {
        assert_eq!(set_ownership(&root, "bkt", ownership.clone()).await, "ok");
        let got = root
            .get_bucket_ownership_controls()
            .bucket("bkt")
            .send()
            .await
            .unwrap();
        let rules = got.ownership_controls().unwrap().rules();
        assert_eq!(rules[0].object_ownership(), &ownership);
    }
    root.delete_bucket_ownership_controls()
        .bucket("bkt")
        .send()
        .await
        .unwrap();
    let gone = root
        .get_bucket_ownership_controls()
        .bucket("bkt")
        .send()
        .await;
    assert_eq!(code(gone), "OwnershipControlsNotFoundError");
    // Without a setting, ACLs are enabled, as on buckets made before AWS had one.
    assert_eq!(
        set_bucket_acl(&root, "bkt", BucketCannedAcl::Private).await,
        "ok"
    );
    assert_eq!(
        set_ownership(&root, "bkt", ObjectOwnership::from("Everyone")).await,
        "MalformedXML"
    );
    assert_eq!(
        set_ownership(&root, "missing", ObjectOwnership::ObjectWriter).await,
        "NoSuchBucket"
    );
}

#[tokio::test]
async fn create_bucket_checks_its_acl_against_ownership() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    let create = |name: &'static str, ownership: Option<ObjectOwnership>, acl| {
        root.create_bucket()
            .bucket(name)
            .set_object_ownership(ownership)
            .set_acl(acl)
            .send()
    };
    let public = Some(BucketCannedAcl::PublicRead);
    let writer = Some(ObjectOwnership::ObjectWriter);
    assert_eq!(
        code(create("aaa", None, public.clone()).await),
        "InvalidBucketAclWithObjectOwnership"
    );
    assert_eq!(
        code(create("aaa", writer.clone(), public).await),
        "InvalidBucketAclWithBlockPublicAccessError"
    );
    let granted = root
        .create_bucket()
        .bucket("aaa")
        .object_ownership(ObjectOwnership::ObjectWriter)
        .grant_read(format!("uri={ALL_USERS}"))
        .send()
        .await;
    assert_eq!(code(granted), "InvalidBucketAclWithBlockPublicAccessError");
    // The owner alone is fine either way.
    let owner = root
        .create_bucket()
        .bucket("aaa")
        .grant_full_control("id=teifs")
        .send()
        .await;
    assert_eq!(code(owner), "ok");
    let private = Some(BucketCannedAcl::Private);
    assert_eq!(code(create("bbb", writer, private).await), "ok");
    let acl = root.get_bucket_acl().bucket("bbb").send().await.unwrap();
    assert_eq!(grants(acl.grants()), owner_full_control());
    let unknown = create("ccc", Some(ObjectOwnership::from("Nobody")), None).await;
    assert_eq!(code(unknown), "InvalidArgument");
}

#[tokio::test]
async fn public_acls_open_what_they_grant() {
    for server in servers().await {
        let root = client(&server, SECRET_KEY);
        open_bucket(&root, "photos").await;
        let public = Some(ObjectCannedAcl::PublicRead);
        assert_eq!(put_with(&root, "photos", "public.jpg", public).await, "ok");
        assert_eq!(put_with(&root, "photos", "private.jpg", None).await, "ok");
        assert_eq!(
            anonymous(&server, Method::GET, "/photos/public.jpg").await,
            200
        );
        assert_eq!(
            anonymous(&server, Method::HEAD, "/photos/public.jpg").await,
            200
        );
        assert_eq!(
            anonymous(&server, Method::GET, "/photos/private.jpg").await,
            403
        );
        // An object's READ doesn't let anyone list the bucket or read its ACL.
        assert_eq!(anonymous(&server, Method::GET, "/photos").await, 403);
        assert_eq!(
            anonymous(&server, Method::GET, "/photos/public.jpg?acl").await,
            403
        );
        assert_eq!(
            anonymous(&server, Method::PUT, "/photos/new.jpg").await,
            403
        );

        // The bucket's READ lists it, and its WRITE writes and deletes in it; neither
        // reads an object.
        let public_rw = BucketCannedAcl::PublicReadWrite;
        assert_eq!(set_bucket_acl(&root, "photos", public_rw).await, "ok");
        assert_eq!(anonymous(&server, Method::GET, "/photos").await, 200);
        assert_eq!(
            anonymous(&server, Method::PUT, "/photos/new.jpg").await,
            200
        );
        assert_eq!(
            anonymous(&server, Method::DELETE, "/photos/new.jpg").await,
            204
        );
        assert_eq!(
            anonymous(&server, Method::GET, "/photos/private.jpg").await,
            403
        );
        assert_eq!(anonymous(&server, Method::GET, "/photos?acl").await, 403);
        // Making an object sets its ACL and tags with it, which the bucket's WRITE allows
        // as it allows the object; changing an existing object's ACL it doesn't.
        let put = |path: &'static str| {
            reqwest::Client::new()
                .put(format!("{}{path}", server.endpoint))
                .header("x-amz-acl", "public-read")
                .header("x-amz-tagging", "team=web")
                .body("shared")
                .send()
        };
        assert_eq!(put("/photos/shared.jpg").await.unwrap().status(), 200);
        assert_eq!(
            anonymous(&server, Method::GET, "/photos/shared.jpg").await,
            200
        );
        let tags = root
            .get_object_tagging()
            .bucket("photos")
            .key("shared.jpg")
            .send()
            .await
            .unwrap();
        assert_eq!(tags.tag_set()[0].value(), "web");
        assert_eq!(put("/photos/private.jpg?acl").await.unwrap().status(), 403);

        // A copy doesn't take its source's ACL.
        root.copy_object()
            .bucket("photos")
            .key("copy.jpg")
            .copy_source("photos/public.jpg")
            .send()
            .await
            .unwrap();
        assert_eq!(
            anonymous(&server, Method::GET, "/photos/copy.jpg").await,
            403
        );
        let acl = root
            .get_object_acl()
            .bucket("photos")
            .key("copy.jpg")
            .send();
        assert_eq!(grants(acl.await.unwrap().grants()), owner_full_control());
        // An object replaced gets the new request's ACL.
        assert_eq!(put_with(&root, "photos", "public.jpg", None).await, "ok");
        assert_eq!(
            anonymous(&server, Method::GET, "/photos/public.jpg").await,
            403
        );
    }
}

#[tokio::test]
async fn ignore_public_acls_and_ownership_turn_acls_off_and_back_on() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    open_bucket(&root, "photos").await;
    let public = Some(ObjectCannedAcl::PublicRead);
    assert_eq!(put_with(&root, "photos", "a.jpg", public).await, "ok");
    let ignore = |on: bool| {
        root.put_public_access_block()
            .bucket("photos")
            .public_access_block_configuration(
                PublicAccessBlockConfiguration::builder()
                    .ignore_public_acls(on)
                    .build(),
            )
            .send()
    };
    ignore(true).await.unwrap();
    assert_eq!(anonymous(&server, Method::GET, "/photos/a.jpg").await, 403);
    ignore(false).await.unwrap();
    assert_eq!(anonymous(&server, Method::GET, "/photos/a.jpg").await, 200);

    // ACLs can't be disabled while the bucket's own ACL grants others.
    let public_bucket = BucketCannedAcl::PublicRead;
    assert_eq!(set_bucket_acl(&root, "photos", public_bucket).await, "ok");
    let enforced = ObjectOwnership::BucketOwnerEnforced;
    assert_eq!(
        set_ownership(&root, "photos", enforced.clone()).await,
        "InvalidBucketAclWithObjectOwnership"
    );
    assert_eq!(anonymous(&server, Method::GET, "/photos").await, 200);
    let private = BucketCannedAcl::Private;
    assert_eq!(set_bucket_acl(&root, "photos", private).await, "ok");
    assert_eq!(set_ownership(&root, "photos", enforced).await, "ok");
    assert_eq!(anonymous(&server, Method::GET, "/photos/a.jpg").await, 403);
    let acl = root.get_object_acl().bucket("photos").key("a.jpg").send();
    assert_eq!(grants(acl.await.unwrap().grants()), owner_full_control());
    // Enabled again, the object's ACL is back.
    let preferred = ObjectOwnership::BucketOwnerPreferred;
    assert_eq!(set_ownership(&root, "photos", preferred).await, "ok");
    assert_eq!(anonymous(&server, Method::GET, "/photos/a.jpg").await, 200);
}

#[tokio::test]
async fn block_public_acls_refuses_public_acls() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    // ACLs on, Block Public Access left on, as a new bucket has it.
    root.create_bucket()
        .bucket("bkt")
        .object_ownership(ObjectOwnership::ObjectWriter)
        .send()
        .await
        .unwrap();
    let public = Some(ObjectCannedAcl::PublicRead);
    assert_eq!(put_with(&root, "bkt", "k", public).await, "AccessDenied");
    let private = Some(ObjectCannedAcl::Private);
    assert_eq!(put_with(&root, "bkt", "k", private).await, "ok");
    let put_acl = root
        .put_object_acl()
        .bucket("bkt")
        .key("k")
        .grant_read(format!("uri=\"{ALL_USERS}\""))
        .send()
        .await;
    assert_eq!(code(put_acl), "AccessDenied");
    let bucket = BucketCannedAcl::AuthenticatedRead;
    assert_eq!(set_bucket_acl(&root, "bkt", bucket).await, "AccessDenied");
    // The log delivery group isn't public.
    let logs = BucketCannedAcl::from("log-delivery-write");
    assert_eq!(set_bucket_acl(&root, "bkt", logs).await, "ok");
}

#[tokio::test]
async fn acls_bind_under_policies_and_boundaries() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    open_bucket(&root, "bkt").await;
    let signed = Some(ObjectCannedAcl::AuthenticatedRead);
    assert_eq!(put_with(&root, "bkt", "k", signed).await, "ok");
    // A grant to every signed request reaches a user with no policies of their own, and
    // no one unsigned.
    let member = user(&server, "member", None);
    let get = |s3: &Client| s3.get_object().bucket("bkt").key("k").send();
    assert_eq!(code(get(&member).await), "ok");
    assert_eq!(anonymous(&server, Method::GET, "/bkt/k").await, 403);
    let signed = BucketCannedAcl::AuthenticatedRead;
    assert_eq!(set_bucket_acl(&root, "bkt", signed).await, "ok");
    let list = member.list_objects_v2().bucket("bkt").send().await;
    assert_eq!(code(list), "ok");
    assert_eq!(anonymous(&server, Method::GET, "/bkt").await, 403);
    // A permissions boundary limits it...
    let boundary = server
        .iam
        .create_policy(
            "nothing",
            None,
            None,
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}"#,
            &[],
        )
        .unwrap();
    server
        .iam
        .set_user_boundary("member", Some(&boundary.arn))
        .unwrap();
    assert_eq!(code(get(&member).await), "AccessDenied");
    let list = member.list_objects_v2().bucket("bkt").send().await;
    assert_eq!(code(list), "AccessDenied");
    server.iam.set_user_boundary("member", None).unwrap();
    assert_eq!(code(get(&member).await), "ok");
    // ...and a policy's Deny overrides it.
    let deny = r#"{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/*"}}"#;
    root.put_bucket_policy()
        .bucket("bkt")
        .policy(deny)
        .send()
        .await
        .unwrap();
    assert_eq!(code(get(&member).await), "AccessDenied");
}

#[tokio::test]
async fn acl_bodies_and_headers_round_trip() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    open_bucket(&root, "bkt").await;
    assert_eq!(put_with(&root, "bkt", "k", None).await, "ok");
    let grant = |grantee: Grantee, permission: Permission| {
        Grant::builder()
            .grantee(grantee)
            .permission(permission)
            .build()
    };
    let owner = Grantee::builder()
        .r#type(Type::CanonicalUser)
        .id("teifs")
        .build()
        .unwrap();
    let everyone = Grantee::builder()
        .r#type(Type::Group)
        .uri(ALL_USERS)
        .build()
        .unwrap();
    let policy = |grants: Vec<Grant>| {
        AccessControlPolicy::builder()
            .owner(aws_sdk_s3::types::Owner::builder().id("teifs").build())
            .set_grants(Some(grants))
            .build()
    };
    let put = |policy: AccessControlPolicy| {
        root.put_object_acl()
            .bucket("bkt")
            .key("k")
            .access_control_policy(policy)
            .send()
    };
    let body = vec![
        grant(owner, Permission::FullControl),
        grant(everyone.clone(), Permission::Read),
    ];
    assert_eq!(code(put(policy(body)).await), "ok");
    let acl = root.get_object_acl().bucket("bkt").key("k").send();
    assert_eq!(
        grants(acl.await.unwrap().grants()),
        [
            ("teifs".to_owned(), "FULL_CONTROL".to_owned()),
            (ALL_USERS.to_owned(), "READ".to_owned())
        ]
    );
    assert_eq!(anonymous(&server, Method::GET, "/bkt/k").await, 200);

    let by_email = Grantee::builder()
        .r#type(Type::AmazonCustomerByEmail)
        .email_address("someone@example.com")
        .build()
        .unwrap();
    let email = put(policy(vec![grant(by_email, Permission::Read)])).await;
    assert_eq!(code(email), "UnresolvableGrantByEmailAddress");
    let stranger = Grantee::builder()
        .r#type(Type::CanonicalUser)
        .id("someone-else")
        .build()
        .unwrap();
    let stranger = put(policy(vec![grant(stranger, Permission::Read)])).await;
    assert_eq!(code(stranger), "InvalidArgument");
    let neither = root.put_object_acl().bucket("bkt").key("k").send().await;
    assert_eq!(code(neither), "MissingSecurityHeader");
    let both = root
        .put_object_acl()
        .bucket("bkt")
        .key("k")
        .acl(ObjectCannedAcl::Private)
        .grant_read("id=teifs")
        .send()
        .await;
    assert_eq!(code(both), "InvalidRequest");
    let missing = root
        .put_object_acl()
        .bucket("bkt")
        .key("missing")
        .acl(ObjectCannedAcl::Private)
        .send()
        .await;
    assert_eq!(code(missing), "NoSuchKey");
    // Grants of the ACL above survive a bucket ACL put by headers.
    let headers = root
        .put_bucket_acl()
        .bucket("bkt")
        .grant_full_control("id=\"teifs\"")
        .grant_read(format!("uri=\"{ALL_USERS}\""))
        .send()
        .await;
    assert_eq!(code(headers), "ok");
    assert_eq!(anonymous(&server, Method::GET, "/bkt").await, 200);
}

#[tokio::test]
async fn legacy_defaults_make_buckets_as_s3_did_before_2023() {
    let server = start_with(|config| config.legacy_bucket_defaults = true).await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket()
        .bucket("site")
        .acl(BucketCannedAcl::PublicRead)
        .send()
        .await
        .unwrap();
    let controls = root.get_bucket_ownership_controls().bucket("site").send();
    assert_eq!(code(controls.await), "OwnershipControlsNotFoundError");
    let block = root.get_public_access_block().bucket("site").send();
    assert_eq!(code(block.await), "NoSuchPublicAccessBlockConfiguration");
    let public = Some(ObjectCannedAcl::PublicRead);
    assert_eq!(put_with(&root, "site", "index.html", public).await, "ok");
    assert_eq!(
        anonymous(&server, Method::GET, "/site/index.html").await,
        200
    );
    assert_eq!(anonymous(&server, Method::GET, "/site").await, 200);
    // A bucket that asks for AWS's current setting gets it, Block Public Access aside.
    root.create_bucket()
        .bucket("private")
        .object_ownership(ObjectOwnership::BucketOwnerEnforced)
        .send()
        .await
        .unwrap();
    let public = Some(ObjectCannedAcl::PublicRead);
    let refused = put_with(&root, "private", "k", public).await;
    assert_eq!(refused, "AccessControlListNotSupported");
}

/// Each version has its own ACL, and a request naming a version is decided on that one.
#[tokio::test]
async fn each_version_has_its_own_acl() {
    let server = start_with(|config| config.default_layout = Layout::Object).await;
    let root = client(&server, SECRET_KEY);
    open_bucket(&root, "photos").await;
    let enabled = aws_sdk_s3::types::VersioningConfiguration::builder()
        .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
        .build();
    root.put_bucket_versioning()
        .bucket("photos")
        .versioning_configuration(enabled)
        .send()
        .await
        .unwrap();
    let put = |acl: Option<ObjectCannedAcl>| {
        root.put_object()
            .bucket("photos")
            .key("a.jpg")
            .set_acl(acl)
            .body(ByteStream::from_static(b"data"))
            .send()
    };
    let public = put(Some(ObjectCannedAcl::PublicRead)).await.unwrap();
    let public = public.version_id().unwrap().to_owned();
    let private = put(None).await.unwrap();
    let private = private.version_id().unwrap().to_owned();
    let get = |version: &str| format!("/photos/a.jpg?versionId={version}");
    assert_eq!(anonymous(&server, Method::GET, "/photos/a.jpg").await, 403);
    assert_eq!(anonymous(&server, Method::GET, &get(&public)).await, 200);
    assert_eq!(anonymous(&server, Method::GET, &get(&private)).await, 403);

    root.put_object_acl()
        .bucket("photos")
        .key("a.jpg")
        .version_id(&private)
        .acl(ObjectCannedAcl::PublicRead)
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous(&server, Method::GET, "/photos/a.jpg").await, 200);
    let acl = root
        .get_object_acl()
        .bucket("photos")
        .key("a.jpg")
        .version_id(&public)
        .send()
        .await
        .unwrap();
    assert!(acl.grants().len() > 1);
}
