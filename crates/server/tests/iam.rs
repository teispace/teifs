//! IAM users over the S3 API: requests signed with a user's key do what the user's
//! policies allow and nothing else, as AWS decides them.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier},
};
use teifs_iam::Owner;

mod common;

use common::{SECRET_KEY, Server, client, client_as, start};

/// A user with one inline policy, and a client signing as them.
fn user(server: &Server, name: &str, policy: &str) -> Client {
    server.iam.create_user(name, None, &[], None).unwrap();
    if !policy.is_empty() {
        server
            .iam
            .put_inline(Owner::User(name), "policy", policy)
            .unwrap();
    }
    let key = server.iam.create_access_key(name).unwrap();
    client_as(server, &key.info.id, &key.secret)
}

fn allow(actions: &str, resources: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":{resources}}}]}}"#
    )
}

async fn put(s3: &Client, bucket: &str, key: &str) -> Result<(), String> {
    s3.put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(b"data"))
        .send()
        .await
        .map(|_| ())
        .map_err(|e| e.code().unwrap_or("?").to_owned())
}

async fn get(s3: &Client, bucket: &str, key: &str) -> Result<(), String> {
    s3.get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| e.code().unwrap_or("?").to_owned())
}

async fn setup(server: &Server) -> Client {
    let root = client(server, SECRET_KEY);
    for bucket in ["photos", "home"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    put(&root, "photos", "a.jpg").await.unwrap();
    root
}

#[tokio::test]
async fn users_get_only_what_their_policies_allow() {
    let server = start().await;
    let root = setup(&server).await;
    let nobody = user(&server, "nobody", "");
    let err = nobody.list_buckets().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert_eq!(
        get(&nobody, "photos", "a.jpg").await.unwrap_err(),
        "AccessDenied"
    );

    let reader = user(
        &server,
        "reader",
        &allow(
            r#"["s3:GetObject","s3:ListBucket"]"#,
            r#"["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]"#,
        ),
    );
    get(&reader, "photos", "a.jpg").await.unwrap();
    let listed = reader
        .list_objects_v2()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.contents().len(), 1);
    assert_eq!(
        put(&reader, "photos", "b.jpg").await.unwrap_err(),
        "AccessDenied"
    );
    let err = reader
        .delete_object()
        .bucket("photos")
        .key("a.jpg")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert_eq!(get(&reader, "home", "x").await.unwrap_err(), "AccessDenied");
    let err = reader.list_buckets().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // A change applies to the next request.
    server
        .iam
        .put_inline(
            Owner::User("reader"),
            "list",
            &allow(r#""s3:ListAllMyBuckets""#, r#""*""#),
        )
        .unwrap();
    assert_eq!(
        reader.list_buckets().send().await.unwrap().buckets().len(),
        2
    );
    // The root user is never restricted.
    put(&root, "home", "r").await.unwrap();
}

#[tokio::test]
async fn policy_variables_give_each_user_a_home() {
    let server = start().await;
    setup(&server).await;
    let policy = allow(r#""s3:*""#, r#""arn:aws:s3:::home/${aws:username}/*""#);
    let alice = user(&server, "alice", &policy);
    let bob = user(&server, "bob", &policy);
    put(&alice, "home", "alice/notes.txt").await.unwrap();
    put(&bob, "home", "bob/notes.txt").await.unwrap();
    assert_eq!(
        put(&alice, "home", "bob/evil.txt").await.unwrap_err(),
        "AccessDenied"
    );
    assert_eq!(
        get(&bob, "home", "alice/notes.txt").await.unwrap_err(),
        "AccessDenied"
    );
}

#[tokio::test]
async fn missing_keys_are_hidden_from_those_who_cant_list() {
    let server = start().await;
    setup(&server).await;
    let get_only = user(
        &server,
        "g",
        &allow(r#""s3:GetObject""#, r#""arn:aws:s3:::photos/*""#),
    );
    assert_eq!(
        get(&get_only, "photos", "missing").await.unwrap_err(),
        "AccessDenied"
    );
    let err = get_only
        .head_object()
        .bucket("photos")
        .key("missing")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 403);
    let lister = user(
        &server,
        "l",
        &allow(
            r#"["s3:GetObject","s3:ListBucket"]"#,
            r#"["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]"#,
        ),
    );
    assert_eq!(
        get(&lister, "photos", "missing").await.unwrap_err(),
        "NoSuchKey"
    );
}

#[tokio::test]
async fn multi_object_deletes_decide_each_key() {
    let server = start().await;
    let root = setup(&server).await;
    for key in ["tmp/1", "keep/2"] {
        put(&root, "photos", key).await.unwrap();
    }
    let cleaner = user(
        &server,
        "c",
        &allow(r#""s3:DeleteObject""#, r#""arn:aws:s3:::photos/tmp/*""#),
    );
    let ids = ["tmp/1", "keep/2"].map(|k| ObjectIdentifier::builder().key(k).build().unwrap());
    let out = cleaner
        .delete_objects()
        .bucket("photos")
        .delete(
            Delete::builder()
                .set_objects(Some(ids.to_vec()))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(out.deleted().len(), 1);
    assert_eq!(out.deleted()[0].key(), Some("tmp/1"));
    assert_eq!(out.errors().len(), 1);
    assert_eq!(out.errors()[0].key(), Some("keep/2"));
    assert_eq!(out.errors()[0].code(), Some("AccessDenied"));
    get(&root, "photos", "keep/2").await.unwrap();
}

#[tokio::test]
async fn copies_and_renames_need_the_source_too() {
    let server = start().await;
    let root = setup(&server).await;
    put(&root, "photos", "secret/x").await.unwrap();
    let writer = user(
        &server,
        "w",
        &allow(r#""s3:PutObject""#, r#""arn:aws:s3:::home/*""#),
    );
    let err = writer
        .copy_object()
        .bucket("home")
        .key("stolen")
        .copy_source("photos/secret/x")
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Some("AccessDenied"),
        "writing the copy isn't enough"
    );
    // A source TeiFS can't name (an access point) is refused, not skipped.
    let err = writer
        .copy_object()
        .bucket("home")
        .key("stolen")
        .copy_source("arn:aws:s3:us-east-1:123456789012:accesspoint/ap/object/secret/x")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    server
        .iam
        .put_inline(
            Owner::User("w"),
            "read",
            &allow(r#""s3:GetObject""#, r#""arn:aws:s3:::photos/secret/*""#),
        )
        .unwrap();
    writer
        .copy_object()
        .bucket("home")
        .key("copied")
        .copy_source("photos/secret/x")
        .send()
        .await
        .unwrap();

    // A rename reads and deletes its source and writes its target.
    put(&root, "home", "old").await.unwrap();
    let rename = |s3: &Client| {
        s3.rename_object()
            .bucket("home")
            .key("new")
            .rename_source("home/old")
            .send()
    };
    assert_eq!(
        rename(&writer).await.unwrap_err().code(),
        Some("AccessDenied")
    );
    server
        .iam
        .put_inline(
            Owner::User("w"),
            "move",
            &allow(
                r#"["s3:GetObject","s3:DeleteObject"]"#,
                r#""arn:aws:s3:::home/old""#,
            ),
        )
        .unwrap();
    rename(&writer).await.unwrap();
    get(&root, "home", "new").await.unwrap();
}

#[tokio::test]
async fn conditions_see_the_connection_and_the_request() {
    let server = start().await;
    setup(&server).await;
    // The tests connect from 127.0.0.1 over plain HTTP.
    let from_elsewhere = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",
      "Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}"#;
    let local = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",
      "Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}}]}"#;
    let tls_only = r#"{"Version":"2012-10-17","Statement":[
      {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
      {"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}"#;
    assert_eq!(
        get(&user(&server, "far", from_elsewhere), "photos", "a.jpg")
            .await
            .unwrap_err(),
        "AccessDenied"
    );
    get(&user(&server, "near", local), "photos", "a.jpg")
        .await
        .unwrap();
    assert_eq!(
        get(&user(&server, "tls", tls_only), "photos", "a.jpg")
            .await
            .unwrap_err(),
        "AccessDenied"
    );

    // Request keys: only a public-read-free upload with a tag of its own.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectTagging"],
      "Resource":"*","Condition":{"StringEquals":{"s3:RequestObjectTag/team":"${aws:PrincipalTag/team}"}}}]}"#;
    server
        .iam
        .create_user("tagger", None, &[("team".into(), "blue".into())], None)
        .unwrap();
    server
        .iam
        .put_inline(Owner::User("tagger"), "p", policy)
        .unwrap();
    let key = server.iam.create_access_key("tagger").unwrap();
    let tagger = client_as(&server, &key.info.id, &key.secret);
    let put_tagged = |tag: &'static str| {
        tagger
            .put_object()
            .bucket("home")
            .key("t")
            .tagging(tag)
            .body(ByteStream::from_static(b"x"))
            .send()
    };
    put_tagged("team=blue").await.unwrap();
    assert_eq!(
        put_tagged("team=red").await.unwrap_err().code(),
        Some("AccessDenied")
    );
    assert_eq!(
        put(&tagger, "home", "untagged").await.unwrap_err(),
        "AccessDenied"
    );
}

#[tokio::test]
async fn optional_details_need_their_own_permission() {
    let server = start().await;
    let root = setup(&server).await;
    root.put_object()
        .bucket("photos")
        .key("t.jpg")
        .tagging("a=1&b=2")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    let read = allow(
        r#"["s3:GetObject","s3:ListBucket"]"#,
        r#"["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]"#,
    );
    let plain = user(&server, "plain", &read);
    let got = plain
        .get_object()
        .bucket("photos")
        .key("t.jpg")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.tag_count(),
        None,
        "no tag count without s3:GetObjectTagging"
    );
    let listed = plain
        .list_objects_v2()
        .bucket("photos")
        .fetch_owner(true)
        .send()
        .await
        .unwrap();
    assert!(
        listed.contents()[0].owner().is_none(),
        "no owners without s3:GetObjectAcl"
    );

    let more = user(&server, "more", &read);
    server
        .iam
        .put_inline(
            Owner::User("more"),
            "extra",
            &allow(
                r#"["s3:GetObjectTagging","s3:GetObjectAcl"]"#,
                r#""arn:aws:s3:::photos/*""#,
            ),
        )
        .unwrap();
    let got = more
        .get_object()
        .bucket("photos")
        .key("t.jpg")
        .send()
        .await
        .unwrap();
    assert_eq!(got.tag_count(), Some(2));
    let listed = more
        .list_objects_v2()
        .bucket("photos")
        .fetch_owner(true)
        .send()
        .await
        .unwrap();
    assert!(listed.contents()[0].owner().is_some());
}

#[tokio::test]
async fn uploads_belong_to_the_user_who_started_them() {
    let server = start().await;
    let root = setup(&server).await;
    let policy = allow(
        r#""s3:*""#,
        r#"["arn:aws:s3:::home","arn:aws:s3:::home/*"]"#,
    );
    let alice = user(&server, "alice", &policy);
    let mallory = user(&server, "mallory", &policy);
    let upload = alice
        .create_multipart_upload()
        .bucket("home")
        .key("big")
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let part = |s3: &Client| {
        s3.upload_part()
            .bucket("home")
            .key("big")
            .upload_id(id)
            .part_number(1)
            .body(ByteStream::from_static(b"part"))
            .send()
    };
    assert_eq!(
        part(&mallory).await.unwrap_err().code(),
        Some("AccessDenied")
    );
    // Alice's second key is still Alice.
    let second = server.iam.create_access_key("alice").unwrap();
    let alice_again = client_as(&server, &second.info.id, &second.secret);
    let etag = part(&alice_again)
        .await
        .unwrap()
        .e_tag()
        .unwrap()
        .to_owned();
    // The root user may finish anyone's upload.
    root.complete_multipart_upload()
        .bucket("home")
        .key("big")
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(CompletedPart::builder().part_number(1).e_tag(etag).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    get(&alice, "home", "big").await.unwrap();
}

#[tokio::test]
async fn keys_stop_working_when_deactivated_or_deleted() {
    let server = start().await;
    setup(&server).await;
    server.iam.create_user("k", None, &[], None).unwrap();
    server
        .iam
        .put_inline(
            Owner::User("k"),
            "p",
            &allow(r#""s3:ListAllMyBuckets""#, r#""*""#),
        )
        .unwrap();
    let key = server.iam.create_access_key("k").unwrap();
    let s3 = client_as(&server, &key.info.id, &key.secret);
    s3.list_buckets().send().await.unwrap();
    server
        .iam
        .update_access_key("k", &key.info.id, false)
        .unwrap();
    assert_eq!(
        s3.list_buckets().send().await.unwrap_err().code(),
        Some("InvalidAccessKeyId")
    );
    server
        .iam
        .update_access_key("k", &key.info.id, true)
        .unwrap();
    s3.list_buckets().send().await.unwrap();
    server.iam.delete_access_key("k", &key.info.id).unwrap();
    assert_eq!(
        s3.list_buckets().send().await.unwrap_err().code(),
        Some("InvalidAccessKeyId")
    );
    let wrong = client_as(&server, "TKIAAAAAAAAAAAAAAAAA", "nope");
    assert_eq!(
        wrong.list_buckets().send().await.unwrap_err().code(),
        Some("InvalidAccessKeyId")
    );
}

#[tokio::test]
async fn groups_and_boundaries_apply() {
    let server = start().await;
    setup(&server).await;
    let s3 = user(&server, "member", "");
    server.iam.create_group("readers", None).unwrap();
    server.iam.add_user_to_group("readers", "member").unwrap();
    let read = server
        .iam
        .create_policy(
            "read",
            None,
            None,
            &allow(r#""s3:GetObject""#, r#""arn:aws:s3:::photos/*""#),
        )
        .unwrap();
    assert_eq!(
        get(&s3, "photos", "a.jpg").await.unwrap_err(),
        "AccessDenied"
    );
    server
        .iam
        .attach(Owner::Group("readers"), &read.arn)
        .unwrap();
    get(&s3, "photos", "a.jpg").await.unwrap();

    server
        .iam
        .put_inline(Owner::User("member"), "all", &allow(r#""s3:*""#, r#""*""#))
        .unwrap();
    put(&s3, "home", "x").await.unwrap();
    server
        .iam
        .set_user_boundary("member", Some(&read.arn))
        .unwrap();
    assert_eq!(put(&s3, "home", "y").await.unwrap_err(), "AccessDenied");
    get(&s3, "photos", "a.jpg").await.unwrap();
}
