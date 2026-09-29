//! Class 2, continued: a bucket's tags decide policies only while the bucket has
//! attribute-based access control (ABAC) on, as on AWS, and then change only with the
//! permission to tag it.

use aws_sdk_s3::{
    Client,
    primitives::ByteStream,
    types::{
        AbacStatus, BucketAbacStatus, BucketLocationConstraint, CreateBucketConfiguration, Tag,
        Tagging,
    },
};

use crate::common::{SECRET_KEY, client, code, start, user};

fn policy(statements: &str) -> String {
    format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#)
}

fn tag(key: &str, value: &str) -> Tag {
    Tag::builder().key(key).value(value).build().unwrap()
}

async fn tag_bucket(s3: &Client, bucket: &str, team: &str) -> String {
    let tagging = Tagging::builder()
        .tag_set(tag("team", team))
        .build()
        .unwrap();
    let put = s3.put_bucket_tagging().bucket(bucket).tagging(tagging);
    code(put.send().await)
}

async fn set_abac(s3: &Client, bucket: &str, status: BucketAbacStatus) -> String {
    let status = AbacStatus::builder().status(status).build();
    code(
        s3.put_bucket_abac()
            .bucket(bucket)
            .abac_status(status)
            .send()
            .await,
    )
}

async fn abac(s3: &Client, bucket: &str) -> BucketAbacStatus {
    let got = s3.get_bucket_abac().bucket(bucket).send().await.unwrap();
    got.abac_status().unwrap().status().unwrap().clone()
}

async fn get(s3: &Client, bucket: &str, key: &str) -> String {
    code(s3.get_object().bucket(bucket).key(key).send().await)
}

async fn create(s3: &Client, bucket: &str, configuration: CreateBucketConfiguration) -> String {
    let create = s3
        .create_bucket()
        .bucket(bucket)
        .create_bucket_configuration(configuration);
    code(create.send().await)
}

fn tagged(tags: &[(&str, &str)]) -> CreateBucketConfiguration {
    tags.iter()
        .fold(CreateBucketConfiguration::builder(), |c, (k, v)| {
            c.tags(tag(k, v))
        })
        .build()
}

/// With ABAC on, a bucket's tags stop changing through `PutBucketTagging` and
/// `DeleteBucketTagging`, which a policy on them could otherwise be undone with.
#[tokio::test]
async fn abac_takes_bucket_tags_out_of_bucket_tagging() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("team").send().await.unwrap();
    assert_eq!(abac(&root, "team").await, BucketAbacStatus::Disabled);
    assert_eq!(tag_bucket(&root, "team", "blue").await, "ok");

    assert_eq!(
        set_abac(&root, "team", BucketAbacStatus::Enabled).await,
        "ok"
    );
    assert_eq!(abac(&root, "team").await, BucketAbacStatus::Enabled);
    assert_eq!(tag_bucket(&root, "team", "red").await, "InvalidRequest");
    let delete = root.delete_bucket_tagging().bucket("team").send();
    assert_eq!(code(delete.await), "InvalidRequest");
    let tags = root.get_bucket_tagging().bucket("team").send().await;
    assert_eq!(tags.unwrap().tag_set(), [tag("team", "blue")]);

    assert_eq!(
        set_abac(&root, "team", BucketAbacStatus::Disabled).await,
        "ok"
    );
    assert_eq!(tag_bucket(&root, "team", "red").await, "ok");
    let missing = root.get_bucket_abac().bucket("missing").send();
    assert_eq!(code(missing.await), "NoSuchBucket");

    // Turning it on and off is its own permission.
    let reader = user(
        &server,
        "reader",
        Some(&policy(
            r#"{"Effect":"Allow","Action":["s3:GetBucketAbac","s3:PutBucketTagging"],"Resource":"*"}"#,
        )),
    );
    assert_eq!(abac(&reader, "team").await, BucketAbacStatus::Disabled);
    assert_eq!(
        set_abac(&reader, "team", BucketAbacStatus::Enabled).await,
        "AccessDenied"
    );
}

/// `aws:ResourceTag` and `s3:BucketTag` are the bucket's tags while ABAC is on, and
/// absent otherwise, in identity and bucket policies, for the bucket, its objects and a
/// copy's source.
#[tokio::test]
async fn a_buckets_tags_decide_policies_only_while_abac_is_on() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    for (bucket, team) in [("blue", "blue"), ("red", "red")] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
        assert_eq!(tag_bucket(&root, bucket, team).await, "ok");
        let put = root
            .put_object()
            .bucket(bucket)
            .key("plan.txt")
            .body(ByteStream::from_static(b"plan"));
        put.send().await.unwrap();
    }
    let blue_team = policy(
        r#"{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"blue"}}},
           {"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}"#,
    );
    let member = user(&server, "member", Some(&blue_team));
    let list = |bucket: &'static str| member.list_objects_v2().bucket(bucket).send();
    let copy = |from: &str| {
        member
            .copy_object()
            .bucket("red")
            .key("copied.txt")
            .copy_source(format!("{from}/plan.txt"))
            .send()
    };
    assert_eq!(get(&member, "blue", "plan.txt").await, "AccessDenied");
    assert_eq!(code(list("blue").await), "AccessDenied");
    assert_eq!(code(copy("blue").await), "AccessDenied");

    for bucket in ["blue", "red"] {
        assert_eq!(
            set_abac(&root, bucket, BucketAbacStatus::Enabled).await,
            "ok"
        );
    }
    assert_eq!(get(&member, "blue", "plan.txt").await, "ok");
    assert_eq!(code(list("blue").await), "ok");
    assert_eq!(code(copy("blue").await), "ok");
    assert_eq!(get(&member, "red", "plan.txt").await, "AccessDenied");
    assert_eq!(code(list("red").await), "AccessDenied");
    assert_eq!(code(copy("red").await), "AccessDenied");

    // A bucket policy's Deny on `s3:BucketTag` binds everyone, the root user too.
    let frozen = policy(
        r#"{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::blue/*","Condition":{"StringEquals":{"s3:BucketTag/team":"blue"}}}"#,
    );
    let put = root.put_bucket_policy().bucket("blue").policy(frozen);
    put.send().await.unwrap();
    assert_eq!(get(&root, "blue", "plan.txt").await, "AccessDenied");
    assert_eq!(get(&member, "blue", "plan.txt").await, "AccessDenied");
    assert_eq!(
        set_abac(&root, "blue", BucketAbacStatus::Disabled).await,
        "ok"
    );
    assert_eq!(get(&root, "blue", "plan.txt").await, "ok");
    assert_eq!(get(&member, "blue", "plan.txt").await, "AccessDenied");
}

/// Tags given to `CreateBucket` need `s3:TagResource`, which policies decide on the tags
/// asked for (`aws:RequestTag`, `aws:TagKeys`) and the location
/// (`s3:locationconstraint`).
#[tokio::test]
async fn tags_at_create_bucket_need_permission_to_tag() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    let only_create = user(
        &server,
        "creator",
        Some(&policy(
            r#"{"Effect":"Allow","Action":"s3:CreateBucket","Resource":"*"}"#,
        )),
    );
    let blue = || tagged(&[("team", "blue")]);
    assert_eq!(create(&only_create, "plain", tagged(&[])).await, "ok");
    assert_eq!(create(&only_create, "tagged", blue()).await, "AccessDenied");
    let head = root.head_bucket().bucket("tagged").send();
    assert_eq!(code(head.await), "NotFound");

    let blue_only = policy(
        r#"{"Effect":"Allow","Action":"s3:CreateBucket","Resource":"*","Condition":{"StringEquals":{"s3:locationconstraint":"us-east-1"}}},
           {"Effect":"Allow","Action":"s3:TagResource","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/team":"blue"},"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}}"#,
    );
    let tagger = user(&server, "tagger", Some(&blue_only));
    let here = |c: CreateBucketConfiguration| {
        let mut c = c;
        c.location_constraint = Some(BucketLocationConstraint::from("us-east-1"));
        c
    };
    assert_eq!(
        create(&tagger, "nowhere", tagged(&[])).await,
        "AccessDenied"
    );
    assert_eq!(create(&tagger, "blue", here(blue())).await, "ok");
    let tags = root.get_bucket_tagging().bucket("blue").send().await;
    assert_eq!(tags.unwrap().tag_set(), [tag("team", "blue")]);
    let red = here(tagged(&[("team", "red")]));
    assert_eq!(create(&tagger, "red", red).await, "AccessDenied");
    let extra = here(tagged(&[("team", "blue"), ("cost", "high")]));
    assert_eq!(create(&tagger, "extra", extra).await, "AccessDenied");

    // A location this drive isn't in is refused as AWS refuses another region's.
    let elsewhere = CreateBucketConfiguration::builder()
        .location_constraint(BucketLocationConstraint::EuWest1)
        .build();
    assert_eq!(
        create(&root, "elsewhere", elsewhere).await,
        "IllegalLocationConstraintException"
    );
    let too_many = (0..51).map(|i| (format!("k{i}"), "v".to_owned()));
    let too_many: Vec<_> = too_many.collect();
    let too_many: Vec<_> = too_many
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        create(&root, "crowded", tagged(&too_many)).await,
        "InvalidTag"
    );
}
