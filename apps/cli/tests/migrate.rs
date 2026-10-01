//! `teifs migrate`, through the real binary between two TeiFS servers: every version
//! and delete marker in order, objects' attributes and ETags, buckets' settings, runs
//! that carry on, conflicts, `--latest`, prefixes and `--dry-run`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;
mod harness;

use aws_sdk_s3::{
    Client as S3,
    primitives::ByteStream,
    types::{
        BucketVersioningStatus, CompletedMultipartUpload, CompletedPart, DefaultRetention,
        ObjectLockConfiguration, ObjectLockEnabled, ObjectLockLegalHoldStatus,
        ObjectLockRetentionMode, ObjectLockRule, Tag, Tagging, VersioningConfiguration,
    },
};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start};
use harness::{Client, records};

const MIB: usize = 1024 * 1024;

/// A client with alias `t` for `source` and `d` for `destination`.
fn cli(source: &Server, destination: &Server) -> Client {
    let mut cli = Client::new(source);
    let address = destination.endpoint.trim_start_matches("http://");
    cli.env.push((
        "TEIFS_ALIAS_D".to_owned(),
        format!("http://{ACCESS_KEY}:{SECRET_KEY}@{address}"),
    ));
    cli
}

async fn versioned(s3: &S3, bucket: &str) {
    s3.create_bucket().bucket(bucket).send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
}

async fn put(s3: &S3, bucket: &str, key: &str, body: &str) {
    s3.put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(body.as_bytes().to_vec()))
        .send()
        .await
        .unwrap();
}

/// Uploads `key` in parts of these sizes; its ETag.
async fn multipart(s3: &S3, bucket: &str, key: &str, sizes: &[usize]) -> String {
    let id = s3
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .content_type("application/x-test")
        .send()
        .await
        .unwrap()
        .upload_id
        .unwrap();
    let mut parts = Vec::new();
    for (n, &len) in (1..).zip(sizes) {
        let seed = usize::try_from(n).unwrap();
        let body: Vec<u8> = (0..len)
            .map(|i| u8::try_from((i * 7 + seed) % 251).unwrap())
            .collect();
        let etag = s3
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(&id)
            .part_number(n)
            .body(ByteStream::from(body))
            .send()
            .await
            .unwrap()
            .e_tag;
        parts.push(
            CompletedPart::builder()
                .part_number(n)
                .set_e_tag(etag)
                .build(),
        );
    }
    s3.complete_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build(),
        )
        .send()
        .await
        .unwrap()
        .e_tag
        .unwrap()
}

/// Makes `bucket`, an object bucket whose objects are encrypted with KMS keys.
async fn sealed(s3: &S3, bucket: &str) {
    s3.create_bucket()
        .bucket(bucket)
        .customize()
        .mutate_request(|req| {
            req.headers_mut()
                .insert(teifs_server::LAYOUT_HEADER, "object");
        })
        .send()
        .await
        .unwrap();
    s3.put_bucket_encryption()
        .bucket(bucket)
        .server_side_encryption_configuration(
            aws_sdk_s3::types::ServerSideEncryptionConfiguration::builder()
                .rules(
                    aws_sdk_s3::types::ServerSideEncryptionRule::builder()
                        .apply_server_side_encryption_by_default(
                            aws_sdk_s3::types::ServerSideEncryptionByDefault::builder()
                                .sse_algorithm(aws_sdk_s3::types::ServerSideEncryption::AwsKms)
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
}

/// Gives `bucket` the tag `cost=value`.
async fn tags(s3: &S3, bucket: &str, value: &str) {
    let tag = Tag::builder().key("cost").value(value).build().unwrap();
    s3.put_bucket_tagging()
        .bucket(bucket)
        .tagging(Tagging::builder().tag_set(tag).build().unwrap())
        .send()
        .await
        .unwrap();
}

/// A key's versions and markers, oldest first: `(marker, etag)`.
async fn history(s3: &S3, bucket: &str, key: &str) -> Vec<(bool, String)> {
    let mut all: Vec<(bool, i128, bool, String)> = Vec::new();
    let (mut key_marker, mut version_marker) = (None, None);
    loop {
        let listed = s3
            .list_object_versions()
            .bucket(bucket)
            .prefix(key)
            .set_key_marker(key_marker.take())
            .set_version_id_marker(version_marker.take())
            .send()
            .await
            .unwrap();
        for v in listed.versions().iter().filter(|v| v.key() == Some(key)) {
            let time = v.last_modified().unwrap().as_nanos();
            all.push((
                v.is_latest().unwrap(),
                time,
                false,
                v.e_tag().unwrap().to_owned(),
            ));
        }
        for m in listed
            .delete_markers()
            .iter()
            .filter(|m| m.key() == Some(key))
        {
            let time = m.last_modified().unwrap().as_nanos();
            all.push((m.is_latest().unwrap(), time, true, String::new()));
        }
        if !listed.is_truncated().unwrap() {
            break;
        }
        key_marker = listed.next_key_marker().map(str::to_owned);
        version_marker = listed.next_version_id_marker().map(str::to_owned);
    }
    all.reverse();
    all.sort_by_key(|(latest, time, _, _)| (*latest, *time));
    all.into_iter()
        .map(|(_, _, marker, etag)| (marker, etag))
        .collect()
}

/// The source's buckets: `photos`, versioned, with settings, objects with attributes,
/// a delete marker and multipart objects; `locked`, with Object Lock. The multipart
/// objects' ETags, and `locked`'s Object Lock settings.
async fn seed(from: &S3) -> (String, String, ObjectLockConfiguration) {
    versioned(from, "photos").await;
    put(from, "photos", "a.txt", "one").await;
    from.put_object()
        .bucket("photos")
        .key("a.txt")
        .body(ByteStream::from_static(b"two"))
        .content_type("text/plain")
        .cache_control("max-age=60")
        .content_disposition("attachment")
        .metadata("colour", "blue")
        .tagging("team=red&note=a%20b")
        .send()
        .await
        .unwrap();
    put(from, "photos", "gone.txt", "soon gone").await;
    from.delete_object()
        .bucket("photos")
        .key("gone.txt")
        .send()
        .await
        .unwrap();
    // Even parts (the last shorter), and uneven ones.
    let even = multipart(from, "photos", "even.bin", &[5 * MIB, 5 * MIB, MIB]).await;
    let uneven = multipart(from, "photos", "uneven.bin", &[5 * MIB, 6 * MIB, MIB]).await;
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutBucketWebsite","Resource":"arn:aws:s3:::photos"}]}"#;
    from.put_bucket_policy()
        .bucket("photos")
        .policy(policy)
        .send()
        .await
        .unwrap();
    from.put_bucket_tagging()
        .bucket("photos")
        .tagging(
            Tagging::builder()
                .tag_set(Tag::builder().key("cost").value("ops").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    from.create_bucket()
        .bucket("locked")
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
    let lock = ObjectLockConfiguration::builder()
        .object_lock_enabled(ObjectLockEnabled::Enabled)
        .rule(
            ObjectLockRule::builder()
                .default_retention(
                    DefaultRetention::builder()
                        .mode(ObjectLockRetentionMode::Governance)
                        .days(1)
                        .build(),
                )
                .build(),
        )
        .build();
    from.put_object_lock_configuration()
        .bucket("locked")
        .object_lock_configuration(lock.clone())
        .send()
        .await
        .unwrap();
    from.put_object()
        .bucket("locked")
        .key("held")
        .body(ByteStream::from_static(b"keep"))
        .object_lock_legal_hold_status(ObjectLockLegalHoldStatus::On)
        .send()
        .await
        .unwrap();
    (even, uneven, lock)
}

/// Checks that everything `seed` made is at the destination, the same.
async fn check_copied(
    from: &S3,
    to: &S3,
    (even, uneven): (&str, &str),
    lock: &ObjectLockConfiguration,
) {
    for key in ["a.txt", "gone.txt", "even.bin", "uneven.bin"] {
        assert_eq!(
            history(to, "photos", key).await,
            history(from, "photos", key).await,
            "{key}"
        );
    }
    let (e, u) = (
        to.head_object()
            .bucket("photos")
            .key("even.bin")
            .send()
            .await
            .unwrap(),
        to.head_object()
            .bucket("photos")
            .key("uneven.bin")
            .send()
            .await
            .unwrap(),
    );
    assert_eq!((e.e_tag(), u.e_tag()), (Some(even), Some(uneven)));
    assert_eq!(e.content_type(), Some("application/x-test"));
    let a = to
        .head_object()
        .bucket("photos")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(a.content_type(), Some("text/plain"));
    assert_eq!(a.cache_control(), Some("max-age=60"));
    assert_eq!(a.content_disposition(), Some("attachment"));
    assert_eq!(a.metadata().unwrap()["colour"], "blue");
    let tags = to
        .get_object_tagging()
        .bucket("photos")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    let mut tags: Vec<(&str, &str)> = tags
        .tag_set()
        .iter()
        .map(|t| (t.key(), t.value()))
        .collect();
    tags.sort_unstable();
    assert_eq!(tags, [("note", "a b"), ("team", "red")]);
    let there = to
        .get_bucket_policy()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert!(there.policy().unwrap().contains("arn:aws:s3:::photos\""));
    assert_eq!(
        to.get_bucket_tagging()
            .bucket("photos")
            .send()
            .await
            .unwrap()
            .tag_set()[0]
            .value(),
        "ops"
    );
    let there = to
        .get_object_lock_configuration()
        .bucket("locked")
        .send()
        .await
        .unwrap();
    assert_eq!(there.object_lock_configuration(), Some(lock));
    let locked = to
        .head_object()
        .bucket("locked")
        .key("held")
        .send()
        .await
        .unwrap();
    assert_eq!(
        locked.object_lock_legal_hold_status(),
        Some(&ObjectLockLegalHoldStatus::On)
    );
    // Its retention came along too.
    assert!(locked.object_lock_retain_until_date().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn buckets_move_with_every_version_and_setting() {
    let (a, b) = (start().await, start().await);
    let (from, to) = (client(&a, SECRET_KEY), client(&b, SECRET_KEY));
    let cli = cli(&a, &b);

    let (even, uneven, lock) = seed(&from).await;

    // A dry run changes nothing.
    let out = cli.ok(&["migrate", "t", "d", "--dry-run"]).await;
    assert!(out.contains("would make d/photos"), "{out}");
    assert!(out.contains("would copy d/photos/a.txt"), "{out}");
    assert!(
        out.contains("would mark deleted d/photos/gone.txt"),
        "{out}"
    );
    assert!(to.list_buckets().send().await.unwrap().buckets().is_empty());

    let out = cli.ok(&["migrate", "t", "d"]).await;
    assert!(out.contains("Created d/locked with Object Lock"), "{out}");
    assert!(out.contains("Copied 6 versions"), "{out}");
    assert!(out.contains("1 delete marker"), "{out}");
    check_copied(&from, &to, (&even, &uneven), &lock).await;

    // Again: nothing left to copy (a key only the destination has is left alone).
    // Then only what's new.
    put(&to, "photos", "0-only-here", "mine").await;
    let out = cli.ok(&["--json", "migrate", "t", "d"]).await;
    let summary = records(&out).pop().unwrap();
    assert_eq!(
        (summary["versions"].as_u64(), summary["present"].as_u64()),
        (Some(0), Some(7))
    );
    put(&from, "photos", "a.txt", "three").await;
    let out = cli.ok(&["migrate", "t/photos", "d"]).await;
    assert!(out.contains("Copied 1 version"), "{out}");
    assert_eq!(
        history(&to, "photos", "a.txt").await,
        history(&from, "photos", "a.txt").await
    );

    // A key whose versions there aren't the source's: left alone, and the run fails.
    put(&to, "photos", "even.bin", "something else").await;
    put(&from, "photos", "new.txt", "new").await;
    let run = cli.run(&["migrate", "t/photos", "d"]).await;
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("d/photos/even.bin: its versions there"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.contains("1 key in conflict"), "{}", run.stdout);
    assert!(run.stdout.contains("Copied 1 version"), "{}", run.stdout);
}

#[tokio::test(flavor = "multi_thread")]
async fn current_objects_and_prefixes_go_where_they_are_sent() {
    let (a, b) = (start().await, start().await);
    let (from, to) = (client(&a, SECRET_KEY), client(&b, SECRET_KEY));
    let cli = cli(&a, &b);
    versioned(&from, "src").await;
    put(&from, "src", "docs/one", "1").await;
    put(&from, "src", "docs/one", "1, again").await;
    put(&from, "src", "docs/sub/two", "2").await;
    put(&from, "src", "other", "x").await;
    to.create_bucket().bucket("dst").send().await.unwrap();

    let out = cli
        .ok(&[
            "migrate",
            "t/src/docs/",
            "d/dst/archive/",
            "--latest",
            "--no-configs",
        ])
        .await;
    assert!(out.contains("Copied 2 versions"), "{out}");
    let listed = to
        .list_object_versions()
        .bucket("dst")
        .send()
        .await
        .unwrap();
    let keys: Vec<&str> = listed.versions().iter().filter_map(|v| v.key()).collect();
    assert_eq!(keys, ["archive/one", "archive/sub/two"]);
    let got = to
        .get_object()
        .bucket("dst")
        .key("archive/one")
        .send()
        .await
        .unwrap();
    assert_eq!(
        &got.body.collect().await.unwrap().into_bytes()[..],
        b"1, again"
    );
    // --no-configs left its versioning alone.
    let versioning = to
        .get_bucket_versioning()
        .bucket("dst")
        .send()
        .await
        .unwrap();
    assert_eq!(versioning.status(), None);
    // Versions need a destination that keeps them.
    let err = cli
        .fails(&["migrate", "t/src", "d/dst", "--no-configs"], 2)
        .await;
    assert!(err.contains("--latest"), "{err}");
    // With settings: its versioning set as the source's, its own tags kept.
    tags(&from, "src", "ops").await;
    tags(&to, "dst", "mine").await;
    let out = cli
        .ok(&["migrate", "t/src/docs/", "d/dst/archive/", "--latest"])
        .await;
    assert!(out.contains("Copied 0 versions"), "{out}");
    assert!(out.contains("Set d/dst's versioning"), "{out}");
    let err_out = cli
        .run(&["migrate", "t/src/docs/", "d/dst/archive/", "--latest"])
        .await;
    assert!(
        err_out
            .stderr
            .contains("kept d/dst's own tags, which differs from t/src's"),
        "{}",
        err_out.stderr
    );
    // Without a destination prefix, the source's is kept.
    cli.ok(&["migrate", "t/src/docs/sub/", "d", "--latest"])
        .await;
    to.head_object()
        .bucket("src")
        .key("docs/sub/two")
        .send()
        .await
        .unwrap();

    // One bucket can't go into itself.
    let err = cli.fails(&["migrate", "t/src", "t/src/copy/"], 2).await;
    assert!(err.contains("overlap"), "{err}");
    // A whole alias goes to an alias.
    let err = cli.fails(&["migrate", "t", "d/dst"], 2).await;
    assert!(err.contains("give the destination as an alias"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn suspended_long_and_encrypted_histories() {
    let (a, b) = (start().await, start().await);
    let (from, to) = (client(&a, SECRET_KEY), client(&b, SECRET_KEY));
    let cli = cli(&a, &b);

    // Versions, then versioning suspended and a `null` version over them.
    versioned(&from, "old").await;
    put(&from, "old", "k", "v1").await;
    put(&from, "old", "k", "v2").await;
    from.put_bucket_versioning()
        .bucket("old")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Suspended)
                .build(),
        )
        .send()
        .await
        .unwrap();
    put(&from, "old", "k", "v3").await;
    cli.ok(&["migrate", "t/old", "d"]).await;
    assert_eq!(
        history(&to, "old", "k").await,
        history(&from, "old", "k").await
    );
    let versioning = to
        .get_bucket_versioning()
        .bucket("old")
        .send()
        .await
        .unwrap();
    assert_eq!(
        versioning.status(),
        Some(&BucketVersioningStatus::Suspended)
    );

    // More versions of a key than one listing page holds.
    versioned(&from, "long").await;
    for i in 0..5 {
        put(&from, "long", "k", &i.to_string()).await;
    }
    put(&from, "long", "l", "after").await;
    cli.ok(&["migrate", "t/long", "d", "--page-size", "2"])
        .await;
    for key in ["k", "l"] {
        assert_eq!(
            history(&to, "long", key).await,
            history(&from, "long", key).await
        );
    }
    let out = cli
        .ok(&["migrate", "t/long", "d", "--page-size", "2"])
        .await;
    assert!(out.contains("6 already there"), "{out}");

    // Within one service, copied by it, with the same attributes.
    from.put_object()
        .bucket("old")
        .key("tagged")
        .body(ByteStream::from_static(b"t"))
        .cache_control("no-cache")
        .tagging("a=b")
        .send()
        .await
        .unwrap();
    cli.ok(&["migrate", "t/old", "t/again", "--latest"]).await;
    let head = from
        .head_object()
        .bucket("again")
        .key("tagged")
        .send()
        .await
        .unwrap();
    assert_eq!(
        (head.cache_control(), head.tag_count()),
        (Some("no-cache"), Some(1))
    );

    // A destination whose ETags aren't MD5s (encrypted with KMS keys): compared by
    // size alone.
    sealed(&to, "sealed").await;
    let args = ["migrate", "t/again", "d/sealed", "--latest", "--no-configs"];
    let err = cli.fails(&args, 1).await;
    assert!(err.contains("--size-only"), "{err}");
    // The copies were made, but their ETags couldn't be checked; by size they're there.
    let out = cli.ok(&[&args[..], &["--size-only"]].concat()).await;
    assert!(
        out.contains("Copied 0 versions") && out.contains("2 already there"),
        "{out}"
    );
}
