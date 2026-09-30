//! Server access logging's configuration over the S3 API: `PutBucketLogging` with AWS's
//! checks of the target bucket, and `GetBucketLogging` answering it as it was given.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    types::{
        BucketLoggingStatus, BucketLogsPermission, DefaultRetention, Grantee, LoggingEnabled,
        ObjectLockConfiguration, ObjectLockEnabled, ObjectLockRetentionMode, ObjectLockRule,
        ObjectOwnership, OwnershipControls, OwnershipControlsRule, PartitionDateSource,
        PartitionedPrefix, SimplePrefix, TargetGrant, TargetObjectKeyFormat, Type,
    },
};

mod common;

use common::{SECRET_KEY, Server, client, code, start, user};

const LOG_DELIVERY: &str = "http://acs.amazonaws.com/groups/s3/LogDelivery";

/// A policy on `target` letting the logging service write under `prefix` for `source`,
/// as AWS's documentation writes it.
fn delivery_policy(target: &str, prefix: &str, source: &str, account: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",
        "Principal":{{"Service":"logging.s3.amazonaws.com"}},"Action":"s3:PutObject",
        "Resource":"arn:aws:s3:::{target}/{prefix}*",
        "Condition":{{"ArnLike":{{"aws:SourceArn":"arn:aws:s3:::{source}"}},
        "StringEquals":{{"aws:SourceAccount":"{account}"}}}}}}]}}"#
    )
}

fn enabled(target: &str, prefix: &str) -> LoggingEnabled {
    LoggingEnabled::builder()
        .target_bucket(target)
        .target_prefix(prefix)
        .build()
        .unwrap()
}

async fn put(s3: &Client, bucket: &str, logging: Option<LoggingEnabled>) -> String {
    let status = BucketLoggingStatus::builder()
        .set_logging_enabled(logging)
        .build();
    code(
        s3.put_bucket_logging()
            .bucket(bucket)
            .bucket_logging_status(status)
            .send()
            .await,
    )
}

async fn get(s3: &Client, bucket: &str) -> Option<LoggingEnabled> {
    s3.get_bucket_logging()
        .bucket(bucket)
        .send()
        .await
        .unwrap()
        .logging_enabled
}

/// Buckets `app` (logged) and `logs` (the target), made by the root user.
async fn setup(server: &Server) -> Client {
    let root = client(server, SECRET_KEY);
    for bucket in ["app", "logs"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    root
}

async fn put_policy(root: &Client, bucket: &str, policy: &str) {
    root.put_bucket_policy()
        .bucket(bucket)
        .policy(policy)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn logging_is_answered_as_it_was_given() {
    let server = start().await;
    let root = setup(&server).await;
    let account = server.iam.account();
    assert_eq!(get(&root, "app").await, None, "off at first");
    put_policy(
        &root,
        "logs",
        &delivery_policy("logs", "app/", "app", &account),
    )
    .await;
    assert_eq!(put(&root, "app", Some(enabled("logs", "app/"))).await, "ok");
    assert_eq!(get(&root, "app").await, Some(enabled("logs", "app/")));

    for format in [
        TargetObjectKeyFormat::builder()
            .simple_prefix(SimplePrefix::builder().build())
            .build(),
        TargetObjectKeyFormat::builder()
            .partitioned_prefix(PartitionedPrefix::builder().build())
            .build(),
        TargetObjectKeyFormat::builder()
            .partitioned_prefix(
                PartitionedPrefix::builder()
                    .partition_date_source(PartitionDateSource::DeliveryTime)
                    .build(),
            )
            .build(),
    ] {
        let mut given = enabled("logs", "app/");
        given.target_object_key_format = Some(format);
        assert_eq!(put(&root, "app", Some(given.clone())).await, "ok");
        assert_eq!(get(&root, "app").await, Some(given));
    }
    // An empty status turns it off.
    assert_eq!(put(&root, "app", None).await, "ok");
    assert_eq!(get(&root, "app").await, None);
    // A bucket may log to itself.
    put_policy(
        &root,
        "app",
        &delivery_policy("app", "self/", "app", &account),
    )
    .await;
    assert_eq!(put(&root, "app", Some(enabled("app", "self/"))).await, "ok");
}

#[tokio::test]
async fn the_logging_service_must_be_let_into_the_target() {
    let server = start().await;
    let root = setup(&server).await;
    let account = server.iam.account();
    let refused = "InvalidTargetBucketForLogging";
    assert_eq!(put(&root, "app", Some(enabled("nope", ""))).await, refused);
    assert_eq!(
        put(&root, "nope", Some(enabled("logs", ""))).await,
        "NoSuchBucket"
    );
    // Neither the policy nor the ACL lets it in.
    assert_eq!(
        put(&root, "app", Some(enabled("logs", "app/"))).await,
        refused
    );
    // A policy for another source, another account or another prefix doesn't.
    for policy in [
        delivery_policy("logs", "app/", "other", &account),
        delivery_policy("logs", "app/", "app", "210987654321"),
        delivery_policy("logs", "elsewhere/", "app", &account),
    ] {
        put_policy(&root, "logs", &policy).await;
        assert_eq!(
            put(&root, "app", Some(enabled("logs", "app/"))).await,
            refused,
            "{policy}"
        );
    }
    put_policy(
        &root,
        "logs",
        &delivery_policy("logs", "app/", "app", &account),
    )
    .await;
    assert_eq!(put(&root, "app", Some(enabled("logs", "app/"))).await, "ok");
    // A Deny for everyone else leaves the service's own Allow alone...
    let deny_others = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",
        "Principal":{{"Service":"logging.s3.amazonaws.com"}},"Action":"s3:PutObject",
        "Resource":"arn:aws:s3:::logs/*"}},{{"Effect":"Deny",
        "NotPrincipal":{{"Service":"logging.s3.amazonaws.com"}},"Action":"s3:PutObject",
        "Resource":"arn:aws:s3:::logs/*","Condition":{{"StringNotEquals":
        {{"aws:PrincipalAccount":"{account}"}}}}}}]}}"#
    );
    put_policy(&root, "logs", &deny_others).await;
    assert_eq!(put(&root, "app", Some(enabled("logs", "app/"))).await, "ok");
    // ...and a Deny naming the service keeps it out.
    let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny",
        "Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:*",
        "Resource":"arn:aws:s3:::logs/*"}]}"#;
    put_policy(&root, "logs", deny).await;
    assert_eq!(
        put(&root, "app", Some(enabled("logs", "app/"))).await,
        refused
    );
}

#[tokio::test]
async fn the_log_delivery_group_may_be_let_in_by_the_acl() {
    let server = start().await;
    let root = setup(&server).await;
    root.put_bucket_ownership_controls()
        .bucket("logs")
        .ownership_controls(
            OwnershipControls::builder()
                .rules(
                    OwnershipControlsRule::builder()
                        .object_ownership(ObjectOwnership::BucketOwnerPreferred)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let refused = "InvalidTargetBucketForLogging";
    assert_eq!(put(&root, "app", Some(enabled("logs", ""))).await, refused);
    root.put_bucket_acl()
        .bucket("logs")
        .grant_write(format!("uri={LOG_DELIVERY}"))
        .grant_read_acp(format!("uri={LOG_DELIVERY}"))
        .send()
        .await
        .unwrap();
    assert_eq!(put(&root, "app", Some(enabled("logs", ""))).await, "ok");
    // Target grants, answered as given.
    let mut given = enabled("logs", "");
    given.target_grants = Some(vec![
        TargetGrant::builder()
            .grantee(
                Grantee::builder()
                    .r#type(Type::Group)
                    .uri("http://acs.amazonaws.com/groups/global/AuthenticatedUsers")
                    .build()
                    .unwrap(),
            )
            .permission(BucketLogsPermission::Read)
            .build(),
    ]);
    assert_eq!(put(&root, "app", Some(given.clone())).await, "ok");
    assert_eq!(get(&root, "app").await, Some(given.clone()));
    // Once ACLs are disabled, the grant no longer lets the service in, and target
    // grants are refused.
    root.put_bucket_ownership_controls()
        .bucket("logs")
        .ownership_controls(
            OwnershipControls::builder()
                .rules(
                    OwnershipControlsRule::builder()
                        .object_ownership(ObjectOwnership::BucketOwnerEnforced)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    // (AWS refuses BucketOwnerEnforced while the ACL grants others: reset it first.)
    root.put_bucket_acl()
        .bucket("logs")
        .acl(aws_sdk_s3::types::BucketCannedAcl::Private)
        .send()
        .await
        .unwrap();
    root.put_bucket_ownership_controls()
        .bucket("logs")
        .ownership_controls(
            OwnershipControls::builder()
                .rules(
                    OwnershipControlsRule::builder()
                        .object_ownership(ObjectOwnership::BucketOwnerEnforced)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put(&root, "app", Some(given)).await, "InvalidArgument");
    assert_eq!(put(&root, "app", Some(enabled("logs", ""))).await, refused);
}

#[tokio::test]
async fn a_target_with_default_retention_is_refused() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("app").send().await.unwrap();
    root.create_bucket()
        .bucket("locked")
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
    let account = server.iam.account();
    put_policy(
        &root,
        "locked",
        &delivery_policy("locked", "", "app", &account),
    )
    .await;
    // Object Lock alone is fine; a default retention isn't.
    assert_eq!(put(&root, "app", Some(enabled("locked", ""))).await, "ok");
    root.put_object_lock_configuration()
        .bucket("locked")
        .object_lock_configuration(
            ObjectLockConfiguration::builder()
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
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        put(&root, "app", Some(enabled("locked", ""))).await,
        "InvalidTargetBucketForLogging"
    );
}

#[tokio::test]
async fn logging_takes_its_own_permissions() {
    let server = start().await;
    let root = setup(&server).await;
    put_policy(
        &root,
        "logs",
        &delivery_policy("logs", "", "app", &server.iam.account()),
    )
    .await;
    let reader = user(
        &server,
        "reader",
        Some(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetBucketLogging","Resource":"*"}}"#,
        ),
    );
    assert_eq!(
        put(&reader, "app", Some(enabled("logs", ""))).await,
        "AccessDenied"
    );
    assert_eq!(get(&reader, "app").await, None);
    let writer = user(
        &server,
        "writer",
        Some(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:PutBucketLogging","Resource":"arn:aws:s3:::app"}}"#,
        ),
    );
    assert_eq!(put(&writer, "app", Some(enabled("logs", ""))).await, "ok");
    assert_eq!(get(&root, "app").await, Some(enabled("logs", "")));
}

/// A record's fields, as log readers split them: by spaces, but for `[…]` and `"…"`.
fn fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut rest = line;
    while !rest.is_empty() {
        let (field, after) = match rest.as_bytes()[0] {
            b'[' => rest.split_at(rest.find(']').unwrap() + 1),
            b'"' => rest.split_at(rest[1..].find('"').unwrap() + 2),
            _ => rest.split_at(rest.find(' ').unwrap_or(rest.len())),
        };
        fields.push(field.to_owned());
        rest = after.strip_prefix(' ').unwrap_or(after);
    }
    fields
}

/// The records delivered into `bucket` under `prefix` (and the log objects' keys), once
/// there are at least `count` of them.
async fn delivered(
    s3: &Client,
    bucket: &str,
    prefix: &str,
    count: usize,
) -> (Vec<String>, Vec<Vec<String>>) {
    for _ in 0..300 {
        let listed = s3
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix)
            .send()
            .await
            .unwrap();
        let keys: Vec<String> = listed
            .contents()
            .iter()
            .filter_map(|o| o.key().map(str::to_owned))
            .collect();
        let mut records = Vec::new();
        for key in &keys {
            let object = s3
                .get_object()
                .bucket(bucket)
                .key(key)
                .send()
                .await
                .unwrap();
            assert_eq!(object.content_type(), Some("text/plain"));
            let body = object.body.collect().await.unwrap().into_bytes();
            let text = String::from_utf8(body.to_vec()).unwrap();
            records.extend(text.lines().map(fields));
        }
        if records.len() >= count {
            return (keys, records);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("{bucket} never had {count} records under {prefix}");
}

/// The record of `operation` on `key`.
fn find<'r>(records: &'r [Vec<String>], operation: &str, key: &str) -> &'r [String] {
    records
        .iter()
        .find(|r| r[6] == operation && r[7] == key)
        .unwrap_or_else(|| panic!("no {operation} of {key} in {records:#?}"))
}

fn fast(config: &mut teifs_server::Config) {
    config.access_log_interval = Some(std::time::Duration::from_secs(1));
}

#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
#[tokio::test]
async fn requests_are_delivered_as_s3_logs_them() {
    use aws_sdk_s3::{
        primitives::ByteStream,
        types::{Delete, ObjectIdentifier},
    };

    let server = common::start_with(fast).await;
    let root = setup(&server).await;
    let account = server.iam.account();
    put_policy(
        &root,
        "logs",
        &delivery_policy("logs", "app/", "app", &account),
    )
    .await;
    assert_eq!(put(&root, "app", Some(enabled("logs", "app/"))).await, "ok");
    root.put_object()
        .bucket("app")
        .key("a b.txt")
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await
        .unwrap();
    root.get_object()
        .bucket("app")
        .key("a b.txt")
        .send()
        .await
        .unwrap();
    root.head_object()
        .bucket("app")
        .key("a b.txt")
        .send()
        .await
        .unwrap();
    root.list_objects_v2().bucket("app").send().await.unwrap();
    assert_eq!(
        code(root.get_object().bucket("app").key("missing").send().await),
        "NoSuchKey"
    );
    let anonymous = reqwest::get(format!("{}/app/a%20b.txt?x-id=GetObject", server.endpoint))
        .await
        .unwrap();
    assert_eq!(anonymous.status().as_u16(), 403);
    root.copy_object()
        .bucket("app")
        .key("copy.txt")
        .copy_source("app/a%20b.txt")
        .send()
        .await
        .unwrap();
    let delete = Delete::builder()
        .objects(ObjectIdentifier::builder().key("a b.txt").build().unwrap())
        .objects(ObjectIdentifier::builder().key("copy.txt").build().unwrap())
        .build()
        .unwrap();
    root.delete_objects()
        .bucket("app")
        .delete(delete)
        .send()
        .await
        .unwrap();
    // A request on another bucket isn't in this one's log.
    root.list_objects_v2().bucket("logs").send().await.unwrap();

    let (keys, records) = delivered(&root, "logs", "app/", 11).await;
    for key in &keys {
        let name = key.strip_prefix("app/").unwrap();
        // YYYY-MM-DD-hh-mm-ss-UNIQUE
        assert_eq!(name.len(), 19 + 1 + 16, "{key}");
        assert!(name[20..].bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
    }
    assert!(
        records
            .iter()
            .all(|r| r.len() == 27 && r[0] == "teifs" && r[1] == "app")
    );
    assert!(
        records
            .iter()
            .all(|r| r[2].starts_with('[') && r[2].ends_with(" +0000]"))
    );
    let put_record = find(&records, "REST.PUT.OBJECT", "a%20b.txt");
    assert_eq!(put_record[3], "127.0.0.1");
    assert_eq!(put_record[4], "teifs", "the root user, by its canonical id");
    assert!(
        put_record[8].starts_with("\"PUT /app/a%20b.txt?x-id=PutObject HTTP/1.1"),
        "{put_record:?}"
    );
    assert_eq!(&put_record[9..12], ["200", "-", "-"]);
    assert_eq!(put_record[12], "5", "the object's size");
    assert_eq!(
        (put_record[19].as_str(), put_record[21].as_str()),
        ("SigV4", "AuthHeader")
    );
    assert!(put_record[22].starts_with("127.0.0.1:"), "the Host header");
    let get = find(&records, "REST.GET.OBJECT", "a%20b.txt");
    assert_eq!(
        (get[9].as_str(), get[11].as_str(), get[12].as_str()),
        ("200", "5", "5")
    );
    assert!(get[16].contains("aws-sdk-rust"), "the user agent: {get:?}");
    find(&records, "REST.HEAD.OBJECT", "a%20b.txt");
    let list = find(&records, "REST.GET.BUCKET", "-");
    assert!(list[8].starts_with("\"GET /app/?list-type=2"), "{list:?}");
    let missing = find(&records, "REST.GET.OBJECT", "missing");
    assert_eq!(
        (missing[9].as_str(), missing[10].as_str()),
        ("404", "NoSuchKey")
    );
    let refused = records
        .iter()
        .find(|r| r[9] == "403")
        .expect("the anonymous request's record");
    assert_eq!(
        (refused[4].as_str(), refused[10].as_str()),
        ("-", "AccessDenied")
    );
    assert_eq!((refused[19].as_str(), refused[21].as_str()), ("-", "-"));
    let copy = find(&records, "REST.COPY.OBJECT", "copy.txt");
    assert_eq!(copy[12], "-", "a copy's body isn't the object");
    find(&records, "REST.COPY.OBJECT_GET", "a%20b.txt");
    find(&records, "REST.POST.MULTI_OBJECT_DELETE", "-");
    for key in ["a%20b.txt", "copy.txt"] {
        assert_eq!(find(&records, "BATCH.DELETE.OBJECT", key)[9], "204");
    }
    assert!(
        records
            .iter()
            .all(|r| !r.iter().any(|f| f.contains("logs"))),
        "{records:#?}"
    );
}

#[tokio::test]
async fn a_bucket_that_logs_to_itself_doesnt_log_its_log_objects() {
    let server = common::start_with(fast).await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("app").send().await.unwrap();
    put_policy(
        &root,
        "app",
        &delivery_policy("app", "logs/", "app", &server.iam.account()),
    )
    .await;
    assert_eq!(put(&root, "app", Some(enabled("app", "logs/"))).await, "ok");
    root.head_bucket().bucket("app").send().await.unwrap();
    let (_, records) = delivered(&root, "app", "logs/", 1).await;
    find(&records, "REST.HEAD.BUCKET", "-");
    // The listing and reads of the log object are logged; its delivery isn't.
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let (_, records) = delivered(&root, "app", "logs/", 2).await;
    assert!(
        records.iter().all(|r| r[6] != "REST.PUT.OBJECT"),
        "{records:#?}"
    );
}

#[tokio::test]
async fn records_a_target_refuses_are_dropped() {
    let server = common::start_with(|config| {
        fast(config);
        config.public_metrics = true;
    })
    .await;
    let root = setup(&server).await;
    put_policy(
        &root,
        "logs",
        &delivery_policy("logs", "", "app", &server.iam.account()),
    )
    .await;
    assert_eq!(put(&root, "app", Some(enabled("logs", ""))).await, "ok");
    root.delete_bucket_policy()
        .bucket("logs")
        .send()
        .await
        .unwrap();
    root.head_bucket().bucket("app").send().await.unwrap();
    let metrics = format!("{}{}", server.endpoint, teifs_types::admin::METRICS_PATH);
    for _ in 0..300 {
        let text = reqwest::get(&metrics).await.unwrap().text().await.unwrap();
        if text.contains("teifs_access_log_dropped_total 1") {
            assert!(text.contains("teifs_access_log_records_total 1"), "{text}");
            assert!(text.contains("teifs_access_log_objects_total 0"), "{text}");
            let listed = root.list_objects_v2().bucket("logs").send().await.unwrap();
            assert_eq!(listed.key_count(), Some(0));
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the record was never dropped");
}

#[tokio::test]
async fn records_wait_through_a_restart() {
    let (dir, keys) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let run = |interval: u64| {
        let mut config = common::config(dir.path(), keys.path());
        config.access_log_interval = Some(std::time::Duration::from_secs(interval));
        async move {
            let server = teifs_server::Server::bind(config).await.unwrap();
            let endpoint = format!("http://{}", server.local_addr().unwrap());
            let account = server.iam().account();
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let running = tokio::spawn(server.run(async {
                let _ = stopped.await;
            }));
            (endpoint, account, stop, running)
        }
    };
    // Records spooled for an hour's delivery...
    let (endpoint, account, stop, running) = run(3600).await;
    let root = common::client_at(&endpoint, common::ACCESS_KEY, SECRET_KEY);
    for bucket in ["app", "logs"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    put_policy(&root, "logs", &delivery_policy("logs", "", "app", &account)).await;
    assert_eq!(put(&root, "app", Some(enabled("logs", ""))).await, "ok");
    root.head_bucket().bucket("app").send().await.unwrap();
    drop(stop);
    running.await.unwrap();
    // A spool cut short by a crash delivers its whole records; an empty one nothing.
    let spools = dir.path().join(".teifs/access-logs/app");
    let whole = "teifs app [01/Oct/2026:00:00:00 +0000] 127.0.0.1 teifs 1 REST.GET.OBJECT \
                 planted \"GET /app/planted HTTP/1.1\" 200 - 1 1 1 1 \"-\" \"-\" - - SigV4 - \
                 AuthHeader host - - - -";
    std::fs::write(
        spools.join("1-cut.log"),
        format!("{whole}\nteifs app [01/Oct/2026:00:00:00"),
    )
    .unwrap();
    std::fs::write(spools.join("2-empty.log"), "").unwrap();
    // ...are delivered after the next start, which watches requests from the first.
    let (endpoint, _, _stop, _running) = run(1).await;
    let root = common::client_at(&endpoint, common::ACCESS_KEY, SECRET_KEY);
    root.list_objects_v2().bucket("app").send().await.unwrap();
    let (keys, records) = delivered(&root, "logs", "", 3).await;
    find(&records, "REST.HEAD.BUCKET", "-");
    find(&records, "REST.GET.BUCKET", "-");
    find(&records, "REST.GET.OBJECT", "planted");
    assert_eq!((keys.len(), records.len()), (3, 3), "{keys:?}");
    for spool in ["1-cut.log", "2-empty.log"] {
        assert!(!spools.join(spool).exists(), "{spool} was removed");
    }
}

#[tokio::test]
async fn lifecycle_removals_are_logged_as_s3_logs_them() {
    use aws_sdk_s3::{
        primitives::ByteStream,
        types::{
            BucketLifecycleConfiguration, BucketVersioningStatus, ExpirationStatus,
            LifecycleExpiration, LifecycleRule, LifecycleRuleFilter, NoncurrentVersionExpiration,
            VersioningConfiguration,
        },
    };

    let server = common::start_with(|config| {
        fast(config);
        config.lifecycle_day = Some(std::time::Duration::from_millis(300));
    })
    .await;
    let root = setup(&server).await;
    put_policy(
        &root,
        "logs",
        &delivery_policy("logs", "", "app", &server.iam.account()),
    )
    .await;
    root.put_bucket_versioning()
        .bucket("app")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let rule = LifecycleRule::builder()
        .id("tmp")
        .status(ExpirationStatus::Enabled)
        .filter(LifecycleRuleFilter::builder().prefix("tmp/").build())
        .expiration(LifecycleExpiration::builder().days(1).build())
        .noncurrent_version_expiration(
            NoncurrentVersionExpiration::builder()
                .noncurrent_days(1)
                .build(),
        )
        .build()
        .unwrap();
    root.put_bucket_lifecycle_configuration()
        .bucket("app")
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put(&root, "app", Some(enabled("logs", ""))).await, "ok");
    root.put_object()
        .bucket("app")
        .key("tmp/a")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    // The PUT, a delete marker, then the version behind it.
    for _ in 0..100 {
        let (_, records) = delivered(&root, "logs", "", 1).await;
        let lifecycle: Vec<&Vec<String>> = records.iter().filter(|r| r[4] == "AmazonS3").collect();
        if lifecycle.len() >= 2 {
            let marker = find(&records, "S3.CREATE.DELETEMARKER", "tmp/a");
            let expired = find(&records, "S3.EXPIRE.OBJECT", "tmp/a");
            assert_eq!(marker[8], "\"-\"", "no request: {marker:?}");
            assert_eq!(marker[9], "-", "no status");
            assert_ne!(expired[17], "-", "the version removed");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the lifecycle's removals were never logged");
}
