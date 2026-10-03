//! Batch jobs' records and the `expire` job, as `MinIO` runs it: the newest version of
//! each key decides, the first matching rule says how many versions stay.

use std::sync::Arc;

use teifs_crypto::LocalKms;
use teifs_types::{
    LockMode, ObjectAttrs, Retention,
    batch::{
        BatchJob, ExpireJob, ExpireKind, ExpireRule, JobProgress, JobRetry, JobSpec, JobStatus,
        KeyValue,
    },
};
use tempfile::TempDir;

use crate::{
    Durability, Layout, NewBucket, Store, StoreOptions, Versioning, VersionsQuery, now_ms,
    test_util::in_both_layouts,
};

in_both_layouts!(
    the_newest_version_decides_and_the_rule_keeps_its_versions,
    tags_metadata_sizes_and_ages_must_all_match,
    locked_versions_fail_and_are_counted,
    prefixes_are_walked_a_page_at_a_time,
);

const TOKEN: &str = "dummy-notify-token-0001";

async fn bucket(layout: Layout, lock: bool) -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let options = StoreOptions {
        durability: Durability::None,
        ..StoreOptions::default()
    };
    let store = Store::open_with(dir.path(), options).unwrap();
    let options = NewBucket {
        object_lock: lock,
        ..NewBucket::default()
    };
    store
        .create_bucket_with("bkt", layout, options)
        .await
        .unwrap();
    if !lock {
        store
            .set_bucket_versioning("bkt", Versioning::Enabled)
            .await
            .unwrap();
    }
    (dir, store)
}

async fn put(store: &Store, key: &str, attrs: ObjectAttrs) -> String {
    store
        .put_bytes("bkt", key, key.as_bytes(), attrs)
        .await
        .unwrap()
        .version_id
        .unwrap()
}

async fn remove(store: &Store, key: &str) {
    store
        .delete_with("bkt", key, None, crate::Precondition::default(), false)
        .await
        .unwrap();
}

fn rule(kind: ExpireKind) -> ExpireRule {
    ExpireRule {
        kind,
        name: None,
        older_than_secs: None,
        created_before_ms: None,
        tags: Vec::new(),
        metadata: Vec::new(),
        size_less_than: None,
        size_greater_than: None,
        retain_versions: 0,
    }
}

fn job(rules: Vec<ExpireRule>, prefixes: &[&str]) -> (BatchJob, ExpireJob) {
    let expire = ExpireJob {
        bucket: "bkt".to_owned(),
        prefixes: prefixes.iter().map(|&p| p.to_owned()).collect(),
        rules,
        notify: None,
        retry: JobRetry {
            attempts: 2,
            delay_ms: 1,
        },
    };
    let job = BatchJob {
        id: "job-1".to_owned(),
        user: "admin".to_owned(),
        created_ms: now_ms(),
        priority: 0,
        status: JobStatus::Active,
        spec: JobSpec::Expire(expire.clone()),
        progress: JobProgress::default(),
        failures: Vec::new(),
    };
    (job, expire)
}

/// Runs the job's pages until it's done; how many pages it took.
async fn run(store: &Store, job: &mut BatchJob, expire: &ExpireJob) -> usize {
    for pages in 1..1000 {
        if store.expire_batch_page(job, expire).await.unwrap() {
            return pages;
        }
    }
    panic!("the job never ended");
}

/// Each key with its versions, newest first: (key, is a delete marker).
async fn left(store: &Store) -> Vec<(String, bool)> {
    let query = VersionsQuery {
        max_keys: 1000,
        ..VersionsQuery::default()
    };
    let listing = store.list_versions("bkt", query).await.unwrap();
    listing
        .versions
        .into_iter()
        .map(|v| (v.info.key, v.delete_marker))
        .collect()
}

async fn the_newest_version_decides_and_the_rule_keeps_its_versions(layout: Layout) {
    let (_dir, store) = bucket(layout, false).await;
    for _ in 0..3 {
        put(&store, "logs/a", ObjectAttrs::default()).await;
        put(&store, "logs/b", ObjectAttrs::default()).await;
    }
    put(&store, "gone", ObjectAttrs::default()).await;
    remove(&store, "gone").await;
    put(&store, "kept", ObjectAttrs::default()).await;
    let keep_two = ExpireRule {
        name: Some("logs/a".to_owned()),
        retain_versions: 2,
        ..rule(ExpireKind::Object)
    };
    let all = ExpireRule {
        name: Some("logs/*".to_owned()),
        ..rule(ExpireKind::Object)
    };
    let (mut job, expire) = job(vec![keep_two, all, rule(ExpireKind::Deleted)], &[]);
    run(&store, &mut job, &expire).await;
    // The first rule that matches decides: `logs/a` keeps two versions, `logs/b` none;
    // `gone`'s marker goes with its version, `kept` is matched by no rule.
    assert_eq!(
        left(&store).await,
        [
            ("kept".to_owned(), false),
            ("logs/a".to_owned(), false),
            ("logs/a".to_owned(), false),
        ]
    );
    let p = &job.progress;
    assert_eq!((p.objects, p.delete_markers), (5, 1));
    assert_eq!(p.bytes, 4 * 6 + 4);
    assert_eq!((p.objects_failed, p.delete_markers_failed), (0, 0));
    assert!(job.failures.is_empty());
}

async fn tags_metadata_sizes_and_ages_must_all_match(layout: Layout) {
    let (_dir, store) = bucket(layout, false).await;
    let tagged = |name: &str, kind: &str| ObjectAttrs {
        content_type: Some(kind.to_owned()),
        tags: [("name".to_owned(), name.to_owned())].into(),
        user: [("owner".to_owned(), "ops".to_owned())].into(),
        ..ObjectAttrs::default()
    };
    put(&store, "a-pickles", tagged("pickles", "image/png")).await;
    put(&store, "b-pickles-text", tagged("pickles", "text/plain")).await;
    put(&store, "c-olives", tagged("olives", "image/png")).await;
    put(&store, "d-no-tags", ObjectAttrs::default()).await;
    put(
        &store,
        "e-a-much-longer-name",
        tagged("pickles", "image/png"),
    )
    .await;
    let pickled_images = ExpireRule {
        tags: vec![KeyValue {
            key: "name".to_owned(),
            value: "pick*".to_owned(),
        }],
        metadata: vec![
            KeyValue {
                key: "Content-Type".to_owned(),
                value: "image/*".to_owned(),
            },
            KeyValue {
                key: "x-amz-meta-owner".to_owned(),
                value: "ops".to_owned(),
            },
        ],
        size_less_than: Some(15),
        size_greater_than: Some(3),
        ..rule(ExpireKind::Object)
    };
    // Too young, or made after: nothing goes.
    let young = ExpireRule {
        older_than_secs: Some(3600),
        ..rule(ExpireKind::Object)
    };
    let later = ExpireRule {
        created_before_ms: Some(now_ms() - 3_600_000),
        ..rule(ExpireKind::Object)
    };
    // Exactly the size given isn't less or greater (`d-no-tags` has 9 bytes).
    let exactly = |less: Option<u64>, greater: Option<u64>| ExpireRule {
        name: Some("d-no-tags".to_owned()),
        size_less_than: less,
        size_greater_than: greater,
        ..rule(ExpireKind::Object)
    };
    let rules = vec![young, later, exactly(Some(9), None), exactly(None, Some(9))];
    let (mut job, expire) = job(rules, &[]);
    run(&store, &mut job, &expire).await;
    assert_eq!(left(&store).await.len(), 5);
    let (mut job, expire) = self::job(vec![pickled_images], &[]);
    run(&store, &mut job, &expire).await;
    let keys: Vec<_> = left(&store).await.into_iter().map(|(k, _)| k).collect();
    assert_eq!(
        keys,
        [
            "b-pickles-text",
            "c-olives",
            "d-no-tags",
            "e-a-much-longer-name"
        ]
    );
    // Made more than a second ago, at the second: older than 0 seconds.
    let old = ExpireRule {
        older_than_secs: Some(0),
        created_before_ms: Some(now_ms() + 1000),
        name: Some("?-olives".to_owned()),
        ..rule(ExpireKind::Object)
    };
    let (mut job, expire) = self::job(vec![old], &[]);
    run(&store, &mut job, &expire).await;
    assert_eq!(left(&store).await.len(), 3);
}

async fn locked_versions_fail_and_are_counted(layout: Layout) {
    let (_dir, store) = bucket(layout, true).await;
    let held = ObjectAttrs {
        retention: Some(Retention {
            mode: LockMode::Compliance,
            until_ms: now_ms() + 3_600_000,
        }),
        ..ObjectAttrs::default()
    };
    put(&store, "free", ObjectAttrs::default()).await;
    put(&store, "held", ObjectAttrs::default()).await;
    let version = put(&store, "held", held).await;
    let (mut job, expire) = job(vec![rule(ExpireKind::Object)], &[]);
    run(&store, &mut job, &expire).await;
    assert_eq!(left(&store).await, [("held".to_owned(), false)]);
    let p = &job.progress;
    assert_eq!((p.objects, p.objects_failed), (2, 1));
    assert_eq!((p.bytes, p.bytes_failed), (8, 4));
    // A lock doesn't pass: not tried again.
    assert_eq!(p.retry_attempts, 0);
    assert_eq!(job.failures.len(), 1);
    assert!(job.failures[0].starts_with(&format!("held ({version}): ")));
}

async fn prefixes_are_walked_a_page_at_a_time(layout: Layout) {
    let (_dir, store) = bucket(layout, false).await;
    for i in 0..300 {
        put(&store, &format!("a/{i:03}"), ObjectAttrs::default()).await;
    }
    put(&store, "b/1", ObjectAttrs::default()).await;
    put(&store, "c/1", ObjectAttrs::default()).await;
    let (mut job, expire) = job(vec![rule(ExpireKind::Object)], &["a/", "c/"]);
    let first = store.expire_batch_page(&mut job, &expire).await.unwrap();
    assert!(!first);
    assert_eq!(job.progress.prefix, 0);
    let last = job.progress.last_key.clone().unwrap();
    assert!(last.starts_with("a/"));
    // Picked up where it left off, as after a restart.
    let mut resumed = job.clone();
    let pages = run(&store, &mut resumed, &expire).await;
    assert_eq!(pages, 2);
    assert_eq!(resumed.progress.objects, 301);
    assert_eq!(left(&store).await, [("b/1".to_owned(), false)]);
    assert!(
        store
            .expire_batch_page(&mut resumed, &expire)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn jobs_are_kept_changed_until_finished_and_forgotten() {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let kms = Arc::new(LocalKms::open(keys.path().join("keyring.json")).unwrap());
    let options = StoreOptions {
        kms: Some(kms),
        ..StoreOptions::default()
    };
    let store = Store::open_with(dir.path(), options).unwrap();
    let (mut first, _) = job(Vec::new(), &[]);
    first.created_ms = 10;
    let mut second = first.clone();
    second.id = "job-2".to_owned();
    second.created_ms = 20;
    store
        .add_batch_job(&first, Some(zeroize::Zeroizing::new(TOKEN.to_owned())))
        .await
        .unwrap();
    store.add_batch_job(&second, None).await.unwrap();
    let ids = |jobs: Vec<BatchJob>| jobs.into_iter().map(|j| j.id).collect::<Vec<_>>();
    assert_eq!(ids(store.batch_jobs().await.unwrap()), ["job-1", "job-2"]);
    assert_eq!(
        store
            .batch_job_token("job-1")
            .await
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some(TOKEN)
    );
    assert_eq!(store.batch_job_token("job-2").await.unwrap(), None);
    assert_eq!(store.batch_job_token("missing").await.unwrap(), None);
    // The token is kept sealed.
    let system = std::fs::read(dir.path().join(".teifs/system.db")).unwrap();
    assert!(!system.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));

    let changed = store
        .update_batch_job("job-1", |job| {
            job.progress.objects = 7;
            job.status = JobStatus::Complete;
            job.progress.updated_ms = Some(30);
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.progress.objects, 7);
    // Finished: changes no more.
    let kept = store
        .update_batch_job("job-1", |job| job.status = JobStatus::Active)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.status, JobStatus::Complete);
    assert_eq!(store.batch_job("job-1").await.unwrap(), Some(changed));
    assert_eq!(
        store.update_batch_job("missing", |_| {}).await.unwrap(),
        None
    );

    // Only finished jobs, finished before then, are forgotten.
    assert_eq!(store.forget_batch_jobs(30).await.unwrap(), 0);
    assert_eq!(store.forget_batch_jobs(31).await.unwrap(), 1);
    assert_eq!(ids(store.batch_jobs().await.unwrap()), ["job-2"]);
    assert_eq!(store.forget_batch_jobs(i64::MAX).await.unwrap(), 0);
}
