//! The lifecycle job, as S3 applies rules: what expires, when, and what stays. The same
//! behaviour in both layouts.

use std::time::{Duration, SystemTime};

use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use teifs_types::replication::{ReplicationStatus, VersionReplication};

use super::*;
use crate::{
    jobs::{ApplyLifecycle, Step},
    test_util::in_both_layouts,
};

in_both_layouts!(
    unversioned_objects_expire_when_due,
    versioned_objects_get_markers_then_old_versions_and_markers_go,
    newer_noncurrent_versions_are_kept,
    locked_versions_stay_and_keep_their_marker,
    tag_and_size_filters_and_disabled_rules,
    an_object_written_again_is_not_expired,
    old_uploads_are_aborted,
    suspended_buckets_get_a_null_marker,
    a_key_with_more_versions_than_a_page,
    noncurrent_days_count_from_the_successor,
    a_recreated_bucket_has_no_rules,
    versions_waiting_for_replication_stay,
);

const DAY: Duration = Duration::from_hours(24);

async fn bucket(layout: Layout, versioning: Option<Versioning>) -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    // Nothing synced: some tests write hundreds of versions.
    let options = StoreOptions {
        durability: Durability::None,
        ..StoreOptions::default()
    };
    let store = Store::open_with(dir.path(), options).unwrap();
    store.create_bucket("bkt", layout).await.unwrap();
    if let Some(versioning) = versioning {
        store
            .set_bucket_versioning("bkt", versioning)
            .await
            .unwrap();
    }
    (dir, store)
}

fn rule(id: &str, prefix: &str) -> LifecycleRule {
    LifecycleRule {
        id: id.to_owned(),
        enabled: true,
        filter: RuleFilter::RulePrefix(prefix.to_owned()),
        expiration: None,
        noncurrent_expiration: None,
        abort_uploads_after_days: None,
    }
}

async fn set_rules(store: &Store, rules: Vec<LifecycleRule>) {
    let lifecycle = Lifecycle {
        rules,
        transition_minimum_size: None,
    };
    store
        .set_bucket_lifecycle("bkt", Some(lifecycle))
        .await
        .unwrap();
}

async fn put(store: &Store, key: &str) -> ObjectInfo {
    store
        .put_bytes("bkt", key, key.as_bytes(), ObjectAttrs::default())
        .await
        .unwrap()
}

/// Runs whole passes of the job at `now`, `days` days from now.
async fn pass(store: &Store, days: u32) {
    let mut job = ApplyLifecycle::new(store.clone());
    let step = Step {
        now: SystemTime::now() + DAY * days,
        cancel: CancellationToken::new(),
    };
    for _ in 0..100 {
        if job.run(&step).await.unwrap() == 0 {
            return;
        }
    }
    panic!("a pass never ended");
}

/// The key's versions, newest first: (is a delete marker, is current).
async fn versions(store: &Store, key: &str) -> Vec<(bool, bool)> {
    store
        .list_versions(
            "bkt",
            VersionsQuery {
                prefix: key.to_owned(),
                max_keys: 1000,
                ..VersionsQuery::default()
            },
        )
        .await
        .unwrap()
        .versions
        .iter()
        .filter(|v| v.info.key == key)
        .map(|v| (v.delete_marker, v.latest))
        .collect()
}

async fn exists(store: &Store, key: &str) -> bool {
    match store.head("bkt", key).await {
        Ok(_) => true,
        Err(StoreError::NoSuchKey) => false,
        Err(err) => panic!("{err}"),
    }
}

async fn unversioned_objects_expire_when_due(layout: Layout) {
    let (_dir, store) = bucket(layout, None).await;
    let mut logs = rule("logs", "logs/");
    logs.expiration = Some(Expiration::Days(2));
    let mut old = rule("old", "old/");
    old.expiration = Some(Expiration::Date(0));
    set_rules(&store, vec![logs, old]).await;
    for key in ["logs/a", "logs/b", "keep/a", "old/a"] {
        put(&store, key).await;
    }
    // A date that has passed applies at once.
    pass(&store, 0).await;
    assert!(!exists(&store, "old/a").await);
    assert!(exists(&store, "logs/a").await);
    // Two days after creation, rounded up to midnight: gone by day 3, not on day 1.
    pass(&store, 1).await;
    assert!(exists(&store, "logs/a").await);
    pass(&store, 3).await;
    assert!(!exists(&store, "logs/a").await && !exists(&store, "logs/b").await);
    assert!(exists(&store, "keep/a").await);
    // Nothing is left behind.
    assert_eq!(versions(&store, "logs/a").await, []);
}

async fn versioned_objects_get_markers_then_old_versions_and_markers_go(layout: Layout) {
    let (_dir, store) = bucket(layout, Some(Versioning::Enabled)).await;
    let mut expire = rule("expire", "");
    expire.expiration = Some(Expiration::Days(1));
    let mut noncurrent = rule("noncurrent", "");
    noncurrent.noncurrent_expiration = Some(NoncurrentExpiration {
        days: Some(3),
        newer_versions: None,
    });
    set_rules(&store, vec![expire, noncurrent]).await;
    put(&store, "a").await;
    put(&store, "a").await;
    pass(&store, 2).await;
    // The current version is hidden by a marker. Both older versions became noncurrent
    // today (the first when the second was written, the second when the marker was
    // made), so three days later, rounded up to midnight, is day 4.
    assert_eq!(
        versions(&store, "a").await,
        [(true, true), (false, false), (false, false)]
    );
    pass(&store, 3).await;
    assert_eq!(versions(&store, "a").await.len(), 3);
    // Then the marker is left alone, and the days rule removes it too: it's old enough.
    pass(&store, 4).await;
    assert_eq!(versions(&store, "a").await, []);

    // With ExpiredObjectDeleteMarker, a lone marker goes at once.
    let mut markers = rule("markers", "");
    markers.expiration = Some(Expiration::ExpiredDeleteMarker(true));
    set_rules(&store, vec![markers]).await;
    store.delete("bkt", "gone").await.unwrap();
    assert_eq!(versions(&store, "gone").await, [(true, true)]);
    pass(&store, 0).await;
    assert_eq!(versions(&store, "gone").await, []);
}

async fn newer_noncurrent_versions_are_kept(layout: Layout) {
    let (_dir, store) = bucket(layout, Some(Versioning::Enabled)).await;
    let mut keep = rule("keep", "");
    keep.filter = RuleFilter::Filter(Condition::Empty);
    keep.noncurrent_expiration = Some(NoncurrentExpiration {
        days: Some(1),
        newer_versions: Some(2),
    });
    set_rules(&store, vec![keep]).await;
    for _ in 0..5 {
        put(&store, "k").await;
    }
    pass(&store, 0).await;
    assert_eq!(versions(&store, "k").await.len(), 5);
    pass(&store, 2).await;
    // The current version and the two newest noncurrent ones.
    assert_eq!(
        versions(&store, "k").await,
        [(false, true), (false, false), (false, false)]
    );
}

async fn locked_versions_stay_and_keep_their_marker(layout: Layout) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let options = NewBucket {
        object_lock: true,
        ..NewBucket::default()
    };
    store
        .create_bucket_with("bkt", layout, options)
        .await
        .unwrap();
    let mut all = rule("all", "");
    all.expiration = Some(Expiration::Days(1));
    all.noncurrent_expiration = Some(NoncurrentExpiration {
        days: Some(1),
        newer_versions: None,
    });
    set_rules(&store, vec![all]).await;
    let held = ObjectAttrs {
        legal_hold: Some(true),
        ..ObjectAttrs::default()
    };
    store.put_bytes("bkt", "held", b"x", held).await.unwrap();
    put(&store, "free").await;
    pass(&store, 2).await;
    // Both got a marker; the free version then went, and its marker after it; the held
    // version stays, and so does the marker in front of it, pass after pass.
    for day in [4, 6] {
        pass(&store, day).await;
        assert_eq!(
            versions(&store, "held").await,
            [(true, true), (false, false)]
        );
    }
    assert_eq!(
        versions(&store, "held").await,
        [(true, true), (false, false)]
    );
    assert_eq!(versions(&store, "free").await, []);
}

async fn tag_and_size_filters_and_disabled_rules(layout: Layout) {
    let (_dir, store) = bucket(layout, None).await;
    let mut tagged = rule("tagged", "");
    tagged.filter = RuleFilter::Filter(Condition::Tag(Tag {
        key: "tmp".into(),
        value: "yes".into(),
    }));
    tagged.expiration = Some(Expiration::Days(1));
    let mut big = rule("big", "");
    big.filter = RuleFilter::Filter(Condition::GreaterThan(5));
    big.expiration = Some(Expiration::Days(1));
    let mut off = rule("off", "");
    off.enabled = false;
    off.expiration = Some(Expiration::Days(1));
    set_rules(&store, vec![tagged, big, off]).await;
    let tmp = ObjectAttrs {
        tags: [("tmp".to_owned(), "yes".to_owned())].into(),
        ..ObjectAttrs::default()
    };
    store.put_bytes("bkt", "t", b"x", tmp).await.unwrap();
    store
        .put_bytes("bkt", "large", b"123456", ObjectAttrs::default())
        .await
        .unwrap();
    store
        .put_bytes("bkt", "small", b"12345", ObjectAttrs::default())
        .await
        .unwrap();
    pass(&store, 3).await;
    assert!(!exists(&store, "t").await);
    assert!(!exists(&store, "large").await);
    assert!(exists(&store, "small").await);
}

async fn an_object_written_again_is_not_expired(layout: Layout) {
    let (_dir, store) = bucket(layout, None).await;
    let mut all = rule("all", "");
    all.expiration = Some(Expiration::Days(1));
    set_rules(&store, vec![all.clone()]).await;
    put(&store, "a").await;
    let listed = store
        .list_versions(
            "bkt",
            VersionsQuery {
                max_keys: 10,
                ..VersionsQuery::default()
            },
        )
        .await
        .unwrap()
        .versions;
    // Written again, with other bytes, after the job listed it.
    store
        .put_bytes("bkt", "a", b"new and longer", ObjectAttrs::default())
        .await
        .unwrap();
    let job = ApplyLifecycle::new(store.clone());
    let lifecycle = Lifecycle {
        rules: vec![all],
        transition_minimum_size: None,
    };
    let later = jobs::millis(SystemTime::now() + DAY * 3);
    job.apply("bkt", &lifecycle, &listed, later).await.unwrap();
    assert_eq!(store.head("bkt", "a").await.unwrap().size, 14);
}

async fn old_uploads_are_aborted(layout: Layout) {
    let (_dir, store) = bucket(layout, None).await;
    let mut uploads = rule("uploads", "up/");
    uploads.abort_uploads_after_days = Some(2);
    set_rules(&store, vec![uploads]).await;
    let mut ids = Vec::new();
    for key in ["up/a", "other"] {
        let upload = store
            .create_upload(
                "bkt",
                key,
                ObjectAttrs::default(),
                None,
                &Encryption::None,
                None,
                None,
            )
            .await
            .unwrap();
        ids.push(upload.id);
    }
    pass(&store, 1).await;
    assert!(store.upload(&ids[0]).await.is_ok());
    pass(&store, 3).await;
    assert!(matches!(
        store.upload(&ids[0]).await,
        Err(StoreError::NoSuchUpload)
    ));
    assert!(store.upload(&ids[1]).await.is_ok());
}

async fn suspended_buckets_get_a_null_marker(layout: Layout) {
    let (_dir, store) = bucket(layout, Some(Versioning::Enabled)).await;
    put(&store, "a").await;
    store
        .set_bucket_versioning("bkt", Versioning::Suspended)
        .await
        .unwrap();
    put(&store, "a").await;
    let mut all = rule("all", "");
    all.expiration = Some(Expiration::Days(1));
    set_rules(&store, vec![all]).await;
    pass(&store, 2).await;
    // The `null` version is replaced by a `null` delete marker; the older one stays.
    let listed = store
        .list_versions(
            "bkt",
            VersionsQuery {
                max_keys: 10,
                ..VersionsQuery::default()
            },
        )
        .await
        .unwrap()
        .versions;
    let seen: Vec<_> = listed
        .iter()
        .map(|v| {
            (
                v.delete_marker,
                v.info.version_id.as_deref() == Some("null"),
            )
        })
        .collect();
    assert_eq!(seen, [(true, true), (false, false)]);
}

async fn a_key_with_more_versions_than_a_page(layout: Layout) {
    let (_dir, store) = bucket(layout, Some(Versioning::Enabled)).await;
    let mut keep = rule("keep", "");
    keep.filter = RuleFilter::Filter(Condition::Empty);
    keep.noncurrent_expiration = Some(NoncurrentExpiration {
        days: Some(1),
        newer_versions: Some(1),
    });
    set_rules(&store, vec![keep]).await;
    // "a" first, so the first page ends partway through "k"'s versions.
    put(&store, "a").await;
    for _ in 0..jobs::BATCH + 20 {
        put(&store, "k").await;
    }
    // "z" after it, which the pass must still reach.
    for _ in 0..3 {
        put(&store, "z").await;
    }
    pass(&store, 2).await;
    assert_eq!(versions(&store, "k").await, [(false, true), (false, false)]);
    assert_eq!(versions(&store, "z").await, [(false, true), (false, false)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_job_applies_rules_on_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let options = StoreOptions {
        lifecycle_day: Some(Duration::from_millis(200)),
        ..StoreOptions::default()
    };
    let store = Store::open_with(dir.path(), options).unwrap();
    store.create_bucket("bkt", Layout::Object).await.unwrap();
    let mut all = rule("all", "");
    all.expiration = Some(Expiration::Days(1));
    set_rules(&store, vec![all]).await;
    put(&store, "a").await;
    let jobs = store.start_jobs(&JobOptions::default());
    let mut gone = false;
    for _ in 0..100 {
        if !exists(&store, "a").await {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let status = jobs.status();
    jobs.stop().await;
    assert!(gone, "the object never expired: {status:?}");
    assert!(status["lifecycle"].items > 0);
}

async fn noncurrent_days_count_from_the_successor(layout: Layout) {
    let (_dir, store) = bucket(layout, Some(Versioning::Enabled)).await;
    let mut noncurrent = rule("noncurrent", "");
    noncurrent.noncurrent_expiration = Some(NoncurrentExpiration {
        days: Some(3),
        newer_versions: None,
    });
    put(&store, "a").await;
    put(&store, "a").await;
    let mut listed = store
        .list_versions(
            "bkt",
            VersionsQuery {
                max_keys: 10,
                ..VersionsQuery::default()
            },
        )
        .await
        .unwrap()
        .versions;
    // Made ten days ago, but noncurrent only since its successor, made now.
    listed[1].info.modified -= DAY * 10;
    let job = ApplyLifecycle::new(store.clone());
    let lifecycle = Lifecycle {
        rules: vec![noncurrent],
        transition_minimum_size: None,
    };
    let tomorrow = jobs::millis(SystemTime::now() + DAY);
    job.apply("bkt", &lifecycle, &listed, tomorrow)
        .await
        .unwrap();
    assert_eq!(versions(&store, "a").await.len(), 2);
    let later = jobs::millis(SystemTime::now() + DAY * 4);
    job.apply("bkt", &lifecycle, &listed, later).await.unwrap();
    assert_eq!(versions(&store, "a").await.len(), 1);
}

async fn a_recreated_bucket_has_no_rules(layout: Layout) {
    let (_dir, store) = bucket(layout, None).await;
    let mut all = rule("all", "");
    all.expiration = Some(Expiration::Days(1));
    set_rules(&store, vec![all]).await;
    let info = put(&store, "a").await;
    assert!(store.expiry("bkt", &info).await.unwrap().is_some());
    store.delete("bkt", "a").await.unwrap();
    store.delete_bucket("bkt").await.unwrap();
    store.create_bucket("bkt", layout).await.unwrap();
    assert_eq!(store.bucket_lifecycle("bkt").await.unwrap(), None);
    let info = put(&store, "a").await;
    assert_eq!(store.expiry("bkt", &info).await.unwrap(), None);
}

async fn versions_waiting_for_replication_stay(layout: Layout) {
    let (_dir, store) = bucket(layout, Some(Versioning::Enabled)).await;
    let mut all = rule("all", "");
    all.expiration = Some(Expiration::Days(1));
    all.noncurrent_expiration = Some(NoncurrentExpiration {
        days: Some(1),
        newer_versions: None,
    });
    set_rules(&store, vec![all]).await;
    let arn = "arn:aws:s3:::copy";
    for (key, status) in [
        ("pending", ReplicationStatus::Pending),
        ("failed", ReplicationStatus::Failed),
        ("done", ReplicationStatus::Completed),
    ] {
        let version = put(&store, key).await.version_id.unwrap();
        store
            .change_replication("bkt", key, &version, move |_| {
                VersionReplication::pending([arn.to_owned()]).map(|r| r.with(arn, status))
            })
            .await
            .unwrap();
    }
    // A version still to reach its destination, or that couldn't, isn't expired; one
    // that did is.
    pass(&store, 2).await;
    assert_eq!(versions(&store, "pending").await, [(false, true)]);
    assert_eq!(versions(&store, "failed").await, [(false, true)]);
    assert_eq!(
        versions(&store, "done").await,
        [(true, true), (false, false)]
    );
    // Nor is it removed once noncurrent, and the marker in front of it stays.
    let pending = store
        .head("bkt", "pending")
        .await
        .unwrap()
        .version_id
        .unwrap();
    store.delete("bkt", "pending").await.unwrap();
    store
        .change_replication("bkt", "pending", &pending, move |_| {
            VersionReplication::pending([arn.to_owned()])
        })
        .await
        .unwrap();
    for day in [4, 6] {
        pass(&store, day).await;
        assert_eq!(
            versions(&store, "pending").await,
            [(true, true), (false, false)]
        );
    }
    assert_eq!(versions(&store, "done").await, []);
    // Once it gets there, the rules apply.
    store
        .set_replication_status(
            "bkt",
            "pending",
            &pending,
            arn,
            ReplicationStatus::Completed,
        )
        .await
        .unwrap();
    pass(&store, 8).await;
    assert_eq!(versions(&store, "pending").await, []);
    // A delete marker still to reach its destination stays too, alone.
    put(&store, "marked").await;
    let marker = store
        .delete_if("bkt", "marked", None, Precondition::default())
        .await
        .unwrap()
        .version_id
        .unwrap();
    store
        .change_replication("bkt", "marked", &marker, move |_| {
            VersionReplication::pending([arn.to_owned()])
        })
        .await
        .unwrap();
    pass(&store, 10).await;
    assert_eq!(versions(&store, "marked").await, [(true, true)]);
}
