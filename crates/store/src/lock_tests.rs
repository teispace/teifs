//! Object Lock, as S3 does it: a bucket with versioning enabled can lock its versions,
//! and a locked version can't be removed until its retention ends or its legal hold is
//! lifted. The same behaviour in both layouts.

use tempfile::TempDir;

use super::*;
use crate::test_util::in_both_layouts;

in_both_layouts!(
    lock_needs_versioning_enabled_and_keeps_it_on,
    a_retention_keeps_a_version_until_it_ends_or_governance_is_bypassed,
    a_legal_hold_keeps_a_version_until_it_is_lifted,
    new_versions_get_the_default_retention_and_copies_never_inherit_a_lock,
    retention_changes_follow_the_mode,
    a_lock_needs_the_buckets_object_lock,
    an_upload_in_parts_gets_the_default_retention,
);

const DAY_MS: i64 = 86_400_000;

async fn locked(layout: Layout) -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let options = NewBucket {
        object_lock: true,
        ..NewBucket::default()
    };
    store
        .create_bucket_with("vault", layout, options)
        .await
        .unwrap();
    (dir, store)
}

fn with_lock(retention: Option<Retention>, legal_hold: bool) -> ObjectAttrs {
    ObjectAttrs {
        retention,
        legal_hold: legal_hold.then_some(true),
        ..ObjectAttrs::default()
    }
}

fn retention(mode: LockMode, from_now_ms: i64) -> Retention {
    Retention {
        mode,
        until_ms: now_ms() + from_now_ms,
    }
}

async fn put(store: &Store, key: &str, attrs: ObjectAttrs) -> String {
    store
        .put_bytes("vault", key, key.as_bytes(), attrs)
        .await
        .unwrap()
        .version_id
        .unwrap()
}

async fn remove(store: &Store, key: &str, version: &str, bypass: bool) -> Result<Deleted> {
    store
        .delete_with("vault", key, Some(version), Precondition::default(), bypass)
        .await
}

async fn lock_needs_versioning_enabled_and_keeps_it_on(layout: Layout) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("plain", layout).await.unwrap();
    assert_eq!(store.bucket_object_lock("plain").await.unwrap(), None);
    let lock = ObjectLock {
        default_retention: Some(DefaultRetention {
            mode: LockMode::Governance,
            period: RetentionPeriod::Days(1),
        }),
    };
    for versioning in [None, Some(Versioning::Suspended)] {
        if let Some(versioning) = versioning {
            store
                .set_bucket_versioning("plain", versioning)
                .await
                .unwrap();
        }
        assert!(matches!(
            store.set_bucket_object_lock("plain", lock.clone()).await,
            Err(StoreError::InvalidBucketState(_))
        ));
    }
    store
        .set_bucket_versioning("plain", Versioning::Enabled)
        .await
        .unwrap();
    store
        .set_bucket_object_lock("plain", lock.clone())
        .await
        .unwrap();
    assert_eq!(store.bucket_object_lock("plain").await.unwrap(), Some(lock));
    assert!(matches!(
        store
            .set_bucket_versioning("plain", Versioning::Suspended)
            .await,
        Err(StoreError::InvalidBucketState(_))
    ));
    // Enabling it again changes nothing, and is fine.
    store
        .set_bucket_versioning("plain", Versioning::Enabled)
        .await
        .unwrap();

    // A bucket created with it has versioning on and no default retention.
    let (_dir, store) = locked(layout).await;
    assert_eq!(
        store.bucket_versioning("vault").await.unwrap(),
        Versioning::Enabled
    );
    assert_eq!(
        store.bucket_object_lock("vault").await.unwrap(),
        Some(ObjectLock::default())
    );
    assert!(matches!(
        store.bucket_object_lock("missing").await,
        Err(StoreError::NoSuchBucket)
    ));
}

async fn a_retention_keeps_a_version_until_it_ends_or_governance_is_bypassed(layout: Layout) {
    let (_dir, store) = locked(layout).await;
    let governed = with_lock(Some(retention(LockMode::Governance, DAY_MS)), false);
    let v1 = put(&store, "a.txt", governed.clone()).await;
    // Current, then older once replaced: protected either way.
    assert!(matches!(
        remove(&store, "a.txt", &v1, false).await,
        Err(StoreError::ObjectLocked)
    ));
    let v2 = put(&store, "a.txt", ObjectAttrs::default()).await;
    let info = store
        .head_version("vault", "a.txt", Some(&v1))
        .await
        .unwrap();
    assert_eq!(info.attrs.retention, governed.retention);
    assert!(matches!(
        remove(&store, "a.txt", &v1, false).await,
        Err(StoreError::ObjectLocked)
    ));
    // A simple delete only adds a marker, which nothing protects.
    let marker = store
        .delete_if("vault", "a.txt", None, Precondition::default())
        .await;
    let marker = marker.unwrap().version_id.unwrap();
    remove(&store, "a.txt", &marker, false).await.unwrap();
    remove(&store, "a.txt", &v2, false).await.unwrap();
    // Bypassed, governance gives way; then it's gone.
    remove(&store, "a.txt", &v1, true).await.unwrap();
    assert!(matches!(
        store.head("vault", "a.txt").await,
        Err(StoreError::NoSuchKey)
    ));

    // Compliance gives way to nobody, current or older.
    let complied = with_lock(Some(retention(LockMode::Compliance, DAY_MS)), false);
    let c1 = put(&store, "c.txt", complied.clone()).await;
    assert!(matches!(
        remove(&store, "c.txt", &c1, true).await,
        Err(StoreError::ObjectLocked)
    ));
    put(&store, "c.txt", ObjectAttrs::default()).await;
    assert!(matches!(
        remove(&store, "c.txt", &c1, true).await,
        Err(StoreError::ObjectLocked)
    ));
    // Ended, it protects nothing.
    let ended = with_lock(Some(retention(LockMode::Compliance, -1)), false);
    let e1 = put(&store, "e.txt", ended).await;
    remove(&store, "e.txt", &e1, false).await.unwrap();
}

async fn a_legal_hold_keeps_a_version_until_it_is_lifted(layout: Layout) {
    let (_dir, store) = locked(layout).await;
    let v1 = put(&store, "a.txt", with_lock(None, true)).await;
    assert!(matches!(
        remove(&store, "a.txt", &v1, true).await,
        Err(StoreError::ObjectLocked)
    ));
    // Placed on an older version, and lifted there.
    put(&store, "a.txt", ObjectAttrs::default()).await;
    let older = store.head_version("vault", "a.txt", Some(&v1)).await;
    assert_eq!(older.unwrap().attrs.legal_hold, Some(true));
    let info = store
        .set_legal_hold("vault", "a.txt", Some(&v1), false)
        .await
        .unwrap();
    assert_eq!(info.attrs.legal_hold, Some(false));
    remove(&store, "a.txt", &v1, false).await.unwrap();
    // Placed on the current version later.
    let current = store
        .set_legal_hold("vault", "a.txt", None, true)
        .await
        .unwrap()
        .version_id
        .unwrap();
    assert!(matches!(
        remove(&store, "a.txt", &current, true).await,
        Err(StoreError::ObjectLocked)
    ));
}

async fn new_versions_get_the_default_retention_and_copies_never_inherit_a_lock(layout: Layout) {
    let (_dir, store) = locked(layout).await;
    let complied = retention(LockMode::Compliance, 10 * DAY_MS);
    put(&store, "src.txt", with_lock(Some(complied), true)).await;
    store
        .set_bucket_object_lock(
            "vault",
            ObjectLock {
                default_retention: Some(DefaultRetention {
                    mode: LockMode::Governance,
                    period: RetentionPeriod::Days(2),
                }),
            },
        )
        .await
        .unwrap();
    let before = now_ms();
    store
        .put_bytes("vault", "new.txt", b"x", ObjectAttrs::default())
        .await
        .unwrap();
    let after = now_ms();
    let given = store
        .head("vault", "new.txt")
        .await
        .unwrap()
        .attrs
        .retention
        .unwrap();
    assert_eq!(given.mode, LockMode::Governance);
    assert!((before + 2 * DAY_MS..=after + 2 * DAY_MS).contains(&given.until_ms));
    // A write's own retention wins over the default.
    put(&store, "own.txt", with_lock(Some(complied), false)).await;
    let own = store.head("vault", "own.txt").await.unwrap().attrs;
    assert_eq!(own.retention, Some(complied));

    // A copy gets the default, not the source's lock...
    let copy = store
        .copy(
            ("vault", "src.txt"),
            ("vault", "copy.txt"),
            None,
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(copy.attrs.retention.unwrap().mode, LockMode::Governance);
    assert_eq!(copy.attrs.legal_hold, None);
    // ...or the one the request gives it.
    let asked = ObjectAttrs {
        content_type: Some("text/plain".into()),
        ..with_lock(None, true)
    };
    let copy = store
        .copy(
            ("vault", "src.txt"),
            ("vault", "held.txt"),
            Some(asked),
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(copy.attrs.legal_hold, Some(true));
    assert_eq!(copy.attrs.retention.unwrap().mode, LockMode::Governance);
}

async fn retention_changes_follow_the_mode(layout: Layout) {
    let (_dir, store) = locked(layout).await;
    let set = |retention: Option<Retention>, bypass| {
        let store = store.clone();
        async move {
            store
                .set_retention("vault", "a.txt", None, retention, bypass)
                .await
        }
    };
    let gov = retention(LockMode::Governance, DAY_MS);
    put(&store, "a.txt", with_lock(Some(gov), false)).await;
    let shorter = Retention {
        until_ms: gov.until_ms - 1000,
        ..gov
    };
    assert!(matches!(
        set(Some(shorter), false).await,
        Err(StoreError::ObjectLocked)
    ));
    assert!(matches!(
        set(None, false).await,
        Err(StoreError::ObjectLocked)
    ));
    let comp = Retention {
        mode: LockMode::Compliance,
        ..gov
    };
    assert!(matches!(
        set(Some(comp), false).await,
        Err(StoreError::ObjectLocked)
    ));
    set(Some(shorter), true).await.unwrap();
    set(Some(comp), true).await.unwrap();
    let longer = Retention {
        until_ms: comp.until_ms + DAY_MS,
        ..comp
    };
    let info = set(Some(longer), false).await.unwrap();
    assert_eq!(info.attrs.retention, Some(longer));
    for change in [Some(gov), Some(comp), None] {
        assert!(matches!(
            set(change, true).await,
            Err(StoreError::ObjectLocked)
        ));
    }
    assert_eq!(
        store.head("vault", "a.txt").await.unwrap().attrs.retention,
        Some(longer)
    );
    // A delete marker has no retention to set.
    store.delete("vault", "a.txt").await.unwrap();
    assert!(matches!(
        set(Some(longer), false).await,
        Err(StoreError::DeleteMarker { .. })
    ));
}

async fn a_lock_needs_the_buckets_object_lock(layout: Layout) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("plain", layout).await.unwrap();
    store
        .set_bucket_versioning("plain", Versioning::Enabled)
        .await
        .unwrap();
    let gov = retention(LockMode::Governance, DAY_MS);
    for attrs in [with_lock(Some(gov), false), with_lock(None, true)] {
        assert!(matches!(
            store.put_bytes("plain", "a.txt", b"x", attrs.clone()).await,
            Err(StoreError::InvalidRequest(_))
        ));
        assert!(matches!(
            store
                .create_upload(
                    "plain",
                    "big.bin",
                    attrs,
                    None,
                    &Encryption::None,
                    None,
                    None
                )
                .await,
            Err(StoreError::InvalidRequest(_))
        ));
    }
    store
        .put_bytes("plain", "a.txt", b"x", ObjectAttrs::default())
        .await
        .unwrap();
    assert!(matches!(
        store
            .set_retention("plain", "a.txt", None, Some(gov), false)
            .await,
        Err(StoreError::InvalidRequest(_))
    ));
    assert!(matches!(
        store.set_legal_hold("plain", "a.txt", None, true).await,
        Err(StoreError::InvalidRequest(_))
    ));
    assert_eq!(
        store.head("plain", "a.txt").await.unwrap().attrs,
        ObjectAttrs {
            checksums: store.head("plain", "a.txt").await.unwrap().attrs.checksums,
            ..ObjectAttrs::default()
        }
    );
}

async fn an_upload_in_parts_gets_the_default_retention(layout: Layout) {
    let (_dir, store) = locked(layout).await;
    store
        .set_bucket_object_lock(
            "vault",
            ObjectLock {
                default_retention: Some(DefaultRetention {
                    mode: LockMode::Compliance,
                    period: RetentionPeriod::Years(1),
                }),
            },
        )
        .await
        .unwrap();
    let upload = store
        .create_upload(
            "vault",
            "big.bin",
            with_lock(None, true),
            None,
            &Encryption::None,
            None,
            None,
        )
        .await
        .unwrap();
    let mut staged = store.stage().await.unwrap();
    staged.write(b"part").await.unwrap();
    let part = store
        .put_part(&upload.id, 1, staged, std::collections::BTreeMap::new())
        .await
        .unwrap();
    let info = store
        .complete(
            &upload.id,
            vec![(1, part.etag)],
            Precondition::default(),
            CompleteWith::default(),
        )
        .await
        .unwrap();
    assert_eq!(info.attrs.legal_hold, Some(true));
    let given = info.attrs.retention.unwrap();
    assert_eq!(given.mode, LockMode::Compliance);
    assert!(given.until_ms > now_ms() + 364 * DAY_MS);
}

#[tokio::test]
async fn a_folder_in_a_folder_bucket_cant_be_locked() {
    let (_dir, store) = locked(Layout::Folder).await;
    assert!(matches!(
        store
            .put_bytes("vault", "photos/", b"", with_lock(None, true))
            .await,
        Err(StoreError::InvalidRequest(_))
    ));
    store
        .put_bytes("vault", "photos/", b"", ObjectAttrs::default())
        .await
        .unwrap();
    assert!(matches!(
        store.set_legal_hold("vault", "photos/", None, true).await,
        Err(StoreError::InvalidRequest(_))
    ));
}
