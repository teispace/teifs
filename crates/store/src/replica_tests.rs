//! Replicas: a version written as a copy of another keeps its id and creation time, is
//! marked a replica and never replicated again, is written once however often it's
//! sent, and only goes where versions are kept.

use std::time::{Duration, UNIX_EPOCH};

use teifs_types::replication::{
    ReplicationConfig, ReplicationDestination, ReplicationFilter, ReplicationRule,
    ReplicationStatus,
};

use super::*;

const VERSION: &str = "0192f0a1b2c37d4e8f90a1b2c3d4e5f6";
const MODIFIED_MS: i64 = 1_700_000_000_123;
/// A multipart upload's ETag: not the replica's bytes' MD5.
const ETAG: &str = "9b2cf535f27731c974343645a3985328-2";

fn replica() -> Replica {
    Replica {
        version_id: VERSION.to_owned(),
        modified_ms: MODIFIED_MS,
        etag: Some(ETAG.to_owned()),
    }
}

async fn send(store: &Store, bucket: &str, bytes: &[u8]) -> Result<ObjectInfo> {
    let mut staged = store.stage();
    staged.write(bytes).await?;
    store
        .commit_replica(bucket, "a.txt", staged, ObjectAttrs::default(), replica())
        .await
}

/// Replicates everything in `bucket` to `to`.
fn everything_to(to: &str) -> ReplicationConfig {
    ReplicationConfig {
        role: String::new(),
        rules: vec![ReplicationRule {
            id: "r".to_owned(),
            priority: Some(1),
            enabled: true,
            filter: ReplicationFilter::All,
            delete_markers: Some(true),
            delete_replication: None,
            existing_objects: None,
            sse_kms_objects: None,
            replica_modifications: None,
            destination: ReplicationDestination {
                bucket: format!("arn:aws:s3:::{to}"),
                account: None,
                storage_class: None,
                owner_override: false,
                encryption: None,
                replication_time: None,
                metrics: None,
            },
        }],
    }
}

#[tokio::test]
async fn a_replica_keeps_its_versions_id_and_time_and_is_never_sent_on() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    for bucket in ["copy", "further"] {
        store.create_bucket(bucket, Layout::Object).await.unwrap();
        store
            .set_bucket_versioning(bucket, Versioning::Enabled)
            .await
            .unwrap();
    }
    // The destination replicates too: a replica isn't sent on (no chains).
    store
        .set_bucket_replication("copy", Some(everything_to("further")))
        .await
        .unwrap();
    let info = send(&store, "copy", b"hello").await.unwrap();
    assert_eq!(info.version_id.as_deref(), Some(VERSION));
    assert_eq!(info.etag, ETAG);
    assert_eq!(
        info.modified,
        UNIX_EPOCH + Duration::from_millis(MODIFIED_MS.try_into().unwrap())
    );
    let head = store
        .head_version("copy", "a.txt", Some(VERSION))
        .await
        .unwrap();
    assert_eq!(
        head.attrs.replication.map(|r| r.status),
        Some(ReplicationStatus::Replica)
    );
    // A new version written there the ordinary way is replicated.
    let own = store
        .put_bytes("copy", "b.txt", b"mine", ObjectAttrs::default())
        .await
        .unwrap();
    assert_eq!(
        own.attrs.replication.map(|r| r.status),
        Some(ReplicationStatus::Pending)
    );

    // Sent again (a retry), it's the one already there.
    let again = send(&store, "copy", b"hello").await.unwrap();
    assert_eq!(again.version_id.as_deref(), Some(VERSION));
    let versions = store
        .list_versions(
            "copy",
            VersionsQuery {
                max_keys: 1000,
                ..VersionsQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        versions
            .versions
            .iter()
            .filter(|v| v.info.key == "a.txt")
            .count(),
        1
    );
}

#[tokio::test]
async fn replicas_go_only_where_versions_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("plain", Layout::Object).await.unwrap();
    store.create_bucket("files", Layout::Folder).await.unwrap();
    for bucket in ["plain", "files"] {
        assert!(
            matches!(
                send(&store, bucket, b"hello").await,
                Err(StoreError::InvalidRequest(_))
            ),
            "{bucket}"
        );
    }
}

#[tokio::test]
async fn a_folder_bucket_keeps_a_replicas_version_as_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("files", Layout::Folder).await.unwrap();
    store
        .set_bucket_versioning("files", Versioning::Enabled)
        .await
        .unwrap();
    let time = |ms: i64| UNIX_EPOCH + Duration::from_millis(ms.try_into().unwrap());

    // An older version first, then the version replica() names.
    let older = Replica {
        version_id: "7bdae243-adae-45de-9ccf-602e9882190d".to_owned(),
        modified_ms: MODIFIED_MS - 60_000,
        etag: None,
    };
    let mut staged = store.stage();
    staged.write(b"old").await.unwrap();
    store
        .commit_replica(
            "files",
            "a.txt",
            staged,
            ObjectAttrs::default(),
            older.clone(),
        )
        .await
        .unwrap();
    let info = send(&store, "files", b"hello").await.unwrap();
    assert_eq!(info.version_id.as_deref(), Some(VERSION));
    assert_eq!(info.etag, ETAG);
    assert_eq!(info.modified, time(MODIFIED_MS));
    // The file is the version, its time the version's.
    let file = dir.path().join("files").join("a.txt");
    assert_eq!(std::fs::read(&file).unwrap(), b"hello");
    assert_eq!(
        std::fs::metadata(&file).unwrap().modified().unwrap(),
        time(MODIFIED_MS)
    );
    let head = store.head_version("files", "a.txt", None).await.unwrap();
    assert_eq!(head.version_id.as_deref(), Some(VERSION));
    assert_eq!(
        head.attrs.replication.map(|r| r.status),
        Some(ReplicationStatus::Replica)
    );
    let old = store
        .head_version("files", "a.txt", Some(&older.version_id))
        .await
        .unwrap();
    assert_eq!((old.size, old.modified), (3, time(older.modified_ms)));

    // Sent again, nothing changes.
    let again = send(&store, "files", b"hello").await.unwrap();
    assert_eq!(again.version_id.as_deref(), Some(VERSION));
    let versions = store
        .list_versions(
            "files",
            VersionsQuery {
                max_keys: 1000,
                ..VersionsQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(versions.versions.len(), 2);

    // A folder has no versions to keep.
    let staged = store.stage();
    let folder = store
        .commit_replica("files", "dir/", staged, ObjectAttrs::default(), older)
        .await;
    assert!(
        matches!(folder, Err(StoreError::InvalidRequest(_))),
        "{folder:?}"
    );
}

#[tokio::test]
async fn markers_people_make_are_replicated_and_lifecycles_arent() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    for bucket in ["source", "copy"] {
        store.create_bucket(bucket, Layout::Object).await.unwrap();
        store
            .set_bucket_versioning(bucket, Versioning::Enabled)
            .await
            .unwrap();
    }
    store
        .set_bucket_replication("source", Some(everything_to("copy")))
        .await
        .unwrap();
    let status = |id: Option<String>| {
        let store = store.clone();
        async move {
            let waiting = store.waiting_replication("source", 100).await.unwrap();
            waiting
                .into_iter()
                .find(|w| Some(&w.version_id) == id.as_ref())
                .map(|w| (w.delete_marker, w.destinations))
        }
    };
    let marked = store
        .delete_with("source", "a.txt", None, Precondition::default(), false)
        .await
        .unwrap();
    assert_eq!(
        status(marked.version_id).await,
        Some((true, vec!["arn:aws:s3:::copy".to_owned()]))
    );
    let expired = store
        .delete_marking(
            "source",
            "b.txt",
            None,
            Precondition::default(),
            (false, Marking::Lifecycle),
        )
        .await
        .unwrap();
    assert!(expired.delete_marker);
    assert_eq!(status(expired.version_id).await, None);

    // The marker arrives with its id and time, once however often it's sent.
    let replica = Replica {
        version_id: VERSION.to_owned(),
        modified_ms: MODIFIED_MS,
        etag: None,
    };
    for _ in 0..2 {
        let made = store
            .commit_replica_marker("copy", "a.txt", replica.clone())
            .await
            .unwrap();
        assert_eq!(made.version_id.as_deref(), Some(VERSION));
    }
    let versions = store
        .list_versions(
            "copy",
            VersionsQuery {
                max_keys: 1000,
                ..VersionsQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(versions.versions.len(), 1);
    let made = &versions.versions[0];
    assert!(made.delete_marker);
    assert_eq!(
        made.info.modified,
        UNIX_EPOCH + Duration::from_millis(MODIFIED_MS.try_into().unwrap())
    );
    assert_eq!(
        made.info.attrs.replication.as_ref().map(|r| r.status),
        Some(ReplicationStatus::Replica)
    );
}

#[tokio::test]
async fn removals_people_make_are_queued_as_the_rules_say_in_either_layout() {
    for layout in [Layout::Object, Layout::Folder] {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.create_bucket("source", layout).await.unwrap();
        store
            .set_bucket_versioning("source", Versioning::Enabled)
            .await
            .unwrap();
        let mut config = everything_to("copy");
        config.rules[0].delete_replication = Some(true);
        store
            .set_bucket_replication("source", Some(config.clone()))
            .await
            .unwrap();
        let put = |key: &'static str| {
            let store = store.clone();
            async move {
                store
                    .put_bytes("source", key, b"hello", ObjectAttrs::default())
                    .await
                    .unwrap()
                    .version_id
                    .unwrap()
            }
        };
        let remove = |key: &'static str, id: String, marking: Marking| {
            let store = store.clone();
            async move {
                store
                    .delete_marking(
                        "source",
                        key,
                        Some(&id),
                        Precondition::default(),
                        (false, marking),
                    )
                    .await
                    .unwrap();
                id
            }
        };
        let (older, current) = (put("a.txt").await, put("a.txt").await);
        // An older version (a row in either layout), then the current one (a file in a
        // folder bucket).
        let older = remove("a.txt", older, Marking::Request).await;
        let current = remove("a.txt", current, Marking::Request).await;
        // Neither lifecycle's removals nor replicated ones are sent on.
        let expired = put("b.txt").await;
        remove("b.txt", expired, Marking::Lifecycle).await;
        let replicated = put("b.txt").await;
        store
            .delete_replicated_version("source", "b.txt", &replicated)
            .await
            .unwrap();
        let copy = vec!["arn:aws:s3:::copy".to_owned()];
        let queued = |key: &str, version_id: &str, delete_marker| QueuedDelete {
            key: key.to_owned(),
            version_id: version_id.to_owned(),
            delete_marker,
            destinations: copy.clone(),
        };
        assert_eq!(
            store.waiting_removals("source", 100).await.unwrap(),
            [
                queued("a.txt", &older, false),
                queued("a.txt", &current, false)
            ],
            "{layout:?}"
        );
        for id in [&older, &current] {
            store
                .set_removal_destinations("source", "a.txt", id, Vec::new())
                .await
                .unwrap();
        }
        assert!(
            store
                .waiting_removals("source", 100)
                .await
                .unwrap()
                .is_empty()
        );

        // Without `DeleteReplication`, a version's removal stays here, but a marker's
        // follows the marker.
        config.rules[0].delete_replication = None;
        store
            .set_bucket_replication("source", Some(config))
            .await
            .unwrap();
        let version = put("c.txt").await;
        remove("c.txt", version, Marking::Request).await;
        let marker = store
            .delete_with("source", "c.txt", None, Precondition::default(), false)
            .await
            .unwrap()
            .version_id
            .unwrap();
        let marker = remove("c.txt", marker, Marking::Request).await;
        assert_eq!(
            store.waiting_removals("source", 100).await.unwrap(),
            [queued("c.txt", &marker, true)],
            "{layout:?}"
        );
    }
}
