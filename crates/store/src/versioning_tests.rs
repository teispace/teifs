//! Versioning in object buckets, as S3 does it: versions stack while it's on, delete
//! markers hide objects without removing them, and a suspended bucket writes `null`.

use tempfile::TempDir;

use super::*;

async fn versioned(versioning: Versioning) -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("docs", Layout::Object).await.unwrap();
    if versioning != Versioning::Unversioned {
        store
            .set_bucket_versioning("docs", versioning)
            .await
            .unwrap();
    }
    (dir, store)
}

async fn put(store: &Store, key: &str, bytes: &[u8]) -> String {
    let info = store
        .put_bytes("docs", key, bytes, ObjectAttrs::default())
        .await
        .unwrap();
    info.version_id.unwrap()
}

async fn bytes_of(store: &Store, key: &str, version_id: Option<&str>) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let (_, body) = store.read_with("docs", key, version_id, None).await?;
    let mut out = Vec::new();
    body.unwrap().all().await?.read_to_end(&mut out).await?;
    Ok(out)
}

/// The contents of every data file under `dir`, as text.
fn data_files(dir: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        if entry.path().is_dir() {
            found.extend(data_files(&entry.path()));
        } else {
            found.push(String::from_utf8_lossy(&fs::read(entry.path()).unwrap()).into_owned());
        }
    }
    found
}

/// `(key, version id, latest, delete marker)` of every version, as listed.
async fn versions(store: &Store) -> Vec<(String, String, bool, bool)> {
    let query = VersionsQuery {
        max_keys: 1000,
        ..VersionsQuery::default()
    };
    let listing = store.list_versions("docs", query).await.unwrap();
    listing
        .versions
        .into_iter()
        .map(|v| {
            let id = v.info.version_id.unwrap();
            (v.info.key, id, v.latest, v.delete_marker)
        })
        .collect()
}

#[tokio::test]
async fn versions_stack_and_each_stays_readable() {
    let (dir, store) = versioned(Versioning::Enabled).await;
    assert_eq!(
        store.bucket_versioning("docs").await.unwrap(),
        Versioning::Enabled
    );
    let v1 = put(&store, "a.txt", b"one").await;
    let v2 = put(&store, "a.txt", b"two").await;
    assert_ne!(v1, v2);
    assert!(v1.len() == 32 && v2.len() == 32 && v1 != NULL_VERSION);
    assert_eq!(bytes_of(&store, "a.txt", None).await.unwrap(), b"two");
    assert_eq!(bytes_of(&store, "a.txt", Some(&v1)).await.unwrap(), b"one");
    let head = store
        .head_version("docs", "a.txt", Some(&v1))
        .await
        .unwrap();
    assert_eq!(head.version_id.as_deref(), Some(v1.as_str()));
    assert!(matches!(
        store
            .head_version("docs", "a.txt", Some(NULL_VERSION))
            .await,
        Err(StoreError::NoSuchVersion)
    ));
    assert_eq!(
        versions(&store).await,
        [
            ("a.txt".into(), v2.clone(), true, false),
            ("a.txt".into(), v1.clone(), false, false),
        ]
    );
    // Each version's bytes are a file of its own whose footer names the version, so the
    // index can be rebuilt from the files.
    let footers = data_files(&dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR));
    assert_eq!(footers.len(), 2);
    for id in [&v1, &v2] {
        let named = format!(r#""version":"{id}""#);
        assert!(footers.iter().any(|f| f.contains(&named)));
    }

    // Tags belong to a version.
    let tags = std::collections::BTreeMap::from([("k".to_owned(), "v".to_owned())]);
    store
        .set_tags("docs", "a.txt", Some(&v1), tags.clone())
        .await
        .unwrap();
    assert_eq!(
        store
            .head_version("docs", "a.txt", Some(&v1))
            .await
            .unwrap()
            .attrs
            .tags,
        tags
    );
    assert!(
        store
            .head("docs", "a.txt")
            .await
            .unwrap()
            .attrs
            .tags
            .is_empty()
    );
}

#[tokio::test]
async fn a_delete_adds_a_marker_and_removing_it_brings_the_object_back() {
    let (_dir, store) = versioned(Versioning::Enabled).await;
    let v1 = put(&store, "a.txt", b"one").await;
    let deleted = store
        .delete_if("docs", "a.txt", None, Precondition::default())
        .await
        .unwrap();
    assert!(deleted.delete_marker);
    let marker = deleted.version_id.unwrap();
    // The current version is a marker: reads say so, naming it.
    match store.head("docs", "a.txt").await {
        Err(StoreError::DeleteMarker {
            version_id, named, ..
        }) => {
            assert_eq!(version_id.as_deref(), Some(marker.as_str()));
            assert!(!named);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        store.head_version("docs", "a.txt", Some(&marker)).await,
        Err(StoreError::DeleteMarker { named: true, .. })
    ));
    assert_eq!(bytes_of(&store, "a.txt", Some(&v1)).await.unwrap(), b"one");
    let listing = store.list(
        "docs",
        ListQuery {
            max_keys: 10,
            ..ListQuery::default()
        },
    );
    assert!(listing.await.unwrap().objects.is_empty());
    // Markers stack, and deleting what's already deleted adds another.
    let again = store.delete("docs", "a.txt").await;
    again.unwrap();
    assert_eq!(versions(&store).await.len(), 3);
    // A bucket with only markers left isn't empty.
    assert!(matches!(
        store.delete_bucket("docs").await,
        Err(StoreError::BucketNotEmpty)
    ));

    // Removing the markers by id makes the newest version left current.
    let listed = versions(&store).await;
    for (_, id, _, marker) in &listed {
        if *marker {
            let removed = store
                .delete_if("docs", "a.txt", Some(id), Precondition::default())
                .await
                .unwrap();
            assert_eq!(removed.version_id.as_deref(), Some(id.as_str()));
            assert!(removed.delete_marker);
        }
    }
    assert_eq!(bytes_of(&store, "a.txt", None).await.unwrap(), b"one");
    // Removing a version for good, twice: the second finds nothing, and succeeds.
    for _ in 0..2 {
        let removed = store
            .delete_if("docs", "a.txt", Some(&v1), Precondition::default())
            .await
            .unwrap();
        assert!(!removed.delete_marker);
    }
    assert!(matches!(
        store.head("docs", "a.txt").await,
        Err(StoreError::NoSuchKey)
    ));
    store.delete_bucket("docs").await.unwrap();
}

#[tokio::test]
async fn suspended_writes_and_deletes_replace_the_null_version() {
    let (_dir, store) = versioned(Versioning::Unversioned).await;
    // Written before versioning: `null`, and not named until versioning is set.
    let before = store
        .put_bytes("docs", "a.txt", b"zero", ObjectAttrs::default())
        .await
        .unwrap();
    assert_eq!(before.version_id, None);
    store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    let v1 = put(&store, "a.txt", b"one").await;
    store
        .set_bucket_versioning("docs", Versioning::Suspended)
        .await
        .unwrap();
    assert_eq!(put(&store, "a.txt", b"two").await, NULL_VERSION);
    assert_eq!(put(&store, "a.txt", b"three").await, NULL_VERSION);
    assert_eq!(
        versions(&store).await,
        [
            ("a.txt".into(), NULL_VERSION.into(), true, false),
            ("a.txt".into(), v1.clone(), false, false),
        ]
    );
    let deleted = store
        .delete_if("docs", "a.txt", None, Precondition::default())
        .await
        .unwrap();
    assert_eq!(deleted.version_id.as_deref(), Some(NULL_VERSION));
    assert!(deleted.delete_marker);
    assert_eq!(
        versions(&store).await,
        [
            ("a.txt".into(), NULL_VERSION.into(), true, true),
            ("a.txt".into(), v1.clone(), false, false),
        ]
    );
    // Versioning never goes back to off.
    assert!(matches!(
        store
            .set_bucket_versioning("docs", Versioning::Unversioned)
            .await,
        Err(StoreError::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn copies_make_versions_and_can_restore_one() {
    let (_dir, store) = versioned(Versioning::Enabled).await;
    let v1 = put(&store, "a.txt", b"one").await;
    let v2 = put(&store, "a.txt", b"two").await;
    // Copying an old version onto its key restores it as a new version.
    let restored = store
        .copy_with(
            ("docs", "a.txt", Some(&v1)),
            ("docs", "a.txt"),
            None,
            Precondition::default(),
            None,
            &Encryption::None,
        )
        .await
        .unwrap();
    let v3 = restored.version_id.unwrap();
    assert!(v3 != v1 && v3 != v2);
    assert_eq!(bytes_of(&store, "a.txt", None).await.unwrap(), b"one");
    // A copy onto itself with new metadata is a new version too, and the old ones stay.
    let attrs = ObjectAttrs {
        content_type: Some("text/plain".into()),
        ..ObjectAttrs::default()
    };
    let copied = store
        .copy(
            ("docs", "a.txt"),
            ("docs", "a.txt"),
            Some(attrs),
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_ne!(copied.version_id.as_deref(), Some(v3.as_str()));
    assert_eq!(versions(&store).await.len(), 4);
    assert_eq!(bytes_of(&store, "a.txt", Some(&v2)).await.unwrap(), b"two");
    assert!(matches!(
        store
            .copy(
                ("docs", "a.txt"),
                ("docs", "a.txt"),
                None,
                Precondition::default()
            )
            .await,
        Err(StoreError::InvalidRequest(_))
    ));
    // A copy of a version that isn't there, or of a delete marker, fails.
    assert!(matches!(
        store
            .copy_with(
                ("docs", "a.txt", Some(&"0".repeat(32))),
                ("docs", "b.txt"),
                None,
                Precondition::default(),
                None,
                &Encryption::None,
            )
            .await,
        Err(StoreError::NoSuchVersion)
    ));
    // Renames move rows, which versions can't follow.
    assert!(matches!(
        store
            .rename(
                "docs",
                "a.txt",
                "b.txt",
                Precondition::default(),
                Precondition::default(),
                None
            )
            .await,
        Err(StoreError::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn versions_list_in_pages_with_markers_and_common_prefixes() {
    let (_dir, store) = versioned(Versioning::Enabled).await;
    let a1 = put(&store, "a", b"1").await;
    let a2 = put(&store, "a", b"2").await;
    put(&store, "dir/x", b"x").await;
    put(&store, "dir/y", b"y").await;
    let c = store.delete("docs", "e").await;
    c.unwrap();
    let page = |key_marker: Option<&str>, version_marker: Option<&str>, max_keys| VersionsQuery {
        delimiter: Some("/".into()),
        key_marker: key_marker.map(Into::into),
        version_marker: version_marker.map(Into::into),
        max_keys,
        ..VersionsQuery::default()
    };
    let first = store
        .list_versions("docs", page(None, None, 1))
        .await
        .unwrap();
    assert_eq!(
        first.versions[0].info.version_id.as_deref(),
        Some(a2.as_str())
    );
    assert!(first.truncated);
    assert_eq!(first.next, Some(("a".into(), Some(a2.clone()))));
    let second = store
        .list_versions("docs", page(Some("a"), Some(&a2), 2))
        .await
        .unwrap();
    assert_eq!(
        second.versions[0].info.version_id.as_deref(),
        Some(a1.as_str())
    );
    assert_eq!(second.prefixes, ["dir/"]);
    assert_eq!(second.next, Some(("dir/".into(), None)));
    let third = store
        .list_versions("docs", page(Some("dir/"), None, 2))
        .await
        .unwrap();
    assert!(!third.truncated && third.next.is_none());
    assert_eq!(third.versions.len(), 1);
    assert!(third.versions[0].delete_marker && third.versions[0].latest);
    assert_eq!(third.versions[0].info.key, "e");
    // Past all of a key's versions.
    let after_a = store
        .list_versions("docs", page(Some("a"), None, 10))
        .await
        .unwrap();
    assert_eq!(after_a.prefixes, ["dir/"]);
}

#[tokio::test]
async fn folder_buckets_have_only_null_versions() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("files", Layout::Folder).await.unwrap();
    assert!(matches!(
        store
            .set_bucket_versioning("files", Versioning::Enabled)
            .await,
        Err(StoreError::NotImplemented(_))
    ));
    assert_eq!(
        store.bucket_versioning("files").await.unwrap(),
        Versioning::Unversioned
    );
    store
        .put_bytes("files", "a.txt", b"one", ObjectAttrs::default())
        .await
        .unwrap();
    assert!(
        store
            .head_version("files", "a.txt", Some(NULL_VERSION))
            .await
            .is_ok()
    );
    assert!(matches!(
        store
            .head_version("files", "a.txt", Some(&"0".repeat(32)))
            .await,
        Err(StoreError::NoSuchVersion)
    ));
    let query = VersionsQuery {
        max_keys: 10,
        ..VersionsQuery::default()
    };
    let listing = store.list_versions("files", query).await.unwrap();
    assert_eq!(listing.versions.len(), 1);
    assert_eq!(
        listing.versions[0].info.version_id.as_deref(),
        Some(NULL_VERSION)
    );
    // Another version id names nothing there: nothing is deleted.
    let other = "0".repeat(32);
    store
        .delete_if("files", "a.txt", Some(&other), Precondition::default())
        .await
        .unwrap();
    assert!(store.head("files", "a.txt").await.is_ok());
}

#[tokio::test]
async fn a_page_of_delete_markers_doesnt_end_a_listing() {
    let (_dir, store) = versioned(Versioning::Enabled).await;
    for key in ["a", "b", "c", "d"] {
        put(&store, key, b"gone").await;
        store.delete("docs", key).await.unwrap();
    }
    put(&store, "e", b"here").await;
    // Each batch the index reads holds only delete markers until the last.
    let query = ListQuery {
        max_keys: 1,
        ..ListQuery::default()
    };
    let listing = store.list("docs", query).await.unwrap();
    let keys: Vec<_> = listing.objects.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["e"]);
    assert!(!listing.truncated);
}

#[tokio::test]
async fn a_key_with_more_versions_than_a_batch_lists_them_all() {
    let dir = tempfile::tempdir().unwrap();
    let options = StoreOptions {
        durability: Durability::None,
        ..StoreOptions::default()
    };
    let store = Store::open_with(dir.path(), options).unwrap();
    store.create_bucket("docs", Layout::Object).await.unwrap();
    store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    // Delete markers: versions without files, so many are quick to make.
    for _ in 0..1001 {
        store.delete("docs", "a").await.unwrap();
    }
    store.delete("docs", "b").await.unwrap();
    let query = VersionsQuery {
        max_keys: 2000,
        ..VersionsQuery::default()
    };
    let listing = store.list_versions("docs", query).await.unwrap();
    assert_eq!(listing.versions.len(), 1002);
    assert!(!listing.truncated);
    let latest = listing.versions.iter().filter(|v| v.latest).count();
    assert_eq!(latest, 2);
}
