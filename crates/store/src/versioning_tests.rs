//! Versioning, as S3 does it: versions stack while it's on, delete markers hide objects
//! without removing them, and a suspended bucket writes `null`. The same behaviour in
//! both layouts: most tests run on an object bucket and on a folder bucket.

use teifs_meta::NULL_VERSION;
use tempfile::TempDir;

use super::*;

/// Runs each test (an `async fn(Layout)`) on an object bucket and on a folder bucket.
macro_rules! in_both_layouts {
    ($($name:ident),* $(,)?) => {$(
        mod $name {
            #[tokio::test]
            async fn object_bucket() {
                super::$name(super::Layout::Object).await;
            }

            #[tokio::test]
            async fn folder_bucket() {
                super::$name(super::Layout::Folder).await;
            }
        }
    )*};
}

in_both_layouts!(
    versions_stack_and_each_stays_readable,
    a_delete_adds_a_marker_and_removing_it_brings_the_object_back,
    suspended_writes_and_deletes_replace_the_null_version,
    copies_make_versions_and_can_restore_one,
    versions_list_in_pages_with_markers_and_common_prefixes,
    a_page_of_delete_markers_doesnt_end_a_listing,
    a_key_with_more_versions_than_a_batch_lists_them_all,
);

async fn versioned(layout: Layout, versioning: Versioning) -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("docs", layout).await.unwrap();
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
    info.version_id.unwrap_or_else(|| NULL_VERSION.to_owned())
}

async fn bytes_of(store: &Store, key: &str, version_id: Option<&str>) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let (_, body) = store.read_with("docs", key, version_id, None).await?;
    let mut out = Vec::new();
    body.unwrap().all().await?.read_to_end(&mut out).await?;
    Ok(out)
}

fn md5_hex(bytes: &[u8]) -> String {
    use md5::{Digest, Md5};
    teifs_types::hex(&Md5::digest(bytes))
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

async fn versions_stack_and_each_stays_readable(layout: Layout) {
    let (dir, store) = versioned(layout, Versioning::Enabled).await;
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
    let stored = data_files(&dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR));
    if layout == Layout::Object {
        // Each version's bytes are a file of its own whose footer names the version, so
        // the index can be rebuilt from the files.
        assert_eq!(stored.len(), 2);
        for id in [&v1, &v2] {
            let named = format!(r#""version":"{id}""#);
            assert!(stored.iter().any(|f| f.contains(&named)));
        }
    } else {
        // The current version is the plain file; the older one is kept, as it was.
        assert_eq!(fs::read(dir.path().join("docs/a.txt")).unwrap(), b"two");
        assert_eq!(stored, ["one"]);
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

async fn a_delete_adds_a_marker_and_removing_it_brings_the_object_back(layout: Layout) {
    let (dir, store) = versioned(layout, Versioning::Enabled).await;
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
    // A conditional delete of what isn't there adds nothing.
    let conditional = Precondition {
        if_match: Some(Match::Any),
        ..Precondition::default()
    };
    let nothing = store.delete_if("docs", "a.txt", None, conditional).await;
    assert_eq!(nothing.unwrap(), Deleted::default());
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
    // Nothing of it is left in the drive's system folder.
    let stores = fs::read_dir(dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR)).unwrap();
    assert_eq!(stores.count(), 0);
}

async fn suspended_writes_and_deletes_replace_the_null_version(layout: Layout) {
    let (_dir, store) = versioned(layout, Versioning::Unversioned).await;
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

async fn copies_make_versions_and_can_restore_one(layout: Layout) {
    let (_dir, store) = versioned(layout, Versioning::Enabled).await;
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
    // The current version can be named as a source too.
    let named = store
        .copy_with(
            ("docs", "a.txt", Some(&v3)),
            ("docs", "b.txt"),
            None,
            Precondition::default(),
            None,
            &Encryption::None,
        )
        .await
        .unwrap();
    assert_eq!(bytes_of(&store, "b.txt", None).await.unwrap(), b"one");
    store
        .delete_if(
            "docs",
            "b.txt",
            named.version_id.as_deref(),
            Precondition::default(),
        )
        .await
        .unwrap();
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

async fn versions_list_in_pages_with_markers_and_common_prefixes(layout: Layout) {
    let (_dir, store) = versioned(layout, Versioning::Enabled).await;
    let a1 = put(&store, "a", b"1").await;
    let a2 = put(&store, "a", b"2").await;
    // Older versions under a common prefix roll up with the current ones.
    put(&store, "dir/x", b"old x").await;
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
async fn folder_buckets_without_versioning_have_only_null_versions() {
    let (_dir, store) = versioned(Layout::Folder, Versioning::Unversioned).await;
    assert_eq!(
        store.bucket_versioning("docs").await.unwrap(),
        Versioning::Unversioned
    );
    let written = store
        .put_bytes("docs", "a.txt", b"one", ObjectAttrs::default())
        .await
        .unwrap();
    assert_eq!(written.version_id, None);
    assert!(
        store
            .head_version("docs", "a.txt", Some(NULL_VERSION))
            .await
            .is_ok()
    );
    let other = "0".repeat(32);
    assert!(matches!(
        store.head_version("docs", "a.txt", Some(&other)).await,
        Err(StoreError::NoSuchVersion)
    ));
    assert_eq!(
        versions(&store).await,
        [("a.txt".into(), NULL_VERSION.into(), true, false)]
    );
    // Another version id names nothing there: nothing is deleted.
    store
        .delete_if("docs", "a.txt", Some(&other), Precondition::default())
        .await
        .unwrap();
    assert!(store.head("docs", "a.txt").await.is_ok());
    // A plain delete removes the file, and keeps nothing.
    store.delete("docs", "a.txt").await.unwrap();
    assert!(versions(&store).await.is_empty());
}

#[tokio::test]
async fn a_folder_made_outside_teifs_can_have_versioning() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("photos")).unwrap();
    fs::write(dir.path().join("photos/a.jpg"), b"old").unwrap();
    let store = Store::open(dir.path()).unwrap();
    store
        .set_bucket_versioning("photos", Versioning::Enabled)
        .await
        .unwrap();
    let v1 = store
        .put_bytes("photos", "a.jpg", b"new", ObjectAttrs::default())
        .await
        .unwrap()
        .version_id
        .unwrap();
    // The file written outside TeiFS was the `null` version; it's kept, with its MD5.
    let old = store
        .head_version("photos", "a.jpg", Some(NULL_VERSION))
        .await
        .unwrap();
    assert_eq!(old.etag, md5_hex(b"old"));
    assert_eq!(
        store.head("photos", "a.jpg").await.unwrap().version_id,
        Some(v1)
    );
    assert_eq!(fs::read(dir.path().join("photos/a.jpg")).unwrap(), b"new");
}

#[tokio::test]
async fn a_file_changed_outside_teifs_is_kept_as_it_is() {
    let (dir, store) = versioned(Layout::Folder, Versioning::Enabled).await;
    let v1 = put(&store, "a.txt", b"one").await;
    // Another program replaces the file: it's no longer version v1, but `null`.
    fs::write(dir.path().join("docs/a.txt"), b"edited").unwrap();
    let head = store.head("docs", "a.txt").await.unwrap();
    assert_eq!(head.version_id.as_deref(), Some(NULL_VERSION));
    let v2 = put(&store, "a.txt", b"two").await;
    assert_eq!(
        bytes_of(&store, "a.txt", Some(NULL_VERSION)).await.unwrap(),
        b"edited"
    );
    let kept = store
        .head_version("docs", "a.txt", Some(NULL_VERSION))
        .await
        .unwrap();
    assert_eq!(kept.etag, md5_hex(b"edited"));
    assert_eq!(
        versions(&store).await,
        [
            ("a.txt".into(), v2, true, false),
            ("a.txt".into(), NULL_VERSION.into(), false, false),
        ]
    );
    // v1 was overwritten in place by the other program: it's gone, not wrong.
    assert!(matches!(
        store.head_version("docs", "a.txt", Some(&v1)).await,
        Err(StoreError::NoSuchVersion)
    ));
}

#[tokio::test]
async fn removing_the_current_version_puts_the_previous_file_back() {
    let (dir, store) = versioned(Layout::Folder, Versioning::Enabled).await;
    let tags = std::collections::BTreeMap::from([("k".to_owned(), "v".to_owned())]);
    let attrs = ObjectAttrs {
        content_type: Some("text/plain".into()),
        tags: tags.clone(),
        ..ObjectAttrs::default()
    };
    let v1 = store
        .put_bytes("docs", "deep/down/a.txt", b"one", attrs)
        .await
        .unwrap();
    let v2 = store
        .put_bytes("docs", "deep/down/a.txt", b"two", ObjectAttrs::default())
        .await
        .unwrap();
    let id = v2.version_id.unwrap();
    store
        .delete_if(
            "docs",
            "deep/down/a.txt",
            Some(&id),
            Precondition::default(),
        )
        .await
        .unwrap();
    // The previous version is the file again, as it was: bytes, ETag, attributes.
    let path = dir.path().join("docs/deep/down/a.txt");
    assert_eq!(fs::read(&path).unwrap(), b"one");
    let head = store.head("docs", "deep/down/a.txt").await.unwrap();
    assert_eq!(head.version_id, v1.version_id);
    assert_eq!(head.etag, v1.etag);
    assert_eq!(head.attrs.tags, tags);
    assert_eq!(head.attrs.content_type.as_deref(), Some("text/plain"));
    assert_eq!(versions(&store).await.len(), 1);
    // A delete leaves a marker and no file; the folders it emptied go too.
    let deleted = store.delete_if("docs", "deep/down/a.txt", None, Precondition::default());
    assert!(deleted.await.unwrap().delete_marker);
    assert!(!dir.path().join("docs/deep").exists());
    // Removing the marker brings the file, and its folders, back.
    let listed = versions(&store).await;
    store
        .delete_if(
            "docs",
            "deep/down/a.txt",
            Some(&listed[0].1),
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"one");
    // Nothing older is left behind in the version store.
    let stored = data_files(&dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR));
    assert!(stored.is_empty());
}

#[tokio::test]
async fn a_suspended_folder_bucket_keeps_versions_that_have_ids() {
    let (dir, store) = versioned(Layout::Folder, Versioning::Unversioned).await;
    put(&store, "a.txt", b"zero").await;
    store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    let v1 = put(&store, "a.txt", b"one").await;
    // The `null` version from before versioning is kept.
    assert_eq!(
        bytes_of(&store, "a.txt", Some(NULL_VERSION)).await.unwrap(),
        b"zero"
    );
    store
        .set_bucket_versioning("docs", Versioning::Suspended)
        .await
        .unwrap();
    // A `null` write keeps v1, and replaces the older `null` version.
    assert_eq!(put(&store, "a.txt", b"two").await, NULL_VERSION);
    let stored = || data_files(&dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR));
    assert_eq!(stored(), ["one"]);
    let null_rows = || {
        let versions_id = store.inner.system().bucket("docs").unwrap().unwrap().id;
        let row = store
            .inner
            .lock()
            .version(&versions_id, "a.txt", NULL_VERSION);
        row.unwrap()
    };
    assert_eq!(null_rows(), None);
    let deleted = store
        .delete_if("docs", "a.txt", None, Precondition::default())
        .await
        .unwrap();
    assert_eq!(deleted.version_id.as_deref(), Some(NULL_VERSION));
    assert!(!dir.path().join("docs/a.txt").exists());
    assert_eq!(
        versions(&store).await,
        [
            ("a.txt".into(), NULL_VERSION.into(), true, true),
            ("a.txt".into(), v1.clone(), false, false),
        ]
    );
    // A `null` write replaces the `null` marker.
    assert_eq!(put(&store, "a.txt", b"three").await, NULL_VERSION);
    assert_eq!(null_rows(), None);
    assert_eq!(stored(), ["one"]);
    assert_eq!(
        versions(&store).await,
        [
            ("a.txt".into(), NULL_VERSION.into(), true, false),
            ("a.txt".into(), v1, false, false),
        ]
    );
}

#[tokio::test]
async fn removing_the_current_file_can_leave_a_delete_marker_current() {
    let (_dir, store) = versioned(Layout::Folder, Versioning::Enabled).await;
    put(&store, "a.txt", b"one").await;
    let marker = store.delete_if("docs", "a.txt", None, Precondition::default());
    let marker = marker.await.unwrap().version_id.unwrap();
    let v2 = put(&store, "a.txt", b"two").await;
    // The marker is an older version now, not the current one.
    let versions_id = store.inner.system().bucket("docs").unwrap().unwrap().id;
    let latest = store.inner.lock().latest_version(&versions_id, "a.txt");
    assert_eq!(latest.unwrap(), None);
    store
        .delete_if("docs", "a.txt", Some(&v2), Precondition::default())
        .await
        .unwrap();
    match store.head("docs", "a.txt").await {
        Err(StoreError::DeleteMarker { version_id, .. }) => {
            assert_eq!(version_id, Some(marker));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_file_created_outside_teifs_is_the_current_version() {
    let (dir, store) = versioned(Layout::Folder, Versioning::Enabled).await;
    let v1 = put(&store, "a.txt", b"one").await;
    store.delete("docs", "a.txt").await.unwrap();
    store
        .set_bucket_versioning("docs", Versioning::Suspended)
        .await
        .unwrap();
    store.delete("docs", "a.txt").await.unwrap();
    // Another program puts a file where the `null` delete marker is current: the file
    // is the `null` version now, and the only current one.
    fs::write(dir.path().join("docs/a.txt"), b"outside").unwrap();
    assert_eq!(bytes_of(&store, "a.txt", None).await.unwrap(), b"outside");
    let listed = versions(&store).await;
    assert_eq!(
        listed[0],
        ("a.txt".into(), NULL_VERSION.into(), true, false)
    );
    assert_eq!(listed.iter().filter(|v| v.2).count(), 1);
    assert_eq!(listed.iter().filter(|v| v.1 == NULL_VERSION).count(), 1);
    assert!(listed.iter().any(|v| v.1 == v1));
    // Where a marker with an id is current, too.
    store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    put(&store, "b.txt", b"one").await;
    store.delete("docs", "b.txt").await.unwrap();
    fs::write(dir.path().join("docs/b.txt"), b"outside").unwrap();
    let listed = versions(&store).await;
    let current: Vec<_> = listed.iter().filter(|v| v.0 == "b.txt" && v.2).collect();
    assert_eq!(
        current,
        [&("b.txt".into(), NULL_VERSION.into(), true, false)]
    );
}

#[tokio::test]
async fn folders_and_failed_writes_make_no_versions() {
    let (dir, store) = versioned(Layout::Folder, Versioning::Enabled).await;
    // A folder key isn't versioned: it's the folder.
    let folder = store
        .put_bytes("docs", "dir/", b"", ObjectAttrs::default())
        .await
        .unwrap();
    assert_eq!(folder.version_id.as_deref(), Some(NULL_VERSION));
    let v1 = put(&store, "a.txt", b"one").await;
    // A write refused by its precondition keeps nothing.
    let mut staged = store.stage().await.unwrap();
    staged.write(b"two").await.unwrap();
    let refused = store
        .commit(
            "docs",
            "a.txt",
            staged,
            ObjectAttrs::default(),
            Precondition {
                if_none_match: Some(Match::Any),
                ..Precondition::default()
            },
        )
        .await;
    assert!(matches!(refused, Err(StoreError::PreconditionFailed)));
    assert_eq!(
        versions(&store).await,
        [
            ("a.txt".into(), v1, true, false),
            ("dir/".into(), NULL_VERSION.into(), true, false),
        ]
    );
    assert!(data_files(&dir.path().join(SYSTEM_DIR).join(BUCKETS_DIR)).is_empty());
    // A bucket with older versions isn't empty, even with no files left.
    store.delete("docs", "dir/").await.unwrap();
    store.delete("docs", "a.txt").await.unwrap();
    assert!(matches!(
        store.delete_bucket("docs").await,
        Err(StoreError::BucketNotEmpty)
    ));
}

async fn a_page_of_delete_markers_doesnt_end_a_listing(layout: Layout) {
    let (_dir, store) = versioned(layout, Versioning::Enabled).await;
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

async fn a_key_with_more_versions_than_a_batch_lists_them_all(layout: Layout) {
    let dir = tempfile::tempdir().unwrap();
    let options = StoreOptions {
        durability: Durability::None,
        ..StoreOptions::default()
    };
    let store = Store::open_with(dir.path(), options).unwrap();
    store.create_bucket("docs", layout).await.unwrap();
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
