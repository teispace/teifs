//! Requests built from hostile strings: whatever a client sends as a prefix, a marker or
//! a key, a folder bucket never shows or opens anything outside its own folder.

use std::{collections::BTreeSet, fs, path::Path};

use proptest::{
    prelude::*,
    test_runner::{Config, TestRunner},
};

use super::*;

/// The files of the bucket under test, by key.
const FILES: [&str; 5] = ["a", "a.txt", "dir/x", "dir/sub/y", "é/z"];

/// Strings that matter to a path: the bucket's own names, what lies beside it and
/// through its links, and dots, joined by slashes into paths or run together.
fn hostile() -> impl Strategy<Value = String> {
    let name = prop::sample::select(vec![
        "",
        ".",
        "..",
        "a",
        "a.txt",
        "dir",
        "sub",
        "x",
        "y",
        "é",
        "z",
        "link",
        "file-link",
        "secret",
        "other",
        "photos",
        ".teifs",
        ".teifs-tmp",
        "%2e%2e",
        "~",
        "\\",
        "\0",
    ]);
    let path = (
        prop::collection::vec(name.clone(), 1..5),
        any::<bool>(),
        0..3usize,
    )
        .prop_map(|(names, folder, cut)| {
            let mut path = names.join("/");
            if folder {
                path.push('/');
            }
            // A prefix can end partway through a name.
            for _ in 0..cut {
                path.pop();
            }
            path
        });
    let pieces = prop::collection::vec(prop_oneof![name, Just("/")], 0..8)
        .prop_map(|pieces| pieces.concat());
    prop_oneof![3 => path, 1 => pieces]
}

fn after() -> impl Strategy<Value = Option<After>> {
    prop_oneof![
        Just(None),
        hostile().prop_map(|key| Some(After::Key(key))),
        hostile().prop_map(|prefix| Some(After::Prefix(prefix))),
    ]
}

fn delimiter() -> impl Strategy<Value = Option<String>> {
    prop::option::of(prop::sample::select(vec!["/", "a", "..", "x/"]).prop_map(str::to_owned))
}

/// Whether `key` is a file of the bucket or a folder on the way to one.
fn inside(key: &str) -> bool {
    FILES
        .iter()
        .any(|file| *file == key || (key.ends_with('/') && file.starts_with(key)))
}

/// A drive with the bucket `photos`, links out of it, a bucket beside it and a secret
/// outside the drive.
async fn drive(outside: &Path) -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("photos", Layout::Folder).await.unwrap();
    store.create_bucket("other", Layout::Folder).await.unwrap();
    for key in FILES {
        store
            .put_bytes("photos", key, b"x", ObjectAttrs::default())
            .await
            .unwrap();
    }
    store
        .put_bytes("other", "secret", b"s", ObjectAttrs::default())
        .await
        .unwrap();
    fs::write(outside.join("secret"), b"s").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside, dir.path().join("photos/link")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), dir.path().join("photos/file-link"))
            .unwrap();
        std::os::unix::fs::symlink(outside, dir.path().join("photos/dir/link")).unwrap();
    }
    (dir, store)
}

fn runner() -> (tokio::runtime::Runtime, TestRunner) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // `PROPTEST_CASES` asks for more, as for every other property test.
    let cases = std::env::var("PROPTEST_CASES").map_or(512, |n| n.parse().unwrap());
    (runtime, TestRunner::new(Config::with_cases(cases)))
}

#[test]
fn listings_stay_inside_a_folder_bucket() {
    let (runtime, mut runner) = runner();
    let outside = tempfile::tempdir().unwrap();
    let (_dir, store) = runtime.block_on(drive(outside.path()));
    runner
        .run(
            &(hostile(), delimiter(), after()),
            |(prefix, delimiter, after)| {
                let query = ListQuery {
                    prefix: prefix.clone(),
                    delimiter,
                    after,
                    max_keys: 1000,
                };
                // A request can be refused, never answered with something outside.
                let Ok(listing) = runtime.block_on(store.list("photos", query)) else {
                    return Ok(());
                };
                for object in &listing.objects {
                    prop_assert!(object.key.starts_with(&prefix), "{:?}", object.key);
                    prop_assert!(inside(&object.key), "listed {:?}", object.key);
                }
                for common in &listing.prefixes {
                    prop_assert!(common.starts_with(&prefix), "{common:?}");
                    prop_assert!(
                        FILES.iter().any(|file| file.starts_with(common.as_str())),
                        "rolled up {common:?}"
                    );
                }
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn reads_stay_inside_a_folder_bucket() {
    let (runtime, mut runner) = runner();
    let outside = tempfile::tempdir().unwrap();
    let (_dir, store) = runtime.block_on(drive(outside.path()));
    runner
        .run(&hostile(), |key| {
            if let Ok(info) = runtime.block_on(store.head("photos", &key)) {
                prop_assert!(inside(&key), "found {key:?}: {info:?}");
            }
            if let Ok((_, body)) = runtime.block_on(store.read("photos", &key)) {
                prop_assert!(inside(&key) && (body.is_some() || key.ends_with('/')));
            }
            Ok(())
        })
        .unwrap();
}

/// Keys a folder bucket can hold too: one to three names, none both a file and a folder.
fn key_set() -> impl Strategy<Value = BTreeSet<String>> {
    let name = prop::sample::select(vec!["a", "b", "ab", "a-b", "a~", "é", "z0"]);
    prop::collection::vec(prop::collection::vec(name, 1..4), 1..20).prop_map(|keys| {
        let mut set = BTreeSet::new();
        for key in keys {
            let key = key.join("/");
            let clashes = set.iter().any(|k: &String| {
                k.starts_with(&format!("{key}/")) || key.starts_with(&format!("{k}/"))
            });
            if !clashes {
                set.insert(key);
            }
        }
        set
    })
}

/// A listing as S3 defines it: keys after `after` under `prefix`, in byte order, each
/// rolled up to its common prefix at the first `delimiter` after the prefix, objects and
/// common prefixes counting alike towards `max`.
fn model(
    keys: &BTreeSet<String>,
    prefix: &str,
    delimiter: Option<&str>,
    after: Option<&After>,
    max: usize,
) -> (Vec<String>, Vec<String>, bool) {
    let (mut objects, mut prefixes, mut taken) = (Vec::new(), Vec::new(), 0);
    let mut last_prefix: Option<String> = None;
    for key in keys {
        let skipped = match after {
            None => false,
            Some(After::Key(marker)) => key <= marker,
            Some(After::Prefix(marker)) => key <= marker || key.starts_with(marker.as_str()),
        };
        if skipped || !key.starts_with(prefix) {
            continue;
        }
        let common = delimiter.filter(|d| !d.is_empty()).and_then(|d| {
            key[prefix.len()..]
                .find(d)
                .map(|at| key[..prefix.len() + at + d.len()].to_owned())
        });
        if common.is_some() && common == last_prefix {
            continue;
        }
        if taken == max {
            return (objects, prefixes, true);
        }
        taken += 1;
        match common {
            Some(common) => {
                last_prefix = Some(common.clone());
                prefixes.push(common);
            }
            None => objects.push(key.clone()),
        }
    }
    (objects, prefixes, false)
}

#[test]
fn listings_follow_s3s_rules_in_both_layouts() {
    let (runtime, mut runner) = runner();
    let keys_and_query = key_set().prop_flat_map(|keys| {
        let known: Vec<String> = keys.iter().cloned().collect();
        let near = prop::sample::select(known).prop_flat_map(|key| {
            (0..=key.len()).prop_map(move |cut| {
                let mut cut = cut;
                while !key.is_char_boundary(cut) {
                    cut -= 1;
                }
                key[..cut].to_owned()
            })
        });
        let prefix = prop_oneof![Just(String::new()), near.clone()];
        let after = prop_oneof![
            Just(None),
            near.clone().prop_map(|k| Some(After::Key(k))),
            near.prop_map(|p| Some(After::Prefix(p))),
        ];
        let delimiter =
            prop::option::of(prop::sample::select(vec!["/", "b", "a/"]).prop_map(str::to_owned));
        (Just(keys), prefix, delimiter, after, 1..6usize)
    });
    let dir = tempfile::tempdir().unwrap();
    // Listings, not durability: nothing synced.
    let options = StoreOptions {
        durability: Durability::None,
        ..StoreOptions::default()
    };
    let store = Store::open_with(dir.path(), options).unwrap();
    let cases = std::sync::atomic::AtomicUsize::new(0);
    runner
        .run(&keys_and_query, |(keys, prefix, delimiter, after, max)| {
            let case = cases.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            runtime.block_on(async {
                for layout in [Layout::Object, Layout::Folder] {
                    let bucket = format!("{layout:?}-{case}").to_lowercase();
                    store.create_bucket(&bucket, layout).await.unwrap();
                    for key in &keys {
                        store
                            .put_bytes(&bucket, key, b"x", ObjectAttrs::default())
                            .await
                            .unwrap();
                    }
                    let query = |after: Option<After>, max_keys| ListQuery {
                        prefix: prefix.clone(),
                        delimiter: delimiter.clone(),
                        after,
                        max_keys,
                    };
                    let page = store
                        .list(&bucket, query(after.clone(), max))
                        .await
                        .unwrap();
                    let names: Vec<String> = page.objects.iter().map(|o| o.key.clone()).collect();
                    let (objects, prefixes, truncated) =
                        model(&keys, &prefix, delimiter.as_deref(), after.as_ref(), max);
                    prop_assert_eq!(
                        (&names, &page.prefixes, page.truncated),
                        (&objects, &prefixes, truncated),
                        "{} after {:?}",
                        bucket,
                        after
                    );
                    // Page after page, the whole listing, each entry once.
                    let (mut all_objects, mut all_prefixes, mut next) =
                        (Vec::new(), Vec::new(), None);
                    for _ in 0..=keys.len() {
                        let page = store.list(&bucket, query(next, max)).await.unwrap();
                        all_objects.extend(page.objects.into_iter().map(|o| o.key));
                        all_prefixes.extend(page.prefixes);
                        next = page.next;
                        if !page.truncated {
                            break;
                        }
                    }
                    let (objects, prefixes, _) =
                        model(&keys, &prefix, delimiter.as_deref(), None, usize::MAX);
                    prop_assert_eq!(
                        (all_objects, all_prefixes),
                        (objects, prefixes),
                        "{} paged",
                        bucket
                    );
                }
                Ok(())
            })
        })
        .unwrap();
}

/// Each key's version ids, newest first.
type Versions = Vec<(String, Vec<String>)>;

/// A versions listing as S3 defines it: versions after the key marker (and after its
/// version marker within that key, or after all of it), rolled up like [`model`]; a key
/// marker that is itself a common prefix resumes after all the prefix holds.
fn versions_model(
    versions: &Versions,
    prefix: &str,
    delimiter: Option<&str>,
    marker: Option<(&str, Option<&str>)>,
    max: usize,
) -> (Vec<(String, String)>, Vec<String>, bool) {
    let (mut listed, mut prefixes, mut taken) = (Vec::new(), Vec::new(), 0);
    let mut last_prefix: Option<String> = None;
    let common_prefix = |key: &str| {
        let d = delimiter.filter(|d| !d.is_empty())?;
        let rest = key.strip_prefix(prefix)?;
        rest.find(d)
            .map(|at| key[..prefix.len() + at + d.len()].to_owned())
    };
    let rolled_up = marker
        .map(|(key, _)| key)
        .filter(|key| common_prefix(key).as_deref() == Some(*key));
    for (key, key_versions) in versions {
        if !key.starts_with(prefix) {
            continue;
        }
        let mut skip = match (marker, rolled_up) {
            (_, Some(common)) if key.as_str() <= common || key.starts_with(common) => continue,
            (Some((marker, _)), _) if key.as_str() < marker => continue,
            // After this version of the key, or after all of it.
            (Some((marker, version)), _) if key == marker => version
                .and_then(|version| key_versions.iter().position(|id| id == version))
                .map_or(key_versions.len(), |at| at + 1),
            _ => 0,
        };
        for id in key_versions {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            let common = common_prefix(key);
            if common.is_some() && common == last_prefix {
                continue;
            }
            if taken == max {
                return (listed, prefixes, true);
            }
            taken += 1;
            match common {
                Some(common) => {
                    last_prefix = Some(common.clone());
                    prefixes.push(common);
                }
                None => listed.push((key.clone(), id.clone())),
            }
        }
    }
    (listed, prefixes, false)
}

/// Writes each key once, then puts (`true`) or deletes as `writes` says, in a versioned
/// bucket; returns each key's versions, newest first.
async fn write_versions(
    store: &Store,
    bucket: &str,
    keys: &BTreeSet<String>,
    writes: &[Vec<bool>],
) -> Versions {
    let mut versions: Versions = Vec::new();
    for (key, later) in keys.iter().zip(writes) {
        let mut key_versions = Vec::new();
        for put in std::iter::once(&true).chain(later) {
            let written = if *put {
                let info = store
                    .put_bytes(bucket, key, b"x", ObjectAttrs::default())
                    .await
                    .unwrap();
                info.version_id.unwrap()
            } else {
                let deleted = store
                    .delete_if(bucket, key, None, Precondition::default())
                    .await
                    .unwrap();
                deleted.version_id.unwrap()
            };
            key_versions.insert(0, written);
        }
        versions.push((key.clone(), key_versions));
    }
    versions
}

type VersionsCase = (
    BTreeSet<String>,
    Vec<Vec<bool>>,
    String,
    Option<String>,
    Option<(String, Option<usize>)>,
    usize,
);

/// Keys, the writes after each one's first, and a versions query: prefix, delimiter,
/// key marker with the index of one of its versions, and page size.
fn versions_case() -> impl Strategy<Value = VersionsCase> {
    key_set().prop_flat_map(|keys| {
        let known: Vec<String> = keys.iter().cloned().collect();
        // After the first write, each later one a put (true) or a delete.
        let writes = prop::collection::vec(prop::collection::vec(any::<bool>(), 0..3), keys.len());
        let near = prop::sample::select(known).prop_flat_map(|key| {
            (0..=key.len()).prop_map(move |cut| {
                let mut cut = cut;
                while !key.is_char_boundary(cut) {
                    cut -= 1;
                }
                key[..cut].to_owned()
            })
        });
        let prefix = prop_oneof![Just(String::new()), near.clone()];
        let marker = prop::option::of((near, prop::option::of(0..4usize)));
        let delimiter =
            prop::option::of(prop::sample::select(vec!["/", "b", "a/"]).prop_map(str::to_owned));
        (Just(keys), writes, prefix, delimiter, marker, 1..6usize)
    })
}

#[test]
fn version_listings_follow_s3s_rules_in_both_layouts() {
    let (runtime, mut runner) = runner();
    let case_strategy = versions_case();
    let dir = tempfile::tempdir().unwrap();
    // Listings, not durability: nothing synced.
    let options = StoreOptions {
        durability: Durability::None,
        ..StoreOptions::default()
    };
    let store = Store::open_with(dir.path(), options).unwrap();
    let cases = std::sync::atomic::AtomicUsize::new(0);
    runner
        .run(
            &case_strategy,
            |(keys, writes, prefix, delimiter, marker, max)| {
                let case = cases.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                runtime.block_on(async {
                    for layout in [Layout::Object, Layout::Folder] {
                        let bucket = format!("v{layout:?}-{case}").to_lowercase();
                        store.create_bucket(&bucket, layout).await.unwrap();
                        store
                            .set_bucket_versioning(&bucket, Versioning::Enabled)
                            .await
                            .unwrap();
                        let versions = write_versions(&store, &bucket, &keys, &writes).await;
                        // A version marker names one of the key's versions, when it has
                        // that many; otherwise it's left out.
                        let marker = marker.as_ref().map(|(key, nth)| {
                            let version = nth.and_then(|nth| {
                                versions
                                    .iter()
                                    .find(|(k, _)| k == key)
                                    .and_then(|(_, v)| v.get(nth).cloned())
                            });
                            (key.clone(), version)
                        });
                        let query = |marker: Option<(String, Option<String>)>, max_keys| {
                            let (key_marker, version_marker) = marker.unzip();
                            VersionsQuery {
                                prefix: prefix.clone(),
                                delimiter: delimiter.clone(),
                                key_marker,
                                version_marker: version_marker.flatten(),
                                max_keys,
                            }
                        };
                        let ids = |page: &VersionListing| -> Vec<(String, String)> {
                            page.versions
                                .iter()
                                .map(|v| (v.info.key.clone(), v.info.version_id.clone().unwrap()))
                                .collect()
                        };
                        let page = store
                            .list_versions(&bucket, query(marker.clone(), max))
                            .await
                            .unwrap();
                        let expected = versions_model(
                            &versions,
                            &prefix,
                            delimiter.as_deref(),
                            marker.as_ref().map(|(k, v)| (k.as_str(), v.as_deref())),
                            max,
                        );
                        prop_assert_eq!(
                            (ids(&page), &page.prefixes, page.truncated),
                            (expected.0, &expected.1, expected.2),
                            "{} after {:?}",
                            bucket,
                            marker
                        );
                        // Page after page, the whole listing, each entry once.
                        let (mut all, mut all_prefixes, mut next) = (Vec::new(), Vec::new(), None);
                        for _ in 0..=keys.len() * 3 {
                            let page = store
                                .list_versions(&bucket, query(next, max))
                                .await
                                .unwrap();
                            all.extend(ids(&page));
                            all_prefixes.extend(page.prefixes);
                            next = page.next;
                            if !page.truncated {
                                break;
                            }
                        }
                        let (listed, prefixes, _) = versions_model(
                            &versions,
                            &prefix,
                            delimiter.as_deref(),
                            None,
                            usize::MAX,
                        );
                        prop_assert_eq!(
                            (all, all_prefixes),
                            (listed, prefixes),
                            "{} paged",
                            bucket
                        );
                    }
                    Ok(())
                })
            },
        )
        .unwrap();
}
