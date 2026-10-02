//! Requests built from hostile strings: whatever a client sends as a prefix, a marker or
//! a key, a folder bucket never shows or opens anything outside its own folder.

use std::{fs, path::Path};

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
    (runtime, TestRunner::new(Config::with_cases(512)))
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
