//! Drive sets: objects erasure-coded across drives, read back with drives lost, the
//! metadata's copies, and sets reopened in any order or with drives down.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use tempfile::TempDir;
use tokio::io::AsyncReadExt;

use super::*;

struct Set {
    _dir: TempDir,
    _keys: TempDir,
    drives: Vec<PathBuf>,
    kms: Arc<LocalKms>,
}

impl Set {
    fn new(n: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let drives = (0..n)
            .map(|i| {
                let d = dir.path().join(format!("d{i}"));
                std::fs::create_dir(&d).unwrap();
                d
            })
            .collect();
        let kms = Arc::new(LocalKms::open(keys.path().join("keyring.json")).unwrap());
        Self {
            _dir: dir,
            _keys: keys,
            drives,
            kms,
        }
    }

    fn options(&self) -> StoreOptions {
        StoreOptions {
            kms: Some(self.kms.clone()),
            // Every object in shard files, so the tests see them.
            inline_max: Some(0),
            ..StoreOptions::default()
        }
    }

    fn open(&self, drives: &[PathBuf]) -> Result<Store> {
        Store::open_set(drives, SetOptions::default(), self.options())
    }

    fn open_all(&self) -> Store {
        self.open(&self.drives).unwrap()
    }

    /// Loses drive `i`: its folder goes (as a dead disk's mount point would be empty,
    /// or gone).
    fn lose(&self, i: usize) {
        std::fs::remove_dir_all(&self.drives[i]).unwrap();
    }

    /// Damages drive `i`'s shards of every object: the shards are cut in half.
    fn damage_shards(&self, i: usize) {
        for shard in files(&self.drives[i].join(SYSTEM_DIR).join(BUCKETS_DIR)) {
            let len = std::fs::metadata(&shard).unwrap().len();
            std::fs::OpenOptions::new()
                .write(true)
                .open(&shard)
                .unwrap()
                .set_len(len / 2)
                .unwrap();
        }
    }
}

fn files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .map(|e| e.unwrap().path())
                .flat_map(|p| if p.is_dir() { files(&p) } else { vec![p] })
                .collect()
        },
    )
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 7 + usize::from(seed)) % 251).unwrap())
        .collect()
}

async fn read(store: &Store, key: &str) -> Result<Vec<u8>> {
    let (_, body) = store.read("docs", key).await?;
    let mut out = Vec::new();
    body.unwrap().all().await?.read_to_end(&mut out).await?;
    Ok(out)
}

async fn read_range(store: &Store, key: &str, start: u64, len: u64) -> Vec<u8> {
    let (_, body) = store.read("docs", key).await.unwrap();
    let mut out = Vec::new();
    body.unwrap()
        .range(start, len)
        .await
        .unwrap()
        .read_to_end(&mut out)
        .await
        .unwrap();
    out
}

async fn put_encrypted(store: &Store, key: &str, bytes: &[u8]) {
    let mut staged = store.stage_for("docs", &Encryption::S3).await.unwrap();
    staged.write(bytes).await.unwrap();
    store
        .commit(
            "docs",
            key,
            staged,
            ObjectAttrs::default(),
            Precondition::default(),
        )
        .await
        .unwrap();
}

/// Sizes around the block (1 MiB) and piece boundaries.
const SIZES: [usize; 6] = [0, 1, 4097, (1 << 20) - 1, 1 << 20, (3 << 20) + 5];

#[tokio::test]
async fn objects_are_shards_on_every_drive_and_read_back() {
    let set = Set::new(4);
    let store = set.open_all();
    let info = store.drive_set().unwrap();
    assert_eq!((info.data, info.parity), (2, 2));
    store.create_bucket("docs", Layout::Object).await.unwrap();
    for (i, size) in SIZES.iter().enumerate() {
        let bytes = pattern(*size, u8::try_from(i).unwrap());
        store
            .put_bytes(
                "docs",
                &format!("plain/{i}"),
                &bytes,
                ObjectAttrs::default(),
            )
            .await
            .unwrap();
        put_encrypted(&store, &format!("sealed/{i}"), &bytes).await;
    }
    for drive in &set.drives {
        let shards = files(&drive.join(SYSTEM_DIR).join(BUCKETS_DIR));
        assert_eq!(shards.len(), SIZES.len() * 2, "{}", drive.display());
        for shard in shards {
            let head = std::fs::read(&shard).unwrap();
            assert_eq!(&head[..4], b"TFSS", "{}", shard.display());
        }
    }
    for (i, size) in SIZES.iter().enumerate() {
        let bytes = pattern(*size, u8::try_from(i).unwrap());
        assert_eq!(read(&store, &format!("plain/{i}")).await.unwrap(), bytes);
        assert_eq!(read(&store, &format!("sealed/{i}")).await.unwrap(), bytes);
    }
    let big = pattern(SIZES[5], 5);
    for (start, len) in [(0u64, 10u64), ((1 << 20) - 3, 10), (2 << 20, 70_000)] {
        let want = &big[usize::try_from(start).unwrap()..][..usize::try_from(len).unwrap()];
        assert_eq!(read_range(&store, "plain/5", start, len).await, want);
    }
    // Deleting removes every drive's shards.
    store.delete("docs", "plain/5").await.unwrap();
    for drive in &set.drives {
        let shards = files(&drive.join(SYSTEM_DIR).join(BUCKETS_DIR));
        assert_eq!(shards.len(), SIZES.len() * 2 - 1);
    }
}

#[tokio::test]
async fn losing_parity_drives_loses_nothing_and_one_more_is_refused() {
    let set = Set::new(4);
    let bytes = pattern((2 << 20) + 11, 3);
    {
        let store = set.open_all();
        store.create_bucket("docs", Layout::Object).await.unwrap();
        store
            .put_bytes("docs", "a", &bytes, ObjectAttrs::default())
            .await
            .unwrap();
        put_encrypted(&store, "b", &bytes).await;
        // Damaged shards on two drives, while the set runs: read around.
        set.damage_shards(1);
        set.damage_shards(2);
        assert_eq!(read(&store, "a").await.unwrap(), bytes);
        assert_eq!(read(&store, "b").await.unwrap(), bytes);
    }
    // Two drives gone (the most a 2+2 set can lose): the set opens and reads.
    set.lose(1);
    set.lose(2);
    let store = set.open(&set.drives).unwrap();
    let info = store.drive_set().unwrap();
    assert_eq!(info.drives.iter().filter(|d| d.is_none()).count(), 2);
    assert_eq!(read(&store, "a").await.unwrap(), bytes);
    assert_eq!(read(&store, "b").await.unwrap(), bytes);
    // Writes need three drives: refused, and nothing is left behind.
    match store
        .put_bytes("docs", "c", b"no", ObjectAttrs::default())
        .await
    {
        Err(StoreError::Quorum {
            found: 2,
            needed: 3,
        }) => {}
        other => panic!("expected Quorum, got {other:?}"),
    }
    assert_eq!(
        files(&set.drives[0].join(SYSTEM_DIR).join(BUCKETS_DIR)).len(),
        2
    );
    drop(store);
    // A third drive's shards damaged too: too few to read.
    set.damage_shards(3);
    let store = set.open(&set.drives).unwrap();
    // The headers still agree, so the read starts, and stops at the first block it
    // can't rebuild (a client sees the body cut short, never wrong bytes).
    match read(&store, "a").await {
        Err(StoreError::Io(err)) => assert!(err.to_string().contains("only 1 of the 2")),
        other => panic!("expected an I/O error, got {other:?}"),
    }
}

#[tokio::test]
async fn writes_made_with_a_drive_down_survive_losing_another_after() {
    let set = Set::new(4);
    let first = pattern(70_000, 1);
    let second = pattern(1_500_000, 2);
    {
        let store = set.open_all();
        store.create_bucket("docs", Layout::Object).await.unwrap();
        store
            .put_bytes("docs", "first", &first, ObjectAttrs::default())
            .await
            .unwrap();
    }
    // Drive 3 is away for a while (unplugged), and the set carries on.
    let away = set.drives[3].with_extension("away");
    std::fs::rename(&set.drives[3], &away).unwrap();
    {
        let store = set.open(&set.drives).unwrap();
        store
            .put_bytes("docs", "second", &second, ObjectAttrs::default())
            .await
            .unwrap();
        store.delete("docs", "first").await.unwrap();
        put_encrypted(&store, "first", &second).await;
    }
    std::fs::rename(&away, &set.drives[3]).unwrap();
    // Drive 3 is back (its metadata is behind and is rebuilt) and drive 0 dies: in any
    // order, the set knows every change.
    set.lose(0);
    let drives = vec![
        set.drives[3].clone(),
        set.drives[0].clone(),
        set.drives[2].clone(),
        set.drives[1].clone(),
    ];
    let store = set.open(&drives).unwrap();
    assert_eq!(read(&store, "second").await.unwrap(), second);
    assert_eq!(read(&store, "first").await.unwrap(), second);
    let listing = store
        .list(
            "docs",
            ListQuery {
                max_keys: 10,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    let keys: Vec<_> = listing.objects.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["first", "second"]);
    // The copy of the index on drive 3 caught up: with drive 1 gone too, drives 2 and
    // 3 still know every object (though those written while drive 3 was away have one
    // shard left until they're healed).
    drop(store);
    set.lose(1);
    let store = set.open(&set.drives).unwrap();
    let listing = store
        .list(
            "docs",
            ListQuery {
                max_keys: 10,
                ..ListQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(listing.objects.len(), 2);
    assert!(matches!(
        read(&store, "second").await,
        Err(StoreError::Quorum {
            found: 1,
            needed: 2
        })
    ));
}

#[tokio::test]
async fn copies_and_versions_work_on_a_set() {
    let set = Set::new(3);
    let store = set.open_all();
    store.create_bucket("docs", Layout::Object).await.unwrap();
    store
        .set_bucket_versioning("docs", Versioning::Enabled)
        .await
        .unwrap();
    let v1 = pattern(300_000, 1);
    let v2 = pattern(200_000, 2);
    store
        .put_bytes("docs", "k", &v1, ObjectAttrs::default())
        .await
        .unwrap();
    store
        .put_bytes("docs", "k", &v2, ObjectAttrs::default())
        .await
        .unwrap();
    store
        .copy(
            ("docs", "k"),
            ("docs", "copy"),
            None,
            Precondition::default(),
        )
        .await
        .unwrap();
    assert_eq!(read(&store, "copy").await.unwrap(), v2);
    assert_eq!(read(&store, "k").await.unwrap(), v2);
    // Two versions and a copy: three objects' shards on each drive.
    for drive in &set.drives {
        assert_eq!(files(&drive.join(SYSTEM_DIR).join(BUCKETS_DIR)).len(), 3);
    }
}

#[tokio::test]
async fn sets_are_made_of_new_drives_and_their_members_only_open_together() {
    let set = Set::new(4);
    drop(set.open_all());
    // A member alone isn't a drive.
    assert!(matches!(
        Store::open(&set.drives[0]),
        Err(StoreError::SetMember)
    ));
    // Each drive records its place and the set.
    let format: DriveFormat = serde_json::from_slice(
        &std::fs::read(set.drives[2].join(SYSTEM_DIR).join("format.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(format.format, SET_FORMAT);
    let member = format.set.unwrap();
    assert_eq!((member.index, member.data, member.parity), (2, 2, 2));
    // The set's id names the store, whichever drive is home.
    let store = set.open(&set.drives).unwrap();
    assert_eq!(store.format().drive, member.id);
    // Folder buckets can't be: every bucket is an object bucket.
    store.create_bucket("files", Layout::Folder).await.unwrap();
    assert_eq!(store.head_bucket("files").await.unwrap(), Layout::Object);
    drop(store);
    // A set's parity can't be changed, nor a drive given twice.
    assert!(matches!(
        Store::open_set(
            &set.drives,
            SetOptions {
                parity: Some(1),
                ..SetOptions::default()
            },
            set.options()
        ),
        Err(StoreError::DriveSet(_))
    ));
    let twice = vec![
        set.drives[0].clone(),
        set.drives[0].clone(),
        set.drives[1].clone(),
        set.drives[2].clone(),
    ];
    assert!(matches!(set.open(&twice), Err(StoreError::DriveSet(_))));
    // A new set needs new, empty drives.
    let other = Set::new(3);
    std::fs::write(other.drives[1].join("file"), b"x").unwrap();
    assert!(matches!(
        other.open(&other.drives),
        Err(StoreError::DriveSet(_))
    ));
    let single = Set::new(3);
    drop(Store::open(&single.drives[0]).unwrap());
    assert!(matches!(
        single.open(&single.drives),
        Err(StoreError::DriveSet(_))
    ));
    // Too much parity is refused.
    let wide = Set::new(4);
    assert!(matches!(
        Store::open_set(
            &wide.drives,
            SetOptions {
                parity: Some(3),
                ..SetOptions::default()
            },
            wide.options()
        ),
        Err(StoreError::DriveSet(_))
    ));
}

#[tokio::test]
async fn too_few_drives_refuse_to_open() {
    let set = Set::new(4);
    drop(set.open_all());
    set.lose(0);
    set.lose(1);
    set.lose(2);
    match set.open(&set.drives) {
        Err(StoreError::Quorum {
            found: 1,
            needed: 2,
        }) => {}
        other => panic!("expected Quorum, got {other:?}"),
    }
    // The lost drives' folders aren't made again.
    assert!(!set.drives[0].exists());
}

#[test]
fn default_parity_and_quorum_follow_minio() {
    let parity: Vec<usize> = (2..=16).map(default_parity).collect();
    assert_eq!(parity, [1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4]);
    assert_eq!(write_quorum(2, 2), 3);
    assert_eq!(write_quorum(12, 4), 12);
    assert_eq!(write_quorum(2, 1), 2);
}

/// Shards of `drive`'s data files.
fn shard_count(drive: &Path) -> usize {
    files(&drive.join(SYSTEM_DIR).join(BUCKETS_DIR)).len()
}

#[tokio::test]
async fn heal_rebuilds_missing_and_damaged_shards() {
    let set = Set::new(4);
    let bytes = pattern((2 << 20) + 3, 9);
    let store = set.open_all();
    store.create_bucket("docs", Layout::Object).await.unwrap();
    for key in ["a", "b", "c"] {
        put_encrypted(&store, key, &bytes).await;
    }
    store.delete("docs", "c").await.unwrap();
    assert_eq!(store.heal_set().await.unwrap().healed, 0);
    // One drive's shards damaged, another's lost.
    set.damage_shards(1);
    for shard in files(&set.drives[2].join(SYSTEM_DIR).join(BUCKETS_DIR)) {
        std::fs::remove_file(shard).unwrap();
    }
    let report = store.heal_set().await.unwrap();
    assert_eq!((report.objects, report.healed, report.shards), (2, 2, 4));
    assert_eq!(report.unreadable, 0);
    assert_eq!(shard_count(&set.drives[2]), 2);
    // Now any two drives can go again.
    drop(store);
    set.lose(0);
    set.lose(3);
    let store = set.open(&set.drives).unwrap();
    assert_eq!(read(&store, "a").await.unwrap(), bytes);
    assert_eq!(read(&store, "b").await.unwrap(), bytes);
}

#[tokio::test]
async fn a_new_drive_replaces_a_lost_one_and_is_healed() {
    let set = Set::new(4);
    let bytes = pattern(700_000, 4);
    {
        let store = set.open_all();
        store.create_bucket("docs", Layout::Object).await.unwrap();
        put_encrypted(&store, "a", &bytes).await;
        store
            .put_bytes("docs", "small", b"a small one", ObjectAttrs::default())
            .await
            .unwrap();
    }
    // Drive 1 dies; a new, empty disk is mounted in its place.
    set.lose(1);
    std::fs::create_dir(&set.drives[1]).unwrap();
    // Without being asked, the new drive is left alone.
    let store = set.open(&set.drives).unwrap();
    let info = store.drive_set().unwrap();
    assert!(info.drives[1].is_none() && info.replaced.is_empty());
    drop(store);
    assert!(std::fs::read_dir(&set.drives[1]).unwrap().next().is_none());
    // Asked, it takes the lost drive's place, gets the metadata, and is healed.
    let store = Store::open_set(
        &set.drives,
        SetOptions {
            replace: true,
            ..SetOptions::default()
        },
        set.options(),
    )
    .unwrap();
    let info = store.drive_set().unwrap();
    assert_eq!(info.replaced, [1]);
    assert!(info.needs_heal && info.drives.iter().all(Option::is_some));
    let report = store.heal_set().await.unwrap();
    // Both objects (the tests keep even small ones in files) get their shard back.
    assert_eq!((report.healed, report.shards), (2, 2));
    drop(store);
    // The new drive is a member like any other: with two others lost, it serves.
    set.lose(0);
    set.lose(2);
    let store = set.open(&set.drives).unwrap();
    assert_eq!(read(&store, "a").await.unwrap(), bytes);
    assert_eq!(read(&store, "small").await.unwrap(), b"a small one");
}
