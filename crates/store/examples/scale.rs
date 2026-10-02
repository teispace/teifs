//! How an object bucket behaves with millions of objects: fills one with tiny objects
//! (kept in the index, so no files), then times what grows with it: reopening the
//! drive, listing (first page, deep in, by prefix, rolled up by `/`, all of it), HEADs
//! and deletes, and reports the index's size.
//!
//! ```sh
//! cargo run --release -p teifs-store --example scale -- /tmp/scale 10000000
//! ```
//!
//! Keys are `k/AAA/BBB/NNNNNNNN`: 100 × 100 folders, the objects spread across them.
//! A drive left by an earlier run with the same count is reused.
//!
//! With `folder` after the count it measures a folder bucket instead: it fills one
//! through TeiFS, adds a tenth as many files by hand, and times listings and the
//! background pass that finds and hashes the added files, then a pass over a bucket
//! that hasn't changed, and how long a PUT takes while a pass runs.
//!
//! ```sh
//! cargo run --release -p teifs-store --example scale -- /tmp/scale-folders 1000000 folder
//! ```

// A measuring tool: it prints, and its rates needn't be exact.
#![allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::too_many_lines
)]

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use teifs_store::{
    After, Durability, JobOptions, Layout, ListQuery, ObjectAttrs, Store, StoreOptions,
};

const BUCKET: &str = "scale";
const FOLDERS: &str = "folders";
const WORKERS: u64 = 64;

fn key(i: u64) -> String {
    format!("k/{:03}/{:03}/{i:08}", i % 100, (i / 100) % 100)
}

fn open(root: &Path) -> Store {
    let options = StoreOptions {
        durability: Durability::None,
        ..StoreOptions::default()
    };
    Store::open_with(root, options).expect("the drive opens")
}

fn rate(count: u64, took: Duration) -> String {
    format!("{:.0}/s", count as f64 / took.as_secs_f64().max(1e-9))
}

fn size_of(dir: &Path) -> u64 {
    std::fs::read_dir(dir).map_or(0, |entries| {
        entries
            .flatten()
            .map(|entry| match entry.metadata() {
                Ok(meta) if meta.is_dir() => size_of(&entry.path()),
                Ok(meta) => meta.len(),
                Err(_) => 0,
            })
            .sum()
    })
}

async fn fill(store: &Arc<Store>, bucket: &'static str, count: u64) {
    let started = Instant::now();
    let done = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for worker in 0..WORKERS {
        let (store, done) = (store.clone(), done.clone());
        workers.push(tokio::spawn(async move {
            let mut i = worker;
            while i < count {
                store
                    .put_bytes(bucket, &key(i), b"x", ObjectAttrs::default())
                    .await
                    .expect("a put works");
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                if n % (count / 10).max(1) == 0 {
                    eprintln!("  {n} objects, {}", rate(n, started.elapsed()));
                }
                i += WORKERS;
            }
        }));
    }
    for worker in workers {
        worker.await.expect("a worker finishes");
    }
    println!(
        "fill            {count} objects in {:.1?} ({})",
        started.elapsed(),
        rate(count, started.elapsed())
    );
}

async fn time_list(store: &Store, bucket: &str, name: &str, query: ListQuery) {
    let started = Instant::now();
    let listing = store.list(bucket, query).await.expect("a listing works");
    println!(
        "{name:<15} {:.2?} ({} objects, {} prefixes)",
        started.elapsed(),
        listing.objects.len(),
        listing.prefixes.len()
    );
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let root = args.next().expect("usage: scale DIR [COUNT]");
    let count: u64 = args
        .next()
        .map_or(1_000_000, |n| n.parse().expect("COUNT is a number"));
    let root = Path::new(&root);
    std::fs::create_dir_all(root).expect("the folder can be made");
    if args.next().as_deref() == Some("folder") {
        folders(root, count).await;
        return;
    }
    let marker = root.join("scale-count");
    let filled = std::fs::read_to_string(&marker).ok() == Some(count.to_string());

    let store = Arc::new(open(root));
    if !filled {
        store
            .create_bucket(BUCKET, Layout::Object)
            .await
            .expect("the bucket is created");
        fill(&store, BUCKET, count).await;
        std::fs::write(&marker, count.to_string()).expect("the marker is written");
    }
    drop(store);

    let started = Instant::now();
    let store = open(root);
    println!("reopen          {:.2?}", started.elapsed());
    println!(
        "drive on disk   {} MiB",
        size_of(&root.join(".teifs")) / (1024 * 1024)
    );

    let page = |prefix: &str, delimiter: Option<&str>, after: Option<After>| ListQuery {
        prefix: prefix.to_owned(),
        delimiter: delimiter.map(str::to_owned),
        after,
        max_keys: 1000,
    };
    time_list(&store, BUCKET, "list first", page("", None, None)).await;
    let middle = key(count / 2);
    time_list(
        &store,
        BUCKET,
        "list middle",
        page("", None, Some(After::Key(middle))),
    )
    .await;
    time_list(
        &store,
        BUCKET,
        "list prefix",
        page("k/099/099/", None, None),
    )
    .await;
    time_list(&store, BUCKET, "list / root", page("", Some("/"), None)).await;
    time_list(&store, BUCKET, "list / k/", page("k/", Some("/"), None)).await;
    time_list(
        &store,
        BUCKET,
        "list / k/050/",
        page("k/050/", Some("/"), None),
    )
    .await;

    // Every object, a page at a time.
    let started = Instant::now();
    let (mut listed, mut after) = (0u64, None);
    loop {
        let listing = store
            .list(BUCKET, page("", None, after))
            .await
            .expect("a listing works");
        listed += listing.objects.len() as u64;
        if !listing.truncated {
            break;
        }
        after = listing.next;
    }
    println!(
        "list all        {listed} in {:.1?} ({})",
        started.elapsed(),
        rate(listed, started.elapsed())
    );

    // HEADs of keys spread across the bucket.
    let heads = 20_000.min(count);
    let started = Instant::now();
    let mut i = 0u64;
    for _ in 0..heads {
        i = (i * 6_364_136_223_846_793_005 + 1_442_695_040_888_963_407) % count;
        store
            .head(BUCKET, &key(i))
            .await
            .expect("the object is there");
    }
    println!(
        "head            {heads} in {:.2?} ({})",
        started.elapsed(),
        rate(heads, started.elapsed())
    );

    // Deletes, from many clients at once, of the last 100k (refilled next run).
    let store = Arc::new(store);
    let deletes = 100_000.min(count);
    let started = Instant::now();
    let mut workers = Vec::new();
    for worker in 0..WORKERS {
        let store = store.clone();
        workers.push(tokio::spawn(async move {
            let mut i = count - deletes + worker;
            while i < count {
                store.delete(BUCKET, &key(i)).await.expect("a delete works");
                i += WORKERS;
            }
        }));
    }
    for worker in workers {
        worker.await.expect("a worker finishes");
    }
    println!(
        "delete          {deletes} in {:.1?} ({})",
        started.elapsed(),
        rate(deletes, started.elapsed())
    );
    // Put them back, so the next run finds the drive as it left it.
    for i in count - deletes..count {
        store
            .put_bytes(BUCKET, &key(i), b"x", ObjectAttrs::default())
            .await
            .expect("a put works");
    }
}

fn page(prefix: &str, delimiter: Option<&str>) -> ListQuery {
    ListQuery {
        prefix: prefix.to_owned(),
        delimiter: delimiter.map(str::to_owned),
        after: None,
        max_keys: 1000,
    }
}

/// A key for a file added by hand, beside the ones TeiFS wrote.
fn added(i: u64) -> String {
    format!("added/{:03}/{i:08}", i % 1000)
}

/// Runs the background jobs until the folder pass has looked at `files` entries; how
/// long that took, and the median and slowest PUT made meanwhile.
async fn one_pass(store: &Arc<Store>, files: u64) -> (Duration, Duration, Duration) {
    let started = Instant::now();
    let jobs = store.start_jobs(&JobOptions {
        pace: 0.0,
        ..JobOptions::default()
    });
    // PUTs, one after another, while the pass runs.
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (store, stop) = (store.clone(), stop.clone());
        tokio::spawn(async move {
            let mut took = Vec::new();
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let started = Instant::now();
                store
                    .put_bytes(
                        FOLDERS,
                        &format!("during/{i:08}"),
                        b"x",
                        ObjectAttrs::default(),
                    )
                    .await
                    .expect("a put works");
                took.push(started.elapsed());
                i += 1;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            took
        })
    };
    loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let items = store
            .job_status()
            .get("index-folders")
            .map_or(0, |status| status.items);
        if items >= files {
            break;
        }
    }
    let took = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    let (median, slowest) = spread(writer.await.expect("the writer finishes"));
    jobs.stop().await;
    (took, median, slowest)
}

/// The median and the slowest of some timings.
fn spread(mut took: Vec<Duration>) -> (Duration, Duration) {
    took.sort();
    let median = took.get(took.len() / 2).copied().unwrap_or_default();
    (median, took.last().copied().unwrap_or_default())
}

async fn folders(root: &Path, count: u64) {
    let marker = root.join("scale-folder-count");
    let filled = std::fs::read_to_string(&marker).ok() == Some(count.to_string());
    let store = Arc::new(open(root));
    let extra = count / 10;
    if !filled {
        store
            .create_bucket(FOLDERS, Layout::Folder)
            .await
            .expect("the bucket is created");
        fill(&store, FOLDERS, count).await;
        std::fs::write(&marker, count.to_string()).expect("the marker is written");
    }
    // Files added by hand, which the pass has to find and hash.
    let dir = root.join(FOLDERS);
    let started = Instant::now();
    for i in 0..extra {
        let path = dir.join(added(i));
        if i % 1000 == 0 || i < 1000 {
            std::fs::create_dir_all(path.parent().expect("a file has a folder"))
                .expect("the folder is made");
        }
        std::fs::write(&path, i.to_le_bytes()).expect("the file is written");
    }
    println!("added by hand   {extra} files in {:.1?}", started.elapsed());
    let _ = std::fs::remove_dir_all(dir.join("during"));
    drop(store);

    let started = Instant::now();
    let store = Arc::new(open(root));
    println!("reopen          {:.2?}", started.elapsed());
    time_list(&store, FOLDERS, "list first", page("", None)).await;
    time_list(&store, FOLDERS, "list prefix", page("k/099/099/", None)).await;
    time_list(&store, FOLDERS, "list / root", page("", Some("/"))).await;
    time_list(&store, FOLDERS, "list / k/", page("k/", Some("/"))).await;
    time_list(&store, FOLDERS, "list / k/050/", page("k/050/", Some("/"))).await;

    let (median, slowest) = put_latency(&store, 2000).await;
    println!("put, quiet      median {median:.2?}, slowest {slowest:.2?}");

    let files = count + extra;
    let (took, median, slowest) = one_pass(&store, files).await;
    println!(
        "pass, {extra} new {files} files in {took:.1?} ({}); put median {median:.2?}, slowest {slowest:.2?}",
        rate(files, took)
    );
    let info = store
        .head(FOLDERS, &added(extra - 1))
        .await
        .expect("an added file is there");
    assert_eq!(info.size, 8, "the added file is indexed");
    drop(store);

    // Each pass starts afresh: one over files that are all indexed already.
    let store = Arc::new(open(root));
    let (took, median, slowest) = one_pass(&store, files).await;
    println!(
        "pass, unchanged {files} files in {took:.1?} ({}); put median {median:.2?}, slowest {slowest:.2?}",
        rate(files, took)
    );
    drop(store);

    // Leave the drive as it was: the hand-made files go, the next pass forgets them.
    for made in ["added", "during", "quiet"] {
        let _ = std::fs::remove_dir_all(dir.join(made));
    }
}

/// The median and slowest of `n` PUTs one after another.
async fn put_latency(store: &Store, n: u64) -> (Duration, Duration) {
    let mut took = Vec::new();
    for i in 0..n {
        let started = Instant::now();
        store
            .put_bytes(
                FOLDERS,
                &format!("quiet/{i:08}"),
                b"x",
                ObjectAttrs::default(),
            )
            .await
            .expect("a put works");
        took.push(started.elapsed());
    }
    spread(took)
}
