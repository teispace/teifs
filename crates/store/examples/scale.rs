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
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use teifs_store::{After, Durability, Layout, ListQuery, ObjectAttrs, Store, StoreOptions};

const BUCKET: &str = "scale";
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

async fn fill(store: &Arc<Store>, count: u64) {
    let started = Instant::now();
    let done = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for worker in 0..WORKERS {
        let (store, done) = (store.clone(), done.clone());
        workers.push(tokio::spawn(async move {
            let mut i = worker;
            while i < count {
                store
                    .put_bytes(BUCKET, &key(i), b"x", ObjectAttrs::default())
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

async fn time_list(store: &Store, name: &str, query: ListQuery) {
    let started = Instant::now();
    let listing = store.list(BUCKET, query).await.expect("a listing works");
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
    let marker = root.join("scale-count");
    let filled = std::fs::read_to_string(&marker).ok() == Some(count.to_string());

    let store = Arc::new(open(root));
    if !filled {
        store
            .create_bucket(BUCKET, Layout::Object)
            .await
            .expect("the bucket is created");
        fill(&store, count).await;
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
    time_list(&store, "list first", page("", None, None)).await;
    let middle = key(count / 2);
    time_list(
        &store,
        "list middle",
        page("", None, Some(After::Key(middle))),
    )
    .await;
    time_list(&store, "list prefix", page("k/099/099/", None, None)).await;
    time_list(&store, "list / root", page("", Some("/"), None)).await;
    time_list(&store, "list / k/", page("k/", Some("/"), None)).await;
    time_list(&store, "list / k/050/", page("k/050/", Some("/"), None)).await;

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
