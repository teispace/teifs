//! Writes survive the process being killed at any moment. A child process (this test
//! binary again) writes to an object bucket and a folder bucket from several tasks and
//! prints each write once it's acknowledged; it's killed with no warning, the drive is
//! opened again, and every object must be what its last acknowledged write left, or what
//! the write in flight would have left, whole and with the right ETag. The repair check
//! must find no version without its data. `TEIFS_CRASH_ROUNDS` sets how many kills
//! (10 by default), and `TEIFS_CRASH_DIR` keeps the drive in that folder, to look at
//! after a failure.
//!
//! With `TEIFS_CRASH_POWER=FIFO|DONE`, each kill is a power loss too: the drive is on a
//! [LazyFS](https://github.com/dsrhaslab/lazyfs) mount, and after the kill the test writes
//! `lazyfs::clear-cache` to its fault FIFO and waits for the reply on the DONE FIFO, which
//! throws away everything not yet synced to disk.

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    reason = "a test: it fails on any error and talks to its parent through stdout"
)]

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use md5::{Digest, Md5};
use teifs_store::{
    CompleteWith, Encryption, Finding, Layout, ListQuery, LocalKms, ObjectAttrs, Precondition,
    RepairOptions, Store, StoreError, StoreOptions,
};
use teifs_types::hex;
use tokio::io::AsyncReadExt;

/// Set in the child: the drive's folder, the keyring's folder, and the first sequence.
const CHILD: &str = "TEIFS_CRASH_CHILD";
/// Writers in the child, each with keys of its own.
const WORKERS: u64 = 6;
/// Keys per writer and bucket.
const KEYS: u64 = 5;
/// Kills; `TEIFS_CRASH_ROUNDS` asks for more (the nightly run does).
const ROUNDS: u64 = 10;
/// A round's sequences start at its number times this.
const ROUND_SEQS: u64 = 1 << 32;
/// The child gives up if it's somehow still running after this.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);
/// The test fails when it waits this long for anything.
const STALL: Duration = Duration::from_secs(120);

/// What the test is waiting for, and since when.
type Waiting = Arc<std::sync::Mutex<(Instant, String)>>;

/// Ends the test when it waits too long, saying for what, instead of hanging: a process
/// stuck in a file system can't be killed, and a stuck `LazyFS` never answers.
fn watchdog() -> Waiting {
    let waiting: Waiting = Arc::new(std::sync::Mutex::new((Instant::now(), String::new())));
    let watched = Arc::clone(&waiting);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let (since, what) = &*watched.lock().unwrap();
            if since.elapsed() > STALL {
                eprintln!("waited {STALL:?} for {what}");
                std::process::exit(1);
            }
        }
    });
    waiting
}

fn wait_for(waiting: &Waiting, what: impl Into<String>) {
    *waiting.lock().unwrap() = (Instant::now(), what.into());
}

fn mix(mut x: u64) -> u64 {
    // splitmix64
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Put { size: usize, sealed: bool },
    Upload { size: usize },
    Delete,
}

/// Writer `worker`'s write number `seq`: always the same.
#[derive(Debug, Clone, Copy)]
struct Op {
    worker: u64,
    seq: u64,
    bucket: &'static str,
    key: u64,
    kind: Kind,
}

impl Op {
    fn of(worker: u64, seq: u64) -> Self {
        let h = mix((worker << 40) ^ seq);
        let bucket = if h & 1 == 0 { "obj" } else { "fold" };
        let size = |base: u64, spread: u64| (base + (h >> 24) % spread) as usize;
        let kind = match (h >> 8) % 20 {
            // Small enough to be kept in the index (object buckets), or held in memory.
            0..=8 => Kind::Put {
                size: size(1, 4_000),
                sealed: (h >> 20) & 1 == 1,
            },
            9..=12 => Kind::Put {
                size: size(40_000, 100_000),
                sealed: (h >> 20) & 1 == 1,
            },
            // Written in batches while it arrives.
            13..=14 => Kind::Put {
                size: size(300_000, 900_000),
                sealed: (h >> 20) & 1 == 1,
            },
            15..=16 => Kind::Upload {
                size: size(1, 200_000),
            },
            _ => Kind::Delete,
        };
        Self {
            worker,
            seq,
            bucket,
            key: (h >> 4) % KEYS,
            kind,
        }
    }

    fn key(&self) -> String {
        format!("w{}/k{}", self.worker, self.key)
    }

    /// What the object holds after this write; `None` for a delete.
    fn body(&self) -> Option<Vec<u8>> {
        let size = match self.kind {
            Kind::Put { size, .. } | Kind::Upload { size } => size,
            Kind::Delete => return None,
        };
        let mut state = mix(self.worker ^ self.seq.rotate_left(17));
        let mut body = Vec::with_capacity(size + 8);
        while body.len() < size {
            state = mix(state);
            body.extend_from_slice(&state.to_le_bytes());
        }
        body.truncate(size);
        Some(body)
    }
}

fn open(drive: &Path, keys: &Path) -> Store {
    let kms = Arc::new(LocalKms::open(keys.join("keyring.json")).unwrap());
    Store::open_with(
        drive,
        StoreOptions {
            kms: Some(kms),
            ..StoreOptions::default()
        },
    )
    .unwrap()
}

async fn apply(store: &Store, op: &Op) -> Result<(), StoreError> {
    let key = op.key();
    match op.kind {
        Kind::Delete => store.delete(op.bucket, &key).await,
        Kind::Put { sealed, .. } => {
            let encryption = if sealed && op.bucket == "obj" {
                Encryption::S3
            } else {
                Encryption::None
            };
            let mut staged = store.stage_for(op.bucket, &encryption).await?;
            // In pieces, as a request's body arrives.
            for piece in op.body().unwrap().chunks(64 * 1024 + 7) {
                staged.write(piece).await?;
            }
            store
                .commit(
                    op.bucket,
                    &key,
                    staged,
                    ObjectAttrs::default(),
                    Precondition::default(),
                )
                .await
                .map(drop)
        }
        Kind::Upload { .. } => {
            let upload = store
                .create_upload(
                    op.bucket,
                    &key,
                    ObjectAttrs::default(),
                    None,
                    &Encryption::None,
                    None,
                    None,
                )
                .await?;
            let mut staged = store.stage();
            staged.write(&op.body().unwrap()).await?;
            let part = store
                .put_part(&upload.id, 1, staged, BTreeMap::new())
                .await?;
            store
                .complete(
                    &upload.id,
                    vec![(1, part.etag)],
                    Precondition::default(),
                    CompleteWith::default(),
                )
                .await
                .map(drop)
        }
    }
}

/// The child: writes until it's killed, printing `ack WORKER SEQ` after each write.
#[test]
fn crash_child() {
    let Ok(setting) = std::env::var(CHILD) else {
        return;
    };
    let mut parts = setting.split('|');
    let (drive, keys) = (parts.next().unwrap(), parts.next().unwrap());
    let first: u64 = parts.next().unwrap().parse().unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let store = Arc::new(open(Path::new(drive), Path::new(keys)));
        let started = Instant::now();
        let mut writers = Vec::new();
        for worker in 0..WORKERS {
            let store = store.clone();
            writers.push(tokio::spawn(async move {
                let mut seq = first;
                while started.elapsed() < CHILD_DEADLINE {
                    apply(&store, &Op::of(worker, seq)).await.unwrap();
                    let mut out = std::io::stdout().lock();
                    writeln!(out, "ack {worker} {seq}").unwrap();
                    out.flush().unwrap();
                    seq += 1;
                }
            }));
        }
        for writer in writers {
            writer.await.unwrap();
        }
    });
}

async fn read(store: &Store, bucket: &str, key: &str) -> Option<(Vec<u8>, String)> {
    match store.read(bucket, key).await {
        Ok((info, body)) => {
            let mut out = Vec::new();
            body.unwrap()
                .all()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out.len() as u64, info.size, "{bucket}/{key}'s size");
            Some((out, info.etag))
        }
        Err(StoreError::NoSuchKey) => None,
        Err(err) => panic!("{bucket}/{key} can't be read: {err}"),
    }
}

/// What an object should be: what the last write to it left (nothing after a delete).
#[derive(Debug, Clone, Copy, Default)]
struct Last {
    op: Option<Op>,
    /// A folder bucket's file put in place by a write in flight when the child was
    /// killed, without its row: a file changed outside TeiFS until the index pass hashes
    /// it, so its ETag is provisional meanwhile.
    provisional: bool,
}

type Model = BTreeMap<(&'static str, String), Last>;

/// Every object as the writes acknowledged left it, or as the one in flight would have.
///
/// After a power loss, a folder bucket's file can also hold its last acknowledged write
/// with a provisional ETag: `LazyFS` reports the time of the last write as a file's mtime
/// until the cache is cleared and the time it synced the file afterwards, which no real
/// file system does, so the row no longer matches the file.
async fn check(store: &Store, model: &mut Model, next: &[Op], power_loss: bool) {
    for op in next {
        model.entry((op.bucket, op.key())).or_default();
    }
    for ((bucket, key), last) in model.iter_mut() {
        let found = read(store, bucket, key).await;
        let in_flight = next
            .iter()
            .find(|op| op.bucket == *bucket && op.key() == *key);
        // A write's ETag is its MD5 (an upload's is the parts').
        let matches = |op: &Option<Op>, provisional_too: bool| match (&found, op) {
            (None, None) => true,
            (None, Some(op)) => op.kind == Kind::Delete,
            (Some((bytes, etag)), Some(op)) => {
                op.body().as_ref() == Some(bytes)
                    && (matches!(op.kind, Kind::Upload { .. })
                        || *etag == hex(&Md5::digest(bytes))
                        || (provisional_too && *bucket == "fold" && etag.ends_with("-1")))
            }
            (Some(_), None) => false,
        };
        if matches(&last.op, last.provisional) {
            continue;
        }
        if power_loss && matches(&last.op, true) {
            last.provisional = true;
            continue;
        }
        let Some(op) = in_flight.filter(|op| matches(&Some(**op), true)) else {
            let detail = found.as_ref().map(|(bytes, etag)| {
                let same = |op: Option<&Op>| op.and_then(Op::body).as_ref() == Some(bytes);
                (
                    bytes.len(),
                    etag.clone(),
                    hex(&Md5::digest(bytes)),
                    same(last.op.as_ref()),
                    same(in_flight),
                )
            });
            panic!(
                "{bucket}/{key} holds (size, etag, md5, last's bytes, in flight's bytes) {detail:?}: neither its last acknowledged write {last:?} nor the one in flight {in_flight:?}",
            );
        };
        *last = Last {
            op: Some(*op),
            provisional: true,
        };
    }
    // Nothing else is listed (a folder left empty by a delete is the object `w0/`).
    for bucket in ["obj", "fold"] {
        let listing = store
            .list(
                bucket,
                ListQuery {
                    max_keys: 10_000,
                    ..ListQuery::default()
                },
            )
            .await
            .unwrap();
        for object in listing.objects {
            let known = model
                .get(&(bucket, object.key.clone()))
                .is_some_and(|last| last.op.is_some());
            let empty_folder = bucket == "fold" && object.key.ends_with('/') && object.size == 0;
            assert!(known || empty_folder, "{bucket} lists {}", object.key);
        }
    }
    let report = store.repair(RepairOptions::default()).await.unwrap();
    for repair in &report.findings {
        assert!(
            !matches!(repair.finding, Finding::Missing { .. }),
            "lost data: {repair:?}"
        );
    }
}

/// The fault FIFO of the `LazyFS` mount, and the FIFO it answers on once a fault is done.
struct PowerLoss {
    faults: File,
    done: BufReader<File>,
}

impl PowerLoss {
    fn open(fifos: &str) -> Self {
        let (faults, done) = fifos.split_once('|').unwrap();
        Self {
            faults: OpenOptions::new().write(true).open(faults).unwrap(),
            // Read and write, so the open doesn't wait for LazyFS and LazyFS never finds
            // the FIFO without a reader.
            done: BufReader::new(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(done)
                    .unwrap(),
            ),
        }
    }

    /// Drops every write the kernel accepted but nothing synced.
    fn cut(&mut self) {
        self.faults.write_all(b"lazyfs::clear-cache\n").unwrap();
        let mut line = String::new();
        self.done.read_line(&mut line).unwrap();
        assert_eq!(line, "finished::clear-cache\n");
    }
}

#[test]
fn writes_survive_a_kill_at_any_moment() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base =
        std::env::var_os("TEIFS_CRASH_DIR").map_or_else(|| dir.path().to_owned(), Into::into);
    let (drive, keys) = (base.join("drive"), base.join("keys"));
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::create_dir_all(&drive).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let store = open(&drive, &keys);
        store.create_bucket("obj", Layout::Object).await.unwrap();
        store.create_bucket("fold", Layout::Folder).await.unwrap();
    });
    let mut power = std::env::var("TEIFS_CRASH_POWER")
        .ok()
        .map(|fifos| PowerLoss::open(&fifos));
    let waiting = watchdog();
    let mut model = Model::new();
    let mut acks = 0;
    let rounds = std::env::var("TEIFS_CRASH_ROUNDS").map_or(ROUNDS, |n| n.parse().unwrap());
    for round in 1..=rounds {
        let first = round * ROUND_SEQS;
        wait_for(&waiting, format!("round {round}'s first acknowledgement"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["crash_child", "--exact", "--nocapture", "--test-threads=1"])
            .env(
                CHILD,
                format!("{}|{}|{first}", drive.display(), keys.display()),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap());
        // Killed after a number of writes that differs every round, mid-write somewhere.
        let kill_after = 20 + mix(round) % 300;
        let mut last: BTreeMap<u64, u64> = BTreeMap::new();
        let mut seen = 0;
        for line in lines.lines() {
            let Ok(line) = line else { break };
            // The first may follow libtest's `test crash_child ... ` on its line.
            let Some(at) = line.find("ack ") else {
                continue;
            };
            let mut words = line[at + 4..].split(' ');
            let worker: u64 = words.next().unwrap().parse().unwrap();
            let seq: u64 = words.next().unwrap().parse().unwrap();
            wait_for(&waiting, format!("round {round}'s acknowledgements"));
            let op = Op::of(worker, seq);
            let state = Last {
                op: op.body().map(|_| op),
                provisional: false,
            };
            model.insert((op.bucket, op.key()), state);
            last.insert(worker, seq);
            seen += 1;
            if seen == kill_after {
                child.kill().unwrap();
            }
        }
        wait_for(&waiting, format!("round {round}'s child to exit"));
        let status = child.wait().unwrap();
        assert!(!status.success(), "the child was killed");
        assert!(seen >= kill_after, "the child stopped early: {status}");
        acks += seen;
        if let Some(power) = &mut power {
            wait_for(
                &waiting,
                format!("LazyFS to clear its cache after round {round}"),
            );
            power.cut();
        }
        wait_for(&waiting, format!("round {round}'s check"));
        // Each writer's next write may have happened or not.
        let next: Vec<Op> = (0..WORKERS)
            .map(|worker| Op::of(worker, last.get(&worker).map_or(first, |seq| seq + 1)))
            .collect();
        runtime.block_on(async {
            let store = open(&drive, &keys);
            check(&store, &mut model, &next, power.is_some()).await;
        });
        if round % 25 == 0 {
            eprintln!("{round} of {rounds} rounds checked");
        }
    }
    assert!(acks > rounds * 20);
}
