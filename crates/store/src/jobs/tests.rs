//! Each job's step, with the clock moved forward, and the runner end to end.

use std::{fs, time::Duration};

use tempfile::TempDir;

use super::*;
use crate::{Encryption, Layout, ObjectAttrs, Precondition, StoreError};
use teifs_types::verify::ScrubReport;

const HOUR: Duration = Duration::from_hours(1);
const DAY: Duration = Duration::from_hours(24);

async fn store() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.create_bucket("bkt", Layout::Folder).await.unwrap();
    (dir, store)
}

fn at(now: SystemTime) -> Step {
    Step {
        now,
        cancel: CancellationToken::new(),
    }
}

async fn upload(store: &Store) -> String {
    store
        .create_upload(
            "bkt",
            "big",
            ObjectAttrs::default(),
            None,
            &Encryption::None,
            None,
            None,
        )
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn uploads_expire_after_their_time_only() {
    let (_dir, store) = store().await;
    let id = upload(&store).await;
    let mut job = ExpireUploads { after: 7 * DAY };
    let now = SystemTime::now();
    assert_eq!(job.step(&store.inner, &at(now + DAY)).unwrap(), 0);
    assert!(store.upload(&id).await.is_ok());
    assert_eq!(job.step(&store.inner, &at(now + 8 * DAY)).unwrap(), 1);
    assert!(matches!(
        store.upload(&id).await,
        Err(StoreError::NoSuchUpload)
    ));
    assert!(!store.inner.uploads.join(&id).exists());
    assert_eq!(job.step(&store.inner, &at(now + 8 * DAY)).unwrap(), 0);
}

#[tokio::test]
async fn only_idle_staged_files_are_swept() {
    let (dir, store) = store().await;
    let staged = store.inner.tmp.join("abandoned");
    fs::write(&staged, b"half a write").unwrap();
    let bucket_staging = dir.path().join("bkt").join(teifs_types::BUCKET_STAGING);
    fs::create_dir(&bucket_staging).unwrap();
    fs::write(bucket_staging.join("other-disk"), b"x").unwrap();

    let now = SystemTime::now();
    // Recently written: an upload may still be writing it.
    assert_eq!(SweepStaging.step(&store.inner, &at(now)).unwrap(), 0);
    assert!(staged.exists());
    assert_eq!(
        SweepStaging
            .step(&store.inner, &at(now + 2 * HOUR))
            .unwrap(),
        2
    );
    assert!(!staged.exists());
    assert!(!bucket_staging.join("other-disk").exists());
}

#[tokio::test]
async fn housekeeping_forgets_old_retry_answers() {
    let (_dir, store) = store().await;
    let done = teifs_meta::CompletedUpload {
        bucket: "bkt".into(),
        key: "k".into(),
        result: "{}".into(),
    };
    let now = SystemTime::now();
    store
        .inner
        .lock()
        .record_completed("u1", &done, millis(now), 0)
        .unwrap();
    assert_eq!(Housekeeping.step(&store.inner, &at(now)).unwrap(), 0);
    assert!(store.inner.lock().completed_upload("u1").unwrap().is_some());
    assert_eq!(
        Housekeeping.step(&store.inner, &at(now + 2 * DAY)).unwrap(),
        1
    );
    assert!(store.inner.lock().completed_upload("u1").unwrap().is_none());
}

#[tokio::test]
async fn jobs_run_in_the_background_and_stop_when_told() {
    let (_dir, store) = store().await;
    let id = upload(&store).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(store.job_status().is_empty());
    let jobs = store.start_jobs(&JobOptions {
        upload_expiry: Some(Duration::ZERO),
        pace: 0.0,
        scrub_every: Some(Duration::from_millis(20)),
        snapshots: 1,
    });
    // The upload goes during the step; the step's result is recorded right after.
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        let status = jobs.status();
        let scrubbed = store.scrub_report().await.unwrap().last.is_some();
        let snapshotted = !store.snapshots().await.unwrap().is_empty();
        if status.get("expire-uploads").is_some_and(|s| s.items == 1) && scrubbed && snapshotted {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the stale upload was never expired"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(matches!(
        store.upload(&id).await,
        Err(StoreError::NoSuchUpload)
    ));
    assert!(status["expire-uploads"].last_progress.is_some());
    assert!(status.contains_key("housekeeping") && status.contains_key("sweep-staging"));
    // The drive reports the same, for whoever holds it rather than the jobs.
    assert!(store.job_status()["expire-uploads"].items >= 1);
    // Stopping doesn't wait for the idle intervals.
    tokio::time::timeout(Duration::from_secs(5), jobs.stop())
        .await
        .expect("jobs stop promptly");
}

#[test]
fn defaults_expire_uploads_after_a_week_scrub_monthly_and_keep_three_snapshots() {
    let options = JobOptions::default();
    assert_eq!(options.upload_expiry, Some(7 * DAY));
    assert_eq!(options.scrub_every, Some(30 * DAY));
    assert_eq!(options.snapshots, 3);
    assert!((options.pace - 1.0).abs() < f64::EPSILON);
}

/// Flips one bit of the file at `path`, keeping its size and modification time, as rot
/// on the disk would.
fn rot(path: &std::path::Path) {
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let mut bytes = fs::read(path).unwrap();
    bytes[0] ^= 1;
    fs::write(path, bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
}

async fn put(store: &Store, key: &str, bytes: &[u8]) {
    let mut staged = store.stage_for("bkt", &Encryption::None).await.unwrap();
    staged.write(bytes).await.unwrap();
    store
        .commit(
            "bkt",
            key,
            staged,
            ObjectAttrs::default(),
            Precondition::default(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn scrubs_come_round_on_time_and_report_damage() {
    let (dir, store) = store().await;
    for key in ["a", "b", "c"] {
        put(&store, key, key.repeat(1000).as_bytes()).await;
    }
    rot(&dir.path().join("bkt").join("b"));
    let mut job = scrub::Scrub::new(store.clone(), 30 * DAY);
    let now = SystemTime::now();
    // The first pass is due an interval after the drive is first seen.
    assert_eq!(job.run(&at(now)).await.unwrap(), 0);
    assert_eq!(job.run(&at(now + 29 * DAY)).await.unwrap(), 0);
    assert_eq!(store.scrub_report().await.unwrap(), ScrubReport::default());
    // A small drive fits in one step, pass and all.
    assert_eq!(job.run(&at(now + 30 * DAY)).await.unwrap(), 3);
    let report = store.scrub_report().await.unwrap();
    assert!(report.current.is_none());
    let last = report.last.unwrap();
    assert_eq!(
        (last.versions, last.bytes, last.damaged, last.unverifiable),
        (3, 3000, 1, 0)
    );
    assert_eq!(last.started_ms, millis(now + 30 * DAY));
    assert!(last.finished_ms.unwrap() >= last.started_ms);
    assert_eq!(last.findings[0].key, "b");
    assert_eq!(
        last.findings[0].verdict,
        teifs_types::verify::Damage::Etag.into()
    );
    // The next one starts an interval after the last one started.
    assert_eq!(job.run(&at(now + 59 * DAY)).await.unwrap(), 0);
    assert_eq!(job.run(&at(now + 60 * DAY)).await.unwrap(), 3);
}

#[tokio::test]
async fn a_scrub_stopped_midway_carries_on_after_a_restart() {
    let (dir, store) = store().await;
    put(&store, "a", &[1; 5000]).await;
    put(&store, "b", &[2; 5000]).await;
    let now = SystemTime::now() + 31 * DAY;
    let stopping = at(now);
    stopping.cancel.cancel();
    // Due (the drive was first seen a month before), but stopped before the first
    // object was read through: nothing counted, and the pass is kept to carry on.
    let mut job = scrub::Scrub::new(store.clone(), 30 * DAY);
    store
        .set_scrub_state(&scrub::State::since(millis(now - 31 * DAY)))
        .await
        .unwrap();
    assert_eq!(job.run(&stopping).await.unwrap(), 0);
    let current = store.scrub_report().await.unwrap().current.unwrap();
    assert_eq!(current.versions, 0);
    drop(job);
    drop(store);

    let store = Store::open(dir.path()).unwrap();
    let mut job = scrub::Scrub::new(store.clone(), 30 * DAY);
    let later = at(now + HOUR);
    assert_eq!(job.run(&later).await.unwrap(), 2);
    assert_eq!(job.run(&later).await.unwrap(), 0);
    let last = store.scrub_report().await.unwrap().last.unwrap();
    // The same pass, from when it started.
    assert_eq!((last.versions, last.damaged), (2, 0));
    assert_eq!(last.started_ms, millis(now));
}

#[tokio::test]
async fn a_scrub_step_is_bounded() {
    let (_dir, store) = store().await;
    for n in 0..=BATCH {
        put(&store, &format!("k{n:04}"), b"x").await;
    }
    let now = SystemTime::now() + 31 * DAY;
    let mut job = scrub::Scrub::new(store.clone(), 30 * DAY);
    store
        .set_scrub_state(&scrub::State::since(millis(now - 31 * DAY)))
        .await
        .unwrap();
    assert_eq!(job.run(&at(now)).await.unwrap(), BATCH);
    // A pass that takes days ends when its last step runs…
    assert_eq!(job.run(&at(now + 10 * DAY)).await.unwrap(), 1);
    let last = store.scrub_report().await.unwrap().last.unwrap();
    assert_eq!(last.versions, BATCH as u64 + 1);
    assert_eq!(last.finished_ms, Some(millis(now + 10 * DAY)));

    // …and the next is due an interval after it started. A step is bounded by the
    // bytes it reads too: here, one listing's worth.
    job.step_bytes = 1;
    assert_eq!(job.run(&at(now + 30 * DAY)).await.unwrap(), 16);
}

#[tokio::test]
async fn an_empty_drives_scrub_counts_as_progress() {
    let (_dir, store) = store().await;
    let now = SystemTime::now();
    let mut job = scrub::Scrub::new(store.clone(), Duration::from_millis(50));
    // Idle no longer than the interval, nor than an hour.
    assert_eq!(job.idle(), Duration::from_millis(50));
    assert_eq!(scrub::Scrub::new(store.clone(), 30 * DAY).idle(), HOUR);
    assert_eq!(job.run(&at(now)).await.unwrap(), 0);
    assert_eq!(job.run(&at(now + HOUR)).await.unwrap(), 1);
    let last = store.scrub_report().await.unwrap().last.unwrap();
    assert_eq!((last.versions, last.bytes), (0, 0));
}

#[tokio::test]
async fn metadata_is_snapshotted_daily_and_the_newest_kept() {
    let (dir, store) = store().await;
    store.create_bucket("obj", Layout::Object).await.unwrap();
    let mut job = TakeSnapshots {
        every: DAY,
        keep: 2,
    };
    let now = SystemTime::now();
    assert_eq!(job.step(&store.inner, &at(now)).unwrap(), 1);
    assert_eq!(job.step(&store.inner, &at(now + HOUR)).unwrap(), 0);
    // A snapshot left half-written by a crash goes at the next prune.
    let auto = dir.path().join(".teifs/backups/auto");
    let partial = auto.join(".20260101T000000.000Z.partial");
    fs::create_dir(&partial).unwrap();
    let first = &store.snapshots().await.unwrap()[0];
    fs::copy(
        auto.join(&first.name).join("snapshot.json"),
        partial.join("snapshot.json"),
    )
    .unwrap();
    assert_eq!(store.snapshots().await.unwrap().len(), 1);
    assert_eq!(job.step(&store.inner, &at(now + DAY)).unwrap(), 1);
    assert_eq!(job.step(&store.inner, &at(now + 2 * DAY)).unwrap(), 1);
    let snapshots = store.snapshots().await.unwrap();
    assert_eq!(
        snapshots.iter().map(|s| s.created_ms).collect::<Vec<_>>(),
        [millis(now + DAY), millis(now + 2 * DAY)]
    );
    assert_eq!(fs::read_dir(&auto).unwrap().count(), 2);
    let newest = &snapshots[1];
    assert_eq!(newest.drive, store.format().drive);
    assert!(newest.bytes > 0);
    // Each is a working copy of both databases.
    let copy = auto.join(&newest.name);
    let system = teifs_meta::System::open(&copy.join("system.db")).unwrap();
    assert!(system.bucket("obj").unwrap().is_some());
    assert!(teifs_meta::intact(&copy.join("index.db")).unwrap());
}

#[tokio::test]
async fn a_snapshot_can_be_asked_for_at_any_time() {
    let (_dir, store) = store().await;
    let first = store.take_snapshot().await.unwrap();
    let second = store.take_snapshot().await.unwrap();
    assert!(first.name < second.name || first.created_ms == second.created_ms);
    assert_eq!(store.snapshots().await.unwrap().len(), 2);
}
