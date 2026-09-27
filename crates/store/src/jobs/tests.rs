//! Each job's step, with the clock moved forward, and the runner end to end.

use std::{fs, time::Duration};

use tempfile::TempDir;

use super::*;
use crate::{Encryption, Layout, ObjectAttrs, StoreError};

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
    let jobs = store.start_jobs(&JobOptions {
        upload_expiry: Some(Duration::ZERO),
        pace: 0.0,
    });
    // The upload goes during the step; the step's result is recorded right after.
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        let status = jobs.status();
        if status.get("expire-uploads").is_some_and(|s| s.items == 1) {
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
    // Stopping doesn't wait for the idle intervals.
    tokio::time::timeout(Duration::from_secs(5), jobs.stop())
        .await
        .expect("jobs stop promptly");
}

#[test]
fn defaults_expire_uploads_after_a_week_at_half_a_core() {
    let options = JobOptions::default();
    assert_eq!(options.upload_expiry, Some(7 * DAY));
    assert!((options.pace - 1.0).abs() < f64::EPSILON);
}
