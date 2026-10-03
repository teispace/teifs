//! S3 Batch Operations' jobs (`aws s3control create-job`): each runs one operation on
//! every object its CSV manifest lists, as the IAM role the job names, through this
//! server's own S3 service, so a task may do just what a request of that role's may.
//!
//! A new job's manifest is read first: its lines are counted and checked, and the job
//! waits to be confirmed (`Suspended`) or is `Ready`. A running job reads the manifest a
//! piece at a time from where it got to, and fails as a whole once at least 1,000 tasks
//! ran and more than half of them failed, as on AWS.

use std::sync::Arc;

use aws_sdk_s3::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    primitives::DateTime,
    types::{
        ObjectLockLegalHold, ObjectLockLegalHoldStatus, ObjectLockRetention,
        ObjectLockRetentionMode, Tag, Tagging,
    },
};
use bytes::Bytes;
use futures::{StreamExt, stream};
use teifs_iam::Iam;
use teifs_store::StoreError;
use teifs_types::batch::{BatchJob, JobStatus, Manifest, ManifestField, Operation, OperationJob};

use crate::{loopback::Loopback, replicator::said};

/// The service principal a job's role must trust.
pub(crate) const SERVICE: &str = "batchoperations.s3.amazonaws.com";

/// How long a page's session lasts, at most (the role may allow less).
const SESSION_SECONDS: u32 = 3600;

/// How much of a manifest is read at a time, in bytes: no line may be longer.
const CHUNK: u64 = 256 * 1024;

/// The most tasks a page runs.
const TASKS: usize = 100;

/// How many of a page's tasks run at once.
const PARALLEL: usize = 8;

/// How many tasks run before a job may fail for failing too many.
const THRESHOLD_TASKS: u64 = 1000;

/// What runs jobs' tasks: IAM, for their roles' sessions, and the S3 service.
#[derive(Debug, Clone)]
pub(crate) struct Operations {
    pub(crate) iam: Arc<Iam>,
    pub(crate) loopback: Loopback,
}

/// One object a manifest lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Task {
    pub(crate) bucket: String,
    pub(crate) key: String,
    pub(crate) version: Option<String>,
}

/// Why a manifest couldn't be read.
#[derive(Debug)]
enum Unread {
    /// For good: the job fails.
    Failed(String),
    /// For now: the page runs again.
    Later(String),
}

/// A piece of a manifest: its whole lines, and whether it's the last.
struct Piece {
    bytes: Bytes,
    last: bool,
}

/// Runs a page of `job`: reads a new job's manifest, or runs the next tasks of a ready
/// or active one; whether it's done. A job that fails as a whole is left `Failed`.
pub(crate) async fn page(
    operations: &Operations,
    job: &mut BatchJob,
    spec: &OperationJob,
) -> Result<bool, StoreError> {
    let client = match session(operations, job, spec) {
        Ok(client) => client,
        Err(why) => {
            fail(job, why);
            return Ok(false);
        }
    };
    let result = if preparing(job.status) {
        prepare(&client, job, spec).await.map(|()| false)
    } else {
        run(&client, job, spec).await
    };
    match result {
        Ok(done) => Ok(done),
        Err(Unread::Failed(why)) => {
            fail(job, why);
            Ok(false)
        }
        Err(Unread::Later(why)) => Err(StoreError::Io(std::io::Error::other(why))),
    }
}

/// Whether a job's manifest is still to be read.
pub(crate) const fn preparing(status: JobStatus) -> bool {
    matches!(status, JobStatus::New | JobStatus::Preparing)
}

fn fail(job: &mut BatchJob, why: String) {
    job.failed_because(why);
    job.status = JobStatus::Failed;
}

/// A client signed in as the job's role.
fn session(operations: &Operations, job: &BatchJob, spec: &OperationJob) -> Result<Client, String> {
    let name = format!("s3-batch-{}", job.id.replace('-', ""));
    let issued = operations
        .iam
        .service_session(&spec.role_arn, SERVICE, &name, SESSION_SECONDS)
        .map_err(|err| format!("AccessDenied: The job's role can't be assumed: {err}"))?;
    Ok(operations
        .loopback
        .client(&issued.access_key, &issued.secret, &issued.token))
}

/// Counts and checks a new job's tasks; it then waits to be confirmed, or is ready.
async fn prepare(client: &Client, job: &mut BatchJob, spec: &OperationJob) -> Result<(), Unread> {
    job.status = JobStatus::Preparing;
    let (mut offset, mut total) = (0, 0_u64);
    loop {
        let piece = read(client, &spec.manifest, offset).await?;
        for (line, _) in lines(&piece.bytes) {
            let line = line.map_err(|why| manifest_line(total + 1, &why))?;
            if let Some(line) = line {
                task(line, &spec.manifest.fields).map_err(|why| manifest_line(total + 1, &why))?;
                total += 1;
            }
        }
        offset += piece.bytes.len() as u64;
        if piece.last {
            break;
        }
    }
    job.progress.total = Some(total);
    job.progress.offset = 0;
    job.status = if spec.confirmation_required {
        JobStatus::Suspended
    } else {
        JobStatus::Ready
    };
    Ok(())
}

fn manifest_line(n: u64, why: &str) -> Unread {
    Unread::Failed(format!(
        "InvalidManifestContent: Line {n} of the manifest is invalid: {why}"
    ))
}

/// Runs the next tasks; whether they were the last.
async fn run(client: &Client, job: &mut BatchJob, spec: &OperationJob) -> Result<bool, Unread> {
    let piece = read(client, &spec.manifest, job.progress.offset).await?;
    let mut tasks = Vec::new();
    let mut consumed = 0;
    for (line, len) in lines(&piece.bytes) {
        if tasks.len() == TASKS {
            break;
        }
        consumed += len;
        // Checked when the job was prepared; a manifest's version doesn't change.
        if let Ok(Some(line)) = line
            && let Ok(task) = task(line, &spec.manifest.fields)
        {
            tasks.push(task);
        }
    }
    // Made first: a stream that maps borrowed tasks wouldn't be `Send` for every
    // lifetime, as the worker's task must be.
    let running: Vec<_> = tasks
        .iter()
        .map(|task| run_task(client, &spec.operation, task))
        .collect();
    let results: Vec<Result<(), String>> = stream::iter(running).buffered(PARALLEL).collect().await;
    for (task, result) in tasks.iter().zip(results) {
        match result {
            Ok(()) => job.progress.objects += 1,
            Err(why) => {
                tracing::debug!(job = job.id, key = task.key, why, "a batch task failed");
                job.progress.objects_failed += 1;
            }
        }
    }
    job.progress.offset += consumed as u64;
    let p = &job.progress;
    let ran = p.objects + p.objects_failed;
    if failing(p.objects, p.objects_failed) {
        fail(
            job,
            format!(
                "TaskFailureThresholdExceeded: More than half of the job's {ran} tasks so far \
                 failed."
            ),
        );
        return Ok(false);
    }
    Ok(piece.last && consumed == piece.bytes.len())
}

/// Whether a job fails for its tasks: at least 1,000 ran, and more than half failed.
const fn failing(succeeded: u64, failed: u64) -> bool {
    let ran = succeeded + failed;
    ran >= THRESHOLD_TASKS && failed * 2 > ran
}

/// Reads the manifest's whole lines from `offset` on, a piece at a time.
async fn read(client: &Client, manifest: &Manifest, offset: u64) -> Result<Piece, Unread> {
    let got = client
        .get_object()
        .bucket(&manifest.bucket)
        .key(&manifest.key)
        .set_version_id(manifest.version_id.clone())
        .if_match(&manifest.etag)
        .range(format!("bytes={offset}-{}", offset + CHUNK - 1))
        .send()
        .await;
    let output = match got {
        Ok(output) => output,
        // Nothing from there on: an empty manifest, or one read to its end.
        Err(err) if err.code() == Some("InvalidRange") => {
            return Ok(Piece {
                bytes: Bytes::new(),
                last: true,
            });
        }
        Err(err) => return Err(unread(&err)),
    };
    let last = output
        .content_range()
        .and_then(|range| range.rsplit_once('/'))
        .and_then(|(range, size)| {
            let end = range.rsplit_once('-')?.1.parse::<u64>().ok()?;
            Some(end + 1 >= size.parse::<u64>().ok()?)
        })
        .unwrap_or(true);
    let bytes = output
        .body
        .collect()
        .await
        .map_err(|err| Unread::Later(format!("Reading the manifest failed: {err}")))?
        .into_bytes();
    if last {
        return Ok(Piece { bytes, last });
    }
    match bytes.iter().rposition(|&b| b == b'\n') {
        Some(end) => Ok(Piece {
            bytes: bytes.slice(..=end),
            last,
        }),
        None => Err(Unread::Failed(format!(
            "InvalidManifestContent: A line of the manifest is longer than {} KiB.",
            CHUNK / 1024
        ))),
    }
}

fn unread<E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static>(
    err: &SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> Unread {
    let status = err.raw_response().map(|r| r.status().as_u16());
    let why = format!(
        "ManifestReadFailed: Reading the manifest failed: {}",
        said(err)
    );
    if for_good(status) {
        Unread::Failed(why)
    } else {
        Unread::Later(why)
    }
}

/// Whether an answer of `status` (none: no answer) refuses a read for good: a client
/// error, but for a timeout or throttling.
fn for_good(status: Option<u16>) -> bool {
    status.is_some_and(|status| (400..500).contains(&status) && !matches!(status, 408 | 429))
}

/// A piece's lines, each with its length in bytes (its line break included): `None`
/// for a blank one.
fn lines(bytes: &[u8]) -> impl Iterator<Item = (Result<Option<&str>, String>, usize)> {
    bytes.split_inclusive(|&b| b == b'\n').map(|raw| {
        let text = raw.strip_suffix(b"\n").unwrap_or(raw);
        let text = text.strip_suffix(b"\r").unwrap_or(text);
        let line = std::str::from_utf8(text)
            .map(|line| (!line.trim().is_empty()).then_some(line))
            .map_err(|_| "it isn't UTF-8".to_owned());
        (line, raw.len())
    })
}

/// The object a manifest's line names.
pub(crate) fn task(line: &str, fields: &[ManifestField]) -> Result<Task, String> {
    let columns = columns(line)?;
    if columns.len() != fields.len() {
        return Err(format!(
            "it has {} columns where the manifest's fields are {}",
            columns.len(),
            fields.len()
        ));
    }
    let (mut bucket, mut key, mut version) = (None, None, None);
    for (field, value) in fields.iter().zip(columns) {
        match field {
            ManifestField::Bucket => bucket = Some(value),
            ManifestField::Key => key = Some(decode_key(&value)?),
            ManifestField::VersionId => version = Some(value).filter(|v| !v.is_empty()),
            ManifestField::Ignore => {}
        }
    }
    match (bucket, key) {
        (Some(bucket), Some(key)) if !bucket.is_empty() && !key.is_empty() => Ok(Task {
            bucket,
            key,
            version,
        }),
        _ => Err("it names no bucket or no key".to_owned()),
    }
}

/// A line's columns, separated by commas, each perhaps in double quotes (`""` is one).
fn columns(line: &str) -> Result<Vec<String>, String> {
    let mut columns = Vec::new();
    let mut column = String::new();
    let (mut quoted, mut at_start) = (false, true);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted => {
                if chars.next_if_eq(&'"').is_some() {
                    column.push('"');
                } else {
                    quoted = false;
                }
            }
            '"' if at_start => quoted = true,
            ',' if !quoted => {
                columns.push(std::mem::take(&mut column));
                at_start = true;
                continue;
            }
            c => column.push(c),
        }
        at_start = false;
    }
    if quoted {
        return Err("a quote isn't closed".to_owned());
    }
    columns.push(column);
    Ok(columns)
}

/// A key as manifests encode it: URL-encoded, with `+` for a space.
fn decode_key(encoded: &str) -> Result<String, String> {
    percent_encoding::percent_decode_str(&encoded.replace('+', " "))
        .decode_utf8()
        .map(String::from)
        .map_err(|_| "its key isn't URL-encoded UTF-8".to_owned())
}

/// Runs one task; why it failed.
async fn run_task(client: &Client, operation: &Operation, task: &Task) -> Result<(), String> {
    let (bucket, key, version) = (&task.bucket, &task.key, task.version.clone());
    match operation {
        Operation::PutObjectTagging { tags } => {
            let tags = tags
                .iter()
                .map(|kv| Tag::builder().key(&kv.key).value(&kv.value).build())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.to_string())?;
            let tagging = Tagging::builder()
                .set_tag_set(Some(tags))
                .build()
                .map_err(|err| err.to_string())?;
            client
                .put_object_tagging()
                .bucket(bucket)
                .key(key)
                .set_version_id(version)
                .tagging(tagging)
                .send()
                .await
                .map(drop)
                .map_err(|err| said(&err))
        }
        Operation::DeleteObjectTagging => client
            .delete_object_tagging()
            .bucket(bucket)
            .key(key)
            .set_version_id(version)
            .send()
            .await
            .map(drop)
            .map_err(|err| said(&err)),
        Operation::PutObjectLegalHold { on } => {
            let status = if *on {
                ObjectLockLegalHoldStatus::On
            } else {
                ObjectLockLegalHoldStatus::Off
            };
            client
                .put_object_legal_hold()
                .bucket(bucket)
                .key(key)
                .set_version_id(version)
                .legal_hold(ObjectLockLegalHold::builder().status(status).build())
                .send()
                .await
                .map(drop)
                .map_err(|err| said(&err))
        }
        Operation::PutObjectRetention {
            mode,
            retain_until_ms,
            bypass_governance,
        } => {
            let retention = ObjectLockRetention::builder()
                .set_mode(mode.as_deref().map(ObjectLockRetentionMode::from))
                .set_retain_until_date(retain_until_ms.map(DateTime::from_millis))
                .build();
            client
                .put_object_retention()
                .bucket(bucket)
                .key(key)
                .set_version_id(version)
                .retention(retention)
                .bypass_governance_retention(*bypass_governance)
                .send()
                .await
                .map(drop)
                .map_err(|err| said(&err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELDS: [ManifestField; 3] = [
        ManifestField::Bucket,
        ManifestField::Key,
        ManifestField::VersionId,
    ];

    #[test]
    fn lines_name_a_bucket_an_encoded_key_and_perhaps_a_version() {
        assert_eq!(
            task("photos,2026/a+b%2Bc%C3%BC.jpg,v1", &FIELDS),
            Ok(Task {
                bucket: "photos".to_owned(),
                key: "2026/a b+cü.jpg".to_owned(),
                version: Some("v1".to_owned()),
            })
        );
        assert_eq!(
            task(r#""photos","a%2C""b""","""#, &FIELDS).map(|t| (t.key, t.version)),
            Ok(("a,\"b\"".to_owned(), None))
        );
        let two = [ManifestField::Bucket, ManifestField::Key];
        assert_eq!(
            task("photos,cat.jpg", &two).map(|t| t.key),
            Ok("cat.jpg".to_owned())
        );
        let skipped = [
            ManifestField::Ignore,
            ManifestField::Bucket,
            ManifestField::Key,
        ];
        assert_eq!(
            task("x,photos,cat.jpg", &skipped).map(|t| t.bucket),
            Ok("photos".to_owned())
        );
        for wrong in [
            "photos,cat.jpg",
            "photos,a,b,c",
            ",cat.jpg,",
            "photos,,v1",
            "\"photos,a,b",
            "photos,a,\"v1",
        ] {
            assert!(task(wrong, &FIELDS).is_err(), "{wrong}");
        }
        assert!(task("photos,%FF,", &FIELDS).is_err());
        // A quote inside a column is the column's.
        assert_eq!(
            task("photos,a\"b,", &FIELDS).map(|t| t.key),
            Ok("a\"b".to_owned())
        );
    }

    #[test]
    fn client_errors_but_timeouts_and_throttling_refuse_a_manifest_for_good() {
        for status in [400, 403, 404, 412, 416] {
            assert!(for_good(Some(status)), "{status}");
        }
        for status in [None, Some(408), Some(429), Some(500), Some(503), Some(399)] {
            assert!(!for_good(status), "{status:?}");
        }
    }

    #[test]
    fn a_job_fails_when_most_of_at_least_a_thousand_tasks_failed() {
        assert!(failing(0, 1000));
        assert!(failing(499, 501));
        assert!(!failing(500, 500));
        assert!(!failing(0, 999));
        assert!(failing(2000, 2001));
        assert!(!failing(1000, 0));
    }

    #[test]
    fn a_piece_splits_into_lines_with_their_lengths() {
        let piece = b"a,b\r\n\nc,d\n\xff\ne,f";
        let lines: Vec<_> = lines(piece).collect();
        assert_eq!(lines[0], (Ok(Some("a,b")), 5));
        assert_eq!(lines[1], (Ok(None), 1));
        assert_eq!(lines[2], (Ok(Some("c,d")), 4));
        assert!(lines[3].0.is_err());
        assert_eq!(lines[4], (Ok(Some("e,f")), 3));
        assert_eq!(lines.len(), 5);
    }
}
