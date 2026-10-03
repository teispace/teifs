//! S3 Batch Operations' completion reports (`Report_CSV_20180820`): when a job ends,
//! the results of its tasks (every one, or the failed ones) are written to the report's
//! bucket as the job's role, as CSV files under `{prefix}/job-{id}/results/`, and
//! `{prefix}/job-{id}/manifest.json` names them, as AWS writes them.
//!
//! Each result is a line of `Bucket, Key (URL-encoded), VersionId, TaskStatus,
//! HTTPStatusCode, ErrorCode, ResultMessage`: AWS's rows put the status code before the
//! error code, whatever the schema they name says.

use aws_sdk_s3::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
};
use md5::{Digest, Md5};
use serde::Serialize;
use teifs_store::Store;
use teifs_types::batch::{BatchJob, JobReport};

use crate::{
    batch_operations::{Failure, Stop, Task, stop},
    replicator::said,
};

/// The report's format.
pub(crate) const FORMAT: &str = "Report_CSV_20180820";

/// The columns, as AWS names them in a report's manifest.
const SCHEMA: &str = "Bucket, Key, VersionId, TaskStatus, ErrorCode, HTTPStatusCode, ResultMessage";

/// How many results are read at a time.
const ROWS: usize = 10_000;

/// A results file larger than this goes in parts of this size.
const PART: usize = 16 * 1024 * 1024;

/// A task's result, as a line of its report.
pub(crate) fn line(task: &Task, result: &Result<(), Failure>) -> String {
    let (status, http, code, message) = match result {
        Ok(()) => ("succeeded", "200".to_owned(), "", "Successful"),
        Err(failure) => (
            "failed",
            failure.status.map(|s| s.to_string()).unwrap_or_default(),
            failure.code.as_str(),
            failure.message.as_str(),
        ),
    };
    let key = crate::encode::url(&task.key);
    let version = task.version.as_deref().unwrap_or_default();
    [&task.bucket, &key, version, status, &http, code, message]
        .map(csv)
        .join(",")
}

/// A CSV field: in double quotes when it has a comma, a quote or a line break.
fn csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

/// Where a job's report goes in its bucket: `{prefix}/job-{id}`.
fn base(prefix: &str, id: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        format!("job-{id}")
    } else {
        format!("{prefix}/job-{id}")
    }
}

/// Writes `job`'s report as its role, then forgets its results.
pub(crate) async fn write(
    client: &Client,
    store: &Store,
    job: &BatchJob,
    report: &JobReport,
) -> Result<(), Stop> {
    let base = base(&report.prefix, &job.id);
    let mut results = Vec::new();
    for failed in [false, true] {
        if failed || !report.failed_only {
            let file = results_file(client, store, (job, report), &base, failed).await?;
            results.extend(file);
        }
    }
    let manifest = ReportManifest {
        format: FORMAT,
        report_creation_date: crate::minio_kms::rfc3339(crate::admin::millis(
            std::time::SystemTime::now(),
        )),
        results,
        report_schema: SCHEMA,
    };
    let body = serde_json::to_vec(&manifest).map_err(|err| Stop::Later(err.to_string()))?;
    let key = format!("{base}/manifest.json");
    client
        .put_object()
        .bucket(&report.bucket)
        .key(&key)
        .content_type("application/json")
        .body(ByteStream::from(body))
        .send()
        .await
        .map_err(|err| unwritten(&err))?;
    store
        .forget_batch_results(&job.id)
        .await
        .map_err(|err| Stop::Later(err.to_string()))
}

/// Writes the results that failed (or succeeded) to a file of their own; what the
/// manifest says of it, none when there are none.
async fn results_file(
    client: &Client,
    store: &Store,
    (job, report): (&BatchJob, &JobReport),
    base: &str,
    failed: bool,
) -> Result<Option<ResultsFile>, Stop> {
    let status = if failed { "failed" } else { "succeeded" };
    // Named by the job and status (40 hex digits, as AWS names them), so a report
    // written again replaces its files.
    let name = results_name(&job.id, status);
    let mut file = Upload {
        client,
        bucket: &report.bucket,
        key: format!("{base}/results/{name}.csv"),
        id: None,
        parts: Vec::new(),
    };
    let (mut md5, mut buffer, mut after) = (Md5::new(), Vec::new(), None);
    loop {
        let rows = store
            .batch_results(&job.id, failed, after, ROWS)
            .await
            .map_err(|err| Stop::Later(err.to_string()))?;
        let Some((last, _)) = rows.last() else {
            break;
        };
        after = Some(*last);
        for (_, line) in rows {
            md5.update(line.as_bytes());
            md5.update(b"\n");
            buffer.extend_from_slice(line.as_bytes());
            buffer.push(b'\n');
        }
        while buffer.len() >= PART {
            let rest = buffer.split_off(PART);
            file.part(std::mem::replace(&mut buffer, rest)).await?;
        }
    }
    if after.is_none() {
        return Ok(None);
    }
    let key = file.key.clone();
    file.finish(buffer).await?;
    Ok(Some(ResultsFile {
        task_execution_status: status,
        bucket: report.bucket.clone(),
        md5_checksum: crate::inventory::hex(&md5.finalize()),
        key,
    }))
}

/// A results file's name: a SHA-1 of its job and status.
fn results_name(id: &str, status: &str) -> String {
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{id}/{status}").as_bytes(),
    );
    crate::inventory::hex(digest.as_ref())
}

/// A results file being written: in one `PutObject`, or in parts once it's large.
struct Upload<'a> {
    client: &'a Client,
    bucket: &'a str,
    key: String,
    /// The multipart upload, once one started.
    id: Option<String>,
    parts: Vec<CompletedPart>,
}

impl Upload<'_> {
    /// Sends a part, starting the upload with the first.
    async fn part(&mut self, body: Vec<u8>) -> Result<(), Stop> {
        let id = if let Some(id) = &self.id {
            id.clone()
        } else {
            let started = self
                .client
                .create_multipart_upload()
                .bucket(self.bucket)
                .key(&self.key)
                .content_type("text/csv")
                .send()
                .await
                .map_err(|err| unwritten(&err))?;
            let id = started.upload_id.unwrap_or_default();
            self.id = Some(id.clone());
            id
        };
        let number = i32::try_from(self.parts.len() + 1).unwrap_or(i32::MAX);
        let sent = self
            .client
            .upload_part()
            .bucket(self.bucket)
            .key(&self.key)
            .upload_id(&id)
            .part_number(number)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|err| unwritten(&err))?;
        self.parts.push(
            CompletedPart::builder()
                .part_number(number)
                .set_e_tag(sent.e_tag)
                .build(),
        );
        Ok(())
    }

    /// Writes the rest: the whole file when it's small, else its last part.
    async fn finish(mut self, rest: Vec<u8>) -> Result<(), Stop> {
        if self.id.is_none() {
            self.client
                .put_object()
                .bucket(self.bucket)
                .key(&self.key)
                .content_type("text/csv")
                .body(ByteStream::from(rest))
                .send()
                .await
                .map_err(|err| unwritten(&err))?;
            return Ok(());
        }
        if !rest.is_empty() {
            self.part(rest).await?;
        }
        let id = self.id.take().unwrap_or_default();
        self.client
            .complete_multipart_upload()
            .bucket(self.bucket)
            .key(&self.key)
            .upload_id(id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(std::mem::take(&mut self.parts)))
                    .build(),
            )
            .send()
            .await
            .map_err(|err| unwritten(&err))?;
        Ok(())
    }
}

fn unwritten<E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static>(
    err: &SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> Stop {
    stop(
        err.raw_response().map(|r| r.status().as_u16()),
        format!(
            "ReportWriteFailed: Writing the completion report failed: {}",
            said(err)
        ),
    )
}

/// A report's `manifest.json`.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ReportManifest {
    format: &'static str,
    report_creation_date: String,
    results: Vec<ResultsFile>,
    report_schema: &'static str,
}

/// A results file, as the manifest names it.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ResultsFile {
    task_execution_status: &'static str,
    bucket: String,
    #[serde(rename = "MD5Checksum")]
    md5_checksum: String,
    key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(key: &str, version: Option<&str>) -> Task {
        Task {
            bucket: "photos".to_owned(),
            key: key.to_owned(),
            version: version.map(str::to_owned),
        }
    }

    #[test]
    fn results_are_lines_as_aws_writes_them() {
        assert_eq!(
            line(&task("a b/ü.jpg", Some("v1")), &Ok(())),
            "photos,a%20b/%C3%BC.jpg,v1,succeeded,200,,Successful"
        );
        let failure = Failure {
            status: Some(403),
            code: "AccessDenied".to_owned(),
            message: "Access Denied, \"really\"".to_owned(),
        };
        assert_eq!(
            line(&task("a,b", None), &Err(failure)),
            r#"photos,a%2Cb,,failed,403,AccessDenied,"Access Denied, ""really""""#
        );
        let unanswered = Failure {
            status: None,
            code: "InternalError".to_owned(),
            message: "no answer\nat all".to_owned(),
        };
        assert_eq!(
            line(&task("k", None), &Err(unanswered)),
            "photos,k,,failed,,InternalError,\"no answer\nat all\""
        );
        assert_eq!(csv("a\rb"), "\"a\rb\"");
        assert_eq!(csv("plain text"), "plain text");
    }

    #[test]
    fn results_files_are_named_as_aws_names_them() {
        let name = results_name("j1", "failed");
        assert_eq!(name, "c5fa7ab547abd70c4a8698a49e3842c1fab7cc24");
        assert_ne!(name, results_name("j1", "succeeded"));
        assert_ne!(name, results_name("j2", "failed"));
    }

    #[test]
    fn reports_go_under_their_prefix_and_job() {
        assert_eq!(base("", "j1"), "job-j1");
        assert_eq!(base("reports", "j1"), "reports/job-j1");
        assert_eq!(base("reports/", "j1"), "reports/job-j1");
    }
}
