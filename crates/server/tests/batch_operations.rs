//! S3 Batch Operations over the official SDK (`aws-sdk-s3control`): a job runs its
//! operation on every object its CSV manifest lists, as the IAM role it names, which may
//! do just what its policies say; it waits to be confirmed when asked; and callers need
//! `s3:CreateJob` and `iam:PassRole` on the role.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::Duration;

use aws_sdk_s3::{Client, primitives::ByteStream};
use aws_sdk_s3control::{
    config::{
        Credentials, Region,
        endpoint::{Endpoint, EndpointFuture, Params, ResolveEndpoint},
    },
    operation::describe_job::DescribeJobOutput,
    types::{
        JobManifest, JobManifestFieldName, JobManifestFormat, JobManifestLocation, JobManifestSpec,
        JobOperation, JobReport, JobReportFormat, JobReportScope, JobStatus, RequestedJobStatus,
        S3DeleteObjectTaggingOperation, S3ObjectLockLegalHold, S3ObjectLockLegalHoldStatus,
        S3ObjectLockRetentionMode, S3Retention, S3SetObjectLegalHoldOperation,
        S3SetObjectRetentionOperation, S3SetObjectTaggingOperation, S3Tag,
    },
};
use md5::{Digest, Md5};
use teifs_iam::{NewRole, Owner};

mod common;
mod signing;

use common::{SECRET_KEY, Server, client, code, start, user};

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"sts:AssumeRole","Principal":{"Service":"batchoperations.s3.amazonaws.com"}}]}"#;

/// What the job role may do: read manifests, and tag photos.
const TAGGER: &str = r#"{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::manifests/*"},
  {"Effect":"Allow","Action":["s3:PutObjectTagging","s3:PutObjectVersionTagging",
    "s3:DeleteObjectTagging","s3:DeleteObjectVersionTagging","s3:PutObjectLegalHold",
    "s3:PutObjectRetention","s3:BypassGovernanceRetention"],"Resource":"arn:aws:s3:::photos/*"}]}"#;

#[derive(Debug)]
struct Direct(String);

impl ResolveEndpoint for Direct {
    fn resolve_endpoint<'a>(&'a self, _: &'a Params) -> EndpointFuture<'a> {
        EndpointFuture::ready(Ok(Endpoint::builder().url(self.0.clone()).build()))
    }
}

fn control(server: &Server, access_key: &str, secret: &str) -> aws_sdk_s3control::Client {
    let config = aws_sdk_s3control::Config::builder()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .endpoint_resolver(Direct(server.endpoint.clone()))
        .credentials_provider(Credentials::new(access_key, secret, None, None, "tests"))
        .build();
    aws_sdk_s3control::Client::from_conf(config)
}

/// A role batch jobs may run as, allowed `policy`; its ARN.
fn role(server: &Server, name: &str, trust: &str, policy: &str) -> String {
    let role = server
        .iam
        .create_role(
            name,
            &NewRole {
                trust,
                ..NewRole::default()
            },
        )
        .unwrap();
    server
        .iam
        .put_inline(Owner::Role(name), "policy", policy)
        .unwrap();
    role.arn
}

/// Buckets `photos` (with `objects`) and `manifests`.
async fn buckets(root: &Client, objects: &[&str]) {
    for bucket in ["photos", "manifests"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    for key in objects {
        put(root, "photos", key, "photo").await;
    }
}

async fn put(root: &Client, bucket: &str, key: &str, body: &str) -> String {
    root.put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(body.as_bytes().to_vec()))
        .send()
        .await
        .unwrap()
        .e_tag
        .unwrap()
}

/// A manifest of `lines` at `manifests/{name}`.
async fn manifest(root: &Client, name: &str, lines: &[&str]) -> JobManifest {
    let etag = put(root, "manifests", name, &lines.join("\n")).await;
    manifest_at(
        name,
        &etag,
        &[JobManifestFieldName::Bucket, JobManifestFieldName::Key],
    )
}

fn manifest_at(name: &str, etag: &str, fields: &[JobManifestFieldName]) -> JobManifest {
    JobManifest::builder()
        .spec(
            JobManifestSpec::builder()
                .format(JobManifestFormat::S3BatchOperationsCsv20180820)
                .set_fields(Some(fields.to_vec()))
                .build()
                .unwrap(),
        )
        .location(
            JobManifestLocation::builder()
                .object_arn(format!("arn:aws:s3:::manifests/{name}"))
                .e_tag(etag)
                .build()
                .unwrap(),
        )
        .build()
}

fn tag(key: &str, value: &str) -> S3Tag {
    S3Tag::builder().key(key).value(value).build().unwrap()
}

fn tagging(key: &str, value: &str) -> JobOperation {
    JobOperation::builder()
        .s3_put_object_tagging(
            S3SetObjectTaggingOperation::builder()
                .tag_set(tag(key, value))
                .build(),
        )
        .build()
}

fn no_report() -> JobReport {
    JobReport::builder().enabled(false).build()
}

/// A report to the `reports` bucket, under `prefix`.
fn report(prefix: Option<&str>, scope: JobReportScope) -> JobReport {
    JobReport::builder()
        .enabled(true)
        .bucket("arn:aws:s3:::reports")
        .format(JobReportFormat::ReportCsv20180820)
        .set_prefix(prefix.map(str::to_owned))
        .report_scope(scope)
        .build()
}

/// Makes a job; its id.
async fn create(
    s3control: &aws_sdk_s3control::Client,
    account: &str,
    job: (JobOperation, JobManifest, &str),
    options: (&str, i32, bool),
) -> Result<String, String> {
    create_reported(s3control, account, job, options, no_report()).await
}

/// Makes a job that writes `report`; its id.
async fn create_reported(
    s3control: &aws_sdk_s3control::Client,
    account: &str,
    (operation, manifest, role): (JobOperation, JobManifest, &str),
    (token, priority, confirm): (&str, i32, bool),
    report: JobReport,
) -> Result<String, String> {
    // Boxed: the request is a large future.
    Box::pin(
        s3control
            .create_job()
            .account_id(account)
            .operation(operation)
            .manifest(manifest)
            .report(report)
            .client_request_token(token)
            .priority(priority)
            .role_arn(role)
            .confirmation_required(confirm)
            .description("tag the photos")
            .send(),
    )
    .await
    .map(|out| out.job_id.unwrap())
    .map_err(|err| {
        aws_sdk_s3control::error::ProvideErrorMetadata::code(&err)
            .unwrap_or("?")
            .to_owned()
    })
}

async fn describe(
    s3control: &aws_sdk_s3control::Client,
    account: &str,
    id: &str,
) -> DescribeJobOutput {
    s3control
        .describe_job()
        .account_id(account)
        .job_id(id)
        .send()
        .await
        .unwrap()
}

/// The job once it's `status`.
async fn wait_for(
    s3control: &aws_sdk_s3control::Client,
    account: &str,
    id: &str,
    status: &JobStatus,
) -> DescribeJobOutput {
    for _ in 0..1200 {
        let described = describe(s3control, account, id).await;
        let job = described.job.as_ref().unwrap();
        if job.status.as_ref() == Some(status) {
            return described;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} never became {status:?}");
}

async fn tags_of(root: &Client, key: &str) -> Vec<(String, String)> {
    root.get_object_tagging()
        .bucket("photos")
        .key(key)
        .send()
        .await
        .unwrap()
        .tag_set
        .into_iter()
        .map(|t| (t.key, t.value))
        .collect()
}

#[tokio::test]
async fn a_job_tags_every_object_its_manifest_lists() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &["a.jpg", "b c+d.jpg"]).await;
    let role = role(&server, "batch", TRUST, TAGGER);
    let lines = [
        "photos,a.jpg",
        "\"photos\",b+c%2Bd.jpg",
        "",
        "photos,missing.jpg",
    ];
    let manifest = manifest(&root, "tag.csv", &lines).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("team", "blue"), manifest.clone(), role.as_str());
    let id = create(&s3control, &account, job.clone(), ("token-1", 10, false))
        .await
        .unwrap();

    let done = wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    let described = done.job.unwrap();
    let progress = described.progress_summary.unwrap();
    assert_eq!(progress.total_number_of_tasks, Some(3));
    assert_eq!(progress.number_of_tasks_succeeded, Some(2));
    assert_eq!(progress.number_of_tasks_failed, Some(1));
    assert_eq!(described.priority, 10);
    assert_eq!(described.description.as_deref(), Some("tag the photos"));
    assert_eq!(described.role_arn.as_deref(), Some(role.as_str()));
    assert_eq!(
        described.job_arn.unwrap(),
        format!("arn:aws:s3:us-east-1:{account}:job/{id}")
    );
    assert!(described.termination_date.is_some());
    let operation = described.operation.unwrap().s3_put_object_tagging.unwrap();
    assert_eq!(operation.tag_set.unwrap(), vec![tag("team", "blue")]);
    let location = described.manifest.unwrap().location.unwrap();
    assert_eq!(location.object_arn, "arn:aws:s3:::manifests/tag.csv");
    for key in ["a.jpg", "b c+d.jpg"] {
        assert_eq!(tags_of(&root, key).await, [("team".into(), "blue".into())]);
    }

    // The same request makes no other job; another with its token is refused.
    let again = create(&s3control, &account, job.clone(), ("token-1", 10, false)).await;
    assert_eq!(again, Ok(id.clone()));
    let other = create(&s3control, &account, job, ("token-1", 11, false)).await;
    assert_eq!(other, Err("IdempotencyException".to_owned()));

    let listed = s3control
        .list_jobs()
        .account_id(&account)
        .job_statuses(aws_sdk_s3control::types::JobStatus::Complete)
        .send()
        .await
        .unwrap()
        .jobs
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].job_id.as_deref(), Some(id.as_str()));
    assert_eq!(
        listed[0].operation,
        Some(aws_sdk_s3control::types::OperationName::S3PutObjectTagging)
    );
    let active = s3control
        .list_jobs()
        .account_id(&account)
        .job_statuses(aws_sdk_s3control::types::JobStatus::Active)
        .send()
        .await
        .unwrap();
    assert!(active.jobs.unwrap_or_default().is_empty());
    // Cancelling a job that ended is refused.
    let cancel = s3control
        .update_job_status()
        .account_id(&account)
        .job_id(&id)
        .requested_job_status(RequestedJobStatus::Cancelled)
        .send()
        .await;
    assert_eq!(code(cancel), "JobStatusException");
}

#[tokio::test]
async fn a_job_waits_until_it_is_confirmed() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &[]).await;
    root.put_object()
        .bucket("photos")
        .key("a.jpg")
        .tagging("k=v")
        .send()
        .await
        .unwrap();
    let role = role(&server, "batch", TRUST, TAGGER);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg"]).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let untag = JobOperation::builder()
        .s3_delete_object_tagging(S3DeleteObjectTaggingOperation::builder().build())
        .build();
    let id = create(
        &s3control,
        &account,
        (untag, manifest, &role),
        ("t", 1, true),
    )
    .await
    .unwrap();
    let suspended = wait_for(&s3control, &account, &id, &JobStatus::Suspended).await;
    let job = suspended.job.unwrap();
    assert_eq!(
        job.suspended_cause.as_deref(),
        Some("AWAITING_CONFIRMATION")
    );
    assert_eq!(job.progress_summary.unwrap().total_number_of_tasks, Some(1));
    assert_eq!(tags_of(&root, "a.jpg").await.len(), 1);

    let priority = s3control
        .update_job_priority()
        .account_id(&account)
        .job_id(&id)
        .priority(42)
        .send()
        .await
        .unwrap();
    assert_eq!(priority.priority, 42);

    let confirmed = s3control
        .update_job_status()
        .account_id(&account)
        .job_id(&id)
        .requested_job_status(RequestedJobStatus::Ready)
        .status_update_reason("checked")
        .send()
        .await
        .unwrap();
    assert_eq!(confirmed.status, Some(JobStatus::Ready));
    let done = wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    let job = done.job.unwrap();
    assert_eq!(job.priority, 42);
    assert_eq!(job.status_update_reason.as_deref(), Some("checked"));
    assert!(tags_of(&root, "a.jpg").await.is_empty());

    let missing = s3control
        .describe_job()
        .account_id(&account)
        .job_id("00000000-0000-0000-0000-000000000000")
        .send()
        .await;
    assert_eq!(code(missing), "NotFoundException");
}

#[tokio::test]
async fn a_cancelled_job_stops() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &[]).await;
    let role = role(&server, "batch", TRUST, TAGGER);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg"]).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("a", "b"), manifest, role.as_str());
    let id = create(&s3control, &account, job, ("t", 1, true))
        .await
        .unwrap();
    wait_for(&s3control, &account, &id, &JobStatus::Suspended).await;
    s3control
        .put_job_tagging()
        .account_id(&account)
        .job_id(&id)
        .tags(tag("owner", "ops"))
        .send()
        .await
        .unwrap();
    let tags = s3control
        .get_job_tagging()
        .account_id(&account)
        .job_id(&id)
        .send()
        .await
        .unwrap()
        .tags
        .unwrap();
    assert_eq!(tags, vec![tag("owner", "ops")]);
    s3control
        .delete_job_tagging()
        .account_id(&account)
        .job_id(&id)
        .send()
        .await
        .unwrap();
    let tags = s3control
        .get_job_tagging()
        .account_id(&account)
        .job_id(&id)
        .send()
        .await
        .unwrap();
    assert!(tags.tags.unwrap_or_default().is_empty());

    let cancelled = s3control
        .update_job_status()
        .account_id(&account)
        .job_id(&id)
        .requested_job_status(RequestedJobStatus::Cancelled)
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled.status, Some(JobStatus::Cancelled));
    let job = describe(&s3control, &account, &id).await.job.unwrap();
    assert_eq!(job.status, Some(JobStatus::Cancelled));
    assert_eq!(
        job.progress_summary.unwrap().number_of_tasks_succeeded,
        Some(0)
    );
    let confirm = s3control
        .update_job_status()
        .account_id(&account)
        .job_id(&id)
        .requested_job_status(RequestedJobStatus::Ready)
        .send()
        .await;
    assert_eq!(code(confirm), "JobStatusException");
}

#[tokio::test]
async fn tasks_may_do_only_what_the_role_may() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &["a.jpg"]).await;
    let reader = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",
      "Resource":"arn:aws:s3:::manifests/*"}]}"#;
    let role = role(&server, "reader", TRUST, reader);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg"]).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("a", "b"), manifest.clone(), role.as_str());
    let id = create(&s3control, &account, job, ("t1", 1, false))
        .await
        .unwrap();
    let done = wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    let progress = done.job.unwrap().progress_summary.unwrap();
    assert_eq!(progress.number_of_tasks_failed, Some(1));
    assert!(tags_of(&root, "a.jpg").await.is_empty());

    // A role that doesn't trust the service, or can't read the manifest, fails the job.
    let untrusting = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
      "Principal":{"Service":"logging.s3.amazonaws.com"}}]}"#;
    let other = self::role(&server, "other", untrusting, TAGGER);
    let blind = self::role(
        &server,
        "blind",
        TRUST,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObjectTagging","Resource":"*"}]}"#,
    );
    let stale = manifest_at(
        "m.csv",
        "\"0123456789abcdef0123456789abcdef\"",
        &[JobManifestFieldName::Bucket, JobManifestFieldName::Key],
    );
    for (token, role, manifest, (code, why)) in [
        (
            "t2",
            other.as_str(),
            manifest.clone(),
            ("AccessDenied", "can't be assumed"),
        ),
        (
            "t3",
            blind.as_str(),
            manifest,
            ("ManifestReadFailed", "AccessDenied"),
        ),
        (
            "t4",
            role.as_str(),
            stale,
            ("ManifestReadFailed", "PreconditionFailed"),
        ),
    ] {
        let job = (tagging("a", "b"), manifest, role);
        let id = create(&s3control, &account, job, (token, 1, false))
            .await
            .unwrap();
        let failed = wait_for(&s3control, &account, &id, &JobStatus::Failed).await;
        let reasons = failed.job.unwrap().failure_reasons.unwrap();
        assert_eq!(reasons.len(), 1, "{token}: {reasons:?}");
        assert_eq!(reasons[0].failure_code.as_deref(), Some(code), "{token}");
        let reason = reasons[0].failure_reason.as_deref().unwrap();
        assert!(reason.contains(why), "{token}: {reason}");
    }
}

#[tokio::test]
async fn a_job_fails_once_most_of_its_first_thousand_tasks_fail() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &[]).await;
    root.create_bucket().bucket("reports").send().await.unwrap();
    let role = role(&server, "batch", TRUST, REPORTER);
    let lines: Vec<String> = (0..1100).map(|n| format!("photos,missing-{n}")).collect();
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    let manifest = manifest(&root, "m.csv", &lines).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("a", "b"), manifest, role.as_str());
    let failed = report(None, JobReportScope::FailedTasksOnly);
    let id = create_reported(&s3control, &account, job, ("t", 1, false), failed)
        .await
        .unwrap();
    let failed = wait_for(&s3control, &account, &id, &JobStatus::Failed).await;
    let job = failed.job.unwrap();
    let progress = job.progress_summary.unwrap();
    assert_eq!(progress.total_number_of_tasks, Some(1100));
    assert_eq!(progress.number_of_tasks_failed, Some(1000));
    let reason = &job.failure_reasons.unwrap()[0];
    assert_eq!(
        reason.failure_code.as_deref(),
        Some("TaskFailureThresholdExceeded")
    );
    // What ran is reported, in the order the manifest lists it.
    let files = report_of(&root, &format!("job-{id}")).await;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].1.len(), 1000);
    assert!(files[0].1[999].starts_with("photos,missing-999,"));
}

fn hold() -> JobOperation {
    let hold = S3ObjectLockLegalHold::builder()
        .status(S3ObjectLockLegalHoldStatus::On)
        .build()
        .unwrap();
    JobOperation::builder()
        .s3_put_object_legal_hold(
            S3SetObjectLegalHoldOperation::builder()
                .legal_hold(hold)
                .build(),
        )
        .build()
}

/// Governance-mode retention for `time` from now.
fn retain(time: Duration, bypass: bool) -> JobOperation {
    let retention = S3Retention::builder()
        .mode(S3ObjectLockRetentionMode::Governance)
        .retain_until_date((std::time::SystemTime::now() + time).into())
        .build();
    JobOperation::builder()
        .s3_put_object_retention(
            S3SetObjectRetentionOperation::builder()
                .bypass_governance_retention(bypass)
                .retention(retention)
                .build(),
        )
        .build()
}

#[tokio::test]
async fn jobs_set_legal_holds_and_retention() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    root.create_bucket()
        .bucket("photos")
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
    root.create_bucket()
        .bucket("manifests")
        .send()
        .await
        .unwrap();
    let version = root
        .put_object()
        .bucket("photos")
        .key("a.jpg")
        .body(ByteStream::from_static(b"photo"))
        .send()
        .await
        .unwrap()
        .version_id
        .unwrap();
    // The job works on the version its manifest names, not the current one.
    put(&root, "photos", "a.jpg", "newer").await;
    let role = role(&server, "batch", TRUST, TAGGER);
    let etag = put(
        &root,
        "manifests",
        "m.csv",
        &format!("photos,a.jpg,{version}"),
    )
    .await;
    let fields = [
        JobManifestFieldName::Bucket,
        JobManifestFieldName::Key,
        JobManifestFieldName::VersionId,
    ];
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    // Shortening governance-mode retention needs the bypass.
    for (token, operation, succeeded) in [
        ("hold", hold(), 1),
        ("retain", retain(Duration::from_hours(1), false), 1),
        ("tag", tagging("kept", "yes"), 1),
        ("sooner", retain(Duration::from_mins(30), false), 0),
        ("bypassed", retain(Duration::from_mins(30), true), 1),
    ] {
        let manifest = manifest_at("m.csv", &etag, &fields);
        let id = create(
            &s3control,
            &account,
            (operation, manifest, &role),
            (token, 1, false),
        )
        .await
        .unwrap();
        let done = wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
        let progress = done.job.unwrap().progress_summary.unwrap();
        assert_eq!(
            progress.number_of_tasks_succeeded,
            Some(succeeded),
            "{token}"
        );
    }
    let tagged = |version: Option<String>| {
        root.get_object_tagging()
            .bucket("photos")
            .key("a.jpg")
            .set_version_id(version)
            .send()
    };
    assert_eq!(
        tagged(Some(version.clone())).await.unwrap().tag_set.len(),
        1
    );
    assert!(tagged(None).await.unwrap().tag_set.is_empty());
    let hold = root
        .get_object_legal_hold()
        .bucket("photos")
        .key("a.jpg")
        .version_id(&version)
        .send()
        .await
        .unwrap();
    assert_eq!(
        hold.legal_hold.unwrap().status,
        Some(aws_sdk_s3::types::ObjectLockLegalHoldStatus::On)
    );
    let retention = root
        .get_object_retention()
        .bucket("photos")
        .key("a.jpg")
        .version_id(&version)
        .send()
        .await
        .unwrap();
    assert_eq!(
        retention.retention.unwrap().mode,
        Some(aws_sdk_s3::types::ObjectLockRetentionMode::Governance)
    );
}

#[tokio::test]
async fn callers_need_create_job_and_pass_role() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &["a.jpg"]).await;
    let role = role(&server, "batch", TRUST, TAGGER);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg"]).await;
    // Low priorities only, and never deleting tags.
    let maker = format!(
        r#"{{"Version":"2012-10-17","Statement":[
          {{"Effect":"Allow","Action":"s3:CreateJob","Resource":"*",
            "Condition":{{"NumericLessThan":{{"s3:RequestJobPriority":"10"}}}}}},
          {{"Effect":"Allow","Action":["s3:DescribeJob","s3:UpdateJobPriority"],"Resource":"*",
            "Condition":{{"NumericLessThan":{{"s3:ExistingJobPriority":"10"}}}}}},
          {{"Effect":"Deny","Action":"s3:UpdateJobPriority","Resource":"*",
            "Condition":{{"NumericGreaterThan":{{"s3:RequestJobPriority":"50"}}}}}},
          {{"Effect":"Deny","Action":"s3:CreateJob","Resource":"*",
            "Condition":{{"StringEquals":{{"s3:RequestJobOperation":"S3DeleteObjectTagging"}}}}}},
          {{"Effect":"Allow","Action":"iam:PassRole","Resource":"{role}"}}]}}"#
    );
    user(&server, "maker", Some(&maker));
    let key = server.iam.create_access_key("maker").unwrap();
    let s3control = control(&server, &key.info.id, &key.secret);
    let job = |operation| (operation, manifest.clone(), role.as_str());
    let high = create(
        &s3control,
        &account,
        job(tagging("a", "b")),
        ("t1", 10, true),
    )
    .await;
    assert_eq!(high, Err("AccessDenied".to_owned()));
    let untag = JobOperation::builder()
        .s3_delete_object_tagging(S3DeleteObjectTaggingOperation::builder().build())
        .build();
    let denied = create(&s3control, &account, job(untag), ("t2", 1, true)).await;
    assert_eq!(denied, Err("AccessDenied".to_owned()));
    let id = create(
        &s3control,
        &account,
        job(tagging("a", "b")),
        ("t3", 1, true),
    )
    .await
    .unwrap();
    describe(&s3control, &account, &id).await;
    let too_high = s3control
        .update_job_priority()
        .account_id(&account)
        .job_id(&id)
        .priority(60)
        .send()
        .await;
    assert_eq!(code(too_high), "AccessDenied");
    // Raised past what the policy allows, the job is out of the caller's reach.
    s3control
        .update_job_priority()
        .account_id(&account)
        .job_id(&id)
        .priority(20)
        .send()
        .await
        .unwrap();
    let hidden = s3control
        .describe_job()
        .account_id(&account)
        .job_id(&id)
        .send()
        .await;
    assert_eq!(code(hidden), "AccessDenied");
    let listed = s3control.list_jobs().account_id(&account).send().await;
    assert_eq!(code(listed), "AccessDenied");

    // Without iam:PassRole on the role, no job is made.
    let no_pass = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:CreateJob","Resource":"*"}]}"#;
    user(&server, "nopass", Some(no_pass));
    let key = server.iam.create_access_key("nopass").unwrap();
    let s3control = control(&server, &key.info.id, &key.secret);
    let refused = create(
        &s3control,
        &account,
        job(tagging("a", "b")),
        ("t4", 1, true),
    )
    .await;
    assert_eq!(refused, Err("AccessDenied".to_owned()));
}

#[tokio::test]
async fn wrong_jobs_are_refused() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &[]).await;
    let role = role(&server, "batch", TRUST, TAGGER);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg"]).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let unformatted = JobReport::builder()
        .enabled(true)
        .bucket("arn:aws:s3:::reports")
        .build();
    let not_a_bucket = JobReport::builder()
        .enabled(true)
        .bucket("reports")
        .format(JobReportFormat::ReportCsv20180820)
        .build();
    let in_a_folder = JobReport::builder()
        .enabled(true)
        .bucket("arn:aws:s3:::reports/out")
        .format(JobReportFormat::ReportCsv20180820)
        .build();
    let long = report(Some(&"p".repeat(513)), JobReportScope::AllTasks);
    for (token, report) in [
        ("r1", unformatted),
        ("r2", not_a_bucket),
        ("r3", in_a_folder),
        ("r4", long),
    ] {
        let job = (tagging("a", "b"), manifest.clone(), role.as_str());
        let refused = create_reported(&s3control, &account, job, (token, 1, false), report).await;
        assert_eq!(refused, Err("BadRequestException".to_owned()), "{token}");
    }
    let lambda = JobOperation::builder()
        .lambda_invoke(
            aws_sdk_s3control::types::LambdaInvokeOperation::builder()
                .function_arn("arn:aws:lambda:us-east-1:123456789012:function:f")
                .build(),
        )
        .build();
    let refused = create(
        &s3control,
        &account,
        (lambda, manifest.clone(), &role),
        ("l", 1, false),
    )
    .await;
    assert_eq!(refused, Err("NotImplemented".to_owned()));
    let no_key = manifest_at("m.csv", "\"x\"", &[JobManifestFieldName::Bucket]);
    let refused = create(
        &s3control,
        &account,
        (tagging("a", "b"), no_key, &role),
        ("k", 1, false),
    )
    .await;
    assert_eq!(refused, Err("BadRequestException".to_owned()));
    let refused = create(
        &s3control,
        &account,
        (tagging("a", "b"), manifest, "arn:aws:iam::1:user/x"),
        ("u", 1, false),
    )
    .await;
    assert_eq!(refused, Err("BadRequestException".to_owned()));
}

#[tokio::test]
async fn long_manifests_are_read_and_run_a_piece_at_a_time() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &["first", "last"]).await;
    let role = role(&server, "batch", TRUST, TAGGER);
    // More than a piece (256 KiB) of lines, and more than a page (100) of tasks.
    let long = "x".repeat(1000);
    let mut lines = vec!["photos,first".to_owned()];
    lines.extend((0..300).map(|n| format!("photos,{n}-{long}")));
    lines.push("photos,last".to_owned());
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    let manifest = manifest(&root, "long.csv", &lines).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("a", "b"), manifest, role.as_str());
    let id = create(&s3control, &account, job, ("long", 1, false))
        .await
        .unwrap();
    let done = wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    let progress = done.job.unwrap().progress_summary.unwrap();
    assert_eq!(progress.total_number_of_tasks, Some(302));
    assert_eq!(progress.number_of_tasks_succeeded, Some(2));
    assert_eq!(progress.number_of_tasks_failed, Some(300));
    for key in ["first", "last"] {
        assert_eq!(tags_of(&root, key).await.len(), 1, "{key}");
    }

    // An empty manifest completes at once.
    let empty = self::manifest(&root, "empty.csv", &[]).await;
    let job = (tagging("a", "b"), empty, role.as_str());
    let id = create(&s3control, &account, job, ("empty", 1, false))
        .await
        .unwrap();
    let done = wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    let progress = done.job.unwrap().progress_summary.unwrap();
    assert_eq!(progress.total_number_of_tasks, Some(0));
}

#[tokio::test]
async fn jobs_are_listed_a_page_at_a_time() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &[]).await;
    let role = role(&server, "batch", TRUST, TAGGER);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg"]).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let mut made = Vec::new();
    for token in ["one", "two", "three"] {
        let job = (tagging("a", "b"), manifest.clone(), role.as_str());
        made.push(
            create(&s3control, &account, job, (token, 1, true))
                .await
                .unwrap(),
        );
        // A few milliseconds apart, so they're listed newest first.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut listed = Vec::new();
    let mut token = None;
    loop {
        let page = s3control
            .list_jobs()
            .account_id(&account)
            .max_results(2)
            .set_next_token(token)
            .send()
            .await
            .unwrap();
        let jobs = page.jobs.unwrap_or_default();
        assert!(jobs.len() <= 2);
        listed.extend(jobs.into_iter().map(|job| job.job_id.unwrap()));
        token = page.next_token;
        if token.is_none() {
            break;
        }
    }
    made.reverse();
    assert_eq!(listed, made);
    // A page that ends the list says so.
    let whole = s3control
        .list_jobs()
        .account_id(&account)
        .max_results(3)
        .send()
        .await
        .unwrap();
    assert_eq!(whole.jobs.unwrap().len(), 3);
    assert_eq!(whole.next_token, None);
    let wrong = s3control
        .list_jobs()
        .account_id(&account)
        .next_token("bm90LWEtam9i")
        .send()
        .await;
    assert_eq!(code(wrong), "InvalidNextTokenException");
}

#[tokio::test]
async fn minio_jobs_and_s3_batch_operations_jobs_are_apart() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &[]).await;
    let role = role(&server, "batch", TRUST, TAGGER);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg"]).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("a", "b"), manifest, role.as_str());
    let ours = create(&s3control, &account, job, ("t", 1, true))
        .await
        .unwrap();
    wait_for(&s3control, &account, &ours, &JobStatus::Suspended).await;
    let admin = |method: &'static str, path: String| {
        let server = &server;
        async move {
            let path = format!("/minio/admin/v3/{path}");
            let key = (common::ACCESS_KEY, SECRET_KEY);
            signing::signed(server, key, method, &path, &[], b"").await
        }
    };
    let yaml = "expire:\n  apiVersion: v1\n  bucket: photos\n  rules:\n    - type: object\n";
    let path = "/minio/admin/v3/start-job";
    let key = (common::ACCESS_KEY, SECRET_KEY);
    let (status, body) = signing::signed(&server, key, "POST", path, &[], yaml.as_bytes()).await;
    assert_eq!(status, 200, "{body}");
    let minio: serde_json::Value = serde_json::from_str(&body).unwrap();
    let minio = minio["id"].as_str().unwrap().to_owned();

    let (_, listed) = admin("GET", "list-jobs".to_owned()).await;
    let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
    let ids: Vec<&str> = listed["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|job| job["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [minio.as_str()]);
    for path in [
        format!("status-job?jobId={ours}"),
        format!("describe-job?jobId={ours}"),
    ] {
        let (status, body) = admin("GET", path).await;
        assert_eq!(status, 404, "{body}");
    }
    let (status, _) = admin("DELETE", format!("cancel-job?id={ours}")).await;
    assert_eq!(status, 404);
    let job = describe(&s3control, &account, &ours).await.job.unwrap();
    assert_eq!(job.status, Some(JobStatus::Suspended));

    let listed = s3control
        .list_jobs()
        .account_id(&account)
        .send()
        .await
        .unwrap()
        .jobs
        .unwrap();
    let ids: Vec<&str> = listed
        .iter()
        .map(|job| job.job_id.as_deref().unwrap())
        .collect();
    assert_eq!(ids, [ours.as_str()]);
    let theirs = s3control
        .describe_job()
        .account_id(&account)
        .job_id(&minio)
        .send()
        .await;
    assert_eq!(code(theirs), "NotFoundException");
}

#[tokio::test]
async fn wrong_manifest_lines_fail_the_job() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &[]).await;
    let role = role(&server, "batch", TRUST, TAGGER);
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    // A line that isn't UTF-8 fails the job as it's read.
    let etag = root
        .put_object()
        .bucket("manifests")
        .key("binary.csv")
        .body(ByteStream::from_static(b"photos,a.jpg\nphotos,\xff\n"))
        .send()
        .await
        .unwrap()
        .e_tag
        .unwrap();
    let fields = [JobManifestFieldName::Bucket, JobManifestFieldName::Key];
    let binary = manifest_at("binary.csv", &etag, &fields);
    let id = create(
        &s3control,
        &account,
        (tagging("a", "b"), binary, &role),
        ("x", 1, false),
    )
    .await
    .unwrap();
    let failed = wait_for(&s3control, &account, &id, &JobStatus::Failed).await;
    let reason = &failed.job.unwrap().failure_reasons.unwrap()[0];
    let reason = reason.failure_reason.as_deref().unwrap();
    assert!(
        reason.starts_with("Line 2 ") && reason.contains("UTF-8"),
        "{reason}"
    );
    // A manifest line that names no key fails the job as it's read.
    let bad = self::manifest(&root, "bad.csv", &["photos,a.jpg", "photos"]).await;
    let id = create(
        &s3control,
        &account,
        (tagging("a", "b"), bad, &role),
        ("b", 1, false),
    )
    .await
    .unwrap();
    let failed = wait_for(&s3control, &account, &id, &JobStatus::Failed).await;
    let reason = &failed.job.unwrap().failure_reasons.unwrap()[0];
    assert_eq!(
        reason.failure_code.as_deref(),
        Some("InvalidManifestContent")
    );
    assert!(
        reason
            .failure_reason
            .as_deref()
            .unwrap()
            .starts_with("Line 2 ")
    );
}

/// What the job role may do to write reports, besides tag photos.
const REPORTER: &str = r#"{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::manifests/*"},
  {"Effect":"Allow","Action":"s3:PutObjectTagging","Resource":"arn:aws:s3:::photos/*"},
  {"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::reports/*"}]}"#;

async fn text(root: &Client, bucket: &str, key: &str) -> String {
    let body = root
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap()
        .body
        .collect()
        .await
        .unwrap()
        .into_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

/// A job's report: its results files' status and lines, checked against the manifest.
async fn report_of(root: &Client, base: &str) -> Vec<(String, Vec<String>)> {
    let manifest = text(root, "reports", &format!("{base}/manifest.json")).await;
    let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(manifest["Format"], "Report_CSV_20180820");
    assert_eq!(
        manifest["ReportSchema"],
        "Bucket, Key, VersionId, TaskStatus, ErrorCode, HTTPStatusCode, ResultMessage"
    );
    assert!(
        manifest["ReportCreationDate"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    let mut files = Vec::new();
    for file in manifest["Results"].as_array().unwrap() {
        assert_eq!(file["Bucket"], "reports");
        let key = file["Key"].as_str().unwrap();
        assert!(key.starts_with(&format!("{base}/results/")), "{key}");
        let name = key.rsplit('/').next().unwrap();
        let hex = name.strip_suffix(".csv").unwrap();
        assert!(
            hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "{key}"
        );
        let body = text(root, "reports", key).await;
        let md5 = Md5::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .concat();
        assert_eq!(file["MD5Checksum"], md5.as_str());
        let lines = body.lines().map(str::to_owned).collect();
        files.push((
            file["TaskExecutionStatus"].as_str().unwrap().to_owned(),
            lines,
        ));
    }
    files
}

#[tokio::test]
async fn a_job_writes_a_completion_report() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &["a.jpg"]).await;
    root.create_bucket().bucket("reports").send().await.unwrap();
    let role = role(&server, "batch", TRUST, REPORTER);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg", "photos,b+c.jpg"]).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("a", "b"), manifest.clone(), role.as_str());
    let every = report(Some("out/"), JobReportScope::AllTasks);
    let id = create_reported(&s3control, &account, job.clone(), ("t1", 1, false), every)
        .await
        .unwrap();
    let done = wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    let described = done.job.unwrap().report.unwrap();
    assert!(described.enabled);
    assert_eq!(described.bucket.as_deref(), Some("arn:aws:s3:::reports"));
    assert_eq!(described.prefix.as_deref(), Some("out/"));
    assert_eq!(described.format, Some(JobReportFormat::ReportCsv20180820));
    assert_eq!(described.report_scope, Some(JobReportScope::AllTasks));
    let files = report_of(&root, &format!("out/job-{id}")).await;
    // Written, the results are forgotten.
    assert_eq!(kept_results(&server, &id), 0);
    assert_eq!(files.len(), 2, "{files:?}");
    assert_eq!(files[0].0, "succeeded");
    assert_eq!(files[0].1, ["photos,a.jpg,,succeeded,200,,Successful"]);
    assert_eq!(files[1].0, "failed");
    assert_eq!(files[1].1.len(), 1);
    assert!(
        files[1].1[0].starts_with("photos,b%20c.jpg,,failed,404,NoSuchKey,"),
        "{files:?}"
    );

    // Just the failed tasks, with no prefix.
    let failed = report(None, JobReportScope::FailedTasksOnly);
    let id = create_reported(&s3control, &account, job.clone(), ("t2", 1, false), failed)
        .await
        .unwrap();
    let done = wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    let described = done.job.unwrap().report.unwrap();
    assert_eq!(described.prefix, None);
    assert_eq!(
        described.report_scope,
        Some(JobReportScope::FailedTasksOnly)
    );
    let files = report_of(&root, &format!("job-{id}")).await;
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(files[0].0, "failed");

    // Only successes, reporting failures: a report with no results files.
    let fine = self::manifest(&root, "fine.csv", &["photos,a.jpg"]).await;
    let job = (tagging("a", "b"), fine, role.as_str());
    let failed = report(None, JobReportScope::FailedTasksOnly);
    let id = create_reported(&s3control, &account, job, ("t3", 1, false), failed)
        .await
        .unwrap();
    wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    assert!(report_of(&root, &format!("job-{id}")).await.is_empty());
}

#[tokio::test]
async fn a_report_the_role_cannot_write_fails_the_job() {
    let server = start().await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    buckets(&root, &["a.jpg"]).await;
    root.create_bucket().bucket("reports").send().await.unwrap();
    let role = role(&server, "batch", TRUST, TAGGER);
    let manifest = manifest(&root, "m.csv", &["photos,a.jpg"]).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("a", "b"), manifest, role.as_str());
    let every = report(None, JobReportScope::AllTasks);
    let id = create_reported(&s3control, &account, job, ("t", 1, false), every)
        .await
        .unwrap();
    let failed = wait_for(&s3control, &account, &id, &JobStatus::Failed).await;
    let job = failed.job.unwrap();
    assert_eq!(
        job.progress_summary.unwrap().number_of_tasks_succeeded,
        Some(1)
    );
    let reason = &job.failure_reasons.unwrap()[0];
    assert_eq!(reason.failure_code.as_deref(), Some("ReportWriteFailed"));
    assert!(
        reason
            .failure_reason
            .as_deref()
            .unwrap()
            .contains("AccessDenied"),
        "{reason:?}"
    );
    assert_eq!(tags_of(&root, "a.jpg").await, [("a".into(), "b".into())]);
}

#[tokio::test]
async fn long_reports_are_written_in_parts() {
    // Object buckets tag the object faster.
    let server =
        common::start_with(|config| config.default_layout = teifs_store::Layout::Object).await;
    let account = server.iam.account();
    let root = client(&server, SECRET_KEY);
    // Three segments of 250 (about as long as a key's segments may be).
    let key = vec!["%".repeat(250); 3].join("/");
    buckets(&root, &[key.as_str()]).await;
    root.create_bucket().bucket("reports").send().await.unwrap();
    let role = role(&server, "batch", TRUST, REPORTER);
    // Lines of 2250 bytes and more: 8000 of them are over a 16 MiB part.
    let line = format!("photos,{}", vec!["%25".repeat(250); 3].join("/"));
    let lines = vec![line.as_str(); 8000];
    let manifest = manifest(&root, "m.csv", &lines).await;
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);
    let job = (tagging("a", "b"), manifest, role.as_str());
    let every = report(None, JobReportScope::AllTasks);
    let id = create_reported(&s3control, &account, job, ("t", 1, false), every)
        .await
        .unwrap();
    wait_for(&s3control, &account, &id, &JobStatus::Complete).await;
    let files = report_of(&root, &format!("job-{id}")).await;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].1.len(), 8000);
    assert!(files[0].1.iter().all(|l| l.starts_with(&line)));
    let listed = root
        .list_objects_v2()
        .bucket("reports")
        .prefix(format!("job-{id}/results/"))
        .send()
        .await
        .unwrap()
        .contents
        .unwrap();
    assert!(
        listed[0].e_tag.as_deref().unwrap().ends_with("-2\""),
        "{listed:?}"
    );
}

/// How many of job `id`'s results the drive keeps.
fn kept_results(server: &Server, id: &str) -> usize {
    let copy = tempfile::tempdir().unwrap();
    let path = copy.path().join("system.db");
    teifs_meta::backup(&server.dir.path().join(".teifs/system.db"), &path).unwrap();
    let system = teifs_meta::System::open(&path).unwrap();
    [false, true]
        .iter()
        .map(|failed| {
            system
                .batch_results(id, *failed, None, 100_000)
                .unwrap()
                .len()
        })
        .sum()
}

/// A job of `lines` taggings of `a.jpg` (with `report`), once it has run some.
async fn running(
    server: &Server,
    (lines, priority): (usize, i32),
    token: &str,
    report: JobReport,
) -> (String, String) {
    let id = queued(server, (lines, priority), token, report).await;
    let (account, s3control) = (
        server.iam.account(),
        control(server, common::ACCESS_KEY, SECRET_KEY),
    );
    for _ in 0..1200 {
        let job = describe(&s3control, &account, &id).await.job.unwrap();
        let succeeded = job
            .progress_summary
            .and_then(|p| p.number_of_tasks_succeeded);
        if succeeded.unwrap_or_default() > 0 {
            return (account, id);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("job {id} never ran a task");
}

/// A job of `lines` taggings of `a.jpg` (with `report`) at `priority`; its id.
async fn queued(
    server: &Server,
    (lines, priority): (usize, i32),
    token: &str,
    report: JobReport,
) -> String {
    let account = server.iam.account();
    let root = client(server, SECRET_KEY);
    let lines = vec!["photos,a.jpg"; lines];
    let manifest = manifest(&root, &format!("{token}.csv"), &lines).await;
    let s3control = control(server, common::ACCESS_KEY, SECRET_KEY);
    let role = format!("arn:aws:iam::{account}:role/batch");
    let job = (tagging("a", "b"), manifest, role.as_str());
    create_reported(&s3control, &account, job, (token, priority, false), report)
        .await
        .unwrap()
}

async fn cancel(
    s3control: &aws_sdk_s3control::Client,
    account: &str,
    id: &str,
) -> Option<JobStatus> {
    s3control
        .update_job_status()
        .account_id(account)
        .job_id(id)
        .requested_job_status(RequestedJobStatus::Cancelled)
        .send()
        .await
        .unwrap()
        .status
}

#[tokio::test]
async fn cancelled_and_failed_jobs_report_what_they_ran() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    buckets(&root, &["a.jpg"]).await;
    root.create_bucket().bucket("reports").send().await.unwrap();
    role(&server, "batch", TRUST, REPORTER);
    let s3control = control(&server, common::ACCESS_KEY, SECRET_KEY);

    // Cancelled once it ran tasks: it reports them first, before a job that comes next.
    let every = || report(None, JobReportScope::AllTasks);
    let (account, id) = running(&server, (20_000, 1), "t1", every()).await;
    let next = queued(&server, (20_000, 10), "t0", no_report()).await;
    assert_eq!(
        cancel(&s3control, &account, &id).await,
        Some(JobStatus::Cancelling)
    );
    let done = wait_for(&s3control, &account, &id, &JobStatus::Cancelled).await;
    let next = describe(&s3control, &account, &next).await.job.unwrap();
    let next_ran = next
        .progress_summary
        .and_then(|p| p.number_of_tasks_succeeded);
    assert!(next_ran.unwrap_or_default() < 20_000, "{next_ran:?}");
    cancel(&s3control, &account, next.job_id.as_deref().unwrap()).await;
    let progress = done.job.unwrap().progress_summary.unwrap();
    let ran = progress.number_of_tasks_succeeded.unwrap();
    assert!(ran < 20_000, "{ran}");
    let files = report_of(&root, &format!("job-{id}")).await;
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(files[0].1.len(), usize::try_from(ran).unwrap());
    assert_eq!(kept_results(&server, &id), 0);

    // Without a report, it's cancelled at once.
    let (account, id) = running(&server, (20_000, 1), "t4", no_report()).await;
    assert_eq!(
        cancel(&s3control, &account, &id).await,
        Some(JobStatus::Cancelled)
    );

    // Failed for its manifest, changed once it ran tasks: it reports them too.
    let (account, id) = running(&server, (20_000, 1), "t2", every()).await;
    put(&root, "manifests", "t2.csv", "photos,a.jpg").await;
    let failed = wait_for(&s3control, &account, &id, &JobStatus::Failed).await;
    let job = failed.job.unwrap();
    let reason = &job.failure_reasons.unwrap()[0];
    assert_eq!(reason.failure_code.as_deref(), Some("ManifestReadFailed"));
    let ran = job
        .progress_summary
        .unwrap()
        .number_of_tasks_succeeded
        .unwrap();
    let files = report_of(&root, &format!("job-{id}")).await;
    assert_eq!(files[0].1.len(), usize::try_from(ran).unwrap());

    // Cancelled before it ran any: nothing to report.
    let (manifest, role) = (
        manifest(&root, "n.csv", &["photos,a.jpg"]).await,
        format!("arn:aws:iam::{account}:role/batch"),
    );
    let job = (tagging("a", "b"), manifest, role.as_str());
    let id = create_reported(&s3control, &account, job, ("t3", 1, true), every())
        .await
        .unwrap();
    wait_for(&s3control, &account, &id, &JobStatus::Suspended).await;
    assert_eq!(
        cancel(&s3control, &account, &id).await,
        Some(JobStatus::Cancelled)
    );
    let manifest = root
        .head_object()
        .bucket("reports")
        .key(format!("job-{id}/manifest.json"))
        .send()
        .await;
    assert_eq!(code(manifest), "NotFound");
}
