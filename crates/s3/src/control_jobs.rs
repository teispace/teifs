//! S3 Control's batch jobs (S3 Batch Operations): `CreateJob`, `DescribeJob`,
//! `ListJobs`, `UpdateJobPriority`, `UpdateJobStatus`, and `GetJobTagging`,
//! `PutJobTagging` and `DeleteJobTagging`. [`crate::batch_operations`] runs the jobs.
//!
//! Each call but `ListJobs` is decided here, once what it's about is read: `CreateJob`
//! on the account with the job's priority and operation (`s3:RequestJobPriority`,
//! `s3:RequestJobOperation`), and `iam:PassRole` on its role; the others on the job's
//! ARN with its priority and operation (`s3:ExistingJobPriority`,
//! `s3:ExistingJobOperation`).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderValue, StatusCode, header};
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use teifs_iam::Identity;
use teifs_policy::{Context, S3Key, TagKind};
use teifs_store::Store;
use teifs_types::batch::{
    BatchJob, JobProgress, JobReport, JobStatus, KeyValue, Manifest, ManifestField, Operation,
    OperationJob,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    errors::StoreResultExt,
    routes::{s3_refusal, signed_body},
};

/// The jobs: `CreateJob` and `ListJobs`.
pub(crate) const JOBS: &str = "/v20180820/jobs";
/// A job: `DescribeJob`.
pub(crate) const JOB: &str = "/v20180820/jobs/{id}";
/// `UpdateJobPriority`.
pub(crate) const PRIORITY: &str = "/v20180820/jobs/{id}/priority";
/// `UpdateJobStatus`.
pub(crate) const STATUS: &str = "/v20180820/jobs/{id}/status";
/// A job's tags.
pub(crate) const TAGGING: &str = "/v20180820/jobs/{id}/tagging";

/// S3 Control's XML namespace.
const NAMESPACE: &str = "http://awss3control.amazonaws.com/doc/2018-08-20/";

/// The largest request body: a job with 50 tags and long ARNs fits many times over.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// The most tags a job has.
const MAX_TAGS: usize = 50;

/// The most jobs a `ListJobs` page has.
const MAX_RESULTS: usize = 1000;

/// The only manifest format read.
const CSV_MANIFEST: &str = "S3BatchOperations_CSV_20180820";

/// A call on jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    Create,
    Describe,
    List,
    Priority,
    Status,
    GetTagging,
    PutTagging,
    DeleteTagging,
}

impl Call {
    /// Its name, in metrics and the audit log.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Create => "CreateJob",
            Self::Describe => "DescribeJob",
            Self::List => "ListJobs",
            Self::Priority => "UpdateJobPriority",
            Self::Status => "UpdateJobStatus",
            Self::GetTagging => "GetJobTagging",
            Self::PutTagging => "PutJobTagging",
            Self::DeleteTagging => "DeleteJobTagging",
        }
    }

    /// The action it needs.
    const fn action(self) -> &'static str {
        match self {
            Self::Create => "s3:CreateJob",
            Self::Describe => "s3:DescribeJob",
            Self::List => "s3:ListJobs",
            Self::Priority => "s3:UpdateJobPriority",
            Self::Status => "s3:UpdateJobStatus",
            Self::GetTagging => "s3:GetJobTagging",
            Self::PutTagging => "s3:PutJobTagging",
            Self::DeleteTagging => "s3:DeleteJobTagging",
        }
    }
}

/// Who calls, and what their call's conditions see.
pub(crate) struct Caller<'a> {
    pub(crate) identity: &'a Identity,
    pub(crate) context: &'a Context,
    pub(crate) account: &'a str,
}

impl Caller<'_> {
    fn check(&self, context: &Context, action: &str, resource: &str) -> S3Result<()> {
        if self
            .identity
            .decide(context, action, resource, None)
            .is_allowed()
        {
            Ok(())
        } else {
            Err(s3s::s3_error!(AccessDenied, "Access Denied"))
        }
    }

    fn job_arn(&self, id: &str) -> String {
        format!(
            "arn:aws:s3:{}:{}:job/{id}",
            crate::drive::REGION,
            self.account
        )
    }
}

/// Makes a call; whether a job may now run is the second value.
pub(crate) async fn serve(
    call: Call,
    store: &Store,
    caller: &Caller<'_>,
    mut req: S3Request<Body>,
) -> S3Result<(S3Response<Body>, bool)> {
    if call == Call::Create {
        return create(store, caller, &mut req).await.map(|r| (r, true));
    }
    if call == Call::List {
        return list(store, req.uri.query()).await.map(|r| (r, false));
    }
    let id = job_id(req.uri.path())?;
    let job = existing(store, caller, call, &id).await?;
    let mut context = in_context(caller.context.clone(), &job);
    if call == Call::Priority {
        let priority = priority(param(&req, "priority").as_deref())?;
        context = context.with(S3Key::RequestJobPriority, i64::from(priority));
        caller.check(&context, call.action(), &caller.job_arn(&id))?;
        return set_priority(store, &id, priority).await.map(|r| (r, false));
    }
    caller.check(&context, call.action(), &caller.job_arn(&id))?;
    match call {
        Call::Describe => Ok((
            xml(
                "DescribeJobResult",
                &Described {
                    job: describe(caller, &job),
                },
            )?,
            false,
        )),
        Call::Status => set_status(store, &req, job).await,
        Call::GetTagging => {
            let tags = operation_of(&job)
                .map(|op| op.tags.clone())
                .unwrap_or_default();
            Ok((
                xml(
                    "GetJobTaggingResult",
                    &Tagged {
                        tags: members(tags.iter().map(TagXml::of)),
                    },
                )?,
                false,
            ))
        }
        Call::PutTagging => {
            let body = signed_body(&mut req, MAX_BODY_BYTES)
                .await
                .map_err(s3_refusal)?;
            let given: PutTagging = read_xml(&body, "PutJobTaggingRequest")?;
            let tags = tags_of(given.tags)?;
            set_tags(store, &id, tags).await?;
            Ok((xml("PutJobTaggingResult", &Empty {})?, false))
        }
        Call::DeleteTagging => {
            set_tags(store, &id, Vec::new()).await?;
            Ok((xml("DeleteJobTaggingResult", &Empty {})?, false))
        }
        Call::Create | Call::List | Call::Priority => unreachable!("answered above"),
    }
}

/// The job a path names (`/v20180820/jobs/{id}…`).
fn job_id(path: &str) -> S3Result<String> {
    path.strip_prefix(JOB.trim_end_matches("{id}"))
        .and_then(|rest| rest.split('/').next())
        .filter(|id| !id.is_empty())
        .map(|id| {
            percent_encoding::percent_decode_str(id)
                .decode_utf8_lossy()
                .into_owned()
        })
        .ok_or_else(|| bad_request("The path names no job."))
}

/// The S3 Batch Operations job `id`, once the caller may know whether it exists:
/// decided first on its ARN alone.
async fn existing(store: &Store, caller: &Caller<'_>, call: Call, id: &str) -> S3Result<BatchJob> {
    let job = store
        .batch_job(id)
        .await
        .s3()?
        .filter(|job| !job.spec.is_minio());
    if let Some(job) = job {
        return Ok(job);
    }
    caller.check(caller.context, call.action(), &caller.job_arn(id))?;
    Err(error(
        StatusCode::NOT_FOUND,
        "NotFoundException",
        format!("The job {id} doesn't exist."),
    ))
}

const fn operation_of(job: &BatchJob) -> Option<&OperationJob> {
    match &job.spec {
        teifs_types::batch::JobSpec::Operation(op) => Some(op),
        _ => None,
    }
}

/// `context` with a job's priority and operation.
fn in_context(context: Context, job: &BatchJob) -> Context {
    let context = context.with(S3Key::ExistingJobPriority, i64::from(job.priority));
    match operation_of(job) {
        Some(op) => context.with(S3Key::ExistingJobOperation, op.operation.name()),
        None => context,
    }
}

/// `POST /v20180820/jobs`: a new job, or the one the same token made.
async fn create(
    store: &Store,
    caller: &Caller<'_>,
    req: &mut S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let body = signed_body(req, MAX_BODY_BYTES).await.map_err(s3_refusal)?;
    let (spec, priority) = match read_xml(&body, "CreateJobRequest").and_then(job_of) {
        Ok(job) => job,
        // Only a caller who may make jobs learns what's wrong with one.
        Err(err) => {
            caller.check(
                caller.context,
                Call::Create.action(),
                teifs_policy::S3_ACCOUNT_RESOURCE,
            )?;
            return Err(err);
        }
    };
    let mut context = caller
        .context
        .clone()
        .with(S3Key::RequestJobPriority, i64::from(priority))
        .with(S3Key::RequestJobOperation, spec.operation.name());
    for tag in &spec.tags {
        context = context.with_tag(TagKind::Request, &tag.key, &tag.value);
    }
    if !spec.tags.is_empty() {
        context = context.with_tag_keys(spec.tags.iter().map(|t| t.key.as_str()));
    }
    caller.check(
        &context,
        Call::Create.action(),
        teifs_policy::S3_ACCOUNT_RESOURCE,
    )?;
    caller.check(caller.context, "iam:PassRole", &spec.role_arn)?;
    let jobs = store.batch_jobs().await.s3()?;
    let earlier = jobs
        .iter()
        .find(|job| operation_of(job).is_some_and(|op| op.client_token == spec.client_token));
    let id = match earlier {
        Some(job) if operation_of(job) == Some(&spec) && job.priority == priority => job.id.clone(),
        Some(_) => {
            return Err(error(
                StatusCode::CONFLICT,
                "IdempotencyException",
                "A job was made with this ClientRequestToken and other parameters.",
            ));
        }
        None => {
            let job = BatchJob {
                id: uuid::Uuid::new_v4().to_string(),
                user: caller
                    .identity
                    .principal()
                    .arn()
                    .unwrap_or_default()
                    .to_owned(),
                created_ms: crate::admin::millis(std::time::SystemTime::now()),
                priority,
                status: JobStatus::New,
                spec: teifs_types::batch::JobSpec::Operation(spec),
                progress: JobProgress::default(),
                failures: Vec::new(),
            };
            store
                .add_batch_job(&job, &teifs_store::JobSecrets::default())
                .await
                .s3()?;
            job.id
        }
    };
    xml("CreateJobResult", &Created { job_id: id })
}

/// A job from a `CreateJobRequest`, with its priority.
fn job_of(request: CreateJob) -> S3Result<(OperationJob, i32)> {
    let token = request
        .client_request_token
        .filter(|t| (1..=64).contains(&t.len()))
        .ok_or_else(|| bad_request("ClientRequestToken must be 1 to 64 characters."))?;
    let priority = request
        .priority
        .and_then(|p| i32::try_from(p).ok())
        .filter(|p| *p >= 0)
        .ok_or_else(|| bad_request("Priority must be from 0 to 2147483647."))?;
    let role_arn = request
        .role_arn
        .filter(|arn| arn.starts_with("arn:aws:iam::") && arn.contains(":role/"))
        .ok_or_else(|| bad_request("RoleArn must be an IAM role's ARN."))?;
    let description = request.description.unwrap_or_default();
    if description.chars().count() > 256 {
        return Err(bad_request("Description must be at most 256 characters."));
    }
    if request.manifest_generator.is_some() {
        return Err(not_implemented(
            "TeiFS reads a job's objects from a CSV manifest; it doesn't generate one.",
        ));
    }
    let manifest = manifest_of(
        request
            .manifest
            .ok_or_else(|| bad_request("A job needs a Manifest."))?,
    )?;
    let report = report_of(
        &request
            .report
            .ok_or_else(|| bad_request("A job needs a Report, enabled or not."))?,
    )?;
    let operation = operation_of_xml(
        request
            .operation
            .ok_or_else(|| bad_request("A job needs an Operation."))?,
    )?;
    let tags = tags_of(request.tags.unwrap_or_default())?;
    Ok((
        OperationJob {
            operation,
            manifest,
            role_arn,
            description,
            confirmation_required: request.confirmation_required.unwrap_or(false),
            client_token: token,
            tags,
            report,
            status_reason: None,
        },
        priority,
    ))
}

fn manifest_of(given: ManifestXml) -> S3Result<Manifest> {
    if given.spec.format != CSV_MANIFEST {
        return Err(not_implemented(format!(
            "TeiFS reads manifests in the {CSV_MANIFEST} format."
        )));
    }
    let fields = given
        .spec
        .fields
        .unwrap_or_default()
        .member
        .iter()
        .map(|field| match field.as_str() {
            "Ignore" => Ok(ManifestField::Ignore),
            "Bucket" => Ok(ManifestField::Bucket),
            "Key" => Ok(ManifestField::Key),
            "VersionId" => Ok(ManifestField::VersionId),
            other => Err(bad_request(format!("{other} isn't a manifest field."))),
        })
        .collect::<S3Result<Vec<_>>>()?;
    let once = |wanted| fields.iter().filter(|f| **f == wanted).count() == 1;
    if !(once(ManifestField::Bucket) && once(ManifestField::Key))
        || fields
            .iter()
            .filter(|f| **f == ManifestField::VersionId)
            .count()
            > 1
    {
        return Err(bad_request(
            "A CSV manifest's Fields name Bucket and Key once each, and VersionId at most once.",
        ));
    }
    let (bucket, key) = object_of(&given.location.object_arn)
        .ok_or_else(|| bad_request("The manifest's ObjectArn must be an object's ARN."))?;
    let etag = given
        .location
        .etag
        .filter(|etag| !etag.is_empty())
        .ok_or_else(|| bad_request("The manifest's Location needs its ETag."))?;
    let etag = if etag.starts_with('"') {
        etag
    } else {
        format!("\"{etag}\"")
    };
    Ok(Manifest {
        bucket,
        key,
        version_id: given.location.object_version_id.filter(|v| !v.is_empty()),
        etag,
        fields,
    })
}

/// The bucket and key of `arn:aws:s3:::bucket/key`.
fn object_of(arn: &str) -> Option<(String, String)> {
    let (bucket, key) = arn.strip_prefix("arn:aws:s3:::")?.split_once('/')?;
    (!bucket.is_empty() && !key.is_empty()).then(|| (bucket.to_owned(), key.to_owned()))
}

fn report_of(given: &ReportXml) -> S3Result<Option<JobReport>> {
    if !given.enabled {
        return Ok(None);
    }
    Err(not_implemented(
        "TeiFS doesn't write completion reports yet: set the Report's Enabled to false.",
    ))
}

fn operation_of_xml(given: OperationXml) -> S3Result<Operation> {
    let mut operations = Vec::new();
    if let Some(tagging) = given.put_tagging {
        let tags = tags_of(tagging.tag_set.unwrap_or_default())?;
        operations.push(Operation::PutObjectTagging { tags });
    }
    if given.delete_tagging.is_some() {
        operations.push(Operation::DeleteObjectTagging);
    }
    if let Some(hold) = given.legal_hold {
        let on = match hold.legal_hold.status.as_str() {
            "ON" => true,
            "OFF" => false,
            _ => return Err(bad_request("A legal hold's Status is ON or OFF.")),
        };
        operations.push(Operation::PutObjectLegalHold { on });
    }
    if let Some(retention) = given.retention {
        let inner = retention.retention.unwrap_or_default();
        let mode = inner.mode.filter(|m| !m.is_empty());
        if mode
            .as_deref()
            .is_some_and(|m| !matches!(m, "GOVERNANCE" | "COMPLIANCE"))
        {
            return Err(bad_request(
                "A retention's Mode is GOVERNANCE or COMPLIANCE.",
            ));
        }
        let until = inner
            .retain_until_date
            .map(|date| {
                OffsetDateTime::parse(&date, &Rfc3339)
                    .map(|t| {
                        i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
                    })
                    .map_err(|_| bad_request("RetainUntilDate must be an ISO 8601 time."))
            })
            .transpose()?;
        if mode.is_some() != until.is_some() {
            return Err(bad_request(
                "A retention has both a Mode and a RetainUntilDate, or neither.",
            ));
        }
        operations.push(Operation::PutObjectRetention {
            mode,
            retain_until_ms: until,
            bypass_governance: retention.bypass_governance_retention.unwrap_or(false),
        });
    }
    match operations.len() {
        1 => Ok(operations.remove(0)),
        0 => Err(not_implemented(
            "TeiFS runs these operations: S3PutObjectTagging, S3DeleteObjectTagging, \
             S3PutObjectLegalHold and S3PutObjectRetention.",
        )),
        _ => Err(bad_request("A job has exactly one Operation.")),
    }
}

/// Tags, checked as a job's.
fn tags_of(given: Members<TagXml>) -> S3Result<Vec<KeyValue>> {
    if given.member.len() > MAX_TAGS {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "TooManyTagsException",
            format!("A job has at most {MAX_TAGS} tags."),
        ));
    }
    let mut tags: Vec<KeyValue> = Vec::with_capacity(given.member.len());
    for tag in given.member {
        if !(1..=128).contains(&tag.key.chars().count()) || tag.value.chars().count() > 256 {
            return Err(bad_request(
                "A tag's key is 1 to 128 characters, its value at most 256.",
            ));
        }
        if tags.iter().any(|t| t.key == tag.key) {
            return Err(bad_request(format!(
                "The tag key {} is given twice.",
                tag.key
            )));
        }
        tags.push(KeyValue {
            key: tag.key,
            value: tag.value,
        });
    }
    Ok(tags)
}

/// `GET /v20180820/jobs`: the jobs, newest first, of the statuses asked for.
async fn list(store: &Store, query: Option<&str>) -> S3Result<S3Response<Body>> {
    let pairs: Vec<(String, String)> = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .map(|(n, v)| (n.into_owned(), v.into_owned()))
        .collect();
    let statuses: Vec<&str> = pairs
        .iter()
        .filter(|(n, _)| n == "jobStatuses")
        .map(|(_, v)| v.as_str())
        .collect();
    let value = |name: &str| {
        pairs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    let max = match value("maxResults") {
        Some(max) => max
            .parse::<usize>()
            .ok()
            .filter(|m| (1..=MAX_RESULTS).contains(m))
            .ok_or_else(|| bad_request(format!("maxResults must be from 1 to {MAX_RESULTS}.")))?,
        None => MAX_RESULTS,
    };
    let mut jobs: Vec<BatchJob> = store
        .batch_jobs()
        .await
        .s3()?
        .into_iter()
        .filter(|job| !job.spec.is_minio())
        .filter(|job| statuses.is_empty() || statuses.contains(&job.status.as_str()))
        .collect();
    jobs.sort_by(|a, b| {
        b.created_ms
            .cmp(&a.created_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    let start = match value("nextToken") {
        Some(token) => {
            let after = URL_SAFE_NO_PAD
                .decode(token)
                .ok()
                .and_then(|id| String::from_utf8(id).ok())
                .and_then(|id| jobs.iter().position(|job| job.id == id))
                .ok_or_else(|| {
                    error(
                        StatusCode::BAD_REQUEST,
                        "InvalidNextTokenException",
                        "The NextToken isn't one ListJobs gave.",
                    )
                })?;
            after + 1
        }
        None => 0,
    };
    let page: Vec<&BatchJob> = jobs.iter().skip(start).take(max).collect();
    let next_token = (start + page.len() < jobs.len())
        .then(|| page.last().map(|job| URL_SAFE_NO_PAD.encode(&job.id)))
        .flatten();
    let listed = Listed {
        next_token,
        jobs: members(page.into_iter().map(listed_job)),
    };
    xml("ListJobsResult", &listed)
}

fn listed_job(job: &BatchJob) -> ListedJob {
    let op = operation_of(job);
    ListedJob {
        job_id: job.id.clone(),
        description: op
            .map(|op| op.description.clone())
            .filter(|d| !d.is_empty()),
        operation: op.map(|op| op.operation.name()),
        priority: job.priority,
        status: job.status.as_str(),
        creation_time: iso(job.created_ms),
        termination_date: termination(job),
        progress_summary: progress(job),
    }
}

fn termination(job: &BatchJob) -> Option<String> {
    job.status
        .finished()
        .then(|| iso(job.progress.updated_ms.unwrap_or(job.created_ms)))
}

fn progress(job: &BatchJob) -> Progress {
    let p = &job.progress;
    let active = p.started_ms.map_or(0, |started| {
        let until = if job.status.finished() {
            p.updated_ms.unwrap_or(started)
        } else {
            crate::admin::millis(std::time::SystemTime::now())
        };
        until.saturating_sub(started) / 1000
    });
    Progress {
        total_number_of_tasks: p.total,
        number_of_tasks_succeeded: p.objects,
        number_of_tasks_failed: p.objects_failed,
        timers: Timers {
            elapsed_time_in_active_seconds: active,
        },
    }
}

/// `DescribeJob`'s `Job`.
fn describe(caller: &Caller<'_>, job: &BatchJob) -> JobXml {
    let op = operation_of(job);
    let suspended = job.status == JobStatus::Suspended;
    JobXml {
        job_id: job.id.clone(),
        confirmation_required: op.is_some_and(|op| op.confirmation_required),
        description: op
            .map(|op| op.description.clone())
            .filter(|d| !d.is_empty()),
        job_arn: caller.job_arn(&job.id),
        status: job.status.as_str(),
        manifest: op.map(|op| manifest_xml(&op.manifest)),
        operation: op.map(|op| operation_xml(&op.operation)),
        priority: job.priority,
        progress_summary: progress(job),
        status_update_reason: op.and_then(|op| op.status_reason.clone()),
        failure_reasons: members(job.failures.iter().map(|why| {
            let (code, reason) = why.split_once(": ").unwrap_or(("Failed", why));
            FailureXml {
                failure_code: code.to_owned(),
                failure_reason: reason.to_owned(),
            }
        })),
        report: ReportXml {
            enabled: false,
            ..ReportXml::default()
        },
        creation_time: iso(job.created_ms),
        termination_date: termination(job),
        role_arn: op.map(|op| op.role_arn.clone()).unwrap_or_default(),
        suspended_date: suspended.then(|| iso(job.progress.updated_ms.unwrap_or(job.created_ms))),
        suspended_cause: suspended.then_some("AWAITING_CONFIRMATION"),
    }
}

fn manifest_xml(manifest: &Manifest) -> ManifestXml {
    ManifestXml {
        spec: SpecXml {
            format: CSV_MANIFEST.to_owned(),
            fields: Some(members(
                manifest.fields.iter().map(|f| f.as_str().to_owned()),
            )),
        },
        location: LocationXml {
            object_arn: format!("arn:aws:s3:::{}/{}", manifest.bucket, manifest.key),
            object_version_id: manifest.version_id.clone(),
            etag: Some(manifest.etag.clone()),
        },
    }
}

fn operation_xml(operation: &Operation) -> OperationXml {
    let mut xml = OperationXml::default();
    match operation {
        Operation::PutObjectTagging { tags } => {
            xml.put_tagging = Some(PutObjectTaggingXml {
                tag_set: Some(members(tags.iter().map(TagXml::of))),
            });
        }
        Operation::DeleteObjectTagging => xml.delete_tagging = Some(Empty {}),
        Operation::PutObjectLegalHold { on } => {
            xml.legal_hold = Some(LegalHoldXml {
                legal_hold: HoldXml {
                    status: if *on { "ON" } else { "OFF" }.to_owned(),
                },
            });
        }
        Operation::PutObjectRetention {
            mode,
            retain_until_ms,
            bypass_governance,
        } => {
            xml.retention = Some(PutRetentionXml {
                bypass_governance_retention: Some(*bypass_governance),
                retention: Some(RetentionXml {
                    retain_until_date: retain_until_ms.map(iso),
                    mode: mode.clone(),
                }),
            });
        }
    }
    xml
}

/// `POST …/priority?priority=N`.
async fn set_priority(store: &Store, id: &str, priority: i32) -> S3Result<S3Response<Body>> {
    store
        .update_batch_job(id, move |job| job.priority = priority)
        .await
        .s3()?;
    xml(
        "UpdateJobPriorityResult",
        &Prioritized {
            job_id: id.to_owned(),
            priority,
        },
    )
}

fn priority(given: Option<&str>) -> S3Result<i32> {
    given
        .and_then(|p| p.parse::<i32>().ok())
        .filter(|p| *p >= 0)
        .ok_or_else(|| bad_request("priority must be from 0 to 2147483647."))
}

/// `POST …/status?requestedJobStatus=Ready|Cancelled[&statusUpdateReason=…]`: confirms
/// a suspended job, or cancels one that hasn't ended.
async fn set_status(
    store: &Store,
    req: &S3Request<Body>,
    job: BatchJob,
) -> S3Result<(S3Response<Body>, bool)> {
    let wanted = match param(req, "requestedJobStatus").as_deref() {
        Some("Ready") => JobStatus::Ready,
        Some("Cancelled") => JobStatus::Cancelled,
        _ => return Err(bad_request("requestedJobStatus is Ready or Cancelled.")),
    };
    let reason = param(req, "statusUpdateReason").filter(|r| !r.is_empty());
    if reason.as_ref().is_some_and(|r| r.chars().count() > 256) {
        return Err(bad_request("statusUpdateReason is at most 256 characters."));
    }
    if !may_become(job.status, wanted) {
        return Err(not_now(&job, wanted));
    }
    let given = reason.clone();
    let kept = store
        .update_batch_job(&job.id, move |job| {
            job.status = wanted;
            if let teifs_types::batch::JobSpec::Operation(op) = &mut job.spec {
                op.status_reason = given;
            }
        })
        .await
        .s3()?;
    // Ended meanwhile.
    if kept.as_ref().is_none_or(|kept| kept.status != wanted) {
        return Err(not_now(&job, wanted));
    }
    let answer = StatusSet {
        job_id: job.id,
        status: wanted.as_str(),
        status_update_reason: reason,
    };
    Ok((
        xml("UpdateJobStatusResult", &answer)?,
        wanted == JobStatus::Ready,
    ))
}

/// Whether a job that's `from` may be made `to`: confirmed while suspended, or
/// cancelled before it ended.
fn may_become(from: JobStatus, to: JobStatus) -> bool {
    match to {
        JobStatus::Ready => from == JobStatus::Suspended,
        JobStatus::Cancelled => !from.finished(),
        _ => false,
    }
}

fn not_now(job: &BatchJob, wanted: JobStatus) -> S3Error {
    error(
        StatusCode::CONFLICT,
        "JobStatusException",
        format!(
            "A job that's {} can't be made {}.",
            job.status.as_str(),
            wanted.as_str()
        ),
    )
}

async fn set_tags(store: &Store, id: &str, tags: Vec<KeyValue>) -> S3Result<()> {
    store
        .update_batch_job(id, move |job| {
            if let teifs_types::batch::JobSpec::Operation(op) = &mut job.spec {
                op.tags = tags;
            }
        })
        .await
        .s3()?;
    Ok(())
}

fn param(req: &S3Request<Body>, name: &str) -> Option<String> {
    form_urlencoded::parse(req.uri.query().unwrap_or_default().as_bytes())
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.into_owned())
}

fn iso(ms: i64) -> String {
    crate::minio_kms::rfc3339(ms)
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> S3Error {
    crate::admin::error(status, code, message)
}

fn bad_request(message: impl Into<String>) -> S3Error {
    error(StatusCode::BAD_REQUEST, "BadRequestException", message)
}

fn not_implemented(message: impl Into<String>) -> S3Error {
    error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", message)
}

fn read_xml<T: for<'de> Deserialize<'de>>(body: &[u8], root: &str) -> S3Result<T> {
    let text = std::str::from_utf8(body).map_err(|_| bad_request("The body isn't UTF-8."))?;
    quick_xml::de::from_str(text)
        .map_err(|err| bad_request(format!("The body must be a {root}: {err}")))
}

/// An answer: `value` as the root element `root`, in S3 Control's namespace.
fn xml<T: Serialize>(root: &str, value: &T) -> S3Result<S3Response<Body>> {
    let mut text = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let mut serializer = quick_xml::se::Serializer::with_root(&mut text, Some(root))
        .map_err(S3Error::internal_error)?;
    serializer.expand_empty_elements(false);
    value
        .serialize(serializer)
        .map_err(S3Error::internal_error)?;
    // The namespace goes on the root element.
    let text = text.replacen(
        &format!("<{root}"),
        &format!("<{root} xmlns=\"{NAMESPACE}\""),
        1,
    );
    let mut response = S3Response::new(Body::from(text));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    Ok(response)
}

fn members<T>(items: impl Iterator<Item = T>) -> Members<T> {
    Members {
        member: items.collect(),
    }
}

/// A list, as S3 Control writes them: each item a `member`.
#[derive(Debug, Serialize, Deserialize)]
struct Members<T> {
    #[serde(default = "Vec::new")]
    member: Vec<T>,
}

impl<T> Default for Members<T> {
    fn default() -> Self {
        Self { member: Vec::new() }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Empty {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateJob {
    confirmation_required: Option<bool>,
    operation: Option<OperationXml>,
    report: Option<ReportXml>,
    client_request_token: Option<String>,
    manifest: Option<ManifestXml>,
    manifest_generator: Option<IgnoredAny>,
    description: Option<String>,
    priority: Option<i64>,
    role_arn: Option<String>,
    tags: Option<Members<TagXml>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OperationXml {
    #[serde(rename = "S3PutObjectTagging", skip_serializing_if = "Option::is_none")]
    put_tagging: Option<PutObjectTaggingXml>,
    #[serde(
        rename = "S3DeleteObjectTagging",
        skip_serializing_if = "Option::is_none"
    )]
    delete_tagging: Option<Empty>,
    #[serde(
        rename = "S3PutObjectLegalHold",
        skip_serializing_if = "Option::is_none"
    )]
    legal_hold: Option<LegalHoldXml>,
    #[serde(
        rename = "S3PutObjectRetention",
        skip_serializing_if = "Option::is_none"
    )]
    retention: Option<PutRetentionXml>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PutObjectTaggingXml {
    tag_set: Option<Members<TagXml>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LegalHoldXml {
    legal_hold: HoldXml,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HoldXml {
    status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PutRetentionXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    bypass_governance_retention: Option<bool>,
    retention: Option<RetentionXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RetentionXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    retain_until_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TagXml {
    key: String,
    #[serde(default)]
    value: String,
}

impl TagXml {
    fn of(tag: &KeyValue) -> Self {
        Self {
            key: tag.key.clone(),
            value: tag.value.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ManifestXml {
    spec: SpecXml,
    location: LocationXml,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SpecXml {
    format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Members<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LocationXml {
    object_arn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_version_id: Option<String>,
    #[serde(rename = "ETag", skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ReportXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(default)]
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_scope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PutTagging {
    #[serde(default)]
    tags: Members<TagXml>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Created {
    job_id: String,
}

#[derive(Serialize)]
struct Described {
    #[serde(rename = "Job")]
    job: JobXml,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct JobXml {
    job_id: String,
    confirmation_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    job_arn: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<ManifestXml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<OperationXml>,
    priority: i32,
    progress_summary: Progress,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_update_reason: Option<String>,
    failure_reasons: Members<FailureXml>,
    report: ReportXml,
    creation_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    termination_date: Option<String>,
    role_arn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suspended_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suspended_cause: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct FailureXml {
    failure_code: String,
    failure_reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Progress {
    #[serde(skip_serializing_if = "Option::is_none")]
    total_number_of_tasks: Option<u64>,
    number_of_tasks_succeeded: u64,
    number_of_tasks_failed: u64,
    timers: Timers,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Timers {
    elapsed_time_in_active_seconds: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Listed {
    #[serde(skip_serializing_if = "Option::is_none")]
    next_token: Option<String>,
    jobs: Members<ListedJob>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ListedJob {
    job_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<&'static str>,
    priority: i32,
    status: &'static str,
    creation_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    termination_date: Option<String>,
    progress_summary: Progress,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Prioritized {
    job_id: String,
    priority: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct StatusSet {
    job_id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_update_reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Tagged {
    tags: Members<TagXml>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(n: usize) -> Members<TagXml> {
        members((0..n).map(|i| TagXml {
            key: format!("k{i}"),
            value: "v".to_owned(),
        }))
    }

    #[test]
    fn suspended_jobs_are_confirmed_and_unended_ones_cancelled() {
        use JobStatus::{Active, Cancelled, Complete, Failed, New, Ready, Suspended};
        assert!(may_become(Suspended, Ready));
        for from in [New, Ready, Active, Complete, Cancelled, Failed] {
            assert!(!may_become(from, Ready), "{from:?}");
        }
        for from in [New, Suspended, Ready, Active] {
            assert!(may_become(from, Cancelled), "{from:?}");
        }
        for from in [Complete, Cancelled, Failed] {
            assert!(!may_become(from, Cancelled), "{from:?}");
        }
        assert!(!may_become(Suspended, Active));
    }

    #[test]
    fn a_job_has_at_most_fifty_distinct_tags() {
        assert_eq!(tags_of(tags(50)).unwrap().len(), 50);
        let err = tags_of(tags(51)).unwrap_err();
        assert_eq!(err.code().as_str(), "TooManyTagsException");
        let twice = members(["a", "a"].into_iter().map(|key| TagXml {
            key: key.to_owned(),
            value: String::new(),
        }));
        assert!(tags_of(twice).is_err());
        for (key, value) in [
            ("", "v"),
            (&*"k".repeat(129), "v"),
            ("k", &*"v".repeat(257)),
        ] {
            let tag = members(std::iter::once(TagXml {
                key: key.to_owned(),
                value: value.to_owned(),
            }));
            assert!(tags_of(tag).is_err(), "{key}={value}");
        }
        let longest = members(std::iter::once(TagXml {
            key: "k".repeat(128),
            value: "v".repeat(256),
        }));
        assert!(tags_of(longest).is_ok());
    }

    #[test]
    fn paths_and_arns_name_jobs_and_objects() {
        assert_eq!(job_id("/v20180820/jobs/abc").unwrap(), "abc");
        assert_eq!(job_id("/v20180820/jobs/abc/tagging").unwrap(), "abc");
        assert!(job_id("/v20180820/jobs/").is_err());
        assert_eq!(
            object_of("arn:aws:s3:::manifests/a/b.csv"),
            Some(("manifests".to_owned(), "a/b.csv".to_owned()))
        );
        for wrong in [
            "arn:aws:s3:::manifests",
            "arn:aws:s3:::/a",
            "arn:aws:s3:::b/",
            "b/a",
        ] {
            assert_eq!(object_of(wrong), None, "{wrong}");
        }
        assert_eq!(priority(Some("0")).unwrap(), 0);
        assert_eq!(priority(Some("2147483647")).unwrap(), i32::MAX);
        for wrong in [None, Some("-1"), Some("2147483648"), Some("x")] {
            assert!(priority(wrong).is_err(), "{wrong:?}");
        }
    }

    fn manifest(fields: &[&str], etag: Option<&str>) -> S3Result<Manifest> {
        manifest_of(ManifestXml {
            spec: SpecXml {
                format: CSV_MANIFEST.to_owned(),
                fields: Some(members(fields.iter().map(|f| (*f).to_owned()))),
            },
            location: LocationXml {
                object_arn: "arn:aws:s3:::manifests/m.csv".to_owned(),
                object_version_id: Some(String::new()),
                etag: etag.map(str::to_owned),
            },
        })
    }

    #[test]
    fn a_manifest_names_its_bucket_and_key_columns_once() {
        let read = manifest(&["Ignore", "Bucket", "Key", "VersionId"], Some("abc")).unwrap();
        assert_eq!(read.etag, "\"abc\"");
        assert_eq!(read.version_id, None);
        assert_eq!(read.bucket, "manifests");
        let quoted = manifest(&["Bucket", "Key"], Some("\"abc\"")).unwrap();
        assert_eq!(quoted.etag, "\"abc\"");
        for wrong in [
            &["Bucket"][..],
            &["Key"],
            &["Bucket", "Key", "Key"],
            &["Bucket", "Bucket", "Key"],
            &["Bucket", "Key", "VersionId", "VersionId"],
            &["Bucket", "Key", "Size"],
        ] {
            assert!(manifest(wrong, Some("abc")).is_err(), "{wrong:?}");
        }
        assert!(manifest(&["Bucket", "Key"], None).is_err());
        assert!(manifest(&["Bucket", "Key"], Some("")).is_err());
    }

    #[test]
    fn operations_are_read_as_s3_control_writes_them() {
        let read = |xml: &str| {
            let given: OperationXml = quick_xml::de::from_str(xml).unwrap();
            operation_of_xml(given)
        };
        assert_eq!(
            read("<Operation><S3PutObjectLegalHold><LegalHold><Status>OFF</Status></LegalHold></S3PutObjectLegalHold></Operation>").unwrap(),
            Operation::PutObjectLegalHold { on: false }
        );
        assert_eq!(
            read("<Operation><S3PutObjectRetention><Retention><RetainUntilDate>2030-01-02T03:04:05Z</RetainUntilDate><Mode>COMPLIANCE</Mode></Retention></S3PutObjectRetention></Operation>").unwrap(),
            Operation::PutObjectRetention {
                mode: Some("COMPLIANCE".to_owned()),
                retain_until_ms: Some(1_893_553_445_000),
                bypass_governance: false,
            }
        );
        // No mode and no date takes retention off.
        assert_eq!(
            read("<Operation><S3PutObjectRetention><BypassGovernanceRetention>true</BypassGovernanceRetention><Retention/></S3PutObjectRetention></Operation>").unwrap(),
            Operation::PutObjectRetention {
                mode: None,
                retain_until_ms: None,
                bypass_governance: true,
            }
        );
        for wrong in [
            "<Operation><S3PutObjectLegalHold><LegalHold><Status>on</Status></LegalHold></S3PutObjectLegalHold></Operation>",
            "<Operation><S3PutObjectRetention><Retention><Mode>COMPLIANCE</Mode></Retention></S3PutObjectRetention></Operation>",
            "<Operation><S3PutObjectRetention><Retention><RetainUntilDate>2030-01-02T03:04:05Z</RetainUntilDate></Retention></S3PutObjectRetention></Operation>",
            "<Operation><S3PutObjectRetention><Retention><RetainUntilDate>2030-01-02T03:04:05Z</RetainUntilDate><Mode>LOCKED</Mode></Retention></S3PutObjectRetention></Operation>",
            "<Operation><S3PutObjectRetention><Retention><RetainUntilDate>soon</RetainUntilDate><Mode>GOVERNANCE</Mode></Retention></S3PutObjectRetention></Operation>",
            "<Operation><S3DeleteObjectTagging/><S3PutObjectLegalHold><LegalHold><Status>ON</Status></LegalHold></S3PutObjectLegalHold></Operation>",
        ] {
            assert_eq!(
                read(wrong).unwrap_err().code().as_str(),
                "BadRequestException",
                "{wrong}"
            );
        }
        assert_eq!(
            read("<Operation/>").unwrap_err().code().as_str(),
            "NotImplemented"
        );
    }

    #[test]
    fn answers_are_in_s3_controls_namespace() {
        let response = xml(
            "CreateJobResult",
            &Created {
                job_id: "j".to_owned(),
            },
        )
        .unwrap();
        let body = format!("{:?}", response.output);
        assert!(
            body.contains(r#"<CreateJobResult xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\"><JobId>j</JobId></CreateJobResult>"#),
            "{body}"
        );
    }
}
