//! S3 Batch Operations: `teifs batch create|ls|describe|confirm|cancel|priority|report`,
//! through S3 Control as `aws s3control` calls it. A job runs one operation on every
//! object a CSV manifest lists, as an IAM role; the manifest's ETag (and version) is
//! read for it, and a role named without an ARN is the alias's account's.

use aws_sdk_s3control::{
    Client,
    config::{
        Region,
        endpoint::{Endpoint, EndpointFuture, Params, ResolveEndpoint},
    },
    primitives::DateTime,
    types::{
        JobListDescriptor, JobManifest, JobManifestFieldName, JobManifestFormat,
        JobManifestLocation, JobManifestSpec, JobOperation, JobReport, JobReportFormat,
        JobReportScope, JobStatus, ObjectEncryption, RequestedJobStatus, S3AccessControlPolicy,
        S3CannedAccessControlList, S3ComputeObjectChecksumOperation, S3CopyObjectOperation,
        S3DeleteObjectTaggingOperation, S3ObjectLockLegalHold, S3ObjectLockLegalHoldStatus,
        S3ObjectLockRetentionMode, S3ReplicateObjectOperation, S3Retention,
        S3SetObjectAclOperation, S3SetObjectLegalHoldOperation, S3SetObjectRetentionOperation,
        S3SetObjectTaggingOperation, S3Tag, S3UpdateObjectEncryptionOperation,
        S3UpdateObjectEncryptionSsekms,
    },
};
use clap::{ArgGroup, Args, Subcommand};
use serde_json::{Value, json};

use super::{
    Error, Kind,
    alias::{Alias, Aliases},
    target::Target,
};
use crate::{
    ui,
    units::{date, from_ms, parse_day},
};

#[derive(Subcommand)]
pub enum BatchAction {
    /// Make a job that runs one operation on every object a CSV manifest lists, as an IAM
    /// role (S3 Batch Operations).
    Create(Box<CreateArgs>),
    /// List the alias's jobs, newest first.
    Ls {
        /// `ALIAS`.
        alias: String,
        /// Only jobs in these statuses (`Active`, `Complete`, `Suspended`, …).
        #[arg(long = "status", value_name = "STATUS")]
        statuses: Vec<String>,
    },
    /// Show a job: its operation, status, progress, and why it failed.
    Describe {
        /// `ALIAS`.
        alias: String,
        /// The job's id.
        id: String,
    },
    /// Let a job that waits to be confirmed run.
    Confirm {
        /// `ALIAS`.
        alias: String,
        /// The job's id.
        id: String,
    },
    /// Cancel a job that hasn't ended.
    Cancel {
        /// `ALIAS`.
        alias: String,
        /// The job's id.
        id: String,
    },
    /// Change a job's priority: higher runs first.
    Priority {
        /// `ALIAS`.
        alias: String,
        /// The job's id.
        id: String,
        /// Its new priority.
        priority: i32,
    },
    /// Print a finished job's completion report, one task a line.
    Report {
        /// `ALIAS`.
        alias: String,
        /// The job's id.
        id: String,
    },
}

/// What `teifs batch create` takes: the manifest, the role, and one operation.
#[derive(Args)]
#[allow(clippy::struct_excessive_bools, reason = "command-line switches")]
#[command(group(
    ArgGroup::new("operation")
        .required(true)
        .args(["tag", "untag", "legal_hold", "retention", "copy_to", "acl", "checksum",
               "encrypt_kms", "replicate"])
))]
pub struct CreateArgs {
    /// `ALIAS/BUCKET/KEY` of the CSV manifest: one object a line, `bucket,key` with the
    /// key URL-encoded (and `,version` with `--versions`).
    manifest: String,
    /// The IAM role the tasks run as: its name, or its ARN. It must trust
    /// `batchoperations.s3.amazonaws.com`.
    #[arg(long)]
    role: String,
    /// The manifest's lines name each object's version in a third column.
    #[arg(long)]
    versions: bool,
    /// Replace each object's tags with these.
    #[arg(long, value_name = "KEY=VALUE")]
    tag: Vec<String>,
    /// Remove each object's tags.
    #[arg(long)]
    untag: bool,
    /// Put a legal hold on each object, or take it off.
    #[arg(long, value_name = "on|off", value_parser = ["on", "off"])]
    legal_hold: Option<String>,
    /// Set each object's retention (with `--retain-until`), or take it off (`off`).
    #[arg(long, value_name = "GOVERNANCE|COMPLIANCE|off",
          value_parser = ["GOVERNANCE", "COMPLIANCE", "off"])]
    retention: Option<String>,
    /// The day the retention ends, `YYYY-MM-DD`.
    #[arg(long, value_name = "DATE", requires = "retention")]
    retain_until: Option<String>,
    /// Shorten or remove governance-mode retention too.
    #[arg(long, requires = "retention")]
    bypass_governance: bool,
    /// Copy each object into this bucket of the same server, under the prefix if given.
    #[arg(long, value_name = "BUCKET[/PREFIX]")]
    copy_to: Option<String>,
    /// Give each object this canned ACL (`private`, `public-read`, …).
    #[arg(long, value_name = "ACL")]
    acl: Option<String>,
    /// Work out each object's checksum into the report (`CRC32`, `SHA256`, …): needs
    /// `--report`.
    #[arg(long, value_name = "ALGORITHM", requires = "report")]
    checksum: Option<String>,
    /// The checksum's type: of the full object (the default) or its parts.
    #[arg(long, value_name = "TYPE", requires = "checksum",
          value_parser = ["FULL_OBJECT", "COMPOSITE"])]
    checksum_type: Option<String>,
    /// Move each SSE-S3 or SSE-KMS object to this KMS key in place (its full ARN).
    #[arg(long, value_name = "KMS_KEY_ARN")]
    encrypt_kms: Option<String>,
    /// With `--encrypt-kms`: use an S3 Bucket Key.
    #[arg(long, requires = "encrypt_kms")]
    bucket_key: bool,
    /// Replicate each object now by its bucket's replication rules (Batch Replication).
    #[arg(long)]
    replicate: bool,
    /// Write a completion report into this bucket of the same server, under the prefix
    /// if given.
    #[arg(long, value_name = "BUCKET[/PREFIX]")]
    report: Option<String>,
    /// Report only the tasks that failed.
    #[arg(long, requires = "report")]
    failed_only: bool,
    /// The job's priority: higher runs first.
    #[arg(long, default_value_t = 10)]
    priority: i32,
    /// Wait to be confirmed (`teifs batch confirm`) before running.
    #[arg(long)]
    confirm: bool,
    /// What the job is for.
    #[arg(long)]
    description: Option<String>,
}

/// `teifs batch …`.
pub(super) async fn run(action: BatchAction, aliases: &Aliases) -> Result<(), Error> {
    match action {
        BatchAction::Create(args) => create(*args, aliases).await,
        BatchAction::Ls { alias, statuses } => {
            ls(&Control::of(aliases, &alias).await?, statuses).await
        }
        BatchAction::Describe { alias, id } => {
            describe(&Control::of(aliases, &alias).await?, &id).await
        }
        BatchAction::Confirm { alias, id } => {
            status(
                &Control::of(aliases, &alias).await?,
                &id,
                RequestedJobStatus::Ready,
            )
            .await
        }
        BatchAction::Cancel { alias, id } => {
            status(
                &Control::of(aliases, &alias).await?,
                &id,
                RequestedJobStatus::Cancelled,
            )
            .await
        }
        BatchAction::Priority {
            alias,
            id,
            priority,
        } => reprioritize(&Control::of(aliases, &alias).await?, &id, priority).await,
        BatchAction::Report { alias, id } => {
            report(&Control::of(aliases, &alias).await?, &id).await
        }
    }
}

/// An alias's S3 Control, and the account it signs as.
struct Control {
    name: String,
    alias: Alias,
    client: Client,
    account: String,
}

/// S3 Control's endpoint is the alias's URL itself: no account id in the host name.
#[derive(Debug)]
struct Direct(String);

impl ResolveEndpoint for Direct {
    fn resolve_endpoint<'a>(&'a self, _: &'a Params) -> EndpointFuture<'a> {
        EndpointFuture::ready(Ok(Endpoint::builder().url(self.0.clone()).build()))
    }
}

impl Control {
    async fn of(aliases: &Aliases, name: &str) -> Result<Self, Error> {
        let (alias, _) = aliases.get(name).ok_or_else(|| {
            Error::new(Kind::NotFound, format!("there's no alias `{name}`"))
                .with_hint("see `teifs alias ls`, or add one with `teifs alias set`")
        })?;
        alias.check_usable(name)?;
        let account = crate::sts::client(alias, true)
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't tell which account `{name}` signs as"), &e))?
            .account
            .unwrap_or_default();
        let mut config = aws_sdk_s3control::Config::builder()
            .behavior_version_latest()
            .region(Region::new(alias.region.clone()))
            .endpoint_resolver(Direct(alias.url.clone()))
            .credentials_provider(alias.credentials());
        config.set_http_client(alias.trust.sdk_client());
        Ok(Self {
            name: name.to_owned(),
            alias: alias.clone(),
            client: Client::from_conf(config.build()),
            account,
        })
    }
}

async fn create(args: CreateArgs, aliases: &Aliases) -> Result<(), Error> {
    let remote = Target::parse(&args.manifest, aliases)?.remote("batch create")?;
    let bucket = remote.bucket()?.to_owned();
    if remote.key.is_empty() {
        return Err(Error::usage(
            "give the manifest's object: ALIAS/BUCKET/KEY".to_owned(),
        ));
    }
    let control = Control::of(aliases, &remote.alias_name).await?;
    let head = remote
        .alias
        .client()
        .head_object()
        .bucket(&bucket)
        .key(&remote.key)
        .send()
        .await
        .map_err(|e| {
            Error::s3(
                format!("can't read the manifest {}", remote.display(&remote.key)),
                &e,
            )
        })?;
    let mut fields = vec![JobManifestFieldName::Bucket, JobManifestFieldName::Key];
    if args.versions {
        fields.push(JobManifestFieldName::VersionId);
    }
    let manifest = JobManifest::builder()
        .spec(
            JobManifestSpec::builder()
                .format(JobManifestFormat::S3BatchOperationsCsv20180820)
                .set_fields(Some(fields))
                .build()
                .map_err(|e| Error::usage(e.to_string()))?,
        )
        .location(
            JobManifestLocation::builder()
                .object_arn(format!("arn:aws:s3:::{bucket}/{}", remote.key))
                .set_object_version_id(head.version_id.filter(|v| v != "null"))
                .set_e_tag(head.e_tag)
                .build()
                .map_err(|e| Error::usage(e.to_string()))?,
        )
        .build();
    let report = match &args.report {
        Some(at) => {
            let (bucket, prefix) = at.split_once('/').unwrap_or((at, ""));
            JobReport::builder()
                .enabled(true)
                .bucket(format!("arn:aws:s3:::{bucket}"))
                .set_prefix(Some(prefix.trim_end_matches('/').to_owned()).filter(|p| !p.is_empty()))
                .format(JobReportFormat::ReportCsv20180820)
                .report_scope(if args.failed_only {
                    JobReportScope::FailedTasksOnly
                } else {
                    JobReportScope::AllTasks
                })
                .build()
        }
        None => JobReport::builder().enabled(false).build(),
    };
    let role = role_arn(&args.role, &control.account);
    let operation = operation(&args)?;
    let created = control
        .client
        .create_job()
        .account_id(&control.account)
        .operation(operation)
        .manifest(manifest)
        .report(report)
        .priority(args.priority)
        .role_arn(&role)
        .confirmation_required(args.confirm)
        .set_description(args.description.clone())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't make the job on {}", control.name), &e))?;
    let id = created.job_id.unwrap_or_default();
    let then = if args.confirm {
        format!(": it waits for `teifs batch confirm {} {id}`", control.name)
    } else {
        String::new()
    };
    ui::done(
        format!("{}: job {id} made{then}", control.name),
        || json!({"type": "batchJob", "alias": control.name, "id": id, "role": role}),
    );
    Ok(())
}

/// A role's ARN: as given, or the account's role of that name.
fn role_arn(role: &str, account: &str) -> String {
    if role.starts_with("arn:") {
        role.to_owned()
    } else {
        format!("arn:aws:iam::{account}:role/{role}")
    }
}

/// The one operation the arguments name.
fn operation(args: &CreateArgs) -> Result<JobOperation, Error> {
    let usage = |e: aws_sdk_s3control::error::BuildError| Error::usage(e.to_string());
    let job = JobOperation::builder();
    let job = if !args.tag.is_empty() {
        let tags = args
            .tag
            .iter()
            .map(|pair| {
                let (key, value) = pair.split_once('=').ok_or_else(|| {
                    Error::usage(format!("`{pair}` isn't a tag: write it KEY=VALUE"))
                })?;
                S3Tag::builder()
                    .key(key)
                    .value(value)
                    .build()
                    .map_err(usage)
            })
            .collect::<Result<Vec<_>, _>>()?;
        job.s3_put_object_tagging(
            S3SetObjectTaggingOperation::builder()
                .set_tag_set(Some(tags))
                .build(),
        )
    } else if args.untag {
        job.s3_delete_object_tagging(S3DeleteObjectTaggingOperation::builder().build())
    } else if args.legal_hold.is_some() || args.retention.is_some() {
        lock_operation(args, job)?
    } else if let Some(to) = &args.copy_to {
        let (bucket, prefix) = to.split_once('/').unwrap_or((to, ""));
        job.s3_put_object_copy(
            S3CopyObjectOperation::builder()
                .target_resource(format!("arn:aws:s3:::{bucket}"))
                .set_target_key_prefix(Some(prefix.to_owned()).filter(|p| !p.is_empty()))
                .build(),
        )
    } else if let Some(acl) = &args.acl {
        job.s3_put_object_acl(
            S3SetObjectAclOperation::builder()
                .access_control_policy(
                    S3AccessControlPolicy::builder()
                        .canned_access_control_list(S3CannedAccessControlList::from(acl.as_str()))
                        .build(),
                )
                .build(),
        )
    } else if let Some(algorithm) = &args.checksum {
        job.s3_compute_object_checksum(
            S3ComputeObjectChecksumOperation::builder()
                .checksum_algorithm(algorithm.to_ascii_uppercase().as_str().into())
                .checksum_type(
                    args.checksum_type
                        .as_deref()
                        .unwrap_or("FULL_OBJECT")
                        .into(),
                )
                .build(),
        )
    } else if let Some(arn) = &args.encrypt_kms {
        let kms = S3UpdateObjectEncryptionSsekms::builder()
            .kms_key_arn(arn)
            .bucket_key_enabled(args.bucket_key)
            .build()
            .map_err(usage)?;
        job.s3_update_object_encryption(
            S3UpdateObjectEncryptionOperation::builder()
                .object_encryption(ObjectEncryption::builder().ssekms(kms).build())
                .build(),
        )
    } else {
        job.s3_replicate_object(S3ReplicateObjectOperation::builder().build())
    };
    Ok(job.build())
}

/// A legal hold or retention operation.
fn lock_operation(
    args: &CreateArgs,
    job: aws_sdk_s3control::types::builders::JobOperationBuilder,
) -> Result<aws_sdk_s3control::types::builders::JobOperationBuilder, Error> {
    let usage = |e: aws_sdk_s3control::error::BuildError| Error::usage(e.to_string());
    if let Some(hold) = &args.legal_hold {
        let status = if hold == "on" {
            S3ObjectLockLegalHoldStatus::On
        } else {
            S3ObjectLockLegalHoldStatus::Off
        };
        return Ok(job.s3_put_object_legal_hold(
            S3SetObjectLegalHoldOperation::builder()
                .legal_hold(
                    S3ObjectLockLegalHold::builder()
                        .status(status)
                        .build()
                        .map_err(usage)?,
                )
                .build(),
        ));
    }
    let mode = args.retention.as_deref().unwrap_or("off");
    let retention = match (mode, &args.retain_until) {
        ("off", None) => S3Retention::builder().build(),
        ("off", Some(_)) => {
            return Err(Error::usage(
                "--retention off takes no --retain-until".to_owned(),
            ));
        }
        (_, None) => {
            return Err(Error::usage(format!(
                "--retention {mode} needs --retain-until YYYY-MM-DD"
            )));
        }
        (mode, Some(day)) => S3Retention::builder()
            .mode(S3ObjectLockRetentionMode::from(mode))
            .retain_until_date(DateTime::from_millis(parse_day(day).map_err(Error::usage)?))
            .build(),
    };
    Ok(job.s3_put_object_retention(
        S3SetObjectRetentionOperation::builder()
            .retention(retention)
            .bypass_governance_retention(args.bypass_governance)
            .build(),
    ))
}

async fn ls(control: &Control, statuses: Vec<String>) -> Result<(), Error> {
    let mut jobs: Vec<JobListDescriptor> = Vec::new();
    let mut token = None;
    loop {
        let page = control
            .client
            .list_jobs()
            .account_id(&control.account)
            .set_job_statuses(
                Some(
                    statuses
                        .iter()
                        .map(|s| JobStatus::from(s.as_str()))
                        .collect(),
                )
                .filter(|s: &Vec<_>| !s.is_empty()),
            )
            .set_next_token(token)
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't list the jobs of {}", control.name), &e))?;
        jobs.extend(page.jobs.unwrap_or_default());
        token = page.next_token;
        if token.is_none() {
            break;
        }
    }
    let mut table = ui::Table::new(&["ID", "STATUS", "OPERATION", "PRIORITY", "TASKS", "CREATED"]);
    let mut records = Vec::new();
    for job in &jobs {
        let id = job.job_id.clone().unwrap_or_default();
        let status = job
            .status
            .as_ref()
            .map(|s| s.as_str().to_owned())
            .unwrap_or_default();
        let operation = job
            .operation
            .as_ref()
            .map(|o| o.as_str().to_owned())
            .unwrap_or_default();
        let (total, succeeded, failed) = job.progress_summary.as_ref().map_or((0, 0, 0), |p| {
            (
                p.total_number_of_tasks.unwrap_or(0),
                p.number_of_tasks_succeeded.unwrap_or(0),
                p.number_of_tasks_failed.unwrap_or(0),
            )
        });
        let created = job
            .creation_time
            .map(|t| date(from_ms(t.to_millis().unwrap_or(0))));
        table.row(vec![
            id.clone(),
            status.clone(),
            operation.clone(),
            job.priority.to_string(),
            tasks(total, succeeded, failed),
            created.clone().unwrap_or_default(),
        ]);
        records.push(json!({
            "type": "batchJob", "alias": control.name, "id": id, "status": status,
            "operation": operation, "priority": job.priority, "description": job.description,
            "tasks": total, "succeeded": succeeded, "failed": failed, "created": created,
        }));
    }
    ui::rows(
        &table,
        &records,
        &format!(
            "{} has no batch jobs. Make one: teifs batch create ALIAS/BUCKET/MANIFEST --role ROLE …",
            control.name
        ),
    );
    Ok(())
}

/// Tasks done of all: `3/10 (1 failed)`.
fn tasks(total: i64, succeeded: i64, failed: i64) -> String {
    let done = succeeded + failed;
    if failed > 0 {
        format!("{done}/{total} ({failed} failed)")
    } else {
        format!("{done}/{total}")
    }
}

async fn describe(control: &Control, id: &str) -> Result<(), Error> {
    let job = control
        .client
        .describe_job()
        .account_id(&control.account)
        .job_id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read job {id} of {}", control.name), &e))?
        .job
        .unwrap_or_else(|| aws_sdk_s3control::types::JobDescriptor::builder().build());
    let status = job
        .status
        .as_ref()
        .map(|s| s.as_str().to_owned())
        .unwrap_or_default();
    let operation = job
        .operation
        .as_ref()
        .map(operation_name)
        .unwrap_or_default();
    let (total, succeeded, failed) = job.progress_summary.as_ref().map_or((0, 0, 0), |p| {
        (
            p.total_number_of_tasks.unwrap_or(0),
            p.number_of_tasks_succeeded.unwrap_or(0),
            p.number_of_tasks_failed.unwrap_or(0),
        )
    });
    let failures: Vec<String> = job
        .failure_reasons
        .iter()
        .flatten()
        .map(|f| {
            format!(
                "{}: {}",
                f.failure_code.as_deref().unwrap_or_default(),
                f.failure_reason.as_deref().unwrap_or_default()
            )
        })
        .collect();
    let report = job
        .report
        .as_ref()
        .filter(|r| r.enabled)
        .map(|r| report_at(r, id));
    let created = job
        .creation_time
        .map(|t| date(from_ms(t.to_millis().unwrap_or(0))));
    let mut fields = vec![
        ("Job", id.to_owned()),
        ("Status", status.clone()),
        ("Operation", operation.clone()),
        ("Priority", job.priority.to_string()),
        ("Tasks", tasks(total, succeeded, failed)),
        ("Role", job.role_arn.clone().unwrap_or_default()),
        ("Created", created.clone().unwrap_or_default()),
    ];
    if let Some(description) = job.description.clone().filter(|d| !d.is_empty()) {
        fields.push(("Description", description));
    }
    if let Some((bucket, key)) = &report {
        fields.push(("Report", format!("{}/{bucket}/{key}", control.name)));
    }
    if let Some(cause) = job.suspended_cause.clone() {
        fields.push(("Waiting", cause));
    }
    if !failures.is_empty() {
        fields.push(("Failed because", failures.join("; ")));
    }
    ui::details(&fields, || {
        json!({
            "type": "batchJob", "alias": control.name, "id": id, "status": status,
            "operation": operation, "priority": job.priority, "tasks": total,
            "succeeded": succeeded, "failed": failed, "role": job.role_arn,
            "created": created, "description": job.description,
            "report": report.as_ref().map(|(b, k)| format!("{}/{b}/{k}", control.name)),
            "failures": failures,
        })
    });
    Ok(())
}

/// The name of the operation a job runs.
fn operation_name(operation: &JobOperation) -> String {
    let names = [
        (
            operation.s3_put_object_tagging.is_some(),
            "S3PutObjectTagging",
        ),
        (
            operation.s3_delete_object_tagging.is_some(),
            "S3DeleteObjectTagging",
        ),
        (
            operation.s3_put_object_legal_hold.is_some(),
            "S3PutObjectLegalHold",
        ),
        (
            operation.s3_put_object_retention.is_some(),
            "S3PutObjectRetention",
        ),
        (operation.s3_put_object_copy.is_some(), "S3PutObjectCopy"),
        (operation.s3_put_object_acl.is_some(), "S3PutObjectAcl"),
        (
            operation.s3_compute_object_checksum.is_some(),
            "S3ComputeObjectChecksum",
        ),
        (
            operation.s3_update_object_encryption.is_some(),
            "S3UpdateObjectEncryption",
        ),
        (operation.s3_replicate_object.is_some(), "S3ReplicateObject"),
        (operation.lambda_invoke.is_some(), "LambdaInvoke"),
        (
            operation.s3_initiate_restore_object.is_some(),
            "S3InitiateRestoreObject",
        ),
    ];
    names
        .iter()
        .find(|(set, _)| *set)
        .map(|(_, name)| (*name).to_owned())
        .unwrap_or_default()
}

/// Where a job's report's `manifest.json` is: its bucket and key.
fn report_at(report: &JobReport, id: &str) -> (String, String) {
    let bucket = report
        .bucket
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches("arn:aws:s3:::")
        .to_owned();
    let key = match report.prefix.as_deref().filter(|p| !p.is_empty()) {
        Some(prefix) => format!("{}/job-{id}/manifest.json", prefix.trim_end_matches('/')),
        None => format!("job-{id}/manifest.json"),
    };
    (bucket, key)
}

async fn status(control: &Control, id: &str, to: RequestedJobStatus) -> Result<(), Error> {
    let done = control
        .client
        .update_job_status()
        .account_id(&control.account)
        .job_id(id)
        .requested_job_status(to.clone())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't change job {id} of {}", control.name), &e))?;
    let status = done
        .status
        .map(|s| s.as_str().to_owned())
        .unwrap_or_default();
    ui::done(
        format!("{}: job {id} is {status}", control.name),
        || json!({"type": "batchJob", "alias": control.name, "id": id, "status": status}),
    );
    Ok(())
}

async fn reprioritize(control: &Control, id: &str, priority: i32) -> Result<(), Error> {
    control
        .client
        .update_job_priority()
        .account_id(&control.account)
        .job_id(id)
        .priority(priority)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't change job {id} of {}", control.name), &e))?;
    ui::done(
        format!("{}: job {id} has priority {priority}", control.name),
        || json!({"type": "batchJob", "alias": control.name, "id": id, "priority": priority}),
    );
    Ok(())
}

async fn report(control: &Control, id: &str) -> Result<(), Error> {
    let job = control
        .client
        .describe_job()
        .account_id(&control.account)
        .job_id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read job {id} of {}", control.name), &e))?
        .job;
    let Some((bucket, key)) = job
        .as_ref()
        .and_then(|job| job.report.as_ref())
        .filter(|r| r.enabled)
        .map(|r| report_at(r, id))
    else {
        return Err(Error::usage(format!(
            "job {id} writes no completion report"
        )));
    };
    let s3 = control.alias.client();
    let text = |key: String| {
        let (s3, bucket) = (&s3, &bucket);
        async move {
            let got = s3
                .get_object()
                .bucket(bucket)
                .key(&key)
                .send()
                .await
                .map_err(|e| {
                    Error::s3(
                        format!("can't read the report {}/{bucket}/{key}", control.name),
                        &e,
                    )
                    .with_hint("a job reports once it has ended")
                })?;
            let bytes = got
                .body
                .collect()
                .await
                .map_err(|e| Error::new(Kind::General, format!("can't read the report: {e}")))?
                .into_bytes();
            Ok::<_, Error>(String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    let manifest: Value = serde_json::from_str(&text(key).await?).map_err(|e| {
        Error::new(
            Kind::General,
            format!("the report's manifest.json isn't JSON: {e}"),
        )
    })?;
    for file in manifest["Results"].as_array().into_iter().flatten() {
        let Some(key) = file["Key"].as_str() else {
            continue;
        };
        let status = file["TaskExecutionStatus"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        for line in text(key.to_owned()).await?.lines() {
            ui::item(
                || line.to_owned(),
                || json!({"type": "batchResult", "id": id, "status": status, "line": line}),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_named_or_given_by_arn() {
        assert_eq!(
            role_arn("batch", "123456789012"),
            "arn:aws:iam::123456789012:role/batch"
        );
        assert_eq!(
            role_arn("arn:aws:iam::1:role/x", "123456789012"),
            "arn:aws:iam::1:role/x"
        );
    }

    #[test]
    fn reports_are_found_under_their_prefix() {
        let report = JobReport::builder()
            .enabled(true)
            .bucket("arn:aws:s3:::reports")
            .prefix("batch/")
            .build();
        assert_eq!(
            report_at(&report, "j1"),
            (
                "reports".to_owned(),
                "batch/job-j1/manifest.json".to_owned()
            )
        );
        let bare = JobReport::builder()
            .enabled(true)
            .bucket("arn:aws:s3:::r")
            .build();
        assert_eq!(report_at(&bare, "j1").1, "job-j1/manifest.json");
        assert_eq!(tasks(10, 2, 1), "3/10 (1 failed)");
        assert_eq!(tasks(10, 10, 0), "10/10");
    }
}
