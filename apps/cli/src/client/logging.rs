//! Server access logging: `teifs logging set|info|rm` for where a bucket's access log
//! goes (S3's `PutBucketLogging`). Like the S3 console, `set` also lets the logging
//! service into the target, with a statement in the target's bucket policy.

use aws_sdk_s3::types::{
    BucketLoggingStatus, LoggingEnabled, PartitionDateSource, PartitionedPrefix, SimplePrefix,
    TargetObjectKeyFormat,
};
use serde_json::{Value, json};

use super::{
    Error, LoggingAction, LoggingFormat,
    alias::Aliases,
    service_policy::{self, Grant},
    target::{Remote, Target},
};
use crate::ui;

/// The service principal that delivers access logs.
const SERVICE: &str = "logging.s3.amazonaws.com";

/// `teifs logging …`.
pub(super) async fn logging(action: LoggingAction, aliases: &Aliases) -> Result<(), Error> {
    match action {
        LoggingAction::Set {
            source,
            target,
            format,
            no_policy,
        } => {
            let source = Target::parse(&source, aliases)?.remote("logging")?;
            let target = Target::parse(&target, aliases)?.remote("logging")?;
            if target.alias_name != source.alias_name {
                return Err(Error::usage(
                    "a bucket's access log goes to a bucket on the same server: give the \
                     target with the same alias",
                ));
            }
            set(&source, &target, format, !no_policy).await
        }
        LoggingAction::Info { bucket } => {
            let remote = Target::parse(&bucket, aliases)?.remote("logging")?;
            info(&remote).await
        }
        LoggingAction::Rm { bucket } => {
            let remote = Target::parse(&bucket, aliases)?.remote("logging")?;
            rm(&remote).await
        }
    }
}

async fn set(
    source: &Remote,
    target: &Remote,
    format: LoggingFormat,
    policy: bool,
) -> Result<(), Error> {
    let bucket = source.bucket()?;
    let target_bucket = target.bucket()?;
    let prefix = target.key.as_str();
    let name = source.display("");
    let client = source.alias.client();
    if policy {
        let account = crate::sts::account(&source.alias).await?;
        let grant = Grant {
            sid: format!("TeiFSAccessLogs-{bucket}"),
            service: SERVICE,
            source: bucket,
            target: (target_bucket, prefix),
            account: &account,
            acl: None,
        };
        service_policy::let_in(&client, &grant).await?;
    }
    let key_format = match format {
        LoggingFormat::Simple => TargetObjectKeyFormat::builder()
            .simple_prefix(SimplePrefix::builder().build())
            .build(),
        LoggingFormat::EventTime | LoggingFormat::DeliveryTime => {
            let source = if format == LoggingFormat::EventTime {
                PartitionDateSource::EventTime
            } else {
                PartitionDateSource::DeliveryTime
            };
            TargetObjectKeyFormat::builder()
                .partitioned_prefix(
                    PartitionedPrefix::builder()
                        .partition_date_source(source)
                        .build(),
                )
                .build()
        }
    };
    let enabled = LoggingEnabled::builder()
        .target_bucket(target_bucket)
        .target_prefix(prefix)
        .target_object_key_format(key_format)
        .build()
        .map_err(|e| Error::usage(e.to_string()))?;
    client
        .put_bucket_logging()
        .bucket(bucket)
        .bucket_logging_status(
            BucketLoggingStatus::builder()
                .logging_enabled(enabled.clone())
                .build(),
        )
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't set the access log of {name}"), &e))?;
    let to = target.display(prefix);
    ui::done(format!("Access log of {name}: to {to}"), || {
        record(&name, Some(&enabled))
    });
    Ok(())
}

async fn info(remote: &Remote) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let out = remote
        .alias
        .client()
        .get_bucket_logging()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read the access log of {name}"), &e))?;
    let enabled = out.logging_enabled();
    let mut fields = vec![("Bucket", name.clone())];
    match enabled {
        None => fields.push(("Access log", "off".to_owned())),
        Some(enabled) => {
            fields.push((
                "Access log",
                format!(
                    "to {}/{}{}",
                    remote.alias_name,
                    enabled.target_bucket(),
                    if enabled.target_prefix().is_empty() {
                        String::new()
                    } else {
                        format!("/{}", enabled.target_prefix())
                    }
                ),
            ));
            fields.push(("Key format", format_text(enabled).to_owned()));
        }
    }
    ui::details(&fields, || record(&name, enabled));
    Ok(())
}

async fn rm(remote: &Remote) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    remote
        .alias
        .client()
        .put_bucket_logging()
        .bucket(bucket)
        .bucket_logging_status(BucketLoggingStatus::builder().build())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't turn off the access log of {name}"), &e))?;
    ui::done(format!("Access log of {name}: off"), || record(&name, None));
    Ok(())
}

/// How log objects are named, in words.
fn format_text(enabled: &LoggingEnabled) -> &'static str {
    match enabled
        .target_object_key_format()
        .and_then(TargetObjectKeyFormat::partitioned_prefix)
    {
        None => "simple",
        Some(partitioned) => match partitioned.partition_date_source() {
            Some(PartitionDateSource::DeliveryTime) => "partitioned by delivery time",
            _ => "partitioned by event time",
        },
    }
}

fn record(bucket: &str, enabled: Option<&LoggingEnabled>) -> Value {
    json!({
        "type": "logging",
        "bucket": bucket,
        "targetBucket": enabled.map(LoggingEnabled::target_bucket),
        "targetPrefix": enabled.map(LoggingEnabled::target_prefix),
        "keyFormat": enabled.map(format_text),
    })
}
