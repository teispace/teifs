//! Server access logging: `teifs logging set|info|rm` for where a bucket's access log
//! goes (S3's `PutBucketLogging`). Like the S3 console, `set` also lets the logging
//! service into the target, with a statement in the target's bucket policy.

use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,
    types::{
        BucketLoggingStatus, LoggingEnabled, PartitionDateSource, PartitionedPrefix, SimplePrefix,
        TargetObjectKeyFormat,
    },
};
use serde_json::{Value, json};

use super::{
    Error, LoggingAction, LoggingFormat,
    alias::Aliases,
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
        let_the_service_in(&client, bucket, (target_bucket, prefix), &account).await?;
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

/// Adds a statement letting the logging service write `source`'s log under `prefix` in
/// `target` to the target's bucket policy, unless it has one of that name already.
async fn let_the_service_in(
    client: &Client,
    source: &str,
    (target, prefix): (&str, &str),
    account: &str,
) -> Result<(), Error> {
    let current = match client.get_bucket_policy().bucket(target).send().await {
        Ok(out) => out.policy().map(str::to_owned),
        Err(e)
            if e.as_service_error().and_then(ProvideErrorMetadata::code)
                == Some("NoSuchBucketPolicy") =>
        {
            None
        }
        Err(e) => {
            return Err(Error::s3(
                format!("can't read the bucket policy of {target}"),
                &e,
            ));
        }
    };
    let Some(policy) = with_statement(current.as_deref(), source, (target, prefix), account)?
    else {
        return Ok(());
    };
    client
        .put_bucket_policy()
        .bucket(target)
        .policy(policy)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't let the logging service into {target}"), &e))?;
    Ok(())
}

/// The policy `current` with the logging service's statement for `source` added; `None`
/// when it has one already.
fn with_statement(
    current: Option<&str>,
    source: &str,
    (target, prefix): (&str, &str),
    account: &str,
) -> Result<Option<String>, Error> {
    let sid = format!("TeiFSAccessLogs-{source}");
    let statement = json!({
        "Sid": sid,
        "Effect": "Allow",
        "Principal": {"Service": SERVICE},
        "Action": "s3:PutObject",
        "Resource": format!("arn:aws:s3:::{target}/{prefix}*"),
        "Condition": {
            "ArnLike": {"aws:SourceArn": format!("arn:aws:s3:::{source}")},
            "StringEquals": {"aws:SourceAccount": account},
        },
    });
    let mut policy: Value = match current {
        None => json!({"Version": "2012-10-17", "Statement": []}),
        Some(text) => serde_json::from_str(text)
            .map_err(|e| Error::usage(format!("the bucket policy of {target} isn't JSON: {e}")))?,
    };
    let statements = match policy.get_mut("Statement") {
        Some(Value::Array(statements)) => statements,
        Some(one) => {
            let one = one.take();
            policy["Statement"] = Value::Array(vec![one]);
            policy["Statement"]
                .as_array_mut()
                .expect("just made an array")
        }
        None => {
            policy["Statement"] = json!([]);
            policy["Statement"]
                .as_array_mut()
                .expect("just made an array")
        }
    };
    if statements.iter().any(|s| s.get("Sid") == Some(&json!(sid))) {
        return Ok(None);
    }
    statements.push(statement);
    Ok(Some(policy.to_string()))
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    #[test]
    fn the_services_statement_is_added_once() {
        let added = with_statement(None, "app", ("logs", "app/"), "123456789012")
            .unwrap()
            .unwrap();
        let policy: Value = serde_json::from_str(&added).unwrap();
        let statement = &policy["Statement"][0];
        assert_eq!(statement["Principal"]["Service"], SERVICE);
        assert_eq!(statement["Resource"], "arn:aws:s3:::logs/app/*");
        assert_eq!(
            statement["Condition"]["ArnLike"]["aws:SourceArn"],
            "arn:aws:s3:::app"
        );
        assert_eq!(
            with_statement(Some(&added), "app", ("logs", "app/"), "123456789012").unwrap(),
            None
        );
        // Another source's goes next to it; a lone statement becomes a list.
        let lone = r#"{"Version":"2012-10-17","Statement":{"Sid":"x","Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::logs"}}"#;
        let both = with_statement(Some(lone), "web", ("logs", ""), "123456789012")
            .unwrap()
            .unwrap();
        let both: Value = serde_json::from_str(&both).unwrap();
        assert_eq!(both["Statement"][0]["Sid"], "x");
        assert_eq!(both["Statement"][1]["Sid"], "TeiFSAccessLogs-web");
        assert_eq!(both["Statement"][1]["Resource"], "arn:aws:s3:::logs/*");
        assert!(with_statement(Some("{"), "a", ("b", ""), "1").is_err());
    }
}
