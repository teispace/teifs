//! Storage class analysis: `teifs analytics add|ls|info|rm` for a bucket's analytics
//! configurations (S3's `PutBucketAnalyticsConfiguration`). With `--export`, each day's
//! figures are added to a CSV in the destination, and, like the S3 console, `add` lets
//! S3 (`s3.amazonaws.com`) in with a statement in the destination's bucket policy.

use std::collections::BTreeMap;

use aws_sdk_s3::types::{
    AnalyticsAndOperator, AnalyticsConfiguration, AnalyticsExportDestination, AnalyticsFilter,
    AnalyticsS3BucketDestination, AnalyticsS3ExportFileFormat, StorageClassAnalysis,
    StorageClassAnalysisDataExport, StorageClassAnalysisSchemaVersion, Tag,
};
use clap::Subcommand;
use serde_json::{Value, json};

use super::{
    Error,
    alias::Aliases,
    metrics::tag,
    pages,
    service_policy::{self, Grant},
    target::{Remote, Target},
};
use crate::ui;

/// The service principal that writes exports.
const SERVICE: &str = "s3.amazonaws.com";
/// The canned ACL it writes with.
const ACL: &str = "bucket-owner-full-control";

#[derive(Subcommand)]
pub enum AnalyticsAction {
    /// Analyse `ALIAS/BUCKET`'s objects (only those matching `--prefix` and `--tag`,
    /// when given) under `ID`, exporting each day's figures with `--export`. Replaces
    /// the bucket's configuration of the same id.
    Add {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id: the `ConfigId` of its rows.
        id: String,
        /// Only objects whose keys start with this.
        #[arg(long)]
        prefix: Option<String>,
        /// Only objects with this tag, as `KEY=VALUE`; repeat for several.
        #[arg(long = "tag", value_parser = tag)]
        tags: Vec<(String, String)>,
        /// `ALIAS/DESTINATION[/PREFIX]`: where the daily CSV goes, as
        /// `PREFIX/BUCKET/ID.csv`.
        #[arg(long)]
        export: Option<String>,
        /// Leave the destination's bucket policy alone (it lets S3 in already).
        #[arg(long)]
        no_policy: bool,
    },
    /// List a bucket's analytics configurations.
    Ls {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Show one of a bucket's analytics configurations.
    Info {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
    },
    /// Remove one of a bucket's analytics configurations.
    Rm {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
    },
}

/// `teifs analytics …`.
pub(super) async fn analytics(action: AnalyticsAction, aliases: &Aliases) -> Result<(), Error> {
    let remote = |target: &str| Target::parse(target, aliases)?.remote("analytics");
    match action {
        AnalyticsAction::Add {
            bucket,
            id,
            prefix,
            tags,
            export,
            no_policy,
        } => {
            let bucket = remote(&bucket)?;
            let export = export.as_deref().map(remote).transpose()?;
            if export
                .as_ref()
                .is_some_and(|export| export.alias_name != bucket.alias_name)
            {
                return Err(Error::usage(
                    "a bucket's analytics go to a bucket on the same server: give the \
                     destination with the same alias",
                ));
            }
            add(&bucket, &id, (prefix, tags), export.as_ref(), !no_policy).await
        }
        AnalyticsAction::Ls { bucket } => ls(&remote(&bucket)?).await,
        AnalyticsAction::Info { bucket, id } => info(&remote(&bucket)?, &id).await,
        AnalyticsAction::Rm { bucket, id } => rm(&remote(&bucket)?, &id).await,
    }
}

async fn add(
    source: &Remote,
    id: &str,
    (prefix, tags): (Option<String>, Vec<(String, String)>),
    export: Option<&Remote>,
    policy: bool,
) -> Result<(), Error> {
    let bucket = source.bucket()?;
    let name = source.display("");
    let client = source.alias.client();
    let destination = export
        .map(|export| Ok::<_, Error>((export.bucket()?, export.key.trim_end_matches('/'))))
        .transpose()?;
    let config = configuration(id, (prefix, tags), destination)?;
    if policy && let Some((target, prefix)) = destination {
        let account = crate::sts::account(&source.alias).await?;
        let grant = Grant {
            sid: format!("TeiFSAnalytics-{bucket}"),
            service: SERVICE,
            source: bucket,
            target: (target, prefix),
            account: &account,
            acl: Some(ACL),
        };
        service_policy::let_in(&client, &grant).await?;
    }
    client
        .put_bucket_analytics_configuration()
        .bucket(bucket)
        .id(id)
        .analytics_configuration(config.clone())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't set the analytics {id} of {name}"), &e))?;
    ui::done(
        format!("Analytics {id} of {name}: {}", summary(&config)),
        || record(&name, &config),
    );
    Ok(())
}

/// The configuration `teifs analytics add` sets: S3's filter is a prefix, a tag, or an
/// `And` of several.
fn configuration(
    id: &str,
    (prefix, tags): (Option<String>, Vec<(String, String)>),
    destination: Option<(&str, &str)>,
) -> Result<AnalyticsConfiguration, Error> {
    let usage = |e: aws_sdk_s3::error::BuildError| Error::usage(e.to_string());
    let mut tags = tags
        .into_iter()
        .map(|(key, value)| Tag::builder().key(key).value(value).build())
        .collect::<Result<Vec<_>, _>>()
        .map_err(usage)?;
    let filter = match (prefix, tags.len()) {
        (None, 0) => None,
        (Some(prefix), 0) => Some(AnalyticsFilter::Prefix(prefix)),
        (None, 1) => tags.pop().map(AnalyticsFilter::Tag),
        (prefix, _) => Some(AnalyticsFilter::And(
            AnalyticsAndOperator::builder()
                .set_prefix(prefix)
                .set_tags(Some(tags))
                .build(),
        )),
    };
    let export = destination
        .map(|(target, prefix)| {
            let mut s3 = AnalyticsS3BucketDestination::builder()
                .format(AnalyticsS3ExportFileFormat::Csv)
                .bucket(format!("arn:aws:s3:::{target}"));
            if !prefix.is_empty() {
                s3 = s3.prefix(prefix);
            }
            StorageClassAnalysisDataExport::builder()
                .output_schema_version(StorageClassAnalysisSchemaVersion::V1)
                .destination(
                    AnalyticsExportDestination::builder()
                        .s3_bucket_destination(s3.build().map_err(usage)?)
                        .build(),
                )
                .build()
                .map_err(usage)
        })
        .transpose()?;
    AnalyticsConfiguration::builder()
        .id(id)
        .set_filter(filter)
        .storage_class_analysis(
            StorageClassAnalysis::builder()
                .set_data_export(export)
                .build(),
        )
        .build()
        .map_err(usage)
}

/// The filter's prefix and tags.
fn filter(config: &AnalyticsConfiguration) -> (Option<&str>, BTreeMap<&str, &str>) {
    fn pairs(tags: &[Tag]) -> BTreeMap<&str, &str> {
        tags.iter().map(|t| (t.key(), t.value())).collect()
    }
    match config.filter() {
        Some(AnalyticsFilter::Prefix(prefix)) => (Some(prefix.as_str()), BTreeMap::new()),
        Some(AnalyticsFilter::Tag(tag)) => (None, pairs(std::slice::from_ref(tag))),
        Some(AnalyticsFilter::And(and)) => (and.prefix(), pairs(and.tags())),
        _ => (None, BTreeMap::new()),
    }
}

/// The objects analysed, in words: `every object`, or their prefix and tags.
fn objects(config: &AnalyticsConfiguration) -> String {
    let (prefix, tags) = filter(config);
    let mut parts: Vec<String> = prefix.map(|p| format!("{p}*")).into_iter().collect();
    parts.extend(tags.iter().map(|(key, value)| format!("{key}={value}")));
    if parts.is_empty() {
        "every object".to_owned()
    } else {
        format!("objects {}", parts.join(" and "))
    }
}

/// Where the daily figures go: `BUCKET[/PREFIX]`, or nothing.
fn destination(config: &AnalyticsConfiguration) -> Option<String> {
    let s3 = config
        .storage_class_analysis()?
        .data_export()?
        .destination()?
        .s3_bucket_destination()?;
    let bucket = s3.bucket().trim_start_matches("arn:aws:s3:::");
    Some(match s3.prefix() {
        Some(prefix) if !prefix.is_empty() => format!("{bucket}/{prefix}"),
        _ => bucket.to_owned(),
    })
}

/// What the configuration does, in words.
fn summary(config: &AnalyticsConfiguration) -> String {
    match destination(config) {
        Some(to) => format!("{}, exported daily to {to}", objects(config)),
        None => objects(config),
    }
}

/// Every configuration of a bucket.
async fn all(remote: &Remote) -> Result<Vec<AnalyticsConfiguration>, Error> {
    let bucket = remote.bucket()?;
    let client = &remote.alias.client();
    pages::every(|token| async move {
        let out = client
            .list_bucket_analytics_configurations()
            .bucket(bucket)
            .set_continuation_token(token)
            .send()
            .await
            .map_err(|e| {
                Error::s3(
                    format!("can't list the analytics of {}", remote.display("")),
                    &e,
                )
            })?;
        Ok(pages::Page {
            items: out.analytics_configuration_list().to_vec(),
            truncated: out.is_truncated().unwrap_or(false),
            next: out.next_continuation_token().map(str::to_owned),
        })
    })
    .await
}

async fn ls(remote: &Remote) -> Result<(), Error> {
    let name = remote.display("");
    let configs = all(remote).await?;
    let mut table = ui::Table::new(&["ID", "OBJECTS", "EXPORT"]);
    for config in &configs {
        table.row(vec![
            config.id().to_owned(),
            objects(config),
            destination(config).unwrap_or_default(),
        ]);
    }
    let records: Vec<Value> = configs.iter().map(|c| record(&name, c)).collect();
    ui::rows(
        &table,
        &records,
        &format!("{name} has no analytics configurations. Add one: teifs analytics add {name} ID"),
    );
    Ok(())
}

async fn info(remote: &Remote, id: &str) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let out = remote
        .alias
        .client()
        .get_bucket_analytics_configuration()
        .bucket(bucket)
        .id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read the analytics {id} of {name}"), &e))?;
    let Some(config) = out.analytics_configuration() else {
        return Err(Error::usage(format!("{name} has no analytics {id}")));
    };
    let fields = [
        ("Bucket", name.clone()),
        ("Analytics", config.id().to_owned()),
        ("Objects", objects(config)),
        (
            "Export",
            destination(config).map_or_else(String::new, |to| format!("{to}/{bucket}/{id}.csv")),
        ),
    ];
    ui::details(&fields, || record(&name, config));
    Ok(())
}

async fn rm(remote: &Remote, id: &str) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    remote
        .alias
        .client()
        .delete_bucket_analytics_configuration()
        .bucket(bucket)
        .id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't remove the analytics {id} of {name}"), &e))?;
    ui::done(
        format!("Analytics {id} of {name}: removed"),
        || json!({"type": "analytics", "bucket": name, "id": id, "removed": true}),
    );
    Ok(())
}

fn record(bucket: &str, config: &AnalyticsConfiguration) -> Value {
    let (prefix, tags) = filter(config);
    json!({
        "type": "analytics",
        "bucket": bucket,
        "id": config.id(),
        "prefix": prefix,
        "tags": tags,
        "export": destination(config),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    fn tags(given: &[(&str, &str)]) -> Vec<(String, String)> {
        given
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn options_make_s3s_configuration() {
        let plain = configuration("all", (None, Vec::new()), None).unwrap();
        assert!(plain.filter().is_none());
        assert!(
            plain
                .storage_class_analysis()
                .unwrap()
                .data_export()
                .is_none()
        );
        assert_eq!(summary(&plain), "every object");
        assert_eq!(destination(&plain), None);

        let exported = configuration(
            "docs",
            (Some("docs/".to_owned()), tags(&[("team", "red")])),
            Some(("reports", "an")),
        )
        .unwrap();
        let Some(AnalyticsFilter::And(and)) = exported.filter() else {
            panic!("{exported:?}")
        };
        assert_eq!((and.prefix(), and.tags().len()), (Some("docs/"), 1));
        let export = exported
            .storage_class_analysis()
            .unwrap()
            .data_export()
            .unwrap();
        assert_eq!(
            export.output_schema_version(),
            &StorageClassAnalysisSchemaVersion::V1
        );
        let s3 = export
            .destination()
            .unwrap()
            .s3_bucket_destination()
            .unwrap();
        assert_eq!(
            (s3.bucket(), s3.prefix(), s3.format()),
            (
                "arn:aws:s3:::reports",
                Some("an"),
                &AnalyticsS3ExportFileFormat::Csv
            )
        );
        assert_eq!(
            summary(&exported),
            "objects docs/* and team=red, exported daily to reports/an"
        );
        let record = record("a/b", &exported);
        assert_eq!(
            (
                &record["prefix"],
                &record["tags"]["team"],
                &record["export"]
            ),
            (&"docs/".into(), &"red".into(), &"reports/an".into())
        );

        let prefix =
            configuration("p", (Some("x/".to_owned()), Vec::new()), Some(("r", ""))).unwrap();
        assert_eq!(
            prefix.filter(),
            Some(&AnalyticsFilter::Prefix("x/".to_owned()))
        );
        assert_eq!(destination(&prefix).as_deref(), Some("r"));
        let to = prefix
            .storage_class_analysis()
            .unwrap()
            .data_export()
            .unwrap();
        assert_eq!(
            to.destination()
                .unwrap()
                .s3_bucket_destination()
                .unwrap()
                .prefix(),
            None
        );
        let tag = configuration("t", (None, tags(&[("a", "1")])), None).unwrap();
        assert!(matches!(tag.filter(), Some(AnalyticsFilter::Tag(t)) if t.key() == "a"));
        let two = configuration("t", (None, tags(&[("a", "1"), ("b", "2")])), None).unwrap();
        assert!(matches!(two.filter(), Some(AnalyticsFilter::And(and)) if and.prefix().is_none()));
    }
}
