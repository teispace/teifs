//! Request metrics: `teifs metrics add|ls|info|rm` for a bucket's metrics
//! configurations (S3's `PutBucketMetricsConfiguration`). Each one counts the requests
//! it matches as `CloudWatch` does, served as Prometheus metrics labeled by bucket and
//! `filter_id` (its id).

use std::collections::BTreeMap;

use aws_sdk_s3::types::{MetricsAndOperator, MetricsConfiguration, MetricsFilter, Tag};
use clap::Subcommand;
use serde_json::{Value, json};

use super::{
    Error,
    alias::Aliases,
    pages,
    target::{Remote, Target},
};
use crate::ui;

#[derive(Subcommand)]
pub enum MetricsAction {
    /// Count `ALIAS/BUCKET`'s requests (only those on objects matching `--prefix` and
    /// `--tag`, when given) under `ID`. Replaces the bucket's configuration of the same
    /// id.
    Add {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id: the `filter_id` its metrics are labeled with.
        id: String,
        /// Only requests on objects whose keys start with this.
        #[arg(long)]
        prefix: Option<String>,
        /// Only requests on objects with this tag, as `KEY=VALUE`; repeat for several.
        #[arg(long = "tag", value_parser = tag)]
        tags: Vec<(String, String)>,
    },
    /// List a bucket's metrics configurations.
    Ls {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Show one of a bucket's metrics configurations.
    Info {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
    },
    /// Remove one of a bucket's metrics configurations.
    Rm {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
    },
}

/// A `KEY=VALUE` tag.
pub(super) fn tag(given: &str) -> Result<(String, String), String> {
    match given.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_owned(), value.to_owned())),
        _ => Err(format!("{given} isn't a tag: give KEY=VALUE")),
    }
}

/// `teifs metrics …`.
pub(super) async fn metrics(action: MetricsAction, aliases: &Aliases) -> Result<(), Error> {
    let remote = |target: &str| Target::parse(target, aliases)?.remote("metrics");
    match action {
        MetricsAction::Add {
            bucket,
            id,
            prefix,
            tags,
        } => add(&remote(&bucket)?, &id, prefix, tags).await,
        MetricsAction::Ls { bucket } => ls(&remote(&bucket)?).await,
        MetricsAction::Info { bucket, id } => info(&remote(&bucket)?, &id).await,
        MetricsAction::Rm { bucket, id } => rm(&remote(&bucket)?, &id).await,
    }
}

async fn add(
    remote: &Remote,
    id: &str,
    prefix: Option<String>,
    tags: Vec<(String, String)>,
) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let config = configuration(id, prefix, tags)?;
    remote
        .alias
        .client()
        .put_bucket_metrics_configuration()
        .bucket(bucket)
        .id(id)
        .metrics_configuration(config.clone())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't set the metrics {id} of {name}"), &e))?;
    ui::done(
        format!("Metrics {id} of {name}: {}", requests(&config)),
        || record(&name, &config),
    );
    Ok(())
}

/// The configuration `teifs metrics add` sets: S3's filter is a prefix, a tag, or an
/// `And` of several.
fn configuration(
    id: &str,
    prefix: Option<String>,
    tags: Vec<(String, String)>,
) -> Result<MetricsConfiguration, Error> {
    let usage = |e: aws_sdk_s3::error::BuildError| Error::usage(e.to_string());
    let mut tags = tags
        .into_iter()
        .map(|(key, value)| Tag::builder().key(key).value(value).build())
        .collect::<Result<Vec<_>, _>>()
        .map_err(usage)?;
    let filter = match (prefix, tags.len()) {
        (None, 0) => None,
        (Some(prefix), 0) => Some(MetricsFilter::Prefix(prefix)),
        (None, 1) => tags.pop().map(MetricsFilter::Tag),
        (prefix, _) => Some(MetricsFilter::And(
            MetricsAndOperator::builder()
                .set_prefix(prefix)
                .set_tags(Some(tags))
                .build(),
        )),
    };
    MetricsConfiguration::builder()
        .id(id)
        .set_filter(filter)
        .build()
        .map_err(usage)
}

/// The filter's prefix and tags.
fn filter(config: &MetricsConfiguration) -> (Option<&str>, BTreeMap<&str, &str>) {
    fn pairs(tags: &[Tag]) -> BTreeMap<&str, &str> {
        tags.iter().map(|t| (t.key(), t.value())).collect()
    }
    match config.filter() {
        Some(MetricsFilter::Prefix(prefix)) => (Some(prefix.as_str()), BTreeMap::new()),
        Some(MetricsFilter::Tag(tag)) => (None, pairs(std::slice::from_ref(tag))),
        Some(MetricsFilter::And(and)) => (and.prefix(), pairs(and.tags())),
        _ => (None, BTreeMap::new()),
    }
}

/// The requests counted, in words: `every request`, or the objects' prefix and tags.
fn requests(config: &MetricsConfiguration) -> String {
    let (prefix, tags) = filter(config);
    let mut parts: Vec<String> = prefix.map(|p| format!("{p}*")).into_iter().collect();
    parts.extend(tags.iter().map(|(key, value)| format!("{key}={value}")));
    if parts.is_empty() {
        "every request".to_owned()
    } else {
        format!("requests on {}", parts.join(" and "))
    }
}

/// Every configuration of a bucket.
async fn all(remote: &Remote) -> Result<Vec<MetricsConfiguration>, Error> {
    let bucket = remote.bucket()?;
    let client = &remote.alias.client();
    pages::every(|token| async move {
        let out = client
            .list_bucket_metrics_configurations()
            .bucket(bucket)
            .set_continuation_token(token)
            .send()
            .await
            .map_err(|e| {
                Error::s3(
                    format!("can't list the metrics of {}", remote.display("")),
                    &e,
                )
            })?;
        Ok(pages::Page {
            items: out.metrics_configuration_list().to_vec(),
            truncated: out.is_truncated().unwrap_or(false),
            next: out.next_continuation_token().map(str::to_owned),
        })
    })
    .await
}

async fn ls(remote: &Remote) -> Result<(), Error> {
    let name = remote.display("");
    let configs = all(remote).await?;
    let mut table = ui::Table::new(&["ID", "COUNTS"]);
    for config in &configs {
        table.row(vec![config.id().to_owned(), requests(config)]);
    }
    let records: Vec<Value> = configs.iter().map(|c| record(&name, c)).collect();
    ui::rows(
        &table,
        &records,
        &format!("{name} has no metrics configurations. Add one: teifs metrics add {name} ID"),
    );
    Ok(())
}

async fn info(remote: &Remote, id: &str) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let out = remote
        .alias
        .client()
        .get_bucket_metrics_configuration()
        .bucket(bucket)
        .id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read the metrics {id} of {name}"), &e))?;
    let Some(config) = out.metrics_configuration() else {
        return Err(Error::usage(format!("{name} has no metrics {id}")));
    };
    let fields = [
        ("Bucket", name.clone()),
        ("Metrics", config.id().to_owned()),
        ("Counts", requests(config)),
        (
            "Series",
            format!("teifs_request_metrics_*{{bucket=\"{bucket}\",filter_id=\"{id}\"}}"),
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
        .delete_bucket_metrics_configuration()
        .bucket(bucket)
        .id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't remove the metrics {id} of {name}"), &e))?;
    ui::done(
        format!("Metrics {id} of {name}: removed"),
        || json!({"type": "metrics", "bucket": name, "id": id, "removed": true}),
    );
    Ok(())
}

fn record(bucket: &str, config: &MetricsConfiguration) -> Value {
    let (prefix, tags) = filter(config);
    json!({
        "type": "metrics",
        "bucket": bucket,
        "id": config.id(),
        "prefix": prefix,
        "tags": tags,
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
    fn tags_are_key_equals_value() {
        assert_eq!(
            tag("team=red").unwrap(),
            ("team".to_owned(), "red".to_owned())
        );
        assert_eq!(
            tag("note=a=b").unwrap(),
            ("note".to_owned(), "a=b".to_owned())
        );
        assert_eq!(tag("empty=").unwrap(), ("empty".to_owned(), String::new()));
        for wrong in ["team", "=red"] {
            assert!(
                tag(wrong).unwrap_err().contains("give KEY=VALUE"),
                "{wrong}"
            );
        }
    }

    #[test]
    fn filters_are_s3s_prefix_tag_or_and() {
        let every = configuration("all", None, Vec::new()).unwrap();
        assert!(every.filter().is_none());
        assert_eq!(requests(&every), "every request");

        let prefix = configuration("docs", Some("docs/".to_owned()), Vec::new()).unwrap();
        assert_eq!(
            prefix.filter(),
            Some(&MetricsFilter::Prefix("docs/".to_owned()))
        );
        assert_eq!(requests(&prefix), "requests on docs/*");

        let one = configuration("red", None, tags(&[("team", "red")])).unwrap();
        assert!(matches!(one.filter(), Some(MetricsFilter::Tag(t)) if t.key() == "team"));
        assert_eq!(requests(&one), "requests on team=red");

        let both = configuration(
            "both",
            Some("docs/".to_owned()),
            tags(&[("team", "red"), ("env", "prod")]),
        )
        .unwrap();
        let Some(MetricsFilter::And(and)) = both.filter() else {
            panic!("{both:?}")
        };
        assert_eq!((and.prefix(), and.tags().len()), (Some("docs/"), 2));
        assert_eq!(
            requests(&both),
            "requests on docs/* and env=prod and team=red"
        );
        let record = record("a/b", &both);
        assert_eq!(record["tags"]["env"], "prod");
        assert_eq!(record["prefix"], "docs/");

        // Two tags without a prefix are an `And` too.
        let tags_only = configuration("t", None, tags(&[("a", "1"), ("b", "2")])).unwrap();
        let Some(MetricsFilter::And(and)) = tags_only.filter() else {
            panic!("{tags_only:?}")
        };
        assert_eq!((and.prefix(), and.tags().len()), (None, 2));
    }
}
