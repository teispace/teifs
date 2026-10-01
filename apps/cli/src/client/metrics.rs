//! Request metrics: `teifs metrics add|ls|info|rm` for a bucket's metrics
//! configurations (S3's `PutBucketMetricsConfiguration`). Each one counts the requests
//! it matches as `CloudWatch` does, served as Prometheus metrics labeled by bucket and
//! `filter_id` (its id).

use std::collections::BTreeMap;

use aws_sdk_s3::types::{MetricsAndOperator, MetricsConfiguration, MetricsFilter};
use clap::Subcommand;
use serde_json::{Value, json};

use super::{
    Error,
    alias::Aliases,
    filters::{self, Shape},
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
        #[arg(long = "tag", value_parser = filters::tag)]
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
    let filter = filters::shape(prefix, tags)?.map(|shape| match shape {
        Shape::Prefix(prefix) => MetricsFilter::Prefix(prefix),
        Shape::Tag(tag) => MetricsFilter::Tag(tag),
        Shape::And(prefix, tags) => MetricsFilter::And(
            MetricsAndOperator::builder()
                .set_prefix(prefix)
                .set_tags(Some(tags))
                .build(),
        ),
    });
    MetricsConfiguration::builder()
        .id(id)
        .set_filter(filter)
        .build()
        .map_err(|e| Error::usage(e.to_string()))
}

/// The filter's prefix and tags.
fn filter(config: &MetricsConfiguration) -> (Option<&str>, BTreeMap<&str, &str>) {
    match config.filter() {
        Some(MetricsFilter::Prefix(prefix)) => (Some(prefix.as_str()), BTreeMap::new()),
        Some(MetricsFilter::Tag(tag)) => (None, filters::pairs(std::slice::from_ref(tag))),
        Some(MetricsFilter::And(and)) => (and.prefix(), filters::pairs(and.tags())),
        _ => (None, BTreeMap::new()),
    }
}

/// The requests counted, in words: `every request`, or the objects' prefix and tags.
fn requests(config: &MetricsConfiguration) -> String {
    let (prefix, tags) = filter(config);
    filters::words(prefix, &tags).map_or_else(
        || "every request".to_owned(),
        |words| format!("requests on {words}"),
    )
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
