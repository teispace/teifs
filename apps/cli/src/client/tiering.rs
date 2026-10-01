//! S3 Intelligent-Tiering's archive settings: `teifs tiering add|ls|info|rm` for a
//! bucket's Intelligent-Tiering configurations (S3's
//! `PutBucketIntelligentTieringConfiguration`). TeiFS keeps them, with S3's checks; its
//! objects are all `STANDARD`, so none is archived.

use aws_sdk_s3::types::{
    IntelligentTieringAccessTier, IntelligentTieringAndOperator, IntelligentTieringConfiguration,
    IntelligentTieringFilter, IntelligentTieringStatus, Tiering,
};
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
pub enum TieringAction {
    /// Archive `ALIAS/BUCKET`'s objects (only those matching `--prefix` and `--tag`, when
    /// given) after days without access, as S3 Intelligent-Tiering's archive tiers do.
    /// Replaces the bucket's configuration of the same id.
    #[command(group(clap::ArgGroup::new("tiers").required(true).multiple(true)))]
    Add {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
        /// Only objects whose keys start with this.
        #[arg(long)]
        prefix: Option<String>,
        /// Only objects with this tag, as `KEY=VALUE`; repeat for several.
        #[arg(long = "tag", value_parser = filters::tag)]
        tags: Vec<(String, String)>,
        /// Days without access before the Archive Access tier (90 to 730).
        #[arg(long, group = "tiers")]
        archive_days: Option<i32>,
        /// Days without access before the Deep Archive Access tier (180 to 730).
        #[arg(long, group = "tiers")]
        deep_archive_days: Option<i32>,
        /// Keep the configuration without it applying.
        #[arg(long)]
        disabled: bool,
    },
    /// List a bucket's Intelligent-Tiering configurations.
    Ls {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Show one of a bucket's Intelligent-Tiering configurations.
    Info {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
    },
    /// Remove one of a bucket's Intelligent-Tiering configurations.
    Rm {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
    },
}

/// What `teifs tiering add` sets.
struct Options {
    prefix: Option<String>,
    tags: Vec<(String, String)>,
    archive_days: Option<i32>,
    deep_archive_days: Option<i32>,
    disabled: bool,
}

/// `teifs tiering …`.
pub(super) async fn tiering(action: TieringAction, aliases: &Aliases) -> Result<(), Error> {
    let remote = |target: &str| Target::parse(target, aliases)?.remote("tiering");
    match action {
        TieringAction::Add {
            bucket,
            id,
            prefix,
            tags,
            archive_days,
            deep_archive_days,
            disabled,
        } => {
            let options = Options {
                prefix,
                tags,
                archive_days,
                deep_archive_days,
                disabled,
            };
            add(&remote(&bucket)?, &id, options).await
        }
        TieringAction::Ls { bucket } => ls(&remote(&bucket)?).await,
        TieringAction::Info { bucket, id } => info(&remote(&bucket)?, &id).await,
        TieringAction::Rm { bucket, id } => rm(&remote(&bucket)?, &id).await,
    }
}

async fn add(remote: &Remote, id: &str, options: Options) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let config = configuration(id, options)?;
    remote
        .alias
        .client()
        .put_bucket_intelligent_tiering_configuration()
        .bucket(bucket)
        .id(id)
        .intelligent_tiering_configuration(config.clone())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't set the tiering {id} of {name}"), &e))?;
    ui::done(
        format!("Tiering {id} of {name}: {}", summary(&config)),
        || record(&name, &config),
    );
    Ok(())
}

/// The configuration `teifs tiering add` sets.
fn configuration(id: &str, options: Options) -> Result<IntelligentTieringConfiguration, Error> {
    let usage = |e: aws_sdk_s3::error::BuildError| Error::usage(e.to_string());
    let filter = filters::shape(options.prefix, options.tags)?
        .map(|shape| {
            let filter = IntelligentTieringFilter::builder();
            Ok::<_, Error>(match shape {
                Shape::Prefix(prefix) => filter.prefix(prefix).build(),
                Shape::Tag(tag) => filter.tag(tag).build(),
                Shape::And(prefix, tags) => filter
                    .and(
                        IntelligentTieringAndOperator::builder()
                            .set_prefix(prefix)
                            .set_tags(Some(tags))
                            .build(),
                    )
                    .build(),
            })
        })
        .transpose()?;
    let tierings = [
        (
            options.archive_days,
            IntelligentTieringAccessTier::ArchiveAccess,
        ),
        (
            options.deep_archive_days,
            IntelligentTieringAccessTier::DeepArchiveAccess,
        ),
    ]
    .into_iter()
    .filter_map(|(days, tier)| days.map(|days| (days, tier)))
    .map(|(days, tier)| Tiering::builder().days(days).access_tier(tier).build())
    .collect::<Result<Vec<_>, _>>()
    .map_err(usage)?;
    IntelligentTieringConfiguration::builder()
        .id(id)
        .set_filter(filter)
        .status(if options.disabled {
            IntelligentTieringStatus::Disabled
        } else {
            IntelligentTieringStatus::Enabled
        })
        .set_tierings(Some(tierings))
        .build()
        .map_err(usage)
}

/// The filter's prefix and tags.
fn filter(
    config: &IntelligentTieringConfiguration,
) -> (Option<&str>, std::collections::BTreeMap<&str, &str>) {
    let Some(filter) = config.filter() else {
        return (None, std::collections::BTreeMap::new());
    };
    if let Some(and) = filter.and() {
        return (and.prefix(), filters::pairs(and.tags()));
    }
    (
        filter.prefix(),
        filters::pairs(filter.tag().map(std::slice::from_ref).unwrap_or_default()),
    )
}

/// The objects it's about and when they'd be archived, in words.
fn summary(config: &IntelligentTieringConfiguration) -> String {
    let (prefix, tags) = filter(config);
    let objects = filters::words(prefix, &tags)
        .map_or_else(|| "every object".to_owned(), |w| format!("objects {w}"));
    let tiers = config
        .tierings()
        .iter()
        .map(|t| match t.access_tier() {
            IntelligentTieringAccessTier::DeepArchiveAccess => {
                format!("deep archive after {} days", t.days())
            }
            _ => format!("archive after {} days", t.days()),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let off = if config.status() == &IntelligentTieringStatus::Enabled {
        ""
    } else {
        " (off)"
    };
    format!("{objects}: {tiers}{off}")
}

/// Every configuration of a bucket.
async fn all(remote: &Remote) -> Result<Vec<IntelligentTieringConfiguration>, Error> {
    let bucket = remote.bucket()?;
    let client = &remote.alias.client();
    pages::every(|token| async move {
        let out = client
            .list_bucket_intelligent_tiering_configurations()
            .bucket(bucket)
            .set_continuation_token(token)
            .send()
            .await
            .map_err(|e| {
                Error::s3(
                    format!("can't list the tierings of {}", remote.display("")),
                    &e,
                )
            })?;
        Ok(pages::Page {
            items: out.intelligent_tiering_configuration_list().to_vec(),
            truncated: out.is_truncated().unwrap_or(false),
            next: out.next_continuation_token().map(str::to_owned),
        })
    })
    .await
}

async fn ls(remote: &Remote) -> Result<(), Error> {
    let name = remote.display("");
    let configs = all(remote).await?;
    let mut table = ui::Table::new(&["ID", "TIERING"]);
    for config in &configs {
        table.row(vec![config.id().to_owned(), summary(config)]);
    }
    let records: Vec<Value> = configs.iter().map(|c| record(&name, c)).collect();
    ui::rows(
        &table,
        &records,
        &format!(
            "{name} has no Intelligent-Tiering configurations. Add one: teifs tiering add {name} ID --archive-days 90"
        ),
    );
    Ok(())
}

async fn info(remote: &Remote, id: &str) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let out = remote
        .alias
        .client()
        .get_bucket_intelligent_tiering_configuration()
        .bucket(bucket)
        .id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read the tiering {id} of {name}"), &e))?;
    let Some(config) = out.intelligent_tiering_configuration() else {
        return Err(Error::usage(format!("{name} has no tiering {id}")));
    };
    let fields = [
        ("Bucket", name.clone()),
        ("Tiering", config.id().to_owned()),
        ("Archives", summary(config)),
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
        .delete_bucket_intelligent_tiering_configuration()
        .bucket(bucket)
        .id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't remove the tiering {id} of {name}"), &e))?;
    ui::done(
        format!("Tiering {id} of {name}: removed"),
        || json!({"type": "tiering", "bucket": name, "id": id, "removed": true}),
    );
    Ok(())
}

fn record(bucket: &str, config: &IntelligentTieringConfiguration) -> Value {
    let (prefix, tags) = filter(config);
    let days = |tier: &IntelligentTieringAccessTier| {
        config
            .tierings()
            .iter()
            .find(|t| t.access_tier() == tier)
            .map(Tiering::days)
    };
    json!({
        "type": "tiering",
        "bucket": bucket,
        "id": config.id(),
        "enabled": config.status() == &IntelligentTieringStatus::Enabled,
        "prefix": prefix,
        "tags": tags,
        "archiveDays": days(&IntelligentTieringAccessTier::ArchiveAccess),
        "deepArchiveDays": days(&IntelligentTieringAccessTier::DeepArchiveAccess),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    fn options() -> Options {
        Options {
            prefix: None,
            tags: Vec::new(),
            archive_days: Some(90),
            deep_archive_days: None,
            disabled: false,
        }
    }

    #[test]
    fn options_make_s3s_configuration() {
        let plain = configuration("archive", options()).unwrap();
        assert!(plain.filter().is_none());
        assert_eq!(plain.status(), &IntelligentTieringStatus::Enabled);
        assert_eq!(summary(&plain), "every object: archive after 90 days");
        let full = configuration(
            "both",
            Options {
                prefix: Some("docs/".to_owned()),
                tags: vec![("team".to_owned(), "red".to_owned())],
                archive_days: Some(120),
                deep_archive_days: Some(365),
                disabled: true,
            },
        )
        .unwrap();
        assert_eq!(
            summary(&full),
            "objects docs/* and team=red: archive after 120 days, deep archive after 365 days (off)"
        );
        let and = full.filter().unwrap().and().unwrap();
        assert_eq!((and.prefix(), and.tags().len()), (Some("docs/"), 1));
        let record = record("a/b", &full);
        assert_eq!(
            (
                &record["archiveDays"],
                &record["deepArchiveDays"],
                &record["enabled"]
            ),
            (&120.into(), &365.into(), &false.into())
        );
        let tagged = configuration(
            "t",
            Options {
                tags: vec![("a".to_owned(), "1".to_owned())],
                ..options()
            },
        )
        .unwrap();
        assert_eq!(tagged.filter().unwrap().tag().unwrap().key(), "a");
        assert_eq!(summary(&tagged), "objects a=1: archive after 90 days");
        let prefixed = configuration(
            "p",
            Options {
                prefix: Some("x/".to_owned()),
                ..options()
            },
        )
        .unwrap();
        assert_eq!(prefixed.filter().unwrap().prefix(), Some("x/"));
    }
}
