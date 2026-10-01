//! Inventory reports: `teifs inventory add|ls|info|rm` for a bucket's inventory
//! configurations (S3's `PutBucketInventoryConfiguration`). Like the S3 console, `add`
//! also lets S3 Inventory (`s3.amazonaws.com`) into the destination, with a statement in
//! its bucket policy.

use aws_sdk_s3::types::{
    InventoryConfiguration, InventoryDestination, InventoryEncryption, InventoryFilter,
    InventoryFormat, InventoryFrequency, InventoryIncludedObjectVersions, InventoryOptionalField,
    InventoryS3BucketDestination, InventorySchedule, Ssekms, Sses3,
};
use clap::Subcommand;
use serde_json::{Value, json};

use super::{
    Error,
    alias::Aliases,
    service_policy::{self, Grant},
    target::{Remote, Target},
};
use crate::ui;

/// The service principal that delivers inventory reports.
const SERVICE: &str = "s3.amazonaws.com";
/// The canned ACL S3 Inventory writes with.
const ACL: &str = "bucket-owner-full-control";

#[derive(Subcommand)]
pub enum InventoryAction {
    /// Report `ALIAS/BUCKET`'s objects daily (or weekly) into `ALIAS/DESTINATION[/PREFIX]`
    /// as S3 Inventory does: gzipped CSV files with a manifest. Replaces the bucket's
    /// configuration of the same id.
    Add {
        /// `ALIAS/BUCKET`: the bucket whose objects are reported.
        source: String,
        /// The configuration's id.
        id: String,
        /// `ALIAS/DESTINATION[/PREFIX]`: where reports go, their keys starting with
        /// `PREFIX/BUCKET/ID/`.
        destination: String,
        /// Only objects whose keys start with this.
        #[arg(long)]
        prefix: Option<String>,
        /// Every version and delete marker, not only current objects.
        #[arg(long)]
        all_versions: bool,
        /// Once a week (on Sundays, UTC) instead of every day.
        #[arg(long)]
        weekly: bool,
        /// The optional fields, comma-separated, as S3 names them (`Size`, `ETag`,
        /// `LastModifiedDate`, `StorageClass`, `EncryptionStatus`…), or `all`.
        #[arg(long, value_delimiter = ',')]
        fields: Vec<String>,
        /// Encrypt reports with SSE-S3, or with SSE-KMS and this key (`sse-s3` or a
        /// KMS key); otherwise the destination's default.
        #[arg(long)]
        encrypt: Option<String>,
        /// Keep the configuration without making reports.
        #[arg(long)]
        disabled: bool,
        /// Leave the destination's bucket policy alone (it lets S3 Inventory in
        /// already).
        #[arg(long)]
        no_policy: bool,
    },
    /// List a bucket's inventory configurations.
    Ls {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Show one of a bucket's inventory configurations.
    Info {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
    },
    /// Remove one of a bucket's inventory configurations.
    Rm {
        /// `ALIAS/BUCKET`.
        bucket: String,
        /// The configuration's id.
        id: String,
    },
}

/// What `teifs inventory add` sets, besides where.
struct Options {
    prefix: Option<String>,
    all_versions: bool,
    weekly: bool,
    fields: Vec<String>,
    encrypt: Option<String>,
    disabled: bool,
}

/// `teifs inventory …`.
pub(super) async fn inventory(action: InventoryAction, aliases: &Aliases) -> Result<(), Error> {
    let remote = |target: &str| Target::parse(target, aliases)?.remote("inventory");
    match action {
        InventoryAction::Add {
            source,
            id,
            destination,
            prefix,
            all_versions,
            weekly,
            fields,
            encrypt,
            disabled,
            no_policy,
        } => {
            let (source, destination) = (remote(&source)?, remote(&destination)?);
            if destination.alias_name != source.alias_name {
                return Err(Error::usage(
                    "a bucket's inventory goes to a bucket on the same server: give the \
                     destination with the same alias",
                ));
            }
            let options = Options {
                prefix,
                all_versions,
                weekly,
                fields,
                encrypt,
                disabled,
            };
            add(&source, &id, &destination, options, !no_policy).await
        }
        InventoryAction::Ls { bucket } => ls(&remote(&bucket)?).await,
        InventoryAction::Info { bucket, id } => info(&remote(&bucket)?, &id).await,
        InventoryAction::Rm { bucket, id } => rm(&remote(&bucket)?, &id).await,
    }
}

async fn add(
    source: &Remote,
    id: &str,
    destination: &Remote,
    options: Options,
    policy: bool,
) -> Result<(), Error> {
    let bucket = source.bucket()?;
    let target = destination.bucket()?;
    let prefix = destination.key.trim_end_matches('/');
    let name = source.display("");
    let client = source.alias.client();
    let config = configuration(id, (target, prefix), options)?;
    if policy {
        let account = crate::sts::account(&source.alias).await?;
        let grant = Grant {
            sid: format!("TeiFSInventory-{bucket}"),
            service: SERVICE,
            source: bucket,
            target: (target, prefix),
            account: &account,
            acl: Some(ACL),
        };
        service_policy::let_in(&client, &grant).await?;
    }
    client
        .put_bucket_inventory_configuration()
        .bucket(bucket)
        .id(id)
        .inventory_configuration(config.clone())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't set the inventory {id} of {name}"), &e))?;
    let to = destination.display(prefix);
    ui::done(format!("Inventory {id} of {name}: to {to}"), || {
        record(&name, &config)
    });
    Ok(())
}

/// The configuration `teifs inventory add` sets.
fn configuration(
    id: &str,
    (target, prefix): (&str, &str),
    options: Options,
) -> Result<InventoryConfiguration, Error> {
    let usage = |e: aws_sdk_s3::error::BuildError| Error::usage(e.to_string());
    let encryption = options
        .encrypt
        .map(|encrypt| {
            let builder = InventoryEncryption::builder();
            Ok::<_, Error>(if encrypt.eq_ignore_ascii_case("sse-s3") {
                builder.sses3(Sses3::builder().build()).build()
            } else {
                builder
                    .ssekms(Ssekms::builder().key_id(encrypt).build().map_err(usage)?)
                    .build()
            })
        })
        .transpose()?;
    let mut s3_destination = InventoryS3BucketDestination::builder()
        .bucket(format!("arn:aws:s3:::{target}"))
        .format(InventoryFormat::Csv)
        .set_encryption(encryption);
    if !prefix.is_empty() {
        s3_destination = s3_destination.prefix(prefix);
    }
    let filter = options
        .prefix
        .map(|prefix| InventoryFilter::builder().prefix(prefix).build())
        .transpose()
        .map_err(usage)?;
    InventoryConfiguration::builder()
        .id(id)
        .is_enabled(!options.disabled)
        .set_filter(filter)
        .destination(
            InventoryDestination::builder()
                .s3_bucket_destination(s3_destination.build().map_err(usage)?)
                .build(),
        )
        .included_object_versions(if options.all_versions {
            InventoryIncludedObjectVersions::All
        } else {
            InventoryIncludedObjectVersions::Current
        })
        .set_optional_fields(Some(fields(&options.fields)?))
        .schedule(
            InventorySchedule::builder()
                .frequency(if options.weekly {
                    InventoryFrequency::Weekly
                } else {
                    InventoryFrequency::Daily
                })
                .build()
                .map_err(usage)?,
        )
        .build()
        .map_err(usage)
}

/// The optional fields named, as S3 names them whatever their case; `all` is every one.
fn fields(names: &[String]) -> Result<Vec<InventoryOptionalField>, Error> {
    let known = InventoryOptionalField::values();
    if names.iter().any(|name| name.eq_ignore_ascii_case("all")) {
        return Ok(known
            .iter()
            .map(|name| InventoryOptionalField::from(*name))
            .collect());
    }
    names
        .iter()
        .map(|name| {
            known
                .iter()
                .find(|known| known.eq_ignore_ascii_case(name))
                .map(|known| InventoryOptionalField::from(*known))
                .ok_or_else(|| {
                    Error::usage(format!(
                        "{name} isn't an inventory field: use {}, or all",
                        known.join(", ")
                    ))
                })
        })
        .collect()
}

/// Every configuration of a bucket, a page at a time.
async fn all(remote: &Remote) -> Result<Vec<InventoryConfiguration>, Error> {
    let bucket = remote.bucket()?;
    let client = remote.alias.client();
    let mut configs = Vec::new();
    let mut token = None;
    loop {
        let out = client
            .list_bucket_inventory_configurations()
            .bucket(bucket)
            .set_continuation_token(token)
            .send()
            .await
            .map_err(|e| {
                Error::s3(
                    format!("can't list the inventories of {}", remote.display("")),
                    &e,
                )
            })?;
        configs.extend(out.inventory_configuration_list().iter().cloned());
        token = out.next_continuation_token().map(str::to_owned);
        if !out.is_truncated().unwrap_or(false) || token.is_none() {
            return Ok(configs);
        }
    }
}

async fn ls(remote: &Remote) -> Result<(), Error> {
    let name = remote.display("");
    let configs = all(remote).await?;
    let mut table = ui::Table::new(&["ID", "SCHEDULE", "OBJECTS", "TO"]);
    for config in &configs {
        table.row(vec![
            config.id().to_owned(),
            schedule(config),
            objects(config),
            destination(config),
        ]);
    }
    let records: Vec<Value> = configs.iter().map(|c| record(&name, c)).collect();
    ui::rows(
        &table,
        &records,
        &format!(
            "{name} has no inventory configurations. Add one: teifs inventory add {name} ID ALIAS/DESTINATION"
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
        .get_bucket_inventory_configuration()
        .bucket(bucket)
        .id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read the inventory {id} of {name}"), &e))?;
    let Some(config) = out.inventory_configuration() else {
        return Err(Error::usage(format!("{name} has no inventory {id}")));
    };
    let s3 = config
        .destination()
        .and_then(InventoryDestination::s3_bucket_destination);
    let fields = [
        ("Bucket", name.clone()),
        ("Inventory", config.id().to_owned()),
        ("Schedule", schedule(config)),
        ("Objects", objects(config)),
        ("To", destination(config)),
        (
            "Format",
            s3.map(|s3| s3.format().as_str().to_owned())
                .unwrap_or_default(),
        ),
        (
            "Encryption",
            s3.and_then(InventoryS3BucketDestination::encryption)
                .map(|e| match e.ssekms() {
                    Some(kms) => format!("SSE-KMS ({})", kms.key_id()),
                    None => "SSE-S3".to_owned(),
                })
                .unwrap_or_default(),
        ),
        (
            "Fields",
            config
                .optional_fields()
                .iter()
                .map(InventoryOptionalField::as_str)
                .collect::<Vec<_>>()
                .join(", "),
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
        .delete_bucket_inventory_configuration()
        .bucket(bucket)
        .id(id)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't remove the inventory {id} of {name}"), &e))?;
    ui::done(
        format!("Inventory {id} of {name}: removed"),
        || json!({"type": "inventory", "bucket": name, "id": id, "removed": true}),
    );
    Ok(())
}

/// How often, in words: `daily`, `weekly`, and `(off)` when disabled.
fn schedule(config: &InventoryConfiguration) -> String {
    let every = config.schedule().map_or("daily", |s| match s.frequency() {
        InventoryFrequency::Weekly => "weekly",
        _ => "daily",
    });
    if config.is_enabled() {
        every.to_owned()
    } else {
        format!("{every} (off)")
    }
}

/// What's reported, in words: `current` or `all versions`, and the key prefix.
fn objects(config: &InventoryConfiguration) -> String {
    let which = match config.included_object_versions() {
        InventoryIncludedObjectVersions::All => "all versions",
        _ => "current",
    };
    match config.filter().map(InventoryFilter::prefix) {
        Some(prefix) if !prefix.is_empty() => format!("{which} of {prefix}*"),
        _ => which.to_owned(),
    }
}

/// Where reports go: `BUCKET[/PREFIX]`.
fn destination(config: &InventoryConfiguration) -> String {
    let Some(s3) = config
        .destination()
        .and_then(InventoryDestination::s3_bucket_destination)
    else {
        return String::new();
    };
    let bucket = s3.bucket().trim_start_matches("arn:aws:s3:::");
    match s3.prefix() {
        Some(prefix) if !prefix.is_empty() => format!("{bucket}/{prefix}"),
        _ => bucket.to_owned(),
    }
}

fn record(bucket: &str, config: &InventoryConfiguration) -> Value {
    let s3 = config
        .destination()
        .and_then(InventoryDestination::s3_bucket_destination);
    json!({
        "type": "inventory",
        "bucket": bucket,
        "id": config.id(),
        "enabled": config.is_enabled(),
        "frequency": config.schedule().map(|s| s.frequency().as_str()),
        "allVersions": config.included_object_versions() == &InventoryIncludedObjectVersions::All,
        "prefix": config.filter().map(InventoryFilter::prefix),
        "destinationBucket": s3.map(|s3| s3.bucket().trim_start_matches("arn:aws:s3:::")),
        "destinationPrefix": s3.and_then(InventoryS3BucketDestination::prefix),
        "format": s3.map(|s3| s3.format().as_str()),
        "fields": config
            .optional_fields()
            .iter()
            .map(InventoryOptionalField::as_str)
            .collect::<Vec<_>>(),
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
            all_versions: false,
            weekly: false,
            fields: Vec::new(),
            encrypt: None,
            disabled: false,
        }
    }

    #[test]
    fn fields_are_s3s_names_in_any_case() {
        let named = fields(&["size".to_owned(), "ETAG".to_owned()]).unwrap();
        assert_eq!(
            named,
            [InventoryOptionalField::Size, InventoryOptionalField::ETag]
        );
        let every = fields(&["all".to_owned()]).unwrap();
        assert_eq!(every.len(), InventoryOptionalField::values().len());
        let err = fields(&["Colour".to_owned()]).unwrap_err().to_string();
        assert!(err.contains("Colour isn't an inventory field"), "{err}");
        assert!(fields(&[]).unwrap().is_empty());
    }

    #[test]
    fn options_make_s3s_configuration() {
        let plain = configuration("daily", ("reports", ""), options()).unwrap();
        assert!(plain.is_enabled());
        assert_eq!(schedule(&plain), "daily");
        assert_eq!(objects(&plain), "current");
        assert_eq!(destination(&plain), "reports");
        let s3 = plain
            .destination()
            .unwrap()
            .s3_bucket_destination()
            .unwrap();
        assert_eq!(s3.bucket(), "arn:aws:s3:::reports");
        assert_eq!(s3.prefix(), None);
        assert!(s3.encryption().is_none());

        let full = configuration(
            "weekly",
            ("reports", "inv"),
            Options {
                prefix: Some("docs/".to_owned()),
                all_versions: true,
                weekly: true,
                fields: vec!["size".to_owned()],
                encrypt: Some("my-key".to_owned()),
                disabled: true,
            },
        )
        .unwrap();
        assert_eq!(schedule(&full), "weekly (off)");
        assert_eq!(objects(&full), "all versions of docs/*");
        assert_eq!(destination(&full), "reports/inv");
        let encryption = full
            .destination()
            .unwrap()
            .s3_bucket_destination()
            .unwrap()
            .encryption()
            .unwrap();
        assert_eq!(encryption.ssekms().unwrap().key_id(), "my-key");
        let sse_s3 = configuration(
            "s3",
            ("reports", ""),
            Options {
                encrypt: Some("SSE-S3".to_owned()),
                ..options()
            },
        )
        .unwrap();
        let encryption = sse_s3
            .destination()
            .unwrap()
            .s3_bucket_destination()
            .unwrap()
            .encryption()
            .unwrap();
        assert!(encryption.sses3().is_some() && encryption.ssekms().is_none());
    }
}
