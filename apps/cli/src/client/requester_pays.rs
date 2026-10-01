//! Requester Pays: `teifs requester-pays enable|disable|info ALIAS/BUCKET` (S3's
//! `PutBucketRequestPayment`). A Requester Pays bucket refuses anonymous requests,
//! whatever its policy allows, and can't receive access logs.

use aws_sdk_s3::types::{Payer, RequestPaymentConfiguration};
use clap::Subcommand;
use serde_json::json;

use super::{Error, alias::Aliases, target::Target};
use crate::ui;

#[derive(Subcommand)]
pub enum RequesterPaysAction {
    /// Make requesters pay: anonymous requests are refused.
    Enable {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Make the bucket's owner pay again.
    Disable {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
    /// Show who pays.
    Info {
        /// `ALIAS/BUCKET`.
        bucket: String,
    },
}

/// `teifs requester-pays …`.
pub(super) async fn run(action: RequesterPaysAction, aliases: &Aliases) -> Result<(), Error> {
    let (bucket, change) = match action {
        RequesterPaysAction::Enable { bucket } => (bucket, Some(Payer::Requester)),
        RequesterPaysAction::Disable { bucket } => (bucket, Some(Payer::BucketOwner)),
        RequesterPaysAction::Info { bucket } => (bucket, None),
    };
    let remote = Target::parse(&bucket, aliases)?.remote("requester-pays")?;
    let bucket = remote.bucket()?;
    if !remote.key.is_empty() {
        return Err(Error::usage(format!(
            "who pays is a bucket's: give ALIAS/BUCKET, not {}",
            remote.display(&remote.key)
        )));
    }
    let name = remote.display("");
    let client = remote.alias.client();
    let changed = change.is_some();
    let payer = match change {
        Some(payer) => {
            let config = RequestPaymentConfiguration::builder()
                .payer(payer.clone())
                .build()
                .map_err(|e| Error::usage(e.to_string()))?;
            client
                .put_bucket_request_payment()
                .bucket(bucket)
                .request_payment_configuration(config)
                .send()
                .await
                .map_err(|e| Error::s3(format!("can't change who pays for {name}"), &e))?;
            payer
        }
        None => client
            .get_bucket_request_payment()
            .bucket(bucket)
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't read who pays for {name}"), &e))?
            .payer()
            .cloned()
            .unwrap_or(Payer::BucketOwner),
    };
    let requester = payer == Payer::Requester;
    let record = || json!({"type": "requesterPays", "bucket": name, "enabled": requester});
    let words = if requester {
        "requesters pay: anonymous requests are refused"
    } else {
        "the owner pays"
    };
    if changed {
        ui::done(format!("{name}: {words}"), record);
    } else {
        ui::details(
            &[
                ("Bucket", name.clone()),
                (
                    "Requester pays",
                    if requester { "on" } else { "off" }.to_owned(),
                ),
            ],
            record,
        );
    }
    Ok(())
}
