//! Bucket quotas: `teifs quota set|info|clear` for the most a bucket may hold, through
//! `MinIO`'s admin API as `mc quota` sets it. Writes that would reach it are refused.

use serde_json::{Value, json};

use super::{Error, QuotaAction, alias::Aliases, target::Target};
use crate::{admin::client_for, ui, units};

/// `teifs quota …`.
pub(super) async fn quota(action: QuotaAction, aliases: &Aliases) -> Result<(), Error> {
    let (bucket, size) = match &action {
        QuotaAction::Set { bucket, size } => (bucket, Some(size)),
        QuotaAction::Info { bucket } | QuotaAction::Clear { bucket } => (bucket, None),
    };
    let remote = Target::parse(bucket, aliases)?.remote("quota")?;
    let name = remote.display("");
    let bucket = remote.bucket()?;
    let client = client_for(&remote.alias)?;
    match action {
        QuotaAction::Set { .. } => {
            let bytes = quota_size(size.map(String::as_str).unwrap_or_default())?;
            client
                .set_bucket_quota(bucket, Some(bytes))
                .await
                .map_err(|e| Error::admin(format!("can't set the quota of {name}"), &e))?;
            ui::done(format!("Quota {name}: {}", units::size(bytes)), || {
                record(&name, Some(bytes))
            });
        }
        QuotaAction::Info { .. } => {
            let bytes = client
                .bucket_quota(bucket)
                .await
                .map_err(|e| Error::admin(format!("can't read the quota of {name}"), &e))?;
            let text = bytes.map_or_else(|| "none".to_owned(), units::size);
            ui::details(&[("Bucket", name.clone()), ("Quota", text)], || {
                record(&name, bytes)
            });
        }
        QuotaAction::Clear { .. } => {
            client
                .set_bucket_quota(bucket, None)
                .await
                .map_err(|e| Error::admin(format!("can't clear the quota of {name}"), &e))?;
            ui::done(format!("Quota {name}: none"), || record(&name, None));
        }
    }
    Ok(())
}

/// `--size`: some bytes, with a unit.
fn quota_size(text: &str) -> Result<u64, Error> {
    match units::parse_size(text) {
        Ok(0) => Err(Error::usage(
            "--size 0 would hold nothing: to remove the quota, use `teifs quota clear`",
        )),
        Ok(bytes) => Ok(bytes),
        Err(why) => Err(Error::usage(format!("--size {why}"))),
    }
}

fn record(bucket: &str, quota: Option<u64>) -> Value {
    json!({"type": "quota", "bucket": bucket, "quota": quota})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_some_bytes() {
        assert_eq!(quota_size("10GiB").ok(), Some(10 << 30));
        assert_eq!(quota_size("512").ok(), Some(512));
        assert!(quota_size("0").is_err());
        assert!(quota_size("0GiB").is_err());
        assert!(quota_size("lots").is_err());
    }
}
