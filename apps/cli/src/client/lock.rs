//! Object Lock: `teifs retention set|clear|info` and `teifs legalhold set|clear|info`,
//! for one object (or with `-r`, every object under a prefix) or a bucket's default
//! retention (`--default`).

use aws_sdk_s3::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    primitives::DateTime,
    types::{
        DefaultRetention, ObjectLockConfiguration, ObjectLockEnabled, ObjectLockLegalHold,
        ObjectLockLegalHoldStatus, ObjectLockRetention, ObjectLockRetentionMode, ObjectLockRule,
    },
};
use futures::{StreamExt, TryStreamExt, stream};
use serde_json::json;
use teifs_store::RetentionPeriod;

use super::{
    Error, Kind, LegalHoldAction, LockModeArg, ObjectArgs, RetentionAction,
    alias::Aliases,
    commands::{keys_under, plural},
    target::{Remote, Target},
};
use crate::{
    ui,
    units::{date, from_ms, now_ms, rfc3339},
};

/// Objects changed at once with `-r`.
const PARALLEL: usize = 8;

/// A retention's length, as mc writes it: `30d` or `1y`.
pub fn parse_validity(text: &str) -> Result<RetentionPeriod, String> {
    let bad = || format!("`{text}` isn't a validity: write days or years, like 30d or 1y");
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let number: u32 = number.parse().map_err(|_| bad())?;
    let period = match unit {
        "d" | "D" => RetentionPeriod::Days(number),
        "y" | "Y" => RetentionPeriod::Years(number),
        _ => return Err(bad()),
    };
    if !period.is_valid() {
        return Err(format!(
            "`{text}` is out of range: from 1d (or 1y) to 36500d (or 100y)"
        ));
    }
    Ok(period)
}

fn mode_of(mode: LockModeArg) -> ObjectLockRetentionMode {
    match mode {
        LockModeArg::Governance => ObjectLockRetentionMode::Governance,
        LockModeArg::Compliance => ObjectLockRetentionMode::Compliance,
    }
}

fn period_text(period: RetentionPeriod) -> String {
    match period {
        RetentionPeriod::Days(days) => format!("{days}d"),
        RetentionPeriod::Years(years) => format!("{years}y"),
    }
}

/// `teifs retention …`.
pub(super) async fn retention(action: RetentionAction, aliases: &Aliases) -> Result<(), Error> {
    match action {
        RetentionAction::Set {
            mode,
            validity,
            lock,
        } => {
            let remote = Target::parse(&lock.objects.target, aliases)?.remote("retention")?;
            if lock.default {
                return set_default(&remote, Some((mode, validity))).await;
            }
            let until = validity.after(now_ms());
            let retention = ObjectLockRetention::builder()
                .mode(mode_of(mode))
                .retain_until_date(DateTime::from_millis(until))
                .build();
            let what = format!(
                "{} until {} UTC",
                mode_of(mode).as_str(),
                date(from_ms(until))
            );
            change_objects(
                &remote,
                &lock.objects,
                RETENTION.to(&what),
                move |client, bucket, key, version| {
                    let retention = retention.clone();
                    async move {
                        client
                            .put_object_retention()
                            .bucket(bucket)
                            .key(key)
                            .set_version_id(version)
                            .retention(retention)
                            .set_bypass_governance_retention(lock.bypass.then_some(true))
                            .send()
                            .await
                            .map(drop)
                    }
                },
            )
            .await
        }
        RetentionAction::Clear { lock } => {
            let remote = Target::parse(&lock.objects.target, aliases)?.remote("retention")?;
            if lock.default {
                return set_default(&remote, None).await;
            }
            change_objects(
                &remote,
                &lock.objects,
                RETENTION.to("cleared"),
                move |client, bucket, key, version| async move {
                    client
                        .put_object_retention()
                        .bucket(bucket)
                        .key(key)
                        .set_version_id(version)
                        .retention(ObjectLockRetention::builder().build())
                        .set_bypass_governance_retention(lock.bypass.then_some(true))
                        .send()
                        .await
                        .map(drop)
                },
            )
            .await
        }
        RetentionAction::Info {
            target,
            default,
            version_id,
        } => {
            let remote = Target::parse(&target, aliases)?.remote("retention")?;
            if default {
                return default_info(&remote).await;
            }
            retention_info(&remote, version_id.as_deref()).await
        }
    }
}

/// `teifs legalhold …`.
pub(super) async fn legal_hold(action: LegalHoldAction, aliases: &Aliases) -> Result<(), Error> {
    let (objects, on) = match action {
        LegalHoldAction::Set { objects } => (objects, true),
        LegalHoldAction::Clear { objects } => (objects, false),
        LegalHoldAction::Info { target, version_id } => {
            let remote = Target::parse(&target, aliases)?.remote("legalhold")?;
            return legal_hold_info(&remote, version_id.as_deref()).await;
        }
    };
    let remote = Target::parse(&objects.target, aliases)?.remote("legalhold")?;
    let status = if on {
        ObjectLockLegalHoldStatus::On
    } else {
        ObjectLockLegalHoldStatus::Off
    };
    let what = if on { "placed" } else { "lifted" };
    change_objects(
        &remote,
        &objects,
        Change {
            noun: "legal hold",
            title: "Legal hold",
            record: "legalHold",
            what,
        },
        move |client, bucket, key, version| {
            let hold = ObjectLockLegalHold::builder()
                .status(status.clone())
                .build();
            async move {
                client
                    .put_object_legal_hold()
                    .bucket(bucket)
                    .key(key)
                    .set_version_id(version)
                    .legal_hold(hold)
                    .send()
                    .await
                    .map(drop)
            }
        },
    )
    .await
}

/// What [`change_objects`] changes, for its messages and records.
#[derive(Clone, Copy)]
pub(super) struct Change<'a> {
    /// In a sentence: `legal hold`.
    pub noun: &'a str,
    /// At the start of one: `Legal hold`.
    pub title: &'a str,
    /// The record's `type`: `legalHold`.
    pub record: &'a str,
    /// The new state: `placed`.
    pub what: &'a str,
}

impl<'a> Change<'a> {
    /// The same change, to `what`.
    pub(super) const fn to(self, what: &'a str) -> Self {
        Self { what, ..self }
    }
}

const RETENTION: Change<'static> = Change {
    noun: "retention",
    title: "Retention",
    record: "retention",
    what: "",
};

/// Applies `change` to the object `objects` names (a version of it with
/// `--version-id`), or with `-r` to every object under it, and reports each.
pub(super) async fn change_objects<F, Fut, E>(
    remote: &Remote,
    objects: &ObjectArgs,
    kind: Change<'_>,
    change: F,
) -> Result<(), Error>
where
    F: Fn(Client, String, String, Option<String>) -> Fut,
    Fut: Future<Output = Result<(), aws_sdk_s3::error::SdkError<E>>>,
    E: aws_sdk_s3::error::ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    let bucket = remote.bucket()?;
    let client = remote.alias.client();
    let name = remote.display(&remote.key);
    let keys = if objects.recursive {
        let keys = keys_under(&client, bucket, remote, &name).await?;
        if keys.is_empty() {
            return Err(Error::new(Kind::NotFound, format!("nothing at {name}")));
        }
        keys
    } else {
        if remote.key.is_empty() {
            return Err(Error::usage(format!(
                "give a key, like {name}/KEY (or -r for every object under a prefix)"
            )));
        }
        vec![remote.key.clone()]
    };
    let count = keys.len();
    stream::iter(keys)
        .map(|key| {
            let (client, bucket) = (client.clone(), bucket.to_owned());
            let shown = remote.display(&key);
            let version = objects.version_id.clone();
            let fut = change(client, bucket, key, version.clone());
            async move {
                fut.await.map_err(|e| {
                    Error::s3(format!("can't change the {} of {shown}", kind.noun), &e)
                })?;
                let Change {
                    title,
                    record,
                    what,
                    ..
                } = kind;
                ui::done(
                    format!("{title} of {shown}: {what}"),
                    || json!({"type": record, "key": shown, "versionId": version, "status": what}),
                );
                Ok::<_, Error>(())
            }
        })
        .buffer_unordered(PARALLEL)
        .try_collect::<()>()
        .await?;
    if count > 1 {
        ui::note(format!("Changed {count} object{}.", plural(count)));
    }
    Ok(())
}

/// Sets (`Some`) or removes a bucket's default retention.
async fn set_default(
    remote: &Remote,
    default: Option<(LockModeArg, RetentionPeriod)>,
) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let rule = default.map(|(mode, period)| {
        let retention = DefaultRetention::builder().mode(mode_of(mode));
        let retention = match period {
            RetentionPeriod::Days(days) => retention.days(i32::try_from(days).unwrap_or(i32::MAX)),
            RetentionPeriod::Years(years) => {
                retention.years(i32::try_from(years).unwrap_or(i32::MAX))
            }
        };
        ObjectLockRule::builder()
            .default_retention(retention.build())
            .build()
    });
    let config = ObjectLockConfiguration::builder()
        .object_lock_enabled(ObjectLockEnabled::Enabled)
        .set_rule(rule)
        .build();
    remote
        .alias
        .client()
        .put_object_lock_configuration()
        .bucket(bucket)
        .object_lock_configuration(config)
        .send()
        .await
        .map_err(|e| {
            Error::s3(format!("can't set the default retention of {name}"), &e)
                .with_hint("Object Lock needs versioning: `teifs version enable` first, or make the bucket with `mb --with-lock`")
        })?;
    let text = default.map_or_else(
        || "none".to_owned(),
        |(mode, period)| format!("{} for {}", mode_of(mode).as_str(), period_text(period)),
    );
    ui::done(
        format!("Default retention of {name}: {text}"),
        || json!({"type": "defaultRetention", "bucket": name, "mode": default.map(|(m, _)| mode_of(m).as_str().to_owned()), "validity": default.map(|(_, p)| period_text(p))}),
    );
    Ok(())
}

/// A bucket's Object Lock, as words: `None` without it.
pub(super) async fn bucket_lock(client: &Client, bucket: &str) -> Option<String> {
    let out = client
        .get_object_lock_configuration()
        .bucket(bucket)
        .send()
        .await
        .ok()?;
    let rule = out
        .object_lock_configuration()?
        .rule()
        .and_then(ObjectLockRule::default_retention);
    Some(rule.map_or_else(
        || "on, no default retention".to_owned(),
        |d| {
            let period = d
                .days()
                .map(|n| format!("{n}d"))
                .or_else(|| d.years().map(|n| format!("{n}y")))
                .unwrap_or_default();
            format!(
                "on, new objects kept {} for {period}",
                d.mode().map_or("", ObjectLockRetentionMode::as_str)
            )
        },
    ))
}

async fn default_info(remote: &Remote) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let client = remote.alias.client();
    let lock = bucket_lock(&client, bucket).await;
    let text = lock.clone().unwrap_or_else(|| "off".to_owned());
    ui::details(
        &[("Bucket", name.clone()), ("Object Lock", text)],
        || json!({"type": "objectLock", "bucket": name, "enabled": lock.is_some(), "status": lock}),
    );
    Ok(())
}

/// Whether S3 answered that the version has no retention or legal hold to show.
fn no_lock<E: ProvideErrorMetadata, R>(err: &SdkError<E, R>) -> bool {
    err.as_service_error().and_then(ProvideErrorMetadata::code)
        == Some("NoSuchObjectLockConfiguration")
}

/// A retention as words: its mode and until when.
pub(super) fn retention_text(mode: &str, until: Option<&DateTime>) -> String {
    let until = until
        .and_then(|t| std::time::SystemTime::try_from(*t).ok())
        .map(|t| format!(" until {} UTC", date(t)))
        .unwrap_or_default();
    format!("{mode}{until}")
}

async fn retention_info(remote: &Remote, version_id: Option<&str>) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display(&remote.key);
    let out = remote
        .alias
        .client()
        .get_object_retention()
        .bucket(bucket)
        .key(&remote.key)
        .set_version_id(version_id.map(str::to_owned))
        .send()
        .await;
    let retention = match out {
        Ok(out) => out.retention().cloned(),
        Err(e) if no_lock(&e) => None,
        Err(e) => return Err(Error::s3(format!("can't read the retention of {name}"), &e)),
    };
    let mode = retention
        .as_ref()
        .and_then(ObjectLockRetention::mode)
        .map(ObjectLockRetentionMode::as_str);
    let until = retention
        .as_ref()
        .and_then(ObjectLockRetention::retain_until_date);
    let text = mode.map_or_else(|| "none".to_owned(), |m| retention_text(m, until));
    ui::details(&[("Name", name.clone()), ("Retention", text)], || {
        json!({
            "type": "retention",
            "key": name,
            "versionId": version_id,
            "mode": mode,
            "retainUntil": until.and_then(|t| std::time::SystemTime::try_from(*t).ok()).map(rfc3339),
        })
    });
    Ok(())
}

async fn legal_hold_info(remote: &Remote, version_id: Option<&str>) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display(&remote.key);
    let out = remote
        .alias
        .client()
        .get_object_legal_hold()
        .bucket(bucket)
        .key(&remote.key)
        .set_version_id(version_id.map(str::to_owned))
        .send()
        .await;
    let on = match out {
        Ok(out) => {
            out.legal_hold().and_then(ObjectLockLegalHold::status)
                == Some(&ObjectLockLegalHoldStatus::On)
        }
        Err(e) if no_lock(&e) => false,
        Err(e) => {
            return Err(Error::s3(
                format!("can't read the legal hold of {name}"),
                &e,
            ));
        }
    };
    let text = if on { "on" } else { "off" };
    ui::details(
        &[("Name", name.clone()), ("Legal hold", text.to_owned())],
        || json!({"type": "legalHold", "key": name, "versionId": version_id, "on": on}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validities_are_days_or_years_in_range() {
        assert_eq!(parse_validity("30d"), Ok(RetentionPeriod::Days(30)));
        assert_eq!(parse_validity("1Y"), Ok(RetentionPeriod::Years(1)));
        assert_eq!(parse_validity("36500d"), Ok(RetentionPeriod::Days(36_500)));
        for bad in ["", "d", "30", "30m", "-1d", "0d", "101y", "36501d", "1.5y"] {
            assert!(parse_validity(bad).is_err(), "{bad}");
        }
        assert_eq!(period_text(RetentionPeriod::Years(2)), "2y");
    }
}
