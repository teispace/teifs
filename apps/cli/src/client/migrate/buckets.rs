//! A migration's buckets: the destination's made when it's missing (with Object Lock
//! when the source has it), and the source's settings given to it where it has none of
//! its own: versioning, Object Lock's default retention, the policy, lifecycle rules,
//! CORS, tags, default encryption, the website, object ownership and the public access
//! block. A setting the destination already has is kept. Notifications, logging and
//! replication name things that belong to the source: they're reported, not copied.

use aws_sdk_s3::{
    Client,
    config::http::HttpResponse,
    error::{ProvideErrorMetadata, SdkError},
    types::{
        BucketLifecycleConfiguration, BucketLocationConstraint, BucketVersioningStatus,
        CorsConfiguration, CreateBucketConfiguration, ObjectLockEnabled, Tagging,
        VersioningConfiguration, WebsiteConfiguration,
    },
};
use futures::future::BoxFuture;
use serde_json::json;

use super::super::{Error, alias};
use super::Pair;
use crate::ui;

/// What a migration does with a bucket's objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// Every version and delete marker, in order; else the current objects.
    pub versions: bool,
    /// Versioning to suspend at the destination once its versions are in (the
    /// source's is suspended; it's on while they're copied).
    pub suspend_after: bool,
}

/// Whether an error says the thing asked for isn't there.
fn absent<E: ProvideErrorMetadata, R>(err: &SdkError<E, R>) -> bool {
    err.code().is_some_and(|code| {
        code.starts_with("NoSuch") || code.ends_with("NotFound") || code.ends_with("NotFoundError")
    })
}

/// A setting read from a bucket: there, not there, or unreadable.
type Read<T> = Result<Option<T>, Error>;

/// Reads a setting, `None` when the bucket has none.
fn read<T, E: ProvideErrorMetadata + std::error::Error + 'static>(
    what: &str,
    name: &str,
    got: Result<T, SdkError<E, HttpResponse>>,
) -> Read<T> {
    match got {
        Ok(found) => Ok(Some(found)),
        Err(err) if absent(&err) => Ok(None),
        Err(err) => Err(Error::s3(format!("can't read the {what} of {name}"), &err)),
    }
}

/// Gets the destination bucket ready; what to do with the objects.
pub async fn prepare(
    pair: &Pair,
    latest: bool,
    configs: bool,
    dry_run: bool,
) -> Result<Plan, Error> {
    let (from, to) = (&pair.from_client, &pair.to_client);
    let (source, destination) = (pair.source_name(), pair.destination_name());
    let versioning = from
        .get_bucket_versioning()
        .bucket(&pair.from_bucket)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read the versioning of {source}"), &e))?;
    let source_versioning = versioning.status().cloned();
    let lock = read(
        "Object Lock",
        &source,
        from.get_object_lock_configuration()
            .bucket(&pair.from_bucket)
            .send()
            .await,
    )
    .unwrap_or(None)
    .and_then(|found| found.object_lock_configuration)
    .filter(|c| c.object_lock_enabled() == Some(&ObjectLockEnabled::Enabled));
    let made = make(pair, lock.is_some(), dry_run).await?;
    let versions = source_versioning.is_some() && !latest;
    let mut plan = Plan {
        versions,
        suspend_after: false,
    };
    if let Some(status) = source_versioning.clone() {
        let there = if made && dry_run {
            None
        } else {
            to.get_bucket_versioning()
                .bucket(&pair.to_bucket)
                .send()
                .await
                .map_err(|e| Error::s3(format!("can't read the versioning of {destination}"), &e))?
                .status()
                .cloned()
        };
        let on = BucketVersioningStatus::Enabled;
        if versions && there != Some(on.clone()) && !configs {
            return Err(Error::usage(format!(
                "{destination} doesn't keep versions, so {source}'s can't be copied in order: \
                 turn its versioning on (or leave out --no-configs), or copy only the current \
                 objects with --latest"
            )));
        }
        // Versions are copied with versioning on, then it's left as the source's.
        if there != Some(on.clone()) && (versions || (configs && there.is_none())) {
            let wanted = if versions { on.clone() } else { status.clone() };
            set(dry_run, "versioning", &destination, async {
                to.put_bucket_versioning()
                    .bucket(&pair.to_bucket)
                    .versioning_configuration(
                        VersioningConfiguration::builder().status(wanted).build(),
                    )
                    .send()
                    .await
                    .map(|_| ())
                    .map_err(|e| Error::s3("can't set versioning", &e))
            })
            .await?;
            plan.suspend_after = versions
                && (status == BucketVersioningStatus::Suspended
                    || there == Some(BucketVersioningStatus::Suspended));
        }
    }
    if configs {
        settings(pair, dry_run, made && dry_run).await;
    }
    Ok(plan)
}

/// Makes the destination bucket when it's missing; whether it was (or would be) made.
async fn make(pair: &Pair, lock: bool, dry_run: bool) -> Result<bool, Error> {
    let name = pair.destination_name();
    match pair
        .to_client
        .head_bucket()
        .bucket(&pair.to_bucket)
        .send()
        .await
    {
        Ok(_) => return Ok(false),
        Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 404) => {}
        Err(e) => return Err(Error::s3(format!("can't reach {name}"), &e)),
    }
    if dry_run {
        ui::item(
            || {
                format!(
                    "would make {name}{}",
                    if lock { " with Object Lock" } else { "" }
                )
            },
            || json!({"type": "plan", "action": "make", "bucket": name, "lock": lock}),
        );
        return Ok(true);
    }
    let region = &pair.to_region;
    let configuration = (region != alias::DEFAULT_REGION).then(|| {
        CreateBucketConfiguration::builder()
            .location_constraint(BucketLocationConstraint::from(region.as_str()))
            .build()
    });
    pair.to_client
        .create_bucket()
        .bucket(&pair.to_bucket)
        .set_create_bucket_configuration(configuration)
        .set_object_lock_enabled_for_bucket(lock.then_some(true))
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't make {name}"), &e))?;
    ui::done(
        format!(
            "Created {name}{}",
            if lock { " with Object Lock" } else { "" }
        ),
        || json!({"type": "bucket", "action": "make", "name": name, "lock": lock}),
    );
    Ok(true)
}

/// Sets a setting (or says it would).
async fn set(
    dry_run: bool,
    what: &str,
    name: &str,
    write: impl Future<Output = Result<(), Error>>,
) -> Result<(), Error> {
    if dry_run {
        ui::item(
            || format!("would set {name}'s {what}"),
            || json!({"type": "plan", "action": "set", "bucket": name, "setting": what}),
        );
        return Ok(());
    }
    write.await?;
    ui::done(
        format!("Set {name}'s {what}"),
        || json!({"type": "setting", "action": "set", "bucket": name, "setting": what}),
    );
    Ok(())
}

/// A setting copied one way: read from a bucket, written to one.
struct Setting<T> {
    what: &'static str,
    read: fn(Client, String) -> BoxFuture<'static, Read<T>>,
    write: fn(Client, String, T) -> BoxFuture<'static, Result<(), Error>>,
}

/// Copies one setting where the destination has none; a failure is a warning (the
/// objects still go). `unmade`: a dry run's bucket that would be made, whose own
/// settings (a service's defaults) can't be read yet.
async fn copy_setting<T: PartialEq + Send + 'static>(
    pair: &Pair,
    (dry_run, unmade): (bool, bool),
    setting: &Setting<T>,
    adapt: impl FnOnce(T) -> T,
) {
    let destination = pair.destination_name();
    let found = match (setting.read)(pair.from_client.clone(), pair.from_bucket.clone()).await {
        Ok(Some(found)) => adapt(found),
        Ok(None) => return,
        Err(err) => {
            ui::warn(format!("{} not copied: {}", setting.what, err.message));
            return;
        }
    };
    if unmade {
        ui::item(
            || {
                format!(
                    "would set {destination}'s {}, unless a new bucket has its own",
                    setting.what
                )
            },
            || json!({"type": "plan", "action": "set", "bucket": destination, "setting": setting.what}),
        );
        return;
    }
    match (setting.read)(pair.to_client.clone(), pair.to_bucket.clone()).await {
        Ok(None) => {}
        Ok(Some(there)) => {
            if there != found {
                ui::note(format!(
                    "kept {destination}'s own {}, which differs from {}'s",
                    setting.what,
                    pair.source_name()
                ));
            }
            return;
        }
        Err(err) => {
            ui::warn(format!("{} not copied: {}", setting.what, err.message));
            return;
        }
    }
    let write = (setting.write)(pair.to_client.clone(), pair.to_bucket.clone(), found);
    if let Err(err) = set(dry_run, setting.what, &destination, write).await {
        ui::warn(format!("{} not copied: {}", setting.what, err.message));
    }
}

/// `arn:aws:s3:::FROM` (the bucket, or anything in it) in a policy, made `TO`'s.
pub fn rewrite_policy(policy: &str, from: &str, to: &str) -> String {
    let before = format!("arn:aws:s3:::{from}");
    let after = format!("arn:aws:s3:::{to}");
    let mut out = String::with_capacity(policy.len());
    let mut rest = policy;
    while let Some(at) = rest.find(&before) {
        let end = at + before.len();
        out.push_str(&rest[..at]);
        // Only the bucket itself: not another bucket whose name starts the same.
        if matches!(rest.as_bytes().get(end), Some(b'"' | b'/')) {
            out.push_str(&after);
        } else {
            out.push_str(&before);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// The settings that copy as they are, in turn.
async fn settings(pair: &Pair, dry_run: bool, unmade: bool) {
    let (from, to) = (pair.from_bucket.clone(), pair.to_bucket.clone());
    copy_setting(
        pair,
        (dry_run, unmade),
        &POLICY,
        |policy: serde_json::Value| {
            let text = rewrite_policy(&policy.to_string(), &from, &to);
            serde_json::from_str(&text).unwrap_or(policy)
        },
    )
    .await;
    copy_setting(pair, (dry_run, unmade), &LOCK, |c| c).await;
    copy_setting(pair, (dry_run, unmade), &LIFECYCLE, |c| c).await;
    copy_setting(pair, (dry_run, unmade), &CORS, |c| c).await;
    copy_setting(pair, (dry_run, unmade), &TAGS, |c| c).await;
    copy_setting(pair, (dry_run, unmade), &ENCRYPTION, |c| c).await;
    copy_setting(pair, (dry_run, unmade), &WEBSITE, |c| c).await;
    copy_setting(pair, (dry_run, unmade), &OWNERSHIP, |c| c).await;
    copy_setting(pair, (dry_run, unmade), &PUBLIC_ACCESS, |c| c).await;
    not_copied(pair).await;
}

/// Says which of the source's settings that name its own things aren't copied.
async fn not_copied(pair: &Pair) {
    let (client, bucket) = (&pair.from_client, pair.from_bucket.as_str());
    let source = pair.source_name();
    let mut left = Vec::new();
    if let Ok(found) = client
        .get_bucket_notification_configuration()
        .bucket(bucket)
        .send()
        .await
        && (!found.topic_configurations().is_empty()
            || !found.queue_configurations().is_empty()
            || !found.lambda_function_configurations().is_empty()
            || found.event_bridge_configuration().is_some())
    {
        left.push("notifications");
    }
    if let Ok(found) = client.get_bucket_logging().bucket(bucket).send().await
        && found.logging_enabled().is_some()
    {
        left.push("access logging");
    }
    if let Ok(found) = client.get_bucket_replication().bucket(bucket).send().await
        && found.replication_configuration().is_some()
    {
        left.push("replication");
    }
    if !left.is_empty() {
        ui::note(format!(
            "{source}'s {} name its own targets and weren't copied: set them up at the \
             destination",
            left.join(", ")
        ));
    }
}

const POLICY: Setting<serde_json::Value> = Setting {
    what: "policy",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client.get_bucket_policy().bucket(&bucket).send().await;
            Ok(read("policy", &bucket, got)?
                .and_then(|p| p.policy)
                .and_then(|p| serde_json::from_str(&p).ok()))
        })
    },
    write: |client, bucket, policy| {
        Box::pin(async move {
            client
                .put_bucket_policy()
                .bucket(bucket)
                .policy(policy.to_string())
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the policy", &e))
        })
    },
};

const LOCK: Setting<aws_sdk_s3::types::ObjectLockConfiguration> = Setting {
    what: "Object Lock retention",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client
                .get_object_lock_configuration()
                .bucket(&bucket)
                .send()
                .await;
            // Only a default retention is a setting to copy: Object Lock itself comes
            // with the bucket.
            Ok(read("Object Lock", &bucket, got)?
                .and_then(|c| c.object_lock_configuration)
                .filter(|c| c.rule().is_some()))
        })
    },
    write: |client, bucket, configuration| {
        Box::pin(async move {
            client
                .put_object_lock_configuration()
                .bucket(bucket)
                .object_lock_configuration(configuration)
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the default retention", &e))
        })
    },
};

const LIFECYCLE: Setting<Vec<aws_sdk_s3::types::LifecycleRule>> = Setting {
    what: "lifecycle rules",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client
                .get_bucket_lifecycle_configuration()
                .bucket(&bucket)
                .send()
                .await;
            Ok(read("lifecycle rules", &bucket, got)?.and_then(|c| c.rules))
        })
    },
    write: |client, bucket, rules| {
        Box::pin(async move {
            let configuration = BucketLifecycleConfiguration::builder()
                .set_rules(Some(rules))
                .build()
                .map_err(|e| Error::general(format!("can't set the lifecycle rules: {e}")))?;
            client
                .put_bucket_lifecycle_configuration()
                .bucket(bucket)
                .lifecycle_configuration(configuration)
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the lifecycle rules", &e))
        })
    },
};

const CORS: Setting<Vec<aws_sdk_s3::types::CorsRule>> = Setting {
    what: "CORS rules",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client.get_bucket_cors().bucket(&bucket).send().await;
            Ok(read("CORS rules", &bucket, got)?.and_then(|c| c.cors_rules))
        })
    },
    write: |client, bucket, rules| {
        Box::pin(async move {
            let configuration = CorsConfiguration::builder()
                .set_cors_rules(Some(rules))
                .build()
                .map_err(|e| Error::general(format!("can't set the CORS rules: {e}")))?;
            client
                .put_bucket_cors()
                .bucket(bucket)
                .cors_configuration(configuration)
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the CORS rules", &e))
        })
    },
};

const TAGS: Setting<Vec<aws_sdk_s3::types::Tag>> = Setting {
    what: "tags",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client.get_bucket_tagging().bucket(&bucket).send().await;
            Ok(read("tags", &bucket, got)?
                .map(|t| t.tag_set)
                .filter(|tags| !tags.is_empty()))
        })
    },
    write: |client, bucket, tags| {
        Box::pin(async move {
            let tagging = Tagging::builder()
                .set_tag_set(Some(tags))
                .build()
                .map_err(|e| Error::general(format!("can't set the tags: {e}")))?;
            client
                .put_bucket_tagging()
                .bucket(bucket)
                .tagging(tagging)
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the tags", &e))
        })
    },
};

const ENCRYPTION: Setting<aws_sdk_s3::types::ServerSideEncryptionConfiguration> = Setting {
    what: "default encryption",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client.get_bucket_encryption().bucket(&bucket).send().await;
            Ok(read("default encryption", &bucket, got)?
                .and_then(|c| c.server_side_encryption_configuration))
        })
    },
    write: |client, bucket, configuration| {
        Box::pin(async move {
            client
                .put_bucket_encryption()
                .bucket(bucket)
                .server_side_encryption_configuration(configuration)
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the default encryption", &e))
        })
    },
};

const WEBSITE: Setting<WebsiteConfiguration> = Setting {
    what: "website",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client.get_bucket_website().bucket(&bucket).send().await;
            Ok(read("website", &bucket, got)?.map(|w| {
                WebsiteConfiguration::builder()
                    .set_index_document(w.index_document)
                    .set_error_document(w.error_document)
                    .set_redirect_all_requests_to(w.redirect_all_requests_to)
                    .set_routing_rules(w.routing_rules)
                    .build()
            }))
        })
    },
    write: |client, bucket, configuration| {
        Box::pin(async move {
            client
                .put_bucket_website()
                .bucket(bucket)
                .website_configuration(configuration)
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the website", &e))
        })
    },
};

const OWNERSHIP: Setting<aws_sdk_s3::types::OwnershipControls> = Setting {
    what: "object ownership",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client
                .get_bucket_ownership_controls()
                .bucket(&bucket)
                .send()
                .await;
            Ok(read("object ownership", &bucket, got)?.and_then(|c| c.ownership_controls))
        })
    },
    write: |client, bucket, controls| {
        Box::pin(async move {
            client
                .put_bucket_ownership_controls()
                .bucket(bucket)
                .ownership_controls(controls)
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the object ownership", &e))
        })
    },
};

const PUBLIC_ACCESS: Setting<aws_sdk_s3::types::PublicAccessBlockConfiguration> = Setting {
    what: "public access block",
    read: |client, bucket| {
        Box::pin(async move {
            let got = client
                .get_public_access_block()
                .bucket(&bucket)
                .send()
                .await;
            Ok(read("public access block", &bucket, got)?
                .and_then(|c| c.public_access_block_configuration))
        })
    },
    write: |client, bucket, configuration| {
        Box::pin(async move {
            client
                .put_public_access_block()
                .bucket(bucket)
                .public_access_block_configuration(configuration)
                .send()
                .await
                .map(|_| ())
                .map_err(|e| Error::s3("can't set the public access block", &e))
        })
    },
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_are_given_the_new_buckets_name() {
        let policy = r#"{"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*","arn:aws:s3:::photos-old/*"]}"#;
        assert_eq!(
            rewrite_policy(policy, "photos", "pictures"),
            r#"{"Resource":["arn:aws:s3:::pictures","arn:aws:s3:::pictures/*","arn:aws:s3:::photos-old/*"]}"#
        );
        assert_eq!(rewrite_policy(policy, "photos", "photos"), policy);
        assert_eq!(rewrite_policy("{}", "a", "b"), "{}");
    }
}
