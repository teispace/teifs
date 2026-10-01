//! `PutBucketLogging` and `GetBucketLogging`: where a bucket's server access log goes,
//! read from S3's XML with S3's checks, and answered as it was given.

use s3s::{S3Error, S3Result, dto, s3_error};
use teifs_store::{Store, StoreError};
use teifs_types::{
    Acl, AclGrant, Permission,
    logging::{DateSource, KeyFormat, LoggingConfig, SERVICE},
};

use crate::{acl, bucket_access::Rules, delivery::Delivery, errors::from_store};

/// The configuration a `BucketLoggingStatus` gives: `None` (an empty status) turns
/// logging off.
pub(crate) fn from_dto(status: dto::BucketLoggingStatus) -> S3Result<Option<LoggingConfig>> {
    let Some(enabled) = status.logging_enabled else {
        return Ok(None);
    };
    let key_format = enabled
        .target_object_key_format
        .map(
            |format| match (format.simple_prefix, format.partitioned_prefix) {
                (Some(_), None) => Ok(KeyFormat::Simple),
                (None, Some(partitioned)) => partitioned
                    .partition_date_source
                    .map(|source| DateSource::parse(source.as_str()).ok_or_else(malformed))
                    .transpose()
                    .map(KeyFormat::Partitioned),
                _ => Err(malformed()),
            },
        )
        .transpose()?;
    let grants = enabled
        .target_grants
        .unwrap_or_default()
        .into_iter()
        .map(|grant| {
            let (Some(who), Some(permission)) = (grant.grantee, grant.permission) else {
                return Err(malformed());
            };
            let permission = match permission.as_str() {
                dto::BucketLogsPermission::FULL_CONTROL => Permission::FullControl,
                dto::BucketLogsPermission::READ => Permission::Read,
                dto::BucketLogsPermission::WRITE => Permission::Write,
                _ => return Err(malformed()),
            };
            Ok(AclGrant {
                grantee: acl::grantee_from_dto(who, malformed)?,
                permission,
            })
        })
        .collect::<S3Result<Vec<_>>>()?;
    Ok(Some(LoggingConfig {
        target_bucket: enabled.target_bucket,
        target_prefix: enabled.target_prefix,
        key_format,
        grants,
    }))
}

/// A bucket's logging as `GetBucketLogging` answers it: as it was given.
pub(crate) fn to_dto(config: Option<&LoggingConfig>) -> dto::GetBucketLoggingOutput {
    dto::GetBucketLoggingOutput {
        logging_enabled: config.map(|config| dto::LoggingEnabled {
            target_bucket: config.target_bucket.clone(),
            target_prefix: config.target_prefix.clone(),
            target_object_key_format: config.key_format.map(|format| match format {
                KeyFormat::Simple => dto::TargetObjectKeyFormat {
                    simple_prefix: Some(dto::SimplePrefix {}),
                    partitioned_prefix: None,
                },
                KeyFormat::Partitioned(source) => dto::TargetObjectKeyFormat {
                    simple_prefix: None,
                    partitioned_prefix: Some(dto::PartitionedPrefix {
                        partition_date_source: source
                            .map(|source| dto::PartitionDateSource::from_static(source.name())),
                    }),
                },
            }),
            target_grants: (!config.grants.is_empty()).then(|| {
                config
                    .grants
                    .iter()
                    .map(|grant| dto::TargetGrant {
                        grantee: Some(acl::grantee_to_dto(grant.grantee)),
                        permission: Some(dto::BucketLogsPermission::from(
                            grant.permission.name().to_owned(),
                        )),
                    })
                    .collect()
            }),
        }),
    }
}

/// What `PutBucketLogging` checks of `source`'s new configuration, as S3 does: the
/// target exists, isn't a Requester Pays bucket, has no default retention, takes target grants only while its ACLs are
/// enabled, and (when IAM decides requests, in `account`) lets the logging service in,
/// by its policy or an ACL grant to the log delivery group.
pub(crate) async fn check(
    store: &Store,
    rules: &Rules,
    account: Option<&str>,
    source: &str,
    config: &LoggingConfig,
) -> S3Result<()> {
    store.head_bucket(source).await.map_err(from_store)?;
    let target = config.target_bucket.as_str();
    match store.head_bucket(target).await {
        Ok(_) => {}
        Err(StoreError::NoSuchBucket) => {
            return Err(invalid_target(
                "The target bucket for logging does not exist",
            ));
        }
        Err(err) => return Err(from_store(err)),
    }
    if store
        .bucket_configurations(target)
        .await
        .map_err(from_store)?
        .requester_pays
    {
        return Err(invalid_target(
            "The target bucket for logging can't be a Requester Pays bucket",
        ));
    }
    let lock = store.bucket_object_lock(target).await.map_err(from_store)?;
    if lock.is_some_and(|lock| lock.default_retention.is_some()) {
        return Err(invalid_target(
            "The target bucket for logging can't have a default retention period (Object Lock)",
        ));
    }
    let target_rules = rules.of(target).await?;
    if !config.grants.is_empty() && !target_rules.ownership.acls_enabled() {
        return Err(s3_error!(
            InvalidArgument,
            "The target bucket's Object Ownership is BucketOwnerEnforced, which doesn't \
             support target grants: grant access with a bucket policy instead"
        ));
    }
    let Some(account) = account else {
        return Ok(());
    };
    if !delivery(source, config).allowed(account, &config.target_prefix, &target_rules) {
        return Err(invalid_target(
            "You must either provide the necessary permissions to the logging service using \
             a bucket policy or give the log-delivery group WRITE and READ_ACP permissions to \
             the target bucket",
        ));
    }
    Ok(())
}

/// How `source`'s log objects are delivered into `config`'s target: by
/// `logging.s3.amazonaws.com`, as plain text, with the configuration's target grants
/// and the target's default encryption.
pub(crate) fn delivery<'a>(source: &'a str, config: &'a LoggingConfig) -> Delivery<'a> {
    let acl = (!config.grants.is_empty()).then(|| {
        let mut acl = Acl::private();
        acl.grants.extend(config.grants.iter().copied());
        acl
    });
    Delivery {
        service: SERVICE,
        source,
        target: &config.target_bucket,
        content_type: "text/plain",
        canned_acl: None,
        acl,
        encryption: None,
    }
}

fn invalid_target(message: &'static str) -> S3Error {
    s3_error!(InvalidTargetBucketForLogging, "{message}")
}

fn malformed() -> S3Error {
    s3_error!(
        MalformedXML,
        "The XML you provided was not well-formed or did not validate against our published schema"
    )
}
