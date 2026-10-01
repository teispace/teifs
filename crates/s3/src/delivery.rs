//! What S3 itself writes into buckets, as one of its services: server access logs
//! (`logging.s3.amazonaws.com`) and inventory reports (`s3.amazonaws.com`). The target
//! bucket's policy and ACL decide whether the service may write there, as on AWS.

use s3s::{S3Error, S3ErrorCode};
use teifs_iam::Identity;
use teifs_policy::{Date, S3Key, bucket_arn, object_arn};
use teifs_types::Acl;

use crate::{access, bucket_access::BucketRules, drive::REGION};

/// One delivery into a bucket: who writes, for which bucket, and how its objects are
/// written.
#[derive(Debug)]
pub(crate) struct Delivery<'a> {
    /// The service writing (its principal in the target's policy).
    pub service: &'static str,
    /// The bucket the delivery is for: `aws:SourceArn` and `aws:SourceAccount`.
    pub source: &'a str,
    /// The bucket written into.
    pub target: &'a str,
    /// The objects' `Content-Type`.
    pub content_type: &'static str,
    /// The canned ACL the service sends (`s3:x-amz-acl`), if any.
    pub canned_acl: Option<&'static str>,
    /// The objects' ACL; `None` is private.
    pub acl: Option<Acl>,
    /// The encryption asked for, over the target's default.
    pub encryption: Option<Encryption<'a>>,
}

/// The encryption a delivery asks for.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Encryption<'a> {
    /// SSE-S3.
    S3,
    /// SSE-KMS with this key.
    Kms(&'a str),
}

impl Delivery<'_> {
    /// Whether the service may write `key` in the target for the source, as the
    /// account's drive: what the target's policy and ACL (in `rules`) say of
    /// `s3:PutObject` by the service with `aws:SourceArn` the source bucket,
    /// `aws:SourceAccount` the account, and the canned ACL it sends.
    pub(crate) fn allowed(&self, account: &str, key: &str, rules: &BucketRules) -> bool {
        let identity = Identity::service(self.service);
        let mut context = identity
            .context(Date::now())
            .with_source(&bucket_arn(self.source), account)
            .with_region(REGION)
            .with_resource_account(account);
        if let Some(acl) = self.canned_acl {
            context = context.with(S3Key::Acl, acl);
        }
        access::allows(
            &identity,
            &context,
            "s3:PutObject",
            &object_arn(self.target, key),
            Some(rules),
        )
    }
}

/// Why something wasn't delivered.
#[derive(Debug)]
pub(crate) enum Undelivered {
    /// The target won't take it: it's given up.
    Refused(String),
    /// It may yet: tried again later.
    Failed(String),
}

/// What an error writing the object means for the delivery.
impl From<S3Error> for Undelivered {
    fn from(err: S3Error) -> Self {
        let why = err
            .message()
            .map_or_else(|| err.code().as_str().to_owned(), str::to_owned);
        match err.code() {
            S3ErrorCode::InternalError
            | S3ErrorCode::ServiceUnavailable
            | S3ErrorCode::SlowDown => Self::Failed(why),
            _ => Self::Refused(why),
        }
    }
}

#[cfg(test)]
mod tests {
    use s3s::s3_error;

    use super::*;

    #[tokio::test]
    async fn a_delivery_writes_its_acl_and_type() {
        use teifs_store::{Layout, Store};
        use teifs_types::{AclGrant, Grantee, Permission};

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.create_bucket("logs", Layout::Folder).await.unwrap();
        let notifier = std::sync::Arc::new(teifs_notify::Notifier::none());
        let drive = crate::drive::Drive::new(store.clone(), Layout::Object, false, notifier, None);
        let mut acl = Acl::private();
        acl.grants.push(AclGrant {
            grantee: Grantee::AllUsers,
            permission: Permission::Read,
        });
        let delivery = Delivery {
            service: "logging.s3.amazonaws.com",
            source: "app",
            target: "logs",
            content_type: "text/plain",
            canned_acl: None,
            acl: Some(acl.clone()),
            encryption: None,
        };
        drive
            .deliver(&delivery, "log", bytes::Bytes::from_static(b"x"))
            .await
            .unwrap();
        let info = store.head("logs", "log").await.unwrap();
        assert_eq!(info.attrs.acl, Some(acl));
        assert_eq!(info.attrs.content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn only_passing_errors_are_tried_again() {
        assert!(matches!(
            Undelivered::from(s3_error!(InternalError, "disk")),
            Undelivered::Failed(why) if why == "disk"
        ));
        assert!(matches!(
            Undelivered::from(s3_error!(SlowDown)),
            Undelivered::Failed(_)
        ));
        assert!(matches!(
            Undelivered::from(s3_error!(ServiceUnavailable)),
            Undelivered::Failed(_)
        ));
        assert!(matches!(
            Undelivered::from(s3_error!(NoSuchBucket)),
            Undelivered::Refused(_)
        ));
        assert!(matches!(
            Undelivered::from(s3_error!(AccessDenied, "locked")),
            Undelivered::Refused(_)
        ));
    }
}
