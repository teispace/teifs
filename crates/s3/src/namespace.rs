//! Bucket namespaces (`x-amz-bucket-namespace` on `CreateBucket`): a name ending in
//! `-<account id>-<region>-an` is in that account's regional namespace, which only that
//! account creates buckets in, and only when it asks for that namespace.

use s3s::{S3Error, S3ErrorCode, S3Result, dto::BucketNamespace};

use crate::drive::REGION;

/// The suffix every bucket in an account regional namespace ends with.
const SUFFIX: &str = "-an";

/// The account and region a bucket name's account regional suffix names, if it has one:
/// `<prefix>-<12 digits>-<region>-an`, with a prefix and a region that aren't empty.
fn regional_suffix(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_suffix(SUFFIX)?;
    let bytes = rest.as_bytes();
    // The last `-<12 digits>-` with a prefix before it and a region after it.
    (1..bytes.len().saturating_sub(13))
        .rev()
        .find(|&i| {
            bytes[i] == b'-'
                && bytes[i + 13] == b'-'
                && i + 14 < bytes.len()
                && bytes[i + 1..i + 13].iter().all(u8::is_ascii_digit)
        })
        .map(|i| (&rest[i + 1..i + 13], &rest[i + 14..]))
}

/// Checks a new bucket's name against the namespace the request asks for, as S3 does:
/// a name ending in `-an` only in the account regional namespace, and there only with
/// the requesting account's id (`account`, when IAM decides requests) and this
/// server's region.
pub(crate) fn check(
    bucket: &str,
    namespace: Option<&BucketNamespace>,
    account: Option<&str>,
) -> S3Result<()> {
    match namespace.map(BucketNamespace::as_str) {
        None | Some(BucketNamespace::GLOBAL) => {
            if bucket.ends_with(SUFFIX) {
                return Err(S3Error::with_message(
                    S3ErrorCode::InvalidBucketName,
                    "Bucket names can only end with the suffix -an when you create buckets in \
                     your account regional namespace (x-amz-bucket-namespace: account-regional).",
                ));
            }
            Ok(())
        }
        Some(BucketNamespace::ACCOUNT_REGIONAL) => {
            let Some((named, region)) = regional_suffix(bucket) else {
                return Err(error(
                    "InvalidNamespaceHeader",
                    "The requested bucket name did not include the account-regional namespace \
                     suffix, but the provided x-amz-bucket-namespace header value is \
                     account-regional. Specify -[accountId]-[region]-an as the bucket name \
                     suffix to create a bucket in your account-regional namespace, or remove \
                     the header.",
                ));
            };
            if account.is_some_and(|account| account != named) {
                return Err(S3Error::with_message(
                    S3ErrorCode::AccessDenied,
                    "The bucket name's account regional suffix names another account; only \
                     that account can create buckets in its namespace.",
                ));
            }
            if region != REGION {
                return Err(error(
                    "IllegalLocationConstraintException",
                    format!(
                        "The bucket name's account regional suffix names the {region} region; \
                         buckets here are created in {REGION}."
                    ),
                ));
            }
            Ok(())
        }
        Some(other) => Err(S3Error::with_message(
            S3ErrorCode::InvalidArgument,
            format!("x-amz-bucket-namespace must be account-regional or global, not {other}"),
        )),
    }
}

/// A `400 Bad Request` with an error code s3s doesn't name.
fn error(code: &str, message: impl Into<String>) -> S3Error {
    let mut err =
        S3Error::with_message(S3ErrorCode::Custom(code.to_owned().into()), message.into());
    err.set_status_code(http::StatusCode::BAD_REQUEST);
    err
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "111122223333";

    fn code(
        bucket: &str,
        namespace: Option<&'static str>,
        account: Option<&str>,
    ) -> Option<String> {
        let namespace = namespace.map(BucketNamespace::from_static);
        check(bucket, namespace.as_ref(), account)
            .err()
            .map(|e| e.code().as_str().to_owned())
    }

    #[test]
    fn the_suffix_names_an_account_and_a_region() {
        assert_eq!(
            regional_suffix("logs-111122223333-us-west-2-an"),
            Some(("111122223333", "us-west-2"))
        );
        // The last account-like part is the account: the prefix may hold digits too.
        assert_eq!(
            regional_suffix("a-999988887777-x-111122223333-eu-north-1-an"),
            Some(("111122223333", "eu-north-1"))
        );
        for name in [
            "logs-an",
            "logs-us-east-1-an",
            "111122223333-us-east-1-an",
            "logs-11112222333-us-east-1-an",
            "logs-111122223333--an",
            "logs-111122223333-us-east-1",
        ] {
            assert_eq!(regional_suffix(name), None, "{name}");
        }
    }

    #[test]
    fn names_ending_in_an_need_the_account_regional_namespace() {
        let name = "logs-111122223333-us-east-1-an";
        assert_eq!(
            code(name, None, Some(ACCOUNT)).as_deref(),
            Some("InvalidBucketName")
        );
        assert_eq!(
            code("plan-an", Some(BucketNamespace::GLOBAL), None).as_deref(),
            Some("InvalidBucketName")
        );
        assert_eq!(code("my-plan", None, Some(ACCOUNT)), None);
        assert_eq!(
            code(name, Some(BucketNamespace::ACCOUNT_REGIONAL), Some(ACCOUNT)),
            None
        );
        // Without IAM there's no account to compare with.
        assert_eq!(
            code(name, Some(BucketNamespace::ACCOUNT_REGIONAL), None),
            None
        );
    }

    #[test]
    fn the_account_regional_namespace_is_the_callers_and_this_regions() {
        let regional = Some(BucketNamespace::ACCOUNT_REGIONAL);
        assert_eq!(
            code("logs", regional, Some(ACCOUNT)).as_deref(),
            Some("InvalidNamespaceHeader")
        );
        assert_eq!(
            code("logs-444455556666-us-east-1-an", regional, Some(ACCOUNT)).as_deref(),
            Some("AccessDenied")
        );
        assert_eq!(
            code("logs-111122223333-eu-west-1-an", regional, Some(ACCOUNT)).as_deref(),
            Some("IllegalLocationConstraintException")
        );
        assert_eq!(
            code("logs", Some("elsewhere"), Some(ACCOUNT)).as_deref(),
            Some("InvalidArgument")
        );
    }
}
