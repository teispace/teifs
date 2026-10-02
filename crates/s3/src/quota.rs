//! Bucket quotas, as `MinIO`'s: a hard limit on the bytes a bucket holds, set and read
//! through `MinIO`'s admin API (`mc quota`, `teifs quota`) and checked before each write.
//!
//! As on `MinIO`, a write is refused when what the bucket holds (every version) and what's
//! written would reach the quota, checked before the body is read; uploads that run at
//! once can pass it together, and a bucket over its quota (a quota set below what it
//! holds) takes no more writes until it's under again.

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use s3s::{Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result};
use serde::{Deserialize, Serialize};
use teifs_store::Store;

use crate::{
    errors::StoreResultExt,
    routes::{s3_refusal, signed_body},
};

/// The largest quota configuration read.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// A quota as `MinIO`'s admin API takes and answers it (`madmin.BucketQuota`).
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct BucketQuota {
    /// The limit as older clients (`mc quota set`) send it.
    #[serde(default)]
    quota: u64,
    /// The limit, in bytes.
    #[serde(default)]
    size: u64,
    /// Bandwidth, which `MinIO` takes and doesn't enforce.
    #[serde(default)]
    rate: u64,
    /// Requests, which `MinIO` takes and doesn't enforce.
    #[serde(default)]
    requests: u64,
    /// `hard`, the only kind there is.
    #[serde(default, rename = "quotatype", skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
}

/// The only kind of quota.
const HARD: &str = "hard";

/// A quota of `bytes`, which must be some.
pub(crate) fn size(bytes: u64) -> S3Result<u64> {
    if bytes == 0 {
        return Err(invalid("a quota is a number of bytes above 0"));
    }
    Ok(bytes)
}

/// Refuses a write of `incoming` bytes to `bucket` when it would reach the bucket's
/// quota, as `MinIO` does.
pub(crate) async fn check(store: &Store, bucket: &str, incoming: u64) -> S3Result<()> {
    let Some(quota) = store.bucket_quota(bucket).await.s3()? else {
        return Ok(());
    };
    let held = store.bucket_usage(bucket).await.s3()?.bytes;
    if held.saturating_add(incoming) >= quota {
        return Err(exceeded());
    }
    Ok(())
}

/// `MinIO`'s refusal of a write past a quota.
fn exceeded() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("XMinioAdminBucketQuotaExceeded".into()),
        "Bucket quota exceeded",
    );
    err.set_status_code(StatusCode::BAD_REQUEST);
    err
}

fn invalid(message: &str) -> S3Error {
    let mut err = S3Error::with_message(S3ErrorCode::InvalidArgument, message.to_owned());
    err.set_status_code(StatusCode::BAD_REQUEST);
    err
}

/// `PUT set-bucket-quota?bucket=NAME`: sets the bucket's quota, or with no size clears
/// it (`mc quota clear`).
pub(crate) async fn set(
    store: &Store,
    bucket: &str,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    store.head_bucket(bucket).await.s3()?;
    let body = signed_body(&mut req, MAX_BODY_BYTES)
        .await
        .map_err(s3_refusal)?;
    let quota = read(&body)?;
    store.set_bucket_quota(bucket, quota).await.s3()?;
    Ok(S3Response::new(Body::empty()))
}

/// The quota a body sets: `None` clears it.
pub(crate) fn read(body: &Bytes) -> S3Result<Option<u64>> {
    // An object only: serde would take an array as a struct's fields, `MinIO` doesn't.
    let given: BucketQuota = serde_json::from_slice(body)
        .and_then(|fields| serde_json::from_value(serde_json::Value::Object(fields)))
        .map_err(|e| invalid(&format!("The body isn't a bucket quota: {e}")))?;
    let bytes = if given.size > 0 {
        given.size
    } else {
        given.quota
    };
    if bytes == 0 {
        return Ok(None);
    }
    // `MinIO` ignores a size without the kind; a quota that's never checked is refused.
    if given.kind.as_deref() != Some(HARD) {
        return Err(invalid(
            "Invalid quota config: a quota's type (quotatype) must be \"hard\"",
        ));
    }
    Ok(Some(bytes))
}

/// A quota (`None`: none) as `MinIO` answers it, zero when there's none.
pub(crate) fn to_json(quota: Option<u64>) -> Vec<u8> {
    let answer = quota.map_or_else(BucketQuota::default, |bytes| BucketQuota {
        quota: bytes,
        size: bytes,
        kind: Some(HARD.to_owned()),
        ..BucketQuota::default()
    });
    serde_json::to_vec(&answer).expect("a quota serializes")
}

/// `GET get-bucket-quota?bucket=NAME`: the bucket's quota, zero when it has none, as
/// `MinIO` answers it.
pub(crate) async fn get(store: &Store, bucket: &str) -> S3Result<S3Response<Body>> {
    store.head_bucket(bucket).await.s3()?;
    let quota = store.bucket_quota(bucket).await.s3()?;
    let mut response = S3Response::new(Body::from(to_json(quota)));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    fn read_json(json: &str) -> S3Result<Option<u64>> {
        read(&Bytes::from(json.to_owned()))
    }

    #[test]
    fn quotas_are_read_as_minio_clients_send_them() {
        // `mc quota set` (the older field), newer clients (`size`), `mc quota clear`.
        assert_eq!(
            read_json(r#"{"quota":1024,"quotatype":"hard"}"#).unwrap(),
            Some(1024)
        );
        assert_eq!(
            read_json(r#"{"quota":0,"size":2048,"rate":0,"requests":0,"quotatype":"hard"}"#)
                .unwrap(),
            Some(2048)
        );
        assert_eq!(
            read_json(r#"{"quota":0,"size":0,"rate":0,"requests":0}"#).unwrap(),
            None
        );
        assert_eq!(read_json("{}").unwrap(), None);
        for bad in [
            r#"{"size":1}"#,
            r#"{"size":1,"quotatype":"fifo"}"#,
            r#"{"size":-1,"quotatype":"hard"}"#,
            "[]",
            "",
        ] {
            let err = read_json(bad).unwrap_err();
            assert_eq!(err.code(), &S3ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(err.status_code(), Some(StatusCode::BAD_REQUEST), "{bad}");
        }
    }

    #[test]
    fn a_quota_is_some_bytes() {
        assert_eq!(size(1).unwrap(), 1);
        assert!(size(0).is_err());
        let err = exceeded();
        assert_eq!(err.status_code(), Some(StatusCode::BAD_REQUEST));
        assert_eq!(err.message(), Some("Bucket quota exceeded"));
    }
}
