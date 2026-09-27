//! Server-side encryption as S3 requests express it: the SSE headers of a write, the
//! customer key (SSE-C) of a read, the bucket's default, and the response headers.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use s3s::{S3Result, dto, s3_error};
use teifs_store::{BucketEncryption, CustomerKey, Encryption, SseInfo, SseMode};

/// A request's SSE-C headers: none, or a valid key.
pub(crate) fn customer_key(
    algorithm: Option<&str>,
    key: Option<&str>,
    key_md5: Option<&str>,
) -> S3Result<Option<CustomerKey>> {
    match (algorithm, key, key_md5) {
        (None, None, None) => Ok(None),
        (Some(algorithm), Some(key), Some(md5)) => {
            if algorithm != "AES256" {
                return Err(s3_error!(
                    InvalidEncryptionAlgorithmError,
                    "The encryption request you specified is not valid. The valid value is AES256."
                ));
            }
            CustomerKey::parse(algorithm, key, md5)
                .map(Some)
                .map_err(|_| {
                    s3_error!(
                        InvalidArgument,
                        "The calculated MD5 hash of the key did not match the hash that was provided."
                    )
                })
        }
        _ => Err(s3_error!(
            InvalidArgument,
            "Requests specifying Server Side Encryption with Customer provided keys must provide an appropriate secret key."
        )),
    }
}

/// What a write asks for.
pub(crate) struct WriteRequest<'a> {
    pub sse: Option<&'a dto::ServerSideEncryption>,
    pub kms_key: Option<&'a str>,
    pub kms_context: Option<&'a str>,
    pub customer: Option<CustomerKey>,
}

/// Decides a write's encryption: what the request asks for, else the bucket's default.
/// `secure` is whether the request came over TLS (or a trusted local connection):
/// SSE-C keys never travel in the clear.
pub(crate) fn for_write(
    request: WriteRequest<'_>,
    bucket: Option<&BucketEncryption>,
    secure: bool,
) -> S3Result<Encryption> {
    if let Some(key) = request.customer {
        if request.sse.is_some() || request.kms_key.is_some() {
            return Err(s3_error!(
                InvalidArgument,
                "Server Side Encryption with Customer provided key is incompatible with the encryption method specified"
            ));
        }
        let Some(bucket) = bucket else {
            return Err(s3_error!(
                InvalidRequest,
                "encryption at rest needs an object bucket; this is a folder bucket"
            ));
        };
        if bucket.block_customer_keys {
            return Err(s3_error!(
                AccessDenied,
                "SSE-C is blocked for this bucket; PutBucketEncryption can allow it"
            ));
        }
        if !secure {
            return Err(s3_error!(
                InvalidRequest,
                "Requests specifying Server Side Encryption with Customer provided keys must be made over a secure connection."
            ));
        }
        return Ok(Encryption::Customer(key));
    }
    match request.sse.map(dto::ServerSideEncryption::as_str) {
        None => {
            if request.kms_key.is_some() {
                return Err(s3_error!(
                    InvalidArgument,
                    "x-amz-server-side-encryption-aws-kms-key-id needs x-amz-server-side-encryption: aws:kms"
                ));
            }
            Ok(bucket.map_or(Encryption::None, |b| match b.default.mode {
                SseMode::Kms => Encryption::Kms {
                    key: b.default.kms_key.clone(),
                    context: BTreeMap::new(),
                },
                _ => Encryption::S3,
            }))
        }
        Some(dto::ServerSideEncryption::AES256) => {
            if request.kms_key.is_some() {
                return Err(s3_error!(
                    InvalidArgument,
                    "A KMS key can only be given with aws:kms"
                ));
            }
            Ok(Encryption::S3)
        }
        Some(dto::ServerSideEncryption::AWS_KMS) => Ok(Encryption::Kms {
            key: request.kms_key.map(kms_key_name),
            context: kms_context(request.kms_context)?,
        }),
        Some(dto::ServerSideEncryption::AWS_KMS_DSSE) => Err(s3_error!(
            NotImplemented,
            "dual-layer encryption (aws:kms:dsse) isn't supported"
        )),
        Some(_) => Err(s3_error!(
            InvalidArgument,
            "x-amz-server-side-encryption must be AES256 or aws:kms"
        )),
    }
}

/// A KMS key named by an ARN (`arn:aws:kms:…:key/<name>`) or directly.
pub(crate) fn kms_key_name(id: &str) -> String {
    id.rsplit_once(":key/")
        .map_or(id, |(_, name)| name)
        .to_owned()
}

/// `x-amz-server-side-encryption-context`: base64 of a JSON object of strings.
fn kms_context(header: Option<&str>) -> S3Result<BTreeMap<String, String>> {
    let Some(header) = header else {
        return Ok(BTreeMap::new());
    };
    let invalid = || {
        s3_error!(
            InvalidArgument,
            "the encryption context must be base64 of a JSON object of strings"
        )
    };
    let bytes = STANDARD.decode(header).map_err(|_| invalid())?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

/// The response headers that describe an object's encryption.
pub(crate) struct Headers {
    pub sse: Option<dto::ServerSideEncryption>,
    pub kms_key: Option<String>,
    pub customer_algorithm: Option<String>,
    pub customer_key_md5: Option<String>,
}

pub(crate) fn headers(info: Option<&SseInfo>) -> Headers {
    let Some(info) = info else {
        return Headers {
            sse: None,
            kms_key: None,
            customer_algorithm: None,
            customer_key_md5: None,
        };
    };
    match info.mode {
        SseMode::S3 => Headers {
            sse: Some(dto::ServerSideEncryption::from_static(
                dto::ServerSideEncryption::AES256,
            )),
            kms_key: None,
            customer_algorithm: None,
            customer_key_md5: None,
        },
        SseMode::Kms => Headers {
            sse: Some(dto::ServerSideEncryption::from_static(
                dto::ServerSideEncryption::AWS_KMS,
            )),
            kms_key: info.kms_key.clone(),
            customer_algorithm: None,
            customer_key_md5: None,
        },
        SseMode::Customer => Headers {
            sse: None,
            kms_key: None,
            customer_algorithm: Some("AES256".to_owned()),
            customer_key_md5: info.customer_key_md5.clone(),
        },
    }
}

/// Sets an output struct's encryption fields from [`Headers`].
macro_rules! set_sse {
    ($out:expr, $info:expr) => {{
        let h = crate::sse::headers($info);
        $out.server_side_encryption = h.sse;
        $out.ssekms_key_id = h.kms_key;
        $out.sse_customer_algorithm = h.customer_algorithm;
        $out.sse_customer_key_md5 = h.customer_key_md5;
    }};
}
pub(crate) use set_sse;

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};

    fn key() -> (String, String) {
        let raw = [9u8; 32];
        (STANDARD.encode(raw), STANDARD.encode(Md5::digest(raw)))
    }

    fn request(sse: Option<&dto::ServerSideEncryption>) -> WriteRequest<'_> {
        WriteRequest {
            sse,
            kms_key: None,
            kms_context: None,
            customer: None,
        }
    }

    #[test]
    fn customer_keys_need_all_three_headers() {
        let (k, m) = key();
        assert!(customer_key(None, None, None).unwrap().is_none());
        assert!(
            customer_key(Some("AES256"), Some(&k), Some(&m))
                .unwrap()
                .is_some()
        );
        assert!(customer_key(Some("AES256"), Some(&k), None).is_err());
        assert!(customer_key(Some("AES256"), Some(&k), Some("bad")).is_err());
        assert!(customer_key(Some("aws:kms"), Some(&k), Some(&m)).is_err());
    }

    #[test]
    fn writes_follow_the_request_then_the_bucket() {
        let default = BucketEncryption::aws_default();
        assert!(matches!(
            for_write(request(None), Some(&default), true).unwrap(),
            Encryption::S3
        ));
        assert!(matches!(
            for_write(request(None), None, true).unwrap(),
            Encryption::None
        ));
        let kms = dto::ServerSideEncryption::from_static(dto::ServerSideEncryption::AWS_KMS);
        let with_key = WriteRequest {
            kms_key: Some("arn:aws:kms:us-east-1:123:key/photos"),
            ..request(Some(&kms))
        };
        assert!(matches!(
            for_write(with_key, Some(&default), true).unwrap(),
            Encryption::Kms { key: Some(k), .. } if k == "photos"
        ));
    }

    #[test]
    fn sse_c_is_blocked_by_default_and_needs_a_secure_connection() {
        let (k, m) = key();
        let customer = || WriteRequest {
            customer: customer_key(Some("AES256"), Some(&k), Some(&m)).unwrap(),
            ..request(None)
        };
        let default = BucketEncryption::aws_default();
        assert!(for_write(customer(), Some(&default), true).is_err());
        let allowed = BucketEncryption {
            block_customer_keys: false,
            ..default
        };
        assert!(for_write(customer(), Some(&allowed), false).is_err());
        assert!(matches!(
            for_write(customer(), Some(&allowed), true).unwrap(),
            Encryption::Customer(_)
        ));
        let aes = dto::ServerSideEncryption::from_static(dto::ServerSideEncryption::AES256);
        let both = WriteRequest {
            sse: Some(&aes),
            ..customer()
        };
        assert!(for_write(both, Some(&allowed), true).is_err());
    }
}
