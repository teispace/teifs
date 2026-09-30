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
    /// `x-amz-server-side-encryption-bucket-key-enabled`: SSE-KMS only, over the
    /// bucket's setting.
    pub bucket_key: Option<bool>,
    pub customer: Option<CustomerKey>,
}

/// Whether a request carries an SSE-C key or its details, for itself or a copy source:
/// such requests are refused over connections that aren't secure, whatever they do, so
/// keys never travel in the clear.
pub(crate) fn names_customer_key(headers: &http::HeaderMap) -> bool {
    headers.keys().any(|name| {
        let name = name.as_str();
        name.starts_with("x-amz-server-side-encryption-customer-")
            || name.starts_with("x-amz-copy-source-server-side-encryption-customer-")
    })
}

/// S3's answer to an SSE-C key sent over plain HTTP.
pub(crate) const CUSTOMER_KEY_NEEDS_TLS: &str = "Requests specifying Server Side Encryption with Customer provided keys must be made over a secure connection.";

/// Decides a write's encryption: what the request asks for, else the bucket's default.
/// (Whether the connection may carry an SSE-C key was decided before: see
/// [`names_customer_key`].)
pub(crate) fn for_write(
    request: WriteRequest<'_>,
    bucket: Option<&BucketEncryption>,
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
        return Ok(Encryption::Customer(key));
    }
    match request.sse.map(dto::ServerSideEncryption::as_str) {
        None => {
            if request.kms_key.is_some() {
                return Err(s3_error!(
                    InvalidArgument,
                    "x-amz-server-side-encryption-aws-kms-key-id needs x-amz-server-side-encryption: aws:kms or aws:kms:dsse"
                ));
            }
            Ok(bucket.map_or(Encryption::None, |b| match b.default.mode {
                SseMode::Kms => Encryption::Kms {
                    key: b.default.kms_key.clone(),
                    context: BTreeMap::new(),
                    bucket_key: request.bucket_key.unwrap_or(b.default.bucket_key),
                },
                SseMode::Dsse => Encryption::Dsse {
                    key: b.default.kms_key.clone(),
                    context: BTreeMap::new(),
                },
                SseMode::S3 | SseMode::Customer => Encryption::S3,
            }))
        }
        Some(dto::ServerSideEncryption::AES256) => {
            if request.kms_key.is_some() {
                return Err(s3_error!(
                    InvalidArgument,
                    "A KMS key can only be given with aws:kms or aws:kms:dsse"
                ));
            }
            Ok(Encryption::S3)
        }
        Some(dto::ServerSideEncryption::AWS_KMS) => Ok(Encryption::Kms {
            key: request.kms_key.map(kms_key_name),
            context: kms_context(request.kms_context)?,
            bucket_key: request
                .bucket_key
                .unwrap_or_else(|| bucket.is_some_and(|b| b.default.bucket_key)),
        }),
        // S3 Bucket Keys don't apply to DSSE-KMS.
        Some(dto::ServerSideEncryption::AWS_KMS_DSSE) => Ok(Encryption::Dsse {
            key: request.kms_key.map(kms_key_name),
            context: kms_context(request.kms_context)?,
        }),
        Some(_) => Err(s3_error!(
            InvalidArgument,
            "x-amz-server-side-encryption must be AES256, aws:kms or aws:kms:dsse"
        )),
    }
}

/// A KMS key named by an ARN (`arn:aws:kms:…:key/<name>`) or directly.
pub(crate) fn kms_key_name(id: &str) -> String {
    id.rsplit_once(":key/")
        .map_or(id, |(_, name)| name)
        .to_owned()
}

/// What `UpdateObjectEncryption` asks for: the KMS key (by name) and whether to report an
/// S3 Bucket Key. S3 takes SSE-KMS only, with a key's full ARN.
pub(crate) fn update_target(encryption: dto::ObjectEncryption) -> S3Result<(String, bool)> {
    let dto::ObjectEncryption::SSEKMS(kms) = encryption else {
        return Err(s3_error!(
            InvalidRequest,
            "Requests that modify an object encryption configuration require a valid new encryption type. Valid values are SSEKMS."
        ));
    };
    let name = key_arn_name(&kms.kms_key_arn).ok_or_else(|| {
        s3_error!(
            InvalidRequest,
            "Requests that modify an object's encryption type to SSE-KMS require a valid AWS KMS key Amazon Resource Name (ARN)."
        )
    })?;
    Ok((name.to_owned(), kms.bucket_key_enabled.unwrap_or(false)))
}

/// The key name in a KMS key ARN, `arn:aws[-a-z0-9]*:kms:[-a-z0-9]*:<12 digits>:key/<name>`
/// (as S3 requires it: no alias, no bare key id).
fn key_arn_name(arn: &str) -> Option<&str> {
    let mut fields = arn.splitn(6, ':');
    let (Some("arn"), Some(partition), Some("kms"), Some(region), Some(account), Some(rest)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return None;
    };
    let lower = |s: &str| {
        s.bytes()
            .all(|b| b == b'-' || b.is_ascii_lowercase() || b.is_ascii_digit())
    };
    let name = rest.strip_prefix("key/").filter(|n| !n.is_empty())?;
    (partition.starts_with("aws")
        && lower(partition)
        && lower(region)
        && account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit()))
    .then_some(name)
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
    /// `x-amz-server-side-encryption-bucket-key-enabled`, sent only when true.
    pub bucket_key: Option<bool>,
}

pub(crate) fn headers(info: Option<&SseInfo>) -> Headers {
    let Some(info) = info else {
        return Headers {
            sse: None,
            kms_key: None,
            customer_algorithm: None,
            customer_key_md5: None,
            bucket_key: None,
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
            bucket_key: None,
        },
        SseMode::Kms => Headers {
            sse: Some(dto::ServerSideEncryption::from_static(
                dto::ServerSideEncryption::AWS_KMS,
            )),
            kms_key: info.kms_key.clone(),
            customer_algorithm: None,
            customer_key_md5: None,
            bucket_key: info.bucket_key.then_some(true),
        },
        SseMode::Dsse => Headers {
            sse: Some(dto::ServerSideEncryption::from_static(
                dto::ServerSideEncryption::AWS_KMS_DSSE,
            )),
            kms_key: info.kms_key.clone(),
            customer_algorithm: None,
            customer_key_md5: None,
            bucket_key: None,
        },
        SseMode::Customer => Headers {
            sse: None,
            kms_key: None,
            customer_algorithm: Some("AES256".to_owned()),
            customer_key_md5: info.customer_key_md5.clone(),
            bucket_key: None,
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
        $out.bucket_key_enabled = h.bucket_key;
    }};
}
pub(crate) use set_sse;

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};
    use teifs_store::DefaultEncryption;

    fn key() -> (String, String) {
        let raw = [9u8; 32];
        (STANDARD.encode(raw), STANDARD.encode(Md5::digest(raw)))
    }

    fn request(sse: Option<&dto::ServerSideEncryption>) -> WriteRequest<'_> {
        WriteRequest {
            sse,
            kms_key: None,
            kms_context: None,
            bucket_key: None,
            customer: None,
        }
    }

    #[test]
    fn updates_name_a_kms_key_by_its_full_arn() {
        let target = |arn: &str, bucket_key| {
            update_target(dto::ObjectEncryption::SSEKMS(dto::SSEKMSEncryption {
                kms_key_arn: arn.to_owned(),
                bucket_key_enabled: bucket_key,
            }))
        };
        assert_eq!(
            target("arn:aws:kms:us-east-1:111122223333:key/photos", Some(true)).unwrap(),
            ("photos".to_owned(), true)
        );
        assert_eq!(
            target("arn:aws-cn:kms:cn-north-1:000000000000:key/a:b", None).unwrap(),
            ("a:b".to_owned(), false)
        );
        for bad in [
            "photos",
            "arn:aws:kms:us-east-1:111122223333:alias/photos",
            "arn:aws:kms:us-east-1:1111:key/photos",
            "arn:aws:kms:us-east-1:11112222333a:key/photos",
            "arn:aws:s3:us-east-1:111122223333:key/photos",
            "arn:aws:kms:us-east-1:111122223333:key/",
            "arn:gcp:kms:us-east-1:111122223333:key/photos",
            "arn:aws:kms:US-EAST-1:111122223333:key/photos",
        ] {
            assert!(target(bad, None).is_err(), "{bad}");
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
            for_write(request(None), Some(&default)).unwrap(),
            Encryption::S3
        ));
        assert!(matches!(
            for_write(request(None), None).unwrap(),
            Encryption::None
        ));
        let kms = dto::ServerSideEncryption::from_static(dto::ServerSideEncryption::AWS_KMS);
        let with_key = WriteRequest {
            kms_key: Some("arn:aws:kms:us-east-1:123:key/photos"),
            ..request(Some(&kms))
        };
        assert!(matches!(
            for_write(with_key, Some(&default)).unwrap(),
            Encryption::Kms { key: Some(k), .. } if k == "photos"
        ));
    }

    #[test]
    fn dual_layer_writes_follow_the_request_then_the_bucket() {
        let dsse = dto::ServerSideEncryption::from_static(dto::ServerSideEncryption::AWS_KMS_DSSE);
        let asked = WriteRequest {
            kms_key: Some("arn:aws:kms:us-east-1:123:key/photos"),
            bucket_key: Some(true),
            ..request(Some(&dsse))
        };
        assert!(matches!(
            for_write(asked, Some(&BucketEncryption::aws_default())).unwrap(),
            Encryption::Dsse { key: Some(k), .. } if k == "photos"
        ));
        let by_default = BucketEncryption {
            default: DefaultEncryption {
                mode: SseMode::Dsse,
                kms_key: Some("photos".into()),
                bucket_key: true,
            },
            ..BucketEncryption::aws_default()
        };
        assert!(matches!(
            for_write(request(None), Some(&by_default)).unwrap(),
            Encryption::Dsse { key: Some(k), .. } if k == "photos"
        ));
        let aes = dto::ServerSideEncryption::from_static(dto::ServerSideEncryption::AES256);
        let key_with_aes = WriteRequest {
            kms_key: Some("photos"),
            ..request(Some(&aes))
        };
        assert!(for_write(key_with_aes, None).is_err());
        let other = dto::ServerSideEncryption::from_static("aws:kms:other");
        assert!(for_write(request(Some(&other)), None).is_err());
        let reported = headers(Some(&SseInfo {
            mode: SseMode::Dsse,
            kms_key: Some("photos".into()),
            customer_key_md5: None,
            bucket_key: true,
        }));
        assert_eq!(
            (
                reported.sse.as_ref().map(dto::ServerSideEncryption::as_str),
                reported.kms_key.as_deref(),
                reported.bucket_key
            ),
            (Some("aws:kms:dsse"), Some("photos"), None)
        );
    }

    #[test]
    fn bucket_keys_follow_the_request_then_the_bucket() {
        let bucket_key = |encryption| match encryption {
            Encryption::Kms { bucket_key, .. } => Some(bucket_key),
            _ => None,
        };
        let kms = dto::ServerSideEncryption::from_static(dto::ServerSideEncryption::AWS_KMS);
        let asking = |sse, bucket_key| WriteRequest {
            bucket_key,
            ..request(sse)
        };
        let plain = BucketEncryption::aws_default();
        let keyed = BucketEncryption {
            default: DefaultEncryption {
                mode: SseMode::Kms,
                kms_key: None,
                bucket_key: true,
            },
            ..BucketEncryption::aws_default()
        };
        let with_bucket_key = BucketEncryption {
            default: DefaultEncryption {
                mode: SseMode::S3,
                ..keyed.default.clone()
            },
            ..BucketEncryption::aws_default()
        };
        let cases = [
            // The bucket's default SSE-KMS with its setting, unless the request says.
            (asking(None, None), &keyed, Some(true)),
            (asking(None, Some(false)), &keyed, Some(false)),
            // Asking for SSE-KMS: the request, else the bucket's setting.
            (asking(Some(&kms), None), &plain, Some(false)),
            (asking(Some(&kms), Some(true)), &plain, Some(true)),
            (asking(Some(&kms), None), &with_bucket_key, Some(true)),
            // SSE-S3 has none.
            (asking(None, Some(true)), &plain, None),
        ];
        for (i, (request, bucket, expected)) in cases.into_iter().enumerate() {
            assert_eq!(
                bucket_key(for_write(request, Some(bucket)).unwrap()),
                expected,
                "{i}"
            );
        }
    }

    #[test]
    fn sse_c_is_blocked_by_default() {
        let (k, m) = key();
        let customer = || WriteRequest {
            customer: customer_key(Some("AES256"), Some(&k), Some(&m)).unwrap(),
            ..request(None)
        };
        let default = BucketEncryption::aws_default();
        assert!(for_write(customer(), Some(&default)).is_err());
        let allowed = BucketEncryption {
            block_customer_keys: false,
            ..default
        };
        assert!(matches!(
            for_write(customer(), Some(&allowed)).unwrap(),
            Encryption::Customer(_)
        ));
        let aes = dto::ServerSideEncryption::from_static(dto::ServerSideEncryption::AES256);
        let both = WriteRequest {
            sse: Some(&aes),
            ..customer()
        };
        assert!(for_write(both, Some(&allowed)).is_err());
    }
}
