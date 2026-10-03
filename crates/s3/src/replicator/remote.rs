//! Sending replicas to a replication target: a bucket on another S3 service (another
//! TeiFS, `MinIO`, AWS…). Each version is one `PutObject` streamed with its
//! `Content-MD5` (which S3 wants of a locked object's write), and never with
//! `aws-chunked` framing, which not every service takes; above 5 GiB, a multipart
//! upload. To services other than AWS go `MinIO`'s replica headers, so another TeiFS or
//! a `MinIO` keeps the version's id, time and ETag.

use std::time::Duration;

use aws_sdk_s3::{
    Client,
    config::{
        BehaviorVersion, Credentials, Region, RequestChecksumCalculation,
        ResponseChecksumValidation, retry::RetryConfig, timeout::TimeoutConfig,
    },
    error::{DisplayErrorContext, ProvideErrorMetadata, SdkError},
    primitives::{ByteStream, DateTime},
    types::{
        CompletedMultipartUpload, CompletedPart, ObjectLockLegalHoldStatus, ObjectLockMode,
        ServerSideEncryption, StorageClass,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures::TryStreamExt as _;
use md5::{Digest as _, Md5};
use teifs_store::{ObjectAttrs, Store};
use teifs_types::{SseMode, md5_of_etag, replication::RemoteTarget};
use tokio::io::AsyncReadExt as _;

use super::{CHUNK, Missed, Sending};
use crate::replica_headers;

/// Larger versions go as multipart uploads (S3's largest `PutObject`).
const MULTIPART_ABOVE: u64 = 5 * 1024 * 1024 * 1024;
/// The smallest part of a multipart upload (more when 10,000 parts wouldn't hold it).
const PART: u64 = 64 * 1024 * 1024;
/// S3's most parts in an upload.
const MOST_PARTS: u64 = 10_000;
/// How long connecting to a target may take.
const CONNECT: Duration = Duration::from_secs(10);

/// A target, with a client signed in to it.
#[derive(Debug)]
pub(super) struct Target {
    client: Client,
    bucket: String,
    /// Its storage class for replicas, when it names one.
    storage_class: Option<String>,
    /// Whether it may be sent `MinIO`'s replica headers (it isn't AWS).
    replica_headers: bool,
}

impl Target {
    /// The target `arn` names, signed in with its keys.
    pub(super) async fn of(store: &Store, arn: &str) -> Result<Self, Missed> {
        let target = store
            .replication_target(arn)
            .await?
            .ok_or_else(|| Missed::Failed(format!("the replication target {arn} was removed")))?;
        let secrets = store.replication_target_secrets(arn).await?;
        let credentials = Credentials::new(
            target.access_key.clone(),
            secrets.secret_key.as_str(),
            secrets
                .session_token
                .as_ref()
                .map(|token| token.as_str().to_owned()),
            None,
            "teifs-replication",
        );
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region(&target)))
            .endpoint_url(endpoint(&target))
            .credentials_provider(credentials)
            .force_path_style(true)
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            // A failed send is tried again on a later pass, with the body read again.
            .retry_config(RetryConfig::disabled())
            .timeout_config(TimeoutConfig::builder().connect_timeout(CONNECT).build())
            .build();
        Ok(Self {
            client: Client::from_conf(config),
            replica_headers: !is_aws(&target.endpoint),
            storage_class: Some(target.storage_class.clone()).filter(|class| !class.is_empty()),
            bucket: target.target_bucket,
        })
    }

    /// Sends a version.
    pub(super) async fn send(&self, sending: Sending<'_>) -> Result<(), Missed> {
        if sending.info.size > MULTIPART_ABOVE {
            self.send_parts(sending).await
        } else {
            self.send_whole(sending).await
        }
    }

    /// Sends a version in one `PutObject`, streamed.
    async fn send_whole(&self, sending: Sending<'_>) -> Result<(), Missed> {
        let md5 = match whole_md5(&sending) {
            Some(md5) => md5,
            // Not known from the ETag: read once to learn it.
            None => self.md5_of(&sending).await?,
        };
        let size = sending.info.size;
        let what = Described::of(&sending.info.attrs, &sending, self);
        let headers = self.headers(&sending);
        let checksums: Vec<(String, String)> = full_object_checksums(&sending.info.attrs)
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        let body = match sending.body {
            Some(body) => {
                let reader = body.all().await?;
                let stream = tokio_util::io::ReaderStream::with_capacity(reader, CHUNK)
                    .map_ok(http_body::Frame::data);
                ByteStream::from_body_1_x(http_body_util::StreamBody::new(stream))
            }
            None => ByteStream::from_static(b""),
        };
        let mut put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(sending.key)
            .content_length(i64::try_from(size).unwrap_or(i64::MAX))
            .content_md5(STANDARD.encode(md5))
            .body(body)
            .set_content_type(what.content_type)
            .set_content_encoding(what.content_encoding)
            .set_content_disposition(what.content_disposition)
            .set_content_language(what.content_language)
            .set_cache_control(what.cache_control)
            .set_expires(what.expires)
            .set_website_redirect_location(what.redirect)
            .set_metadata(what.metadata)
            .set_tagging(what.tagging)
            .set_object_lock_mode(what.lock_mode)
            .set_object_lock_retain_until_date(what.retain_until)
            .set_object_lock_legal_hold_status(what.legal_hold)
            .set_server_side_encryption(what.sse)
            .set_ssekms_key_id(what.kms_key)
            .set_storage_class(what.storage_class);
        for (name, value) in checksums {
            put = match name.as_str() {
                "CRC32" => put.checksum_crc32(value),
                "CRC32C" => put.checksum_crc32_c(value),
                "CRC64NVME" => put.checksum_crc64_nvme(value),
                "SHA1" => put.checksum_sha1(value),
                "SHA256" => put.checksum_sha256(value),
                _ => put,
            };
        }
        // The version's id goes in the query, as minio-go sends it.
        let version_id = (!headers.is_empty()).then(|| sending.replica.version_id.clone());
        put.customize()
            .mutate_request(move |request| {
                for (name, value) in &headers {
                    request.headers_mut().insert(*name, value.clone());
                }
                if let Some(id) = &version_id {
                    let uri = request.uri().to_owned();
                    let joint = if uri.contains('?') { '&' } else { '?' };
                    let named = format!("{uri}{joint}{}={id}", replica_headers::VERSION_ID);
                    // An id is hex and dashes, which a URI always takes.
                    let _ = request.set_uri(named);
                }
            })
            .send()
            .await
            .map_err(|err| missed(&err))?;
        Ok(())
    }

    /// Sends a version as a multipart upload, a part at a time.
    async fn send_parts(&self, sending: Sending<'_>) -> Result<(), Missed> {
        let what = Described::of(&sending.info.attrs, &sending, self);
        let started = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(sending.key)
            .set_content_type(what.content_type)
            .set_content_encoding(what.content_encoding)
            .set_content_disposition(what.content_disposition)
            .set_content_language(what.content_language)
            .set_cache_control(what.cache_control)
            .set_expires(what.expires)
            .set_website_redirect_location(what.redirect)
            .set_metadata(what.metadata)
            .set_tagging(what.tagging)
            .set_object_lock_mode(what.lock_mode)
            .set_object_lock_retain_until_date(what.retain_until)
            .set_object_lock_legal_hold_status(what.legal_hold)
            .set_server_side_encryption(what.sse)
            .set_ssekms_key_id(what.kms_key)
            .set_storage_class(what.storage_class)
            .send()
            .await
            .map_err(|err| missed(&err))?;
        let upload_id = started
            .upload_id
            .ok_or_else(|| Missed::Later("the target didn't start an upload".to_owned()))?;
        let sent = self.upload_parts(&sending, &upload_id).await;
        let completed = match sent {
            Ok(parts) => self
                .client
                .complete_multipart_upload()
                .bucket(&self.bucket)
                .key(sending.key)
                .upload_id(&upload_id)
                .multipart_upload(
                    CompletedMultipartUpload::builder()
                        .set_parts(Some(parts))
                        .build(),
                )
                .send()
                .await
                .map(|_| ())
                .map_err(|err| missed(&err)),
            Err(err) => Err(err),
        };
        if completed.is_err() {
            // Nothing's left behind on the target (a failed abort, its lifecycle's).
            let _ = self
                .client
                .abort_multipart_upload()
                .bucket(&self.bucket)
                .key(sending.key)
                .upload_id(&upload_id)
                .send()
                .await;
        }
        completed
    }

    /// Sends a version's bytes as the parts of `upload_id`.
    async fn upload_parts(
        &self,
        sending: &Sending<'_>,
        upload_id: &str,
    ) -> Result<Vec<CompletedPart>, Missed> {
        let size = sending.info.size;
        let part_size = PART.max(size.div_ceil(MOST_PARTS));
        let (_, body) = sending.reread().await?;
        let mut reader = match body {
            Some(body) => body.all().await?,
            None => return Err(Missed::Later("the version has no bytes".to_owned())),
        };
        let mut parts = Vec::new();
        let mut left = size;
        let mut number = 0;
        while left > 0 {
            number += 1;
            let len = part_size.min(left);
            let mut part = vec![0; usize::try_from(len).unwrap_or(usize::MAX)];
            reader
                .read_exact(&mut part)
                .await
                .map_err(|err| Missed::Later(err.to_string()))?;
            left -= len;
            let md5 = Md5::digest(&part);
            let answer = self
                .client
                .upload_part()
                .bucket(&self.bucket)
                .key(sending.key)
                .upload_id(upload_id)
                .part_number(number)
                .content_md5(STANDARD.encode(md5))
                .body(ByteStream::from(Bytes::from(part)))
                .send()
                .await
                .map_err(|err| missed(&err))?;
            parts.push(
                CompletedPart::builder()
                    .part_number(number)
                    .set_e_tag(answer.e_tag)
                    .build(),
            );
        }
        Ok(parts)
    }

    /// The MD5 of a version's bytes, read for it.
    async fn md5_of(&self, sending: &Sending<'_>) -> Result<[u8; 16], Missed> {
        let (_, body) = sending.reread().await?;
        let mut hasher = Md5::new();
        if let Some(body) = body {
            let mut reader = body.all().await?;
            let mut chunk = vec![0; CHUNK];
            loop {
                let read = reader
                    .read(&mut chunk)
                    .await
                    .map_err(|err| Missed::Later(err.to_string()))?;
                if read == 0 {
                    break;
                }
                hasher.update(&chunk[..read]);
            }
        }
        Ok(hasher.finalize().into())
    }

    /// `MinIO`'s replica headers, for a target that takes them.
    fn headers(&self, sending: &Sending<'_>) -> Vec<(&'static str, String)> {
        if self.replica_headers {
            replica_headers::of(&sending.replica)
        } else {
            Vec::new()
        }
    }
}

/// What a replica's write says about it besides its bytes.
struct Described {
    content_type: Option<String>,
    content_encoding: Option<String>,
    content_disposition: Option<String>,
    content_language: Option<String>,
    cache_control: Option<String>,
    expires: Option<DateTime>,
    redirect: Option<String>,
    metadata: Option<std::collections::HashMap<String, String>>,
    tagging: Option<String>,
    lock_mode: Option<ObjectLockMode>,
    retain_until: Option<DateTime>,
    legal_hold: Option<ObjectLockLegalHoldStatus>,
    sse: Option<ServerSideEncryption>,
    kms_key: Option<String>,
    storage_class: Option<StorageClass>,
}

impl Described {
    fn of(attrs: &ObjectAttrs, sending: &Sending<'_>, target: &Target) -> Self {
        let tagging = (!attrs.tags.is_empty()).then(|| {
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&attrs.tags)
                .finish()
        });
        // Only a KMS key is asked for: for the rest the target's default decides, as for
        // a write without encryption headers, since not every service has SSE-S3 (a
        // `MinIO` without a KMS refuses it).
        let (sse, kms_key) = match sending.info.sse.as_ref().map(|sse| sse.mode) {
            Some(SseMode::Kms) => (
                Some(ServerSideEncryption::AwsKms),
                sending.replica_key.clone(),
            ),
            Some(SseMode::Dsse) => (
                Some(ServerSideEncryption::AwsKmsDsse),
                sending.replica_key.clone(),
            ),
            Some(SseMode::S3 | SseMode::Customer) | None => (None, None),
        };
        Self {
            content_type: attrs.content_type.clone(),
            content_encoding: attrs.content_encoding.clone(),
            content_disposition: attrs.content_disposition.clone(),
            content_language: attrs.content_language.clone(),
            cache_control: attrs.cache_control.clone(),
            expires: attrs.expires.as_deref().and_then(|e| {
                DateTime::from_str(e, aws_sdk_s3::primitives::DateTimeFormat::HttpDate).ok()
            }),
            redirect: attrs.website_redirect_location.clone(),
            metadata: (!attrs.user.is_empty()).then(|| {
                attrs
                    .user
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }),
            tagging,
            lock_mode: attrs
                .retention
                .as_ref()
                .map(|r| ObjectLockMode::from(r.mode.as_str())),
            retain_until: attrs
                .retention
                .as_ref()
                .map(|r| DateTime::from_millis(r.until_ms)),
            legal_hold: attrs.legal_hold.map(|on| {
                if on {
                    ObjectLockLegalHoldStatus::On
                } else {
                    ObjectLockLegalHoldStatus::Off
                }
            }),
            sse,
            kms_key,
            storage_class: sending
                .storage_class
                .clone()
                .or_else(|| target.storage_class.clone())
                .map(|class| StorageClass::from(class.as_str())),
        }
    }
}

/// The MD5 of a version's bytes, when its ETag is it: a single upload's, unencrypted
/// or with SSE-S3.
fn whole_md5(sending: &Sending<'_>) -> Option<[u8; 16]> {
    let plain_etag = sending
        .info
        .sse
        .as_ref()
        .is_none_or(|sse| sse.mode == SseMode::S3);
    (plain_etag && sending.info.parts.is_empty())
        .then(|| md5_of_etag(&sending.info.etag))
        .flatten()
}

/// The version's checksums of its whole bytes (a multipart upload's checksum of its
/// parts' checksums can't be given to a `PutObject`).
fn full_object_checksums(attrs: &ObjectAttrs) -> impl Iterator<Item = (&str, &str)> {
    attrs
        .checksums
        .iter()
        .filter(|(_, value)| !value.contains('-'))
        .map(|(name, value)| (name.as_str(), value.as_str()))
}

/// The region a target's requests are signed for.
fn region(target: &RemoteTarget) -> String {
    if target.region.is_empty() {
        "us-east-1".to_owned()
    } else {
        target.region.clone()
    }
}

/// A target's URL.
fn endpoint(target: &RemoteTarget) -> String {
    let scheme = if target.secure { "https" } else { "http" };
    format!("{scheme}://{}", target.endpoint)
}

/// Whether an endpoint is AWS's S3, which is sent nothing but S3's own headers.
fn is_aws(endpoint: &str) -> bool {
    let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "amazonaws.com"
        || host.ends_with(".amazonaws.com")
        || host.ends_with(".amazonaws.com.cn")
}

/// What a target's answer means for the version: refused for good (it answered no, or
/// said the request is wrong), or worth trying again (it couldn't answer, or was busy).
fn missed<E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static>(
    err: &SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> Missed {
    let status = err.raw_response().map(|r| r.status().as_u16());
    let said = DisplayErrorContext(err).to_string();
    match status {
        // `501`: what the replica asks for (its encryption…) the target doesn't do.
        Some(status)
            if (400..500).contains(&status) && !matches!(status, 408 | 429) || status == 501 =>
        {
            Missed::Failed(format!("the target answered {status}: {said}"))
        }
        _ => Missed::Later(said),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_aws_goes_without_minios_headers() {
        for aws in [
            "s3.amazonaws.com",
            "s3.eu-west-1.amazonaws.com:443",
            "S3.AMAZONAWS.COM.",
            "s3.cn-north-1.amazonaws.com.cn",
        ] {
            assert!(is_aws(aws), "{aws}");
        }
        for other in [
            "backup.example.com:9000",
            "amazonaws.com.example.com",
            "10.0.0.1:9000",
        ] {
            assert!(!is_aws(other), "{other}");
        }
    }
}
