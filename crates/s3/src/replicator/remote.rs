//! Sending replicas to a replication target: a bucket on another S3 service (another
//! TeiFS, `MinIO`, AWS…). Each version is one `PutObject` streamed with its
//! `Content-MD5` (which S3 wants of a locked object's write), and never with
//! `aws-chunked` framing, which not every service takes; a version uploaded in parts,
//! and any above 5 GiB, as a multipart upload (with the version's own parts where they
//! aren't too big to hold, as `MinIO` sends them). To services other than AWS go
//! `MinIO`'s replica headers, so another TeiFS or a `MinIO` keeps the version's id, time
//! and ETag.

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
        BucketVersioningStatus, CompletedMultipartUpload, CompletedPart, ObjectLockEnabled,
        ObjectLockLegalHoldStatus, ObjectLockMode, ServerSideEncryption, StorageClass,
        TaggingDirective,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures::TryStreamExt as _;
use md5::{Digest as _, Md5};
use teifs_store::{ObjectAttrs, Replica, Store};
use teifs_types::{PartInfo, SseMode, md5_of_etag, replication::RemoteTarget};
use tokio::io::AsyncReadExt as _;

use super::{CHUNK, Missed, Sending, check::Unready};
use crate::{inventory::now_ms, replica_headers};

/// What a copy source's key escapes: all but S3's unreserved characters and `/`.
const COPY_SOURCE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');

/// Larger versions go as multipart uploads (S3's largest `PutObject`).
const MULTIPART_ABOVE: u64 = 5 * 1024 * 1024 * 1024;
/// The smallest part of a multipart upload (more when 10,000 parts wouldn't hold it).
const PART: u64 = 64 * 1024 * 1024;
/// S3's most parts in an upload.
const MOST_PARTS: u64 = 10_000;
/// How long connecting to a target may take.
const CONNECT: Duration = Duration::from_secs(10);
/// The key a replication check's writes and deletes name (as `MinIO`'s does, under its
/// system bucket's name: a receiver refuses them without writing).
const CHECKED_KEY: &str = ".minio.sys/teifs/deleteme";

/// How to reach a bucket on another S3 service.
pub(crate) struct Connection<'a> {
    /// Its URL (`http[s]://HOST[:PORT]`).
    pub(crate) endpoint: String,
    /// The region requests are signed for.
    pub(crate) region: String,
    pub(crate) access_key: &'a str,
    pub(crate) secret_key: &'a str,
    pub(crate) session_token: Option<&'a str>,
    pub(crate) bucket: String,
    /// Whether buckets are named in the path, rather than the host.
    pub(crate) path_style: bool,
    /// Its storage class for replicas, when it names one.
    pub(crate) storage_class: Option<String>,
    /// Whether it may be sent `MinIO`'s replica headers.
    pub(crate) replica_headers: bool,
}

/// A target, with a client signed in to it.
#[derive(Debug)]
pub(crate) struct Target {
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
        Ok(Self::connect(Connection {
            endpoint: endpoint(&target),
            region: region(&target),
            access_key: &target.access_key,
            secret_key: secrets.secret_key.as_str(),
            session_token: secrets.session_token.as_ref().map(|token| token.as_str()),
            bucket: target.target_bucket.clone(),
            path_style: true,
            storage_class: Some(target.storage_class.clone()).filter(|class| !class.is_empty()),
            replica_headers: !is_aws(&target.endpoint),
        }))
    }

    /// A client for the bucket `to` names, signed in with its keys.
    pub(crate) fn connect(to: Connection<'_>) -> Self {
        let credentials = Credentials::new(
            to.access_key,
            to.secret_key,
            to.session_token.map(str::to_owned),
            None,
            "teifs-replication",
        );
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(to.region))
            .endpoint_url(to.endpoint)
            .credentials_provider(credentials)
            .force_path_style(to.path_style)
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            // A failed send is tried again on a later pass, with the body read again.
            .retry_config(RetryConfig::disabled())
            .timeout_config(TimeoutConfig::builder().connect_timeout(CONNECT).build())
            .build();
        Self {
            client: Client::from_conf(config),
            replica_headers: to.replica_headers,
            storage_class: to.storage_class,
            bucket: to.bucket,
        }
    }

    /// The client, signed in.
    pub(crate) const fn client(&self) -> &Client {
        &self.client
    }

    /// The bucket.
    pub(crate) fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Checks that the target can take replicas: its bucket is versioned, has Object
    /// Lock when the source is `locked`, and (on a service that takes `MinIO`'s replica
    /// headers) lets these keys write and delete replicas, asked with `MinIO`'s check
    /// header so nothing is written.
    pub(super) async fn check(&self, locked: bool) -> Result<(), Unready> {
        if locked {
            let lock = self
                .client
                .get_object_lock_configuration()
                .bucket(&self.bucket)
                .send()
                .await;
            let enabled = match lock {
                Ok(out) => {
                    out.object_lock_configuration()
                        .and_then(|config| config.object_lock_enabled())
                        == Some(&ObjectLockEnabled::Enabled)
                }
                Err(err) if err.code() == Some("ObjectLockConfigurationNotFoundError") => false,
                Err(err) => return Err(Unready::Invalid(said(&err))),
            };
            if !enabled {
                return Err(Unready::TargetUnlocked(self.bucket.clone()));
            }
        }
        let versioning = self
            .client
            .get_bucket_versioning()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|err| Unready::Invalid(said(&err)))?;
        if versioning.status() != Some(&BucketVersioningStatus::Enabled) {
            return Err(Unready::TargetNotVersioned(self.bucket.clone()));
        }
        // AWS doesn't know the check header: it would write.
        if self.replica_headers {
            self.probe().await?;
        }
        Ok(())
    }

    /// Asks the target, with `MinIO`'s check header, whether these keys may write a
    /// replica, a replicated delete marker and a replicated removal.
    async fn probe(&self) -> Result<(), Unready> {
        let replica = Replica {
            version_id: uuid::Uuid::new_v4().to_string(),
            modified_ms: now_ms(),
            etag: None,
        };
        let mut headers = replica_headers::of(&replica);
        headers.push((replica_headers::CHECK, "true".to_owned()));
        let version_id = replica.version_id.clone();
        let put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(CHECKED_KEY)
            .body(ByteStream::from_static(b"aaaaaaaa"))
            .customize()
            .mutate_request({
                let headers = headers.clone();
                move |request| {
                    for (name, value) in &headers {
                        request.headers_mut().insert(*name, value.clone());
                    }
                    let uri = request.uri().to_owned();
                    let joint = if uri.contains('?') { '&' } else { '?' };
                    // An id is hex and dashes, which a URI always takes.
                    let _ = request.set_uri(format!(
                        "{uri}{joint}{}={version_id}",
                        replica_headers::VERSION_ID
                    ));
                }
            })
            .send()
            .await;
        let written = match put {
            Ok(out) => out.version_id,
            Err(err) if refused_check(&err) => None,
            Err(err) => {
                return Err(Unready::Invalid(format!(
                    "s3:ReplicateObject permissions missing for replication user: {}",
                    said(&err)
                )));
            }
        };
        // A replicated delete marker, then a replicated removal of the version.
        for marker in [true, false] {
            let mut headers = replica_headers::of_removal();
            headers.push((replica_headers::CHECK, "true".to_owned()));
            if marker {
                headers.push((replica_headers::DELETE_MARKER, "true".to_owned()));
            }
            let deleted = self
                .client
                .delete_object()
                .bucket(&self.bucket)
                .key(CHECKED_KEY)
                .set_version_id(written.clone())
                .customize()
                .mutate_request(move |request| {
                    for (name, value) in &headers {
                        request.headers_mut().insert(*name, value.clone());
                    }
                })
                .send()
                .await;
            match deleted {
                Ok(_) => {}
                Err(err) if refused_check(&err) => {}
                Err(err) => {
                    return Err(Unready::Invalid(format!(
                        "s3:ReplicateDelete permissions missing for replication user: {}",
                        said(&err)
                    )));
                }
            }
        }
        Ok(())
    }

    /// Sends a version.
    pub(crate) async fn send(&self, sending: Sending<'_>) -> Result<(), Missed> {
        if sending.info.size > MULTIPART_ABOVE || !sending.info.parts.is_empty() {
            self.send_parts(sending).await
        } else {
            self.send_whole(sending).await
        }
    }

    /// Makes a delete marker the key's current version on the target: one with the
    /// marker's id and time where `MinIO`'s headers are taken.
    pub(crate) async fn send_marker(&self, key: &str, replica: &Replica) -> Result<(), Missed> {
        let mut delete = self.client.delete_object().bucket(&self.bucket).key(key);
        let mut headers = Vec::new();
        if self.replica_headers {
            delete = delete.version_id(&replica.version_id);
            headers = replica_headers::of_marker(replica);
        }
        delete
            .customize()
            .mutate_request(move |request| {
                for (name, value) in &headers {
                    request.headers_mut().insert(*name, value.clone());
                }
            })
            .send()
            .await
            .map_err(|err| missed(&err))?;
        Ok(())
    }

    /// Sends what changed in the metadata of the version `replica` names (now `attrs`) to
    /// the target, which has it: `MinIO`'s copy of the version onto itself with its
    /// tags, retention and legal hold. Whether it did (`false`: the target doesn't have
    /// the version, so it all goes). AWS (whose versions have ids of their own) gets
    /// nothing.
    pub(super) async fn send_metadata(
        &self,
        key: &str,
        replica: &Replica,
        attrs: &ObjectAttrs,
    ) -> Result<bool, Missed> {
        if !self.replica_headers {
            return Ok(true);
        }
        let source = format!(
            "{}/{}?versionId={}",
            self.bucket,
            percent_encoding::utf8_percent_encode(key, COPY_SOURCE),
            replica.version_id
        );
        let (lock_mode, retain_until, legal_hold) = lock_of(attrs);
        let headers = replica_headers::of_metadata(replica, now_ms());
        let version_id = replica.version_id.clone();
        let sent = self
            .client
            .copy_object()
            .bucket(&self.bucket)
            .key(key)
            .copy_source(source)
            .tagging_directive(TaggingDirective::Replace)
            .tagging(tagging_of(attrs).unwrap_or_default())
            .set_object_lock_mode(lock_mode)
            .set_object_lock_retain_until_date(retain_until)
            .set_object_lock_legal_hold_status(legal_hold)
            .customize()
            .mutate_request(move |request| {
                for (name, value) in &headers {
                    request.headers_mut().insert(*name, value.clone());
                }
                let uri = request.uri().to_owned();
                let sep = if uri.contains('?') { '&' } else { '?' };
                // Ids are hex and dashes: nothing to encode.
                let _ = request.set_uri(format!("{uri}{sep}versionId={version_id}"));
            })
            .send()
            .await;
        match sent {
            Ok(_) => Ok(true),
            Err(err)
                if err
                    .raw_response()
                    .is_some_and(|r| r.status().as_u16() == 404) =>
            {
                Ok(false)
            }
            Err(err) => Err(missed(&err)),
        }
    }

    /// Removes the version `version_id` of `key` from the target, as a replicated
    /// removal. On AWS (whose versions have ids of their own, and which doesn't take
    /// replicated removals) there's nothing to remove.
    pub(super) async fn send_removal(&self, key: &str, version_id: &str) -> Result<(), Missed> {
        if !self.replica_headers {
            return Ok(());
        }
        let headers = replica_headers::of_removal();
        let sent = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .version_id(version_id)
            .customize()
            .mutate_request(move |request| {
                for (name, value) in &headers {
                    request.headers_mut().insert(*name, value.clone());
                }
            })
            .send()
            .await;
        match sent {
            Ok(_) => Ok(()),
            // Not there (never sent, or removed already): nothing left to remove.
            Err(err)
                if err
                    .raw_response()
                    .is_some_and(|r| r.status().as_u16() == 404) =>
            {
                Ok(())
            }
            Err(err) => Err(missed(&err)),
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
            .key(sending.target_key)
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
        // The replica's id goes with the start, its time and ETag with the end.
        let identity = self.replica_headers.then(|| sending.replica.clone());
        let (start, end) = match &identity {
            Some(replica) => (
                vec![
                    (replica_headers::REQUEST, "true".to_owned()),
                    (replica_headers::STATUS, "REPLICA".to_owned()),
                ],
                replica_headers::of(replica),
            ),
            None => (Vec::new(), Vec::new()),
        };
        let version_id = identity.map(|replica| replica.version_id);
        let started = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(sending.target_key)
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
            .customize()
            .mutate_request(move |request| {
                for (name, value) in &start {
                    request.headers_mut().insert(*name, value.clone());
                }
                if let Some(id) = &version_id {
                    // Ids are hex and dashes: nothing to encode.
                    let uri = request.uri().to_owned();
                    let sep = if uri.contains('?') { '&' } else { '?' };
                    let _ = request.set_uri(format!("{uri}{sep}versionId={id}"));
                }
            })
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
                .key(sending.target_key)
                .upload_id(&upload_id)
                .multipart_upload(
                    CompletedMultipartUpload::builder()
                        .set_parts(Some(parts))
                        .build(),
                )
                .customize()
                .mutate_request(move |request| {
                    for (name, value) in &end {
                        request.headers_mut().insert(*name, value.clone());
                    }
                })
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
                .key(sending.target_key)
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
        let layout = part_layout(sending.info.size, &sending.info.parts);
        let (_, body) = sending.reread().await?;
        let mut reader = match body {
            Some(body) => body.all().await?,
            None => return Err(Missed::Later("the version has no bytes".to_owned())),
        };
        let mut parts = Vec::new();
        for (number, len) in (1..).zip(layout) {
            let mut part = vec![0; usize::try_from(len).unwrap_or(usize::MAX)];
            reader
                .read_exact(&mut part)
                .await
                .map_err(|err| Missed::Later(err.to_string()))?;
            let md5 = Md5::digest(&part);
            let answer = self
                .client
                .upload_part()
                .bucket(&self.bucket)
                .key(sending.target_key)
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
        let tagging = tagging_of(attrs);
        let (lock_mode, retain_until, legal_hold) = lock_of(attrs);
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
            lock_mode,
            retain_until,
            legal_hold,
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

/// The sizes of the parts a version of `size` bytes goes in: its own `parts`, when they
/// add up and none is too big to hold (so the replica's ETag is the version's anywhere),
/// else parts of [`PART`] (more when 10,000 of them wouldn't hold it).
fn part_layout(size: u64, parts: &[PartInfo]) -> Vec<u64> {
    let own: Vec<u64> = parts.iter().map(|part| part.size).collect();
    if !own.is_empty()
        && own.iter().sum::<u64>() == size
        && own.iter().all(|len| *len <= PART)
        && own.len() <= usize::try_from(MOST_PARTS).unwrap_or(usize::MAX)
    {
        return own;
    }
    let part = PART.max(size.div_ceil(MOST_PARTS));
    let mut layout = Vec::new();
    let mut left = size;
    while left > 0 {
        let len = part.min(left);
        layout.push(len);
        left -= len;
    }
    layout
}

/// A version's tags as the `x-amz-tagging` header says them.
fn tagging_of(attrs: &ObjectAttrs) -> Option<String> {
    (!attrs.tags.is_empty()).then(|| {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&attrs.tags)
            .finish()
    })
}

/// A version's retention and legal hold, as the `x-amz-object-lock-*` headers say them.
fn lock_of(
    attrs: &ObjectAttrs,
) -> (
    Option<ObjectLockMode>,
    Option<DateTime>,
    Option<ObjectLockLegalHoldStatus>,
) {
    let legal_hold = attrs.legal_hold.map(|on| {
        if on {
            ObjectLockLegalHoldStatus::On
        } else {
            ObjectLockLegalHoldStatus::Off
        }
    });
    (
        attrs
            .retention
            .as_ref()
            .map(|r| ObjectLockMode::from(r.mode.as_str())),
        attrs
            .retention
            .as_ref()
            .map(|r| DateTime::from_millis(r.until_ms)),
        legal_hold,
    )
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
pub(crate) fn is_aws(endpoint: &str) -> bool {
    let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "amazonaws.com"
        || host.ends_with(".amazonaws.com")
        || host.ends_with(".amazonaws.com.cn")
}

/// What a target answered, short: its error's code and message (or why there was no
/// answer).
pub(crate) fn said<E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static>(
    err: &SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> String {
    match (err.code(), err.message()) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code.to_owned(),
        _ => DisplayErrorContext(err).to_string(),
    }
}

/// Whether a target refused a request as a replication check's (it would have taken it).
fn refused_check<E: ProvideErrorMetadata>(
    err: &SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> bool {
    err.code() == Some(replica_headers::CHECK_REFUSED)
}

/// What a target's answer means for the version: refused for good (it answered no, or
/// said the request is wrong), or worth trying again (it couldn't answer, or was busy).
pub(crate) fn missed<E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static>(
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
        Some(_) => Missed::Later(said),
        None => Missed::Unreachable(said),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_go_in_their_own_parts_when_they_can_be_held() {
        let parts = |sizes: &[u64]| -> Vec<PartInfo> {
            sizes
                .iter()
                .map(|size| PartInfo {
                    size: *size,
                    checksums: std::collections::BTreeMap::new(),
                })
                .collect()
        };
        let mib = 1024 * 1024;
        assert_eq!(
            part_layout(11 * mib, &parts(&[5 * mib, 5 * mib, mib])),
            [5 * mib, 5 * mib, mib]
        );
        // Parts that don't add up, or too big to hold: parts of our own.
        assert_eq!(part_layout(70 * mib, &parts(&[5 * mib])), [PART, 6 * mib]);
        assert_eq!(
            part_layout(100 * mib, &parts(&[100 * mib])),
            [PART, 36 * mib]
        );
        assert_eq!(part_layout(0, &[]), Vec::<u64>::new());
    }

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
