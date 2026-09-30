//! The S3 operations.

use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use futures::StreamExt;
use s3s::{
    S3, S3Request, S3Response, S3Result,
    dto::{
        self, ChecksumMode, CopySource, ETag, ETagCondition, MetadataDirective, ObjectStorageClass,
        StreamingBlob, Timestamp,
    },
    s3_error,
};
use teifs_store::{
    Acl, After, BucketEncryption, CustomerKey, DefaultEncryption, Encryption, Layout, ListQuery,
    Match, NewBucket, OWNER_ID, ObjectAttrs, ObjectInfo, ObjectOwnership, Precondition, SseInfo,
    SseMode, Staged, Store, Upload, Versioning, VersionsQuery,
};
use tokio_util::io::ReaderStream;

use crate::{
    access,
    acl::{self, AclHeaders, acl_headers},
    bucket_access::{self, Rules},
    caps::{self, Caps},
    checksums::{self, Sums, checksum_of, set_checksums},
    cors, encode,
    errors::{StoreResultExt, from_body},
    lifecycle,
    object_lock::{self, ReadLock, WriteLock, set_lock, write_lock},
    post_form::{self, Form},
    sse::{self, set_sse},
    tagging,
};

/// How many keys a listing returns at most, and by default.
const MAX_KEYS: i32 = 1000;
/// The most buckets one `ListBuckets` page may ask for.
const MAX_BUCKETS: usize = 10_000;
/// The region every bucket is in (a drive has one).
pub(crate) const REGION: &str = "us-east-1";
/// How many keys one `DeleteObjects` may name.
const MAX_DELETE: usize = 1000;
/// Read buffer for object bodies.
const READ_CHUNK: usize = 256 * 1024;
/// Who owns every bucket (a drive has one owner).
/// Chooses the layout of a bucket being created (`object` or `folder`); without it, the
/// server's default applies.
pub const LAYOUT_HEADER: &str = "x-teifs-bucket-layout";
/// The version id of every object in a bucket without versioning, as S3 names it.
const NULL_VERSION: &str = "null";

/// The S3 API over a drive.
#[derive(Debug, Clone)]
pub struct Drive {
    store: Store,
    default_layout: Layout,
    /// The buckets' policies and Block Public Access settings, as requests read them.
    rules: Arc<Rules>,
    /// New buckets start as S3's did before April 2023: ACLs enabled, no Block Public
    /// Access.
    legacy_bucket_defaults: bool,
}

impl Drive {
    /// Serves `store`; buckets created without choosing get `default_layout`.
    #[must_use]
    pub fn new(store: Store, default_layout: Layout, legacy_bucket_defaults: bool) -> Self {
        Self {
            rules: Arc::new(Rules::new(store.clone())),
            store,
            default_layout,
            legacy_bucket_defaults,
        }
    }

    /// The `x-amz-expiration` of the current version `info` of an object in `bucket`,
    /// when a lifecycle rule expires it. Only informative: a damaged configuration
    /// leaves it out rather than failing the request.
    async fn expiration(&self, bucket: &str, info: &ObjectInfo) -> Option<String> {
        match self.store.expiry(bucket, info).await {
            Ok(expiry) => expiry.as_ref().map(lifecycle::expiration_header),
            Err(err) => {
                tracing::warn!(bucket, error = %err, "couldn't read the lifecycle configuration");
                None
            }
        }
    }

    /// When a lifecycle rule aborts `upload`, and the rule's id.
    async fn abort_date(
        &self,
        upload: &teifs_store::Upload,
    ) -> (Option<Timestamp>, Option<String>) {
        match self
            .store
            .upload_abort(&upload.bucket, &upload.key, upload.created_ms)
            .await
        {
            Ok(Some(expiry)) => (Some(millis(expiry.at_ms)), Some(expiry.rule_id)),
            Ok(None) => (None, None),
            Err(err) => {
                tracing::warn!(bucket = upload.bucket, error = %err, "couldn't read the lifecycle configuration");
                (None, None)
            }
        }
    }

    /// The rules requests are decided with, shared with [`crate::access::Access`].
    pub(crate) fn rules(&self) -> Arc<Rules> {
        Arc::clone(&self.rules)
    }

    /// The ACL an object write asks for, checked against the bucket's Object Ownership
    /// and Block Public Access; none when it asks for none.
    async fn object_write_acl(
        &self,
        bucket: &str,
        headers: AclHeaders<'_>,
    ) -> S3Result<Option<Acl>> {
        let requested = acl::requested(&headers, false)?;
        if requested == acl::Requested::Nothing {
            return Ok(None);
        }
        self.store.head_bucket(bucket).await.s3()?;
        let rules = self.rules.of(bucket).await?;
        acl::for_object_write(requested, rules.ownership, rules.block)
    }

    /// Reads an object. As in S3, a part number the object doesn't have is reported
    /// before a missing SSE-C key.
    async fn read(
        &self,
        (bucket, key, version_id): (&str, &str, Option<&str>),
        customer: Option<&CustomerKey>,
        part_number: Option<i32>,
    ) -> S3Result<(ObjectInfo, Option<teifs_store::ObjectBody>)> {
        match self
            .store
            .read_with(bucket, key, version_id, customer)
            .await
        {
            Err(err @ teifs_store::StoreError::CustomerKeyRequired) if part_number.is_some() => {
                if let Ok(info) = self.store.head_version(bucket, key, version_id).await {
                    Slice::of(&info, None, part_number)?;
                }
                Err(err).s3()
            }
            other => other.s3(),
        }
    }

    /// The checksum a completed upload's object gets, worked out from its parts' and
    /// checked against what the client sent (AWS's rules: a listed part's checksum must
    /// match the stored one, the object's must match the sent one).
    async fn object_checksum(
        &self,
        upload: &teifs_store::Upload,
        input: &dto::CompleteMultipartUploadInput,
        listed: &[(u32, String, Sums)],
        customer: Option<&CustomerKey>,
    ) -> S3Result<(Sums, Option<teifs_store::ChecksumType>)> {
        let checksum = Store::upload_checksum(upload);
        let sse_c = self
            .store
            .upload_encryption(upload)
            .is_some_and(|i| i.mode == SseMode::Customer);
        if sse_c && customer.is_none() && checksum.as_ref().is_some_and(|c| c.requested) {
            return Err(s3_error!(
                InvalidRequest,
                "The upload has a checksum and SSE-C: completing it needs the SSE-C key"
            ));
        }
        let stored: BTreeMap<u32, teifs_store::Part> = self
            .store
            .parts(
                &upload.id,
                0,
                teifs_store::MAX_PART_NUMBER as usize,
                customer,
            )
            .await
            .s3()?
            .into_iter()
            .map(|p| (p.number, p))
            .collect();
        for (number, _, sent) in listed {
            let Some(part) = stored.get(number) else {
                continue; // The store refuses the missing part.
            };
            if sent
                .iter()
                .any(|(name, value)| part.checksums.get(name).is_some_and(|v| v != value))
            {
                return Err(s3_error!(
                    InvalidPart,
                    "part {number}'s checksum doesn't match the uploaded part"
                ));
            }
        }
        let parts: Option<Vec<&teifs_store::Part>> =
            listed.iter().map(|(n, ..)| stored.get(n)).collect();
        if let (Some(size), Some(parts)) = (input.mpu_object_size, &parts)
            && u64::try_from(size).ok() != Some(parts.iter().map(|p| p.size).sum())
        {
            return Err(s3_error!(
                InvalidRequest,
                "The provided 'x-amz-mp-object-size' header value does not match what was computed"
            ));
        }
        let Some(checksum) = checksum else {
            return Ok((Sums::new(), None));
        };
        check_complete(&checksum, input.checksum_type.as_ref(), listed)?;
        let computed = parts.and_then(|parts| {
            let sums: Vec<(u64, Option<&str>)> = parts
                .iter()
                .map(|p| {
                    (
                        p.size,
                        p.checksums.get(&checksum.algorithm).map(String::as_str),
                    )
                })
                .collect();
            checksums::of_parts(&checksum, &sums)
        });
        for (name, value) in &checksums::from_dto(&checksum_of!(input)) {
            if *name == checksum.algorithm {
                if computed
                    .as_deref()
                    .is_some_and(|c| !checksums::same_object_checksum(checksum.kind, value, c))
                {
                    return Err(s3_error!(
                        BadDigest,
                        "the {name} checksum doesn't match the parts"
                    ));
                }
            } else if checksum.requested {
                return Err(s3_error!(
                    InvalidRequest,
                    "The upload was created using the {} checksum algorithm",
                    checksum.algorithm.to_ascii_lowercase()
                ));
            }
        }
        // Without the SSE-C key, S3's default checksum can't be sealed: it's left out.
        match computed {
            Some(value) if !(sse_c && customer.is_none()) => {
                Ok(([(checksum.algorithm, value)].into(), Some(checksum.kind)))
            }
            _ => Ok((Sums::new(), None)),
        }
    }

    /// Refuses a write before its body is read: a key (when it names one) the bucket
    /// can't create, or `len` bytes (when the request says how many) that wouldn't leave
    /// the room kept free for deletes.
    async fn check_write(&self, bucket: &str, key: Option<&str>, len: Option<i64>) -> S3Result<()> {
        let len = len.and_then(|len| u64::try_from(len).ok());
        self.store.check_write(bucket, key, len).await.s3()
    }

    /// Decides a write's encryption from its SSE headers and the bucket's default.
    async fn write_encryption(
        &self,
        bucket: &str,
        request: sse::WriteRequest<'_>,
    ) -> S3Result<Encryption> {
        let default = self.store.bucket_encryption(bucket).await.s3()?;
        sse::for_write(request, default.as_ref())
    }

    /// Streams a request body into `staged`, hashing it for the checksums asked for. A
    /// body longer than `limit` is cut off with `EntityTooLarge`, whatever it declared.
    /// A version whose lock is asked about, in a bucket that must have Object Lock.
    async fn locked_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> S3Result<ObjectInfo> {
        let version_id = check_version(version_id)?;
        if self.store.bucket_object_lock(bucket).await.s3()?.is_none() {
            return Err(s3_error!(
                InvalidRequest,
                "Bucket is missing Object Lock Configuration"
            ));
        }
        self.store.head_version(bucket, key, version_id).await.s3()
    }

    async fn stage(
        &self,
        mut staged: Staged,
        body: StreamingBlob,
        sums: &mut s3s::checksum::ChecksumHasher,
        limit: Option<u64>,
    ) -> S3Result<Staged> {
        let mut body = body;
        let mut left = limit.unwrap_or(u64::MAX);
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(from_body)?;
            left = left
                .checked_sub(chunk.len() as u64)
                .ok_or_else(caps::too_large)?;
            sums.update(&chunk);
            staged.write(&chunk).await.s3()?;
        }
        Ok(staged)
    }
}

/// An object's encryption as S3 reports it, with the SSE-C key's MD5 the request sent.
fn with_customer_md5(info: Option<SseInfo>, md5: Option<String>) -> Option<SseInfo> {
    info.map(|mut info| {
        if info.mode == SseMode::Customer {
            info.customer_key_md5 = md5;
        }
        info
    })
}

/// Checks a request's `versionId`. Without versioning, an object's only version is
/// `null` (the current one); any other id is invalid, as S3 answers.
fn initiator() -> dto::Initiator {
    dto::Initiator {
        display_name: Some(OWNER_ID.to_owned()),
        id: Some(OWNER_ID.to_owned()),
    }
}

/// A new bucket's `LocationConstraint`, when it names one, must be the server's region:
/// AWS refuses another region's at a region's endpoint. (AWS also refuses `us-east-1`
/// named outright; TeiFS takes it, as MinIO does, since some clients send it.)
fn check_location(configuration: Option<&dto::CreateBucketConfiguration>) -> S3Result<()> {
    match configuration.and_then(|c| c.location_constraint.as_ref()) {
        Some(location) if location.as_str() != REGION && !location.as_str().is_empty() => {
            let mut err = s3s::S3Error::with_message(
                s3s::S3ErrorCode::Custom("IllegalLocationConstraintException".into()),
                format!(
                    "The {} location constraint is incompatible for the region specific \
                     endpoint this request was sent to.",
                    location.as_str()
                ),
            );
            err.set_status_code(http::StatusCode::BAD_REQUEST);
            Err(err)
        }
        _ => Ok(()),
    }
}

/// Checks a version id a request names: `null`, or one TeiFS makes (32 hex digits).
/// Anything else can't name a version, which AWS refuses before looking.
fn check_version(version_id: Option<&str>) -> S3Result<Option<&str>> {
    match version_id {
        None => Ok(None),
        Some(id) if is_version_id(id) => Ok(Some(id)),
        Some(_) => Err(s3_error!(InvalidArgument, "Invalid version id specified")),
    }
}

/// A versions listing's entries, as S3 answers them: versions and delete markers apart.
fn version_entries(
    listed: Vec<teifs_store::ObjectVersion>,
    enc: &impl Fn(String) -> String,
) -> (Vec<dto::ObjectVersion>, Vec<dto::DeleteMarkerEntry>) {
    let (mut versions, mut markers) = (Vec::new(), Vec::new());
    for version in listed {
        let info = version.info;
        if version.delete_marker {
            markers.push(dto::DeleteMarkerEntry {
                key: Some(enc(info.key)),
                version_id: info.version_id,
                is_latest: Some(version.latest),
                last_modified: Some(info.modified.into()),
                owner: Some(acl::owner()),
            });
            continue;
        }
        versions.push(dto::ObjectVersion {
            key: Some(enc(info.key)),
            version_id: info.version_id,
            is_latest: Some(version.latest),
            size: Some(i64::try_from(info.size).unwrap_or(i64::MAX)),
            e_tag: Some(etag(&info.etag)),
            last_modified: Some(info.modified.into()),
            storage_class: Some(dto::ObjectVersionStorageClass::from_static(
                dto::ObjectVersionStorageClass::STANDARD,
            )),
            owner: Some(acl::owner()),
            ..Default::default()
        });
    }
    (versions, markers)
}

/// A copy onto itself must change something the request names: metadata or encryption
/// (the bucket's default encryption doesn't count), unless it copies a version named by
/// its id (restoring it).
fn check_copy_onto_itself(
    input: &dto::CopyObjectInput,
    (src_bucket, src_key, src_version): (&str, &str, Option<&str>),
    replace: bool,
) -> S3Result<()> {
    let asks_encryption = input.server_side_encryption.is_some()
        || input.sse_customer_algorithm.is_some()
        || input.ssekms_key_id.is_some();
    if src_bucket == input.bucket
        && src_key == input.key
        && !replace
        && !asks_encryption
        && src_version.is_none()
    {
        return Err(s3_error!(
            InvalidRequest,
            "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes."
        ));
    }
    Ok(())
}

/// What S3 answers about a version that has no retention or legal hold to show.
fn no_lock_of_object() -> s3s::S3Error {
    s3_error!(
        NoSuchObjectLockConfiguration,
        "The specified object does not have a ObjectLock configuration"
    )
}

/// A `DeleteObjects` answer's entry: the version asked for, and when a delete marker was
/// added or removed, that marker.
fn deleted_object(
    key: String,
    asked: Option<String>,
    done: teifs_store::Deleted,
) -> dto::DeletedObject {
    let marker = done.delete_marker;
    dto::DeletedObject {
        key: Some(key),
        delete_marker: marker.then_some(true),
        delete_marker_version_id: done.version_id.clone().filter(|_| marker),
        version_id: asked.or_else(|| done.version_id.filter(|_| !marker)),
    }
}

/// The version id a write answers with: the new version's, none when it's `null` (a
/// bucket without versioning, or suspended), as s3-tests expect and MinIO answers.
fn written_version(info: &ObjectInfo) -> Option<String> {
    info.version_id.clone().filter(|id| id != NULL_VERSION)
}

fn is_version_id(id: &str) -> bool {
    id == NULL_VERSION || (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Where a V1 listing (or a versions listing) resumes after `marker`. A marker ending in
/// the delimiter (past the prefix) is a common prefix a previous page ended with: resume
/// after everything under it.
fn after_marker(marker: Option<String>, delimiter: Option<&str>, prefix: &str) -> Option<After> {
    marker
        .filter(|m| !m.is_empty())
        .map(|marker| match delimiter {
            Some(d) if !d.is_empty() && marker.ends_with(d) && marker.len() > prefix.len() => {
                After::Prefix(marker)
            }
            _ => After::Key(marker),
        })
}

fn etag(value: &str) -> ETag {
    ETag::Strong(value.to_owned())
}

fn condition(condition: Option<&ETagCondition>) -> Option<Match> {
    condition.map(|c| match c.as_etag() {
        Some(etag) if !c.is_any() => Match::ETag(etag.value().to_owned()),
        _ => Match::Any,
    })
}

fn precondition(
    if_match: Option<&ETagCondition>,
    if_none_match: Option<&ETagCondition>,
) -> Precondition {
    Precondition {
        if_match: condition(if_match),
        if_none_match: condition(if_none_match),
        ..Precondition::default()
    }
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn timestamp_seconds(timestamp: &Timestamp) -> i64 {
    time::OffsetDateTime::from(timestamp.clone()).unix_timestamp()
}

/// The key `x-amz-rename-source` names, URL-decoded: `/bucket/key`, `bucket/key` or
/// `/key` (the bucket must be the request's: renames stay in one bucket).
pub(crate) fn rename_source(source: &str, bucket: &str) -> S3Result<String> {
    let decoded = urlencoding_decode(source)?;
    let trimmed = decoded.strip_prefix('/').unwrap_or(&decoded);
    let key = match trimmed.split_once('/') {
        Some((first, rest)) if first == bucket && !rest.is_empty() => rest,
        _ => trimmed,
    };
    if key.is_empty() {
        return Err(s3_error!(
            InvalidArgument,
            "x-amz-rename-source names no object"
        ));
    }
    Ok(key.to_owned())
}

/// Percent-decodes a header value.
pub(crate) fn urlencoding_decode(value: &str) -> S3Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = value
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| s3_error!(InvalidArgument, "invalid percent-encoding"))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| s3_error!(InvalidArgument, "the key isn't UTF-8"))
}

/// A timestamp as a time, to the second (S3's conditional headers carry seconds).
fn to_system_time(timestamp: &Timestamp) -> SystemTime {
    SystemTime::UNIX_EPOCH
        + std::time::Duration::from_secs(u64::try_from(timestamp_seconds(timestamp)).unwrap_or(0))
}

/// Checks a read's conditions in the order HTTP defines (RFC 9110 §13.2.2).
fn check_read(
    info: &ObjectInfo,
    if_match: Option<&ETagCondition>,
    if_none_match: Option<&ETagCondition>,
    if_modified_since: Option<&Timestamp>,
    if_unmodified_since: Option<&Timestamp>,
) -> S3Result<()> {
    let modified = unix_seconds(info.modified);
    let matches = |c: &ETagCondition| {
        condition(Some(c)).is_some_and(|m| match m {
            Match::Any => true,
            Match::ETag(e) => e == info.etag,
        })
    };
    if let Some(c) = if_match {
        if !matches(c) {
            return Err(s3_error!(PreconditionFailed));
        }
    } else if let Some(since) = if_unmodified_since
        && modified > timestamp_seconds(since)
    {
        return Err(s3_error!(PreconditionFailed));
    }
    if let Some(c) = if_none_match {
        if matches(c) {
            return Err(s3_error!(NotModified));
        }
    } else if let Some(since) = if_modified_since
        && modified <= timestamp_seconds(since)
    {
        return Err(s3_error!(NotModified));
    }
    Ok(())
}

/// The attributes a write sets.
struct NewAttrs {
    content_type: Option<String>,
    content_encoding: Option<String>,
    content_disposition: Option<String>,
    content_language: Option<String>,
    cache_control: Option<String>,
    expires: Option<String>,
    website_redirect_location: Option<String>,
    metadata: Option<dto::Metadata>,
}

/// Content types clients send when they don't know better: the drive guesses from the
/// file name instead, so a photo uploaded by a generic tool still opens as a photo.
const GENERIC_TYPES: [&str; 2] = ["application/octet-stream", "binary/octet-stream"];

impl NewAttrs {
    fn into_attrs(self, checksums: Sums) -> ObjectAttrs {
        ObjectAttrs {
            content_type: self
                .content_type
                .filter(|t| !GENERIC_TYPES.contains(&t.as_str())),
            content_encoding: self.content_encoding,
            content_disposition: self.content_disposition,
            content_language: self.content_language,
            cache_control: self.cache_control,
            expires: self.expires,
            website_redirect_location: self.website_redirect_location,
            user: self
                .metadata
                .map(|m| m.into_iter().collect())
                .unwrap_or_default(),
            checksums,
            checksum_type: None,
            tags: BTreeMap::new(),
            acl: None,
            retention: None,
            legal_hold: None,
        }
    }
}

macro_rules! new_attrs {
    ($input:expr) => {
        NewAttrs {
            content_type: $input.content_type.take(),
            content_encoding: $input.content_encoding.take(),
            content_disposition: $input.content_disposition.take(),
            content_language: $input.content_language.take(),
            cache_control: $input.cache_control.take(),
            expires: $input.expires.take().map(|e| e.to_string()),
            website_redirect_location: $input.website_redirect_location.take(),
            metadata: $input.metadata.take(),
        }
    };
}

fn user_metadata(attrs: &ObjectAttrs) -> Option<dto::Metadata> {
    (!attrs.user.is_empty()).then(|| attrs.user.clone().into_iter().collect())
}

/// Who starts and continues multipart uploads.
struct Uploader {
    /// What the upload records as its owner: the caller's `aws:userid` with IAM, else the
    /// access key (`None` for unsigned requests).
    id: Option<String>,
    /// The account's root user, who may continue anyone's upload.
    root: bool,
}

fn uploader<T>(req: &S3Request<T>) -> Uploader {
    match access::caller(req) {
        Some(caller) => Uploader {
            id: Some(caller.id().to_owned()),
            root: caller.is_root(),
        },
        None => Uploader {
            id: req.credentials.as_ref().map(|c| c.access_key.clone()),
            root: false,
        },
    }
}

fn check_owner(upload: &Upload, bucket: &str, key: &str, who: &Uploader) -> S3Result<()> {
    if upload.bucket != bucket || upload.key != key {
        return Err(s3_error!(NoSuchUpload));
    }
    if !who.root && upload.owner != who.id {
        return Err(s3_error!(
            AccessDenied,
            "the upload was started by someone else"
        ));
    }
    Ok(())
}

fn part_number(number: i32) -> S3Result<u32> {
    u32::try_from(number)
        .ok()
        .filter(|n| (1..=teifs_store::MAX_PART_NUMBER).contains(n))
        .ok_or_else(|| s3_error!(InvalidArgument, "part numbers go from 1 to 10000"))
}

pub(crate) fn http_date(timestamp: &Timestamp) -> String {
    let mut out = Vec::new();
    let _ = timestamp.format(dto::TimestampFormat::HttpDate, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

pub(crate) fn millis(ms: i64) -> Timestamp {
    Timestamp::from(
        SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(u64::try_from(ms).unwrap_or(0)),
    )
}

/// The bytes a read returns: a range, one part (`partNumber`), or the whole object.
struct Slice<'a> {
    start: u64,
    len: u64,
    /// `Content-Range`, for anything but the whole object.
    content_range: Option<String>,
    /// How many parts the object has, when one of a multipart object's parts was asked for.
    parts_count: Option<i32>,
    /// The checksums that describe exactly these bytes, if any do.
    checksums: Option<&'a Sums>,
    /// What they cover, for the whole object.
    checksum_type: Option<dto::ChecksumType>,
}

impl<'a> Slice<'a> {
    fn of(
        info: &'a ObjectInfo,
        range: Option<&dto::Range>,
        part_number: Option<i32>,
    ) -> S3Result<Self> {
        let whole = Self {
            start: 0,
            len: info.size,
            content_range: None,
            parts_count: None,
            checksums: Some(&info.attrs.checksums),
            checksum_type: checksum_type(&info.attrs.checksums, info.attrs.checksum_type),
        };
        let partial = |start: u64, len: u64| {
            (len > 0).then(|| format!("bytes {start}-{}/{}", start + len - 1, info.size))
        };
        match (range, part_number) {
            (Some(_), Some(_)) => Err(s3_error!(
                InvalidRequest,
                "Cannot specify both Range header and partNumber query parameter"
            )),
            (Some(range), None) => {
                let r = range
                    .check(info.size)
                    .map_err(|_| s3_error!(InvalidRange))?;
                Ok(Self {
                    start: r.start,
                    len: r.end - r.start,
                    content_range: partial(r.start, r.end - r.start),
                    parts_count: None,
                    checksums: None,
                    checksum_type: None,
                })
            }
            (None, Some(number)) => {
                let invalid = || s3_error!(InvalidPart, "the object has no such part");
                let index = usize::try_from(number)
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .ok_or_else(invalid)?;
                if info.parts.is_empty() {
                    // An object put in one piece is its own part 1.
                    return if index == 0 {
                        Ok(Self {
                            content_range: partial(0, info.size),
                            ..whole
                        })
                    } else {
                        Err(invalid())
                    };
                }
                let part = info.parts.get(index).ok_or_else(invalid)?;
                let start = info.parts[..index].iter().map(|p| p.size).sum();
                Ok(Self {
                    start,
                    len: part.size,
                    content_range: partial(start, part.size),
                    parts_count: Some(i32::try_from(info.parts.len()).unwrap_or(i32::MAX)),
                    checksums: Some(&part.checksums),
                    checksum_type: None,
                })
            }
            (None, None) => Ok(whole),
        }
    }
}

/// One page of a multipart object's parts, for `GetObjectAttributes`.
fn object_parts(
    parts: &[teifs_store::PartInfo],
    marker: Option<i32>,
    max_parts: Option<i32>,
) -> dto::GetObjectAttributesParts {
    let after = usize::try_from(marker.unwrap_or(0)).unwrap_or(0);
    let max = usize::try_from(max_parts.unwrap_or(1000))
        .unwrap_or(0)
        .min(1000);
    let page: Vec<dto::ObjectPart> = parts
        .iter()
        .enumerate()
        .skip(after)
        .take(max)
        .map(|(index, part)| {
            let mut out = dto::ObjectPart {
                part_number: Some(i32::try_from(index + 1).unwrap_or(i32::MAX)),
                size: Some(i64::try_from(part.size).unwrap_or(i64::MAX)),
                ..Default::default()
            };
            set_checksums!(out, &part.checksums);
            out
        })
        .collect();
    let truncated = after.saturating_add(page.len()) < parts.len();
    let last = page.last().and_then(|p| p.part_number);
    dto::GetObjectAttributesParts {
        is_truncated: Some(truncated),
        max_parts: max_parts.or(Some(1000)),
        part_number_marker: marker,
        next_part_number_marker: truncated.then_some(last).flatten(),
        total_parts_count: Some(i32::try_from(parts.len()).unwrap_or(i32::MAX)),
        parts: Some(page),
    }
}

/// The attributes a copy gets when the request replaces its metadata or its tags (each
/// has its own directive) or gives it an ACL or a lock; `None` keeps the source's,
/// without its ACL and lock.
fn copy_attrs(
    input: &mut dto::CopyObjectInput,
    source: &ObjectAttrs,
    replace_metadata: bool,
    acl: Option<Acl>,
    lock: WriteLock,
) -> S3Result<Option<ObjectAttrs>> {
    let replace_tags = input
        .tagging_directive
        .as_ref()
        .is_some_and(|d| d.as_str() == dto::TaggingDirective::REPLACE);
    if !replace_metadata && !replace_tags && acl.is_none() && !lock.is_some() {
        return Ok(None);
    }
    let mut attrs = if replace_metadata {
        new_attrs!(input).into_attrs(BTreeMap::new())
    } else {
        source.clone()
    };
    attrs.tags = if replace_tags {
        header_tags(input.tagging.as_deref())?
    } else {
        source.tags.clone()
    };
    attrs.acl = acl;
    lock.apply(&mut attrs);
    Ok(Some(attrs))
}

/// Tags from an `x-amz-tagging` header, checked.
fn header_tags(value: Option<&str>) -> S3Result<tagging::Tags> {
    match value {
        Some(value) => tagging::check(tagging::from_header(value)?, tagging::MAX_OBJECT_TAGS),
        None => Ok(tagging::Tags::new()),
    }
}

/// The permission that shows an object's tag count.
const TAGGING: &str = "s3:GetObjectTagging";
/// The permission that shows owners in listings.
const READ_ACL: &str = "s3:GetObjectAcl";
/// The permission that shows a version's retention.
const READ_RETENTION: &str = "s3:GetObjectRetention";
/// The permission that shows a version's legal hold.
const READ_LEGAL_HOLD: &str = "s3:GetObjectLegalHold";
/// The permission to remove or shorten what governance-mode retention protects.
const BYPASS_GOVERNANCE: &str = "s3:BypassGovernanceRetention";

/// What a read shows of a version's lock, given what the caller may read.
fn read_lock(caller: Option<&access::Caller>, attrs: &ObjectAttrs) -> ReadLock {
    let may = |action| caller.is_none_or(|c| c.may(action));
    ReadLock::of(attrs, may(READ_RETENTION), may(READ_LEGAL_HOLD))
}

/// `x-amz-tagging-count`, when the object has tags.
fn tag_count(attrs: &ObjectAttrs) -> Option<i32> {
    (!attrs.tags.is_empty()).then(|| i32::try_from(attrs.tags.len()).unwrap_or(i32::MAX))
}

/// What `CompleteMultipartUpload` answers.
fn complete_output(
    bucket: &str,
    key: &str,
    info: &ObjectInfo,
    sums: &Sums,
    kind: Option<teifs_store::ChecksumType>,
) -> dto::CompleteMultipartUploadOutput {
    let mut out = dto::CompleteMultipartUploadOutput {
        bucket: Some(bucket.to_owned()),
        key: Some(key.to_owned()),
        location: Some(format!("/{bucket}/{key}")),
        e_tag: Some(etag(&info.etag)),
        checksum_type: checksum_type(sums, kind),
        version_id: written_version(info),
        ..Default::default()
    };
    set_checksums!(out, sums);
    out
}

/// The checksum algorithm and type an upload was created with, if the client chose them.
fn upload_checksum_dto(
    upload: &teifs_store::Upload,
) -> (Option<dto::ChecksumAlgorithm>, Option<dto::ChecksumType>) {
    match Store::upload_checksum(upload).filter(|c| c.requested) {
        Some(c) => (
            Some(dto::ChecksumAlgorithm::from(c.algorithm)),
            Some(dto::ChecksumType::from_static(c.kind.as_str())),
        ),
        None => (None, None),
    }
}

/// `x-amz-checksum-type` for these checksums: the recorded type, else full object.
fn checksum_type(
    sums: &Sums,
    kind: Option<teifs_store::ChecksumType>,
) -> Option<dto::ChecksumType> {
    (!sums.is_empty()).then(|| {
        dto::ChecksumType::from_static(
            kind.unwrap_or(teifs_store::ChecksumType::FullObject)
                .as_str(),
        )
    })
}

/// Whether a request's checksum comes as a trailer after its body.
fn has_trailer(headers: &http::HeaderMap) -> bool {
    headers
        .get("x-amz-trailer")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("x-amz-checksum-"))
}

fn checksum_mode_on(mode: Option<&ChecksumMode>) -> bool {
    mode.is_some_and(|m| m.as_str() == ChecksumMode::ENABLED)
}

/// Parses `bytes=first-last` (inclusive) for a part copy.
fn copy_range(range: &str, size: u64) -> S3Result<(u64, u64)> {
    let invalid = || {
        s3_error!(
            InvalidArgument,
            "the copy range must look like bytes=first-last"
        )
    };
    let (first, last) = range
        .strip_prefix("bytes=")
        .and_then(|r| r.split_once('-'))
        .ok_or_else(invalid)?;
    let (first, last): (u64, u64) = (
        first.parse().map_err(|_| invalid())?,
        last.parse().map_err(|_| invalid())?,
    );
    if first > last || last >= size {
        return Err(s3_error!(InvalidRange));
    }
    Ok((first, last - first + 1))
}

#[async_trait::async_trait]
impl S3 for Drive {
    async fn list_buckets(
        &self,
        req: S3Request<dto::ListBucketsInput>,
    ) -> S3Result<S3Response<dto::ListBucketsOutput>> {
        let input = req.input;
        let max = match input.max_buckets {
            None => usize::MAX,
            Some(n) => usize::try_from(n)
                .ok()
                .filter(|n| (1..=MAX_BUCKETS).contains(n))
                .ok_or_else(|| {
                    s3_error!(InvalidArgument, "max-buckets must be between 1 and 10000")
                })?,
        };
        let after = match input
            .continuation_token
            .as_deref()
            .filter(|t| !t.is_empty())
        {
            Some(token) => match encode::parse_token(token) {
                Some(After::Key(name)) => Some(name),
                _ => return Err(s3_error!(InvalidArgument, "invalid continuation token")),
            },
            None => None,
        };
        let prefix = input.prefix.clone().unwrap_or_default();
        // Every bucket lives in the drive's one region.
        let in_region = input.bucket_region.as_deref().is_none_or(|r| r == REGION);
        let mut buckets: Vec<_> = self
            .store
            .list_buckets()
            .await
            .s3()?
            .into_iter()
            .filter(|b| in_region && b.name.starts_with(&prefix))
            .filter(|b| after.as_ref().is_none_or(|a| b.name > *a))
            .collect();
        buckets.sort_by(|a, b| a.name.cmp(&b.name));
        let truncated = buckets.len() > max;
        buckets.truncate(max);
        let continuation_token = buckets
            .last()
            .filter(|_| truncated)
            .map(|b| encode::token(&After::Key(b.name.clone())));
        let buckets = buckets
            .into_iter()
            .map(|b| dto::Bucket {
                name: Some(b.name),
                creation_date: Some(b.created.into()),
                bucket_region: Some(REGION.to_owned()),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(dto::ListBucketsOutput {
            buckets: Some(buckets),
            owner: Some(acl::owner()),
            continuation_token,
            prefix: input.prefix,
        }))
    }

    async fn create_bucket(
        &self,
        req: S3Request<dto::CreateBucketInput>,
    ) -> S3Result<S3Response<dto::CreateBucketOutput>> {
        access::ensure_decided(&req)?;
        let layout = match req.headers.get(LAYOUT_HEADER).map(|v| v.to_str()) {
            None => self.default_layout,
            Some(Ok("object")) => Layout::Object,
            Some(Ok("folder")) => Layout::Folder,
            Some(_) => {
                return Err(s3_error!(
                    InvalidArgument,
                    "x-teifs-bucket-layout must be `object` or `folder`"
                ));
            }
        };
        let input = &req.input;
        let ownership = match &input.object_ownership {
            None if self.legacy_bucket_defaults => None,
            None => Some(ObjectOwnership::default()),
            Some(value) => Some(ObjectOwnership::parse(value.as_str()).ok_or_else(|| {
                s3_error!(
                    InvalidArgument,
                    "`{}` isn't an Object Ownership setting",
                    value.as_str()
                )
            })?),
        };
        let new = NewBucket {
            ownership,
            block_public_access: !self.legacy_bucket_defaults,
            acl: None,
            tags: None,
            object_lock: input.object_lock_enabled_for_bucket == Some(true),
        };
        let requested = acl::requested(&acl_headers!(input, bucket), true)?;
        let acl = acl::for_new_bucket(requested, &new)?;
        let configuration = input.create_bucket_configuration.as_ref();
        check_location(configuration)?;
        let tags = tagging::of_new_bucket(configuration)?;
        self.store
            .create_bucket_with(&input.bucket, layout, NewBucket { acl, tags, ..new })
            .await
            .s3()?;
        self.rules.forget(&input.bucket);
        Ok(S3Response::new(dto::CreateBucketOutput {
            location: Some(format!("/{}", req.input.bucket)),
            ..Default::default()
        }))
    }

    async fn head_bucket(
        &self,
        req: S3Request<dto::HeadBucketInput>,
    ) -> S3Result<S3Response<dto::HeadBucketOutput>> {
        self.store.head_bucket(&req.input.bucket).await.s3()?;
        Ok(S3Response::new(dto::HeadBucketOutput::default()))
    }

    async fn delete_bucket(
        &self,
        req: S3Request<dto::DeleteBucketInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketOutput>> {
        self.store.delete_bucket(&req.input.bucket).await.s3()?;
        self.rules.forget(&req.input.bucket);
        Ok(S3Response::new(dto::DeleteBucketOutput::default()))
    }

    async fn get_bucket_location(
        &self,
        req: S3Request<dto::GetBucketLocationInput>,
    ) -> S3Result<S3Response<dto::GetBucketLocationOutput>> {
        self.store.head_bucket(&req.input.bucket).await.s3()?;
        Ok(S3Response::new(dto::GetBucketLocationOutput::default()))
    }

    async fn get_bucket_versioning(
        &self,
        req: S3Request<dto::GetBucketVersioningInput>,
    ) -> S3Result<S3Response<dto::GetBucketVersioningOutput>> {
        // A bucket that never had versioning answers with no status, as S3's does.
        let status = match self.store.bucket_versioning(&req.input.bucket).await.s3()? {
            Versioning::Unversioned => None,
            Versioning::Enabled => Some(dto::BucketVersioningStatus::ENABLED),
            Versioning::Suspended => Some(dto::BucketVersioningStatus::SUSPENDED),
        };
        Ok(S3Response::new(dto::GetBucketVersioningOutput {
            status: status.map(dto::BucketVersioningStatus::from_static),
            ..Default::default()
        }))
    }

    async fn put_bucket_versioning(
        &self,
        req: S3Request<dto::PutBucketVersioningInput>,
    ) -> S3Result<S3Response<dto::PutBucketVersioningOutput>> {
        let input = req.input;
        let config = input.versioning_configuration;
        // MFA delete needs a hardware token TeiFS has no way to check.
        if config
            .mfa_delete
            .as_ref()
            .is_some_and(|m| m.as_str() == dto::MFADelete::ENABLED)
            || input.mfa.is_some()
        {
            return Err(s3_error!(
                NotImplemented,
                "MFA delete isn't supported: TeiFS has no MFA devices"
            ));
        }
        let versioning = match config
            .status
            .as_ref()
            .map(dto::BucketVersioningStatus::as_str)
        {
            Some(dto::BucketVersioningStatus::ENABLED) => Versioning::Enabled,
            Some(dto::BucketVersioningStatus::SUSPENDED) => Versioning::Suspended,
            // No status changes nothing, as on S3.
            None => {
                self.store.head_bucket(&input.bucket).await.s3()?;
                return Ok(S3Response::new(dto::PutBucketVersioningOutput::default()));
            }
            Some(_) => return Err(s3_error!(MalformedXML)),
        };
        self.store
            .set_bucket_versioning(&input.bucket, versioning)
            .await
            .s3()?;
        Ok(S3Response::new(dto::PutBucketVersioningOutput::default()))
    }

    async fn get_bucket_encryption(
        &self,
        req: S3Request<dto::GetBucketEncryptionInput>,
    ) -> S3Result<S3Response<dto::GetBucketEncryptionOutput>> {
        let Some(config) = self.store.bucket_encryption(&req.input.bucket).await.s3()? else {
            return Err(s3_error!(
                ServerSideEncryptionConfigurationNotFoundError,
                "a folder bucket stores plain files and has no encryption"
            ));
        };
        let algorithm = match config.default.mode {
            SseMode::Kms => dto::ServerSideEncryption::AWS_KMS,
            _ => dto::ServerSideEncryption::AES256,
        };
        let blocked = if config.block_customer_keys {
            dto::EncryptionType::SSE_C
        } else {
            dto::EncryptionType::NONE
        };
        let rule = dto::ServerSideEncryptionRule {
            apply_server_side_encryption_by_default: Some(dto::ServerSideEncryptionByDefault {
                sse_algorithm: dto::ServerSideEncryption::from_static(algorithm),
                kms_master_key_id: config.default.kms_key.clone(),
            }),
            bucket_key_enabled: Some(config.default.bucket_key),
            blocked_encryption_types: Some(dto::BlockedEncryptionTypes {
                encryption_type: Some(vec![dto::EncryptionType::from_static(blocked)]),
            }),
        };
        Ok(S3Response::new(dto::GetBucketEncryptionOutput {
            server_side_encryption_configuration: Some(dto::ServerSideEncryptionConfiguration {
                rules: vec![rule],
            }),
        }))
    }

    async fn put_bucket_encryption(
        &self,
        req: S3Request<dto::PutBucketEncryptionInput>,
    ) -> S3Result<S3Response<dto::PutBucketEncryptionOutput>> {
        let input = req.input;
        let [rule] = input.server_side_encryption_configuration.rules.as_slice() else {
            return Err(s3_error!(
                MalformedXML,
                "a bucket encryption configuration has exactly one rule"
            ));
        };
        let current = self
            .store
            .bucket_encryption(&input.bucket)
            .await
            .s3()?
            .unwrap_or_else(BucketEncryption::aws_default);
        let default = match &rule.apply_server_side_encryption_by_default {
            None => current.default.clone(),
            Some(by_default) => {
                let kms_key = by_default
                    .kms_master_key_id
                    .as_deref()
                    .map(sse::kms_key_name);
                let mode = match by_default.sse_algorithm.as_str() {
                    dto::ServerSideEncryption::AES256 if kms_key.is_none() => SseMode::S3,
                    dto::ServerSideEncryption::AES256 => {
                        return Err(s3_error!(
                            InvalidArgument,
                            "a KMS key can only be given with aws:kms"
                        ));
                    }
                    dto::ServerSideEncryption::AWS_KMS => SseMode::Kms,
                    dto::ServerSideEncryption::AWS_KMS_DSSE => {
                        return Err(s3_error!(
                            NotImplemented,
                            "dual-layer encryption (aws:kms:dsse) isn't supported"
                        ));
                    }
                    _ => {
                        return Err(s3_error!(
                            InvalidArgument,
                            "the algorithm must be AES256 or aws:kms"
                        ));
                    }
                };
                DefaultEncryption {
                    mode,
                    kms_key,
                    bucket_key: rule.bucket_key_enabled.unwrap_or(false),
                }
            }
        };
        let block_customer_keys = match rule
            .blocked_encryption_types
            .as_ref()
            .and_then(|b| b.encryption_type.as_ref())
        {
            None => current.block_customer_keys,
            Some(types) => {
                let names: Vec<&str> = types.iter().map(dto::EncryptionType::as_str).collect();
                match names.as_slice() {
                    [dto::EncryptionType::SSE_C] => true,
                    [dto::EncryptionType::NONE] | [] => false,
                    _ => {
                        return Err(s3_error!(
                            InvalidArgument,
                            "BlockedEncryptionTypes is SSE-C or NONE"
                        ));
                    }
                }
            }
        };
        self.store
            .set_bucket_encryption(
                &input.bucket,
                Some(BucketEncryption {
                    default,
                    block_customer_keys,
                }),
            )
            .await
            .s3()?;
        Ok(S3Response::new(dto::PutBucketEncryptionOutput::default()))
    }

    async fn delete_bucket_encryption(
        &self,
        req: S3Request<dto::DeleteBucketEncryptionInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketEncryptionOutput>> {
        // As on AWS, a bucket goes back to the default (SSE-S3), not to no encryption.
        self.store
            .set_bucket_encryption(&req.input.bucket, None)
            .await
            .s3()?;
        Ok(S3Response::new(dto::DeleteBucketEncryptionOutput::default()))
    }

    async fn put_object(
        &self,
        req: S3Request<dto::PutObjectInput>,
    ) -> S3Result<S3Response<dto::PutObjectOutput>> {
        let mut input = req.input;
        let body = input.body.take().ok_or_else(|| s3_error!(IncompleteBody))?;
        let limit = req
            .extensions
            .get::<Caps>()
            .and_then(|caps| caps.content_length);
        if let Some(cap) = limit {
            caps::admit(input.content_length, cap)?;
        }
        let tags = header_tags(input.tagging.as_deref())?;
        let lock = write_lock!(input)?;
        let mut sent = checksums::from_dto(&checksum_of!(input));
        // S3 wants a locked object's bytes checked on the way in (a browser form has no
        // way to send a checksum header).
        let checked = input.content_md5.is_some()
            || input.checksum_algorithm.is_some()
            || !sent.is_empty()
            || has_trailer(&req.headers);
        if lock.is_some() && !checked && req.extensions.get::<Form>().is_none() {
            return Err(s3_error!(
                InvalidRequest,
                "Content-MD5 OR x-amz-checksum- HTTP header is required for Put Object requests with Object Lock parameters"
            ));
        }
        // Like S3, an object sent without a checksum gets CRC64NVME.
        let algorithm = input
            .checksum_algorithm
            .as_ref()
            .map(s3s::dto::ChecksumAlgorithm::as_str)
            .or_else(|| {
                (sent.is_empty() && !has_trailer(&req.headers))
                    .then_some(checksums::DEFAULT_ALGORITHM)
            });
        let mut hasher = checksums::hasher(&sent, algorithm)?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let customer_md5 = customer.as_ref().map(CustomerKey::md5_base64);
        let encryption = self
            .write_encryption(
                &input.bucket,
                sse::WriteRequest {
                    sse: input.server_side_encryption.as_ref(),
                    kms_key: input.ssekms_key_id.as_deref(),
                    kms_context: input.ssekms_encryption_context.as_deref(),
                    bucket_key: input.bucket_key_enabled,
                    customer,
                },
            )
            .await?;
        self.check_write(&input.bucket, Some(&input.key), input.content_length)
            .await?;
        let acl = self
            .object_write_acl(&input.bucket, acl_headers!(input))
            .await?;
        let staged = self
            .store
            .stage_for(&input.bucket, &encryption)
            .await
            .s3()?;
        let staged = self.stage(staged, body, &mut hasher, limit).await?;
        checksums::add_trailers(&mut sent, req.trailing_headers)?;
        let computed = checksums::from_dto(&hasher.finalize());
        checksums::verify(&sent, &computed)?;
        if let Some(content_md5) = &input.content_md5 {
            use base64::Engine;
            let expected = base64::engine::general_purpose::STANDARD
                .decode(content_md5)
                .map_err(|_| s3_error!(InvalidDigest))?;
            if expected != staged.md5() {
                return Err(s3_error!(BadDigest, "Content-MD5 doesn't match the data"));
            }
        }
        let mut attrs = new_attrs!(input).into_attrs(computed.clone());
        attrs.tags = tags;
        attrs.acl = acl;
        lock.apply(&mut attrs);
        let pre = precondition(input.if_match.as_ref(), input.if_none_match.as_ref());
        let info = self
            .store
            .commit(&input.bucket, &input.key, staged, attrs, pre)
            .await
            .s3()?;
        let mut out = dto::PutObjectOutput {
            e_tag: Some(etag(&info.etag)),
            checksum_type: checksum_type(&computed, None),
            version_id: written_version(&info),
            expiration: self.expiration(&input.bucket, &info).await,
            ..Default::default()
        };
        set_checksums!(out, &computed);
        set_sse!(out, with_customer_md5(info.sse, customer_md5).as_ref());
        Ok(S3Response::new(out))
    }

    async fn post_object(
        &self,
        req: S3Request<dto::PostObjectInput>,
    ) -> S3Result<S3Response<dto::PostObjectOutput>> {
        let form = req
            .extensions
            .get::<Form>()
            .cloned()
            .ok_or_else(post_form::too_large)?;
        // Only the object whose upload was authorized.
        if form.key() != Some(req.input.key.as_str()) {
            return Err(s3_error!(AccessDenied, "Access Denied"));
        }
        let tags = form.tags()?;
        let req = req.map_input(|x| post_form::into_put(x, &form, tags));
        let mut response = self.put_object(req).await?.map_output(post_form::from_put);
        // As AWS answers a form: the ETag as a header, and quoted where s3s writes it (a
        // redirect's `etag` and the 201 answer's body).
        if let Some(etag) = response.output.e_tag.take() {
            let quoted = format!("\"{}\"", etag.value());
            if let Ok(value) = http::HeaderValue::from_str(&quoted) {
                response.headers.insert(http::header::ETAG, value);
            }
            response.output.e_tag = Some(ETag::Strong(quoted));
        }
        Ok(response)
    }

    async fn rename_object(
        &self,
        req: S3Request<dto::RenameObjectInput>,
    ) -> S3Result<S3Response<dto::RenameObjectOutput>> {
        let input = req.input;
        let source_key = rename_source(&input.rename_source, &input.bucket)?;
        let time = |t: Option<&Timestamp>| t.map(to_system_time);
        let text_condition = |value: Option<&String>| {
            value.map(|v| match v.trim() {
                "*" => Match::Any,
                etag => Match::ETag(etag.trim_matches('"').to_owned()),
            })
        };
        let source = Precondition {
            if_match: text_condition(input.source_if_match.as_ref()),
            if_none_match: text_condition(input.source_if_none_match.as_ref()),
            if_modified_since: time(input.source_if_modified_since.as_ref()),
            if_unmodified_since: time(input.source_if_unmodified_since.as_ref()),
            ..Precondition::default()
        };
        let destination = Precondition {
            if_modified_since: time(input.destination_if_modified_since.as_ref()),
            if_unmodified_since: time(input.destination_if_unmodified_since.as_ref()),
            ..precondition(
                input.destination_if_match.as_ref(),
                input.destination_if_none_match.as_ref(),
            )
        };
        if let Some(token) = &input.client_token
            && !(1..=64).contains(&token.len())
        {
            return Err(s3_error!(
                InvalidArgument,
                "x-amz-client-token is 1 to 64 characters"
            ));
        }
        self.store
            .rename(
                &input.bucket,
                &source_key,
                &input.key,
                source,
                destination,
                input.client_token,
            )
            .await
            .s3()?;
        Ok(S3Response::new(dto::RenameObjectOutput::default()))
    }

    async fn get_object(
        &self,
        req: S3Request<dto::GetObjectInput>,
    ) -> S3Result<S3Response<dto::GetObjectOutput>> {
        let caller = access::caller(&req).cloned();
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let (info, file) = self
            .read(
                (&input.bucket, &input.key, version_id),
                customer.as_ref(),
                input.part_number,
            )
            .await
            .map_err(|e| access::hide_missing(caller.as_ref(), &input.bucket, e))?;
        check_read(
            &info,
            input.if_match.as_ref(),
            input.if_none_match.as_ref(),
            input.if_modified_since.as_ref(),
            input.if_unmodified_since.as_ref(),
        )?;
        let slice = Slice::of(&info, input.range.as_ref(), input.part_number)?;
        let body = match file {
            Some(body) => {
                let reader = body.range(slice.start, slice.len).await.s3()?;
                StreamingBlob::wrap(ReaderStream::with_capacity(reader, READ_CHUNK))
            }
            None => StreamingBlob::from(s3s::Body::empty()),
        };
        let mut out = dto::GetObjectOutput {
            version_id: info.version_id.clone(),
            body: Some(body),
            content_length: Some(i64::try_from(slice.len).unwrap_or(i64::MAX)),
            content_range: slice.content_range.clone(),
            parts_count: slice.parts_count,
            accept_ranges: Some("bytes".to_owned()),
            last_modified: Some(info.modified.into()),
            e_tag: Some(etag(&info.etag)),
            content_type: Some(
                input
                    .response_content_type
                    .unwrap_or_else(|| info.content_type()),
            ),
            content_encoding: input
                .response_content_encoding
                .or_else(|| info.attrs.content_encoding.clone()),
            content_disposition: input
                .response_content_disposition
                .or_else(|| info.attrs.content_disposition.clone()),
            content_language: input
                .response_content_language
                .or_else(|| info.attrs.content_language.clone()),
            cache_control: input
                .response_cache_control
                .or_else(|| info.attrs.cache_control.clone()),
            expires: input
                .response_expires
                .as_ref()
                .map(http_date)
                .or_else(|| info.attrs.expires.clone()),
            website_redirect_location: info.attrs.website_redirect_location.clone(),
            metadata: user_metadata(&info.attrs),
            tag_count: tag_count(&info.attrs)
                .filter(|_| caller.as_ref().is_none_or(|c| c.may(TAGGING))),
            expiration: match version_id {
                None => self.expiration(&input.bucket, &info).await,
                Some(_) => None,
            },
            ..Default::default()
        };
        if let Some(sums) = slice.checksums
            && checksum_mode_on(input.checksum_mode.as_ref())
        {
            set_checksums!(out, sums);
            out.checksum_type.clone_from(&slice.checksum_type);
        }
        set_sse!(out, info.sse.as_ref());
        set_lock!(out, read_lock(caller.as_ref(), &info.attrs));
        Ok(S3Response::new(out))
    }

    async fn head_object(
        &self,
        req: S3Request<dto::HeadObjectInput>,
    ) -> S3Result<S3Response<dto::HeadObjectOutput>> {
        let caller = access::caller(&req).cloned();
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let (info, _) = self
            .read(
                (&input.bucket, &input.key, version_id),
                customer.as_ref(),
                input.part_number,
            )
            .await
            .map_err(|e| access::hide_missing(caller.as_ref(), &input.bucket, e))?;
        check_read(
            &info,
            input.if_match.as_ref(),
            input.if_none_match.as_ref(),
            input.if_modified_since.as_ref(),
            input.if_unmodified_since.as_ref(),
        )?;
        let slice = Slice::of(&info, input.range.as_ref(), input.part_number)?;
        let mut out = dto::HeadObjectOutput {
            version_id: info.version_id.clone(),
            content_length: Some(i64::try_from(slice.len).unwrap_or(i64::MAX)),
            content_range: slice.content_range.clone(),
            parts_count: slice.parts_count,
            accept_ranges: Some("bytes".to_owned()),
            last_modified: Some(info.modified.into()),
            e_tag: Some(etag(&info.etag)),
            content_type: Some(info.content_type()),
            content_encoding: info.attrs.content_encoding.clone(),
            content_disposition: info.attrs.content_disposition.clone(),
            content_language: info.attrs.content_language.clone(),
            cache_control: info.attrs.cache_control.clone(),
            expires: info.attrs.expires.clone(),
            website_redirect_location: info.attrs.website_redirect_location.clone(),
            metadata: user_metadata(&info.attrs),
            tag_count: tag_count(&info.attrs)
                .filter(|_| caller.as_ref().is_none_or(|c| c.may(TAGGING))),
            expiration: match version_id {
                None => self.expiration(&input.bucket, &info).await,
                Some(_) => None,
            },
            ..Default::default()
        };
        if let Some(sums) = slice.checksums
            && checksum_mode_on(input.checksum_mode.as_ref())
        {
            set_checksums!(out, sums);
            out.checksum_type.clone_from(&slice.checksum_type);
        }
        set_sse!(out, info.sse.as_ref());
        set_lock!(out, read_lock(caller.as_ref(), &info.attrs));
        let mut response = S3Response::new(out);
        if slice.content_range.is_some() {
            // s3s answers every HEAD with 200; a partial one is 206, as for GET.
            response.status = Some(http::StatusCode::PARTIAL_CONTENT);
        }
        Ok(response)
    }

    async fn get_object_attributes(
        &self,
        req: S3Request<dto::GetObjectAttributesInput>,
    ) -> S3Result<S3Response<dto::GetObjectAttributesOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let (info, _) = self
            .store
            .read_with(&input.bucket, &input.key, version_id, customer.as_ref())
            .await
            .s3()?;
        // SDKs send the list as one comma-separated header.
        let wants = |name: &str| {
            input
                .object_attributes
                .iter()
                .flat_map(|a| a.as_str().split(','))
                .any(|a| a.trim() == name)
        };
        let mut out = dto::GetObjectAttributesOutput {
            last_modified: Some(info.modified.into()),
            version_id: info.version_id.clone(),
            ..Default::default()
        };
        if wants(dto::ObjectAttributes::ETAG) {
            out.e_tag = Some(etag(&info.etag));
        }
        if wants(dto::ObjectAttributes::OBJECT_SIZE) {
            out.object_size = Some(i64::try_from(info.size).unwrap_or(i64::MAX));
        }
        if wants(dto::ObjectAttributes::STORAGE_CLASS) {
            out.storage_class = Some(dto::StorageClass::from_static(dto::StorageClass::STANDARD));
        }
        if wants(dto::ObjectAttributes::CHECKSUM) && !info.attrs.checksums.is_empty() {
            let mut checksum = checksums::to_dto(&info.attrs.checksums);
            checksum.checksum_type = checksum_type(&info.attrs.checksums, info.attrs.checksum_type);
            out.checksum = Some(checksum);
        }
        if wants(dto::ObjectAttributes::OBJECT_PARTS) && !info.parts.is_empty() {
            out.object_parts = Some(object_parts(
                &info.parts,
                input.part_number_marker,
                input.max_parts,
            ));
        }
        Ok(S3Response::new(out))
    }

    async fn get_object_tagging(
        &self,
        req: S3Request<dto::GetObjectTaggingInput>,
    ) -> S3Result<S3Response<dto::GetObjectTaggingOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let info = self
            .store
            .head_version(&input.bucket, &input.key, version_id)
            .await
            .s3()?;
        Ok(S3Response::new(dto::GetObjectTaggingOutput {
            tag_set: tagging::to_dto(&info.attrs.tags),
            version_id: info.version_id,
        }))
    }

    async fn put_object_tagging(
        &self,
        req: S3Request<dto::PutObjectTaggingInput>,
    ) -> S3Result<S3Response<dto::PutObjectTaggingOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let tags = tagging::check(tagging::from_dto(input.tagging), tagging::MAX_OBJECT_TAGS)?;
        let info = self
            .store
            .set_tags(&input.bucket, &input.key, version_id, tags)
            .await
            .s3()?;
        Ok(S3Response::new(dto::PutObjectTaggingOutput {
            version_id: info.version_id,
        }))
    }

    async fn delete_object_tagging(
        &self,
        req: S3Request<dto::DeleteObjectTaggingInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectTaggingOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let info = self
            .store
            .set_tags(&input.bucket, &input.key, version_id, tagging::Tags::new())
            .await
            .s3()?;
        Ok(S3Response::new(dto::DeleteObjectTaggingOutput {
            version_id: info.version_id,
        }))
    }

    async fn get_object_lock_configuration(
        &self,
        req: S3Request<dto::GetObjectLockConfigurationInput>,
    ) -> S3Result<S3Response<dto::GetObjectLockConfigurationOutput>> {
        let lock = self
            .store
            .bucket_object_lock(&req.input.bucket)
            .await
            .s3()?
            .ok_or_else(|| {
                s3_error!(
                    ObjectLockConfigurationNotFoundError,
                    "Object Lock configuration does not exist for this bucket"
                )
            })?;
        Ok(S3Response::new(dto::GetObjectLockConfigurationOutput {
            object_lock_configuration: Some(object_lock::config_to_dto(&lock)),
        }))
    }

    async fn put_object_lock_configuration(
        &self,
        req: S3Request<dto::PutObjectLockConfigurationInput>,
    ) -> S3Result<S3Response<dto::PutObjectLockConfigurationOutput>> {
        let input = req.input;
        let lock = object_lock::config_from_dto(input.object_lock_configuration)?;
        self.store
            .set_bucket_object_lock(&input.bucket, lock)
            .await
            .s3()?;
        Ok(S3Response::new(
            dto::PutObjectLockConfigurationOutput::default(),
        ))
    }

    async fn get_object_retention(
        &self,
        req: S3Request<dto::GetObjectRetentionInput>,
    ) -> S3Result<S3Response<dto::GetObjectRetentionOutput>> {
        let input = req.input;
        let info = self
            .locked_version(&input.bucket, &input.key, input.version_id.as_deref())
            .await?;
        let retention = info.attrs.retention.ok_or_else(no_lock_of_object)?;
        Ok(S3Response::new(dto::GetObjectRetentionOutput {
            retention: Some(object_lock::retention_to_dto(&retention)),
        }))
    }

    async fn put_object_retention(
        &self,
        req: S3Request<dto::PutObjectRetentionInput>,
    ) -> S3Result<S3Response<dto::PutObjectRetentionOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let retention = object_lock::retention_from_dto(input.retention)?;
        // The access check made sure the caller may bypass governance when it asks.
        let bypass = input.bypass_governance_retention == Some(true);
        self.store
            .set_retention(&input.bucket, &input.key, version_id, retention, bypass)
            .await
            .s3()?;
        Ok(S3Response::new(dto::PutObjectRetentionOutput::default()))
    }

    async fn get_object_legal_hold(
        &self,
        req: S3Request<dto::GetObjectLegalHoldInput>,
    ) -> S3Result<S3Response<dto::GetObjectLegalHoldOutput>> {
        let input = req.input;
        let info = self
            .locked_version(&input.bucket, &input.key, input.version_id.as_deref())
            .await?;
        let on = info.attrs.legal_hold.ok_or_else(no_lock_of_object)?;
        Ok(S3Response::new(dto::GetObjectLegalHoldOutput {
            legal_hold: Some(object_lock::legal_hold_to_dto(on)),
        }))
    }

    async fn put_object_legal_hold(
        &self,
        req: S3Request<dto::PutObjectLegalHoldInput>,
    ) -> S3Result<S3Response<dto::PutObjectLegalHoldOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let on = object_lock::legal_hold_from_dto(input.legal_hold)?;
        self.store
            .set_legal_hold(&input.bucket, &input.key, version_id, on)
            .await
            .s3()?;
        Ok(S3Response::new(dto::PutObjectLegalHoldOutput::default()))
    }

    async fn update_object_encryption(
        &self,
        req: S3Request<dto::UpdateObjectEncryptionInput>,
    ) -> S3Result<S3Response<dto::UpdateObjectEncryptionOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let (kms_key, bucket_key) = sse::update_target(input.object_encryption)?;
        self.store
            .update_encryption(&input.bucket, &input.key, version_id, &kms_key, bucket_key)
            .await
            .s3()?;
        Ok(S3Response::new(dto::UpdateObjectEncryptionOutput::default()))
    }

    async fn get_bucket_cors(
        &self,
        req: S3Request<dto::GetBucketCorsInput>,
    ) -> S3Result<S3Response<dto::GetBucketCorsOutput>> {
        let rules = self
            .store
            .bucket_cors(&req.input.bucket)
            .await
            .s3()?
            .ok_or_else(|| {
                s3_error!(
                    NoSuchCORSConfiguration,
                    "The CORS configuration does not exist"
                )
            })?;
        Ok(S3Response::new(dto::GetBucketCorsOutput {
            cors_rules: Some(cors::to_dto(rules)),
        }))
    }

    async fn put_bucket_cors(
        &self,
        req: S3Request<dto::PutBucketCorsInput>,
    ) -> S3Result<S3Response<dto::PutBucketCorsOutput>> {
        let input = req.input;
        let rules = cors::from_dto(input.cors_configuration)?;
        self.store
            .set_bucket_cors(&input.bucket, Some(rules))
            .await
            .s3()?;
        Ok(S3Response::new(dto::PutBucketCorsOutput::default()))
    }

    async fn delete_bucket_cors(
        &self,
        req: S3Request<dto::DeleteBucketCorsInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketCorsOutput>> {
        self.store
            .set_bucket_cors(&req.input.bucket, None)
            .await
            .s3()?;
        Ok(S3Response::new(dto::DeleteBucketCorsOutput::default()))
    }

    async fn get_bucket_lifecycle_configuration(
        &self,
        req: S3Request<dto::GetBucketLifecycleConfigurationInput>,
    ) -> S3Result<S3Response<dto::GetBucketLifecycleConfigurationOutput>> {
        let lifecycle = self
            .store
            .bucket_lifecycle(&req.input.bucket)
            .await
            .s3()?
            .ok_or_else(|| {
                s3_error!(
                    NoSuchLifecycleConfiguration,
                    "The lifecycle configuration does not exist"
                )
            })?;
        Ok(S3Response::new(lifecycle::to_dto(&lifecycle)))
    }

    async fn put_bucket_lifecycle_configuration(
        &self,
        req: S3Request<dto::PutBucketLifecycleConfigurationInput>,
    ) -> S3Result<S3Response<dto::PutBucketLifecycleConfigurationOutput>> {
        let input = req.input;
        let config = lifecycle::from_dto(
            input.lifecycle_configuration,
            input.transition_default_minimum_object_size.as_ref(),
        )?;
        let minimum_size = lifecycle::minimum_size(&config);
        self.store
            .set_bucket_lifecycle(&input.bucket, Some(config))
            .await
            .s3()?;
        Ok(S3Response::new(
            dto::PutBucketLifecycleConfigurationOutput {
                transition_default_minimum_object_size: Some(minimum_size),
            },
        ))
    }

    async fn delete_bucket_lifecycle(
        &self,
        req: S3Request<dto::DeleteBucketLifecycleInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketLifecycleOutput>> {
        self.store
            .set_bucket_lifecycle(&req.input.bucket, None)
            .await
            .s3()?;
        Ok(S3Response::new(dto::DeleteBucketLifecycleOutput::default()))
    }

    async fn get_bucket_policy(
        &self,
        req: S3Request<dto::GetBucketPolicyInput>,
    ) -> S3Result<S3Response<dto::GetBucketPolicyOutput>> {
        let access = self.store.bucket_access(&req.input.bucket).await.s3()?;
        let policy = access.policy.ok_or_else(bucket_access::no_policy)?;
        Ok(S3Response::new(dto::GetBucketPolicyOutput {
            policy: Some(policy),
        }))
    }

    async fn get_bucket_policy_status(
        &self,
        req: S3Request<dto::GetBucketPolicyStatusInput>,
    ) -> S3Result<S3Response<dto::GetBucketPolicyStatusOutput>> {
        self.store.head_bucket(&req.input.bucket).await.s3()?;
        let rules = self.rules.of(&req.input.bucket).await?;
        if rules.policy.is_none() {
            return Err(bucket_access::no_policy());
        }
        Ok(S3Response::new(dto::GetBucketPolicyStatusOutput {
            policy_status: Some(dto::PolicyStatus {
                is_public: Some(rules.public),
            }),
        }))
    }

    async fn put_bucket_policy(
        &self,
        req: S3Request<dto::PutBucketPolicyInput>,
    ) -> S3Result<S3Response<dto::PutBucketPolicyOutput>> {
        let input = req.input;
        self.store.head_bucket(&input.bucket).await.s3()?;
        let policy = bucket_access::parse_policy(&input.bucket, &input.policy)?;
        let rules = self.rules.of(&input.bucket).await?;
        if rules.block.block_public_policy && policy.is_public() {
            return Err(s3_error!(
                AccessDenied,
                "Access Denied: the bucket's Block Public Access settings (BlockPublicPolicy) \
                 refuse a public policy"
            ));
        }
        self.store
            .set_bucket_policy(&input.bucket, Some(input.policy))
            .await
            .s3()?;
        self.rules.forget(&input.bucket);
        Ok(S3Response::new(dto::PutBucketPolicyOutput::default()))
    }

    async fn delete_bucket_policy(
        &self,
        req: S3Request<dto::DeleteBucketPolicyInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketPolicyOutput>> {
        self.store
            .set_bucket_policy(&req.input.bucket, None)
            .await
            .s3()?;
        self.rules.forget(&req.input.bucket);
        Ok(S3Response::new(dto::DeleteBucketPolicyOutput::default()))
    }

    async fn get_public_access_block(
        &self,
        req: S3Request<dto::GetPublicAccessBlockInput>,
    ) -> S3Result<S3Response<dto::GetPublicAccessBlockOutput>> {
        let access = self.store.bucket_access(&req.input.bucket).await.s3()?;
        let block = access
            .public_access_block
            .ok_or_else(bucket_access::no_public_access_block)?;
        Ok(S3Response::new(dto::GetPublicAccessBlockOutput {
            public_access_block_configuration: Some(bucket_access::block_to_dto(block)),
        }))
    }

    async fn put_public_access_block(
        &self,
        req: S3Request<dto::PutPublicAccessBlockInput>,
    ) -> S3Result<S3Response<dto::PutPublicAccessBlockOutput>> {
        let input = req.input;
        let block = bucket_access::block_from_dto(&input.public_access_block_configuration);
        self.store
            .set_bucket_public_access_block(&input.bucket, Some(block))
            .await
            .s3()?;
        self.rules.forget(&input.bucket);
        Ok(S3Response::new(dto::PutPublicAccessBlockOutput::default()))
    }

    async fn delete_public_access_block(
        &self,
        req: S3Request<dto::DeletePublicAccessBlockInput>,
    ) -> S3Result<S3Response<dto::DeletePublicAccessBlockOutput>> {
        self.store
            .set_bucket_public_access_block(&req.input.bucket, None)
            .await
            .s3()?;
        self.rules.forget(&req.input.bucket);
        Ok(S3Response::new(
            dto::DeletePublicAccessBlockOutput::default(),
        ))
    }

    async fn get_bucket_ownership_controls(
        &self,
        req: S3Request<dto::GetBucketOwnershipControlsInput>,
    ) -> S3Result<S3Response<dto::GetBucketOwnershipControlsOutput>> {
        let access = self.store.bucket_access(&req.input.bucket).await.s3()?;
        let ownership = access.ownership.ok_or_else(acl::no_ownership_controls)?;
        Ok(S3Response::new(dto::GetBucketOwnershipControlsOutput {
            ownership_controls: Some(dto::OwnershipControls {
                rules: vec![dto::OwnershipControlsRule {
                    object_ownership: dto::ObjectOwnership::from(ownership.name().to_owned()),
                }],
            }),
        }))
    }

    async fn put_bucket_ownership_controls(
        &self,
        req: S3Request<dto::PutBucketOwnershipControlsInput>,
    ) -> S3Result<S3Response<dto::PutBucketOwnershipControlsOutput>> {
        let input = req.input;
        let ownership = match input.ownership_controls.rules.as_slice() {
            [rule] => ObjectOwnership::parse(rule.object_ownership.as_str()),
            _ => None,
        }
        .ok_or_else(|| {
            s3_error!(
                MalformedXML,
                "OwnershipControls needs exactly one rule, with BucketOwnerEnforced, \
                 BucketOwnerPreferred or ObjectWriter"
            )
        })?;
        self.store
            .set_bucket_ownership(&input.bucket, Some(ownership))
            .await
            .s3()?;
        self.rules.forget(&input.bucket);
        Ok(S3Response::new(
            dto::PutBucketOwnershipControlsOutput::default(),
        ))
    }

    async fn delete_bucket_ownership_controls(
        &self,
        req: S3Request<dto::DeleteBucketOwnershipControlsInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketOwnershipControlsOutput>> {
        self.store
            .set_bucket_ownership(&req.input.bucket, None)
            .await
            .s3()?;
        self.rules.forget(&req.input.bucket);
        Ok(S3Response::new(
            dto::DeleteBucketOwnershipControlsOutput::default(),
        ))
    }

    async fn get_bucket_acl(
        &self,
        req: S3Request<dto::GetBucketAclInput>,
    ) -> S3Result<S3Response<dto::GetBucketAclOutput>> {
        self.store.head_bucket(&req.input.bucket).await.s3()?;
        let rules = self.rules.of(&req.input.bucket).await?;
        let acl = acl::effective(rules.ownership, rules.acl.clone());
        Ok(S3Response::new(dto::GetBucketAclOutput {
            grants: Some(acl::to_grants(&acl)),
            owner: Some(acl::owner()),
        }))
    }

    async fn put_bucket_acl(
        &self,
        req: S3Request<dto::PutBucketAclInput>,
    ) -> S3Result<S3Response<dto::PutBucketAclOutput>> {
        let mut input = req.input;
        let headers = acl_headers!(input, bucket);
        let requested = acl::put_request(&headers, input.access_control_policy.take(), true)?;
        self.store.head_bucket(&input.bucket).await.s3()?;
        let rules = self.rules.of(&input.bucket).await?;
        let acl = acl::for_acl_write(requested, rules.ownership, rules.block)?;
        self.store
            .set_bucket_acl(&input.bucket, Some(acl))
            .await
            .s3()?;
        self.rules.forget(&input.bucket);
        Ok(S3Response::new(dto::PutBucketAclOutput::default()))
    }

    async fn get_object_acl(
        &self,
        req: S3Request<dto::GetObjectAclInput>,
    ) -> S3Result<S3Response<dto::GetObjectAclOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        let info = self
            .store
            .head_version(&input.bucket, &input.key, version_id)
            .await
            .s3()?;
        let rules = self.rules.of(&input.bucket).await?;
        let acl = acl::effective(rules.ownership, info.attrs.acl);
        Ok(S3Response::new(dto::GetObjectAclOutput {
            grants: Some(acl::to_grants(&acl)),
            owner: Some(acl::owner()),
            ..Default::default()
        }))
    }

    async fn put_object_acl(
        &self,
        req: S3Request<dto::PutObjectAclInput>,
    ) -> S3Result<S3Response<dto::PutObjectAclOutput>> {
        let mut input = req.input;
        let version_id = check_version(input.version_id.as_deref())?.map(str::to_owned);
        let version_id = version_id.as_deref();
        let headers = AclHeaders {
            write: input.grant_write.as_deref(),
            ..acl_headers!(input)
        };
        let requested = acl::put_request(&headers, input.access_control_policy.take(), false)?;
        self.store
            .head_version(&input.bucket, &input.key, version_id)
            .await
            .s3()?;
        let rules = self.rules.of(&input.bucket).await?;
        let acl = acl::for_acl_write(requested, rules.ownership, rules.block)?;
        self.store
            .set_acl(&input.bucket, &input.key, version_id, Some(acl))
            .await
            .s3()?;
        Ok(S3Response::new(dto::PutObjectAclOutput::default()))
    }

    async fn get_bucket_tagging(
        &self,
        req: S3Request<dto::GetBucketTaggingInput>,
    ) -> S3Result<S3Response<dto::GetBucketTaggingOutput>> {
        let tags = self
            .store
            .bucket_tags(&req.input.bucket)
            .await
            .s3()?
            .ok_or_else(|| s3_error!(NoSuchTagSet, "The TagSet does not exist"))?;
        Ok(S3Response::new(dto::GetBucketTaggingOutput {
            tag_set: tagging::to_dto(&tags),
        }))
    }

    async fn put_bucket_tagging(
        &self,
        req: S3Request<dto::PutBucketTaggingInput>,
    ) -> S3Result<S3Response<dto::PutBucketTaggingOutput>> {
        let input = req.input;
        let tags = tagging::check(tagging::from_dto(input.tagging), tagging::MAX_BUCKET_TAGS)?;
        self.store
            .set_bucket_tags(&input.bucket, Some(tags))
            .await
            .s3()?;
        self.rules.forget(&input.bucket);
        Ok(S3Response::new(dto::PutBucketTaggingOutput::default()))
    }

    async fn delete_bucket_tagging(
        &self,
        req: S3Request<dto::DeleteBucketTaggingInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketTaggingOutput>> {
        self.store
            .set_bucket_tags(&req.input.bucket, None)
            .await
            .s3()?;
        self.rules.forget(&req.input.bucket);
        Ok(S3Response::new(dto::DeleteBucketTaggingOutput::default()))
    }

    async fn get_bucket_abac(
        &self,
        req: S3Request<dto::GetBucketAbacInput>,
    ) -> S3Result<S3Response<dto::GetBucketAbacOutput>> {
        let enabled = self.store.bucket_abac(&req.input.bucket).await.s3()?;
        let status = if enabled {
            dto::BucketAbacStatus::ENABLED
        } else {
            dto::BucketAbacStatus::DISABLED
        };
        Ok(S3Response::new(dto::GetBucketAbacOutput {
            abac_status: Some(dto::AbacStatus {
                status: Some(dto::BucketAbacStatus::from_static(status)),
            }),
        }))
    }

    async fn put_bucket_abac(
        &self,
        req: S3Request<dto::PutBucketAbacInput>,
    ) -> S3Result<S3Response<dto::PutBucketAbacOutput>> {
        let input = req.input;
        let enabled = match input
            .abac_status
            .status
            .as_ref()
            .map(dto::BucketAbacStatus::as_str)
        {
            Some(dto::BucketAbacStatus::ENABLED) => true,
            Some(dto::BucketAbacStatus::DISABLED) => false,
            _ => {
                return Err(s3_error!(
                    MalformedXML,
                    "The ABAC status must be Enabled or Disabled"
                ));
            }
        };
        self.store
            .set_bucket_abac(&input.bucket, enabled)
            .await
            .s3()?;
        self.rules.forget(&input.bucket);
        Ok(S3Response::new(dto::PutBucketAbacOutput::default()))
    }

    async fn delete_object(
        &self,
        req: S3Request<dto::DeleteObjectInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectOutput>> {
        let input = req.input;
        let version_id = check_version(input.version_id.as_deref())?;
        self.store.head_bucket(&input.bucket).await.s3()?;
        let precondition = Precondition {
            if_size: input
                .if_match_size
                .map(|size| u64::try_from(size).unwrap_or(u64::MAX)),
            if_modified_at: input
                .if_match_last_modified_time
                .as_ref()
                .map(to_system_time),
            ..precondition(input.if_match.as_ref(), None)
        };
        // The access check made sure the caller may bypass governance when it asks.
        let bypass = input.bypass_governance_retention == Some(true);
        let deleted = self
            .store
            .delete_with(&input.bucket, &input.key, version_id, precondition, bypass)
            .await
            .s3()?;
        Ok(S3Response::new(dto::DeleteObjectOutput {
            version_id: deleted.version_id,
            // AWS says so only when it's true.
            delete_marker: deleted.delete_marker.then_some(true),
            ..Default::default()
        }))
    }

    async fn delete_objects(
        &self,
        req: S3Request<dto::DeleteObjectsInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectsOutput>> {
        let caller = access::caller(&req).cloned();
        let input = req.input;
        if input.delete.objects.len() > MAX_DELETE {
            return Err(s3_error!(
                MalformedXML,
                "at most 1000 keys can be deleted at once"
            ));
        }
        self.store.head_bucket(&input.bucket).await.s3()?;
        let quiet = input.delete.quiet.unwrap_or(false);
        let (mut deleted, mut errors) = (Vec::new(), Vec::new());
        for object in input.delete.objects {
            let precondition = Precondition {
                if_match: object.e_tag.as_ref().map(|etag| match etag.value() {
                    "*" => Match::Any,
                    value => Match::ETag(value.to_owned()),
                }),
                if_size: object
                    .size
                    .map(|size| u64::try_from(size).unwrap_or(u64::MAX)),
                if_modified_at: object.last_modified_time.as_ref().map(to_system_time),
                ..Precondition::default()
            };
            // Each key is decided on its own, as AWS does: a key the caller may not
            // delete is reported in the answer and the others go ahead.
            let action = if object.version_id.is_some() {
                "s3:DeleteObjectVersion"
            } else {
                "s3:DeleteObject"
            };
            let arn = teifs_policy::object_arn(&input.bucket, &object.key);
            let allowed = caller.as_ref().is_none_or(|c| c.allows(action, &arn));
            let bypass = input.bypass_governance_retention == Some(true)
                && caller
                    .as_ref()
                    .is_none_or(|c| c.allows(BYPASS_GOVERNANCE, &arn));
            let result = match check_version(object.version_id.as_deref()) {
                Ok(_) if !allowed => Err(s3_error!(AccessDenied, "Access Denied")),
                Ok(version_id) => self
                    .store
                    .delete_with(&input.bucket, &object.key, version_id, precondition, bypass)
                    .await
                    .s3(),
                Err(err) => Err(err),
            };
            match result {
                Ok(_) if quiet => {}
                Ok(done) => deleted.push(deleted_object(object.key, object.version_id, done)),
                Err(err) => errors.push(dto::Error {
                    code: Some(err.code().as_str().to_owned()),
                    message: err.message().map(str::to_owned),
                    key: Some(object.key),
                    version_id: object.version_id,
                }),
            }
        }
        Ok(S3Response::new(dto::DeleteObjectsOutput {
            deleted: Some(deleted),
            errors: Some(errors),
            ..Default::default()
        }))
    }

    async fn copy_object(
        &self,
        req: S3Request<dto::CopyObjectInput>,
    ) -> S3Result<S3Response<dto::CopyObjectOutput>> {
        let mut input = req.input;
        let CopySource::Bucket {
            bucket: src_bucket,
            key: src_key,
            version_id: src_version,
        } = &input.copy_source
        else {
            return Err(s3_error!(
                NotImplemented,
                "copying from an access point isn't supported"
            ));
        };
        let src_version = check_version(src_version.as_deref())?.map(str::to_owned);
        let src_version = src_version.as_deref();
        let (src_bucket, src_key) = (src_bucket.to_string(), src_key.to_string());
        let source_key = sse::customer_key(
            input.copy_source_sse_customer_algorithm.as_deref(),
            input.copy_source_sse_customer_key.as_deref(),
            input.copy_source_sse_customer_key_md5.as_deref(),
        )?;
        let (source, _) = self
            .store
            .read_with(&src_bucket, &src_key, src_version, source_key.as_ref())
            .await
            .s3()?;
        check_read(
            &source,
            input.copy_source_if_match.as_ref(),
            input.copy_source_if_none_match.as_ref(),
            input.copy_source_if_modified_since.as_ref(),
            input.copy_source_if_unmodified_since.as_ref(),
        )
        .map_err(|_| s3_error!(PreconditionFailed))?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let customer_md5 = customer.as_ref().map(CustomerKey::md5_base64);
        let encryption = self
            .write_encryption(
                &input.bucket,
                sse::WriteRequest {
                    sse: input.server_side_encryption.as_ref(),
                    kms_key: input.ssekms_key_id.as_deref(),
                    kms_context: input.ssekms_encryption_context.as_deref(),
                    bucket_key: input.bucket_key_enabled,
                    customer,
                },
            )
            .await?;
        let replace = input
            .metadata_directive
            .as_ref()
            .is_some_and(|d| d.as_str() == MetadataDirective::REPLACE);
        check_copy_onto_itself(&input, (&src_bucket, &src_key, src_version), replace)?;
        let acl = self
            .object_write_acl(&input.bucket, acl_headers!(input))
            .await?;
        let lock = write_lock!(input)?;
        let attrs = copy_attrs(&mut input, &source.attrs, replace, acl, lock)?;
        self.check_write(
            &input.bucket,
            Some(&input.key),
            i64::try_from(source.size).ok(),
        )
        .await?;
        let pre = precondition(input.if_match.as_ref(), input.if_none_match.as_ref());
        let info = self
            .store
            .copy_with(
                (&src_bucket, &src_key, src_version),
                (&input.bucket, &input.key),
                attrs,
                pre,
                source_key.as_ref(),
                &encryption,
            )
            .await
            .s3()?;
        let mut out = dto::CopyObjectOutput {
            copy_object_result: Some(dto::CopyObjectResult {
                e_tag: Some(etag(&info.etag)),
                last_modified: Some(info.modified.into()),
                ..Default::default()
            }),
            version_id: written_version(&info),
            copy_source_version_id: source.version_id.clone(),
            expiration: self.expiration(&input.bucket, &info).await,
            ..Default::default()
        };
        set_sse!(out, with_customer_md5(info.sse, customer_md5).as_ref());
        Ok(S3Response::new(out))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<dto::ListObjectsV2Input>,
    ) -> S3Result<S3Response<dto::ListObjectsV2Output>> {
        let show_owner = access::may(&req, READ_ACL);
        let mut input = req.input;
        // An empty delimiter is no delimiter, and S3 leaves it out of the answer.
        input.delimiter = input.delimiter.filter(|d| !d.is_empty());
        // An empty token is no token (S3 echoes it back).
        let after = match input
            .continuation_token
            .as_deref()
            .filter(|t| !t.is_empty())
        {
            Some(token) => Some(
                encode::parse_token(token)
                    .ok_or_else(|| s3_error!(InvalidArgument, "invalid continuation token"))?,
            ),
            None => input.start_after.clone().map(After::Key),
        };
        let max_keys = input.max_keys.unwrap_or(MAX_KEYS).clamp(0, MAX_KEYS);
        let prefix = input.prefix.clone().unwrap_or_default();
        let listing = self
            .store
            .list(
                &input.bucket,
                ListQuery {
                    prefix,
                    delimiter: input.delimiter.clone(),
                    after,
                    max_keys: usize::try_from(max_keys).unwrap_or(0),
                },
            )
            .await
            .s3()?;
        let url = input
            .encoding_type
            .as_ref()
            .is_some_and(|e| e.as_str() == dto::EncodingType::URL);
        let enc = |s: String| if url { encode::url(&s) } else { s };
        let fetch_owner = show_owner && input.fetch_owner.unwrap_or(false);
        let key_count = listing.objects.len() + listing.prefixes.len();
        let contents: Vec<dto::Object> = listing
            .objects
            .into_iter()
            .map(|o| dto::Object {
                key: Some(enc(o.key)),
                size: Some(i64::try_from(o.size).unwrap_or(i64::MAX)),
                e_tag: Some(etag(&o.etag)),
                last_modified: Some(o.modified.into()),
                storage_class: Some(ObjectStorageClass::from_static(
                    ObjectStorageClass::STANDARD,
                )),
                owner: fetch_owner.then(acl::owner),
                ..Default::default()
            })
            .collect();
        let prefixes: Vec<dto::CommonPrefix> = listing
            .prefixes
            .into_iter()
            .map(|p| dto::CommonPrefix {
                prefix: Some(enc(p)),
            })
            .collect();
        Ok(S3Response::new(dto::ListObjectsV2Output {
            name: Some(input.bucket),
            prefix: Some(enc(input.prefix.unwrap_or_default())),
            delimiter: input.delimiter.map(enc),
            start_after: input.start_after.map(enc),
            encoding_type: input.encoding_type,
            max_keys: Some(max_keys),
            key_count: Some(i32::try_from(key_count).unwrap_or(i32::MAX)),
            is_truncated: Some(listing.truncated),
            continuation_token: input.continuation_token,
            next_continuation_token: listing.next.as_ref().map(encode::token),
            contents: (!contents.is_empty()).then_some(contents),
            common_prefixes: (!prefixes.is_empty()).then_some(prefixes),
            ..Default::default()
        }))
    }

    async fn list_objects(
        &self,
        req: S3Request<dto::ListObjectsInput>,
    ) -> S3Result<S3Response<dto::ListObjectsOutput>> {
        let show_owner = access::may(&req, READ_ACL);
        let mut input = req.input;
        // An empty delimiter is no delimiter, and S3 leaves it out of the answer.
        input.delimiter = input.delimiter.filter(|d| !d.is_empty());
        let prefix = input.prefix.clone().unwrap_or_default();
        let after = after_marker(input.marker.clone(), input.delimiter.as_deref(), &prefix);
        let max_keys = input.max_keys.unwrap_or(MAX_KEYS).clamp(0, MAX_KEYS);
        let listing = self
            .store
            .list(
                &input.bucket,
                ListQuery {
                    prefix,
                    delimiter: input.delimiter.clone(),
                    after,
                    max_keys: usize::try_from(max_keys).unwrap_or(0),
                },
            )
            .await
            .s3()?;
        let url = input
            .encoding_type
            .as_ref()
            .is_some_and(|e| e.as_str() == dto::EncodingType::URL);
        let enc = |s: String| if url { encode::url(&s) } else { s };
        // S3 gives NextMarker only when a delimiter was used; otherwise clients take the
        // last key.
        let next_marker = listing
            .next
            .as_ref()
            .filter(|_| input.delimiter.is_some())
            .map(|after| match after {
                After::Key(k) | After::Prefix(k) => enc(k.clone()),
            });
        let contents: Vec<dto::Object> = listing
            .objects
            .into_iter()
            .map(|o| dto::Object {
                key: Some(enc(o.key)),
                size: Some(i64::try_from(o.size).unwrap_or(i64::MAX)),
                e_tag: Some(etag(&o.etag)),
                last_modified: Some(o.modified.into()),
                storage_class: Some(ObjectStorageClass::from_static(
                    ObjectStorageClass::STANDARD,
                )),
                owner: show_owner.then(acl::owner),
                ..Default::default()
            })
            .collect();
        let prefixes: Vec<dto::CommonPrefix> = listing
            .prefixes
            .into_iter()
            .map(|p| dto::CommonPrefix {
                prefix: Some(enc(p)),
            })
            .collect();
        Ok(S3Response::new(dto::ListObjectsOutput {
            name: Some(input.bucket),
            // V1 answers with the prefix as sent; only V2 and versions encode it.
            prefix: Some(input.prefix.unwrap_or_default()),
            delimiter: input.delimiter.map(enc),
            marker: Some(input.marker.map(enc).unwrap_or_default()),
            encoding_type: input.encoding_type,
            max_keys: Some(max_keys),
            is_truncated: Some(listing.truncated),
            next_marker,
            contents: (!contents.is_empty()).then_some(contents),
            common_prefixes: (!prefixes.is_empty()).then_some(prefixes),
            ..Default::default()
        }))
    }

    async fn list_object_versions(
        &self,
        req: S3Request<dto::ListObjectVersionsInput>,
    ) -> S3Result<S3Response<dto::ListObjectVersionsOutput>> {
        let mut input = req.input;
        // An empty delimiter is no delimiter, and S3 leaves it out of the answer; empty
        // markers are no markers.
        input.delimiter = input.delimiter.filter(|d| !d.is_empty());
        let key_marker = input.key_marker.clone().filter(|m| !m.is_empty());
        let version_marker = input.version_id_marker.clone().filter(|m| !m.is_empty());
        if version_marker.is_some() && key_marker.is_none() {
            return Err(s3_error!(
                InvalidArgument,
                "A version-id marker cannot be specified without a key marker."
            ));
        }
        check_version(version_marker.as_deref())?;
        let max_keys = input.max_keys.unwrap_or(MAX_KEYS).clamp(0, MAX_KEYS);
        let listing = self
            .store
            .list_versions(
                &input.bucket,
                VersionsQuery {
                    prefix: input.prefix.clone().unwrap_or_default(),
                    delimiter: input.delimiter.clone(),
                    key_marker,
                    version_marker,
                    max_keys: usize::try_from(max_keys).unwrap_or(0),
                },
            )
            .await
            .s3()?;
        let url = input
            .encoding_type
            .as_ref()
            .is_some_and(|e| e.as_str() == dto::EncodingType::URL);
        let enc = |s: String| if url { encode::url(&s) } else { s };
        let (next_key_marker, next_version_id_marker) = match listing.next {
            Some((key, version)) => (Some(enc(key)), version),
            None => (None, None),
        };
        let (versions, markers) = version_entries(listing.versions, &enc);
        let prefixes: Vec<dto::CommonPrefix> = listing
            .prefixes
            .into_iter()
            .map(|p| dto::CommonPrefix {
                prefix: Some(enc(p)),
            })
            .collect();
        Ok(S3Response::new(dto::ListObjectVersionsOutput {
            name: Some(input.bucket),
            prefix: Some(enc(input.prefix.unwrap_or_default())),
            delimiter: input.delimiter.map(enc),
            key_marker: Some(input.key_marker.map(enc).unwrap_or_default()),
            version_id_marker: Some(input.version_id_marker.unwrap_or_default()),
            encoding_type: input.encoding_type,
            max_keys: Some(max_keys),
            is_truncated: Some(listing.truncated),
            next_key_marker,
            next_version_id_marker,
            versions: (!versions.is_empty()).then_some(versions),
            delete_markers: (!markers.is_empty()).then_some(markers),
            common_prefixes: (!prefixes.is_empty()).then_some(prefixes),
            ..Default::default()
        }))
    }

    async fn create_multipart_upload(
        &self,
        req: S3Request<dto::CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::CreateMultipartUploadOutput>> {
        let owner = uploader(&req).id;
        let max_size = req
            .extensions
            .get::<Caps>()
            .and_then(|caps| caps.total_object_size);
        let mut input = req.input;
        let mut attrs = new_attrs!(input).into_attrs(BTreeMap::new());
        attrs.tags = header_tags(input.tagging.as_deref())?;
        attrs.acl = self
            .object_write_acl(&input.bucket, acl_headers!(input))
            .await?;
        write_lock!(input)?.apply(&mut attrs);
        let checksum = checksums::for_upload(
            input
                .checksum_algorithm
                .as_ref()
                .map(dto::ChecksumAlgorithm::as_str),
            input.checksum_type.as_ref().map(dto::ChecksumType::as_str),
        )?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let customer_md5 = customer.as_ref().map(CustomerKey::md5_base64);
        let encryption = self
            .write_encryption(
                &input.bucket,
                sse::WriteRequest {
                    sse: input.server_side_encryption.as_ref(),
                    kms_key: input.ssekms_key_id.as_deref(),
                    kms_context: input.ssekms_encryption_context.as_deref(),
                    bucket_key: input.bucket_key_enabled,
                    customer,
                },
            )
            .await?;
        let upload = self
            .store
            .create_upload(
                &input.bucket,
                &input.key,
                attrs,
                owner,
                &encryption,
                Some(&checksum),
                max_size,
            )
            .await
            .s3()?;
        let (abort_date, abort_rule_id) = self.abort_date(&upload).await;
        let mut out = dto::CreateMultipartUploadOutput {
            bucket: Some(input.bucket),
            key: Some(input.key),
            upload_id: Some(upload.id.clone()),
            abort_date,
            abort_rule_id,
            ..Default::default()
        };
        if checksum.requested {
            out.checksum_algorithm = Some(dto::ChecksumAlgorithm::from(checksum.algorithm));
            out.checksum_type = Some(dto::ChecksumType::from_static(checksum.kind.as_str()));
        }
        let info = self.store.upload_encryption(&upload);
        set_sse!(out, with_customer_md5(info, customer_md5).as_ref());
        Ok(S3Response::new(out))
    }

    async fn upload_part(
        &self,
        req: S3Request<dto::UploadPartInput>,
    ) -> S3Result<S3Response<dto::UploadPartOutput>> {
        let upload = self.store.upload(&req.input.upload_id).await.s3()?;
        check_owner(&upload, &req.input.bucket, &req.input.key, &uploader(&req))?;
        let mut input = req.input;
        let number = part_number(input.part_number)?;
        let body = input.body.take().ok_or_else(|| s3_error!(IncompleteBody))?;
        let mut sent = checksums::from_dto(&checksum_of!(input));
        let asked = input
            .checksum_algorithm
            .as_ref()
            .map(|a| a.as_str().to_owned());
        // The part's checksum in the upload's algorithm is worked out whatever was sent.
        let upload_checksum = Store::upload_checksum(&upload);
        if let Some(checksum) = &upload_checksum {
            let named: Sums = asked.iter().map(|a| (a.clone(), String::new())).collect();
            checksums::check_part(checksum, &named)?;
            checksums::check_part(checksum, &sent)?;
        }
        let mut hasher = checksums::hasher(
            &sent,
            asked
                .as_deref()
                .into_iter()
                .chain(upload_checksum.as_ref().map(|c| c.algorithm.as_str())),
        )?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        // A capped upload's part must declare a length that fits beside the other parts.
        let room = self.store.part_room(&upload, number).await.s3()?;
        if let Some(room) = room {
            caps::admit(input.content_length, room)?;
        }
        self.check_write(&upload.bucket, None, input.content_length)
            .await?;
        let staged = self
            .store
            .stage_part(&upload.id, number, customer.as_ref())
            .await
            .s3()?;
        let staged = self.stage(staged, body, &mut hasher, room).await?;
        checksums::add_trailers(&mut sent, req.trailing_headers)?;
        if let Some(checksum) = &upload_checksum {
            checksums::check_part(checksum, &sent)?;
        }
        let computed = checksums::from_dto(&hasher.finalize());
        checksums::verify(&sent, &computed)?;
        let part = self
            .store
            .put_part(&upload.id, number, staged, computed.clone())
            .await
            .s3()?;
        let mut out = dto::UploadPartOutput {
            e_tag: Some(etag(&part.etag)),
            ..Default::default()
        };
        set_checksums!(out, &computed);
        let info = self.store.upload_encryption(&upload);
        set_sse!(
            out,
            with_customer_md5(info, customer.as_ref().map(CustomerKey::md5_base64)).as_ref()
        );
        Ok(S3Response::new(out))
    }

    async fn upload_part_copy(
        &self,
        req: S3Request<dto::UploadPartCopyInput>,
    ) -> S3Result<S3Response<dto::UploadPartCopyOutput>> {
        let upload = self.store.upload(&req.input.upload_id).await.s3()?;
        check_owner(&upload, &req.input.bucket, &req.input.key, &uploader(&req))?;
        let input = req.input;
        let number = part_number(input.part_number)?;
        let CopySource::Bucket {
            bucket: src_bucket,
            key: src_key,
            version_id: src_version,
        } = &input.copy_source
        else {
            return Err(s3_error!(
                NotImplemented,
                "copying from an access point isn't supported"
            ));
        };
        let src_version = check_version(src_version.as_deref())?;
        let source_key = sse::customer_key(
            input.copy_source_sse_customer_algorithm.as_deref(),
            input.copy_source_sse_customer_key.as_deref(),
            input.copy_source_sse_customer_key_md5.as_deref(),
        )?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let (source, file) = self
            .store
            .read_with(src_bucket, src_key, src_version, source_key.as_ref())
            .await
            .s3()?;
        check_read(
            &source,
            input.copy_source_if_match.as_ref(),
            input.copy_source_if_none_match.as_ref(),
            input.copy_source_if_modified_since.as_ref(),
            input.copy_source_if_unmodified_since.as_ref(),
        )
        .map_err(|_| s3_error!(PreconditionFailed))?;
        let (start, length) = match &input.copy_source_range {
            Some(range) => copy_range(range, source.size)?,
            None => (0, source.size),
        };
        if let Some(room) = self.store.part_room(&upload, number).await.s3()?
            && length > room
        {
            return Err(caps::too_large());
        }
        self.check_write(&upload.bucket, None, i64::try_from(length).ok())
            .await?;
        let mut staged = self
            .store
            .stage_part(&upload.id, number, customer.as_ref())
            .await
            .s3()?;
        let upload_checksum = Store::upload_checksum(&upload);
        let none = Sums::new();
        let mut hasher = checksums::hasher(
            &none,
            upload_checksum.as_ref().map(|c| c.algorithm.as_str()),
        )?;
        if let Some(body) = file {
            let reader = body.range(start, length).await.s3()?;
            let mut reader = ReaderStream::with_capacity(reader, READ_CHUNK);
            while let Some(chunk) = reader.next().await {
                let chunk = chunk.map_err(|e| s3_error!(e, InternalError))?;
                hasher.update(&chunk);
                staged.write(&chunk).await.s3()?;
            }
        }
        let computed = checksums::from_dto(&hasher.finalize());
        let part = self
            .store
            .put_part(&upload.id, number, staged, computed.clone())
            .await
            .s3()?;
        let mut result = dto::CopyPartResult {
            e_tag: Some(etag(&part.etag)),
            last_modified: Some(millis(part.modified_ms)),
            ..Default::default()
        };
        set_checksums!(result, &computed);
        Ok(S3Response::new(dto::UploadPartCopyOutput {
            copy_part_result: Some(result),
            copy_source_version_id: source.version_id,
            ..Default::default()
        }))
    }

    async fn list_parts(
        &self,
        req: S3Request<dto::ListPartsInput>,
    ) -> S3Result<S3Response<dto::ListPartsOutput>> {
        let upload = self.store.upload(&req.input.upload_id).await.s3()?;
        check_owner(&upload, &req.input.bucket, &req.input.key, &uploader(&req))?;
        let input = req.input;
        let max_parts = input.max_parts.unwrap_or(MAX_KEYS).clamp(0, MAX_KEYS);
        let after = u32::try_from(input.part_number_marker.unwrap_or(0)).unwrap_or(0);
        let limit = usize::try_from(max_parts).unwrap_or(0);
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let mut parts = self
            .store
            .parts(&upload.id, after, limit + 1, customer.as_ref())
            .await
            .s3()?;
        let (checksum_algorithm, checksum_type) = upload_checksum_dto(&upload);
        let (abort_date, abort_rule_id) = self.abort_date(&upload).await;
        let truncated = parts.len() > limit;
        parts.truncate(limit);
        let next = parts
            .last()
            .map(|p| i32::try_from(p.number).unwrap_or(i32::MAX));
        let parts = parts
            .into_iter()
            .map(|p| {
                let mut part = dto::Part {
                    part_number: Some(i32::try_from(p.number).unwrap_or(i32::MAX)),
                    size: Some(i64::try_from(p.size).unwrap_or(i64::MAX)),
                    e_tag: Some(etag(&p.etag)),
                    last_modified: Some(millis(p.modified_ms)),
                    ..Default::default()
                };
                set_checksums!(part, &p.checksums);
                part
            })
            .collect();
        Ok(S3Response::new(dto::ListPartsOutput {
            bucket: Some(input.bucket),
            key: Some(input.key),
            upload_id: Some(upload.id),
            parts: Some(parts),
            max_parts: Some(max_parts),
            part_number_marker: input.part_number_marker,
            next_part_number_marker: truncated.then_some(next).flatten(),
            is_truncated: Some(truncated),
            owner: Some(acl::owner()),
            initiator: Some(initiator()),
            storage_class: Some(dto::StorageClass::from_static(dto::StorageClass::STANDARD)),
            checksum_algorithm,
            checksum_type,
            abort_date,
            abort_rule_id,
            ..Default::default()
        }))
    }

    async fn list_multipart_uploads(
        &self,
        req: S3Request<dto::ListMultipartUploadsInput>,
    ) -> S3Result<S3Response<dto::ListMultipartUploadsOutput>> {
        let input = req.input;
        let max = input.max_uploads.unwrap_or(MAX_KEYS).clamp(0, MAX_KEYS);
        let limit = usize::try_from(max).unwrap_or(0);
        let after = input
            .key_marker
            .clone()
            .map(|k| (k, input.upload_id_marker.clone().unwrap_or_default()));
        let prefix = input.prefix.clone().unwrap_or_default();
        let mut uploads = self
            .store
            .uploads(&input.bucket, &prefix, after, limit + 1)
            .await
            .s3()?;
        let truncated = uploads.len() > limit;
        uploads.truncate(limit);
        let next = uploads.last().map(|u| (u.key.clone(), u.id.clone()));
        let uploads = uploads
            .into_iter()
            .map(|u| {
                let (checksum_algorithm, checksum_type) = upload_checksum_dto(&u);
                dto::MultipartUpload {
                    key: Some(u.key),
                    upload_id: Some(u.id),
                    checksum_algorithm,
                    checksum_type,
                    initiated: Some(millis(u.created_ms)),
                    owner: Some(acl::owner()),
                    initiator: Some(initiator()),
                    storage_class: Some(dto::StorageClass::from_static(
                        dto::StorageClass::STANDARD,
                    )),
                }
            })
            .collect();
        Ok(S3Response::new(dto::ListMultipartUploadsOutput {
            bucket: Some(input.bucket),
            prefix: input.prefix,
            key_marker: input.key_marker,
            upload_id_marker: input.upload_id_marker,
            max_uploads: Some(max),
            is_truncated: Some(truncated),
            next_key_marker: next.as_ref().filter(|_| truncated).map(|n| n.0.clone()),
            next_upload_id_marker: next.filter(|_| truncated).map(|n| n.1),
            uploads: Some(uploads),
            ..Default::default()
        }))
    }

    async fn complete_multipart_upload(
        &self,
        req: S3Request<dto::CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::CompleteMultipartUploadOutput>> {
        let who = uploader(&req);
        let input = req.input;
        let upload = match self.store.upload(&input.upload_id).await {
            // A retried Complete of a finished upload gets the same answer.
            Err(teifs_store::StoreError::NoSuchUpload) => {
                let done = self
                    .store
                    .completed(&input.upload_id, &input.bucket, &input.key)
                    .await
                    .s3()?
                    .ok_or_else(|| s3_error!(NoSuchUpload))?;
                let sums = done.attrs.checksums.clone();
                let kind = done.attrs.checksum_type;
                return Ok(S3Response::new(complete_output(
                    &input.bucket,
                    &input.key,
                    &done,
                    &sums,
                    kind,
                )));
            }
            other => other.s3()?,
        };
        check_owner(&upload, &input.bucket, &input.key, &who)?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let listed = input
            .multipart_upload
            .as_ref()
            .and_then(|m| m.parts.as_ref())
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|p| {
                let number = part_number(p.part_number.ok_or_else(|| s3_error!(InvalidPart))?)?;
                let etag = p
                    .e_tag
                    .as_ref()
                    .ok_or_else(|| s3_error!(InvalidPart))?
                    .value()
                    .to_owned();
                Ok((number, etag, checksums::from_dto(&checksum_of!(p))))
            })
            .collect::<S3Result<Vec<_>>>()?;
        let (sums, kind) = self
            .object_checksum(&upload, &input, &listed, customer.as_ref())
            .await?;
        let pre = precondition(input.if_match.as_ref(), input.if_none_match.as_ref());
        let info = self
            .store
            .complete(
                &upload.id,
                listed.into_iter().map(|(n, e, _)| (n, e)).collect(),
                pre,
                teifs_store::CompleteWith {
                    checksums: sums.clone(),
                    checksum_type: kind,
                    customer,
                },
            )
            .await
            .s3()?;
        let mut out = complete_output(&input.bucket, &input.key, &info, &sums, kind);
        out.expiration = self.expiration(&input.bucket, &info).await;
        // S3 reports SSE-S3 and SSE-KMS here, not SSE-C.
        let headers = sse::headers(info.sse.as_ref());
        out.server_side_encryption = headers.sse;
        out.ssekms_key_id = headers.kms_key;
        out.bucket_key_enabled = headers.bucket_key;
        Ok(S3Response::new(out))
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<dto::AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::AbortMultipartUploadOutput>> {
        let upload = self.store.upload(&req.input.upload_id).await.s3()?;
        check_owner(&upload, &req.input.bucket, &req.input.key, &uploader(&req))?;
        self.store.abort(&upload.id).await.s3()?;
        Ok(S3Response::new(dto::AbortMultipartUploadOutput::default()))
    }
}

/// S3's rules for the checksums a Complete sends: the upload's own checksum type, and
/// for a composite checksum the client asked for (built from every part's), each part's.
fn check_complete(
    checksum: &teifs_types::UploadChecksum,
    kind: Option<&dto::ChecksumType>,
    listed: &[(u32, String, Sums)],
) -> S3Result<()> {
    if !checksum.requested {
        return Ok(());
    }
    if kind.is_some_and(|kind| kind.as_str() != checksum.kind.as_str()) {
        return Err(s3_error!(
            InvalidRequest,
            "The upload was created with the {} checksum type",
            checksum.kind.as_str()
        ));
    }
    if checksum.kind != teifs_store::ChecksumType::Composite {
        return Ok(());
    }
    match listed
        .iter()
        .find(|(_, _, sent)| !sent.contains_key(&checksum.algorithm))
    {
        None => Ok(()),
        Some((number, ..)) => Err(s3_error!(
            InvalidRequest,
            "The upload was created using a {} checksum. The complete request must include the checksum for each part. It was missing for part {number} in the request.",
            checksum.algorithm.to_ascii_lowercase()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_checksums_need_every_parts() {
        use teifs_store::ChecksumType::{Composite, FullObject};
        let upload = |kind, requested| teifs_types::UploadChecksum {
            algorithm: "SHA256".into(),
            kind,
            requested,
        };
        let sent = |name: &str| -> Sums { [(name.to_owned(), "x".to_owned())].into() };
        let listed = [
            (1, "a".to_owned(), sent("SHA256")),
            (2, "b".to_owned(), sent("CRC32")),
        ];
        let err = check_complete(&upload(Composite, true), None, &listed).unwrap_err();
        assert_eq!(err.code(), &s3s::S3ErrorCode::InvalidRequest);
        let message = err.message().unwrap();
        assert!(
            message.contains("using a sha256 checksum") && message.contains("part 2"),
            "{message}"
        );
        assert!(check_complete(&upload(Composite, true), None, &listed[..1]).is_ok());
        assert!(check_complete(&upload(FullObject, true), None, &listed).is_ok());
        assert!(check_complete(&upload(Composite, false), None, &listed).is_ok());
        let full = dto::ChecksumType::from_static(dto::ChecksumType::FULL_OBJECT);
        let err = check_complete(&upload(Composite, true), Some(&full), &listed[..1]);
        assert!(err.unwrap_err().message().unwrap().contains("COMPOSITE"));
    }

    #[test]
    fn copy_ranges_are_inclusive() {
        assert_eq!(copy_range("bytes=0-9", 100).unwrap(), (0, 10));
        assert_eq!(copy_range("bytes=90-99", 100).unwrap(), (90, 10));
        assert!(copy_range("bytes=90-100", 100).is_err());
        assert!(copy_range("bytes=5-1", 100).is_err());
        assert!(copy_range("0-9", 100).is_err());
    }
}
