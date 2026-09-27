//! The S3 operations.

use std::{collections::BTreeMap, time::SystemTime};

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
    After, BucketEncryption, CustomerKey, DefaultEncryption, Encryption, Layout, ListQuery, Match,
    ObjectAttrs, ObjectInfo, Precondition, SseInfo, SseMode, Staged, Store, Upload,
};
use tokio_util::io::ReaderStream;

use crate::{
    checksums::{self, Sums, checksum_of, set_checksums},
    cors, encode,
    errors::{StoreResultExt, from_body},
    sse::{self, set_sse},
    tagging,
};

/// How many keys a listing returns at most, and by default.
const MAX_KEYS: i32 = 1000;
/// How many keys one `DeleteObjects` may name.
const MAX_DELETE: usize = 1000;
/// Read buffer for object bodies.
const READ_CHUNK: usize = 256 * 1024;
/// Who owns every bucket (a drive has one owner).
const OWNER: &str = "teifs";
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
    /// Whether requests over plain HTTP count as secure for SSE-C (a server that only
    /// listens on this machine, or behind a proxy that terminates TLS).
    plain_http_is_secure: bool,
}

impl Drive {
    /// Serves `store`; buckets created without choosing get `default_layout`.
    #[must_use]
    pub fn new(store: Store, default_layout: Layout, plain_http_is_secure: bool) -> Self {
        Self {
            store,
            default_layout,
            plain_http_is_secure,
        }
    }

    /// Reads an object. As in S3, a part number the object doesn't have is reported
    /// before a missing SSE-C key.
    async fn read(
        &self,
        bucket: &str,
        key: &str,
        customer: Option<&CustomerKey>,
        part_number: Option<i32>,
    ) -> S3Result<(ObjectInfo, Option<teifs_store::ObjectBody>)> {
        match self.store.read_with(bucket, key, customer).await {
            Err(err @ teifs_store::StoreError::CustomerKeyRequired) if part_number.is_some() => {
                if let Ok(info) = self.store.head(bucket, key).await {
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
        if let Some(kind) = &input.checksum_type
            && checksum.requested
            && kind.as_str() != checksum.kind.as_str()
        {
            return Err(s3_error!(
                InvalidRequest,
                "The upload was created with the {} checksum type",
                checksum.kind.as_str()
            ));
        }
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

    /// Decides a write's encryption from its SSE headers and the bucket's default.
    async fn write_encryption(
        &self,
        bucket: &str,
        request: sse::WriteRequest<'_>,
    ) -> S3Result<Encryption> {
        let default = self.store.bucket_encryption(bucket).await.s3()?;
        sse::for_write(request, default.as_ref(), self.plain_http_is_secure)
    }

    /// Streams a request body into `staged`, hashing it for the checksums asked for.
    async fn stage(
        &self,
        mut staged: Staged,
        body: StreamingBlob,
        sums: &mut s3s::checksum::ChecksumHasher,
    ) -> S3Result<Staged> {
        let mut body = body;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(from_body)?;
            sums.update(&chunk);
            staged.write(&chunk).await.s3()?;
        }
        Ok(staged)
    }
}

fn owner() -> dto::Owner {
    dto::Owner {
        display_name: Some(OWNER.to_owned()),
        id: Some(OWNER.to_owned()),
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
fn check_version(version_id: Option<&str>) -> S3Result<()> {
    match version_id {
        None | Some(NULL_VERSION) => Ok(()),
        Some(_) => Err(s3_error!(InvalidArgument, "Invalid version id specified")),
    }
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
fn rename_source(source: &str, bucket: &str) -> S3Result<String> {
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
fn urlencoding_decode(value: &str) -> S3Result<String> {
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

fn check_owner(upload: &Upload, bucket: &str, key: &str, access_key: Option<&str>) -> S3Result<()> {
    if upload.bucket != bucket || upload.key != key {
        return Err(s3_error!(NoSuchUpload));
    }
    if upload.owner.as_deref() != access_key {
        return Err(s3_error!(
            AccessDenied,
            "the upload was started by someone else"
        ));
    }
    Ok(())
}

fn access_key<T>(req: &S3Request<T>) -> Option<&str> {
    req.credentials.as_ref().map(|c| c.access_key.as_str())
}

fn part_number(number: i32) -> S3Result<u32> {
    u32::try_from(number)
        .ok()
        .filter(|n| (1..=teifs_store::MAX_PART_NUMBER).contains(n))
        .ok_or_else(|| s3_error!(InvalidArgument, "part numbers go from 1 to 10000"))
}

fn http_date(timestamp: &Timestamp) -> String {
    let mut out = Vec::new();
    let _ = timestamp.format(dto::TimestampFormat::HttpDate, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

fn millis(ms: i64) -> Timestamp {
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
/// has its own directive); `None` keeps the source's.
fn copy_attrs(
    input: &mut dto::CopyObjectInput,
    source: &ObjectAttrs,
    replace_metadata: bool,
) -> S3Result<Option<ObjectAttrs>> {
    let replace_tags = input
        .tagging_directive
        .as_ref()
        .is_some_and(|d| d.as_str() == dto::TaggingDirective::REPLACE);
    if !replace_metadata && !replace_tags {
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
    Ok(Some(attrs))
}

/// Tags from an `x-amz-tagging` header, checked.
fn header_tags(value: Option<&str>) -> S3Result<tagging::Tags> {
    match value {
        Some(value) => tagging::check(tagging::from_header(value)?, tagging::MAX_OBJECT_TAGS),
        None => Ok(tagging::Tags::new()),
    }
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
        _req: S3Request<dto::ListBucketsInput>,
    ) -> S3Result<S3Response<dto::ListBucketsOutput>> {
        let buckets = self
            .store
            .list_buckets()
            .await
            .s3()?
            .into_iter()
            .map(|b| dto::Bucket {
                name: Some(b.name),
                creation_date: Some(b.created.into()),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(dto::ListBucketsOutput {
            buckets: Some(buckets),
            owner: Some(owner()),
            ..Default::default()
        }))
    }

    async fn create_bucket(
        &self,
        req: S3Request<dto::CreateBucketInput>,
    ) -> S3Result<S3Response<dto::CreateBucketOutput>> {
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
        self.store
            .create_bucket(&req.input.bucket, layout)
            .await
            .s3()?;
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
        // Versioning was never enabled: an empty answer, as S3 gives.
        self.store.head_bucket(&req.input.bucket).await.s3()?;
        Ok(S3Response::new(dto::GetBucketVersioningOutput::default()))
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
        let tags = header_tags(input.tagging.as_deref())?;
        let mut sent = checksums::from_dto(&checksum_of!(input));
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
                    customer,
                },
            )
            .await?;
        let staged = self
            .store
            .stage_for(&input.bucket, &encryption)
            .await
            .s3()?;
        let staged = self.stage(staged, body, &mut hasher).await?;
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
        let pre = precondition(input.if_match.as_ref(), input.if_none_match.as_ref());
        let info = self
            .store
            .commit(&input.bucket, &input.key, staged, attrs, pre)
            .await
            .s3()?;
        let mut out = dto::PutObjectOutput {
            e_tag: Some(etag(&info.etag)),
            checksum_type: checksum_type(&computed, None),
            ..Default::default()
        };
        set_checksums!(out, &computed);
        set_sse!(out, with_customer_md5(info.sse, customer_md5).as_ref());
        Ok(S3Response::new(out))
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
        let input = req.input;
        check_version(input.version_id.as_deref())?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let (info, file) = self
            .read(
                &input.bucket,
                &input.key,
                customer.as_ref(),
                input.part_number,
            )
            .await?;
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
            tag_count: tag_count(&info.attrs),
            ..Default::default()
        };
        if let Some(sums) = slice.checksums
            && checksum_mode_on(input.checksum_mode.as_ref())
        {
            set_checksums!(out, sums);
            out.checksum_type.clone_from(&slice.checksum_type);
        }
        set_sse!(out, info.sse.as_ref());
        Ok(S3Response::new(out))
    }

    async fn head_object(
        &self,
        req: S3Request<dto::HeadObjectInput>,
    ) -> S3Result<S3Response<dto::HeadObjectOutput>> {
        let input = req.input;
        check_version(input.version_id.as_deref())?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let (info, _) = self
            .read(
                &input.bucket,
                &input.key,
                customer.as_ref(),
                input.part_number,
            )
            .await?;
        check_read(
            &info,
            input.if_match.as_ref(),
            input.if_none_match.as_ref(),
            input.if_modified_since.as_ref(),
            input.if_unmodified_since.as_ref(),
        )?;
        let slice = Slice::of(&info, input.range.as_ref(), input.part_number)?;
        let mut out = dto::HeadObjectOutput {
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
            tag_count: tag_count(&info.attrs),
            ..Default::default()
        };
        if let Some(sums) = slice.checksums
            && checksum_mode_on(input.checksum_mode.as_ref())
        {
            set_checksums!(out, sums);
            out.checksum_type.clone_from(&slice.checksum_type);
        }
        set_sse!(out, info.sse.as_ref());
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
        check_version(input.version_id.as_deref())?;
        let customer = sse::customer_key(
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let (info, _) = self
            .store
            .read_with(&input.bucket, &input.key, customer.as_ref())
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
        check_version(input.version_id.as_deref())?;
        let info = self.store.head(&input.bucket, &input.key).await.s3()?;
        Ok(S3Response::new(dto::GetObjectTaggingOutput {
            tag_set: tagging::to_dto(&info.attrs.tags),
            version_id: None,
        }))
    }

    async fn put_object_tagging(
        &self,
        req: S3Request<dto::PutObjectTaggingInput>,
    ) -> S3Result<S3Response<dto::PutObjectTaggingOutput>> {
        let input = req.input;
        check_version(input.version_id.as_deref())?;
        let tags = tagging::check(tagging::from_dto(input.tagging), tagging::MAX_OBJECT_TAGS)?;
        self.store
            .set_tags(&input.bucket, &input.key, tags)
            .await
            .s3()?;
        Ok(S3Response::new(dto::PutObjectTaggingOutput::default()))
    }

    async fn delete_object_tagging(
        &self,
        req: S3Request<dto::DeleteObjectTaggingInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectTaggingOutput>> {
        let input = req.input;
        check_version(input.version_id.as_deref())?;
        self.store
            .set_tags(&input.bucket, &input.key, tagging::Tags::new())
            .await
            .s3()?;
        Ok(S3Response::new(dto::DeleteObjectTaggingOutput::default()))
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
        Ok(S3Response::new(dto::DeleteBucketTaggingOutput::default()))
    }

    async fn delete_object(
        &self,
        req: S3Request<dto::DeleteObjectInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectOutput>> {
        let input = req.input;
        check_version(input.version_id.as_deref())?;
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
        self.store
            .delete_if(&input.bucket, &input.key, precondition)
            .await
            .s3()?;
        Ok(S3Response::new(dto::DeleteObjectOutput {
            version_id: input.version_id,
            ..Default::default()
        }))
    }

    async fn delete_objects(
        &self,
        req: S3Request<dto::DeleteObjectsInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectsOutput>> {
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
            let result = match check_version(object.version_id.as_deref()) {
                Ok(()) => self
                    .store
                    .delete_if(&input.bucket, &object.key, precondition)
                    .await
                    .s3(),
                Err(err) => Err(err),
            };
            match result {
                Ok(()) if quiet => {}
                Ok(()) => deleted.push(dto::DeletedObject {
                    key: Some(object.key),
                    version_id: object.version_id,
                    ..Default::default()
                }),
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
        check_version(src_version.as_deref())?;
        let (src_bucket, src_key) = (src_bucket.to_string(), src_key.to_string());
        let source_key = sse::customer_key(
            input.copy_source_sse_customer_algorithm.as_deref(),
            input.copy_source_sse_customer_key.as_deref(),
            input.copy_source_sse_customer_key_md5.as_deref(),
        )?;
        let (source, _) = self
            .store
            .read_with(&src_bucket, &src_key, source_key.as_ref())
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
                    customer,
                },
            )
            .await?;
        let replace = input
            .metadata_directive
            .as_ref()
            .is_some_and(|d| d.as_str() == MetadataDirective::REPLACE);
        // A copy onto itself must change something the request names: metadata or
        // encryption (the bucket's default encryption doesn't count).
        let asks_encryption = input.server_side_encryption.is_some()
            || input.sse_customer_algorithm.is_some()
            || input.ssekms_key_id.is_some();
        if *src_bucket == *input.bucket && *src_key == *input.key && !replace && !asks_encryption {
            return Err(s3_error!(
                InvalidRequest,
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes."
            ));
        }
        let attrs = copy_attrs(&mut input, &source.attrs, replace)?;
        let pre = precondition(input.if_match.as_ref(), input.if_none_match.as_ref());
        let info = self
            .store
            .copy_with(
                (&src_bucket, &src_key),
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
            ..Default::default()
        };
        set_sse!(out, with_customer_md5(info.sse, customer_md5).as_ref());
        Ok(S3Response::new(out))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<dto::ListObjectsV2Input>,
    ) -> S3Result<S3Response<dto::ListObjectsV2Output>> {
        let mut input = req.input;
        // An empty delimiter is no delimiter, and S3 leaves it out of the answer.
        input.delimiter = input.delimiter.filter(|d| !d.is_empty());
        let after = match &input.continuation_token {
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
        let fetch_owner = input.fetch_owner.unwrap_or(false);
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
                owner: fetch_owner.then(owner),
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
                owner: Some(owner()),
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
            prefix: Some(enc(input.prefix.unwrap_or_default())),
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
        // Without versioning each object has exactly one version, `null`, so this is the
        // V1 listing with version fields: a page resumes after its key marker.
        let mut input = req.input;
        // An empty delimiter is no delimiter, and S3 leaves it out of the answer.
        input.delimiter = input.delimiter.filter(|d| !d.is_empty());
        let prefix = input.prefix.clone().unwrap_or_default();
        if input
            .version_id_marker
            .as_deref()
            .is_some_and(|m| !m.is_empty())
            && input.key_marker.as_deref().is_none_or(str::is_empty)
        {
            return Err(s3_error!(
                InvalidArgument,
                "A version-id marker cannot be specified without a key marker."
            ));
        }
        let after = after_marker(
            input.key_marker.clone(),
            input.delimiter.as_deref(),
            &prefix,
        );
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
        let (next_key_marker, next_version_id_marker) = match &listing.next {
            Some(After::Key(k) | After::Prefix(k)) => {
                (Some(enc(k.clone())), Some(NULL_VERSION.to_owned()))
            }
            None => (None, None),
        };
        let versions: Vec<dto::ObjectVersion> = listing
            .objects
            .into_iter()
            .map(|o| dto::ObjectVersion {
                key: Some(enc(o.key)),
                version_id: Some(NULL_VERSION.to_owned()),
                is_latest: Some(true),
                size: Some(i64::try_from(o.size).unwrap_or(i64::MAX)),
                e_tag: Some(etag(&o.etag)),
                last_modified: Some(o.modified.into()),
                storage_class: Some(dto::ObjectVersionStorageClass::from_static(
                    dto::ObjectVersionStorageClass::STANDARD,
                )),
                owner: Some(owner()),
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
            common_prefixes: (!prefixes.is_empty()).then_some(prefixes),
            ..Default::default()
        }))
    }

    async fn create_multipart_upload(
        &self,
        req: S3Request<dto::CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::CreateMultipartUploadOutput>> {
        let owner = access_key(&req).map(str::to_owned);
        let mut input = req.input;
        let mut attrs = new_attrs!(input).into_attrs(BTreeMap::new());
        attrs.tags = header_tags(input.tagging.as_deref())?;
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
            )
            .await
            .s3()?;
        let mut out = dto::CreateMultipartUploadOutput {
            bucket: Some(input.bucket),
            key: Some(input.key),
            upload_id: Some(upload.id.clone()),
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
        check_owner(&upload, &req.input.bucket, &req.input.key, access_key(&req))?;
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
        let staged = self
            .store
            .stage_part(&upload.id, number, customer.as_ref())
            .await
            .s3()?;
        let staged = self.stage(staged, body, &mut hasher).await?;
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
        check_owner(&upload, &req.input.bucket, &req.input.key, access_key(&req))?;
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
        check_version(src_version.as_deref())?;
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
            .read_with(src_bucket, src_key, source_key.as_ref())
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
            ..Default::default()
        }))
    }

    async fn list_parts(
        &self,
        req: S3Request<dto::ListPartsInput>,
    ) -> S3Result<S3Response<dto::ListPartsOutput>> {
        let upload = self.store.upload(&req.input.upload_id).await.s3()?;
        check_owner(&upload, &req.input.bucket, &req.input.key, access_key(&req))?;
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
            owner: Some(owner()),
            initiator: Some(dto::Initiator {
                display_name: Some(OWNER.to_owned()),
                id: Some(OWNER.to_owned()),
            }),
            storage_class: Some(dto::StorageClass::from_static(dto::StorageClass::STANDARD)),
            checksum_algorithm,
            checksum_type,
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
                    owner: Some(owner()),
                    initiator: Some(dto::Initiator {
                        display_name: Some(OWNER.to_owned()),
                        id: Some(OWNER.to_owned()),
                    }),
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
        let who = access_key(&req).map(str::to_owned);
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
        check_owner(&upload, &input.bucket, &input.key, who.as_deref())?;
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
        // S3 reports SSE-S3 and SSE-KMS here, not SSE-C.
        let headers = sse::headers(info.sse.as_ref());
        out.server_side_encryption = headers.sse;
        out.ssekms_key_id = headers.kms_key;
        Ok(S3Response::new(out))
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<dto::AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::AbortMultipartUploadOutput>> {
        let upload = self.store.upload(&req.input.upload_id).await.s3()?;
        check_owner(&upload, &req.input.bucket, &req.input.key, access_key(&req))?;
        self.store.abort(&upload.id).await.s3()?;
        Ok(S3Response::new(dto::AbortMultipartUploadOutput::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_ranges_are_inclusive() {
        assert_eq!(copy_range("bytes=0-9", 100).unwrap(), (0, 10));
        assert_eq!(copy_range("bytes=90-99", 100).unwrap(), (90, 10));
        assert!(copy_range("bytes=90-100", 100).is_err());
        assert!(copy_range("bytes=5-1", 100).is_err());
        assert!(copy_range("0-9", 100).is_err());
    }
}
