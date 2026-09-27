//! The S3 operations.

use std::{collections::BTreeMap, io::SeekFrom, time::SystemTime};

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
    After, ListQuery, Match, ObjectAttrs, ObjectInfo, Precondition, Staged, Store, Upload,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::{
    checksums::{self, Sums, checksum_of, set_checksums},
    encode,
    errors::{StoreResultExt, from_body},
};

/// How many keys a listing returns at most, and by default.
const MAX_KEYS: i32 = 1000;
/// How many keys one `DeleteObjects` may name.
const MAX_DELETE: usize = 1000;
/// Read buffer for object bodies.
const READ_CHUNK: usize = 256 * 1024;
/// Who owns every bucket (a drive has one owner).
const OWNER: &str = "teifs";
/// The version id of every object in a bucket without versioning, as S3 names it.
const NULL_VERSION: &str = "null";

/// The S3 API over a drive.
#[derive(Debug, Clone)]
pub struct Drive {
    store: Store,
}

impl Drive {
    /// Serves `store`.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Streams a request body into a staged file, hashing it for the checksums asked for.
    async fn stage(
        &self,
        body: StreamingBlob,
        sums: &mut s3s::checksum::ChecksumHasher,
    ) -> S3Result<Staged> {
        let mut staged = self.store.stage().await.s3()?;
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
    }
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn timestamp_seconds(timestamp: &Timestamp) -> i64 {
    time::OffsetDateTime::from(timestamp.clone()).unix_timestamp()
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
        self.store.create_bucket(&req.input.bucket).await.s3()?;
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

    async fn put_object(
        &self,
        req: S3Request<dto::PutObjectInput>,
    ) -> S3Result<S3Response<dto::PutObjectOutput>> {
        let mut input = req.input;
        let body = input.body.take().ok_or_else(|| s3_error!(IncompleteBody))?;
        let mut sent = checksums::from_dto(&checksum_of!(input));
        let mut hasher = checksums::hasher(
            &sent,
            input
                .checksum_algorithm
                .as_ref()
                .map(s3s::dto::ChecksumAlgorithm::as_str),
        )?;
        let staged = self.stage(body, &mut hasher).await?;
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
        let attrs = new_attrs!(input).into_attrs(computed.clone());
        let pre = precondition(input.if_match.as_ref(), input.if_none_match.as_ref());
        let info = self
            .store
            .commit(&input.bucket, &input.key, staged, attrs, pre)
            .await
            .s3()?;
        let mut out = dto::PutObjectOutput {
            e_tag: Some(etag(&info.etag)),
            ..Default::default()
        };
        set_checksums!(out, &computed);
        Ok(S3Response::new(out))
    }

    async fn get_object(
        &self,
        req: S3Request<dto::GetObjectInput>,
    ) -> S3Result<S3Response<dto::GetObjectOutput>> {
        let input = req.input;
        check_version(input.version_id.as_deref())?;
        if input.part_number.is_some() {
            return Err(s3_error!(
                NotImplemented,
                "reading one part of an object isn't supported"
            ));
        }
        let (info, file) = self.store.read(&input.bucket, &input.key).await.s3()?;
        check_read(
            &info,
            input.if_match.as_ref(),
            input.if_none_match.as_ref(),
            input.if_modified_since.as_ref(),
            input.if_unmodified_since.as_ref(),
        )?;
        let range = match &input.range {
            Some(range) => Some(
                range
                    .check(info.size)
                    .map_err(|_| s3_error!(InvalidRange))?,
            ),
            None => None,
        };
        let (start, length) = range
            .as_ref()
            .map_or((0, info.size), |r| (r.start, r.end - r.start));
        let body = match file {
            Some(mut file) => {
                if start > 0 {
                    file.seek(SeekFrom::Start(start))
                        .await
                        .map_err(|e| s3_error!(e, InternalError))?;
                }
                StreamingBlob::wrap(ReaderStream::with_capacity(file.take(length), READ_CHUNK))
            }
            None => StreamingBlob::from(s3s::Body::empty()),
        };
        let whole = range.is_none();
        let mut out = dto::GetObjectOutput {
            body: Some(body),
            content_length: Some(i64::try_from(length).unwrap_or(i64::MAX)),
            content_range: range
                .as_ref()
                .map(|r| format!("bytes {}-{}/{}", r.start, r.end - 1, info.size)),
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
            ..Default::default()
        };
        let asked = input
            .checksum_mode
            .as_ref()
            .is_some_and(|m| m.as_str() == ChecksumMode::ENABLED);
        if asked && whole {
            set_checksums!(out, &info.attrs.checksums);
        }
        Ok(S3Response::new(out))
    }

    async fn head_object(
        &self,
        req: S3Request<dto::HeadObjectInput>,
    ) -> S3Result<S3Response<dto::HeadObjectOutput>> {
        let input = req.input;
        check_version(input.version_id.as_deref())?;
        let info = self.store.head(&input.bucket, &input.key).await.s3()?;
        check_read(
            &info,
            input.if_match.as_ref(),
            input.if_none_match.as_ref(),
            input.if_modified_since.as_ref(),
            input.if_unmodified_since.as_ref(),
        )?;
        let mut out = dto::HeadObjectOutput {
            content_length: Some(i64::try_from(info.size).unwrap_or(i64::MAX)),
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
            ..Default::default()
        };
        if input
            .checksum_mode
            .as_ref()
            .is_some_and(|m| m.as_str() == ChecksumMode::ENABLED)
        {
            set_checksums!(out, &info.attrs.checksums);
        }
        Ok(S3Response::new(out))
    }

    async fn delete_object(
        &self,
        req: S3Request<dto::DeleteObjectInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectOutput>> {
        check_version(req.input.version_id.as_deref())?;
        self.store.head_bucket(&req.input.bucket).await.s3()?;
        self.store
            .delete(&req.input.bucket, &req.input.key)
            .await
            .s3()?;
        Ok(S3Response::new(dto::DeleteObjectOutput {
            version_id: req.input.version_id,
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
            let result = match check_version(object.version_id.as_deref()) {
                Ok(()) => self.store.delete(&input.bucket, &object.key).await.s3(),
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
        let source = self.store.head(src_bucket, src_key).await.s3()?;
        check_read(
            &source,
            input.copy_source_if_match.as_ref(),
            input.copy_source_if_none_match.as_ref(),
            input.copy_source_if_modified_since.as_ref(),
            input.copy_source_if_unmodified_since.as_ref(),
        )
        .map_err(|_| s3_error!(PreconditionFailed))?;
        let replace = input
            .metadata_directive
            .as_ref()
            .is_some_and(|d| d.as_str() == MetadataDirective::REPLACE);
        let attrs = replace.then(|| new_attrs!(input).into_attrs(BTreeMap::new()));
        let pre = precondition(input.if_match.as_ref(), input.if_none_match.as_ref());
        let info = self
            .store
            .copy(
                (src_bucket, src_key),
                (&input.bucket, &input.key),
                attrs,
                pre,
            )
            .await
            .s3()?;
        Ok(S3Response::new(dto::CopyObjectOutput {
            copy_object_result: Some(dto::CopyObjectResult {
                e_tag: Some(etag(&info.etag)),
                last_modified: Some(info.modified.into()),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<dto::ListObjectsV2Input>,
    ) -> S3Result<S3Response<dto::ListObjectsV2Output>> {
        let input = req.input;
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
        let input = req.input;
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
            .filter(|_| input.delimiter.as_deref().is_some_and(|d| !d.is_empty()))
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
        let input = req.input;
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
        let attrs = new_attrs!(input).into_attrs(BTreeMap::new());
        let upload = self
            .store
            .create_upload(&input.bucket, &input.key, attrs, owner)
            .await
            .s3()?;
        Ok(S3Response::new(dto::CreateMultipartUploadOutput {
            bucket: Some(input.bucket),
            key: Some(input.key),
            upload_id: Some(upload.id),
            ..Default::default()
        }))
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
        let mut hasher = checksums::hasher(
            &sent,
            input
                .checksum_algorithm
                .as_ref()
                .map(s3s::dto::ChecksumAlgorithm::as_str),
        )?;
        let staged = self.stage(body, &mut hasher).await?;
        checksums::add_trailers(&mut sent, req.trailing_headers)?;
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
        let (source, file) = self.store.read(src_bucket, src_key).await.s3()?;
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
        let mut staged = self.store.stage().await.s3()?;
        if let Some(mut file) = file {
            file.seek(SeekFrom::Start(start))
                .await
                .map_err(|e| s3_error!(e, InternalError))?;
            let mut reader = ReaderStream::with_capacity(file.take(length), READ_CHUNK);
            while let Some(chunk) = reader.next().await {
                let chunk = chunk.map_err(|e| s3_error!(e, InternalError))?;
                staged.write(&chunk).await.s3()?;
            }
        }
        let part = self
            .store
            .put_part(&upload.id, number, staged, BTreeMap::new())
            .await
            .s3()?;
        Ok(S3Response::new(dto::UploadPartCopyOutput {
            copy_part_result: Some(dto::CopyPartResult {
                e_tag: Some(etag(&part.etag)),
                last_modified: Some(millis(part.modified_ms)),
                ..Default::default()
            }),
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
        let mut parts = self.store.parts(&upload.id, after, limit + 1).await.s3()?;
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
            .map(|u| dto::MultipartUpload {
                key: Some(u.key),
                upload_id: Some(u.id),
                initiated: Some(millis(u.created_ms)),
                owner: Some(owner()),
                initiator: Some(dto::Initiator {
                    display_name: Some(OWNER.to_owned()),
                    id: Some(OWNER.to_owned()),
                }),
                storage_class: Some(dto::StorageClass::from_static(dto::StorageClass::STANDARD)),
                ..Default::default()
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
        let upload = self.store.upload(&req.input.upload_id).await.s3()?;
        check_owner(&upload, &req.input.bucket, &req.input.key, access_key(&req))?;
        let input = req.input;
        let listed = input
            .multipart_upload
            .and_then(|m| m.parts)
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                let number = part_number(p.part_number.ok_or_else(|| s3_error!(InvalidPart))?)?;
                let etag = p
                    .e_tag
                    .ok_or_else(|| s3_error!(InvalidPart))?
                    .value()
                    .to_owned();
                Ok((number, etag))
            })
            .collect::<S3Result<Vec<_>>>()?;
        let pre = precondition(input.if_match.as_ref(), input.if_none_match.as_ref());
        let info = self.store.complete(&upload.id, listed, pre).await.s3()?;
        Ok(S3Response::new(dto::CompleteMultipartUploadOutput {
            bucket: Some(input.bucket.clone()),
            key: Some(input.key.clone()),
            location: Some(format!("/{}/{}", input.bucket, input.key)),
            e_tag: Some(etag(&info.etag)),
            ..Default::default()
        }))
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
