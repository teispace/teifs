//! Buckets and objects as folders and files, the way every gateway shows them: `/` holds
//! the buckets the person may list, `/BUCKET` is a bucket, and `/BUCKET/a/b` is the object
//! `a/b`, or the folder `a/b/` when keys start with it. Each operation is S3 requests,
//! made with the person's own key.

use std::time::SystemTime;

use aws_sdk_s3::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
};
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use bytes::{Bytes, BytesMut};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// The largest object S3's `CopyObject` copies in one request (5 GiB).
const MAX_COPY: u64 = 5 * 1024 * 1024 * 1024;
/// How many objects a listing asks for at once.
const PAGE: i32 = 1000;
/// Parts after the first thousand are this many times bigger, so an upload can reach
/// about 590 GB in S3's 10,000 parts with 16 MiB ones first.
const LATER_PARTS: usize = 4;
/// The most parts an upload has (S3's limit).
const MAX_PARTS: i32 = 10_000;

/// What a copy source and a rename source leave unencoded: RFC 3986's unreserved
/// characters, and the slashes between a key's names.
const SOURCE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');

/// Why a file operation failed, as the protocols tell it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// There's no such file or folder.
    NotFound,
    /// The person's policies don't allow it.
    Denied,
    /// Something is already there.
    Exists,
    /// The folder or bucket isn't empty.
    NotEmpty,
    /// Files over S3 can't do that.
    Unsupported(&'static str),
    /// The path or request is invalid.
    Invalid(String),
    /// The S3 service refused or failed it, with its code and message.
    Failed(String),
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("No such file or folder"),
            Self::Denied => f.write_str("Access denied"),
            Self::Exists => f.write_str("It already exists"),
            Self::NotEmpty => f.write_str("The folder isn't empty"),
            Self::Unsupported(what) => write!(f, "Not supported: {what}"),
            Self::Invalid(why) | Self::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for FsError {}

/// What an S3 error means for a file operation.
fn s3_error<E>(err: &SdkError<E, HttpResponse>) -> FsError
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
{
    let status = err.raw_response().map(|r| r.status().as_u16());
    let code = err.code().unwrap_or_default();
    match (status, code) {
        (_, "NoSuchKey" | "NoSuchBucket" | "NotFound" | "NoSuchUpload") | (Some(404), _) => {
            FsError::NotFound
        }
        (_, "AccessDenied") | (Some(403), _) => FsError::Denied,
        (_, "BucketNotEmpty") => FsError::NotEmpty,
        (_, "BucketAlreadyExists" | "BucketAlreadyOwnedByYou" | "PreconditionFailed")
        | (Some(412), _) => FsError::Exists,
        (_, "InvalidBucketName" | "KeyTooLongError" | "InvalidArgument") => {
            FsError::Invalid(err.message().map_or_else(|| code.to_owned(), str::to_owned))
        }
        _ => FsError::Failed(match (err.code(), err.message()) {
            (Some(code), Some(message)) => format!("{code}: {message}"),
            (Some(code), None) => code.to_owned(),
            _ => format!(
                "{}",
                aws_smithy_types::error::display::DisplayErrorContext(err)
            ),
        }),
    }
}

/// A path, made absolute and resolved: a bucket, and a key in it without its folder's
/// slash (empty for the bucket itself); neither for `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// The bucket, unless it's `/`.
    pub bucket: Option<String>,
    /// The key in the bucket, `a/b` for `/bucket/a/b` (and `/bucket/a/b/`).
    pub key: String,
}

impl Location {
    /// Resolves `path` (absolute, or relative to `/`): `.` and empty names are dropped,
    /// `..` goes up (never above `/`).
    #[must_use]
    pub fn parse(path: &str) -> Self {
        let mut names: Vec<&str> = Vec::new();
        for name in path.split('/') {
            match name {
                "" | "." => {}
                ".." => {
                    names.pop();
                }
                name => names.push(name),
            }
        }
        let mut names = names.into_iter();
        Self {
            bucket: names.next().map(str::to_owned),
            key: names.collect::<Vec<_>>().join("/"),
        }
    }

    /// Its path, absolute: `/`, `/bucket`, `/bucket/a/b`.
    #[must_use]
    pub fn path(&self) -> String {
        match (&self.bucket, self.key.is_empty()) {
            (None, _) => "/".to_owned(),
            (Some(bucket), true) => format!("/{bucket}"),
            (Some(bucket), false) => format!("/{bucket}/{}", self.key),
        }
    }

    /// The location of `name` in this folder.
    #[must_use]
    pub fn child(&self, name: &str) -> Self {
        match &self.bucket {
            None => Self {
                bucket: Some(name.to_owned()),
                key: String::new(),
            },
            Some(bucket) => Self {
                bucket: Some(bucket.clone()),
                key: if self.key.is_empty() {
                    name.to_owned()
                } else {
                    format!("{}/{name}", self.key)
                },
            },
        }
    }

    /// The bucket and key of an object: none for `/` and buckets.
    fn object(&self) -> Option<(&str, &str)> {
        match &self.bucket {
            Some(bucket) if !self.key.is_empty() => Some((bucket, &self.key)),
            _ => None,
        }
    }

    /// The prefix of the keys in this folder: `a/b/`, or none for a bucket's top.
    fn prefix(&self) -> Option<String> {
        (!self.key.is_empty()).then(|| format!("{}/", self.key))
    }

    /// Its last name, `b` for `/bucket/a/b`.
    #[must_use]
    pub fn name(&self) -> &str {
        if self.key.is_empty() {
            self.bucket.as_deref().unwrap_or("/")
        } else {
            self.key.rsplit('/').next().unwrap_or(&self.key)
        }
    }
}

/// A folder or a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `/`, a bucket, or the keys under a prefix.
    Folder,
    /// An object.
    File,
}

/// A folder or file, as a listing or `stat` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its name in its folder.
    pub name: String,
    /// Folder or file.
    pub kind: Kind,
    /// A file's size in bytes (0 for folders).
    pub size: u64,
    /// When it was last written, when S3 says.
    pub modified: Option<SystemTime>,
}

impl Entry {
    fn folder(name: &str, modified: Option<SystemTime>) -> Self {
        Self {
            name: name.to_owned(),
            kind: Kind::Folder,
            size: 0,
            modified,
        }
    }
}

fn system_time(time: Option<&aws_sdk_s3::primitives::DateTime>) -> Option<SystemTime> {
    time.and_then(|t| SystemTime::try_from(*t).ok())
}

/// One page of a folder's listing, and where the next starts.
#[derive(Debug, Default)]
pub struct Page {
    /// What's in it.
    pub entries: Vec<Entry>,
    /// The token for the next page, unless this was the last.
    pub next: Option<String>,
}

/// A person's buckets and objects, as folders and files.
#[derive(Debug, Clone)]
pub struct Files {
    s3: Client,
    part_size: usize,
}

impl Files {
    /// Files over `s3`, uploading in parts of `part_size` bytes (at least S3's 5 MiB).
    #[must_use]
    pub fn new(s3: Client, part_size: usize) -> Self {
        Self {
            s3,
            part_size: part_size.max(5 * 1024 * 1024),
        }
    }

    /// What's at `at`.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] when nothing is.
    pub async fn stat(&self, at: &Location) -> Result<Entry, FsError> {
        let Some(bucket) = &at.bucket else {
            return Ok(Entry::folder("/", None));
        };
        let Some((_, key)) = at.object() else {
            return match self.s3.head_bucket().bucket(bucket).send().await {
                Ok(_) => Ok(Entry::folder(bucket, None)),
                // It's there, but the person can't list it: maybe its objects.
                Err(err) if s3_error(&err) == FsError::Denied => Ok(Entry::folder(bucket, None)),
                Err(err) => Err(s3_error(&err)),
            };
        };
        let head = self.s3.head_object().bucket(bucket).key(key).send().await;
        let refused = match head {
            Ok(head) => {
                return Ok(Entry {
                    name: at.name().to_owned(),
                    kind: Kind::File,
                    size: head.content_length.unwrap_or(0).try_into().unwrap_or(0),
                    modified: system_time(head.last_modified.as_ref()),
                });
            }
            Err(err) => s3_error(&err),
        };
        if !matches!(refused, FsError::NotFound | FsError::Denied) {
            return Err(refused);
        }
        // No such object: a folder, if any key starts with it.
        let listed = self
            .s3
            .list_objects_v2()
            .bucket(bucket)
            .prefix(format!("{key}/"))
            .max_keys(1)
            .send()
            .await;
        match listed {
            Ok(listed) if listed.key_count.unwrap_or(0) > 0 => Ok(Entry::folder(at.name(), None)),
            Ok(_) => Err(refused),
            Err(err) => match s3_error(&err) {
                FsError::Denied => Err(refused),
                other => Err(other),
            },
        }
    }

    /// One page of what's in the folder `at`, from `token` (none for the first).
    ///
    /// # Errors
    ///
    /// When the folder can't be listed.
    pub async fn list(&self, at: &Location, token: Option<String>) -> Result<Page, FsError> {
        let Some(bucket) = &at.bucket else {
            let buckets = self
                .s3
                .list_buckets()
                .set_continuation_token(token)
                .send()
                .await
                .map_err(|err| s3_error(&err))?;
            return Ok(Page {
                entries: buckets
                    .buckets()
                    .iter()
                    .filter_map(|b| {
                        let name = b.name.as_deref()?;
                        Some(Entry::folder(name, system_time(b.creation_date.as_ref())))
                    })
                    .collect(),
                next: buckets.continuation_token.filter(|t| !t.is_empty()),
            });
        };
        let prefix = at.prefix();
        let listed = self
            .s3
            .list_objects_v2()
            .bucket(bucket)
            .set_prefix(prefix.clone())
            .delimiter("/")
            .max_keys(PAGE)
            .set_continuation_token(token)
            .send()
            .await
            .map_err(|err| s3_error(&err))?;
        let prefix = prefix.unwrap_or_default();
        let name = |full: &str| -> Option<String> {
            let name = full.strip_prefix(prefix.as_str())?.trim_end_matches('/');
            (!name.is_empty() && !name.contains('/') && name != "." && name != "..")
                .then(|| name.to_owned())
        };
        let mut entries: Vec<Entry> = listed
            .common_prefixes()
            .iter()
            .filter_map(|p| name(p.prefix.as_deref()?))
            .map(|n| Entry::folder(&n, None))
            .collect();
        entries.extend(listed.contents().iter().filter_map(|object| {
            let key = object.key.as_deref()?;
            // The folder's own key (`a/b/`) is the folder, not a file in it.
            if key.ends_with('/') {
                return None;
            }
            Some(Entry {
                name: name(key)?,
                kind: Kind::File,
                size: object.size.unwrap_or(0).try_into().unwrap_or(0),
                modified: system_time(object.last_modified.as_ref()),
            })
        }));
        Ok(Page {
            entries,
            next: listed
                .next_continuation_token
                .filter(|_| listed.is_truncated == Some(true)),
        })
    }

    /// Makes the folder `at`: a bucket at the top, else an empty `key/` object.
    ///
    /// # Errors
    ///
    /// [`FsError::Exists`] when something is there.
    pub async fn mkdir(&self, at: &Location) -> Result<(), FsError> {
        let Some(bucket) = &at.bucket else {
            return Err(FsError::Exists);
        };
        if at.key.is_empty() {
            return self
                .s3
                .create_bucket()
                .bucket(bucket)
                .send()
                .await
                .map(|_| ())
                .map_err(|err| s3_error(&err));
        }
        if self.stat(at).await.is_ok() {
            return Err(FsError::Exists);
        }
        self.s3
            .put_object()
            .bucket(bucket)
            .key(format!("{}/", at.key))
            .body(ByteStream::from_static(b""))
            .send()
            .await
            .map(|_| ())
            .map_err(|err| s3_error(&err))
    }

    /// Removes the empty folder `at`: its `key/` object, or the bucket.
    ///
    /// # Errors
    ///
    /// [`FsError::NotEmpty`] when it has files or folders.
    pub async fn rmdir(&self, at: &Location) -> Result<(), FsError> {
        let Some(bucket) = &at.bucket else {
            return Err(FsError::Denied);
        };
        let Some(prefix) = at.prefix() else {
            return self
                .s3
                .delete_bucket()
                .bucket(bucket)
                .send()
                .await
                .map(|_| ())
                .map_err(|err| s3_error(&err));
        };
        let listed = self
            .s3
            .list_objects_v2()
            .bucket(bucket)
            .prefix(&prefix)
            .max_keys(2)
            .send()
            .await
            .map_err(|err| s3_error(&err))?;
        let keys: Vec<&str> = listed
            .contents()
            .iter()
            .filter_map(|o| o.key.as_deref())
            .collect();
        match keys.as_slice() {
            // A folder bucket's listing of a folder leaves the folder's own key out.
            [] => match self
                .s3
                .head_object()
                .bucket(bucket)
                .key(&prefix)
                .send()
                .await
            {
                Ok(_) => self
                    .s3
                    .delete_object()
                    .bucket(bucket)
                    .key(&prefix)
                    .send()
                    .await
                    .map(|_| ())
                    .map_err(|err| s3_error(&err)),
                Err(err) => Err(s3_error(&err)),
            },
            [only] if *only == prefix => self
                .s3
                .delete_object()
                .bucket(bucket)
                .key(&prefix)
                .send()
                .await
                .map(|_| ())
                .map_err(|err| s3_error(&err)),
            _ => Err(FsError::NotEmpty),
        }
    }

    /// Removes the file `at`.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] when there's no such file.
    pub async fn remove(&self, at: &Location) -> Result<(), FsError> {
        let Some((bucket, key)) = at.object() else {
            return Err(FsError::Invalid("That's a folder, not a file".into()));
        };
        let entry = self.stat(at).await?;
        if entry.kind == Kind::Folder {
            return Err(FsError::Invalid("That's a folder, not a file".into()));
        }
        self.s3
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map(|_| ())
            .map_err(|err| s3_error(&err))
    }

    /// Renames the file `from` to `to`, replacing a file there only when `replace`.
    /// Within a bucket it's S3's `RenameObject`, else (or where a bucket keeps versions)
    /// a copy and a delete. Folders aren't renamed.
    ///
    /// # Errors
    ///
    /// [`FsError::Exists`] when `to` is there and not to be replaced.
    pub async fn rename(
        &self,
        from: &Location,
        to: &Location,
        replace: bool,
    ) -> Result<(), FsError> {
        let (Some((from_bucket, from_key)), Some((to_bucket, to_key))) =
            (from.object(), to.object())
        else {
            return Err(FsError::Unsupported("renaming buckets"));
        };
        let source = self.stat(from).await?;
        if source.kind == Kind::Folder {
            return Err(FsError::Unsupported("renaming folders"));
        }
        match self.stat(to).await {
            Ok(entry) if entry.kind == Kind::Folder => return Err(FsError::Exists),
            Ok(_) if !replace => return Err(FsError::Exists),
            Ok(_) | Err(FsError::NotFound) => {}
            Err(err) => return Err(err),
        }
        if from_bucket == to_bucket {
            let renamed = self
                .s3
                .rename_object()
                .bucket(to_bucket)
                .key(to_key)
                .rename_source(
                    utf8_percent_encode(&format!("/{from_bucket}/{from_key}"), SOURCE).to_string(),
                )
                .set_destination_if_none_match((!replace).then(|| "*".to_owned()))
                .send()
                .await;
            match renamed {
                Ok(_) => return Ok(()),
                // A bucket that has had versioning: copy instead.
                Err(err) if err.code() == Some("InvalidRequest") => {}
                Err(err) => return Err(s3_error(&err)),
            }
        }
        if source.size > MAX_COPY {
            return Err(FsError::Unsupported(
                "moving a file over 5 GiB between buckets or in a bucket that keeps versions",
            ));
        }
        self.s3
            .copy_object()
            .bucket(to_bucket)
            .key(to_key)
            .copy_source(
                utf8_percent_encode(&format!("{from_bucket}/{from_key}"), SOURCE).to_string(),
            )
            .set_if_none_match((!replace).then(|| "*".to_owned()))
            .send()
            .await
            .map_err(|err| s3_error(&err))?;
        self.s3
            .delete_object()
            .bucket(from_bucket)
            .key(from_key)
            .send()
            .await
            .map(|_| ())
            .map_err(|err| s3_error(&err))
    }

    /// Opens the file `at` to read.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] when there's no such file.
    pub async fn reader(&self, at: &Location) -> Result<Reader, FsError> {
        let Some((bucket, key)) = at.object() else {
            return Err(FsError::Invalid("That's a folder, not a file".into()));
        };
        let head = self
            .s3
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|err| s3_error(&err))?;
        Ok(Reader {
            s3: self.s3.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            entry: Entry {
                name: at.name().to_owned(),
                kind: Kind::File,
                size: head.content_length.unwrap_or(0).try_into().unwrap_or(0),
                modified: system_time(head.last_modified.as_ref()),
            },
            etag: head.e_tag,
            stream: None,
        })
    }

    /// Opens the file `at` to write from its start: it's uploaded (replacing what's
    /// there, unless `exclusive`) when the writer is finished.
    ///
    /// # Errors
    ///
    /// When `at` isn't in a bucket.
    pub fn writer(&self, at: &Location, exclusive: bool) -> Result<Writer, FsError> {
        let Some((bucket, key)) = at.object() else {
            return Err(FsError::Invalid("Files go in a bucket".into()));
        };
        Ok(Writer {
            s3: self.s3.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            name: at.name().to_owned(),
            part_size: self.part_size,
            exclusive,
            buffer: BytesMut::new(),
            written: 0,
            upload: None,
        })
    }
}

/// An open download, read from where the last read ended without asking again.
#[derive(Debug)]
pub struct Reader {
    s3: Client,
    bucket: String,
    key: String,
    entry: Entry,
    etag: Option<String>,
    stream: Option<Stream>,
}

#[derive(Debug)]
struct Stream {
    at: u64,
    body: ByteStream,
    pending: Bytes,
}

impl Reader {
    /// The file, as it was opened.
    #[must_use]
    pub fn entry(&self) -> &Entry {
        &self.entry
    }

    /// Up to `len` bytes from `offset`: none at the end of the file.
    ///
    /// # Errors
    ///
    /// When the object can't be read, or changed since it was opened.
    pub async fn read(&mut self, offset: u64, len: usize) -> Result<Option<Bytes>, FsError> {
        if offset >= self.entry.size || len == 0 {
            return Ok(None);
        }
        let stream = match self.stream.take() {
            Some(stream) if stream.at == offset => stream,
            _ => {
                let got = self
                    .s3
                    .get_object()
                    .bucket(&self.bucket)
                    .key(&self.key)
                    .range(format!("bytes={offset}-"))
                    .set_if_match(self.etag.clone())
                    .send()
                    .await
                    .map_err(|err| match s3_error(&err) {
                        FsError::Exists => {
                            FsError::Failed("The file changed while it was read".into())
                        }
                        other => other,
                    })?;
                Stream {
                    at: offset,
                    body: got.body,
                    pending: Bytes::new(),
                }
            }
        };
        let mut stream = stream;
        let mut out = BytesMut::with_capacity(len.min(256 * 1024));
        while out.len() < len {
            if stream.pending.is_empty() {
                match stream.body.next().await {
                    Some(Ok(chunk)) => stream.pending = chunk,
                    Some(Err(err)) => return Err(FsError::Failed(err.to_string())),
                    None => break,
                }
                continue;
            }
            let take = (len - out.len()).min(stream.pending.len());
            out.extend_from_slice(&stream.pending.split_to(take));
        }
        if out.is_empty() {
            return Ok(None);
        }
        stream.at += out.len() as u64;
        self.stream = Some(stream);
        Ok(Some(out.freeze()))
    }
}

/// An upload being written: a `PutObject` when it's small, else a multipart upload whose
/// parts go as they fill. Writes must come in order, from the start.
#[derive(Debug)]
pub struct Writer {
    s3: Client,
    bucket: String,
    key: String,
    name: String,
    part_size: usize,
    exclusive: bool,
    buffer: BytesMut,
    written: u64,
    upload: Option<Upload>,
}

#[derive(Debug)]
struct Upload {
    id: String,
    parts: Vec<CompletedPart>,
}

impl Writer {
    /// The file as written so far.
    #[must_use]
    pub fn entry(&self) -> Entry {
        Entry {
            name: self.name.clone(),
            kind: Kind::File,
            size: self.written,
            modified: Some(SystemTime::now()),
        }
    }

    /// How big the next part is.
    fn next_part_size(&self) -> usize {
        let done = self.upload.as_ref().map_or(0, |u| u.parts.len());
        if done < 1000 {
            self.part_size
        } else {
            self.part_size * LATER_PARTS
        }
    }

    /// Writes `data` at `offset`, which must be where the last write ended.
    ///
    /// # Errors
    ///
    /// [`FsError::Unsupported`] for a write anywhere else; when a part can't be sent.
    pub async fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), FsError> {
        if offset != self.written {
            return Err(FsError::Unsupported(
                "writing anywhere but at the end of what's written (uploads go in order)",
            ));
        }
        self.buffer.extend_from_slice(data);
        self.written += data.len() as u64;
        while self.buffer.len() >= self.next_part_size() {
            let part = self.buffer.split_to(self.next_part_size()).freeze();
            self.send_part(part).await?;
        }
        Ok(())
    }

    async fn send_part(&mut self, part: Bytes) -> Result<(), FsError> {
        if self.upload.is_none() {
            let created = self
                .s3
                .create_multipart_upload()
                .bucket(&self.bucket)
                .key(&self.key)
                .content_type(content_type(&self.key))
                .send()
                .await
                .map_err(|err| s3_error(&err))?;
            self.upload = Some(Upload {
                id: created.upload_id.unwrap_or_default(),
                parts: Vec::new(),
            });
        }
        let upload = self.upload.as_mut().expect("the upload was just started");
        let number = i32::try_from(upload.parts.len() + 1).unwrap_or(MAX_PARTS + 1);
        if number > MAX_PARTS {
            return Err(FsError::Unsupported(
                "a file this big (10,000 parts at most)",
            ));
        }
        let sent = self
            .s3
            .upload_part()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&upload.id)
            .part_number(number)
            .body(ByteStream::from(part))
            .send()
            .await
            .map_err(|err| s3_error(&err))?;
        upload.parts.push(
            CompletedPart::builder()
                .part_number(number)
                .set_e_tag(sent.e_tag)
                .build(),
        );
        Ok(())
    }

    /// Uploads what's left and makes the object.
    ///
    /// # Errors
    ///
    /// When the upload fails (an upload in parts is then aborted).
    pub async fn finish(mut self) -> Result<(), FsError> {
        let rest = std::mem::take(&mut self.buffer).freeze();
        let Some(_) = &self.upload else {
            return self
                .s3
                .put_object()
                .bucket(&self.bucket)
                .key(&self.key)
                .content_type(content_type(&self.key))
                .set_if_none_match(self.exclusive.then(|| "*".to_owned()))
                .body(ByteStream::from(rest))
                .send()
                .await
                .map(|_| ())
                .map_err(|err| s3_error(&err));
        };
        if !rest.is_empty()
            && let Err(err) = self.send_part(rest).await
        {
            self.abort().await;
            return Err(err);
        }
        let upload = self.upload.take().expect("checked above");
        let completed = self
            .s3
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&upload.id)
            .set_if_none_match(self.exclusive.then(|| "*".to_owned()))
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(upload.parts))
                    .build(),
            )
            .send()
            .await;
        match completed {
            Ok(_) => Ok(()),
            Err(err) => {
                self.upload = Some(Upload {
                    id: upload.id,
                    parts: Vec::new(),
                });
                self.abort().await;
                Err(s3_error(&err))
            }
        }
    }

    /// Gives up: an upload in parts is aborted, so its parts don't linger.
    pub async fn abort(mut self) {
        if let Some(upload) = self.upload.take()
            && let Err(err) = self
                .s3
                .abort_multipart_upload()
                .bucket(&self.bucket)
                .key(&self.key)
                .upload_id(&upload.id)
                .send()
                .await
        {
            tracing::debug!(error = %s3_error(&err), "couldn't abort a gateway's upload");
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Dropped unfinished (the client went away): abort the upload in the background.
        let Some(upload) = self.upload.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let s3 = self.s3.clone();
        let (bucket, key) = (self.bucket.clone(), self.key.clone());
        runtime.spawn(async move {
            let _ = s3
                .abort_multipart_upload()
                .bucket(bucket)
                .key(key)
                .upload_id(upload.id)
                .send()
                .await;
        });
    }
}

/// The content type an upload gets: guessed from its name, as browsers and the AWS CLI
/// do.
fn content_type(key: &str) -> String {
    mime_guess::from_path(key)
        .first_or_octet_stream()
        .essence_str()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_resolve_to_buckets_and_keys() {
        let at = |path: &str| Location::parse(path);
        assert_eq!(
            at("/"),
            Location {
                bucket: None,
                key: String::new()
            }
        );
        assert_eq!(at(""), at("/"));
        assert_eq!(at("/.."), at("/"));
        assert_eq!(at("/b/").bucket.as_deref(), Some("b"));
        assert_eq!(at("/b//a/./c/").key, "a/c");
        assert_eq!(at("b/a/../../c/d").path(), "/c/d");
        assert_eq!(at("/b/a/b").name(), "b");
        assert_eq!(at("/b").name(), "b");
        assert_eq!(at("/b").child("x").path(), "/b/x");
        assert_eq!(at("/").child("b").path(), "/b");
        assert_eq!(at("/b/a").child("x").key, "a/x");
        assert_eq!(at("/b/a").prefix().as_deref(), Some("a/"));
        assert_eq!(at("/b").prefix(), None);
    }

    #[test]
    fn content_types_are_guessed_from_names() {
        assert_eq!(content_type("a/notes.txt"), "text/plain");
        assert_eq!(content_type("a/blob"), "application/octet-stream");
    }
}
