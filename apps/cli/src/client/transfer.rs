//! Moving bytes: uploads, downloads and copies of single objects, in parallel parts when
//! they're large. One budget of requests is shared by every file and part in a command.
//!
//! - Uploads send files larger than the part size as a multipart upload, reading each
//!   part straight from the file. If an unfinished upload of the same key is there,
//!   the parts that match the file (same size and MD5) are kept: running an interrupted
//!   copy again resumes it.
//! - Downloads fetch large objects in ranges at once, each pinned to the object's ETag
//!   (`If-Match`) so a change midway fails instead of mixing versions, into a hidden
//!   file beside the destination that's renamed over it when complete.
//! - Copies within one endpoint are done by the server (`CopyObject`, or
//!   `UploadPartCopy` above 5 GiB); between endpoints, each part is fetched and sent on.
//! - Streams (standard input) of unknown length go in parts read one after another and
//!   sent several at once, holding at most one part per request in memory; parts grow
//!   as they go so the largest object S3 allows fits in 10,000 of them. A stream can't
//!   be read again, so a failed one is aborted rather than left to resume.

use std::{
    collections::BTreeMap,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use aws_sdk_s3::{
    Client,
    operation::head_object::HeadObjectOutput,
    primitives::{ByteStream, Length},
    types::{
        ChecksumAlgorithm, ChecksumMode, CompletedMultipartUpload, CompletedPart, MetadataDirective,
    },
};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt, stream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

use super::{Error, Kind, TransferArgs};
use crate::ui::Progress;

pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * KIB;
pub const GIB: u64 = 1024 * MIB;
/// S3's smallest part (except the last).
pub const MIN_PART: u64 = 5 * MIB;
/// S3's largest part, and its largest single `PutObject` or `CopyObject`.
pub const MAX_PART: u64 = 5 * GIB;
/// S3's most parts in one upload.
pub const MAX_PARTS: u64 = 10_000;
/// How much of a file is read at a time while sending it (the SDK's default is 4 KiB).
const READ_BUFFER: usize = 256 * 1024;
/// Parts of a copy the server makes itself: nothing passes through here, so large.
const COPY_PART: u64 = 512 * MIB;
/// A stream's parts double in size after every this many.
const STREAM_PARTS_PER_SIZE: u64 = 1000;

/// Parses a part size ([`crate::units::parse_size`]): from 5 MiB to 5 GiB.
pub fn parse_part_size(text: &str) -> Result<u64, String> {
    let bytes = crate::units::parse_size(text)?;
    if !(MIN_PART..=MAX_PART).contains(&bytes) {
        return Err(format!("`{}` must be from 5MiB to 5GiB", text.trim()));
    }
    Ok(bytes)
}

/// The part size for `total` bytes: at least `min`, and large enough (in whole MiB)
/// that there are at most 10,000 parts.
pub fn part_size(total: u64, min: u64) -> u64 {
    min.max(total.div_ceil(MAX_PARTS).next_multiple_of(MIB))
}

/// `total` bytes cut into parts of `part` bytes (the last may be shorter).
fn ranges(total: u64, part: u64) -> Vec<Range<u64>> {
    (0..total.div_ceil(part))
        .map(|i| i * part..((i + 1) * part).min(total))
        .collect()
}

/// An object at an endpoint.
#[derive(Clone)]
pub struct Object {
    pub client: Client,
    pub bucket: String,
    pub key: String,
    /// `ALIAS/BUCKET/KEY`, for messages.
    pub name: String,
    /// The endpoint's URL and access key: objects with the same can be copied by the
    /// server.
    pub endpoint: (String, String),
    /// A version of it, as a source (`--version-id`); `None`: the current one.
    pub version_id: Option<String>,
}

/// What's known about an object: from `HEAD` (with its type and metadata), or from a
/// listing.
#[derive(Clone)]
pub struct Head {
    pub size: u64,
    pub etag: Option<String>,
    pub modified: Option<SystemTime>,
    /// The whole `HEAD` answer, when there was one.
    pub output: Option<HeadObjectOutput>,
}

impl Object {
    /// The object's details; a `NotFound` error when it isn't there.
    pub async fn head(&self) -> Result<Head, Error> {
        let output = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .set_version_id(self.version_id.clone())
            .send()
            .await
            .map_err(|e| Error::s3(&self.name, &e))?;
        Ok(Head {
            size: output
                .content_length()
                .and_then(|n| u64::try_from(n).ok())
                .unwrap_or(0),
            etag: output.e_tag().map(str::to_owned),
            modified: output
                .last_modified()
                .and_then(|t| SystemTime::try_from(*t).ok()),
            output: Some(output),
        })
    }
}

/// The request budget and part size shared by one command's transfers.
#[derive(Clone)]
pub struct Transfers {
    parallel: usize,
    part_size: u64,
    permits: Arc<Semaphore>,
    /// Bytes moved, as they're moved.
    progress: Progress,
}

impl Transfers {
    pub fn new(args: TransferArgs, progress: Progress) -> Self {
        Self {
            parallel: args.parallel,
            part_size: args.part_size,
            permits: Arc::new(Semaphore::new(args.parallel)),
            progress,
        }
    }

    /// Takes the progress bar away, once everything is done.
    pub fn finish(&self) {
        self.progress.finish();
    }

    /// How many files to work on at once (their requests share the budget).
    pub const fn parallel(&self) -> usize {
        self.parallel
    }

    async fn permit(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .expect("the semaphore stays open")
    }

    /// Uploads the local file `path` of `size` bytes to `to`.
    pub async fn upload(&self, path: &Path, size: u64, to: &Object) -> Result<(), Error> {
        let what = || format!("can't upload {} to {}", path.display(), to.name);
        let content_type = mime_guess::from_path(path).first_raw();
        if size <= self.part_size {
            let body = ByteStream::read_from()
                .path(path)
                .buffer_size(READ_BUFFER)
                .build()
                .await
                .map_err(|e| Error::general(format!("{}: {e}", what())))?;
            let _permit = self.permit().await;
            to.client
                .put_object()
                .bucket(&to.bucket)
                .key(&to.key)
                .set_content_type(content_type.map(str::to_owned))
                .body(body)
                .send()
                .await
                .map_err(|e| Error::s3(what(), &e))?;
            self.progress.add(size);
            return Ok(());
        }
        let parts = ranges(size, part_size(size, self.part_size));
        let (upload_id, done) = if let Some(found) = self.resumable(path, &parts, to).await {
            found
        } else {
            let content_type = content_type.map(str::to_owned);
            let id = self
                .start_upload(to, content_type, None, true)
                .await
                .map_err(|e| e.within(what()))?;
            (id, BTreeMap::new())
        };
        for number in done.keys() {
            if let Some(range) = usize::try_from(number - 1).ok().and_then(|i| parts.get(i)) {
                self.progress.add(range.end - range.start);
            }
        }
        let sent = stream::iter(parts.iter().cloned().zip(1..))
            .filter(|(_, number)| std::future::ready(!done.contains_key(number)))
            .map(|(range, number)| {
                let upload_id = upload_id.as_str();
                async move {
                    let body = ByteStream::read_from()
                        .path(path)
                        .buffer_size(READ_BUFFER)
                        .offset(range.start)
                        .length(Length::Exact(range.end - range.start))
                        .build()
                        .await
                        .map_err(|e| Error::general(format!("{}: {e}", what())))?;
                    let _permit = self.permit().await;
                    let part = to
                        .client
                        .upload_part()
                        .bucket(&to.bucket)
                        .key(&to.key)
                        .upload_id(upload_id)
                        .part_number(number)
                        .checksum_algorithm(ChecksumAlgorithm::Crc32)
                        .body(body)
                        .send()
                        .await
                        .map_err(|e| resumable_failure(Error::s3(what(), &e)))?;
                    self.progress.add(range.end - range.start);
                    Ok::<_, Error>(
                        CompletedPart::builder()
                            .part_number(number)
                            .set_e_tag(part.e_tag)
                            .set_checksum_crc32(part.checksum_crc32)
                            .build(),
                    )
                }
            })
            .buffer_unordered(self.parallel)
            .try_collect::<Vec<_>>()
            .await?;
        let mut all = done;
        all.extend(sent.into_iter().map(|p| (p.part_number().unwrap_or(0), p)));
        self.complete(to, &upload_id, all.into_values().collect())
            .await
            .map_err(|e| e.within(what()))
    }

    /// Uploads everything `input` gives until it ends to `to`; the bytes sent.
    pub async fn upload_stream(
        &self,
        mut input: impl AsyncRead + Unpin,
        to: &Object,
    ) -> Result<u64, Error> {
        let what = || format!("can't upload standard input to {}", to.name);
        let read_failed = |e: std::io::Error| Error::general(format!("{}: reading: {e}", what()));
        let first = read_part(&mut input, stream_part_size(self.part_size, 1))
            .await
            .map_err(read_failed)?;
        let first_len = first.len() as u64;
        if first_len < stream_part_size(self.part_size, 1) {
            // It all fits in one request.
            let _permit = self.permit().await;
            to.client
                .put_object()
                .bucket(&to.bucket)
                .key(&to.key)
                .body(ByteStream::from(first))
                .send()
                .await
                .map_err(|e| Error::s3(what(), &e))?;
            self.progress.add(first_len);
            return Ok(first_len);
        }
        let upload_id = self
            .start_upload(to, None, None, true)
            .await
            .map_err(|e| e.within(what()))?;
        let sent = self.send_stream(&mut input, first, &upload_id, to).await;
        let sent = match sent {
            Ok((parts, total)) => self.complete(to, &upload_id, parts).await.map(|()| total),
            Err(err) => Err(err),
        };
        if sent.is_err() {
            // Nothing can resume it: don't leave its parts behind.
            let _ = to
                .client
                .abort_multipart_upload()
                .bucket(&to.bucket)
                .key(&to.key)
                .upload_id(&upload_id)
                .send()
                .await;
        }
        sent.map_err(|e| e.within(what()))
    }

    /// Sends `first`, then the rest of `input`, as parts of `upload_id`; the parts in
    /// order, and the bytes sent.
    async fn send_stream(
        &self,
        input: &mut (impl AsyncRead + Unpin),
        first: Bytes,
        upload_id: &str,
        to: &Object,
    ) -> Result<(Vec<CompletedPart>, u64), Error> {
        let mut running = JoinSet::new();
        let mut parts = Vec::new();
        let (mut chunk, mut number, mut total) = (first, 1_u64, 0_u64);
        loop {
            total += chunk.len() as u64;
            running.spawn(self.clone().send_part(
                to.clone(),
                upload_id.to_owned(),
                i32::try_from(number).expect("at most 10,000 parts"),
                chunk,
            ));
            // One part per request in memory, and one being read.
            while running.len() >= self.parallel {
                parts.push(joined(running.join_next().await)?);
            }
            let next = read_part(input, stream_part_size(self.part_size, number + 1))
                .await
                .map_err(|e| Error::general(format!("reading: {e}")))?;
            if next.is_empty() {
                break;
            }
            if number == MAX_PARTS {
                return Err(Error::usage(
                    "the input is larger than S3's largest object (10,000 parts)",
                ));
            }
            (chunk, number) = (next, number + 1);
        }
        while let Some(result) = running.join_next().await {
            parts.push(joined(Some(result))?);
        }
        parts.sort_by_key(CompletedPart::part_number);
        Ok((parts, total))
    }

    /// Sends one part of a stream.
    async fn send_part(
        self,
        to: Object,
        upload_id: String,
        number: i32,
        body: Bytes,
    ) -> Result<CompletedPart, Error> {
        let len = body.len() as u64;
        let _permit = self.permit().await;
        let part = to
            .client
            .upload_part()
            .bucket(&to.bucket)
            .key(&to.key)
            .upload_id(upload_id)
            .part_number(number)
            .checksum_algorithm(ChecksumAlgorithm::Crc32)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| Error::s3(format!("sending part {number}"), &e))?;
        self.progress.add(len);
        Ok(CompletedPart::builder()
            .part_number(number)
            .set_e_tag(part.e_tag)
            .set_checksum_crc32(part.checksum_crc32)
            .build())
    }

    async fn complete(
        &self,
        to: &Object,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<(), Error> {
        let _permit = self.permit().await;
        to.client
            .complete_multipart_upload()
            .bucket(&to.bucket)
            .key(&to.key)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .await
            .map_err(|e| Error::s3("completing the upload", &e))?;
        Ok(())
    }

    /// An unfinished upload of `to`'s key to carry on with, and its parts that match
    /// the file; `None` when there's none (or it can't be looked at: start afresh).
    async fn resumable(
        &self,
        path: &Path,
        parts: &[Range<u64>],
        to: &Object,
    ) -> Option<(String, BTreeMap<i32, CompletedPart>)> {
        let uploads = {
            let _permit = self.permit().await;
            to.client
                .list_multipart_uploads()
                .bucket(&to.bucket)
                .prefix(&to.key)
                .send()
                .await
                .ok()?
        };
        let upload_id = uploads
            .uploads()
            .iter()
            .filter(|u| u.key() == Some(to.key.as_str()))
            .max_by_key(|u| u.initiated().map(|t| (t.secs(), t.subsec_nanos())))?
            .upload_id()?
            .to_owned();
        let mut listed = to
            .client
            .list_parts()
            .bucket(&to.bucket)
            .key(&to.key)
            .upload_id(&upload_id)
            .into_paginator()
            .items()
            .send();
        let mut done = BTreeMap::new();
        while let Some(part) = listed.next().await {
            let part = part.ok()?;
            // Parts sent without a CRC32 can't join an upload that has them.
            let (Some(number), Some(etag), Some(crc)) =
                (part.part_number(), part.e_tag(), part.checksum_crc32())
            else {
                return None;
            };
            let Some(range) = usize::try_from(number - 1).ok().and_then(|i| parts.get(i)) else {
                continue;
            };
            let same_size = part
                .size()
                .and_then(|s| u64::try_from(s).ok())
                .is_some_and(|s| s == range.end - range.start);
            if same_size && md5_of(path, range.clone()).await.ok()? == etag.trim_matches('"') {
                done.insert(
                    number,
                    CompletedPart::builder()
                        .part_number(number)
                        .e_tag(etag)
                        .checksum_crc32(crc)
                        .build(),
                );
            }
        }
        if !done.is_empty() {
            crate::ui::note(format!(
                "Resuming the upload of {}: {} of {} parts are already there.",
                to.name,
                done.len(),
                parts.len()
            ));
        }
        Some((upload_id, done))
    }

    /// Downloads `from` (described by `head`) to the local file `dest`, replacing it
    /// only once the whole object is here; its modification time becomes the object's.
    pub async fn download(&self, from: &Object, head: &Head, dest: &Path) -> Result<(), Error> {
        let what = || format!("can't download {} to {}", from.name, dest.display());
        let local = |e: &dyn std::fmt::Display| Error::general(format!("{}: {e}", what()));
        if let Some(dir) = dest.parent().filter(|d| !d.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|e| local(&e))?;
        }
        let partial = partial_path(dest);
        let result = async {
            let file = tokio::fs::File::create(&partial)
                .await
                .map_err(|e| local(&e))?;
            if head.size <= self.part_size {
                let _permit = self.permit().await;
                let got = from
                    .client
                    .get_object()
                    .bucket(&from.bucket)
                    .key(&from.key)
                    .set_version_id(from.version_id.clone())
                    .set_if_match(head.etag.clone())
                    .checksum_mode(ChecksumMode::Enabled)
                    .send()
                    .await
                    .map_err(|e| Error::s3(what(), &e))?;
                write_body(file, got.body, head.size, &self.progress)
                    .await
                    .map_err(|e| local(&e))?;
            } else {
                file.set_len(head.size).await.map_err(|e| local(&e))?;
                drop(file);
                let parts = ranges(head.size, part_size(head.size, self.part_size));
                stream::iter(parts)
                    .map(|range| {
                        let partial = &partial;
                        async move {
                            let body = self.get_range(from, head, range.clone()).await?;
                            let mut file = tokio::fs::OpenOptions::new()
                                .write(true)
                                .open(partial)
                                .await
                                .map_err(|e| local(&e))?;
                            file.seek(std::io::SeekFrom::Start(range.start))
                                .await
                                .map_err(|e| local(&e))?;
                            write_body(file, body, range.end - range.start, &self.progress)
                                .await
                                .map_err(|e| local(&e))
                        }
                    })
                    .buffer_unordered(self.parallel)
                    .try_collect::<()>()
                    .await?;
            }
            if let Some(modified) = head.modified {
                let file = std::fs::File::options()
                    .write(true)
                    .open(&partial)
                    .map_err(|e| local(&e))?;
                file.set_modified(modified).map_err(|e| local(&e))?;
            }
            tokio::fs::rename(&partial, dest)
                .await
                .map_err(|e| local(&e))
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&partial).await;
        }
        result
    }

    /// Bytes `range` of `from`, as long as it's still the object `head` describes.
    async fn get_range(
        &self,
        from: &Object,
        head: &Head,
        range: Range<u64>,
    ) -> Result<ByteStream, Error> {
        let _permit = self.permit().await;
        let got = from
            .client
            .get_object()
            .bucket(&from.bucket)
            .key(&from.key)
            .set_version_id(from.version_id.clone())
            .range(format!("bytes={}-{}", range.start, range.end - 1))
            .set_if_match(head.etag.clone())
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't read {}", from.name), &e))?;
        Ok(got.body)
    }

    /// Copies `from` (described by `head`) to `to`. At one endpoint with the same keys
    /// the server copies it itself; otherwise the bytes pass through here.
    pub async fn copy(&self, from: &Object, head: &Head, to: &Object) -> Result<(), Error> {
        let what = || format!("can't copy {} to {}", from.name, to.name);
        let server_side = from.endpoint == to.endpoint;
        if server_side && from.bucket == to.bucket && from.key == to.key {
            return Err(Error::usage(format!("{}: it's the same object", what())));
        }
        if server_side && head.size <= MAX_PART {
            let _permit = self.permit().await;
            to.client
                .copy_object()
                .bucket(&to.bucket)
                .key(&to.key)
                .copy_source(copy_source(from))
                .set_copy_source_if_match(head.etag.clone())
                .metadata_directive(MetadataDirective::Copy)
                .send()
                .await
                .map_err(|e| Error::s3(what(), &e))?;
            self.progress.add(head.size);
            return Ok(());
        }
        // The object's type and metadata go too: they need a HEAD.
        let fresh;
        let head = if head.output.is_none() {
            fresh = from.head().await?;
            &fresh
        } else {
            head
        };
        let details = head.output.as_ref();
        let content_type = details.and_then(|o| o.content_type().map(str::to_owned));
        let metadata = details.and_then(|o| o.metadata().cloned());
        if !server_side && head.size <= self.part_size {
            let body = self.get_whole(from, head).await?;
            let _permit = self.permit().await;
            to.client
                .put_object()
                .bucket(&to.bucket)
                .key(&to.key)
                .set_content_type(content_type)
                .set_metadata(metadata)
                .body(ByteStream::from(body))
                .send()
                .await
                .map_err(|e| Error::s3(what(), &e))?;
            self.progress.add(head.size);
            return Ok(());
        }
        let upload_id = self
            .start_upload(to, content_type, metadata, false)
            .await
            .map_err(|e| e.within(what()))?;
        let result = self
            .copy_parts(from, head, to, &upload_id, server_side)
            .await;
        if result.is_err() {
            // Nothing here can resume a copy: don't leave its parts behind.
            let _ = to
                .client
                .abort_multipart_upload()
                .bucket(&to.bucket)
                .key(&to.key)
                .upload_id(&upload_id)
                .send()
                .await;
        }
        result.map_err(|e| e.within(what()))
    }

    /// Copies `from` into the multipart upload `upload_id` of `to`, part by part, and
    /// completes it.
    async fn copy_parts(
        &self,
        from: &Object,
        head: &Head,
        to: &Object,
        upload_id: &str,
        server_side: bool,
    ) -> Result<(), Error> {
        let part = part_size(
            head.size,
            if server_side {
                COPY_PART
            } else {
                self.part_size
            },
        );
        let mut parts = stream::iter(ranges(head.size, part).into_iter().zip(1..))
            .map(|(range, number)| async move {
                let len = range.end - range.start;
                let etag = if server_side {
                    let _permit = self.permit().await;
                    to.client
                        .upload_part_copy()
                        .bucket(&to.bucket)
                        .key(&to.key)
                        .upload_id(upload_id)
                        .part_number(number)
                        .copy_source(copy_source(from))
                        .copy_source_range(format!("bytes={}-{}", range.start, range.end - 1))
                        .set_copy_source_if_match(head.etag.clone())
                        .send()
                        .await
                        .map_err(|e| Error::s3("a part", &e))?
                        .copy_part_result
                        .and_then(|r| r.e_tag)
                } else {
                    let body = self
                        .get_range(from, head, range)
                        .await?
                        .collect()
                        .await
                        .map_err(|e| Error::new(Kind::Network, format!("a part: {e}")))?
                        .into_bytes();
                    let _permit = self.permit().await;
                    to.client
                        .upload_part()
                        .bucket(&to.bucket)
                        .key(&to.key)
                        .upload_id(upload_id)
                        .part_number(number)
                        .body(ByteStream::from(body))
                        .send()
                        .await
                        .map_err(|e| Error::s3("a part", &e))?
                        .e_tag
                };
                self.progress.add(len);
                Ok::<_, Error>(
                    CompletedPart::builder()
                        .part_number(number)
                        .set_e_tag(etag)
                        .build(),
                )
            })
            .buffer_unordered(self.parallel)
            .try_collect::<Vec<_>>()
            .await?;
        parts.sort_by_key(CompletedPart::part_number);
        self.complete(to, upload_id, parts).await
    }

    /// Starts a multipart upload to `to`; its id.
    async fn start_upload(
        &self,
        to: &Object,
        content_type: Option<String>,
        metadata: Option<std::collections::HashMap<String, String>>,
        crc32: bool,
    ) -> Result<String, Error> {
        let _permit = self.permit().await;
        let created = to
            .client
            .create_multipart_upload()
            .bucket(&to.bucket)
            .key(&to.key)
            .set_content_type(content_type)
            .set_metadata(metadata)
            .set_checksum_algorithm(crc32.then_some(ChecksumAlgorithm::Crc32))
            .send()
            .await
            .map_err(|e| Error::s3("starting the upload", &e))?;
        created
            .upload_id()
            .map(str::to_owned)
            .ok_or_else(|| Error::general("the endpoint gave no upload id"))
    }

    /// The whole of a small object, as long as it's still the one `head` describes.
    async fn get_whole(&self, from: &Object, head: &Head) -> Result<Bytes, Error> {
        let _permit = self.permit().await;
        let got = from
            .client
            .get_object()
            .bucket(&from.bucket)
            .key(&from.key)
            .set_version_id(from.version_id.clone())
            .set_if_match(head.etag.clone())
            .checksum_mode(ChecksumMode::Enabled)
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't read {}", from.name), &e))?;
        Ok(got
            .body
            .collect()
            .await
            .map_err(|e| Error::general(format!("can't read {}: {e}", from.name)))?
            .into_bytes())
    }
}

/// A failed part: the upload stays, so the same command can carry on from it.
/// The size of a stream's part `number` (from 1): `part_size`, doubling after every
/// 1,000 parts, at most S3's largest part.
fn stream_part_size(part_size: u64, number: u64) -> u64 {
    let doublings = u32::try_from((number - 1) / STREAM_PARTS_PER_SIZE).unwrap_or(u32::MAX);
    part_size
        .checked_shl(doublings)
        .map_or(MAX_PART, |size| size.min(MAX_PART))
}

/// Up to `limit` bytes of `input`: fewer only at its end.
async fn read_part(input: &mut (impl AsyncRead + Unpin), limit: u64) -> std::io::Result<Bytes> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut part = bytes::BytesMut::with_capacity(limit);
    while part.len() < limit {
        if input.read_buf(&mut part).await? == 0 {
            break;
        }
    }
    Ok(part.freeze())
}

/// A finished part's result, or its task's panic passed on.
fn joined(
    result: Option<Result<Result<CompletedPart, Error>, tokio::task::JoinError>>,
) -> Result<CompletedPart, Error> {
    match result.expect("a part is running") {
        Ok(result) => result,
        Err(err) => std::panic::resume_unwind(err.into_panic()),
    }
}

fn resumable_failure(err: Error) -> Error {
    err.with_hint("the parts sent so far are kept: run the same command again to resume")
}

/// Where a download is written until it's complete: a hidden file beside it.
fn partial_path(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map_or_else(|| "download".into(), |n| n.to_string_lossy());
    dest.with_file_name(format!(".{name}.teifs-partial"))
}

/// Writes all of `body` to `file`, which must come to `expected` bytes.
async fn write_body(
    mut file: tokio::fs::File,
    mut body: ByteStream,
    expected: u64,
    progress: &Progress,
) -> Result<(), String> {
    let mut written = 0u64;
    while let Some(chunk) = body.try_next().await.map_err(|e| e.to_string())? {
        file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        written += chunk.len() as u64;
        progress.add(chunk.len() as u64);
    }
    file.flush().await.map_err(|e| e.to_string())?;
    if written == expected {
        Ok(())
    } else {
        Err(format!(
            "the connection ended after {written} of {expected} bytes"
        ))
    }
}

/// The MD5 of bytes `range` of the file at `path`, in hex (a single part's ETag).
async fn md5_of(path: &Path, range: Range<u64>) -> std::io::Result<String> {
    use md5::Digest;
    use std::io::{Read, Seek};
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(path)?;
        file.seek(std::io::SeekFrom::Start(range.start))?;
        let mut limited = file.take(range.end - range.start);
        let mut hasher = md5::Md5::new();
        let mut buf = vec![0; 256 * 1024];
        loop {
            let n = limited.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex(&hasher.finalize()))
    })
    .await
    .map_err(std::io::Error::other)?
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `bucket/key` for `x-amz-copy-source`, with the key percent-encoded (keeping `/`),
/// and `?versionId=` when it names a version.
fn copy_source(from: &Object) -> String {
    let mut out = format!("{}/", from.bucket);
    percent_encode(&mut out, &from.key, b"-_.~/");
    if let Some(version) = &from.version_id {
        // Encoded too: a version id from another service could hold anything.
        out.push_str("?versionId=");
        percent_encode(&mut out, version, b"-_.~");
    }
    out
}

/// Appends `text` percent-encoded, keeping letters, digits and the bytes in `keep`.
fn percent_encode(out: &mut String, text: &str, keep: &[u8]) {
    use std::fmt::Write;
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || keep.contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_sizes_stay_within_s3s_limits() {
        assert_eq!(part_size(100 * MIB, 8 * MIB), 8 * MIB);
        // 1 TiB in 8 MiB parts would be 131,072 parts: parts grow to fit 10,000.
        let tib = 1024 * GIB;
        let part = part_size(tib, 8 * MIB);
        assert!(tib.div_ceil(part) <= MAX_PARTS);
        assert_eq!(part % MIB, 0);
        // S3's largest object.
        assert!((5 * tib).div_ceil(part_size(5 * tib, MIN_PART)) <= MAX_PARTS);
        assert!(part_size(5 * tib, MIN_PART) <= MAX_PART);
    }

    #[test]
    fn ranges_cover_every_byte_once() {
        assert_eq!(ranges(10, 4), vec![0..4, 4..8, 8..10]);
        assert_eq!(ranges(8, 4), vec![0..4, 4..8]);
        assert!(ranges(0, 4).is_empty());
    }

    #[test]
    fn part_sizes_parse_with_units() {
        assert_eq!(parse_part_size("8MiB"), Ok(8 * MIB));
        assert_eq!(parse_part_size("16M"), Ok(16 * MIB));
        assert_eq!(parse_part_size("1 GiB"), Ok(GIB));
        assert_eq!(parse_part_size("5242880"), Ok(5 * MIB));
        for bad in ["", "4MiB", "6GiB", "8MB", "x", "99999999999999999999G"] {
            assert!(parse_part_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn copy_sources_are_percent_encoded_but_keep_slashes() {
        let client = Client::from_conf(
            aws_sdk_s3::Config::builder()
                .behavior_version_latest()
                .build(),
        );
        let mut from = Object {
            client,
            bucket: "b".into(),
            key: "a/b c+ü?.txt".into(),
            name: String::new(),
            endpoint: (String::new(), String::new()),
            version_id: None,
        };
        assert_eq!(copy_source(&from), "b/a/b%20c%2B%C3%BC%3F.txt");
        from.version_id = Some("v 1/&".into());
        assert_eq!(
            copy_source(&from),
            "b/a/b%20c%2B%C3%BC%3F.txt?versionId=v%201%2F%26"
        );
    }

    #[test]
    fn partial_downloads_are_hidden_beside_the_file() {
        assert_eq!(
            partial_path(Path::new("dir/cat.jpg")),
            Path::new("dir/.cat.jpg.teifs-partial")
        );
    }

    #[tokio::test]
    async fn md5s_cover_exactly_the_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"hello world").unwrap();
        // MD5("world")
        assert_eq!(
            md5_of(&path, 6..11).await.unwrap(),
            "7d793037a0760186574b0282f2f435e7"
        );
    }
}
