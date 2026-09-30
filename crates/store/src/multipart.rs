//! Multipart uploads: parts wait in `.teifs/uploads/<id>/`, and completing the upload
//! joins them into one staged file that's committed like any other write.

use std::{collections::BTreeMap, fs, io, time::Duration, time::SystemTime};

use serde::{Deserialize, Serialize};
use teifs_meta::{CompletedUpload, Part, Upload};
use teifs_types::{ChecksumType, PartInfo, UploadChecksum, md5_of_etag, multipart_etag};

use teifs_types::SseMode;

use crate::{
    Bucket, CustomerKey, Encryption, Inner, ObjectInfo, Precondition, Staged, Store, StoreError,
    error::Result,
    now_ms,
    objects::Finished,
    sse::{self, Crypt, Keyed},
    staged::TmpFile,
};

/// The highest part number S3 allows.
pub const MAX_PART_NUMBER: u32 = 10_000;
/// The smallest a part other than the last may be.
pub const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
/// How long a completed upload's answer is kept for retried Completes.
const COMPLETED_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// What completing an upload records beyond its parts.
#[derive(Debug, Default)]
pub struct CompleteWith {
    /// The object's checksums, worked out from its parts.
    pub checksums: BTreeMap<String, String>,
    /// What they cover.
    pub checksum_type: Option<ChecksumType>,
    /// SSE-C: the customer's key, needed to seal the checksums.
    pub customer: Option<CustomerKey>,
}

/// What a completed upload answered (`completed_uploads.result`, JSON).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompletedResult {
    etag: String,
    size: u64,
    modified_ms: i64,
    #[serde(default)]
    checksums: BTreeMap<String, String>,
    #[serde(default)]
    checksum_type: Option<ChecksumType>,
    #[serde(default)]
    crypt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
}

impl Store {
    /// Starts a multipart upload to `bucket`/`key`, encrypted as `encryption` asks, whose
    /// object gets `checksum` and may be at most `max_size` bytes, all parts together.
    #[allow(
        clippy::too_many_arguments,
        reason = "each is one of S3's upload settings"
    )]
    pub async fn create_upload(
        &self,
        bucket: &str,
        key: &str,
        attrs: crate::ObjectAttrs,
        owner: Option<String>,
        encryption: &Encryption,
        checksum: Option<&UploadChecksum>,
        max_size: Option<u64>,
    ) -> Result<Upload> {
        let crypt = match encryption {
            Encryption::None => None,
            encryption => {
                let bucket_id = self.object_bucket_id(bucket).await?;
                let object_id = uuid::Uuid::now_v7().simple().to_string();
                let keyed = sse::new_key(
                    self.kms(),
                    encryption,
                    &self.inner.format.drive,
                    &bucket_id,
                    &object_id,
                )
                .await?
                .ok_or(StoreError::InvalidRequest("no encryption was asked for"))?;
                Some(serde_json::to_string(&keyed.crypt).expect("crypt serializes"))
            }
        };
        let upload = Upload {
            id: uuid::Uuid::new_v4().simple().to_string(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            owner,
            attrs,
            created_ms: now_ms(),
            crypt,
            checksum: checksum.map(|c| serde_json::to_string(c).expect("checksum serializes")),
            max_size,
        };
        self.blocking(move |inner| {
            let bucket = inner.bucket(&upload.bucket)?;
            // A lock the bucket can't give is refused now, not when the upload completes
            // (which applies the bucket's default retention then).
            inner.lock_new_version(bucket.versions(), &mut upload.attrs.clone())?;
            match bucket {
                crate::Bucket::Folder(..) => {
                    if inner.new_key(&upload.key)?.is_folder() {
                        return Err(StoreError::InvalidRequest(
                            "a folder (a key ending in `/`) can't be uploaded in parts",
                        ));
                    }
                }
                crate::Bucket::Object(_) => teifs_types::check_object_key(&upload.key)?,
            }
            fs::create_dir(inner.uploads.join(&upload.id))?;
            inner.lock().insert_upload(&upload)?;
            Ok(upload)
        })
        .await
    }

    /// An upload in progress.
    pub async fn upload(&self, id: &str) -> Result<Upload> {
        let id = id.to_owned();
        self.blocking(move |inner| {
            inner
                .lock()
                .get_upload(&id)?
                .ok_or(StoreError::NoSuchUpload)
        })
        .await
    }

    /// Starts writing part `number` of an upload: encrypted with the upload's data key
    /// when the upload is encrypted (SSE-C uploads need the customer's key for every
    /// part, as in S3).
    pub async fn stage_part(
        &self,
        id: &str,
        number: u32,
        customer: Option<&CustomerKey>,
    ) -> Result<Staged> {
        let upload = self.upload(id).await?;
        let Some(json) = upload.crypt.as_deref() else {
            if customer.is_some() {
                return Err(StoreError::CustomerKeyNotApplicable);
            }
            return self.stage().await;
        };
        let crypt: Crypt = serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata)?;
        let bucket_id = self.object_bucket_id(&upload.bucket).await?;
        let data_key = sse::data_key(
            self.kms(),
            &crypt,
            &self.inner.format.drive,
            &bucket_id,
            customer,
        )
        .await?;
        let outer =
            sse::outer_key(self.kms(), &crypt, &self.inner.format.drive, &bucket_id).await?;
        let keyed = Keyed {
            data_key,
            outer,
            crypt,
        };
        Staged::create_sealed(&self.inner.tmp, keyed, bucket_id, number).await
    }

    /// How many bytes part `number` of an upload may have: what its size cap leaves
    /// beside its other parts (a part being replaced doesn't count), or `None` without a
    /// cap. Parts are checked again when stored.
    pub async fn part_room(&self, upload: &Upload, number: u32) -> Result<Option<u64>> {
        let Some(max) = upload.max_size else {
            return Ok(None);
        };
        let id = upload.id.clone();
        let others = self
            .blocking(move |inner| Ok(inner.lock().parts_size(&id, number)?))
            .await?;
        Ok(Some(max.saturating_sub(others)))
    }

    /// The checksum an upload's object will get, if any.
    #[must_use]
    pub fn upload_checksum(upload: &Upload) -> Option<UploadChecksum> {
        serde_json::from_str(upload.checksum.as_deref()?).ok()
    }

    /// How an upload's object will be encrypted, as S3 reports it.
    #[must_use]
    pub fn upload_encryption(&self, upload: &Upload) -> Option<teifs_types::SseInfo> {
        let crypt: Crypt = serde_json::from_str(upload.crypt.as_deref()?).ok()?;
        Some(crypt.info(None))
    }

    /// The id of an object bucket; folder buckets can't hold encrypted objects.
    pub(crate) async fn object_bucket_id(&self, bucket: &str) -> Result<String> {
        let name = bucket.to_owned();
        self.blocking(move |inner| match inner.bucket(&name)? {
            Bucket::Object(bucket) => Ok(bucket.id),
            Bucket::Folder(..) => Err(StoreError::InvalidRequest(
                "encryption at rest needs an object bucket",
            )),
        })
        .await
    }

    /// Stores a part (replacing one with the same number).
    pub async fn put_part(
        &self,
        id: &str,
        number: u32,
        mut staged: Staged,
        checksums: BTreeMap<String, String>,
    ) -> Result<Part> {
        if !(1..=MAX_PART_NUMBER).contains(&number) {
            return Err(StoreError::InvalidRequest(
                "part numbers go from 1 to 10,000",
            ));
        }
        staged.finish().await?;
        let id = id.to_owned();
        self.blocking(move |inner| {
            let conn = inner.lock();
            let upload = conn.get_upload(&id)?.ok_or(StoreError::NoSuchUpload)?;
            let md5 = staged.md5();
            let mut checksums = checksums;
            let etag = match (&upload.crypt, staged.sealing()) {
                (None, None) => teifs_types::hex(&md5),
                (Some(json), Some(sealing)) => {
                    let crypt: Crypt =
                        serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata)?;
                    if sealing.keyed.crypt.object != crypt.object || sealing.part != number {
                        return Err(StoreError::InvalidRequest(
                            "the part was encrypted for another upload or part",
                        ));
                    }
                    if crypt.mode == SseMode::S3 {
                        teifs_types::hex(&md5)
                    } else {
                        let key = &sealing.keyed.data_key;
                        checksums = sse::part_sums(Some(key), checksums);
                        teifs_types::hex(&key.etag_for(&md5))
                    }
                }
                _ => {
                    return Err(StoreError::InvalidRequest(
                        "the part's encryption doesn't match the upload's",
                    ));
                }
            };
            let dir = inner.uploads.join(&id);
            let size = staged.size();
            // Checked under the lock, so parts sent at once can't add up past the cap.
            if let Some(max) = upload.max_size
                && conn.parts_size(&id, number)?.saturating_add(size) > max
            {
                return Err(StoreError::EntityTooLarge);
            }
            // An acknowledged part must survive a power cut.
            inner.sync_file(staged.path())?;
            fs::rename(staged.path(), dir.join(number.to_string()))?;
            staged.keep();
            inner.sync_folder(&dir)?;
            let part = Part {
                number,
                size,
                etag,
                checksums,
                modified_ms: now_ms(),
            };
            conn.put_part(&id, &part)?;
            Ok(part)
        })
        .await
    }

    /// Parts of an upload numbered above `after`, at most `limit` of them. Checksums
    /// sealed under SSE-KMS are opened; under SSE-C only with the customer's key, else
    /// they're left out.
    pub async fn parts(
        &self,
        id: &str,
        after: u32,
        limit: usize,
        customer: Option<&CustomerKey>,
    ) -> Result<Vec<Part>> {
        let id = id.to_owned();
        let (upload, parts) = self
            .blocking(move |inner| {
                let conn = inner.lock();
                let upload = conn.get_upload(&id)?.ok_or(StoreError::NoSuchUpload)?;
                let parts = conn.list_parts(&id, after, limit)?;
                Ok((upload, parts))
            })
            .await?;
        let sealed = parts.iter().any(|p| p.checksums.contains_key(sse::SEALED));
        let key = match upload.crypt.as_deref() {
            Some(json) if sealed => {
                let crypt: Crypt =
                    serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata)?;
                if crypt.mode == SseMode::Customer && customer.is_none() {
                    None
                } else {
                    let bucket_id = self.object_bucket_id(&upload.bucket).await?;
                    Some(
                        sse::data_key(
                            self.kms(),
                            &crypt,
                            &self.inner.format.drive,
                            &bucket_id,
                            customer,
                        )
                        .await?,
                    )
                }
            }
            _ => None,
        };
        parts
            .into_iter()
            .map(|mut part| {
                part.checksums = sse::open_part_sums(key.as_ref(), part.checksums)?;
                Ok(part)
            })
            .collect()
    }

    /// What completing upload `id` to `bucket`/`key` answered, if it completed recently.
    pub async fn completed(&self, id: &str, bucket: &str, key: &str) -> Result<Option<ObjectInfo>> {
        let (id, bucket, key) = (id.to_owned(), bucket.to_owned(), key.to_owned());
        self.blocking(move |inner| {
            let Some(done) = inner.lock().completed_upload(&id)? else {
                return Ok(None);
            };
            if done.bucket != bucket || done.key != key {
                return Ok(None);
            }
            let result: CompletedResult =
                serde_json::from_str(&done.result).map_err(|_| StoreError::CorruptMetadata)?;
            let sse = match result.crypt.as_deref() {
                Some(json) => Some(
                    serde_json::from_str::<Crypt>(json)
                        .map_err(|_| StoreError::CorruptMetadata)?
                        .info(None),
                ),
                None => None,
            };
            Ok(Some(ObjectInfo {
                key,
                size: result.size,
                modified: SystemTime::UNIX_EPOCH
                    + Duration::from_millis(u64::try_from(result.modified_ms).unwrap_or(0)),
                etag: result.etag,
                attrs: crate::ObjectAttrs {
                    checksums: result.checksums,
                    checksum_type: result.checksum_type,
                    ..crate::ObjectAttrs::default()
                },
                sse,
                parts: Vec::new(),
                version_id: result.version_id,
            }))
        })
        .await
    }

    /// Uploads in progress in a bucket, by key then id, after `(key, id)`.
    pub async fn uploads(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<(String, String)>,
        limit: usize,
    ) -> Result<Vec<Upload>> {
        let (bucket, prefix) = (bucket.to_owned(), prefix.to_owned());
        self.blocking(move |inner| {
            inner.bucket(&bucket)?;
            let after = after.as_ref().map(|(k, i)| (k.as_str(), i.as_str()));
            Ok(inner.lock().list_uploads(&bucket, &prefix, after, limit)?)
        })
        .await
    }

    /// Joins the listed parts, in order, into the object, with the checksums in `with`.
    pub async fn complete(
        &self,
        id: &str,
        listed: Vec<(u32, String)>,
        precondition: Precondition,
        with: CompleteWith,
    ) -> Result<ObjectInfo> {
        let upload = self.upload(id).await?;
        let checksum_type = with.checksum_type;
        let (crypt, checksums) = self.seal_object_sums(&upload, with).await?;
        let id = id.to_owned();
        self.blocking(move |inner| {
            let upload = inner
                .lock()
                .get_upload(&id)?
                .ok_or(StoreError::NoSuchUpload)?;
            if listed.is_empty() {
                return Err(StoreError::InvalidPart);
            }
            if listed.windows(2).any(|w| w[0].0 >= w[1].0) {
                return Err(StoreError::InvalidPartOrder);
            }
            let (tmp, parts, md5s) = inner.join_parts(&id, &upload.bucket, &listed)?;

            let conn = inner.lock();
            // Aborted while the parts were being joined: the upload no longer exists.
            if conn.get_upload(&id)?.is_none() {
                return Err(StoreError::NoSuchUpload);
            }
            let bucket = inner.bucket(&upload.bucket)?;
            let stored_len = fs::metadata(&tmp.path)?.len();
            let size: u64 = parts.iter().map(|p| p.size).sum();
            if upload.max_size.is_some_and(|max| size > max) {
                return Err(StoreError::EntityTooLarge);
            }
            // Parts' checksums are already sealed under SSE-KMS and SSE-C (see put_part).
            let sealed = crypt.map(|crypt| (crypt.object.clone(), crypt));
            let attrs = crate::ObjectAttrs {
                checksums,
                checksum_type,
                ..upload.attrs.clone()
            };
            let finished = Finished {
                stored_len,
                sealed,
                parts: Some(parts),
                ..Finished::plain(&tmp.path, size, multipart_etag(&md5s), attrs)
            };
            let info = inner.commit_to(&conn, &bucket, &upload.key, finished, &precondition)?;
            tmp.keep();
            let result = CompletedResult {
                etag: info.etag.clone(),
                size: info.size,
                modified_ms: now_ms(),
                checksums: info.attrs.checksums.clone(),
                checksum_type: info.attrs.checksum_type,
                crypt: upload.crypt.clone(),
                version_id: info.version_id.clone(),
            };
            let now = now_ms();
            conn.record_completed(
                &id,
                &CompletedUpload {
                    bucket: upload.bucket.clone(),
                    key: upload.key.clone(),
                    result: serde_json::to_string(&result).expect("result serializes"),
                },
                now,
                now - COMPLETED_TTL_MS,
            )?;
            conn.delete_upload(&id)?;
            drop(conn);
            let _ = fs::remove_dir_all(inner.uploads.join(&id));
            Ok(info)
        })
        .await
    }

    /// An upload's encryption record, with the object's checksums sealed into it under
    /// SSE-KMS and SSE-C (then none are left in the clear), and the clear checksums.
    async fn seal_object_sums(
        &self,
        upload: &Upload,
        with: CompleteWith,
    ) -> Result<(Option<Crypt>, BTreeMap<String, String>)> {
        let mut checksums = with.checksums;
        let Some(json) = upload.crypt.as_deref() else {
            return Ok((None, checksums));
        };
        let mut crypt: Crypt =
            serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata)?;
        if crypt.mode != SseMode::S3 && !checksums.is_empty() {
            let bucket_id = self.object_bucket_id(&upload.bucket).await?;
            let key = sse::data_key(
                self.kms(),
                &crypt,
                &self.inner.format.drive,
                &bucket_id,
                with.customer.as_ref(),
            )
            .await?;
            crypt.checksums = Some(sse::seal_sums(&key, &checksums));
            checksums.clear();
        }
        Ok((Some(crypt), checksums))
    }

    /// Abandons an upload and its parts.
    pub async fn abort(&self, id: &str) -> Result<()> {
        let id = id.to_owned();
        self.blocking(move |inner| inner.abort_upload(&id)).await
    }
}

impl Inner {
    /// Joins an upload's listed parts, in order, into one staged file: it, the parts, and
    /// their MD5s (for the multipart ETag). Checks each part is there with its ETag and,
    /// but for the last, big enough, and that the object fits on the disk.
    fn join_parts(
        &self,
        id: &str,
        bucket: &str,
        listed: &[(u32, String)],
    ) -> Result<(TmpFile, Vec<PartInfo>, Vec<[u8; 16]>)> {
        let stored: BTreeMap<u32, Part> = self
            .lock()
            .list_parts(id, 0, usize::MAX)?
            .into_iter()
            .map(|part| (part.number, part))
            .collect();
        // Joining the parts writes the object again: it must fit.
        let total = listed
            .iter()
            .filter_map(|(number, _)| stored.get(number))
            .map(|part| part.size)
            .sum();
        self.ensure_space(bucket, total)?;
        let dir = self.uploads.join(id);
        let tmp = TmpFile::new(&self.tmp);
        let mut out = fs::File::create(&tmp.path)?;
        let mut md5s = Vec::with_capacity(listed.len());
        let mut parts = Vec::with_capacity(listed.len());
        for (index, (number, etag)) in listed.iter().enumerate() {
            let part = stored
                .get(number)
                .filter(|p| p.etag == etag.trim_matches('"'))
                .ok_or(StoreError::InvalidPart)?;
            if index + 1 < listed.len() && part.size < MIN_PART_SIZE {
                return Err(StoreError::EntityTooSmall);
            }
            md5s.push(md5_of_etag(&part.etag).ok_or(StoreError::InvalidPart)?);
            parts.push(PartInfo {
                size: part.size,
                checksums: part.checksums.clone(),
            });
            let mut source =
                fs::File::open(dir.join(number.to_string())).map_err(|e| match e.kind() {
                    io::ErrorKind::NotFound => StoreError::InvalidPart,
                    _ => e.into(),
                })?;
            io::copy(&mut source, &mut out)?;
        }
        Ok((tmp, parts, md5s))
    }

    /// Forgets an upload, then removes its parts.
    pub(crate) fn abort_upload(&self, id: &str) -> Result<()> {
        let conn = self.lock();
        if conn.get_upload(id)?.is_none() {
            return Err(StoreError::NoSuchUpload);
        }
        conn.delete_upload(id)?;
        drop(conn);
        match fs::remove_dir_all(self.uploads.join(id)) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err.into()),
            _ => Ok(()),
        }
    }
}
