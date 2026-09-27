//! Multipart uploads: parts wait in `.teifs/uploads/<id>/`, and completing the upload
//! joins them into one staged file that's committed like any other write.

use std::{collections::BTreeMap, fs, io};

use teifs_meta::{Part, Upload};
use teifs_types::{md5_of_etag, multipart_etag};

use teifs_types::SseMode;

use crate::{
    Bucket, CustomerKey, Encryption, ObjectInfo, ObjectKey, Precondition, Staged, Store,
    StoreError,
    error::Result,
    now_ms,
    objects::Finished,
    sse::{self, Crypt, Keyed},
    staged::{TmpFile, sync_dir},
};

/// The highest part number S3 allows.
pub const MAX_PART_NUMBER: u32 = 10_000;
/// The smallest a part other than the last may be.
pub const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

impl Store {
    /// Starts a multipart upload to `bucket`/`key`, encrypted as `encryption` asks.
    pub async fn create_upload(
        &self,
        bucket: &str,
        key: &str,
        attrs: crate::ObjectAttrs,
        owner: Option<String>,
        encryption: &Encryption,
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
        };
        self.blocking(move |inner| {
            match inner.bucket(&upload.bucket)? {
                crate::Bucket::Folder(..) => {
                    if ObjectKey::parse(&upload.key)?.is_folder() {
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
        let keyed = Keyed { data_key, crypt };
        Staged::create_sealed(&self.inner.tmp, keyed, bucket_id, number).await
    }

    /// How an upload's object will be encrypted, as S3 reports it.
    #[must_use]
    pub fn upload_encryption(&self, upload: &Upload) -> Option<teifs_types::SseInfo> {
        let crypt: Crypt = serde_json::from_str(upload.crypt.as_deref()?).ok()?;
        Some(crypt.info(None))
    }

    /// The id of an object bucket; folder buckets can't hold encrypted objects.
    async fn object_bucket_id(&self, bucket: &str) -> Result<String> {
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
                    match crypt.mode {
                        SseMode::S3 => teifs_types::hex(&md5),
                        _ => teifs_types::hex(&sealing.keyed.data_key.etag_for(&md5)),
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
            // An acknowledged part must survive a power cut.
            fs::OpenOptions::new()
                .write(true)
                .open(staged.path())?
                .sync_all()?;
            fs::rename(staged.path(), dir.join(number.to_string()))?;
            staged.keep();
            sync_dir(&dir)?;
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

    /// Parts of an upload numbered above `after`, at most `limit` of them.
    pub async fn parts(&self, id: &str, after: u32, limit: usize) -> Result<Vec<Part>> {
        let id = id.to_owned();
        self.blocking(move |inner| {
            let conn = inner.lock();
            if conn.get_upload(&id)?.is_none() {
                return Err(StoreError::NoSuchUpload);
            }
            Ok(conn.list_parts(&id, after, limit)?)
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

    /// Joins the listed parts, in order, into the object.
    pub async fn complete(
        &self,
        id: &str,
        listed: Vec<(u32, String)>,
        precondition: Precondition,
    ) -> Result<ObjectInfo> {
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
            let stored: BTreeMap<u32, Part> = inner
                .lock()
                .list_parts(&id, 0, usize::MAX)?
                .into_iter()
                .map(|part| (part.number, part))
                .collect();

            let dir = inner.uploads.join(&id);
            let tmp = TmpFile::new(&inner.tmp);
            let mut out = fs::File::create(&tmp.path)?;
            let mut md5s = Vec::with_capacity(listed.len());
            let mut sizes = Vec::with_capacity(listed.len());
            for (index, (number, etag)) in listed.iter().enumerate() {
                let part = stored
                    .get(number)
                    .filter(|p| p.etag == etag.trim_matches('"'))
                    .ok_or(StoreError::InvalidPart)?;
                if index + 1 < listed.len() && part.size < MIN_PART_SIZE {
                    return Err(StoreError::EntityTooSmall);
                }
                md5s.push(md5_of_etag(&part.etag).ok_or(StoreError::InvalidPart)?);
                sizes.push(part.size);
                let mut source =
                    fs::File::open(dir.join(number.to_string())).map_err(|e| match e.kind() {
                        io::ErrorKind::NotFound => StoreError::InvalidPart,
                        _ => e.into(),
                    })?;
                io::copy(&mut source, &mut out)?;
            }
            drop(out);

            let conn = inner.lock();
            // Aborted while the parts were being joined: the upload no longer exists.
            if conn.get_upload(&id)?.is_none() {
                return Err(StoreError::NoSuchUpload);
            }
            let bucket = inner.bucket(&upload.bucket)?;
            let stored_len = fs::metadata(&tmp.path)?.len();
            let size = sizes.iter().sum();
            let sealed = match upload.crypt.as_deref() {
                Some(json) => {
                    let crypt: Crypt =
                        serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata)?;
                    Some((crypt.object.clone(), crypt))
                }
                None => None,
            };
            let finished = Finished {
                stored_len,
                sealed,
                parts: Some(sizes),
                ..Finished::plain(&tmp.path, size, multipart_etag(&md5s), upload.attrs.clone())
            };
            let info = inner.commit_to(&conn, &bucket, &upload.key, finished, &precondition)?;
            tmp.keep();
            conn.delete_upload(&id)?;
            drop(conn);
            let _ = fs::remove_dir_all(&dir);
            Ok(info)
        })
        .await
    }

    /// Abandons an upload and its parts.
    pub async fn abort(&self, id: &str) -> Result<()> {
        let id = id.to_owned();
        self.blocking(move |inner| {
            let conn = inner.lock();
            if conn.get_upload(&id)?.is_none() {
                return Err(StoreError::NoSuchUpload);
            }
            conn.delete_upload(&id)?;
            drop(conn);
            match fs::remove_dir_all(inner.uploads.join(&id)) {
                Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err.into()),
                _ => Ok(()),
            }
        })
        .await
    }
}
