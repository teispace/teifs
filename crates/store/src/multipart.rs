//! Multipart uploads: parts wait in `.teifs/uploads/<id>/`, and completing the upload
//! joins them into one staged file that's committed like any other write.

use std::{collections::BTreeMap, fs, io};

use teifs_meta::{Part, Upload};
use teifs_types::{md5_of_etag, multipart_etag};

use crate::{
    ObjectInfo, ObjectKey, Precondition, Staged, Store, StoreError,
    error::Result,
    now_ms,
    staged::{TmpFile, sync_dir},
};

/// The highest part number S3 allows.
pub const MAX_PART_NUMBER: u32 = 10_000;
/// The smallest a part other than the last may be.
pub const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

impl Store {
    /// Starts a multipart upload to `bucket`/`key`.
    pub async fn create_upload(
        &self,
        bucket: &str,
        key: &str,
        attrs: crate::ObjectAttrs,
        owner: Option<String>,
    ) -> Result<Upload> {
        let parsed = ObjectKey::parse(key)?;
        if parsed.is_folder() {
            return Err(StoreError::InvalidRequest(
                "a folder (a key ending in `/`) can't be uploaded in parts",
            ));
        }
        let upload = Upload {
            id: uuid::Uuid::new_v4().simple().to_string(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            owner,
            attrs,
            created_ms: now_ms(),
        };
        self.blocking(move |inner| {
            inner.bucket_dir(&upload.bucket)?;
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
            if conn.get_upload(&id)?.is_none() {
                return Err(StoreError::NoSuchUpload);
            }
            let dir = inner.uploads.join(&id);
            let (size, etag) = (staged.size(), teifs_types::hex(&staged.md5()));
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
            inner.bucket_dir(&bucket)?;
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
            let key = ObjectKey::parse(&upload.key)?;
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
            for (index, (number, etag)) in listed.iter().enumerate() {
                let part = stored
                    .get(number)
                    .filter(|p| p.etag == etag.trim_matches('"'))
                    .ok_or(StoreError::InvalidPart)?;
                if index + 1 < listed.len() && part.size < MIN_PART_SIZE {
                    return Err(StoreError::EntityTooSmall);
                }
                md5s.push(md5_of_etag(&part.etag).ok_or(StoreError::InvalidPart)?);
                let mut source =
                    fs::File::open(dir.join(number.to_string())).map_err(|e| match e.kind() {
                        io::ErrorKind::NotFound => StoreError::InvalidPart,
                        _ => e.into(),
                    })?;
                io::copy(&mut source, &mut out)?;
            }
            out.sync_all()?;
            drop(out);

            let conn = inner.lock();
            // Aborted while the parts were being joined: the upload no longer exists.
            if conn.get_upload(&id)?.is_none() {
                return Err(StoreError::NoSuchUpload);
            }
            let info = inner.commit_file(
                &conn,
                &upload.bucket,
                &key,
                &tmp.path,
                multipart_etag(&md5s),
                upload.attrs.clone(),
                &precondition,
            )?;
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
