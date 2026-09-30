//! Rewrapping: sealing the data keys a KMS key's older versions sealed under its newest,
//! so an old version can be retired (DSSE-KMS's second data key too, when it's the
//! managed key being rewrapped). Only each record's sealed keys change: the data,
//! ETags, dates and checksums stay, and so does each object's mode and Bucket Key.
//! Objects under Object Lock are rewrapped too (nothing about them changes). Running it
//! again carries on: what's done no longer matches.

use std::collections::BTreeMap;

use teifs_crypto::{Context, CryptoError, DataKey, Kms, SealedKey};
use teifs_meta::VersionRow;

use crate::{
    Layout, Store, StoreError,
    error::Result,
    objects::crypt_of,
    sse::{Crypt, Resealed},
};

/// Versions read at a time.
const PAGE: usize = 500;

/// What [`Store::rewrap`] did (or, dry, would do).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rewrapped {
    /// The newest version of the key, which seals them now.
    pub newest: u32,
    /// Object versions sealed again.
    pub versions: u64,
    /// Multipart uploads in progress sealed again.
    pub uploads: u64,
    /// Ones written again meanwhile, left for another run.
    pub changed_meanwhile: u64,
}

impl Store {
    /// Seals the data keys that older versions of the KMS key `kms_key` sealed under its
    /// newest version; with `dry_run`, only counts them.
    pub async fn rewrap(&self, kms_key: &str, dry_run: bool) -> Result<Rewrapped> {
        let kms = self.kms().ok_or(StoreError::NoKms)?;
        let newest = kms
            .keys()
            .await?
            .into_iter()
            .find(|k| k.name == kms_key)
            .ok_or_else(|| CryptoError::NoSuchKey(kms_key.to_owned()))?
            .version;
        let mut done = Rewrapped {
            newest,
            ..Rewrapped::default()
        };
        let names = self.bucket_names().await?;
        let mut after: Option<(String, String, i64)> = None;
        loop {
            let (key, from) = (kms_key.to_owned(), after.clone());
            let page = self
                .blocking(move |inner| {
                    let from = from.as_ref().map(|(b, k, s)| (b.as_str(), k.as_str(), *s));
                    Ok(inner.lock().sealed_before(&key, newest, from, PAGE)?)
                })
                .await?;
            let Some(last) = page.last() else { break };
            after = Some((last.bucket_id.clone(), last.key.clone(), last.seq));
            for row in page {
                // A bucket removed meanwhile took its versions with it.
                let Some(bucket) = names.get(&row.bucket_id) else {
                    continue;
                };
                if dry_run {
                    done.versions += 1;
                    continue;
                }
                match self.rewrap_version(kms, kms_key, newest, bucket, row).await {
                    Ok(()) => done.versions += 1,
                    Err(StoreError::ChangedMeanwhile | StoreError::NoSuchVersion) => {
                        done.changed_meanwhile += 1;
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        self.rewrap_uploads(kms, kms_key, newest, dry_run, &mut done)
            .await?;
        Ok(done)
    }

    /// Object buckets' names, by id.
    async fn bucket_names(&self) -> Result<BTreeMap<String, String>> {
        let mut names = BTreeMap::new();
        for bucket in self.list_buckets().await? {
            if bucket.layout == Layout::Object {
                names.insert(self.object_bucket_id(&bucket.name).await?, bucket.name);
            }
        }
        Ok(names)
    }

    async fn rewrap_version(
        &self,
        kms: &dyn Kms,
        kms_key: &str,
        newest: u32,
        bucket: &str,
        row: VersionRow,
    ) -> Result<()> {
        let crypt = crypt_of(&row)?.ok_or(StoreError::CorruptMetadata)?;
        let context = crypt.context(&self.inner.format.drive, &row.bucket_id);
        let (crypt, data_key) = rewrapped(kms, kms_key, newest, crypt, &context).await?;
        let new = Resealed {
            mode: crypt.mode,
            bucket_key: crypt.bucket_key,
            sealed: crypt.sealed.clone(),
            crypt,
            data_key,
        };
        let key = row.key.clone();
        self.write_resealed(bucket, &key, row, new, false).await
    }

    async fn rewrap_uploads(
        &self,
        kms: &dyn Kms,
        kms_key: &str,
        newest: u32,
        dry_run: bool,
        done: &mut Rewrapped,
    ) -> Result<()> {
        let key = kms_key.to_owned();
        let uploads = self
            .blocking(move |inner| Ok(inner.lock().uploads_sealed_before(&key, newest)?))
            .await?;
        for upload in uploads {
            let Ok(bucket_id) = self.object_bucket_id(&upload.bucket).await else {
                continue;
            };
            if dry_run {
                done.uploads += 1;
                continue;
            }
            let old = upload.crypt.ok_or(StoreError::CorruptMetadata)?;
            let crypt: Crypt =
                serde_json::from_str(&old).map_err(|_| StoreError::CorruptMetadata)?;
            let context = crypt.context(&self.inner.format.drive, &bucket_id);
            let (crypt, _) = rewrapped(kms, kms_key, newest, crypt, &context).await?;
            let new = serde_json::to_string(&crypt).expect("crypt serializes");
            let id = upload.id;
            let replaced = self
                .blocking(move |inner| Ok(inner.lock().replace_upload_crypt(&id, &old, &new)?))
                .await?;
            if replaced {
                done.uploads += 1;
            } else {
                done.changed_meanwhile += 1;
            }
        }
        Ok(())
    }
}

/// `crypt` with each of its sealed keys that an older version of `kms_key` sealed sealed
/// again under the newest, and its data key.
async fn rewrapped(
    kms: &dyn Kms,
    kms_key: &str,
    newest: u32,
    mut crypt: Crypt,
    context: &Context,
) -> Result<(Crypt, DataKey)> {
    let stale = |sealed: &SealedKey| sealed.kms_key == kms_key && sealed.kms_version < newest;
    let data_key = kms.unseal(&crypt.sealed, context).await?;
    if stale(&crypt.sealed) {
        crypt.sealed = kms.seal(Some(kms_key), context, &data_key).await?;
    }
    if let Some(outer) = crypt.outer.as_ref().filter(|o| stale(o)) {
        let context = context.clone().outer();
        let key = kms.unseal(outer, &context).await?;
        crypt.outer = Some(kms.seal(Some(kms_key), &context, &key).await?);
    }
    Ok((crypt, data_key))
}
