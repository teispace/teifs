//! Server-side encryption in the store (`docs/ENCRYPTION_FORMAT.md`): what a write asks
//! for, what's recorded with an encrypted object, and turning either into its data key.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use teifs_crypto::{Context, CustomerKey, DEFAULT_KEY, DataKey, Kms, SealedKey};
use teifs_meta::VersionRow;
use teifs_types::{SseInfo, SseMode, batch::RotateTo};

use crate::{
    Bucket, Inner, Store, StoreError,
    error::Result,
    lock::check_removal,
    now_ms,
    objects::{PartsRecord, crypt_of},
};

/// The encryption a write asks for.
#[derive(Debug, Clone, Default)]
pub enum Encryption {
    /// Stored as sent.
    #[default]
    None,
    /// SSE-S3: sealed by the drive's managed key.
    S3,
    /// SSE-KMS: sealed by a named KMS key (the managed key when `None`), bound to the
    /// client's extra context pairs too.
    Kms {
        /// The KMS key's name.
        key: Option<String>,
        /// Extra context pairs from `x-amz-server-side-encryption-context`.
        context: BTreeMap<String, String>,
        /// Whether it's reported as using an S3 Bucket Key.
        bucket_key: bool,
    },
    /// DSSE-KMS: encrypted twice, under a data key sealed by a named KMS key (the managed
    /// key when `None`) and under a second one sealed by the managed key.
    Dsse {
        /// The KMS key's name.
        key: Option<String>,
        /// Extra context pairs from `x-amz-server-side-encryption-context`.
        context: BTreeMap<String, String>,
    },
    /// SSE-C: sealed by a key derived from the customer's key.
    Customer(CustomerKey),
}

/// What's recorded with an encrypted object (the row's `crypt` column, JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Crypt {
    pub mode: SseMode,
    /// The object id the data key is bound to.
    pub object: String,
    pub sealed: SealedKey,
    /// The client's extra SSE-KMS context pairs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
    /// SSE-C: the salt and the salted HMAC that recognize the customer's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer: Option<CustomerCheck>,
    /// SSE-KMS and SSE-C: the object's checksums, sealed with its data key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksums: Option<String>,
    /// SSE-KMS: whether it's reported as using an S3 Bucket Key.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bucket_key: bool,
    /// DSSE-KMS: the second data key, sealed by the managed key under the context
    /// marked as the outer layer's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outer: Option<SealedKey>,
}

/// What recognizes an SSE-C key without storing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CustomerCheck {
    pub salt: String,
    pub hmac: String,
}

/// An object's data key, ready to encrypt with, and what to record about it.
#[derive(Debug)]
pub(crate) struct Keyed {
    pub data_key: DataKey,
    /// DSSE-KMS's second data key.
    pub outer: Option<DataKey>,
    pub crypt: Crypt,
}

impl Crypt {
    /// The context the data key is sealed under.
    pub fn context(&self, drive: &str, bucket_id: &str) -> Context {
        object_context(drive, bucket_id, &self.object, &self.context)
    }

    /// What S3 reports about it.
    pub fn info(&self, customer_key_md5: Option<String>) -> SseInfo {
        SseInfo {
            mode: self.mode,
            kms_key: matches!(self.mode, SseMode::Kms | SseMode::Dsse)
                .then(|| self.sealed.kms_key.clone()),
            customer_key_md5,
            bucket_key: self.bucket_key,
        }
    }
}

/// The context an object's data key is sealed under: its ids and the client's pairs.
fn object_context(
    drive: &str,
    bucket_id: &str,
    object_id: &str,
    pairs: &BTreeMap<String, String>,
) -> Context {
    pairs.iter().fold(
        Context::object(drive, bucket_id, object_id),
        |ctx, (k, v)| ctx.with(k, v),
    )
}

/// No extra context pairs.
const NO_CONTEXT: &BTreeMap<String, String> = &BTreeMap::new();

/// Creates the data key for a new object `object_id` in bucket `bucket_id`.
pub(crate) async fn new_key(
    kms: Option<&dyn Kms>,
    encryption: &Encryption,
    drive: &str,
    bucket_id: &str,
    object_id: &str,
) -> Result<Option<Keyed>> {
    let (mode, key, context, bucket_key) = match encryption {
        Encryption::None => return Ok(None),
        Encryption::Customer(key) => {
            return Ok(Some(customer_keyed(key, drive, bucket_id, object_id)));
        }
        Encryption::S3 => (SseMode::S3, Some(DEFAULT_KEY), NO_CONTEXT, false),
        Encryption::Kms {
            key,
            context,
            bucket_key,
        } => (SseMode::Kms, key.as_deref(), context, *bucket_key),
        Encryption::Dsse { key, context } => (SseMode::Dsse, key.as_deref(), context, false),
    };
    let kms = kms.ok_or(StoreError::NoKms)?;
    let ctx = object_context(drive, bucket_id, object_id, context);
    let (data_key, sealed) = kms.generate(key, &ctx).await?;
    let (outer, outer_sealed) = if mode == SseMode::Dsse {
        let (outer, sealed) = kms.generate(Some(DEFAULT_KEY), &ctx.outer()).await?;
        (Some(outer), Some(sealed))
    } else {
        (None, None)
    };
    Ok(Some(Keyed {
        data_key,
        outer,
        crypt: Crypt {
            mode,
            object: object_id.to_owned(),
            sealed,
            context: context.clone(),
            customer: None,
            checksums: None,
            bucket_key,
            outer: outer_sealed,
        },
    }))
}

/// A new SSE-C object's data key, sealed by a key derived from the customer's.
fn customer_keyed(key: &CustomerKey, drive: &str, bucket_id: &str, object_id: &str) -> Keyed {
    let salt = teifs_crypto::random_salt();
    let data_key = DataKey::generate();
    let base = Context::object(drive, bucket_id, object_id);
    let sealed = teifs_crypto::seal(&key.kek(&salt), &base, &data_key, "", 0);
    let check = CustomerCheck {
        salt: STANDARD.encode(salt),
        hmac: STANDARD.encode(key.check(&salt)),
    };
    Keyed {
        data_key,
        outer: None,
        crypt: Crypt {
            mode: SseMode::Customer,
            object: object_id.to_owned(),
            sealed,
            context: BTreeMap::new(),
            customer: Some(check),
            checksums: None,
            bucket_key: false,
            outer: None,
        },
    }
}

/// Recovers the data key of a stored object. SSE-C needs the customer's key; the other
/// modes must not be given one (S3 refuses such requests).
pub(crate) async fn data_key(
    kms: Option<&dyn Kms>,
    crypt: &Crypt,
    drive: &str,
    bucket_id: &str,
    customer: Option<&CustomerKey>,
) -> Result<DataKey> {
    let context = crypt.context(drive, bucket_id);
    match (crypt.mode, customer) {
        (SseMode::Customer, None) => Err(StoreError::CustomerKeyRequired),
        (SseMode::Customer, Some(key)) => {
            let check = crypt.customer.as_ref().ok_or(StoreError::CorruptMetadata)?;
            let salt: [u8; 32] = STANDARD
                .decode(&check.salt)
                .ok()
                .and_then(|s| s.try_into().ok())
                .ok_or(StoreError::CorruptMetadata)?;
            let hmac = STANDARD
                .decode(&check.hmac)
                .map_err(|_| StoreError::CorruptMetadata)?;
            key.verify(&salt, &hmac)
                .map_err(|_| StoreError::WrongCustomerKey)?;
            Ok(teifs_crypto::unseal(
                &key.kek(&salt),
                &context,
                &crypt.sealed,
            )?)
        }
        (_, Some(_)) => Err(StoreError::CustomerKeyNotApplicable),
        (_, None) => {
            let kms = kms.ok_or(StoreError::NoKms)?;
            Ok(kms.unseal(&crypt.sealed, &context).await?)
        }
    }
}

/// Recovers a DSSE-KMS object's second data key (`None` for the other modes).
pub(crate) async fn outer_key(
    kms: Option<&dyn Kms>,
    crypt: &Crypt,
    drive: &str,
    bucket_id: &str,
) -> Result<Option<DataKey>> {
    match (crypt.mode, &crypt.outer) {
        (SseMode::Dsse, Some(sealed)) => {
            let kms = kms.ok_or(StoreError::NoKms)?;
            let context = crypt.context(drive, bucket_id).outer();
            Ok(Some(kms.unseal(sealed, &context).await?))
        }
        (SseMode::Dsse, None) | (_, Some(_)) => Err(StoreError::CorruptMetadata),
        _ => Ok(None),
    }
}

const UNENCRYPTED: &str = "The UpdateObjectEncryption operation doesn't support unencrypted source objects. Only source objects encrypted with SSE-S3 or SSE-KMS are supported.";
const NOT_UPDATABLE: &str = "The UpdateObjectEncryption operation doesn't support source objects with the encryption type DSSE-KMS or SSE-C. Only source objects encrypted with SSE-S3 or SSE-KMS are supported.";

impl Store {
    /// Seals the data key of a version of an object (`None`: the current one) under the
    /// KMS key `kms_key`, as S3's `UpdateObjectEncryption` does: the data isn't touched,
    /// and its ETag, modification time and checksums stay. For SSE-S3 and SSE-KMS
    /// objects that Object Lock doesn't protect.
    pub async fn update_encryption(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        kms_key: &str,
        bucket_key: bool,
    ) -> Result<()> {
        let kms = self.kms().ok_or(StoreError::NoKms)?;
        let (bucket_id, row) = self.updatable_row(bucket, key, version_id).await?;
        let crypt = crypt_of(&row)?.ok_or(StoreError::CorruptMetadata)?;
        let context = crypt.context(&self.inner.format.drive, &bucket_id);
        let data_key = kms.unseal(&crypt.sealed, &context).await?;
        let sealed = kms.seal(Some(kms_key), &context, &data_key).await?;
        let new = Resealed {
            mode: SseMode::Kms,
            crypt,
            sealed,
            bucket_key,
            data_key,
        };
        self.write_resealed(bucket, key, row, new, true).await
    }

    /// Seals the data key of a version of an SSE-S3 or SSE-KMS object again, as a
    /// `keyrotate` batch job does: under the managed key's newest version, or under the
    /// KMS key `to` names with its context (an SSE-S3 object then becomes SSE-KMS). The
    /// data, ETag, modification time and checksums stay. A version Object Lock protects
    /// keeps its mode, so only the managed key's rotation reaches it.
    pub async fn rotate_key(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        to: &RotateTo,
    ) -> Result<()> {
        let kms = self.kms().ok_or(StoreError::NoKms)?;
        let (bucket_id, row) = self.updatable_row(bucket, key, version_id).await?;
        let mut crypt = crypt_of(&row)?.ok_or(StoreError::CorruptMetadata)?;
        let drive = &self.inner.format.drive;
        let data_key = kms
            .unseal(&crypt.sealed, &crypt.context(drive, &bucket_id))
            .await?;
        let (mode, kms_key) = match to {
            RotateTo::S3 if crypt.mode == SseMode::Kms => {
                return Err(StoreError::InvalidRequest(
                    "an SSE-KMS object's key can't be rotated to SSE-S3",
                ));
            }
            RotateTo::S3 => (SseMode::S3, DEFAULT_KEY),
            RotateTo::Kms { key, context } => {
                crypt.context.clone_from(context);
                (SseMode::Kms, key.as_str())
            }
        };
        let sealed = kms
            .seal(Some(kms_key), &crypt.context(drive, &bucket_id), &data_key)
            .await?;
        let lock = mode != crypt.mode;
        let new = Resealed {
            mode,
            bucket_key: crypt.bucket_key,
            crypt,
            sealed,
            data_key,
        };
        self.write_resealed(bucket, key, row, new, lock).await
    }

    /// Records `new` for the version `row` describes, if its record is still the one
    /// `row` holds (else it was written again meanwhile, and the caller may try again)
    /// and, if `respect_lock`, Object Lock doesn't protect it.
    pub(crate) async fn write_resealed(
        &self,
        bucket: &str,
        key: &str,
        row: VersionRow,
        new: Resealed,
        respect_lock: bool,
    ) -> Result<()> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        self.blocking(move |inner| {
            let conn = inner.lock();
            let Bucket::Object(bucket) = inner.bucket(&bucket)? else {
                return Err(StoreError::InvalidRequest(UNENCRYPTED));
            };
            let old = row.crypt.as_deref().ok_or(StoreError::CorruptMetadata)?;
            let mut current = Inner::version_row(&conn, &bucket, &key, Some(&row.version_id))?;
            if respect_lock {
                check_removal(&current.attrs, false, now_ms())?;
            }
            let crypt = new.record(&mut current)?;
            let replaced = conn.replace_version_crypt(
                &bucket.id,
                &key,
                &current.version_id,
                old,
                (&crypt, &current.attrs, current.parts.as_deref()),
            )?;
            if replaced {
                Ok(())
            } else {
                Err(StoreError::ChangedMeanwhile)
            }
        })
        .await
    }

    /// The row of a version whose encryption may be updated, and its bucket's id.
    pub(crate) async fn updatable_row(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<(String, VersionRow)> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        let version_id = version_id.map(str::to_owned);
        self.blocking(move |inner| {
            let Bucket::Object(bucket) = inner.bucket(&bucket)? else {
                // Folder buckets keep plain files.
                return Err(StoreError::InvalidRequest(UNENCRYPTED));
            };
            let conn = inner.lock();
            let row = Inner::version_row(&conn, &bucket, &key, version_id.as_deref())?;
            match crypt_of(&row)? {
                None => return Err(StoreError::InvalidRequest(UNENCRYPTED)),
                Some(crypt) if matches!(crypt.mode, SseMode::Customer | SseMode::Dsse) => {
                    return Err(StoreError::InvalidRequest(NOT_UPDATABLE));
                }
                Some(_) => {}
            }
            Ok((bucket.id.clone(), row))
        })
        .await
    }
}

/// An object's record once its data key is sealed again by a KMS key.
pub(crate) struct Resealed {
    /// Its mode from now on: SSE-KMS, or (for a key version's rewrap) the one it had.
    pub mode: SseMode,
    /// The record it had.
    pub crypt: Crypt,
    /// The data key, sealed by the KMS key.
    pub sealed: SealedKey,
    pub bucket_key: bool,
    pub data_key: DataKey,
}

impl Resealed {
    /// The new record (JSON) of the version `row` describes; an SSE-S3 object that
    /// becomes SSE-KMS has the checksums it kept in the open sealed (as SSE-KMS keeps them).
    fn record(self, row: &mut VersionRow) -> Result<String> {
        let was_s3 = self.crypt.mode == SseMode::S3 && self.mode != SseMode::S3;
        let mut crypt = Crypt {
            mode: self.mode,
            sealed: self.sealed,
            bucket_key: self.bucket_key,
            ..self.crypt
        };
        if was_s3 {
            if !row.attrs.checksums.is_empty() {
                crypt.checksums = Some(seal_sums(&self.data_key, &row.attrs.checksums));
                row.attrs.checksums.clear();
            }
            if let Some(json) = &row.parts {
                let mut record = PartsRecord::parse(json)?;
                record.checksums = std::mem::take(&mut record.checksums)
                    .into_iter()
                    .map(|sums| part_sums(Some(&self.data_key), sums))
                    .collect();
                row.parts = Some(record.to_json());
            }
        }
        Ok(serde_json::to_string(&crypt).expect("crypt serializes"))
    }
}

/// The entry that holds sealed checksums in a checksum map (never an algorithm's name).
pub(crate) const SEALED: &str = "sealed";

/// Checksums say something about the plaintext: under SSE-KMS and SSE-C they're kept
/// sealed with the object's data key, base64.
pub(crate) fn seal_sums(key: &DataKey, sums: &BTreeMap<String, String>) -> String {
    let json = serde_json::to_vec(sums).expect("checksums serialize");
    STANDARD.encode(key.seal_metadata(&json))
}

/// Opens what [`seal_sums`] sealed.
pub(crate) fn open_sums(key: &DataKey, sealed: &str) -> Result<BTreeMap<String, String>> {
    let bytes = STANDARD
        .decode(sealed)
        .map_err(|_| StoreError::CorruptMetadata)?;
    let json = key.open_metadata(&bytes)?;
    serde_json::from_slice(&json).map_err(|_| StoreError::CorruptMetadata)
}

/// A part's checksums as stored: sealed into the [`SEALED`] entry when `key` is given.
pub(crate) fn part_sums(
    key: Option<&DataKey>,
    sums: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    match key {
        Some(key) if !sums.is_empty() => [(SEALED.to_owned(), seal_sums(key, &sums))].into(),
        _ => sums,
    }
}

/// A part's checksums as reported: opened with `key` when sealed and a key is given,
/// else without the sealed entry.
pub(crate) fn open_part_sums(
    key: Option<&DataKey>,
    mut sums: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    match (sums.remove(SEALED), key) {
        (Some(sealed), Some(key)) => open_sums(key, &sealed),
        _ => Ok(sums),
    }
}
