//! Integrity checks: an object's stored bytes read back and compared with what was
//! recorded when it was written. Nothing new is stored for this: every object already
//! has something to compare against. Plain and SSE-S3 objects have their ETag (the MD5
//! of their bytes, or of their parts' MD5s); objects written through S3 have a checksum
//! (CRC64NVME unless the client chose another), and their parts theirs; and encrypted
//! objects authenticate every 64 KiB package as they're decrypted. A pass goes through
//! every version of every object, bucket by bucket, from a cursor it can resume at.

use std::io;

use serde::{Deserialize, Serialize};
use teifs_types::{ChecksumType, SseMode, hex, md5_of_etag, multipart_etag};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

pub use teifs_types::verify::{Checked, Damage, Unverifiable, Verdict};

use crate::{Store, StoreError, VersionsQuery, checksum::Checksums, error::Result};

/// Bytes read at a time.
const CHUNK: usize = 1 << 20;

/// Where a pass over the drive is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCursor {
    /// The bucket it's in (or has just finished).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// The last version checked in it: its key and version id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<(String, String)>,
    /// Whether `bucket` is finished.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bucket_done: bool,
}

impl Store {
    /// Checks a version of an object (`None`: the current one) against what was
    /// recorded when it was written. Errors are for a check that couldn't run (a KMS
    /// that can't be reached, a version that no longer exists), never for damage.
    pub async fn verify_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<Verdict> {
        let verdict = self.check_version(bucket, key, version_id, None).await?;
        Ok(verdict.expect("only a stop ends a check early"))
    }

    /// [`Store::verify_version`], ending early (`None`) once `stop` is cancelled.
    async fn check_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        stop: Option<&CancellationToken>,
    ) -> Result<Option<Verdict>> {
        let (info, body) = match self.read_with(bucket, key, version_id, None).await {
            Ok(found) => found,
            Err(StoreError::CustomerKeyRequired) => {
                return Ok(Some(Unverifiable::CustomerKey.into()));
            }
            Err(StoreError::NoKms) => return Ok(Some(Unverifiable::NoKms.into())),
            Err(StoreError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(Some(Damage::Missing.into()));
            }
            Err(StoreError::Crypto(_) | StoreError::CorruptMetadata) => {
                return Ok(Some(Damage::Tampered.into()));
            }
            Err(err) => return Err(err),
        };
        // A folder has no bytes.
        let Some(body) = body else {
            return Ok(Some(Verdict::Intact));
        };
        let expected = Expected::of(&info);
        if expected.is_empty() && info.sse.is_none() {
            return Ok(Some(Unverifiable::NothingToCompare.into()));
        }
        let found = match expected.check(body, stop).await {
            Ok(found) => found,
            Err(err)
                if err.kind() == io::ErrorKind::Interrupted
                    && stop.is_some_and(CancellationToken::is_cancelled) =>
            {
                return Ok(None);
            }
            Err(err) if err.kind() == io::ErrorKind::InvalidData => Some(Damage::Tampered),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Some(Damage::Truncated),
            Err(err) => return Err(err.into()),
        };
        let Some(damage) = found else {
            return Ok(Some(Verdict::Intact));
        };
        // A folder bucket's file may have been edited while it was read.
        match self.head_version(bucket, key, version_id).await {
            Ok(now) if now.etag == info.etag && now.modified == info.modified => {
                Ok(Some(damage.into()))
            }
            Ok(_) | Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => {
                Ok(Some(Unverifiable::ChangedMeanwhile.into()))
            }
            Err(err) => Err(err),
        }
    }

    /// Checks the next versions of a pass over the drive (or over the bucket `only`),
    /// at most `limit` of them, from `cursor`, which it moves on; an empty answer means
    /// the pass is finished. Delete markers are skipped, and so are versions removed
    /// meanwhile.
    pub async fn verify_next(
        &self,
        cursor: &mut VerifyCursor,
        only: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Checked>> {
        self.verify_until(cursor, only, limit, None).await
    }

    /// [`Store::verify_next`], ending early once `stop` is cancelled: then `cursor` stays
    /// before the version being checked, and an empty answer doesn't mean the end.
    pub(crate) async fn verify_until(
        &self,
        cursor: &mut VerifyCursor,
        only: Option<&str>,
        limit: usize,
        stop: Option<&CancellationToken>,
    ) -> Result<Vec<Checked>> {
        let mut checked = Vec::new();
        while checked.is_empty() {
            let Some(bucket) = self.next_bucket(cursor, only).await? else {
                return Ok(checked);
            };
            let (key_marker, version_marker) = cursor.after.clone().unzip();
            let query = VersionsQuery {
                prefix: String::new(),
                delimiter: None,
                key_marker,
                version_marker,
                max_keys: limit.max(1),
            };
            let listing = match self.list_versions(&bucket, query).await {
                Ok(listing) => listing,
                // Removed meanwhile: on to the next one.
                Err(StoreError::NoSuchBucket) => {
                    cursor.bucket_done = true;
                    continue;
                }
                Err(err) => return Err(err),
            };
            for version in listing.versions {
                let info = version.info;
                let version_id = info.version_id.clone().unwrap_or_default();
                let before = cursor.after.replace((info.key.clone(), version_id.clone()));
                if version.delete_marker {
                    continue;
                }
                let verdict = match self
                    .check_version(&bucket, &info.key, Some(&version_id), stop)
                    .await
                {
                    Ok(Some(verdict)) => verdict,
                    Ok(None) => {
                        cursor.after = before;
                        return Ok(checked);
                    }
                    Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => continue,
                    Err(err) => return Err(err),
                };
                checked.push(Checked {
                    bucket: bucket.clone(),
                    key: info.key,
                    version_id,
                    size: info.size,
                    verdict,
                });
            }
            cursor.bucket_done = !listing.truncated;
            if stop.is_some_and(CancellationToken::is_cancelled) {
                break;
            }
        }
        Ok(checked)
    }

    /// The bucket a pass is in, moving `cursor` to the next one when it's finished; `None`
    /// when there are no more.
    async fn next_bucket(
        &self,
        cursor: &mut VerifyCursor,
        only: Option<&str>,
    ) -> Result<Option<String>> {
        if let Some(bucket) = &cursor.bucket
            && !cursor.bucket_done
        {
            return Ok(Some(bucket.clone()));
        }
        let mut names: Vec<String> = self
            .list_buckets()
            .await?
            .into_iter()
            .map(|b| b.name)
            .filter(|name| only.is_none_or(|only| name == only))
            .collect();
        names.sort_unstable();
        let next = names
            .into_iter()
            .find(|name| cursor.bucket.as_ref().is_none_or(|done| name > done));
        // At the end the cursor stays where it is, so the pass stays finished.
        if let Some(name) = &next {
            *cursor = VerifyCursor {
                bucket: Some(name.clone()),
                after: None,
                bucket_done: false,
            };
        }
        Ok(next)
    }
}

/// What a version's bytes are compared with.
struct Expected {
    /// Its ETag when it's an MD5 (plain and SSE-S3 objects), and whether it's a
    /// multipart one.
    etag: Option<String>,
    /// Whole-object checksums.
    whole: Vec<(String, String)>,
    /// Each part's size and checksums (one part unless uploaded in parts).
    parts: Vec<(u64, Vec<(String, String)>)>,
    multipart: bool,
}

impl Expected {
    fn of(info: &crate::ObjectInfo) -> Self {
        let md5_etag = info.sse.as_ref().is_none_or(|s| s.mode == SseMode::S3);
        let multipart = !info.parts.is_empty();
        let etag = (md5_etag && (multipart || md5_of_etag(&info.etag).is_some()))
            .then(|| info.etag.clone());
        // A composite checksum is of the parts' checksums, which are checked instead.
        let whole = if info.attrs.checksum_type == Some(ChecksumType::Composite) {
            Vec::new()
        } else {
            known(&info.attrs.checksums)
        };
        let parts = if multipart {
            info.parts
                .iter()
                .map(|p| (p.size, known(&p.checksums)))
                .collect()
        } else {
            vec![(info.size, Vec::new())]
        };
        Self {
            etag,
            whole,
            parts,
            multipart,
        }
    }

    fn is_empty(&self) -> bool {
        self.etag.is_none() && self.whole.is_empty() && self.parts.iter().all(|p| p.1.is_empty())
    }

    /// Reads the bytes once, hashing the whole and each part as they pass; the first
    /// thing that doesn't match.
    async fn check(
        self,
        body: crate::ObjectBody,
        stop: Option<&CancellationToken>,
    ) -> io::Result<Option<Damage>> {
        let size = body.size();
        let mut reader = body.all().await.map_err(io::Error::other)?;
        let mut whole = hasher(&self.whole);
        let mut md5s = Vec::with_capacity(self.parts.len());
        let mut damage = None;
        let mut buf = vec![0u8; CHUNK.min(usize::try_from(size).unwrap_or(CHUNK)).max(1)];
        let mut read = 0u64;
        for (number, (part_size, sums)) in (1u32..).zip(&self.parts) {
            let mut part = hasher(sums);
            part.add("MD5");
            let mut left = *part_size;
            while left > 0 {
                if stop.is_some_and(CancellationToken::is_cancelled) {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let want = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
                let got = reader.read(&mut buf[..want]).await?;
                if got == 0 {
                    return Ok(Some(Damage::Truncated));
                }
                whole.update(&buf[..got]);
                part.update(&buf[..got]);
                left -= got as u64;
                read += got as u64;
            }
            let mut computed = part.finish();
            let md5 = computed.remove("MD5").unwrap_or_default();
            md5s.push(decode_md5(&md5));
            if damage.is_none() {
                damage = mismatch(sums, &computed).map(|algorithm| Damage::Checksum {
                    algorithm,
                    part: self.multipart.then_some(number),
                });
            }
        }
        debug_assert_eq!(read, size);
        if damage.is_some() {
            return Ok(damage);
        }
        if let Some(algorithm) = mismatch(&self.whole, &whole.finish()) {
            return Ok(Some(Damage::Checksum {
                algorithm,
                part: None,
            }));
        }
        let etag_matches = self.etag.as_ref().is_none_or(|etag| {
            if self.multipart {
                *etag == multipart_etag(&md5s)
            } else {
                md5s.first().is_some_and(|md5| *etag == hex(md5))
            }
        });
        Ok((!etag_matches).then_some(Damage::Etag))
    }
}

/// The checksums of algorithms TeiFS can compute (anything else is left out).
fn known(sums: &std::collections::BTreeMap<String, String>) -> Vec<(String, String)> {
    sums.iter()
        .filter(|(name, _)| Checksums::supports(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn hasher(sums: &[(String, String)]) -> Checksums {
    let mut hasher = Checksums::default();
    for (name, _) in sums {
        hasher.add(name);
    }
    hasher
}

/// The first algorithm whose checksum doesn't match.
fn mismatch(
    expected: &[(String, String)],
    computed: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    expected
        .iter()
        .find(|(name, value)| computed.get(name) != Some(value))
        .map(|(name, _)| name.clone())
}

fn decode_md5(base64: &str) -> [u8; 16] {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD
        .decode(base64)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or_default()
}
