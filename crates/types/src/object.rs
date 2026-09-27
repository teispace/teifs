//! What the store knows about an object beyond its bytes.

use std::{collections::BTreeMap, fs::Metadata, time::SystemTime};

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

/// An object's HTTP attributes, user metadata and checksums, kept beside the file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ObjectAttrs {
    /// `Content-Type`; guessed from the file name when not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// `Content-Encoding`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    /// `Content-Disposition`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_disposition: Option<String>,
    /// `Content-Language`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_language: Option<String>,
    /// `Cache-Control`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    /// `Expires`, as sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// `x-amz-website-redirect-location`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_redirect_location: Option<String>,
    /// User metadata (`x-amz-meta-*`, without the prefix).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub user: BTreeMap<String, String>,
    /// Whole-object checksums by algorithm (`CRC32`, `SHA256`, …), base64 as S3 sends them.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub checksums: BTreeMap<String, String>,
}

/// An object as listed or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    /// Its key.
    pub key: String,
    /// Its size in bytes.
    pub size: u64,
    /// When its file last changed.
    pub modified: SystemTime,
    /// Its ETag, without quotes.
    pub etag: String,
    /// Its attributes.
    pub attrs: ObjectAttrs,
}

impl ObjectInfo {
    /// The `Content-Type`: the stored one, else a guess from the key, else binary.
    #[must_use]
    pub fn content_type(&self) -> String {
        if let Some(stored) = &self.attrs.content_type {
            return stored.clone();
        }
        if self.key.ends_with('/') {
            return "application/x-directory".to_owned();
        }
        mime_guess::from_path(&self.key)
            .first_or_octet_stream()
            .essence_str()
            .to_owned()
    }
}

/// Identifies a file's current contents without reading them: when its size or
/// modification time changes, the file was written again (by TeiFS or by anything else)
/// and what was stored about it no longer applies.
///
/// The inode is recorded but not compared: backups, restores and moves to another disk
/// keep sizes and modification times but not inodes, and must keep their metadata.
/// Deliberately not `PartialEq`: compare with [`Stamp::matches`].
#[derive(Debug, Clone, Copy)]
pub struct Stamp {
    /// Size in bytes.
    pub size: u64,
    /// Modification time, in nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
    /// Inode number (0 where the platform has none).
    pub ino: u64,
}

impl Stamp {
    /// The stamp of a file's metadata.
    #[must_use]
    pub fn of(meta: &Metadata) -> Self {
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
        Self {
            size: meta.len(),
            mtime_ns,
            ino: inode(meta),
        }
    }

    /// Whether both describe the same contents: same size and modification time.
    #[must_use]
    pub fn matches(&self, other: &Stamp) -> bool {
        self.size == other.size && self.mtime_ns == other.mtime_ns
    }
}

#[cfg(unix)]
fn inode(meta: &Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}

#[cfg(not(unix))]
fn inode(_: &Metadata) -> u64 {
    0
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// The ETag of an empty object (and of folders).
#[must_use]
pub fn empty_etag() -> String {
    hex(&Md5::digest([]))
}

/// The ETag of a multipart object: the MD5 of the parts' MD5s, then `-` and the count.
#[must_use]
pub fn multipart_etag(part_md5s: &[[u8; 16]]) -> String {
    let mut hasher = Md5::new();
    for md5 in part_md5s {
        hasher.update(md5);
    }
    format!("{}-{}", hex(&hasher.finalize()), part_md5s.len())
}

/// An ETag for a file whose MD5 isn't known yet (placed or changed outside TeiFS). It's
/// stable while the file doesn't change, and shaped like a multipart ETag so clients don't
/// mistake it for the file's MD5.
#[must_use]
pub fn provisional_etag(stamp: Stamp) -> String {
    let digest = Md5::digest(format!("{}:{}:{}", stamp.size, stamp.mtime_ns, stamp.ino));
    format!("{}-1", hex(&digest))
}

/// Parses an ETag's hex MD5 (a plain one, not a multipart one).
#[must_use]
pub fn md5_of_etag(etag: &str) -> Option<[u8; 16]> {
    let etag = etag.trim_matches('"');
    if etag.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(etag.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags_match_s3() {
        assert_eq!(empty_etag(), "d41d8cd98f00b204e9800998ecf8427e");
        // Two parts whose MD5s are those of "a" and "b".
        let a = Md5::digest(b"a").into();
        let b = Md5::digest(b"b").into();
        let etag = multipart_etag(&[a, b]);
        assert!(etag.ends_with("-2"));
        let mut both = Vec::new();
        both.extend_from_slice(&a);
        both.extend_from_slice(&b);
        assert_eq!(etag, format!("{}-2", hex(&Md5::digest(&both))));
    }

    #[test]
    fn provisional_etags_never_look_like_an_md5() {
        let etag = provisional_etag(Stamp {
            size: 3,
            mtime_ns: 1,
            ino: 2,
        });
        assert!(etag.ends_with("-1"));
        assert_eq!(md5_of_etag(&etag), None);
        assert_eq!(
            md5_of_etag("\"d41d8cd98f00b204e9800998ecf8427e\""),
            Some(Md5::digest([]).into())
        );
    }

    #[test]
    fn stamps_ignore_the_inode() {
        let a = Stamp {
            size: 3,
            mtime_ns: 1,
            ino: 2,
        };
        assert!(a.matches(&Stamp { ino: 9, ..a }));
        assert!(!a.matches(&Stamp { size: 4, ..a }));
        assert!(!a.matches(&Stamp { mtime_ns: 2, ..a }));
    }

    #[test]
    fn content_type_is_guessed_when_not_stored() {
        let mut info = ObjectInfo {
            key: "a/photo.JPG".into(),
            size: 0,
            modified: SystemTime::UNIX_EPOCH,
            etag: empty_etag(),
            attrs: ObjectAttrs::default(),
        };
        assert_eq!(info.content_type(), "image/jpeg");
        info.attrs.content_type = Some("text/plain".into());
        assert_eq!(info.content_type(), "text/plain");
        info.key = "a/".into();
        info.attrs.content_type = None;
        assert_eq!(info.content_type(), "application/x-directory");
    }
}
