//! Bucket names and object keys, and the paths they map to.
//!
//! A bucket is a folder directly under the drive's root and an object is a file inside it,
//! so a key must be something every supported file system can hold: no empty, `.` or `..`
//! segments, no backslashes or NUL bytes, and no segment longer than a file name may be.
//! A key ending in `/` is a folder (S3's "directory marker").

use std::path::PathBuf;

use crate::error::{Result, StoreError};

/// The longest key S3 allows, in bytes.
pub const MAX_KEY_LEN: usize = 1024;
/// The longest file name most file systems allow, in bytes.
pub const MAX_SEGMENT_LEN: usize = 255;

/// Checks a bucket name against S3's rules for new buckets.
pub fn check_bucket(name: &str) -> Result<()> {
    let invalid = StoreError::InvalidBucketName;
    if !(3..=63).contains(&name.len()) {
        return Err(invalid("it must be 3 to 63 characters long"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(invalid(
            "it may only hold lowercase letters, digits, hyphens and dots",
        ));
    }
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = name.as_bytes();
    if !edge(bytes[0]) || !edge(bytes[bytes.len() - 1]) {
        return Err(invalid("it must start and end with a letter or a digit"));
    }
    if name.contains("..") || name.contains(".-") || name.contains("-.") {
        return Err(invalid("dots can't be next to each other or to a hyphen"));
    }
    if name.split('.').count() == 4 && name.split('.').all(|part| part.parse::<u8>().is_ok()) {
        return Err(invalid("it can't look like an IP address"));
    }
    Ok(())
}

/// An object key, checked, with the path it maps to inside its bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectKey {
    key: String,
    rel: PathBuf,
    folder: bool,
}

impl ObjectKey {
    /// Checks `key` and maps it to a relative path.
    pub fn parse(key: &str) -> Result<Self> {
        let invalid = StoreError::InvalidKey;
        if key.is_empty() {
            return Err(invalid("it's empty"));
        }
        if key.len() > MAX_KEY_LEN {
            return Err(invalid("it's longer than 1024 bytes"));
        }
        if key.starts_with('/') {
            return Err(invalid("it starts with a slash"));
        }
        if key.contains('\0') || key.contains('\\') {
            return Err(invalid("it holds a NUL byte or a backslash"));
        }
        let folder = key.ends_with('/');
        let body = if folder { &key[..key.len() - 1] } else { key };
        let mut rel = PathBuf::new();
        for segment in body.split('/') {
            match segment {
                "" => return Err(invalid("it has an empty segment (two slashes in a row)")),
                "." | ".." => return Err(invalid("it has a `.` or `..` segment")),
                s if s.len() > MAX_SEGMENT_LEN => {
                    return Err(invalid("a segment is longer than 255 bytes"));
                }
                s => rel.push(s),
            }
        }
        Ok(Self {
            key: key.to_owned(),
            rel,
            folder,
        })
    }

    /// The key as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// The path inside the bucket.
    #[must_use]
    pub fn rel(&self) -> &std::path::Path {
        &self.rel
    }

    /// Whether the key names a folder (ends in `/`).
    #[must_use]
    pub fn is_folder(&self) -> bool {
        self.folder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names_follow_s3() {
        for good in ["abc", "my-photos", "a.b.c", "2026-backups", &"a".repeat(63)] {
            assert!(check_bucket(good).is_ok(), "{good}");
        }
        for bad in [
            "ab",
            "ABC",
            "-abc",
            "abc-",
            ".abc",
            "a..b",
            "a.-b",
            "a_b",
            "192.168.1.1",
            &"a".repeat(64),
        ] {
            assert!(check_bucket(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keys_map_to_relative_paths() {
        let key = ObjectKey::parse("photos/2026/a.jpg").unwrap();
        assert_eq!(key.rel(), std::path::Path::new("photos/2026/a.jpg"));
        assert!(!key.is_folder());

        let folder = ObjectKey::parse("photos/2026/").unwrap();
        assert_eq!(folder.rel(), std::path::Path::new("photos/2026"));
        assert!(folder.is_folder());

        assert!(ObjectKey::parse("dots in names are fine...txt").is_ok());
        assert!(ObjectKey::parse("unicode/ünïcødé ✓.txt").is_ok());
    }

    #[test]
    fn keys_that_cant_be_files_are_refused() {
        let long_segment = format!("a/{}", "b".repeat(256));
        let long_key = "a/".repeat(513);
        for bad in [
            "",
            "/a",
            "a//b",
            "a/./b",
            "a/../b",
            "..",
            "a\\b",
            "a\0b",
            "/",
            &long_segment,
            &long_key,
        ] {
            assert!(ObjectKey::parse(bad).is_err(), "{bad:?}");
        }
    }
}
