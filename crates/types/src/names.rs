//! Bucket names and object keys, and the paths they map to in a plain bucket.
//!
//! A bucket is a folder directly under the drive's root and an object is a file inside it,
//! so a key must be something every supported file system can hold: no empty, `.` or `..`
//! segments, no backslashes or NUL bytes, and no segment longer than a file name may be.
//! A key ending in `/` is a folder (S3's "directory marker").
//!
//! Windows can't hold every name the others can: device names (`CON`, `NUL.txt`), the
//! characters `<>:"|?*` and control characters, and names ending in a dot or a space are
//! refused or silently changed by its path layer (`a:b` even writes a hidden stream of the
//! file `a`). Those names are always refused on Windows, and elsewhere when a drive's keys
//! are kept portable ([`ObjectKey::check_portable`]), so a drive can move between systems.

use std::path::PathBuf;

/// Why a name can't be a bucket name or an object key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// The name breaks S3's rules for bucket names.
    #[error("invalid bucket name: {0}")]
    InvalidBucketName(&'static str),
    /// The key is longer than [`MAX_KEY_LEN`] bytes.
    #[error("the key is longer than 1024 bytes")]
    KeyTooLong,
    /// The key can't be stored as a file.
    #[error("invalid object key: {0}")]
    InvalidKey(&'static str),
}

type Result<T> = std::result::Result<T, NameError>;

/// The longest key S3 allows, in bytes.
pub const MAX_KEY_LEN: usize = 1024;
/// The longest file name most file systems allow, in bytes.
pub const MAX_SEGMENT_LEN: usize = 255;
/// A folder at the top of a bucket that TeiFS may use to stage writes (for a bucket on
/// another disk than the drive), so no key may start with it.
pub const BUCKET_STAGING: &str = ".teifs-tmp";

/// Checks a bucket name against S3's rules for new buckets.
pub fn check_bucket(name: &str) -> Result<()> {
    let invalid = NameError::InvalidBucketName;
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

/// Names Windows treats as devices, in any letter case and with any extension.
const WINDOWS_DEVICES: [&str; 32] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$", //
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9", //
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}", //
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9", //
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// Why Windows can't hold a file or folder called `name`, if it can't.
fn windows_name_error(name: &str) -> Option<&'static str> {
    if name.chars().any(|c| {
        matches!(
            c,
            '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\u{1}'..='\u{1f}'
        )
    }) {
        return Some("Windows can't hold a name with any of <>:\"|?* or a control character");
    }
    if name.ends_with(['.', ' ']) {
        return Some("Windows can't hold a name ending in a dot or a space");
    }
    // `NUL.txt` and `NUL .txt` are the device too.
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    WINDOWS_DEVICES
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
        .then_some("Windows reserves this name for a device (CON, NUL, COM1, LPT1, …)")
}

/// Checks a bucket name for a folder bucket, whose folder has the bucket's name:
/// Windows device names (`con`, `nul`, `com1`, …) can't be folders there.
pub fn check_folder_bucket(name: &str, portable: bool) -> Result<()> {
    check_bucket(name)?;
    match windows_name_error(name) {
        Some(why) if portable || cfg!(windows) => Err(NameError::InvalidBucketName(why)),
        _ => Ok(()),
    }
}

/// Checks a key for an object bucket, which stores any key S3 allows: 1 to 1024 bytes of
/// UTF-8 (the type guarantees UTF-8).
pub fn check_object_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(NameError::InvalidKey("it's empty"));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(NameError::KeyTooLong);
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
        let invalid = NameError::InvalidKey;
        if key.is_empty() {
            return Err(invalid("it's empty"));
        }
        if key.len() > MAX_KEY_LEN {
            return Err(NameError::KeyTooLong);
        }
        if key.starts_with('/') {
            return Err(invalid("it starts with a slash"));
        }
        if key.contains('\0') || key.contains('\\') {
            return Err(invalid("it holds a NUL byte or a backslash"));
        }
        let folder = key.ends_with('/');
        let body = if folder { &key[..key.len() - 1] } else { key };
        if body.split('/').next() == Some(BUCKET_STAGING) {
            return Err(invalid(
                "`.teifs-tmp` at the top of a bucket is reserved for TeiFS",
            ));
        }
        let mut rel = PathBuf::new();
        for segment in body.split('/') {
            match segment {
                "" => return Err(invalid("it has an empty segment (two slashes in a row)")),
                "." | ".." => return Err(invalid("it has a `.` or `..` segment")),
                s if s.len() > MAX_SEGMENT_LEN => {
                    return Err(invalid("a segment is longer than 255 bytes"));
                }
                s => {
                    // Windows would open something else: a device, a hidden stream, the
                    // name without its trailing dot.
                    if cfg!(windows)
                        && let Some(why) = windows_name_error(s)
                    {
                        return Err(invalid(why));
                    }
                    rel.push(s);
                }
            }
        }
        Ok(Self {
            key: key.to_owned(),
            rel,
            folder,
        })
    }

    /// Fails unless every system TeiFS runs on can hold the key as a path, so the drive
    /// can move between them: Windows' rules, whichever system this is.
    pub fn check_portable(&self) -> Result<()> {
        self.segments()
            .find_map(windows_name_error)
            .map_or(Ok(()), |why| Err(NameError::InvalidKey(why)))
    }

    /// The key's names, from the bucket's top down.
    fn segments(&self) -> impl Iterator<Item = &str> {
        self.key.trim_end_matches('/').split('/')
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
        ] {
            assert!(ObjectKey::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(ObjectKey::parse(&long_key), Err(NameError::KeyTooLong));
        for reserved in [".teifs-tmp", ".teifs-tmp/", ".teifs-tmp/x"] {
            assert!(ObjectKey::parse(reserved).is_err(), "{reserved}");
        }
        assert!(ObjectKey::parse("a/.teifs-tmp/x").is_ok());
    }

    #[test]
    fn object_buckets_take_any_s3_key() {
        for key in [
            "a",
            "a/../b",
            "//x",
            "/lead",
            "a\\b",
            ".teifs-tmp/x",
            "CON",
            "a:b",
        ] {
            assert!(check_object_key(key).is_ok(), "{key}");
        }
        assert!(check_object_key("").is_err());
        assert_eq!(
            check_object_key(&"k".repeat(1025)),
            Err(NameError::KeyTooLong)
        );
    }

    #[test]
    fn portable_keys_follow_windows_rules() {
        let portable = |key: &str| ObjectKey::parse(key).and_then(|k| k.check_portable());
        for good in [
            "a/b.txt",
            "CONSOLE",
            "con_not",
            "COM10",
            "LPT",
            "nul-ish/x",
            ".CON",
            "a/.hidden",
            " lead",
            "ünïcødé/ok.txt",
            "folder/",
            "a.b.c",
        ] {
            assert!(portable(good).is_ok(), "{good:?}");
        }
        for bad in [
            "CON",
            "con",
            "Nul.txt",
            "NUL .tar.gz",
            "photos/aux/1.jpg",
            "COM1",
            "com\u{b9}.log",
            "LPT9",
            "lpt0",
            "CONIN$",
            "conout$.x",
            "a:b",
            "a/b?",
            "x*",
            "q\"uote",
            "p|ipe",
            "<a>",
            "tab\there",
            "bell\u{7}",
            "dot./x",
            "ends.",
            "space /x",
            "trailing ",
            "prn/",
        ] {
            // Windows refuses them outright; elsewhere they're refused as not portable.
            let refused = match ObjectKey::parse(bad) {
                Ok(key) => matches!(key.check_portable(), Err(NameError::InvalidKey(_))),
                Err(err) => cfg!(windows) && matches!(err, NameError::InvalidKey(_)),
            };
            assert!(refused, "{bad:?}");
        }
    }

    #[test]
    fn windows_refuses_its_own_names_whatever_the_setting() {
        assert_eq!(ObjectKey::parse("a:b").is_err(), cfg!(windows));
        assert_eq!(ObjectKey::parse("NUL.txt").is_err(), cfg!(windows));
    }

    #[test]
    fn folder_buckets_cant_be_devices() {
        for device in ["con", "nul", "aux", "prn", "com1", "lpt9"] {
            assert!(check_folder_bucket(device, true).is_err(), "{device}");
            assert_eq!(check_folder_bucket(device, false).is_err(), cfg!(windows));
        }
        assert!(check_folder_bucket("console", true).is_ok());
        assert!(check_folder_bucket("con.logs", true).is_err());
        assert!(check_folder_bucket("A", true).is_err());
    }

    mod properties {
        use std::path::Component;

        use proptest::prelude::*;

        use super::super::*;

        /// Keys made of the pieces that matter to a path: separators, dots, characters
        /// some system treats specially, and plain names.
        fn hostile_key() -> impl Strategy<Value = String> {
            let piece = prop::sample::select(vec![
                "/",
                "/",
                "/",
                ".",
                "..",
                "\\",
                "\0",
                "a",
                "b.txt",
                "é",
                " ",
                ":",
                "C:",
                "~",
                "%2e",
                ".teifs-tmp",
                ".teifs",
                "\u{202e}",
            ]);
            prop::collection::vec(piece, 1..12).prop_map(|pieces| pieces.concat())
        }

        fn check(key: &str) {
            let Ok(parsed) = ObjectKey::parse(key) else {
                return;
            };
            // Only plain names: nothing climbs out of the bucket's folder, jumps to a
            // root, or names the folder itself.
            let names: Vec<&str> = parsed
                .rel()
                .components()
                .map(|component| match component {
                    Component::Normal(name) => name.to_str().expect("a key is UTF-8"),
                    other => panic!("{key:?} maps to {other:?}"),
                })
                .collect();
            assert!(!names.is_empty(), "{key:?} maps to the bucket itself");
            // And the path is the key, name for name.
            let folder = if parsed.is_folder() { "/" } else { "" };
            assert_eq!(format!("{}{folder}", names.join("/")), key);
            assert!(names.iter().all(|name| name.len() <= MAX_SEGMENT_LEN));
            assert_ne!(names[0], BUCKET_STAGING);
        }

        proptest! {
            #[test]
            fn a_key_maps_to_a_path_inside_its_bucket(key in hostile_key()) {
                check(&key);
            }

            #[test]
            fn any_string_parses_or_is_refused_without_panicking(key in any::<String>()) {
                check(&key);
            }
        }
    }
}
