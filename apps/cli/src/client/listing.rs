//! Everything under a local folder or a key prefix, by path relative to it: what
//! recursive copies and mirrors work through; and every version under a key prefix.

use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use aws_sdk_s3::Client;

use super::{Error, target::relative_key};

/// A file or an object, by its path below the folder or prefix listed (`/`-separated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub relative: String,
    pub size: u64,
    pub modified: Option<SystemTime>,
    /// An object's ETag (files have none).
    pub etag: Option<String>,
}

/// Every file under `root`, sorted. Symbolic links to files are followed; links to
/// folders are skipped (they can loop), and so is anything that isn't a file.
pub fn local(root: &Path) -> Result<Vec<Entry>, Error> {
    let failed = |path: &Path, e: &dyn std::fmt::Display| {
        Error::general(format!("can't read {}: {e}", path.display()))
    };
    let mut entries = Vec::new();
    let mut folders: Vec<PathBuf> = vec![root.to_owned()];
    while let Some(folder) = folders.pop() {
        for item in fs::read_dir(&folder).map_err(|e| failed(&folder, &e))? {
            let item = item.map_err(|e| failed(&folder, &e))?;
            let path = item.path();
            let kind = item.file_type().map_err(|e| failed(&path, &e))?;
            if kind.is_dir() {
                folders.push(path);
                continue;
            }
            // Follows a link to what it points at.
            let Ok(meta) = fs::metadata(&path) else {
                crate::ui::warn(format!("skipping {}: a broken link", path.display()));
                continue;
            };
            if !meta.is_file() {
                if !meta.is_dir() {
                    crate::ui::warn(format!("skipping {}: not a file", path.display()));
                }
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|e| failed(&path, &e))
                .and_then(|r| relative_key(r).map_err(Error::general))?;
            entries.push(Entry {
                relative,
                size: meta.len(),
                modified: meta.modified().ok(),
                etag: None,
            });
        }
    }
    entries.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(entries)
}

/// Every object whose key starts with `prefix`, in key order, relative to it.
pub async fn remote(
    client: &Client,
    bucket: &str,
    prefix: &str,
    name: &str,
) -> Result<Vec<Entry>, Error> {
    let mut pages = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .into_paginator()
        .send();
    let mut entries = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| Error::s3(format!("can't list {name}"), &e))?;
        for object in page.contents() {
            let Some(key) = object.key() else { continue };
            entries.push(Entry {
                relative: key.strip_prefix(prefix).unwrap_or(key).to_owned(),
                size: object
                    .size()
                    .and_then(|s| u64::try_from(s).ok())
                    .unwrap_or(0),
                modified: object
                    .last_modified()
                    .and_then(|t| SystemTime::try_from(*t).ok()),
                etag: object.e_tag().map(str::to_owned),
            });
        }
    }
    Ok(entries)
}

/// A version of an object, or a delete marker, from a versions listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub key: String,
    /// Its version id (`null` for one written without versioning).
    pub id: String,
    /// Whether it's the key's current version.
    pub latest: bool,
    pub delete_marker: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub etag: Option<String>,
}

/// S3 lists versions and delete markers apart: as one list, keys in order, each key's
/// current version first, then newest to oldest (times are to the second, so the
/// current one can't be told by its time alone).
fn in_order(versions: &mut [Version]) {
    versions.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then(b.latest.cmp(&a.latest))
            .then(b.modified.cmp(&a.modified))
    });
}

/// Every version and delete marker whose key starts with `prefix` (rolled up at
/// `delimiter` into the common prefixes returned beside them): keys in order, each
/// key's current version first, then newest to oldest.
pub async fn versions(
    client: &Client,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    name: &str,
) -> Result<(Vec<Version>, Vec<String>), Error> {
    let (mut versions, mut prefixes) = (Vec::new(), Vec::new());
    let (mut key_marker, mut version_marker) = (None, None);
    loop {
        let page = client
            .list_object_versions()
            .bucket(bucket)
            .prefix(prefix)
            .set_delimiter(delimiter.map(str::to_owned))
            .set_key_marker(key_marker.take())
            .set_version_id_marker(version_marker.take())
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't list the versions in {name}"), &e))?;
        let time = |t: Option<&aws_sdk_s3::primitives::DateTime>| {
            t.and_then(|t| SystemTime::try_from(*t).ok())
        };
        for v in page.versions() {
            versions.push(Version {
                key: v.key().unwrap_or_default().to_owned(),
                id: v.version_id().unwrap_or("null").to_owned(),
                latest: v.is_latest().unwrap_or(false),
                delete_marker: false,
                size: v.size().and_then(|s| u64::try_from(s).ok()).unwrap_or(0),
                modified: time(v.last_modified()),
                etag: v.e_tag().map(str::to_owned),
            });
        }
        for m in page.delete_markers() {
            versions.push(Version {
                key: m.key().unwrap_or_default().to_owned(),
                id: m.version_id().unwrap_or("null").to_owned(),
                latest: m.is_latest().unwrap_or(false),
                delete_marker: true,
                size: 0,
                modified: time(m.last_modified()),
                etag: None,
            });
        }
        prefixes.extend(
            page.common_prefixes()
                .iter()
                .filter_map(|p| p.prefix().map(str::to_owned)),
        );
        if !page.is_truncated().unwrap_or(false) {
            break;
        }
        key_marker = page.next_key_marker().map(str::to_owned);
        version_marker = page.next_version_id_marker().map(str::to_owned);
        if key_marker.is_none() {
            // A truncated page that says nowhere to go on from would loop forever.
            return Err(Error::general(format!(
                "can't list the versions in {name}: the endpoint gave no marker to go on from"
            )));
        }
    }
    in_order(&mut versions);
    prefixes.sort();
    prefixes.dedup();
    Ok((versions, prefixes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn versions_list_by_key_current_first_then_newest() {
        let at = |secs| Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs));
        let version = |key: &str, id: &str, latest, secs| Version {
            key: key.into(),
            id: id.into(),
            latest,
            delete_marker: id.starts_with('m'),
            size: 0,
            modified: at(secs),
            etag: None,
        };
        // As S3 answers: versions, then delete markers.
        let mut versions = vec![
            version("b", "v1", false, 5),
            version("a", "v1", false, 3),
            version("a", "v2", false, 9),
            version("a", "m1", true, 9),
        ];
        in_order(&mut versions);
        let order: Vec<_> = versions
            .iter()
            .map(|v| format!("{}:{}", v.key, v.id))
            .collect();
        assert_eq!(order, ["a:m1", "a:v2", "a:v1", "b:v1"]);
    }

    use super::*;

    #[test]
    fn local_folders_list_files_by_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join("a/b/deep.txt"), "deep").unwrap();
        fs::write(root.join("top.txt"), "top!").unwrap();
        fs::write(root.join("a/naïve café.txt"), "").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("top.txt"), root.join("link.txt")).unwrap();
            std::os::unix::fs::symlink(root.join("a"), root.join("loop")).unwrap();
            std::os::unix::fs::symlink(root.join("nowhere"), root.join("broken")).unwrap();
        }
        let listed: Vec<_> = local(root)
            .unwrap()
            .into_iter()
            .map(|e| (e.relative, e.size))
            .collect();
        let mut expected = vec![
            ("a/b/deep.txt".to_owned(), 4),
            ("a/naïve café.txt".to_owned(), 0),
            ("top.txt".to_owned(), 4),
        ];
        #[cfg(unix)]
        expected.insert(2, ("link.txt".to_owned(), 4));
        assert_eq!(listed, expected);
    }
}
