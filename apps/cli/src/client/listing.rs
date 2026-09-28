//! Everything under a local folder or a key prefix, by path relative to it: what
//! recursive copies and mirrors work through.

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

#[cfg(test)]
mod tests {
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
