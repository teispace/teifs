//! What a path on the command line names: a local file or folder, or (when it starts
//! with an alias) an alias, a bucket, or objects in one.

use std::path::{Component, Path, PathBuf};

use super::{
    Error,
    alias::{Alias, Aliases},
};

/// A path on the command line.
#[derive(Debug)]
pub enum Target {
    Local(PathBuf),
    Remote(Remote),
}

/// `ALIAS[/BUCKET[/KEY]]`.
#[derive(Debug, Clone)]
pub struct Remote {
    pub alias_name: String,
    pub alias: Box<Alias>,
    /// `None` for the alias itself.
    pub bucket: Option<String>,
    /// The key or key prefix; empty for the whole bucket.
    pub key: String,
}

impl Remote {
    /// `ALIAS/BUCKET/KEY` for messages.
    pub fn display(&self, key: &str) -> String {
        match &self.bucket {
            None => self.alias_name.clone(),
            Some(bucket) if key.is_empty() => format!("{}/{bucket}", self.alias_name),
            Some(bucket) => format!("{}/{bucket}/{key}", self.alias_name),
        }
    }

    /// The bucket, or a usage error naming what was expected.
    pub fn bucket(&self) -> Result<&str, Error> {
        self.bucket.as_deref().ok_or_else(|| {
            Error::usage(format!(
                "`{}` is an alias: add a bucket, like {}/BUCKET",
                self.alias_name, self.alias_name
            ))
        })
    }

    /// Whether this names a place to put things (a bucket, or a key ending in `/`) rather
    /// than one object.
    pub fn is_folder(&self) -> bool {
        self.key.is_empty() || self.key.ends_with('/')
    }

    /// The key prefix that holds this "folder"'s objects: the key with a `/` at the end,
    /// or nothing for the whole bucket.
    pub fn folder_prefix(&self) -> String {
        folder_prefix(&self.key)
    }
}

/// `key` with a `/` at the end unless it's empty or has one.
pub fn folder_prefix(key: &str) -> String {
    if key.is_empty() || key.ends_with('/') {
        key.to_owned()
    } else {
        format!("{key}/")
    }
}

impl Target {
    /// Reads a command-line path: `ALIAS/…` when its first part is a known alias,
    /// otherwise a local path (write `./name` for a local folder named like an alias).
    pub fn parse(text: &str, aliases: &Aliases) -> Result<Self, Error> {
        let (first, rest) = text.split_once('/').unwrap_or((text, ""));
        let Some((alias, _)) = aliases.get(first) else {
            if text.is_empty() {
                return Err(Error::usage("a path can't be empty"));
            }
            return Ok(Self::Local(PathBuf::from(text)));
        };
        alias.check_usable(first)?;
        let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
        Ok(Self::Remote(Remote {
            alias_name: first.to_owned(),
            alias: Box::new(alias.clone()),
            bucket: (!bucket.is_empty()).then(|| bucket.to_owned()),
            key: key.to_owned(),
        }))
    }

    /// The remote this names, or a usage error saying `what` needs one.
    pub fn remote(self, what: &str) -> Result<Remote, Error> {
        match self {
            Self::Remote(remote) => Ok(remote),
            Self::Local(path) => Err(Error::usage(format!(
                "{what} needs ALIAS/BUCKET[/KEY], and `{}` isn't an alias (see `teifs alias ls`)",
                path.display()
            ))),
        }
    }
}

/// The last part of a key (`photos/cat.jpg` → `cat.jpg`).
pub fn base_name(key: &str) -> &str {
    key.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
}

/// The local path, under a folder, for the key `relative` (the part of a key below the
/// folder being copied), or an error when it can't safely be one: it would leave the
/// folder (`..`, a leading `/`), or has parts this system can't name.
pub fn local_path(relative: &str) -> Result<PathBuf, String> {
    let refuse = |why: &str| Err(format!("`{relative}` can't be a file name here: {why}"));
    if relative.is_empty() {
        return refuse("it's empty");
    }
    let mut path = PathBuf::new();
    for part in relative.split('/') {
        match part {
            "" => return refuse("it has an empty part (`//` or a leading `/`)"),
            "." | ".." => return refuse("it has a `.` or `..` part"),
            _ if part.contains('\0') => return refuse("it has a NUL character"),
            _ if cfg!(windows) && part.contains(['\\', ':']) => {
                return refuse("it has a `\\` or `:`, which name other places on Windows");
            }
            _ => path.push(part),
        }
    }
    // Belt and braces: every part must be a plain name.
    if !path.components().all(|c| matches!(c, Component::Normal(_))) {
        return refuse("it isn't a plain relative path");
    }
    Ok(path)
}

/// The key part for a local path relative to the folder being copied: its parts joined
/// with `/`.
pub fn relative_key(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| format!("{} isn't valid Unicode", path.display()))?,
            ),
            _ => return Err(format!("{} isn't a plain relative path", path.display())),
        }
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_become_paths_only_inside_the_folder() {
        assert_eq!(
            local_path("a/b/c.txt").unwrap(),
            Path::new("a").join("b").join("c.txt")
        );
        for bad in [
            "",
            "../x",
            "a/../../x",
            "/etc/passwd",
            "a//b",
            "./a",
            "a/.",
            "a\0b",
        ] {
            assert!(local_path(bad).is_err(), "{bad:?}");
        }
        #[cfg(windows)]
        for bad in ["a\\..\\x", "C:x", "a:stream"] {
            assert!(local_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn paths_become_keys_with_slashes() {
        let path = Path::new("a").join("b").join("c.txt");
        assert_eq!(relative_key(&path).unwrap(), "a/b/c.txt");
        assert!(relative_key(Path::new("../x")).is_err());
    }

    #[test]
    fn names_and_folders() {
        assert_eq!(base_name("photos/cat.jpg"), "cat.jpg");
        assert_eq!(base_name("photos/"), "photos");
        assert_eq!(base_name("cat.jpg"), "cat.jpg");
        assert_eq!(folder_prefix(""), "");
        assert_eq!(folder_prefix("a"), "a/");
        assert_eq!(folder_prefix("a/"), "a/");
    }
}
