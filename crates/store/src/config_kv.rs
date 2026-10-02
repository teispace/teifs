//! Where a drive keeps `MinIO`'s key-value configuration ([`teifs_types::config_kv`]):
//! `.teifs/config.kv`, and each change made to it in `.teifs/config-history/ID.kv`, so
//! one can be put back. Both are owner-only: they may hold passwords.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use teifs_types::config_kv::ConfigKv;
use uuid::Uuid;

use crate::{SYSTEM_DIR, create_private, replace_private};

/// The file's name in the drive's system folder.
const FILE: &str = "config.kv";
/// The folder of past changes in the drive's system folder.
const HISTORY: &str = "config-history";
/// A past change's file extension.
const EXTENSION: &str = "kv";

/// A change made to the configuration, as `MinIO`'s `ConfigHistoryEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigChange {
    /// What puts it back (`mc admin config restore ALIAS ID`).
    pub id: String,
    /// When it was made.
    pub created: SystemTime,
    /// The lines it set.
    pub text: String,
}

/// A drive's configuration files.
#[derive(Debug, Clone)]
pub struct ConfigFiles {
    system: PathBuf,
}

impl ConfigFiles {
    /// The files of the drive in `drive`.
    #[must_use]
    pub fn new(drive: &Path) -> Self {
        Self {
            system: drive.join(SYSTEM_DIR),
        }
    }

    /// The configuration file.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.system.join(FILE)
    }

    /// The configuration; empty when none was set.
    pub fn load(&self) -> io::Result<ConfigKv> {
        let path = self.path();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(ConfigKv::default()),
            Err(err) => return Err(err),
        };
        ConfigKv::parse(&text).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {err}", path.display()),
            )
        })
    }

    /// Replaces the configuration with `config`.
    pub fn save(&self, config: &ConfigKv) -> io::Result<()> {
        replace_private(&self.path(), config.to_text().as_bytes())
    }

    fn history(&self) -> PathBuf {
        self.system.join(HISTORY)
    }

    /// Where the change `id` is kept, if `id` can name one.
    fn change(&self, id: &str) -> Option<PathBuf> {
        let id = Uuid::try_parse(id).ok()?;
        Some(
            self.history()
                .join(format!("{}.{EXTENSION}", id.hyphenated())),
        )
    }

    /// Keeps `text`, a change just made, and says what puts it back.
    pub fn record(&self, text: &str) -> io::Result<String> {
        let history = self.history();
        create_folder(&history)?;
        let id = Uuid::now_v7().hyphenated().to_string();
        create_private(&history.join(format!("{id}.{EXTENSION}")), text.as_bytes())?;
        Ok(id)
    }

    /// The newest `count` changes (all of them when `None`), oldest first.
    pub fn changes(&self, count: Option<usize>) -> io::Result<Vec<ConfigChange>> {
        let entries = match fs::read_dir(self.history()) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        let mut ids = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            let Some(stem) = name
                .to_str()
                .and_then(|n| n.strip_suffix(&format!(".{EXTENSION}")))
            else {
                continue;
            };
            if let Ok(id) = Uuid::try_parse(stem) {
                ids.push(id);
            }
        }
        // Version 7 ids sort by when they were made.
        ids.sort_unstable();
        let skip = count.map_or(0, |count| ids.len().saturating_sub(count));
        let mut changes = Vec::new();
        for id in ids.into_iter().skip(skip) {
            let id = id.hyphenated().to_string();
            if let Some(change) = self.read(&id)? {
                changes.push(change);
            }
        }
        Ok(changes)
    }

    /// The change `id`, if it's kept.
    pub fn read(&self, id: &str) -> io::Result<Option<ConfigChange>> {
        let Some(path) = self.change(id) else {
            return Ok(None);
        };
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let created = Uuid::try_parse(id)
            .ok()
            .and_then(|id| id.get_timestamp())
            .map_or(SystemTime::UNIX_EPOCH, |stamp| {
                let (secs, nanos) = stamp.to_unix();
                SystemTime::UNIX_EPOCH + Duration::new(secs, nanos)
            });
        Ok(Some(ConfigChange {
            id: id.to_owned(),
            created,
            text,
        }))
    }

    /// Forgets the change `id`; whether it was kept.
    pub fn forget(&self, id: &str) -> io::Result<bool> {
        let Some(path) = self.change(id) else {
            return Ok(false);
        };
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }
}

/// Makes `path` an owner-only folder, if it isn't there.
fn create_folder(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(path) {
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    fn drive() -> (tempfile::TempDir, ConfigFiles) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(SYSTEM_DIR)).unwrap();
        let files = ConfigFiles::new(dir.path());
        (dir, files)
    }

    #[test]
    fn the_configuration_is_kept_owner_only() {
        let (_dir, files) = drive();
        assert!(files.load().unwrap().is_empty());
        let config =
            ConfigKv::parse("identity_ldap server_addr=a:636 lookup_bind_password=pw").unwrap();
        files.save(&config).unwrap();
        assert_eq!(files.load().unwrap(), config);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(files.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::write(files.path(), "storage_class standard=EC:2").unwrap();
        let err = files.load().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("config.kv"), "{err}");
    }

    #[test]
    fn changes_are_kept_until_forgotten() {
        let (_dir, files) = drive();
        assert!(files.changes(None).unwrap().is_empty());
        let ids: Vec<String> = ["one", "two", "three"]
            .iter()
            .map(|text| files.record(text).unwrap())
            .collect();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(files.history()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let all = files.changes(None).unwrap();
        assert_eq!(
            all.iter().map(|c| c.text.as_str()).collect::<Vec<_>>(),
            ["one", "two", "three"]
        );
        assert!(all[0].created <= all[2].created);
        assert!(all[2].created <= SystemTime::now());
        let newest = files.changes(Some(2)).unwrap();
        assert_eq!(newest[0].id, ids[1]);
        assert_eq!(files.read(&ids[0]).unwrap().unwrap().text, "one");

        assert!(files.forget(&ids[0]).unwrap());
        assert!(!files.forget(&ids[0]).unwrap());
        assert!(files.read(&ids[0]).unwrap().is_none());
        // Ids are only ever ids: never a path.
        assert!(files.read("../config").unwrap().is_none());
        assert!(!files.forget("../config.kv").unwrap());
        assert_eq!(files.changes(None).unwrap().len(), 2);
    }
}
