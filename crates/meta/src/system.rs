//! The system database (`.teifs/system.db`): what can't be rebuilt from the files.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::{Result, db};

/// The system database's schema, one entry per version.
const MIGRATIONS: &[&str] = &[
    // 1: buckets TeiFS created, with the layout their objects are stored in.
    "CREATE TABLE buckets (
        name       TEXT    PRIMARY KEY,
        layout     TEXT    NOT NULL,
        created_ms INTEGER NOT NULL,
        config     TEXT    NOT NULL DEFAULT '{}'
     ) WITHOUT ROWID;",
    // 2: a permanent id per bucket (object buckets store data under it; encryption binds
    //    keys to it).
    "ALTER TABLE buckets ADD COLUMN id TEXT;
     UPDATE buckets SET id = lower(hex(randomblob(16))) WHERE id IS NULL;
     CREATE UNIQUE INDEX buckets_by_id ON buckets (id);",
    // 3: IAM (teifs-iam owns the rules; these tables only keep its state).
    crate::iam::MIGRATION,
    // 4: the drive's own settings (JSON the store owns, by name), such as the account's
    //    Block Public Access.
    "CREATE TABLE settings (
        name  TEXT PRIMARY KEY,
        value TEXT NOT NULL
     ) WITHOUT ROWID;",
    // 5: IAM roles.
    crate::iam::ROLES_MIGRATION,
    // 6: IAM OpenID Connect providers.
    crate::iam::OIDC_MIGRATION,
    // 7: a bucket's versioning (`enabled`, `suspended`; NULL until first configured),
    //    read with its record on every request.
    "ALTER TABLE buckets ADD COLUMN versioning TEXT;",
    // 8: IAM's LDAP sign-in: policies mapped to DNs, and directory users' records.
    crate::iam::LDAP_MIGRATION,
    // 9: IAM SAML providers, their private keys and tags.
    crate::iam::SAML_MIGRATION,
    // 10: MinIO's status of IAM users and groups (a disabled one's keys and policies
    //     don't count).
    crate::iam::STATUS_MIGRATION,
    // 11: MinIO's service accounts: keys of a user (or the root user) narrowed by a
    //     policy, with a name, a description and an expiry.
    crate::iam::SERVICE_ACCOUNTS_MIGRATION,
    // 12: service accounts of LDAP users.
    crate::iam::LDAP_SERVICE_ACCOUNTS_MIGRATION,
];

/// How a bucket stores its objects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Layout {
    /// Each object is a plain file at its key's path, in a folder at the drive's root.
    #[default]
    Folder,
    /// Objects are stored by id under `.teifs/`, with every key S3 allows.
    Object,
}

impl Layout {
    fn as_str(self) -> &'static str {
        match self {
            Layout::Folder => "plain",
            Layout::Object => "object",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(Layout::Folder),
            "object" => Some(Layout::Object),
            _ => None,
        }
    }
}

/// A bucket's versioning, as S3 has it: once configured, it's enabled or suspended,
/// never again unversioned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Versioning {
    /// Never configured: every object has one version, `null`, and answers don't name it.
    #[default]
    Unversioned,
    /// Every write makes a new version; a delete adds a delete marker.
    Enabled,
    /// Writes replace the `null` version; a delete makes the `null` version a delete
    /// marker. Other versions are kept.
    Suspended,
}

impl Versioning {
    fn as_db(self) -> Option<&'static str> {
        match self {
            Versioning::Unversioned => None,
            Versioning::Enabled => Some("enabled"),
            Versioning::Suspended => Some("suspended"),
        }
    }

    fn from_db(value: Option<&str>) -> Self {
        match value {
            Some("enabled") => Versioning::Enabled,
            Some("suspended") => Versioning::Suspended,
            // Anything else can only come from a newer TeiFS, whose schema this build
            // refuses to open.
            _ => Versioning::Unversioned,
        }
    }

    /// Whether answers name versions: once versioning was ever configured.
    #[must_use]
    pub fn names_versions(self) -> bool {
        self != Versioning::Unversioned
    }
}

/// What's recorded about a bucket. A folder in the drive without a record is a plain
/// bucket with default settings (made outside TeiFS, or before records existed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketRecord {
    /// Its permanent id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// How it stores objects.
    pub layout: Layout,
    /// When TeiFS created it, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Its versioning.
    pub versioning: Versioning,
}

/// A drive's system database. Not `Sync`: the store keeps it behind a lock.
#[derive(Debug)]
pub struct System {
    pub(crate) conn: Connection,
}

impl System {
    /// Opens the system database at `path`, creating and migrating it.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            conn: db::open(path, MIGRATIONS)?,
        })
    }

    /// Records a bucket TeiFS just created, with its first settings (`config`), in one
    /// statement: a new bucket never exists without them.
    pub fn record_bucket(&self, record: &BucketRecord, config: &str) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO buckets (id, name, layout, created_ms, config, versioning)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (name) DO UPDATE SET id = excluded.id, layout = excluded.layout,
                   created_ms = excluded.created_ms, config = excluded.config,
                   versioning = excluded.versioning",
            )?
            .execute(params![
                record.id,
                record.name,
                record.layout.as_str(),
                record.created_ms,
                config,
                record.versioning.as_db(),
            ])?;
        Ok(())
    }

    /// Sets a recorded bucket's versioning; false when the bucket isn't recorded.
    pub fn set_bucket_versioning(&self, name: &str, versioning: Versioning) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("UPDATE buckets SET versioning = ?2 WHERE name = ?1")?
            .execute(params![name, versioning.as_db()])?
            > 0)
    }

    /// The record of a bucket, if TeiFS created it.
    pub fn bucket(&self, name: &str) -> Result<Option<BucketRecord>> {
        Ok(self
            .conn
            .prepare_cached(&format!("SELECT {RECORD} FROM buckets WHERE name = ?1"))?
            .query_row([name], record_from_row)
            .optional()?)
    }

    /// Every recorded bucket, by name.
    pub fn buckets(&self) -> Result<Vec<BucketRecord>> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {RECORD} FROM buckets ORDER BY name"))?;
        let rows = stmt.query_map([], record_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// A bucket's settings (JSON the store owns), if it's recorded.
    pub fn bucket_config(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT config FROM buckets WHERE name = ?1")?
            .query_row([name], |r| r.get(0))
            .optional()?)
    }

    /// The settings of the bucket recorded with this id (its permanent id), if any.
    pub fn bucket_config_by_id(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT config FROM buckets WHERE id = ?1")?
            .query_row([id], |r| r.get(0))
            .optional()?)
    }

    /// Replaces a recorded bucket's settings; false when the bucket isn't recorded.
    pub fn set_bucket_config(&self, name: &str, config: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("UPDATE buckets SET config = ?2 WHERE name = ?1")?
            .execute([name, config])?
            > 0)
    }

    /// Forgets a deleted bucket.
    pub fn forget_bucket(&self, name: &str) -> Result<()> {
        self.conn
            .prepare_cached("DELETE FROM buckets WHERE name = ?1")?
            .execute([name])?;
        Ok(())
    }

    /// A drive setting (JSON the store owns), if it's set.
    pub fn setting(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT value FROM settings WHERE name = ?1")?
            .query_row([name], |r| r.get(0))
            .optional()?)
    }

    /// Sets a drive setting, or removes it (`None`).
    pub fn set_setting(&self, name: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(value) => self
                .conn
                .prepare_cached(
                    "INSERT INTO settings (name, value) VALUES (?1, ?2)
                     ON CONFLICT (name) DO UPDATE SET value = excluded.value",
                )?
                .execute([name, value])?,
            None => self
                .conn
                .prepare_cached("DELETE FROM settings WHERE name = ?1")?
                .execute([name])?,
        };
        Ok(())
    }
}

/// The columns [`record_from_row`] reads.
const RECORD: &str = "id, name, layout, created_ms, versioning";

fn record_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<BucketRecord> {
    Ok(BucketRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        // An unknown layout can only come from a newer TeiFS, whose schema this build
        // refuses to open; folder is the safe reading.
        layout: Layout::parse(&r.get::<_, String>(2)?).unwrap_or_default(),
        created_ms: r.get(3)?,
        versioning: Versioning::from_db(r.get::<_, Option<String>>(4)?.as_deref()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_recorded_and_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let system = System::open(&dir.path().join("system.db")).unwrap();
        let record = BucketRecord {
            id: "id1".into(),
            name: "photos".into(),
            layout: Layout::Object,
            created_ms: 42,
            versioning: Versioning::Unversioned,
        };
        system.record_bucket(&record, r#"{"b":2}"#).unwrap();
        assert_eq!(system.bucket("photos").unwrap(), Some(record.clone()));
        assert_eq!(system.buckets().unwrap(), [record]);
        assert_eq!(
            system.bucket_config("photos").unwrap().as_deref(),
            Some(r#"{"b":2}"#)
        );
        assert!(system.set_bucket_config("photos", r#"{"a":1}"#).unwrap());
        assert_eq!(
            system.bucket_config("photos").unwrap().as_deref(),
            Some(r#"{"a":1}"#)
        );
        assert_eq!(
            system.bucket_config_by_id("id1").unwrap().as_deref(),
            Some(r#"{"a":1}"#)
        );
        assert_eq!(system.bucket_config_by_id("photos").unwrap(), None);
        assert!(!system.set_bucket_config("missing", "{}").unwrap());
        for versioning in [Versioning::Enabled, Versioning::Suspended] {
            assert!(system.set_bucket_versioning("photos", versioning).unwrap());
            assert_eq!(
                system.bucket("photos").unwrap().unwrap().versioning,
                versioning
            );
        }
        assert!(
            !system
                .set_bucket_versioning("missing", Versioning::Enabled)
                .unwrap()
        );
        system.forget_bucket("photos").unwrap();
        assert_eq!(system.bucket("photos").unwrap(), None);
    }

    #[test]
    fn settings_are_set_replaced_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.db");
        let system = System::open(&path).unwrap();
        assert_eq!(system.setting("a").unwrap(), None);
        system.set_setting("a", Some("1")).unwrap();
        system.set_setting("a", Some("2")).unwrap();
        system.set_setting("b", Some("3")).unwrap();
        drop(system);
        let system = System::open(&path).unwrap();
        assert_eq!(system.setting("a").unwrap().as_deref(), Some("2"));
        system.set_setting("a", None).unwrap();
        system.set_setting("missing", None).unwrap();
        assert_eq!(system.setting("a").unwrap(), None);
        assert_eq!(system.setting("b").unwrap().as_deref(), Some("3"));
    }
}
