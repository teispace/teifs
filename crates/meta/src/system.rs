//! The system database (`.teifs/system.db`): what can't be rebuilt from the files.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::{Result, db};

/// The system database's schema, one entry per version.
pub(crate) const MIGRATIONS: &[&str] = &[
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
    // 13: revoked temporary credentials (`MinIO`'s `revoke-tokens`).
    crate::iam::REVOCATIONS_MIGRATION,
    // 14: service accounts of OpenID Connect users.
    crate::iam::OPENID_SERVICE_ACCOUNTS_MIGRATION,
    // 15: batch jobs: each one's JSON (what it does, where it stands, how far it got),
    //     and its secrets sealed apart.
    "CREATE TABLE batch_jobs (
        id         TEXT    PRIMARY KEY,
        created_ms INTEGER NOT NULL,
        job        TEXT    NOT NULL,
        secrets    TEXT
     ) WITHOUT ROWID;",
    // 16: the results of S3 Batch Operations jobs' tasks, numbered in the manifest's
    //     order, kept for their completion reports: each a report's CSV line.
    "CREATE TABLE batch_results (
        job    TEXT    NOT NULL,
        seq    INTEGER NOT NULL,
        failed INTEGER NOT NULL,
        line   TEXT    NOT NULL,
        PRIMARY KEY (job, seq)
     ) WITHOUT ROWID;",
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

    /// Records a new batch job: its JSON and its sealed secrets.
    pub fn add_batch_job(
        &self,
        id: &str,
        created_ms: i64,
        job: &str,
        secrets: Option<&str>,
    ) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO batch_jobs (id, created_ms, job, secrets) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![id, created_ms, job, secrets])?;
        Ok(())
    }

    /// Replaces a batch job's JSON, keeping its secrets; whether it was there.
    pub fn set_batch_job(&self, id: &str, job: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("UPDATE batch_jobs SET job = ?2 WHERE id = ?1")?
            .execute([id, job])?
            > 0)
    }

    /// A batch job's JSON and sealed secrets.
    pub fn batch_job(&self, id: &str) -> Result<Option<(String, Option<String>)>> {
        Ok(self
            .conn
            .prepare_cached("SELECT job, secrets FROM batch_jobs WHERE id = ?1")?
            .query_row([id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }

    /// Every batch job's JSON, oldest first.
    pub fn batch_jobs(&self) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare_cached("SELECT job FROM batch_jobs ORDER BY created_ms, id")?;
        let jobs = statement
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(jobs)
    }

    /// Removes a batch job, and its tasks' results; whether it was there.
    pub fn remove_batch_job(&self, id: &str) -> Result<bool> {
        self.remove_batch_results(id)?;
        Ok(self
            .conn
            .prepare_cached("DELETE FROM batch_jobs WHERE id = ?1")?
            .execute([id])?
            > 0)
    }

    /// Records results of batch job `job`'s tasks: each its number, whether it failed,
    /// and its line, replacing a result of the same number (a page that ran again).
    pub fn add_batch_results(&self, job: &str, results: &[(u64, bool, String)]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT OR REPLACE INTO batch_results (job, seq, failed, line)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for (seq, failed, line) in results {
                let seq = i64::try_from(*seq).unwrap_or(i64::MAX);
                insert.execute(params![job, seq, failed, line])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Up to `limit` results of `job`'s tasks that failed (or succeeded), numbered after
    /// `after`, in order: each its number and line.
    pub fn batch_results(
        &self,
        job: &str,
        failed: bool,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, String)>> {
        let after = after.map_or(-1, |a| i64::try_from(a).unwrap_or(i64::MAX));
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.conn.prepare_cached(
            "SELECT seq, line FROM batch_results
             WHERE job = ?1 AND failed = ?2 AND seq > ?3 ORDER BY seq LIMIT ?4",
        )?;
        let results = statement
            .query_map(params![job, failed, after, limit], |r| {
                Ok((u64::try_from(r.get::<_, i64>(0)?).unwrap_or(0), r.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(results)
    }

    /// Removes batch job `job`'s tasks' results; how many.
    pub fn remove_batch_results(&self, job: &str) -> Result<usize> {
        Ok(self
            .conn
            .prepare_cached("DELETE FROM batch_results WHERE job = ?1")?
            .execute([job])?)
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

    #[test]
    fn batch_jobs_are_added_changed_listed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.db");
        let system = System::open(&path).unwrap();
        system.add_batch_job("b", 20, "{\"n\":1}", None).unwrap();
        system
            .add_batch_job("a", 30, "{\"n\":2}", Some("sealed"))
            .unwrap();
        assert!(system.add_batch_job("a", 40, "{}", None).is_err());
        assert!(system.set_batch_job("b", "{\"n\":3}").unwrap());
        assert!(!system.set_batch_job("missing", "{}").unwrap());
        drop(system);
        let system = System::open(&path).unwrap();
        assert_eq!(system.batch_jobs().unwrap(), ["{\"n\":3}", "{\"n\":2}"]);
        assert_eq!(
            system.batch_job("a").unwrap(),
            Some(("{\"n\":2}".to_owned(), Some("sealed".to_owned())))
        );
        assert_eq!(system.batch_job("missing").unwrap(), None);
        assert!(system.remove_batch_job("a").unwrap());
        assert!(!system.remove_batch_job("a").unwrap());
        assert_eq!(system.batch_jobs().unwrap(), ["{\"n\":3}"]);
    }

    #[test]
    fn batch_results_are_kept_in_order_until_their_job_goes() {
        let dir = tempfile::tempdir().unwrap();
        let system = System::open(&dir.path().join("system.db")).unwrap();
        system.add_batch_job("j", 1, "{}", None).unwrap();
        let line = |n: u64| format!("line {n}");
        let results: Vec<_> = (0..5).map(|n| (n, n % 2 == 1, line(n))).collect();
        system.add_batch_results("j", &results).unwrap();
        system
            .add_batch_results("other", &[(0, false, "x".into())])
            .unwrap();
        // A page that ran again replaces its results.
        system
            .add_batch_results("j", &[(4, true, "again".into())])
            .unwrap();
        let ok = system.batch_results("j", false, None, 10).unwrap();
        assert_eq!(ok, [(0, line(0)), (2, line(2))]);
        let failed = system.batch_results("j", true, None, 10).unwrap();
        assert_eq!(failed, [(1, line(1)), (3, line(3)), (4, "again".into())]);
        assert_eq!(
            system.batch_results("j", true, Some(1), 1).unwrap(),
            [(3, line(3))]
        );
        assert!(
            system
                .batch_results("j", true, Some(4), 10)
                .unwrap()
                .is_empty()
        );
        assert!(system.remove_batch_job("j").unwrap());
        assert!(
            system
                .batch_results("j", true, None, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(system.remove_batch_results("other").unwrap(), 1);
    }
}
