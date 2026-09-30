//! What each bucket holds: its objects, versions, delete markers and bytes, kept by
//! triggers in the index's own transactions, so reading them costs a row per bucket
//! however many objects there are, and they're never out of step with the rows.
//!
//! Object buckets (and folder buckets' older versions and delete markers) are counted
//! from `object_versions` by bucket id; folder buckets' current files from `objects` by
//! bucket name, which follows the files as the `index-folders` job finds them.

use std::collections::BTreeMap;

use crate::{Index, Result, index::from_db};

/// The counters, their triggers, and the counts of what's already there.
pub(crate) const MIGRATION: &str = "
    CREATE TABLE usage_versions (
        bucket_id      TEXT    PRIMARY KEY,
        objects        INTEGER NOT NULL,
        versions       INTEGER NOT NULL,
        delete_markers INTEGER NOT NULL,
        bytes          INTEGER NOT NULL
    ) WITHOUT ROWID;
    INSERT INTO usage_versions
        SELECT bucket_id,
               sum(latest != 0 AND delete_marker = 0),
               sum(delete_marker = 0),
               sum(delete_marker != 0),
               sum(CASE WHEN delete_marker = 0 THEN size ELSE 0 END)
        FROM object_versions GROUP BY bucket_id;
    CREATE TRIGGER usage_versions_added AFTER INSERT ON object_versions BEGIN
        INSERT INTO usage_versions VALUES (
            NEW.bucket_id,
            NEW.latest != 0 AND NEW.delete_marker = 0,
            NEW.delete_marker = 0,
            NEW.delete_marker != 0,
            CASE WHEN NEW.delete_marker = 0 THEN NEW.size ELSE 0 END)
        ON CONFLICT (bucket_id) DO UPDATE SET
            objects = objects + excluded.objects,
            versions = versions + excluded.versions,
            delete_markers = delete_markers + excluded.delete_markers,
            bytes = bytes + excluded.bytes;
    END;
    CREATE TRIGGER usage_versions_removed AFTER DELETE ON object_versions BEGIN
        UPDATE usage_versions SET
            objects = objects - (OLD.latest != 0 AND OLD.delete_marker = 0),
            versions = versions - (OLD.delete_marker = 0),
            delete_markers = delete_markers - (OLD.delete_marker != 0),
            bytes = bytes - CASE WHEN OLD.delete_marker = 0 THEN OLD.size ELSE 0 END
        WHERE bucket_id = OLD.bucket_id;
    END;
    CREATE TRIGGER usage_versions_changed
    AFTER UPDATE OF bucket_id, latest, delete_marker, size ON object_versions BEGIN
        UPDATE usage_versions SET
            objects = objects - (OLD.latest != 0 AND OLD.delete_marker = 0),
            versions = versions - (OLD.delete_marker = 0),
            delete_markers = delete_markers - (OLD.delete_marker != 0),
            bytes = bytes - CASE WHEN OLD.delete_marker = 0 THEN OLD.size ELSE 0 END
        WHERE bucket_id = OLD.bucket_id;
        INSERT INTO usage_versions VALUES (
            NEW.bucket_id,
            NEW.latest != 0 AND NEW.delete_marker = 0,
            NEW.delete_marker = 0,
            NEW.delete_marker != 0,
            CASE WHEN NEW.delete_marker = 0 THEN NEW.size ELSE 0 END)
        ON CONFLICT (bucket_id) DO UPDATE SET
            objects = objects + excluded.objects,
            versions = versions + excluded.versions,
            delete_markers = delete_markers + excluded.delete_markers,
            bytes = bytes + excluded.bytes;
    END;
    CREATE TABLE usage_files (
        bucket  TEXT    PRIMARY KEY,
        objects INTEGER NOT NULL,
        bytes   INTEGER NOT NULL
    ) WITHOUT ROWID;
    INSERT INTO usage_files SELECT bucket, count(*), sum(size) FROM objects GROUP BY bucket;
    CREATE TRIGGER usage_files_added AFTER INSERT ON objects BEGIN
        INSERT INTO usage_files VALUES (NEW.bucket, 1, NEW.size)
        ON CONFLICT (bucket) DO UPDATE SET
            objects = objects + 1,
            bytes = bytes + excluded.bytes;
    END;
    CREATE TRIGGER usage_files_removed AFTER DELETE ON objects BEGIN
        UPDATE usage_files SET objects = objects - 1, bytes = bytes - OLD.size
        WHERE bucket = OLD.bucket;
    END;
    CREATE TRIGGER usage_files_changed AFTER UPDATE OF bucket, size ON objects BEGIN
        UPDATE usage_files SET objects = objects - 1, bytes = bytes - OLD.size
        WHERE bucket = OLD.bucket;
        INSERT INTO usage_files VALUES (NEW.bucket, 1, NEW.size)
        ON CONFLICT (bucket) DO UPDATE SET
            objects = objects + 1,
            bytes = bytes + excluded.bytes;
    END;";

/// What a bucket, or part of one, holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Current objects: keys whose latest version isn't a delete marker.
    pub objects: u64,
    /// Versions that aren't delete markers, current ones included.
    pub versions: u64,
    /// Delete markers.
    pub delete_markers: u64,
    /// The bytes of every version.
    pub bytes: u64,
}

impl std::ops::Add for Usage {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            objects: self.objects + other.objects,
            versions: self.versions + other.versions,
            delete_markers: self.delete_markers + other.delete_markers,
            bytes: self.bytes + other.bytes,
        }
    }
}

/// Every bucket's counters, as the index keeps them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usages {
    /// Versions (every version of an object bucket; a folder bucket's older ones and
    /// delete markers), by bucket id.
    pub versions: BTreeMap<String, Usage>,
    /// Folder buckets' current files, by bucket name.
    pub files: BTreeMap<String, Usage>,
}

impl Index {
    /// Every bucket's counters.
    pub fn usage(&self) -> Result<Usages> {
        let mut usages = Usages::default();
        let mut versions = self.conn.prepare_cached(
            "SELECT bucket_id, objects, versions, delete_markers, bytes FROM usage_versions",
        )?;
        let rows = versions.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                Usage {
                    objects: from_db(r.get(1)?),
                    versions: from_db(r.get(2)?),
                    delete_markers: from_db(r.get(3)?),
                    bytes: from_db(r.get(4)?),
                },
            ))
        })?;
        for row in rows {
            let (id, usage) = row?;
            usages.versions.insert(id, usage);
        }
        let mut files = self
            .conn
            .prepare_cached("SELECT bucket, objects, bytes FROM usage_files")?;
        let rows = files.query_map([], |r| {
            let objects = from_db(r.get(1)?);
            Ok((
                r.get::<_, String>(0)?,
                Usage {
                    objects,
                    versions: objects,
                    delete_markers: 0,
                    bytes: from_db(r.get(2)?),
                },
            ))
        })?;
        for row in rows {
            let (bucket, usage) = row?;
            usages.files.insert(bucket, usage);
        }
        Ok(usages)
    }
}

#[cfg(test)]
mod tests {
    use teifs_types::{ObjectAttrs, Stamp};

    use super::*;
    use crate::{NULL_VERSION, Row, VersionRow};

    /// The counters, counted again from every row; buckets left empty are dropped.
    fn recounted(index: &Index) -> Usages {
        let mut again = Usages::default();
        let mut rows = index
            .conn
            .prepare("SELECT bucket_id, latest, delete_marker, size FROM object_versions")
            .unwrap();
        let rows = rows
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (id, latest, marker, size) = row.unwrap();
            let usage = again.versions.entry(id).or_default();
            usage.objects += u64::from(latest && !marker);
            usage.versions += u64::from(!marker);
            usage.delete_markers += u64::from(marker);
            usage.bytes += if marker { 0 } else { from_db(size) };
        }
        let mut rows = index
            .conn
            .prepare("SELECT bucket, size FROM objects")
            .unwrap();
        let rows = rows
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .unwrap();
        for row in rows {
            let (bucket, size) = row.unwrap();
            let usage = again.files.entry(bucket).or_default();
            usage.objects += 1;
            usage.versions += 1;
            usage.bytes += from_db(size);
        }
        again
    }

    fn kept(mut usages: Usages) -> Usages {
        usages.versions.retain(|_, u| *u != Usage::default());
        usages.files.retain(|_, u| *u != Usage::default());
        usages
    }

    fn version(bucket: &str, key: &str, id: &str, size: u64, marker: bool) -> VersionRow {
        VersionRow {
            bucket_id: bucket.into(),
            key: key.into(),
            version_id: id.into(),
            delete_marker: marker,
            object_id: (!marker).then(|| format!("o-{bucket}-{key}-{id}")),
            size,
            etag: "e".into(),
            modified_ms: 1,
            attrs: ObjectAttrs::default(),
            crypt: None,
            parts: None,
            inline: None,
            seq: 0,
            latest: false,
        }
    }

    fn file(size: u64) -> Row {
        Row {
            stamp: Stamp {
                size,
                mtime_ns: 1,
                ino: 1,
            },
            etag: "e".into(),
            attrs: ObjectAttrs::default(),
            parts: None,
            version_id: None,
        }
    }

    /// Every kind of write, in a long pseudo-random sequence; after each, the counters
    /// are what counting every row again gives.
    #[test]
    fn the_counters_always_match_the_rows() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("index.db")).unwrap();
        index.set_synchronous("OFF").unwrap();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        for step in 0..4000_i64 {
            let bucket = ["b1", "b2", "b3"][usize::try_from(next(3)).unwrap()];
            let key = format!("k{}", next(8));
            let id = format!("v{}", next(4));
            let size = next(1000);
            let to = format!("k{}", next(8));
            let row = |marker| version(bucket, &key, &id, if marker { 0 } else { size }, marker);
            match next(16) {
                0..=2 => drop(index.put_version(&row(false), step).unwrap()),
                3 => drop(index.put_version(&row(true), step).unwrap()),
                4 => drop(index.put_noncurrent(&row(false), step).unwrap()),
                5 => drop(index.delete_version(bucket, &key, &id, step).unwrap()),
                6 => {
                    let null = version(bucket, &key, NULL_VERSION, size, false);
                    index.put_version(&null, step).unwrap();
                }
                7 => drop(index.rename_null_version(bucket, &key, &to, step)),
                8 => drop(index.adopt_version(&row(false), next(2) == 0).unwrap()),
                9 => index.demote_versions(bucket, &key).unwrap(),
                10 => drop(index.set_latest(bucket, &key, &id)),
                11 if next(20) == 0 => {
                    index.forget_bucket_versions(bucket, step).unwrap();
                }
                11 | 12 => index.put(bucket, &key, &file(size)).unwrap(),
                13 => index.delete(bucket, &key).unwrap(),
                14 => drop(index.rename(bucket, &key, &to)),
                _ if next(30) == 0 => index.forget_bucket(bucket).unwrap(),
                _ => {}
            }
            assert_eq!(
                kept(index.usage().unwrap()),
                kept(recounted(&index)),
                "after step {step}"
            );
        }
    }

    #[test]
    fn counts_already_there_are_counted_when_the_index_is_upgraded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.db");
        {
            let index = Index::open(&path).unwrap();
            index
                .put_version(&version("b1", "k", "v1", 5, false), 1)
                .unwrap();
            index
                .put_version(&version("b1", "k", "v2", 7, false), 2)
                .unwrap();
            index
                .put_version(&version("b1", "gone", "v3", 0, true), 3)
                .unwrap();
            index.put("f", "a", &file(11)).unwrap();
            // As before the counters existed.
            index
                .conn
                .execute_batch(
                    "DROP TABLE usage_versions; DROP TABLE usage_files;
                     DROP TRIGGER usage_versions_added; DROP TRIGGER usage_versions_removed;
                     DROP TRIGGER usage_versions_changed; DROP TRIGGER usage_files_added;
                     DROP TRIGGER usage_files_removed; DROP TRIGGER usage_files_changed;",
                )
                .unwrap();
            index.conn.execute_batch(MIGRATION).unwrap();
        }
        let usage = Index::open(&path).unwrap().usage().unwrap();
        assert_eq!(
            usage.versions["b1"],
            Usage {
                objects: 1,
                versions: 2,
                delete_markers: 1,
                bytes: 12
            }
        );
        assert_eq!(usage.files["f"].bytes, 11);
    }
}
