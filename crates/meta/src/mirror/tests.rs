use std::path::{Path, PathBuf};

use rusqlite::{Connection, params, types::Value};

use crate::{CopyState, Index, MetaError, System};

fn paths(dir: &Path, n: usize) -> Vec<PathBuf> {
    (0..n)
        .map(|i| {
            let drive = dir.join(format!("d{i}"));
            std::fs::create_dir_all(&drive).unwrap();
            drive.join("index.db")
        })
        .collect()
}

/// Every row of every table, in key order.
fn dump(path: &Path) -> Vec<(String, Vec<Vec<String>>)> {
    let conn = Connection::open(path).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    tables
        .into_iter()
        .map(|t| {
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
            let n = stmt.column_count();
            let mut rows: Vec<Vec<String>> = stmt
                .query_map([], |r| {
                    Ok((0..n)
                        .map(|i| format!("{:?}", r.get::<_, Value>(i).unwrap()))
                        .collect())
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            rows.sort();
            (t, rows)
        })
        .collect()
}

fn assert_equal(paths: &[PathBuf]) {
    let first = dump(&paths[0]);
    assert!(first.iter().any(|(_, rows)| !rows.is_empty()));
    for path in &paths[1..] {
        assert_eq!(dump(path), first, "{}", path.display());
    }
}

fn put_version(index: &Index, key: &[u8], seq: i64, latest: bool, size: i64) {
    index
        .conn
        .execute(
            "INSERT OR REPLACE INTO object_versions (bucket_id, key, seq, version_id, latest, delete_marker,
             object_id, size, etag, modified_ms, attrs, data)
             VALUES ('b', ?1, ?2, 'null', ?3, 0, NULL, ?4, 'e', 1, '{}', ?5)",
            params![key, seq, latest, size, vec![0u8, 1, 2]],
        )
        .unwrap();
}

/// A small, reproducible mix of writes: object versions (usage triggers), folder
/// objects, uploads (a rowid table) and their parts, updates and deletes, some in
/// batches, some alone.
fn workload(index: &Index, rounds: u64) {
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for round in 0..rounds {
        let k = (next() % 20).to_be_bytes();
        let seq = i64::try_from(round).unwrap();
        match next() % 6 {
            0 => put_version(index, &k, seq, true, i64::try_from(next() % 1000).unwrap()),
            1 => {
                index
                    .batch(|ix| {
                        ix.conn.execute(
                            "UPDATE object_versions SET latest = 0, size = size + 1 WHERE key = ?1",
                            [&k[..]],
                        )?;
                        put_version(ix, &k, seq, true, 7);
                        Ok(())
                    })
                    .unwrap();
            }
            2 => {
                index
                    .conn
                    .execute("DELETE FROM object_versions WHERE key = ?1", [&k[..]])
                    .unwrap();
            }
            3 => {
                index
                    .conn
                    .execute(
                        "INSERT OR REPLACE INTO objects (bucket, key, size, mtime_ns, ino, etag, attrs)
                         VALUES ('f', ?1, ?2, 1, 1, 'e', '{}')",
                        params![format!("k{}", k[7]), i64::try_from(next() % 100).unwrap()],
                    )
                    .unwrap();
            }
            4 => {
                let id = format!("u{}", next() % 5);
                index
                    .batch(|ix| {
                        ix.conn.execute(
                            "INSERT OR IGNORE INTO uploads (id, bucket, key, attrs, created_ms)
                             VALUES (?1, 'b', 'k', '{}', 1)",
                            [&id],
                        )?;
                        ix.conn.execute(
                            "INSERT OR REPLACE INTO parts VALUES (?1, ?2, 5, 'e', '{}', 1, NULL)",
                            params![id, i64::try_from(next() % 3).unwrap()],
                        )?;
                        Ok(())
                    })
                    .unwrap();
            }
            _ => {
                let id = format!("u{}", next() % 5);
                index
                    .batch(|ix| {
                        ix.conn
                            .execute("DELETE FROM parts WHERE upload_id = ?1", [&id])?;
                        ix.conn
                            .execute("DELETE FROM uploads WHERE id = ?1", [&id])?;
                        Ok(())
                    })
                    .unwrap();
            }
        }
        index.ship().unwrap();
    }
}

#[test]
fn copies_end_equal_to_the_primary_after_any_writes() {
    let dir = tempfile::tempdir().unwrap();
    let paths = paths(dir.path(), 3);
    let (index, opened) = Index::open_copies(&paths, 2, 2).unwrap();
    assert_eq!(opened.primary, 0);
    assert!(opened.failed.is_empty());
    workload(&index, 400);
    drop(index);
    assert_equal(&paths);
}

#[test]
fn nothing_is_shipped_inside_a_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let paths = paths(dir.path(), 2);
    let (index, _) = Index::open_copies(&paths, 1, 2).unwrap();
    index
        .batch(|ix| {
            put_version(ix, b"a", 1, true, 1);
            ix.ship()?;
            Ok(())
        })
        .unwrap();
    assert!(
        dump(&paths[1])
            .iter()
            .all(|(t, rows)| t == "teifs_copy" || rows.is_empty())
    );
    index.ship().unwrap();
    assert_equal(&paths);
}

#[test]
fn a_rolled_back_change_ships_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let paths = paths(dir.path(), 2);
    let (index, _) = Index::open_copies(&paths, 1, 2).unwrap();
    put_version(&index, b"kept", 1, true, 1);
    let failed: crate::Result<()> = index.batch(|ix| {
        put_version(ix, b"undone", 2, true, 1);
        Err(MetaError::Unmirrorable("on purpose".into()))
    });
    assert!(failed.is_err());
    index.ship().unwrap();
    let rows = dump(&paths[1]);
    let versions = &rows.iter().find(|(t, _)| t == "object_versions").unwrap().1;
    assert_eq!(versions.len(), 1);
    assert_equal(&paths);
}

#[test]
fn a_copy_behind_is_rebuilt_and_the_newest_is_the_primary() {
    let dir = tempfile::tempdir().unwrap();
    let all = paths(dir.path(), 3);
    {
        let (index, _) = Index::open_copies(&all, 2, 2).unwrap();
        workload(&index, 50);
    }
    // The first drive is down for a while; the others go on.
    {
        let (index, opened) = Index::open_copies(&all[1..], 2, 2).unwrap();
        assert_eq!(opened.primary, 0);
        put_version(&index, b"while d0 was down", 999, true, 3);
        index.ship().unwrap();
    }
    let (index, opened) = Index::open_copies(&all, 2, 2).unwrap();
    assert_eq!(opened.primary, 1, "the newest copy is written");
    assert_eq!(opened.rebuilt, vec![0]);
    workload(&index, 20);
    drop(index);
    assert_equal(&all);
}

#[test]
fn too_few_readable_copies_refuse_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let all = paths(dir.path(), 3);
    drop(Index::open_copies(&all, 2, 2).unwrap());
    std::fs::remove_dir_all(dir.path().join("d1")).unwrap();
    std::fs::remove_dir_all(dir.path().join("d2")).unwrap();
    match Index::open_copies(&all, 2, 2) {
        Err(MetaError::Copies {
            found: 1,
            needed: 2,
        }) => {}
        other => panic!("expected Copies, got {other:?}"),
    }
    // A missing drive's folder is never made.
    assert!(!dir.path().join("d1").exists());
}

#[test]
fn a_failed_copy_is_set_aside_below_quorum_fails_and_heal_rebuilds_it() {
    let dir = tempfile::tempdir().unwrap();
    let all = paths(dir.path(), 3);
    let (index, _) = Index::open_copies(&all, 2, 3).unwrap();
    put_version(&index, b"a", 1, true, 1);
    index.ship().unwrap();
    // Copy 2 can't be written: another writer holds it (past the busy timeout).
    let conn = Connection::open(&all[2]).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    put_version(&index, b"b", 2, true, 1);
    match index.ship() {
        Err(MetaError::Quorum {
            current: 2,
            needed: 3,
        }) => {}
        other => panic!("expected Quorum, got {other:?}"),
    }
    let states = index.copies().unwrap().states();
    assert!(matches!(states[1].1, CopyState::Failed(_)));
    drop(conn);
    let healed = index.heal_copies().unwrap();
    assert!(healed.iter().all(|(_, s)| *s == CopyState::Current));
    put_version(&index, b"c", 3, true, 1);
    index.ship().unwrap();
    drop(index);
    assert_equal(&all);
}

#[test]
fn two_writing_connections_keep_the_copies_equal() {
    let dir = tempfile::tempdir().unwrap();
    let all: Vec<PathBuf> = paths(dir.path(), 3)
        .into_iter()
        .map(|p| p.with_file_name("system.db"))
        .collect();
    let (store, _) = System::open_copies(&all, 2, 2).unwrap();
    let iam = System::attach(store.copies().unwrap()).unwrap();
    for i in 0..20 {
        let (by, other) = if i % 2 == 0 {
            (&store, &iam)
        } else {
            (&iam, &store)
        };
        by.conn
            .execute(
                "INSERT OR REPLACE INTO settings (name, value) VALUES (?1, ?2)",
                params![format!("s{}", i % 7), i],
            )
            .unwrap();
        other.ship().unwrap();
        by.ship().unwrap();
    }
    drop((store, iam));
    assert_equal(&all);
}
