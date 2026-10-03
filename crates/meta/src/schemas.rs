//! The schemas are frozen: `schemas/<database>.json` records what every version of each
//! database's schema is (its tables, indexes and triggers, as SQLite keeps them), so a
//! released migration that's edited fails here. A new migration's version is recorded
//! with `UPDATE_SCHEMAS=1`, which adds versions and never changes one.
//!
//! And every version upgrades to the newest with rows in every table.

use std::{collections::BTreeMap, path::Path};

use rusqlite::Connection;

use crate::{db, index, system};

const DATABASES: [(&str, &[&str]); 2] =
    [("index", index::MIGRATIONS), ("system", system::MIGRATIONS)];

/// The schema, one `<type> <name>: <sql>` line per table, index and trigger.
fn schema(conn: &Connection) -> Vec<String> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master
             WHERE sql IS NOT NULL ORDER BY type, name",
        )
        .unwrap();
    statement
        .query_map([], |row| {
            Ok(format!(
                "{} {}: {}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn released_schemas_never_change() {
    let dir = tempfile::tempdir().unwrap();
    for (name, migrations) in DATABASES {
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("schemas/{name}.json"));
        let mut recorded: BTreeMap<usize, Vec<String>> = std::fs::read(&file)
            .map(|json| serde_json::from_slice(&json).unwrap())
            .unwrap_or_default();
        let mut added = false;
        for version in 1..=migrations.len() {
            let path = dir.path().join(format!("{name}-{version}.db"));
            let now = schema(&db::open(&path, &migrations[..version]).unwrap());
            match recorded.get(&version) {
                Some(then) => assert_eq!(
                    then, &now,
                    "{name}.db's migration {version} changed: released migrations never \
                     change; add a new one"
                ),
                None if std::env::var_os("UPDATE_SCHEMAS").is_some() => {
                    recorded.insert(version, now);
                    added = true;
                }
                None => panic!(
                    "{name}.db's schema version {version} isn't recorded: run this test \
                     with UPDATE_SCHEMAS=1"
                ),
            }
        }
        assert!(
            recorded.len() <= migrations.len(),
            "{name}.db's newest migrations are gone: released migrations stay"
        );
        if added {
            let json = serde_json::to_string_pretty(&recorded).unwrap();
            std::fs::write(&file, json + "\n").unwrap();
        }
    }
}

/// A value of the column's declared type.
fn value(declared: &str) -> &'static str {
    let declared = declared.to_ascii_uppercase();
    if declared.contains("INT") {
        "1"
    } else if declared.contains("BLOB") {
        "x'01'"
    } else if declared.contains("REAL") {
        "1.0"
    } else {
        "'1'"
    }
}

/// Puts a row in every table that takes one (foreign keys off: rows of their own; a
/// table whose checks refuse the made-up row stays empty), and returns how many each
/// has.
fn fill(conn: &Connection) -> BTreeMap<String, i64> {
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut counts = BTreeMap::new();
    for table in tables {
        let columns: Vec<(String, String)> = conn
            .prepare(&format!(
                "SELECT name, type FROM pragma_table_info('{table}')"
            ))
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let names: Vec<String> = columns.iter().map(|(n, _)| format!("\"{n}\"")).collect();
        let values: Vec<&str> = columns.iter().map(|(_, t)| value(t)).collect();
        let _ = conn.execute(
            &format!(
                "INSERT INTO \"{table}\" ({}) VALUES ({})",
                names.join(", "),
                values.join(", ")
            ),
            [],
        );
        let count = conn
            .query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |row| {
                row.get(0)
            })
            .unwrap();
        counts.insert(table, count);
    }
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    counts
}

#[test]
fn every_schema_version_upgrades_with_rows_in_it() {
    let dir = tempfile::tempdir().unwrap();
    for (name, migrations) in DATABASES {
        let mut filled = 0;
        for version in 1..migrations.len() {
            let path = dir.path().join(format!("{name}-{version}.db"));
            let before = fill(&db::open(&path, &migrations[..version]).unwrap());
            filled += before.values().filter(|&&n| n > 0).count();
            let conn = db::open(&path, migrations)
                .unwrap_or_else(|e| panic!("{name}.db from version {version}: {e}"));
            assert_eq!(
                schema(&conn),
                schema(
                    &db::open(&dir.path().join(format!("{name}-fresh.db")), migrations).unwrap()
                )
            );
            for (table, rows) in before {
                let now: i64 = conn
                    .query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |row| {
                        row.get(0)
                    })
                    .unwrap_or_else(|e| panic!("{name}.db's {table} after version {version}: {e}"));
                assert_eq!(
                    now, rows,
                    "{name}.db's {table} lost rows upgrading from {version}"
                );
            }
        }
        assert!(filled > 0, "{name}: no table took a row");
    }
}
