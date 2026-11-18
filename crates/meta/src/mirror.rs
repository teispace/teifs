//! Copies of a database on several drives (a drive set's `index.db` and `system.db`),
//! kept equal to the one being written (the **primary**), so the metadata survives
//! losing drives as the objects' shards do.
//!
//! - Each connection that writes the primary gets TEMP triggers on every table (made
//!   from the schema, nothing stored) that note which rows a change touched in a TEMP
//!   table, and count changes in the copy's `teifs_copy.seq`.
//! - [`Copies::ship`], called once the change is committed, copies those rows' current
//!   state (or their absence) to every other copy, with the primary's `seq`, in one
//!   transaction per copy, all copies at once. Shipping state rather than statements
//!   makes it idempotent and order-free: two connections shipping in either order leave
//!   the copies as the primary is. Rows that tables' own triggers keep (usage counters)
//!   are put right by a second pass.
//! - A copy that fails is set aside until [`Copies::heal`] rebuilds it whole from the
//!   primary (`VACUUM INTO`, synced, renamed into place).
//! - Opening ([`open`]) reads every copy's `seq`: the highest is the primary, lower ones
//!   are rebuilt.
//!
//! Copies' foreign keys are off: the primary checked every change, and its cascades are
//! shipped as the rows they removed.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use rusqlite::{Connection, OptionalExtension, params_from_iter, types::Value};

use crate::{MetaError, Result, db};

/// Most columns a table's key may have.
const MAX_KEY: usize = 4;
/// The table recording a copy's change count. Never copied as a row.
const SEQ_TABLE: &str = "teifs_copy";

/// What a change is refused with while too few copies are current (raised by the
/// TEMP triggers, recognised by [`MetaError`]'s conversion).
pub(crate) const BLOCKED: &str = "teifs: too few copies of the database are current";

/// One table: its columns, and what identifies a row.
#[derive(Debug, Clone)]
struct Table {
    name: String,
    /// Every column, `rowid` first for a table keyed by it.
    columns: Vec<String>,
    /// How many of `key` columns, which are named in `key`.
    key: Vec<String>,
}

impl Table {
    fn by_rowid(&self) -> bool {
        self.key.len() == 1 && self.key[0] == "rowid"
    }

    fn select(&self) -> String {
        let columns = self.columns.iter().map(|c| quote(c)).collect::<Vec<_>>();
        format!(
            "SELECT {} FROM {} WHERE {}",
            columns.join(", "),
            quote(&self.name),
            self.matches()
        )
    }

    fn matches(&self) -> String {
        self.key
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{} IS ?{}", quote(c), i + 1))
            .collect::<Vec<_>>()
            .join(" AND ")
    }
}

fn quote(name: &str) -> String {
    if name == "rowid" {
        return name.to_owned();
    }
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// A row to make every copy hold as the primary does: its table, key, and values (all
/// columns), or `None` where the primary no longer has it.
type Change = (usize, Vec<Value>, Option<Vec<Value>>);

/// What happened to a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyState {
    /// Holds what the primary holds.
    Current,
    /// Set aside after a failure: its error. Rebuilt by [`Copies::heal`].
    Failed(String),
}

#[derive(Debug)]
struct Copy {
    path: PathBuf,
    conn: Option<Connection>,
    state: CopyState,
}

#[derive(Debug)]
struct State {
    primary: PathBuf,
    tables: Vec<Table>,
    copies: Vec<Copy>,
    synchronous: String,
    migrations: &'static [&'static str],
}

/// The other copies of a database, shared by every connection that writes its primary.
#[derive(Debug, Clone)]
pub struct Copies {
    state: Arc<Mutex<State>>,
    /// How many copies, the primary included, a change must reach.
    quorum: usize,
}

/// What opening a database's copies found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// Which of the paths given is the primary.
    pub primary: usize,
    /// Those rebuilt from the primary because they were behind, new or unreadable.
    pub rebuilt: Vec<usize>,
    /// Those that couldn't be opened or rebuilt (with why), for [`Copies::heal`].
    pub failed: Vec<(usize, String)>,
}

/// Opens the copies of a database at `paths` (creating new ones), migrating each with
/// `migrations`. The copy with the most changes is the primary; copies behind it are
/// rebuilt from it. At least `readable` copies must open, and every change from now on
/// must reach `quorum` copies (the primary included) or [`Copies::ship`] fails.
pub(crate) fn open(
    paths: &[PathBuf],
    migrations: &'static [&'static str],
    readable: usize,
    quorum: usize,
) -> Result<(Connection, Copies, Opened)> {
    let seqs: Vec<Option<i64>> = paths
        .iter()
        .map(|path| open_copy(path, migrations).and_then(|conn| seq(&conn)).ok())
        .collect();
    let found = seqs.iter().flatten().count();
    if found < readable.max(1) {
        return Err(MetaError::Copies {
            found,
            needed: readable.max(1),
        });
    }
    let newest = seqs.iter().flatten().copied().max().unwrap_or(0);
    let primary = seqs
        .iter()
        .position(|s| *s == Some(newest))
        .expect("a copy has the highest seq");
    let conn = db::open(&paths[primary], migrations)?;
    let tables = tables(&conn)?;
    let mut state = State {
        primary: paths[primary].clone(),
        tables,
        copies: Vec::new(),
        synchronous: "FULL".to_owned(),
        migrations,
    };
    let mut rebuilt = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        if i == primary {
            continue;
        }
        let mut copy = Copy {
            path: path.clone(),
            conn: None,
            state: CopyState::Current,
        };
        let done = if seqs[i] == Some(newest) {
            open_copy(path, migrations).map(|c| copy.conn = Some(c))
        } else {
            // Behind, new, or unreadable: a copy of the primary replaces it.
            state.rebuild(&conn, &mut copy).map(|()| rebuilt.push(i))
        };
        if let Err(err) = done {
            copy.state = CopyState::Failed(err.to_string());
        }
        state.copies.push(copy);
    }
    let failed = state
        .copies
        .iter()
        .zip((0..paths.len()).filter(|i| *i != primary))
        .filter_map(|(c, i)| match &c.state {
            CopyState::Failed(err) => Some((i, err.clone())),
            CopyState::Current => None,
        })
        .collect();
    let copies = Copies {
        state: Arc::new(Mutex::new(state)),
        quorum,
    };
    copies.attach(&conn)?;
    Ok((
        conn,
        copies,
        Opened {
            primary,
            rebuilt,
            failed,
        },
    ))
}

/// Opens a copy for shipping to: migrated, foreign keys off.
fn open_copy(path: &Path, migrations: &[&str]) -> Result<Connection> {
    let conn = db::open(path, migrations)?;
    conn.pragma_update(None, "foreign_keys", false)?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {SEQ_TABLE} (
            id  INTEGER PRIMARY KEY CHECK (id = 0),
            seq INTEGER NOT NULL
         );
         INSERT OR IGNORE INTO {SEQ_TABLE} VALUES (0, 0);"
    ))?;
    Ok(conn)
}

fn seq(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        &format!("SELECT seq FROM {SEQ_TABLE} WHERE id = 0"),
        [],
        |r| r.get(0),
    )?)
}

/// Every table of the database but SQLite's own and the seq table, with its key: its
/// primary key, or `rowid` for a rowid table without an `INTEGER PRIMARY KEY`.
fn tables(conn: &Connection) -> Result<Vec<Table>> {
    let mut stmt = conn.prepare(
        "SELECT name, sql FROM sqlite_schema WHERE type = 'table'
         AND name NOT LIKE 'sqlite_%' AND name != ?1 ORDER BY name",
    )?;
    let found: Vec<(String, String)> = stmt
        .query_map([SEQ_TABLE], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut tables = Vec::new();
    for (name, sql) in found {
        let without_rowid = sql.to_ascii_uppercase().contains("WITHOUT ROWID");
        let mut info = conn.prepare(&format!("PRAGMA table_info({})", quote(&name)))?;
        let columns: Vec<(String, String, i64)> = info
            .query_map([], |r| Ok((r.get(1)?, r.get(2)?, r.get(5)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut key: Vec<(i64, String)> = columns
            .iter()
            .filter(|(_, _, pk)| *pk > 0)
            .map(|(c, _, pk)| (*pk, c.clone()))
            .collect();
        key.sort();
        let mut names: Vec<String> = columns.iter().map(|(c, _, _)| c.clone()).collect();
        let integer_key = key.len() == 1
            && columns
                .iter()
                .any(|(c, t, pk)| *pk == 1 && *c == key[0].1 && t.eq_ignore_ascii_case("INTEGER"));
        let key: Vec<String> = if without_rowid || integer_key {
            key.into_iter().map(|(_, c)| c).collect()
        } else {
            names.insert(0, "rowid".to_owned());
            vec!["rowid".to_owned()]
        };
        if key.is_empty() || key.len() > MAX_KEY {
            return Err(MetaError::Unmirrorable(name));
        }
        tables.push(Table {
            name,
            columns: names,
            key,
        });
    }
    Ok(tables)
}

impl Copies {
    /// Gets `conn` (a writing connection to the primary) ready: TEMP triggers noting
    /// every row its changes touch.
    pub fn attach(&self, conn: &Connection) -> Result<()> {
        let state = self.lock();
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS teifs_changes (tbl INTEGER NOT NULL, k0, k1, k2, k3);
             CREATE TEMP TABLE IF NOT EXISTS teifs_blocked (id INTEGER PRIMARY KEY CHECK (id = 0));",
        )?;
        // While too few copies are current, every change is refused before it's made:
        // one acknowledged on fewer than the quorum could be lost with the drives
        // holding it.
        let refuse = format!(
            "SELECT RAISE(ABORT, '{BLOCKED}') WHERE EXISTS (SELECT 1 FROM temp.teifs_blocked);"
        );
        for (t, table) in state.tables.iter().enumerate() {
            let keys = |row: &str| {
                (0..MAX_KEY)
                    .map(|i| {
                        table
                            .key
                            .get(i)
                            .map_or_else(|| "NULL".to_owned(), |c| format!("{row}.{}", quote(c)))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let note = |row: &str| {
                format!(
                    "INSERT INTO temp.teifs_changes VALUES ({t}, {});",
                    keys(row)
                )
            };
            let bump = format!("UPDATE main.{SEQ_TABLE} SET seq = seq + 1 WHERE id = 0;");
            let on = format!("main.{}", quote(&table.name));
            conn.execute_batch(&format!(
                "CREATE TEMP TRIGGER IF NOT EXISTS \"teifs_copy_i{t}\" AFTER INSERT ON {on}
                 BEGIN {refuse} {} {bump} END;
                 CREATE TEMP TRIGGER IF NOT EXISTS \"teifs_copy_u{t}\" AFTER UPDATE ON {on}
                 BEGIN {refuse} {} {} {bump} END;
                 CREATE TEMP TRIGGER IF NOT EXISTS \"teifs_copy_d{t}\" AFTER DELETE ON {on}
                 BEGIN {refuse} {} {bump} END;",
                note("NEW"),
                note("OLD"),
                note("NEW"),
                note("OLD"),
            ))?;
        }
        Self::refuse_changes(conn, state.current() < self.quorum)
    }

    /// Makes `conn` refuse changes, or take them again.
    fn refuse_changes(conn: &Connection, refuse: bool) -> Result<()> {
        conn.execute(
            if refuse {
                "INSERT OR IGNORE INTO temp.teifs_blocked VALUES (0)"
            } else {
                "DELETE FROM temp.teifs_blocked"
            },
            [],
        )?;
        Ok(())
    }

    /// Whether fewer than the quorum of copies are current, so changes are refused.
    #[must_use]
    pub fn below_quorum(&self) -> bool {
        self.lock().current() < self.quorum
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Ships what `conn` changed since its last ship to every current copy. Does
    /// nothing inside a transaction (call it again once it's committed). Fails when
    /// fewer than the quorum of copies (the primary included) now hold the change: the
    /// change is committed on those that do, and later ones are refused
    /// ([`MetaError::TooFewCopies`]) until [`Copies::heal`] brings enough back.
    pub fn ship(&self, conn: &Connection) -> Result<()> {
        if !conn.is_autocommit() {
            return Ok(());
        }
        let changes = {
            let mut stmt =
                conn.prepare_cached("SELECT DISTINCT tbl, k0, k1, k2, k3 FROM temp.teifs_changes")?;
            stmt.query_map([], |r| {
                let t: i64 = r.get(0)?;
                let t = usize::try_from(t).unwrap_or(usize::MAX);
                let key = (1..=MAX_KEY)
                    .map(|i| r.get::<_, Value>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok((t, key))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut state = self.lock();
        let shipped = !changes.is_empty();
        if shipped {
            let seq = seq(conn)?;
            let mut rows: Vec<Change> = Vec::with_capacity(changes.len());
            for (t, mut key) in changes {
                let Some(table) = state.tables.get(t) else {
                    continue;
                };
                key.truncate(table.key.len());
                let row = conn
                    .prepare_cached(&table.select())?
                    .query_row(params_from_iter(&key), |r| {
                        (0..table.columns.len())
                            .map(|i| r.get::<_, Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .optional()?;
                rows.push((t, key, row));
            }
            let tables = state.tables.clone();
            std::thread::scope(|scope| {
                for copy in &mut state.copies {
                    if copy.state != CopyState::Current {
                        continue;
                    }
                    let (tables, rows) = (&tables, &rows);
                    scope.spawn(move || {
                        let Some(target) = copy.conn.as_mut() else {
                            return;
                        };
                        if let Err(err) = apply(target, tables, rows, seq) {
                            copy.state = CopyState::Failed(err.to_string());
                            copy.conn = None;
                        }
                    });
                }
            });
            conn.execute_batch("DELETE FROM temp.teifs_changes")?;
        }
        let current = state.current();
        Self::refuse_changes(conn, current < self.quorum)?;
        // Only a change shipped now can have reached too few (once below the quorum,
        // the next is refused before it's made).
        if shipped && current < self.quorum {
            return Err(MetaError::Quorum {
                current,
                needed: self.quorum,
            });
        }
        Ok(())
    }

    /// Rebuilds every failed copy from the primary (`conn`, which must not be in a
    /// transaction; nothing may write the primary meanwhile, which the caller's commit
    /// lock ensures). Which copies are current afterwards, by path.
    pub fn heal(&self, conn: &Connection) -> Result<Vec<(PathBuf, CopyState)>> {
        let mut state = self.lock();
        let mut copies = std::mem::take(&mut state.copies);
        for copy in &mut copies {
            if copy.state != CopyState::Current
                && let Err(err) = state.rebuild(conn, copy)
            {
                copy.state = CopyState::Failed(err.to_string());
            }
        }
        state.copies = copies;
        Self::refuse_changes(conn, state.current() < self.quorum)?;
        Ok(state.report())
    }

    /// Every copy but the primary, and its state.
    #[must_use]
    pub fn states(&self) -> Vec<(PathBuf, CopyState)> {
        self.lock().report()
    }

    /// The primary copy's path.
    #[must_use]
    pub fn primary(&self) -> PathBuf {
        self.lock().primary.clone()
    }

    /// Sets how far commits are synced on every copy (as [`crate::Index::set_synchronous`]).
    pub fn set_synchronous(&self, level: &str) -> Result<()> {
        let mut state = self.lock();
        level.clone_into(&mut state.synchronous);
        for copy in &state.copies {
            if let Some(conn) = &copy.conn {
                conn.pragma_update(None, "synchronous", level)?;
            }
        }
        Ok(())
    }
}

impl State {
    /// Copies holding every change, the primary included.
    fn current(&self) -> usize {
        1 + self
            .copies
            .iter()
            .filter(|c| c.state == CopyState::Current)
            .count()
    }

    fn report(&self) -> Vec<(PathBuf, CopyState)> {
        self.copies
            .iter()
            .map(|c| (c.path.clone(), c.state.clone()))
            .collect()
    }

    /// Replaces `copy` with a copy of the primary: written beside it, synced, renamed
    /// over it (its write-ahead log removed first), then opened.
    fn rebuild(&self, primary: &Connection, copy: &mut Copy) -> Result<()> {
        copy.conn = None;
        let path = &copy.path;
        let staged = with_suffix(path, ".rebuilding");
        // Never makes the folder: a drive that's gone must not become a folder on
        // whatever disk its mount point is on.
        let _ = fs::remove_file(&staged);
        primary.execute("VACUUM INTO ?1", [staged.to_string_lossy()])?;
        fs::File::open(&staged)
            .and_then(|f| f.sync_all())
            .map_err(MetaError::Io)?;
        for suffix in ["-wal", "-shm"] {
            match fs::remove_file(with_suffix(path, suffix)) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(MetaError::Io(err)),
            }
        }
        fs::rename(&staged, path).map_err(MetaError::Io)?;
        if let Some(dir) = path.parent() {
            sync_dir(dir).map_err(MetaError::Io)?;
        }
        let conn = open_copy(path, self.migrations)?;
        conn.pragma_update(None, "synchronous", &self.synchronous)?;
        copy.conn = Some(conn);
        copy.state = CopyState::Current;
        Ok(())
    }
}

/// Makes `target` hold `rows` as the primary does, and the primary's `seq`, in one
/// transaction. Two passes: rows that the copy's own triggers changed in the first
/// (usage counters) are put right in the second.
fn apply(target: &mut Connection, tables: &[Table], rows: &[Change], seq: i64) -> Result<()> {
    let tx = target.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for _ in 0..2 {
        for (t, key, row) in rows {
            let table = &tables[*t];
            let have = tx
                .prepare_cached(&table.select())?
                .query_row(params_from_iter(key), |r| {
                    (0..table.columns.len())
                        .map(|i| r.get::<_, Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .optional()?;
            match (have, row) {
                (Some(have), Some(row)) if have == *row => {}
                (Some(_), Some(row)) => {
                    let skip = usize::from(table.by_rowid());
                    let set = table.columns[skip..]
                        .iter()
                        .enumerate()
                        .map(|(i, c)| format!("{} = ?{}", quote(c), i + 1 + table.key.len()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let sql = format!(
                        "UPDATE {} SET {set} WHERE {}",
                        quote(&table.name),
                        table.matches()
                    );
                    let values = key.iter().chain(&row[skip..]);
                    tx.prepare_cached(&sql)?.execute(params_from_iter(values))?;
                }
                (None, Some(row)) => {
                    let columns = table.columns.iter().map(|c| quote(c)).collect::<Vec<_>>();
                    let marks = (1..=row.len()).map(|i| format!("?{i}")).collect::<Vec<_>>();
                    let sql = format!(
                        "INSERT INTO {} ({}) VALUES ({})",
                        quote(&table.name),
                        columns.join(", "),
                        marks.join(", ")
                    );
                    tx.prepare_cached(&sql)?.execute(params_from_iter(row))?;
                }
                (Some(_), None) => {
                    let sql = format!(
                        "DELETE FROM {} WHERE {}",
                        quote(&table.name),
                        table.matches()
                    );
                    tx.prepare_cached(&sql)?.execute(params_from_iter(key))?;
                }
                (None, None) => {}
            }
        }
    }
    tx.execute(
        &format!("UPDATE {SEQ_TABLE} SET seq = ?1 WHERE id = 0"),
        [seq],
    )?;
    tx.commit()?;
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
