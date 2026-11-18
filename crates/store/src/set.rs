//! Drive sets: several drives serving as one (`docs/ON_DISK_FORMAT.md`, format 3).
//!
//! Object buckets' data files are stored erasure-coded ([`teifs_erasure`]): one shard
//! file per drive, at the same path a single drive keeps the data file at. Each
//! database has a copy on every drive ([`teifs_meta::Copies`]). The drive holding the
//! primary copy of the index is the set's **home**: the store's `root` and `.teifs`
//! folder, where writes are staged and the other `.teifs` files live.

use std::{
    fs,
    io::{self, BufReader, BufWriter},
    path::{Path, PathBuf},
};

use teifs_erasure::{Geometry, Reader};

use crate::{
    SYSTEM_DIR,
    error::{Result, StoreError},
    format::{self, DriveFormat, SET_FORMAT, SetFormat},
    staged::sync_dir,
};

/// Most drives a set may have.
pub const MAX_DRIVES: usize = 16;

/// The parity a set of `drives` drives gets unless told otherwise (as MinIO and RustFS
/// choose it): 1 for 2–3 drives, 2 for 4–5, 3 for 6–7, 4 for 8 or more.
#[must_use]
pub fn default_parity(drives: usize) -> usize {
    match drives {
        0..=3 => 1,
        4 | 5 => 2,
        6 | 7 => 3,
        _ => 4,
    }
}

/// How many drives a change must reach: the data shards, one more when data and parity
/// are as many (so two halves of a set can't both take writes).
#[must_use]
pub fn write_quorum(data: usize, parity: usize) -> usize {
    if data == parity { data + 1 } else { data }
}

/// An open drive set.
#[derive(Debug)]
pub(crate) struct DriveSet {
    /// Each place's drive folder (canonical); `None` where the drive is down.
    roots: Vec<Option<PathBuf>>,
    home: usize,
    geometry: Geometry,
    quorum: usize,
    sync: bool,
    /// Each up drive's lock, held while the set is open.
    _locks: Vec<fs::File>,
}

/// What opening a set's drives found.
#[derive(Debug)]
pub(crate) struct Opened {
    pub set: DriveSet,
    /// The home drive's format record.
    pub format: DriveFormat,
}

impl DriveSet {
    /// Opens (or, when every drive is new, creates) the drive set made of `drives`, in
    /// any order: each member's `format.json` says its place. A new set gets `parity`
    /// (or [`default_parity`]). Drives that are missing or unreadable are down; the set
    /// opens while enough are up for its metadata (more than `drives - quorum`).
    pub(crate) fn open(drives: &[PathBuf], parity: Option<usize>, sync: bool) -> Result<Opened> {
        let n = drives.len();
        if !(2..=MAX_DRIVES).contains(&n) {
            return Err(StoreError::DriveSet(format!(
                "a set has 2 to {MAX_DRIVES} drives, not {n}"
            )));
        }
        let mut found: Vec<Option<(PathBuf, Option<DriveFormat>)>> = Vec::with_capacity(n);
        for drive in drives {
            found.push(read_member(drive)?);
        }
        given_once(&found)?;
        let formats: Vec<&DriveFormat> = found
            .iter()
            .flatten()
            .filter_map(|(_, f)| f.as_ref())
            .collect();
        if formats.is_empty() {
            if found.iter().any(Option::is_none) {
                return Err(StoreError::DriveSet(
                    "a new set needs every drive to be there".into(),
                ));
            }
            let roots: Vec<PathBuf> = found.into_iter().flatten().map(|(p, _)| p).collect();
            return Self::create(roots, parity.unwrap_or_else(|| default_parity(n)), sync);
        }
        let set = formats[0]
            .set
            .clone()
            .ok_or_else(|| StoreError::DriveSet("a drive isn't a set member".into()))?;
        if set.drives.len() != n {
            return Err(StoreError::DriveSet(format!(
                "the set has {} drives, and {n} are given",
                set.drives.len()
            )));
        }
        if parity.is_some_and(|p| p != set.parity) {
            return Err(StoreError::DriveSet(format!(
                "the set's parity is {}; it can't be changed",
                set.parity
            )));
        }
        let geometry = Geometry::new(set.data, set.parity, set.block_size)
            .map_err(|e| StoreError::DriveSet(e.to_string()))?;
        // Each drive in its recorded place; a new (empty) drive, or one that's down,
        // leaves its place empty for now.
        let mut places: Vec<Option<(PathBuf, DriveFormat)>> = vec![None; n];
        let mut roots: Vec<Option<PathBuf>> = vec![None; n];
        for (path, format) in found.into_iter().flatten() {
            let Some(format) = format else {
                continue;
            };
            let Some(member) = &format.set else {
                return Err(StoreError::DriveSet(format!(
                    "{} is a single drive, not a member of this set",
                    path.display()
                )));
            };
            if member.id != set.id {
                return Err(StoreError::DriveSet(format!(
                    "{} belongs to another set",
                    path.display()
                )));
            }
            let index = member.index;
            if index >= n || places[index].is_some() {
                return Err(StoreError::DriveSet(format!(
                    "{} claims a place another drive has",
                    path.display()
                )));
            }
            roots[index] = Some(path.clone());
            places[index] = Some((path, format));
        }
        let quorum = write_quorum(set.data, set.parity);
        let up_count = places.iter().flatten().count();
        if up_count + quorum <= n {
            return Err(StoreError::Quorum {
                found: up_count,
                needed: n - quorum + 1,
            });
        }
        let mut locks = Vec::new();
        for root in roots.iter().flatten() {
            locks.push(crate::lock_drive(&root.join(SYSTEM_DIR))?);
        }
        let home = roots
            .iter()
            .position(Option::is_some)
            .expect("enough drives are up");
        let format = places[home].clone().map(|(_, f)| f).expect("home is up");
        Ok(Opened {
            set: Self {
                roots,
                home,
                geometry,
                quorum,
                sync,
                _locks: locks,
            },
            format,
        })
    }

    /// Formats new drives as a set.
    fn create(roots: Vec<PathBuf>, parity: usize, sync: bool) -> Result<Opened> {
        let n = roots.len();
        if parity == 0 || parity > n / 2 {
            return Err(StoreError::DriveSet(format!(
                "parity must be 1 to {} for {n} drives",
                n / 2
            )));
        }
        let geometry = Geometry::new(n - parity, parity, Geometry::DEFAULT_BLOCK)
            .map_err(|e| StoreError::DriveSet(e.to_string()))?;
        let mut locks = Vec::new();
        for root in &roots {
            let system = root.join(SYSTEM_DIR);
            fs::create_dir_all(&system)?;
            locks.push(crate::lock_drive(&system)?);
        }
        let ids: Vec<String> = (0..n).map(|_| uuid::Uuid::new_v4().to_string()).collect();
        let set_id = uuid::Uuid::new_v4().to_string();
        let created = format::now_rfc3339();
        let mut home_format = None;
        for (i, root) in roots.iter().enumerate() {
            let record = DriveFormat {
                format: SET_FORMAT,
                drive: ids[i].clone(),
                created: created.clone(),
                set: Some(SetFormat {
                    id: set_id.clone(),
                    index: i,
                    drives: ids.clone(),
                    data: geometry.data(),
                    parity,
                    block_size: geometry.block(),
                }),
            };
            format::write_atomic(
                &root.join(SYSTEM_DIR).join(format::FORMAT_FILE),
                &serde_json::to_vec_pretty(&record).expect("the format serializes"),
            )?;
            if i == 0 {
                home_format = Some(record);
            }
        }
        Ok(Opened {
            set: Self {
                roots: roots.into_iter().map(Some).collect(),
                home: 0,
                geometry,
                quorum: write_quorum(n - parity, parity),
                sync,
                _locks: locks,
            },
            format: home_format.expect("a set has drives"),
        })
    }

    /// The home drive's folder.
    pub(crate) fn home(&self) -> &Path {
        self.roots[self.home]
            .as_deref()
            .expect("the home drive is up")
    }

    /// Makes the up drive whose copy of the index is at `primary` the set's home.
    pub(crate) fn set_home(&mut self, primary: &Path) {
        if let Some(home) = self
            .roots
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| primary.starts_with(r)))
        {
            self.home = home;
        }
    }

    /// Each up drive's `.teifs` folder (down drives have none).
    pub(crate) fn systems(&self) -> Vec<PathBuf> {
        self.roots
            .iter()
            .flatten()
            .map(|r| r.join(SYSTEM_DIR))
            .collect()
    }

    /// Where each up drive's copy of the database `name` is.
    pub(crate) fn database_paths(&self, name: &str) -> Vec<PathBuf> {
        self.systems().into_iter().map(|s| s.join(name)).collect()
    }

    /// How the set codes objects.
    pub(crate) fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// How many drives a change must reach.
    pub(crate) fn quorum(&self) -> usize {
        self.quorum
    }

    /// How many drives must be up for the metadata to open.
    pub(crate) fn readable(&self) -> usize {
        self.roots.len() - self.quorum + 1
    }

    /// The drives by place (`None` where one is down).
    pub(crate) fn drives(&self) -> &[Option<PathBuf>] {
        &self.roots
    }

    /// `path` (under the home drive) on every drive, by place (`None` where the drive
    /// is down); `None` for a path outside the home drive.
    fn on_drives(&self, path: &Path) -> Option<Vec<Option<PathBuf>>> {
        let rel = path.strip_prefix(self.home()).ok()?;
        Some(
            self.roots
                .iter()
                .map(|r| r.as_ref().map(|r| r.join(rel)))
                .collect(),
        )
    }

    /// Which drive shard `shard` of object `id` goes to: rotated by the id, so parity
    /// doesn't always land on the same drives.
    fn drive_of(&self, id: &[u8; 16], shard: usize) -> usize {
        let n = self.roots.len();
        let turn = usize::try_from(xxhash_rust::xxh3::xxh3_64(id) % n as u64).unwrap_or(0);
        (shard + turn) % n
    }

    /// Makes every drive's folder `dir` (under the home drive's `.teifs`).
    pub(crate) fn create_dirs(&self, dir: &Path) -> io::Result<()> {
        for path in self.on_drives(dir).into_iter().flatten().flatten() {
            fs::create_dir_all(&path)?;
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
        }
        Ok(())
    }

    /// Removes every drive's folder `dir`, as far as each can.
    pub(crate) fn remove_dirs(&self, dir: &Path) {
        for path in self.on_drives(dir).into_iter().flatten().flatten() {
            let _ = fs::remove_dir_all(path);
        }
    }

    /// Codes the file staged at `tmp` (object `id`'s data file) into a shard file on
    /// each drive at `to`'s place: staged in each drive's `.teifs/tmp`, synced, renamed
    /// into place, the folder synced. Needs the write quorum of drives; below it, every
    /// shard placed is removed again. `tmp` is removed either way.
    pub(crate) fn publish(&self, tmp: &Path, to: &Path, id: &str) -> Result<()> {
        let done = self.publish_shards(tmp, to, id);
        let _ = fs::remove_file(tmp);
        done
    }

    fn publish_shards(&self, tmp: &Path, to: &Path, id: &str) -> Result<()> {
        let id16 = object_id(id)?;
        let dests = self
            .on_drives(to)
            .ok_or(StoreError::InvalidRequest("a data file outside the drive"))?;
        let n = self.roots.len();
        let len = fs::metadata(tmp)?.len();
        let staged: Vec<Option<PathBuf>> = self
            .roots
            .iter()
            .map(|r| {
                r.as_ref().map(|r| {
                    r.join(SYSTEM_DIR)
                        .join("tmp")
                        .join(format!("{}.shard", uuid::Uuid::new_v4().simple()))
                })
            })
            .collect();
        // Shard `s` to drive `drive_of(s)`.
        let mut sinks: Vec<Option<BufWriter<fs::File>>> = (0..n)
            .map(|s| {
                let path = staged[self.drive_of(&id16, s)].as_ref()?;
                let file = fs::File::create(path).ok()?;
                Some(BufWriter::with_capacity(1 << 20, file))
            })
            .collect();
        let mut src = BufReader::with_capacity(1 << 20, fs::File::open(tmp)?);
        teifs_erasure::encode(self.geometry, id16, len, &mut src, &mut sinks)
            .map_err(io::Error::from)?;
        let sync = self.sync;
        let placed: Vec<bool> = std::thread::scope(|scope| {
            let handles: Vec<_> = sinks
                .into_iter()
                .enumerate()
                .map(|(s, sink)| {
                    let d = self.drive_of(&id16, s);
                    let (from, to) = (&staged[d], &dests[d]);
                    scope.spawn(move || -> io::Result<()> {
                        let (Some(from), Some(to)) = (from, to) else {
                            return Err(io::Error::other("the drive is down"));
                        };
                        let file = sink
                            .ok_or_else(|| io::Error::other("the drive failed"))?
                            .into_inner()
                            .map_err(io::IntoInnerError::into_error)?;
                        if sync {
                            file.sync_all()?;
                        }
                        drop(file);
                        let parent = to.parent().ok_or_else(|| io::Error::other("no folder"))?;
                        create_parents(parent, to)?;
                        fs::rename(from, to)?;
                        if sync {
                            sync_dir(parent)?;
                        }
                        Ok(())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().is_ok_and(|r| r.is_ok()))
                .collect()
        });
        for path in staged.iter().flatten() {
            let _ = fs::remove_file(path);
        }
        let found = placed.iter().filter(|p| **p).count();
        if found < self.quorum {
            for (s, ok) in placed.iter().enumerate() {
                if *ok && let Some(dest) = &dests[self.drive_of(&id16, s)] {
                    let _ = fs::remove_file(dest);
                }
            }
            return Err(StoreError::Quorum {
                found,
                needed: self.quorum,
            });
        }
        Ok(())
    }

    /// Opens object `id`'s data file at `path`'s place, from its shards on the drives
    /// that are up.
    pub(crate) fn open_file(&self, path: &Path, id: &str) -> Result<Reader<fs::File>> {
        let id16 = object_id(id)?;
        let paths = self
            .on_drives(path)
            .ok_or(StoreError::InvalidRequest("a data file outside the drive"))?;
        let mut missing = 0;
        let sources = paths
            .iter()
            .map(|p| match p.as_ref().map(fs::File::open) {
                Some(Ok(file)) => Some(file),
                Some(Err(err)) if err.kind() == io::ErrorKind::NotFound => {
                    missing += 1;
                    None
                }
                _ => None,
            })
            .collect();
        match Reader::open(id16, self.geometry, sources) {
            Ok(reader) => Ok(reader),
            // Gone from every drive: removed (a read racing a delete, as with a file).
            Err(_) if missing == paths.iter().flatten().count() => {
                Err(io::Error::from(io::ErrorKind::NotFound).into())
            }
            Err(teifs_erasure::Error::NotEnoughShards { needed, found }) => {
                Err(StoreError::Quorum { found, needed })
            }
            Err(err) => Err(io::Error::from(err).into()),
        }
    }

    /// Removes the shards at `path`'s place; whether none is left on the drives that
    /// are up (one on a drive that's down is removed when it's healed).
    pub(crate) fn remove(&self, path: &Path) -> bool {
        let Some(paths) = self.on_drives(path) else {
            return false;
        };
        paths.iter().flatten().all(|p| match fs::remove_file(p) {
            Ok(()) => true,
            Err(err) => err.kind() == io::ErrorKind::NotFound,
        })
    }

    /// Whether any drive has a shard at `path`'s place.
    pub(crate) fn exists(&self, path: &Path) -> bool {
        self.on_drives(path)
            .is_some_and(|paths| paths.iter().flatten().any(|p| p.exists()))
    }
}

/// Fails when a drive is given twice (by two paths to it, say).
fn given_once(found: &[Option<(PathBuf, Option<DriveFormat>)>]) -> Result<()> {
    let canonical: Vec<&PathBuf> = found.iter().flatten().map(|(p, _)| p).collect();
    for (i, a) in canonical.iter().enumerate() {
        if canonical[..i].contains(a) {
            return Err(StoreError::DriveSet(format!(
                "{} is given twice",
                a.display()
            )));
        }
    }
    Ok(())
}

/// Makes the folders above a shard on its drive, never the drive itself: a drive's
/// `.teifs` must already be there, so a drive that's gone doesn't become a folder on
/// whatever disk its mount point is on.
fn create_parents(parent: &Path, shard: &Path) -> io::Result<()> {
    if parent.is_dir() {
        return Ok(());
    }
    let system = shard
        .ancestors()
        .find(|a| a.file_name().is_some_and(|n| n == SYSTEM_DIR))
        .ok_or_else(|| io::Error::other("a shard outside a drive"))?;
    if !system.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the drive isn't there",
        ));
    }
    fs::create_dir_all(parent)
}

/// An object id (32 hex digits) as the 16 bytes shard headers carry.
fn object_id(id: &str) -> Result<[u8; 16]> {
    uuid::Uuid::try_parse(id)
        .map(|u| *u.as_bytes())
        .map_err(|_| StoreError::CorruptMetadata)
}

/// A drive given for a set: its folder (canonical) and its format record, if it has
/// one; `None` for a drive that isn't there.
fn read_member(drive: &Path) -> Result<Option<(PathBuf, Option<DriveFormat>)>> {
    let Ok(root) = fs::canonicalize(drive) else {
        return Ok(None);
    };
    if !root.is_dir() {
        return Ok(None);
    }
    let system = root.join(SYSTEM_DIR);
    match format::read(&system) {
        Ok(format) => {
            if format.format != SET_FORMAT || format.set.is_none() {
                return Err(StoreError::DriveSet(format!(
                    "{} is a single drive (format {}); a set is made of new, empty drives",
                    root.display(),
                    format.format
                )));
            }
            Ok(Some((root, Some(format))))
        }
        Err(StoreError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
            if system.join(format::INDEX_DB).exists() {
                return Err(StoreError::DriveSet(format!(
                    "{} has TeiFS data but no format record",
                    root.display()
                )));
            }
            let has_data = fs::read_dir(&root)?
                .flatten()
                .any(|e| e.file_name() != ".DS_Store" && e.file_name() != SYSTEM_DIR);
            if has_data {
                return Err(StoreError::DriveSet(format!(
                    "{} isn't empty; a set is made of new, empty drives",
                    root.display()
                )));
            }
            Ok(Some((root, None)))
        }
        Err(err) => Err(err),
    }
}
