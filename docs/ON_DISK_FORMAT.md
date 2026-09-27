# On-disk format

This is the specification of how TeiFS stores a drive. It's a contract: any change to it
bumps the format version, and every release can open every drive any earlier release
wrote. `crates/store/src/format.rs` enforces it and `crates/store/tests/format.rs` proves
it against a drive written by each released format.

## Current format: 2

```
<drive>/
├── .teifs/                   TeiFS's own data
│   ├── format.json           which format this drive is in
│   ├── index.db              the object index (SQLite, WAL mode)
│   ├── system.db             bucket settings (SQLite, WAL mode)
│   ├── backups/              copies made before upgrades
│   │   └── pre-format-<n>/
│   ├── buckets/<bucket id>/  object buckets' data files
│   │   └── <aa>/<bb>/<object id>
│   ├── tmp/                  bytes being written (emptied at every start)
│   ├── uploads/<id>/<part>   parts of multipart uploads in progress
│   └── credentials.json      generated credentials, readable only by the owner
├── <bucket>/                 each folder is a folder bucket
│   └── <key path>            each object is a plain file at its key's path
└── …
```

### `format.json`

```json
{
  "format": 2,
  "drive": "0b7f3e5c-2d4e-4c1a-9f7e-6a3b2c1d0e9f",
  "created": "2026-09-27T12:00:00Z"
}
```

| Field | Meaning |
|---|---|
| `format` | The format version. A TeiFS that finds a higher number than it knows refuses to open the drive and says so; it never guesses. |
| `drive` | A random id, permanent for the life of the drive. |
| `created` | When the drive was first formatted (RFC 3339, UTC). |

The file is written to a temporary name, synced and renamed into place, so it's always
complete.

### Two kinds of bucket

| | Folder bucket | Object bucket |
|---|---|---|
| Where | A folder at the drive's root | `.teifs/buckets/<bucket id>/`, recorded in `system.db` |
| Objects | Plain files at their keys' paths | Data files named by object id |
| Keys | Those a file system can hold (below) | Any key S3 allows: 1 to 1024 bytes |
| Source of truth | The files; the index is rebuildable | The index; data files carry a footer to rebuild it |

A folder at the drive's root that has an object bucket's name isn't a bucket; it
becomes one if the object bucket is deleted.

### Folder buckets

- A **folder bucket** is a folder directly inside the drive whose name follows S3's
  bucket rules. A folder created by anything else is a bucket too. It may be a symbolic
  link to a folder elsewhere (another disk).
- An **object** is a regular file at the path its key names: key `2026/trip/a.jpg` in
  bucket `photos` is the file `photos/2026/trip/a.jpg`. A key ending in `/` is a folder.
- Keys that can't be files are refused: empty, `.` or `..` segments, `//`, a leading
  `/`, NUL or `\`, segments over 255 bytes, keys over 1024 bytes, and a name that
  collides with an existing file or folder (a file and a folder with the same name, or
  names that differ only in letter case on a case-insensitive disk).
- Symbolic links inside a bucket are never followed.
- `.teifs-tmp` at the top of a bucket is reserved: writes to a bucket on another disk
  than the drive stage there, so the last step is an atomic rename on that disk. It's
  never listed and is emptied at every start.

### Object buckets

Each version of an object is a row in `index.db`'s `object_versions`, which is
authoritative. Its bytes are a data file at `.teifs/buckets/<bucket id>/<aa>/<bb>/<object
id>`, where the object id is a UUIDv7 (32 hex digits) and `aa`, `bb` are its last four
digits. A data file holds exactly the object's bytes, then a footer:

| Part | Bytes |
|---|---|
| The object's bytes | `size` |
| Footer JSON: `bucket` (id), `key`, `object` (id), `size`, `etag`, `createdMs`, `attrs` | variable |
| Footer JSON length | 4, big-endian |
| Footer version (1) | 1 |
| Magic `TFSO` | 4 |

A write puts the data file in place (staged, synced, renamed, folder synced), then
replaces the row in one transaction that also queues the replaced file in `garbage`,
then removes that file. A crash leaves at most a data file no row refers to; queued
garbage is removed at the next start.

### `index.db`

| Table | Holds |
|---|---|
| `objects` | Folder buckets, per object: `bucket`, `key`, the file's `size`, `mtime_ns` and `ino` when it was recorded, its `etag`, and `attrs` (JSON: content headers, user metadata, checksums). Rebuildable from the files |
| `object_versions` | Object buckets, per version: `bucket_id`, `key` (bytes, so it sorts in S3's byte order), `seq`, `version_id` (`null` without versioning), `latest`, `delete_marker`, `object_id`, `size`, `etag`, `modified_ms`, `attrs`, and columns for encryption, parts and small objects kept in the row. Authoritative |
| `garbage` | Data files waiting to be removed |
| `uploads` | Multipart uploads in progress: id, bucket, key, owner, attributes, start time |
| `parts` | Their parts: number, size, ETag, checksums, upload time |

A row describes a file only while the file's **size and modification time** match what
the row recorded. The inode is recorded but not compared, so a drive copied or restored
with modification times preserved (`rsync -a`, `cp -p`, `tar`, most backup tools) keeps
all of its metadata. Times are compared at the coarser precision of the two values
(nanoseconds, 100 ns on NTFS, 10 ms on exFAT, 1 s on HFS+ and ext3), so a drive moved to
a file system that keeps coarser times keeps its metadata too; FAT's 2-second times are
the exception, and files copied to FAT are treated as changed. A file changed by anything other than TeiFS no longer matches its
row: until TeiFS reads it again, its ETag is a stable provisional one shaped like a
multipart ETag (`<hex>-1`), so clients never mistake it for the file's MD5, and its
content type is guessed from its name.

On file systems that record modification times only to the second (FAT, HFS+, ext3), a
change that keeps the size and happens within the same second as the recorded write can
go unnoticed.

### `system.db`

What can't be rebuilt from the files.

| Table | Holds |
|---|---|
| `buckets` | Buckets TeiFS created: `id` (permanent), `name`, `layout` (`plain` for folder buckets, `object`), creation time, settings (JSON) |

A bucket folder without a row is a folder bucket with default settings.

### Durability

Object bytes are written to `.teifs/tmp/`, synced to disk, and renamed into place (for
a bucket on another disk, copied to the bucket's `.teifs-tmp` first); the folder holding
them is synced too. A write that may only create the object (`If-None-Match: *`) is put
in place with a hard link, which the file system refuses if anything, even another
program's file, appeared there meanwhile. Both databases commit with SQLite's
`synchronous=FULL` (plus `fullfsync` on macOS, where a plain `fsync` doesn't reach the
disk). Every acknowledged write survives a power cut; a write in progress
leaves nothing behind.

## Upgrades

Opening a drive in an older format upgrades it: first a copy of the old metadata goes to
`.teifs/backups/pre-format-<new>/`, then the change is made, then `format.json` is
written. Writing `format.json` is the commit point: an upgrade interrupted before it is
redone from the start at the next open; one interrupted after it only has leftovers to
remove.

| From | To | What changes |
|---|---|---|
| 0 | 1 | `meta.db` (format 0's only database) becomes `index.db`; `system.db` and `format.json` are created |
| 1 | 2 | Both databases are copied to `backups/pre-format-2/`; buckets get ids; `index.db` gets `object_versions` and `garbage`; every existing bucket stays a folder bucket |

Format 0 is what TeiFS wrote before formats were recorded: a `.teifs/meta.db` and no
`format.json`.

To go back to an older release after an upgrade, restore the matching backup: stop
TeiFS, copy the databases from `.teifs/backups/pre-format-<n>/` back into `.teifs/`, and
set `format` in `format.json` to the older number (for format 0, remove `format.json`,
`index.db` and `system.db` and restore `meta.db`). Objects written in folder buckets
after the upgrade keep their bytes but lose metadata recorded since; object buckets
created after the upgrade don't exist in the older release.
