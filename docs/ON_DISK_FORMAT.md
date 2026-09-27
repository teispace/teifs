# On-disk format

This is the specification of how TeiFS stores a drive. It's a contract: any change to it
bumps the format version, and every release can open every drive any earlier release
wrote. `crates/store/src/format.rs` enforces it and `crates/store/tests/format.rs` proves
it against a drive written by each released format.

## Current format: 1

```
<drive>/
├── .teifs/                   TeiFS's own data
│   ├── format.json           which format this drive is in
│   ├── index.db              the object index (SQLite, WAL mode)
│   ├── system.db             bucket settings (SQLite, WAL mode)
│   ├── backups/              copies made before upgrades
│   │   └── pre-format-1/meta.db
│   ├── tmp/                  bytes being written (emptied at every start)
│   ├── uploads/<id>/<part>   parts of multipart uploads in progress
│   └── credentials.json      generated credentials, readable only by the owner
├── <bucket>/                 each folder is a bucket
│   └── <key path>            each object is a plain file at its key's path
└── …
```

### `format.json`

```json
{
  "format": 1,
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

### Buckets and objects

- A **bucket** is a folder directly inside the drive whose name follows S3's bucket
  rules. A folder created by anything else is a bucket too. A bucket may be a symbolic
  link to a folder elsewhere (another disk).
- An **object** is a regular file at the path its key names: key `2026/trip/a.jpg` in
  bucket `photos` is the file `photos/2026/trip/a.jpg`. A key ending in `/` is a folder.
- Keys that can't be files are refused: empty, `.` or `..` segments, `//`, a leading
  `/`, NUL or `\`, segments over 255 bytes, keys over 1024 bytes, and a name that
  collides with an existing file or folder (a file and a folder with the same name, or
  names that differ only in letter case on a case-insensitive disk).
- Symbolic links inside a bucket are never followed.

### `index.db`

What S3 needs about an object that its file doesn't hold. **It can always be rebuilt
from the files**; losing it loses only what's listed as "attributes" below.

| Table | Holds |
|---|---|
| `objects` | Per object: `bucket`, `key`, the file's `size`, `mtime_ns` and `ino` when it was recorded, its `etag`, and `attrs` (JSON: content headers, user metadata, checksums) |
| `uploads` | Multipart uploads in progress: id, bucket, key, owner, attributes, start time |
| `parts` | Their parts: number, size, ETag, checksums, upload time |

A row describes a file only while the file's **size and modification time** match what
the row recorded. The inode is recorded but not compared, so a drive copied or restored
with modification times preserved (`rsync -a`, `cp -p`, `tar`, most backup tools) keeps
all of its metadata. A file changed by anything other than TeiFS no longer matches its
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
| `buckets` | Buckets TeiFS created: `name`, `layout` (`plain`), creation time, settings (JSON) |

A bucket folder without a row is a plain bucket with default settings.

### Durability

Object bytes are written to `.teifs/tmp/`, synced to disk, and renamed into place; the
folder holding them is synced too. Both databases commit with SQLite's
`synchronous=FULL`. Every acknowledged write survives a power cut; a write in progress
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

Format 0 is what TeiFS wrote before formats were recorded: a `.teifs/meta.db` and no
`format.json`.

To go back to an older release after an upgrade, restore the matching backup: stop
TeiFS, move `.teifs/backups/pre-format-<n>/meta.db` (or the files it lists) back into
`.teifs/`, and remove `format.json`, `index.db` and `system.db`. Objects written after the
upgrade keep their bytes but lose the metadata recorded since.
