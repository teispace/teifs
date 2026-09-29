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
│   ├── lock                  held by the one process that has the drive open
│   ├── index.db              the object index (SQLite, WAL mode)
│   ├── system.db             bucket settings (SQLite, WAL mode)
│   ├── backups/              copies made before upgrades
│   │   └── pre-format-<n>/
│   ├── buckets/<bucket id>/  object buckets' data files
│   │   └── <aa>/<bb>/<object id>
│   ├── tmp/                  bytes being written (emptied at every start)
│   ├── uploads/<id>/<part>   parts of multipart uploads in progress
│   ├── credentials.json      generated credentials, readable only by the owner
│   └── settings.toml         optional `teifs serve` settings (`teifs init`); never secrets
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
  names the disk treats as one: letter case on a case-insensitive disk, Unicode form on
  APFS and HFS+, short 8.3 names on NTFS).
- Names Windows can't hold are refused on Windows, and by default everywhere, so a drive
  can move between systems: device names in any case and with any extension (`CON`,
  `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM0`–`COM9`, `LPT0`–`LPT9` and their
  superscript-digit forms), any of `<>:"|?*` or a control character, and a name ending
  in `.` or a space. `serve --key-names host` lifts that outside Windows. Files with such
  names put there by other programs are still served; TeiFS only never creates them.
  Folder buckets can't be named after a device either.
- Symbolic links inside a bucket are never followed.
- `.teifs-tmp` at the top of a bucket is reserved: writes to a bucket on another disk
  than the drive stage there, so the last step is an atomic rename on that disk. It's
  never listed and is emptied at every start.

### Object buckets

Each version of an object is a row in `index.db`'s `object_versions`, which is
authoritative. Its bytes are a data file at `.teifs/buckets/<bucket id>/<aa>/<bb>/<object
id>`, where the object id is a UUIDv7 (32 hex digits) and `aa`, `bb` are its last four
digits. A data file holds exactly the object's bytes (for an encrypted object, its encrypted
packages as [ENCRYPTION_FORMAT.md](ENCRYPTION_FORMAT.md) describes; `size` is always the
size before encryption), then a footer:

| Part | Bytes |
|---|---|
| The object's bytes | `size` |
| Footer JSON: `bucket` (id), `key`, `object` (id), `size`, `etag`, `createdMs`, `attrs`, and for encrypted objects `crypt` (mode, sealed data key, SSE-C check), for multipart objects `parts` (part sizes, and part checksums except under SSE-KMS and SSE-C) | variable |
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
| `objects` | Folder buckets, per object: `bucket`, `key`, the file's `size`, `mtime_ns` and `ino` when it was recorded, its `etag`, `attrs` (JSON: content headers, user metadata, checksums and `checksumType`, absent for a whole-object checksum, `tags`, and `acl` when the object has one), and for multipart objects `parts` (JSON: each part's size and checksums). Rebuildable from the files, except the parts |
| `object_versions` | Object buckets, per version: `bucket_id`, `key` (bytes, so it sorts in S3's byte order), `seq`, `version_id` (`null` without versioning), `latest`, `delete_marker`, `object_id`, `size`, `etag`, `modified_ms`, `attrs`, and columns for encryption, parts and small objects kept in the row. Authoritative |
| `garbage` | Data files waiting to be removed |
| `uploads`, `parts` | Multipart uploads in progress and their parts; an encrypted upload keeps its sealed data key in `uploads.crypt`, and every upload the checksum its object gets in `uploads.checksum` (JSON: `algorithm`, `type` `FULL_OBJECT` or `COMPOSITE`, `requested`); an upload created with a size cap keeps it in `uploads.max_size` (bytes, all parts together; `NULL` without one) |
| `completed_uploads` | What each completed upload answered (ETag, size, checksums), kept 24 hours so a retried Complete gets the same answer |
| `uploads` | Multipart uploads in progress: id, bucket, key, owner, attributes, start time |
| `parts` | Their parts: number, size, ETag, checksums, upload time |

A row describes a file only while the file's **size and modification time** match what
the row recorded. The inode is recorded but not compared, so a drive copied or restored
with modification times preserved (`rsync -a`, `cp -p`, `tar`, most backup tools) keeps
all of its metadata. Times are compared at the coarser precision of the two values
(nanoseconds, 100 ns on NTFS, 10 ms on exFAT, 1 s on HFS+ and ext3), so a drive moved to
a file system that keeps coarser times keeps its metadata too; FAT's 2-second times are
the exception, and files copied to FAT are treated as changed. A file changed by anything other than TeiFS no longer matches its
row: until the background indexer reaches it, its ETag is a stable provisional one
shaped like a multipart ETag (`<hex>-1`), so clients never mistake it for the file's
MD5, and its content type is guessed from its name. The indexer then hashes the file.
If the content still matches the old row (its MD5, or for a multipart object the MD5s of
its recorded parts), the row is re-adopted with its metadata, tags and checksums; if not,
the file gets a new row with its MD5. Rows whose files are gone are removed.

On file systems that record modification times only to the second (FAT, HFS+, ext3), a
change that keeps the size and happens within the same second as the recorded write can
go unnoticed.

### `system.db`

What can't be rebuilt from the files.

| Table | Holds |
|---|---|
| `buckets` | Buckets TeiFS created or configured (a folder made by hand gets a record when a setting is saved): `id` (permanent), `name`, `layout` (`plain` for folder buckets, `object`), creation time, settings (JSON: `encryption` with the default mode, KMS key and whether SSE-C is blocked; `tags`; `cors`, the CORS rules; `policy`, the bucket policy as sent; `publicAccessBlock`; `ownership`, the Object Ownership setting; `acl`, the bucket's ACL) |

| `settings` | The drive's own settings, by `name`, each a JSON `value`: `accountPublicAccessBlock`, the account's Block Public Access settings |
| `iam_*` | IAM's users, access keys (secrets sealed by the drive's KMS), groups, policies and their versions, attachments and tags |

A bucket folder without a row is a folder bucket with default settings.

### Durability

Object bytes are written to `.teifs/tmp/`, synced to disk, and renamed into place (for
a bucket on another disk, copied to the bucket's `.teifs-tmp` first); the folder holding
them is synced too. A write that may only create the object (`If-None-Match: *`) is put
in place with a hard link, which the file system refuses if anything, even another
program's file, appeared there meanwhile. Both databases commit with SQLite's
`synchronous=FULL` (plus `fullfsync` on macOS, where a plain `fsync` doesn't reach the
disk). Every acknowledged write survives a power cut; a write in progress
leaves nothing behind. That's the default, `strict` durability; `serve --durability`
can relax it:

| Mode | Synced before a write is acknowledged | After a power cut |
|---|---|---|
| `strict` (default) | The file's data, its folder entry, the index | Nothing acknowledged is lost |
| `relaxed` | The file's data (index `synchronous=NORMAL`) | The last moments' writes may be lost |
| `none` | Nothing | Recent writes may be lost |

No mode can corrupt the drive: files still appear by atomic rename, and the index is
still a write-ahead-logged SQLite database. `system.db` and format upgrades are always
synced.

Only one process opens a drive at a time: it holds an exclusive lock on `.teifs/lock`,
released when it exits (even by a crash), and a second one is refused before it touches
anything.

When the disk is nearly full, writes whose size is known are refused up front with
`507 XTeiFSStorageFull` once they'd leave less than 0.1 % of the disk free (at least
64 MiB, at most 1 GiB), so deletes, which need a little room themselves, keep working.
A disk that fills up during a write gives the same answer, and the staged bytes are
removed.

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
