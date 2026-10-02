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
│   ├── backups/              copies of the databases
│   │   ├── pre-format-<n>/   made before an upgrade
│   │   ├── auto/<UTC time>/  daily snapshots (`serve --snapshots`): index.db, system.db, snapshot.json
│   │   └── pre-restore-<UTC time>/  the databases a `teifs restore` replaced
│   ├── buckets/<bucket id>/  object buckets' data files
│   │   └── <aa>/<bb>/<object id>
│   ├── tmp/                  bytes being written (emptied at every start)
│   ├── uploads/<id>/<part>   parts of multipart uploads in progress
│   ├── credentials.json      generated credentials, readable only by the owner
│   ├── config.kv             optional MinIO settings (`mc admin config set`), owner-only
│   ├── config-history/<id>.kv  optional: each change to them, owner-only
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
| Objects | Plain files at their keys' paths | Data files named by object id; small objects in their rows |
| Keys | Those a file system can hold (below) | Any key S3 allows: 1 to 1024 bytes |
| Source of truth | The files; the index is rebuildable | The index; data files carry a footer to rebuild it, but small objects live only in the index |

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
- With **versioning**, the file is always the current version; its id is the `objects`
  row's `version_id` (`NULL`, or a row that no longer matches the file, means `null`).
  Older versions and delete markers are `object_versions` rows under the bucket's id,
  with their bytes in data files at `.teifs/buckets/<bucket id>/…` as an object
  bucket's are, but **without a footer**: exactly the version's bytes. A file becomes an
  older version by a hard link to its data file (a copy where links can't go) made
  before anything replaces or removes it; an older version becomes the file again the
  same way back. So a crash can leave a version twice (the file wins), never lose one.
  A file changed by another program becomes the `null` version, as any file TeiFS
  didn't write is. Folder keys (`key/`) have no versions.

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
| Footer JSON: `bucket` (id), `key`, `object` (id), `size`, `etag`, `createdMs`, `attrs`, and for encrypted objects `crypt` (mode, sealed data key, DSSE-KMS's second sealed key, SSE-C check), for multipart objects `parts` (part sizes, part checksums except under SSE-KMS, DSSE-KMS and SSE-C, and for encrypted ones each part's `keys`: the number it was uploaded as and its key's `salt`), for a version other than `null` `version` (its id) | variable |
| Footer JSON length | 4, big-endian |
| Footer version (1) | 1 |
| Magic `TFSO` | 4 |

An object of at most 32 KiB as stored (encrypted, when it is), uploaded in one piece,
has no data file: its stored bytes, exactly what a data file would hold before its
footer, are in its row's `data` column, and its `object_id` is `NULL`. Writing it costs
only the index's own sync, shared with the writes recorded alongside it. Such objects
can't be rebuilt from files, so they are only as safe as `index.db` and its snapshots.
Objects uploaded in parts always get a data file.

The footer records the object as it was written. Later changes (tags, retention, legal
hold, an encryption update) are in the index only; an older sealed key in a footer still
opens its data, because KMS key versions are never deleted.

Each version but a small one has a data file of its own; a delete marker is a row
without one, so markers and small objects are what the files can't rebuild. Version ids are `null` or 32 hex
digits (a UUIDv7); a key's versions are ordered by `seq`, not by id, and exactly one
of them is `latest` while the key has any.

A write puts the data file in place (staged, synced, renamed, folder synced), then
adds the row (or replaces the `null` version's) in one transaction that also queues the replaced file in `garbage`,
then removes that file. A crash leaves at most a data file no row refers to; queued
garbage is removed at the next start. In a folder bucket the file itself goes in place
before its row, so a crash between the two leaves the new file with the old row: it's
read as a file changed outside TeiFS (a provisional ETag) until the index pass hashes
it. `crates/store/tests/crash.rs` kills a writing process at many moments and checks
all of this; the nightly run also runs it on [LazyFS](https://github.com/dsrhaslab/lazyfs),
which drops everything not yet synced at each kill, as a power cut would.

### `index.db`

| Table | Holds |
|---|---|
| `objects` | Folder buckets, per object: `bucket`, `key`, the file's `size`, `mtime_ns` and `ino` when it was recorded, its `etag`, `attrs` (JSON: content headers, user metadata, checksums and `checksumType`, absent for a whole-object checksum, `tags`, `acl` when the object has one, and for Object Lock `retention` with its `mode` and `untilMs` and `legalHold`, `true` or `false` once set), for multipart objects `parts` (JSON: each part's size and checksums), and `version_id` (the file's version id with versioning; `NULL` for `null`). Rebuildable from the files, except the parts and version ids |
| `object_versions` | Object buckets, per version, and folder buckets' older versions and delete markers: `bucket_id`, `key` (bytes, so it sorts in S3's byte order), `seq` (higher is newer), `version_id` (`null` for one written without versioning on), `latest`, `delete_marker`, `object_id`, `size`, `etag`, `modified_ms`, `attrs`, and columns for encryption, parts and small objects kept in the row. Authoritative |
| `garbage` | Data files waiting to be removed |
| `uploads`, `parts` | Multipart uploads in progress and their parts; an encrypted upload keeps its sealed data key in `uploads.crypt`, and every upload the checksum its object gets in `uploads.checksum` (JSON: `algorithm`, `type` `FULL_OBJECT` or `COMPOSITE`, `requested`); an upload created with a size cap keeps it in `uploads.max_size` (bytes, all parts together; `NULL` without one) |
| `completed_uploads` | What each completed upload answered (ETag, size, checksums), kept 24 hours so a retried Complete gets the same answer |
| `uploads` | Multipart uploads in progress: id, bucket, key, owner, attributes, start time |
| `parts` | Their parts: number, size, ETag, checksums, upload time, and for an encrypted part the salt in its key (hex) |

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
| `buckets` | Buckets TeiFS created or configured (a folder made by hand gets a record when a setting is saved): `id` (permanent), `name`, `layout` (`plain` for folder buckets, `object`), creation time, `versioning` (`enabled`, `suspended`, or `NULL` while it was never set), settings (JSON: `encryption` with the default mode, KMS key and whether SSE-C is blocked; `tags`; `cors`, the CORS rules; `policy`, the bucket policy as sent; `publicAccessBlock`; `ownership`, the Object Ownership setting; `acl`, the bucket's ACL; `abac`, `true` when its tags decide access; `objectLock`, present once Object Lock is on, with its `defaultRetention`: a `mode` and a `period` of `{"days": N}` or `{"years": N}`; `lifecycle`, the lifecycle rules as given: each rule's `id`, `enabled`, `filter` (`"all"`, `{"rulePrefix": P}` or `{"filter": C}` where `C` is `"empty"`, `{"prefix": P}`, `{"tag": {"key", "value"}}`, `{"greaterThan": N}`, `{"lessThan": N}` or `{"and": {"prefix", "tags", "greaterThan", "lessThan"}}`), `expiration` (`{"days": N}`, `{"date": ms}` or `{"expiredDeleteMarker": bool}`), `noncurrentExpiration` (`days`, `newerVersions`) and `abortUploadsAfterDays`, and the `transitionMinimumSize` header as set) |
| `settings` | The drive's own settings, by `name`, each a JSON `value`: `accountPublicAccessBlock`, the account's Block Public Access settings; `scrub`, the integrity scrub's state: `sinceMs` (when the drive was first scrubbed for), `current` (the pass under way: `startedMs`, counts of `versions`, `bytes`, `damaged` and `unverifiable`, `findings`, the first 100 damaged versions, and `cursor`, where it is) and `last` (the last finished pass, with `finishedMs`) |
| `iam_*` | IAM's users, access keys and MinIO service accounts (secrets sealed by the drive's KMS; a service account's parent (a user, the root user, an LDAP user's DN and name, or an OpenID Connect user as JSON: its provider's id, `sub`, `aud` and the policies' ids), status, policy, name, description, expiry and creation time), groups, roles (trust policy, longest session, boundary), OpenID Connect providers (URL, audiences, thumbprints), SAML providers (metadata, private keys sealed under the IAM key), policies and their versions, attachments and tags, and revocations of temporary credentials (`iam_revocations`: whom they act for, the token revoke type or empty for all, and the moment before which sessions issued are refused; dropped after 365 days) |

A bucket folder without a row is a folder bucket with default settings.

### `config.kv` and `config-history/`

The settings `mc admin config set` and `teifs admin config set` keep, in MinIO's text
form: one line per target, `SUBSYS[:TARGET] KEY=VALUE …`, values with spaces in double
quotes, every key of the target listed (`enable=off` for a target that's off). Only the
sub-systems TeiFS has settings for are kept: `identity_*`, `notify_*` and
`audit_webhook`. Each value stands for MinIO's variable (`MINIO_IDENTITY_LDAP_SERVER_ADDR`, `MINIO_IDENTITY_OPENID_CLIENT_ID_<TARGET>`),
read at start when nothing else sets it. It may hold passwords and tokens, so it's mode
`0600`, replaced atomically.

`config-history/` (mode `0700`) keeps each change set or imported as its own file
(`0600`), named by a version 7 UUID, which says when it was made and is what
`mc admin config restore` names. A change is the lines as they were sent. Restoring one
removes it, as MinIO does.

Neither file is in snapshots: a restore leaves them as they are.

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

### Snapshots

A running server copies both databases every day (and when asked, `teifs admin snapshot
take`) into `.teifs/backups/auto/<UTC time>/`, named like `20260930T045501.123Z`, with
SQLite's `VACUUM INTO`, which is consistent while the drive is in use. Each is written
to a hidden `.<name>.partial` folder, checked (`PRAGMA quick_check`), synced and renamed,
so a listed snapshot is complete; leftovers of an interrupted one are removed. Its
`snapshot.json` records `name`, `createdMs`, the `drive` id and its `format`. The newest
`--snapshots` (3 by default) are kept. A snapshot that would eat into the room kept free
is skipped and retried an hour later.

`teifs backup --to FOLDER` writes the same, into a folder of its own in `FOLDER`, from a
drive no server has open. `teifs restore --from` puts either back, on a drive no server
has open: it must be of the same drive (`drive`) and format, and both databases must
pass the quick check. The copies are staged beside the databases as
`<db>.restoring`, the current databases (with their `-wal` and `-shm` files) are moved
to `.teifs/backups/pre-restore-<UTC time>/`, and the copies renamed into place. Objects
written after the snapshot keep their bytes but not rows: folder buckets' files are
indexed again, while object buckets' data files stay on the disk, unlisted, until
`teifs repair --apply` gives them back.

### Repairs

`teifs repair` compares a drive's metadata with its files, on a drive no server has
open, and reports what disagrees; `--apply` sets right what's safe to. It first runs
SQLite's quick check on both databases and stops if either fails it: restore a snapshot
first.

| Found | With `--apply` |
|---|---|
| A data file no version refers to, not queued for removal | Its footer gives its version back, placed among its key's versions by `createdMs` (the key's newest becomes current). A `null` version replaced since keeps its place and the file is removed; a newer one replaces the recorded `null` version |
| A version whose data file is missing | Forgotten only with `--forget-missing` |
| A data file with no footer (a folder bucket's older version), whose footer names another bucket or file, or whose version id another file has | Left alone |
| A folder under `.teifs/buckets/` of no bucket | Left alone |
| A folder under `.teifs/uploads/` of no upload | Removed |

A lost `index.db` is rebuilt the same way: with it removed, the drive opens with an
empty index, `teifs repair --apply` gives every object bucket's versions back from their
footers, and folder buckets are indexed again when the drive is next served. What
footers don't record is lost: delete markers, and tags, retention and legal holds set
after a version was written.

To go back to an older release after an upgrade, restore the matching backup: stop
TeiFS, copy the databases from `.teifs/backups/pre-format-<n>/` back into `.teifs/`, and
set `format` in `format.json` to the older number (for format 0, remove `format.json`,
`index.db` and `system.db` and restore `meta.db`). Objects written in folder buckets
after the upgrade keep their bytes but lose metadata recorded since; object buckets
created after the upgrade don't exist in the older release.
