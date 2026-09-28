# Architecture

A tour of the code for contributors: what each part does, how a request flows, and the
rules the design depends on. It describes the code as it is; when you change what it
says, change it in the same pull request.

## Bird's-eye view

TeiFS turns a folder (a **drive**) into an S3 endpoint with two kinds of bucket: **folder
buckets** (a folder at the drive's root, each object a plain file at its key's path) and
**object buckets** (every key S3 allows, stored by id under `.teifs/buckets/`). What S3
needs beyond the bytes lives in two SQLite databases in `.teifs/`. The layout is specified in
[ON_DISK_FORMAT.md](ON_DISK_FORMAT.md).

```
S3 client ──HTTP──▶ teifs-server ──▶ s3s (HTTP ↔ S3, signatures) ──▶ teifs-s3 (S3 operations)
                                                                        │
                                                                        ▼
                                                   teifs-store (buckets, objects, multipart)
                                                      │                      │
                                                      ▼                      ▼
                                             plain files on disk     teifs-meta (index.db, system.db)
```

## Code map

```
crates/types    teifs-types    Bucket names and object keys with their rules, object
                               attributes, file stamps, ETags. No I/O.
crates/meta     teifs-meta     SQLite: the object index (index.db) and the system
                               database (system.db). All SQL lives here.
crates/crypto   teifs-crypto   Encryption at rest (docs/ENCRYPTION_FORMAT.md): data keys,
                               sealing, 64 KiB authenticated packages, SSE-C keys, the
                               KMS trait and the local keyring. aws-lc-rs only.
crates/store    teifs-store    The storage engine: opening a drive (and upgrading its
                               format), folder buckets (folder.rs) and object buckets
                               (objects.rs) behind one API, staging and committing
                               writes, reads (ObjectBody), listings in S3 order,
                               copies, multipart uploads.
crates/s3       teifs-s3       The S3 operations: implements s3s's `S3` trait over a
                               store; checksums, S3 errors, continuation tokens.
crates/server   teifs-server   Credentials, the HTTP listener (HTTP/1.1 and HTTP/2),
                               graceful shutdown, and `Server::bind` / `run`, which the
                               command and embedders use.
apps/cli        teifs          The `teifs` command: parses arguments, calls the crates,
                               prints results. `src/client/` is its S3 client (aliases,
                               cp/mirror with parallel, resumable transfers) on the AWS
                               SDK, for TeiFS or any S3 service.
```

Dependencies point one way: `types` ← `meta` ← `store` ← `s3` ← `server` ← `cli`.
Library crates never depend on the command line, and nothing depends on a user
interface, so the server can be embedded (Teitunnel will run it this way).

### The protocol layer: s3s

[s3s](https://github.com/s3s-project/s3s) turns HTTP requests into typed S3 operations and
back: routing, XML, SigV4 (headers, presigned URLs, chunked and trailer bodies) and the
S3 error format. TeiFS implements the `S3` trait in `teifs-s3` (`drive.rs`). Nothing
outside `teifs-s3` and `teifs-server` knows about s3s.

## Two layouts, one API

`Store` resolves a bucket name to `Bucket::Folder` (a folder at the root) or
`Bucket::Object` (a record in `system.db`), and every operation dispatches on it. The
shared step is `Inner::commit_to`: a finished temporary file becomes the object `key`,
either renamed to its path (folder) or given a footer and stored by id with a row in
`object_versions` (object). Reads return an `ObjectBody`, which only ever yields the
object's own bytes (whole or a range). Copies between layouts clone the bytes where
the disk can. The tests in `crates/store/src/layout_tests.rs` run the same S3 behaviour
against both layouts.

## Encryption

`crates/store/src/sse.rs` turns what a write asks for (`Encryption`: none, SSE-S3,
SSE-KMS, SSE-C) into a data key through the KMS (or the customer's key) and records how
the object is encrypted (the row's `crypt` column and the data file's footer).
`Store::stage_for` gives a staged upload that encrypts as bytes arrive; `read_with`
unseals the key and returns an `ObjectBody` that decrypts only the packages a range
needs. Copies of encrypted objects are decrypted and encrypted again under the copy's own
key. The S3 layer (`crates/s3/src/sse.rs`) maps the SSE headers, the bucket's default
(`settings.rs`) and AWS's rules onto this. The server attaches a `LocalKms` keyring kept
outside the drive.

## How a write works

`PutObject` (`crates/s3/src/drive.rs` → `crates/store/src/lib.rs`):

1. **Stage.** The body streams into a new file in `.teifs/tmp/`, hashed as it goes (MD5
   for the ETag, plus any checksums the client sent or asked for). s3s has already
   checked the signature, and checks each chunk's signature as it streams.
2. **Verify.** Checksums the client sent must match what arrived, or the request fails
   with `BadDigest` and the staged file is deleted.
3. **Commit.** Under the drive's commit lock, the store checks preconditions against the
   current object, creates the parent folders (refusing to go through a file, a link or
   a name that differs only in case), renames the staged file into place, syncs the
   folder, and records the object's row in the index. The rename is atomic, so readers
   see either the old object or the new one.

A read opens the file first and then describes it from the index, so the bytes and the
metadata returned belong together even if the object is replaced during the read.

## Files are the source of truth

- A row in the index applies only while its file's size and modification time match
  (`Stamp::matches` in `crates/types/src/object.rs`). A file changed by anything else
  gets a provisional ETag (`<hex>-1`) and a content type guessed from its name, until
  the `index-folders` job (`crates/store/src/reconcile.rs`) hashes it: a file whose
  content still matches its old row (a restore that lost modification times) gets the
  row back with its metadata; any other gets a new row with its MD5. Rows of deleted
  files are forgotten.
- Listing a folder bucket walks its folders in S3's byte order
  (`crates/store/src/list.rs`), so objects added outside TeiFS appear immediately.
  Large folders' sorted contents are cached (`crates/store/src/folders.rs`) and used
  only while the folder's modification time is unchanged, so paging through a folder of
  a million files reads it once, not once per page; each page starts with a binary
  search.
  Object buckets list from the index with range queries, jumping past rolled-up common
  prefixes.
- Folders created on purpose (a `key/` object) stay when their last file is deleted;
  folders created only to hold a file are removed with it.

## Opening a drive

`Store::open` (`crates/store/src/lib.rs`) canonicalizes the folder, clears
`.teifs/tmp/`, reads or creates `format.json` and upgrades older formats
(`crates/store/src/format.rs`), then opens `index.db` and `system.db`. A drive from a
newer release is refused.

## Background jobs

A running server keeps the drive tidy with jobs (`crates/store/src/jobs.rs`), started by
`Server::run` and stopped at shutdown:

| Job | Does |
|---|---|
| `expire-uploads` | Aborts multipart uploads unfinished after `--upload-expiry` (7 days by default) |
| `sweep-staging` | Removes staged files no write has touched for an hour (a crashed client's leftovers) |
| `housekeeping` | Retries data files the garbage queue holds; forgets retry answers older than a day |
| `index-folders` | Walks folder buckets page by page: hashes files added or changed outside TeiFS, re-adopts rows of restored files, forgets rows of deleted ones; rests 30 minutes after a full pass |

Each job works in bounded steps on the blocking pool. After a step that did something it
sleeps for as long as the step took (so it uses at most half a core), and after a step
with nothing to do it waits for its idle interval. A job never loops without progress:
work that can't be done yet (a file still open on Windows) doesn't count. Each job's
steps, items and last error are kept for `teifs status`.

## Concurrency

- Blocking file and database work runs on Tokio's blocking pool (`Store::blocking`).
- One mutex around the index serves as the commit lock: whoever changes a file holds it
  until the file and its row agree again. The system database has its own lock, always
  taken after the index lock when both are needed.
- Reads don't take the commit lock while streaming.

## Errors

- `NameError` (types) for names that break the rules, `MetaError` (meta) for SQLite,
  `StoreError` (store) for everything the engine can report. `teifs-s3` maps each to the
  S3 error a client expects (`crates/s3/src/errors.rs`); unexpected I/O or database
  errors become `InternalError` and are logged.
- Request data never panics the server: `unwrap` is denied outside tests, and `expect`
  is used only for invariants.

## Tests

- Unit tests sit beside the code (`#[cfg(test)] mod tests`).
- `crates/store/tests/format.rs` opens a drive written by every earlier on-disk format.
- `crates/server/tests/sdk.rs` runs a real server and drives it with the official AWS
  SDK for Rust: signed requests, chunked bodies with trailer checksums, multipart,
  presigned URLs.
- Run everything with `cargo test --workspace`.
