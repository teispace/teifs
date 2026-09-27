# Architecture

A tour of the code for contributors: what each part does, how a request flows, and the
rules the design depends on. It describes the code as it is; when you change what it
says, change it in the same pull request.

## Bird's-eye view

TeiFS turns a folder (a **drive**) into an S3 endpoint. Each folder in the drive is a
bucket and each object is a plain file at its key's path. What S3 needs beyond the bytes
lives in two SQLite databases in `.teifs/`. The layout is specified in
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
crates/store    teifs-store    The storage engine: opening a drive (and upgrading its
                               format), buckets, staging and committing writes, reads,
                               listing in S3 order, copies, multipart uploads.
crates/s3       teifs-s3       The S3 operations: implements s3s's `S3` trait over a
                               store; checksums, S3 errors, continuation tokens.
crates/server   teifs-server   Credentials, the HTTP listener (HTTP/1.1 and HTTP/2),
                               graceful shutdown, and `Server::bind` / `run`, which the
                               command and embedders use.
apps/cli        teifs          The `teifs` command: parses arguments, calls the crates,
                               prints results.
```

Dependencies point one way: `types` ← `meta` ← `store` ← `s3` ← `server` ← `cli`.
Library crates never depend on the command line, and nothing depends on a user
interface, so the server can be embedded (Teitunnel will run it this way).

### The protocol layer: s3s

[s3s](https://github.com/s3s-project/s3s) turns HTTP requests into typed S3 operations and
back: routing, XML, SigV4 (headers, presigned URLs, chunked and trailer bodies) and the
S3 error format. TeiFS implements the `S3` trait in `teifs-s3` (`drive.rs`). Nothing
outside `teifs-s3` and `teifs-server` knows about s3s.

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
  gets a provisional ETag (`<hex>-1`) and a content type guessed from its name.
- Listing walks the bucket's folders in S3's byte order (`crates/store/src/list.rs`),
  so objects added outside TeiFS appear immediately.
- Folders created on purpose (a `key/` object) stay when their last file is deleted;
  folders created only to hold a file are removed with it.

## Opening a drive

`Store::open` (`crates/store/src/lib.rs`) canonicalizes the folder, clears
`.teifs/tmp/`, reads or creates `format.json` and upgrades older formats
(`crates/store/src/format.rs`), then opens `index.db` and `system.db`. A drive from a
newer release is refused.

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
