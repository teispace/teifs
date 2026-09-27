# TeiDrive

Your folders, as a drive and as S3.

TeiDrive serves a folder over the S3 API. Every folder inside it is a bucket, and every
object is a plain file at the path its key names. Open the folder in Finder or Explorer,
back it up with anything, or stop using TeiDrive: your files are just files.

> Early development. The S3 core works; the web drive, previews and the Teitunnel
> integration come next.

## Quick start

```sh
cargo build --release
./target/release/teidrive serve ~/Drive
```

The first run creates credentials in `~/Drive/.teidrive/credentials.json` (readable only
by you) and prints the access key. Then use any S3 client:

```sh
export AWS_ENDPOINT_URL=http://127.0.0.1:9000
export AWS_ACCESS_KEY_ID=…      # printed by `teidrive serve`
export AWS_SECRET_ACCESS_KEY=…  # in .teidrive/credentials.json
aws s3 mb s3://photos
aws s3 sync ~/Pictures s3://photos/
```

`photos` is now the folder `~/Drive/photos`, with your pictures in it as plain files.

To set the keys yourself (servers, containers), use `TEIDRIVE_ACCESS_KEY` and
`TEIDRIVE_SECRET_KEY`. The secret is only read from the environment, so it never shows in
a process list.

## Commands

| Command | What it does |
|---|---|
| `teidrive serve [DIR] [--listen ADDR] [--domain D]` | Serve a drive over S3 (default `127.0.0.1:9000`) |
| `teidrive credentials [DIR]` | Show the access key and where the secret is |
| `teidrive bucket list\|create\|remove` | Manage buckets without a server |
| `teidrive ls BUCKET [PREFIX] [-r]` | List objects |

## How it stores things

- **Buckets are folders** directly in the drive; **objects are files**. A key ending in `/`
  is a folder.
- **Metadata lives beside the buckets** in `.teidrive/meta.db` (SQLite): ETags, content
  types, user metadata, checksums, and multipart uploads in progress.
- **Writes are atomic.** Bytes go to `.teidrive/tmp`, are synced to disk, and are renamed
  into place. A crash or a failed upload never leaves a half-written file.
- **Files changed outside TeiDrive are objects too.** Until TeiDrive has read one, its ETag
  is a provisional one shaped like a multipart ETag (`…-1`), so clients don't take it for
  an MD5. Its content type is guessed from the name.
- **Folders a file needed go when it goes**, as in S3. Folders created on purpose (a `key/`
  object, or later in the web drive) stay.

## S3 support

| Area | Supported |
|---|---|
| Buckets | list, create, head, delete, location, versioning status (always off) |
| Objects | put, get (ranges, conditional requests, response overrides), head, delete, delete many, copy (keep or replace metadata) |
| Listing | ListObjectsV2 and V1, prefixes, delimiters, pagination, `encoding-type=url` |
| Multipart | create, upload part, upload part copy, list parts, list uploads, complete, abort |
| Integrity | Content-MD5, and CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256 (also as trailers), returned with checksum mode |
| Auth | Signature V4 (headers and presigned URLs); path-style and virtual-hosted-style |

**Not yet:** versioning, bucket policies and ACLs, lifecycle rules, server-side encryption,
object lock, tagging, CORS configuration, website hosting, several nodes.

**Known limits of storing plain files:**
- On a case-insensitive disk (the default on macOS and Windows), two keys that differ only
  in letter case can't both exist. The second is refused with `409 XTeiDriveKeyConflict`.
- A key can't name a file and a folder at once (`a` and `a/b`).
- Symbolic links inside a bucket aren't served. A bucket itself may be a link to a folder
  elsewhere, such as another disk.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

The tests include an end-to-end suite that runs a real server and drives it with the
official AWS SDK.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at
your option.
