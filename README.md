# TeiFS

**S3 for your own disks.** Plain files, one binary, open source.

TeiFS serves folders over the S3 API. Every folder in a drive is a bucket and every object
is a plain file at the path its key names, so the same data is a normal folder in Finder,
Explorer or `ls`, and a bucket for the AWS CLI, rclone, restic, boto3 and every other S3
client. Back it up with anything. Stop using TeiFS and your files are still just files.

> **Early development.** The S3 core works and is tested with the official AWS SDK and
> CLI. Users and policies, versioning, Object Lock, encryption and a compatibility report
> from the standard S3 test suite are next. Don't store data you can't afford to lose
> with it yet.

## Why

MinIO used to have a mode that served plain folders over S3. It was removed in 2022, and
the project has since been archived. The alternatives store objects in their own formats,
need a cluster, or leave out large parts of S3. TeiFS aims to be:

- **Files first.** Your data stays in plain files you can open, back up and move. The
  metadata TeiFS keeps can be rebuilt from them.
- **Correct.** S3 behaviour is proven by tests, not claimed. The on-disk format is
  versioned, and every release opens every drive an earlier release wrote.
- **Secure by construction.** No default secrets, no secrets in logs, strict key-to-path
  rules. See the [security model](docs/SECURITY_MODEL.md).
- **One binary.** Server and command line in one program, for Linux, macOS and Windows.

## Quick start

```sh
cargo build --release
./target/release/teifs serve ~/Drive
```

The first run creates credentials in `~/Drive/.teifs/credentials.json` (readable only by
you) and prints the access key. Then use any S3 client:

```sh
export AWS_ENDPOINT_URL=http://127.0.0.1:9000
export AWS_ACCESS_KEY_ID=…      # printed by `teifs serve`
export AWS_SECRET_ACCESS_KEY=…  # in .teifs/credentials.json
aws s3 mb s3://photos
aws s3 sync ~/Pictures s3://photos/
```

`photos` is now the folder `~/Drive/photos`, with your pictures in it as plain files.

To set the keys yourself (on servers and in containers), use `TEIFS_ACCESS_KEY` and
`TEIFS_SECRET_KEY`. The secret is only read from the environment, so it never shows in a
process list.

## Commands

| Command | What it does |
|---|---|
| `teifs serve [DIR] [--listen ADDR] [--domain D] [--default-layout object\|folder] [--kms-keyring PATH] [--allow-sse-c]` | Serve a drive over S3 (default `127.0.0.1:9000`) |
| `teifs credentials [DIR]` | Show the access key and where the secret is |
| `teifs bucket list\|create [--layout object\|folder]\|remove` | Manage buckets without a server |
| `teifs ls BUCKET [PREFIX] [-r]` | List objects |
| `teifs key list\|create NAME\|rotate NAME` | Manage the KMS keys that encrypt objects |

## S3 support today

| Area | Supported |
|---|---|
| Buckets | list, create, head, delete, location, versioning status (always off) |
| Objects | put, get (ranges, conditional requests, response overrides), head, delete, delete many, copy (keep or replace metadata) |
| Listing | ListObjectsV2 and V1, prefixes, delimiters, pagination, `encoding-type=url` |
| Multipart | create, upload part, upload part copy, list parts, list uploads, complete, abort |
| Integrity | Content-MD5, and CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256 (also as trailers), returned with checksum mode |
| Auth | Signature V4 (headers and presigned URLs); path-style and virtual-hosted-style |

**Encryption at rest** in object buckets: SSE-S3 by default (as AWS), SSE-KMS with named
keys, and SSE-C with your own keys. The keys live in a keyring outside the drive
(`teifs key list|create|rotate`); **back it up**, because encrypted objects can't be read
without it.

**Not yet:** users and policies, versioning, Object Lock, lifecycle rules, tagging,
CORS, website hosting, event notifications, replication, several disks or machines. [COMPATIBILITY.md](docs/COMPATIBILITY.md) tracks what's proven.

**Two kinds of bucket.** An *object bucket* stores objects by id under `.teifs/` and
takes every key S3 allows. A *folder bucket* is a folder of plain files you can open
anywhere, with the limits below. Choose per bucket (`--layout`, or the
`x-teifs-bucket-layout` header on CreateBucket).

**Limits of folder buckets:**
- On a case-insensitive disk (the default on macOS and Windows), two keys that differ
  only in letter case can't both exist. The second is refused with
  `409 XTeiFSKeyConflict`.
- A key can't name a file and a folder at once (`a` and `a/b`), and keys with `.`, `..`
  or empty segments are refused.
- Symbolic links inside a bucket aren't served. A bucket itself may be a link to a folder
  elsewhere, such as another disk.

## How it stores things

Folder buckets are folders and their objects are files; object buckets keep their data
under `.teifs/buckets/`. What S3 needs beyond the bytes (ETags, content types, user
metadata, checksums, multipart uploads in progress) lives in `.teifs/` beside the
buckets. Writes are atomic: bytes go to `.teifs/tmp`, are synced to
disk and renamed into place, so a crash never leaves a half-written file. Files changed
outside TeiFS are objects too. The full specification is
[ON_DISK_FORMAT.md](docs/ON_DISK_FORMAT.md).

## Contributing

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a tour of the code. Security issues go
through [SECURITY.md](SECURITY.md), never public issues.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at
your option. Unless you explicitly state otherwise, any contribution you intentionally
submit for inclusion in TeiFS, as defined in the Apache-2.0 license, is dual licensed as
above, without any additional terms or conditions.
