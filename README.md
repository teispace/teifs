# TeiFS

**S3 for your own disks.** AWS-compatible object storage in one binary, open source.

TeiFS is an S3 server for your own machines. By default it behaves like AWS S3: any key
S3 allows, and every object encrypted at rest (SSE-S3), with SSE-KMS (a local keyring,
Vault or OpenBao) and SSE-C when you want them. When you'd rather keep plain files, a
bucket can instead be a **folder bucket**: a normal folder in Finder, Explorer or `ls`
that is also a bucket for the AWS CLI, rclone, restic, boto3 and every other S3 client.

> **Early development.** The S3 core, encryption and both bucket kinds work and are
> tested with the official AWS SDK, the AWS CLI and the ceph/s3-tests suite. Users and
> policies, versioning, Object Lock and lifecycle rules are next. Don't store data you
> can't afford to lose with it yet.

## Why

MinIO, the usual self-hosted S3, dropped its admin console and binaries and was archived
in 2026; it had already removed the mode that served plain folders. The alternatives need
a cluster, leave out large parts of S3, or keep objects in formats you can't open. TeiFS
aims to be:

- **AWS-compatible by default.** S3's behaviour and defaults, proven by tests, not
  claimed: encryption at rest on, SSE-C blocked until you allow it, AWS's error codes.
- **Plain files when you want them.** Folder buckets keep your data as files you can
  open, back up and move; the metadata TeiFS keeps can be rebuilt from them.
- **Secure by construction.** No default secrets, no secrets in logs, keys kept off the
  drive, authenticated encryption. See the [security model](docs/SECURITY_MODEL.md).
- **Durable and upgradeable.** Atomic writes, synced before they're acknowledged; a
  versioned on-disk format, and every release opens every drive an earlier one wrote.
- **One binary.** Server and command line in one program, for Linux, macOS and Windows.

## Quick start

```sh
cargo build --release
./target/release/teifs serve ~/Drive
```

The first run creates credentials in `~/Drive/.teifs/credentials.json` (readable only by
you) and an encryption keyring in your config folder (back it up), and prints the access
key. Then use any S3 client:

```sh
export AWS_ENDPOINT_URL=http://127.0.0.1:9000
export AWS_ACCESS_KEY_ID=…      # printed by `teifs serve`
export AWS_SECRET_ACCESS_KEY=…  # in .teifs/credentials.json
aws s3 mb s3://photos
aws s3 sync ~/Pictures s3://photos/
```

`photos` is an object bucket: your pictures are stored encrypted under `~/Drive/.teifs/`.
For a folder of plain files instead:

```sh
teifs bucket create pictures --layout folder --dir ~/Drive   # or serve --default-layout folder
aws s3 sync ~/Pictures s3://pictures/                          # now ~/Drive/pictures/…
```

Any folder already in the drive is a folder bucket too.

To set the keys yourself (on servers and in containers), use `TEIFS_ACCESS_KEY` with
`TEIFS_SECRET_KEY`, or with `--secret-key-file` naming a file that holds the secret
(Docker and systemd secrets). The secret is never taken from the command line, so it
never shows in a process list. Coming from MinIO, `MINIO_ROOT_USER` and
`MINIO_ROOT_PASSWORD` work too when nothing else sets the keys.

### Settings file

Every `serve` flag can live in a TOML file instead, under the flag's name. Flags and
`TEIFS_*` environment variables win over it; relative paths in it are relative to the
file.

```toml
# teifs.toml: teifs serve --config teifs.toml
dir = "/srv/drive"
listen = "0.0.0.0:9000"
domains = ["s3.example.com"]
access-key = "admin"
secret-key-file = "/run/secrets/teifs"
durability = "relaxed"
```

`teifs config show --config teifs.toml` prints the settings `serve` would use and where
each comes from. The secret key never goes in the file, and is never printed.

## Commands

| Command | What it does |
|---|---|
| `teifs serve [DIR] [--listen ADDR] [--domain D] [--default-layout object\|folder] [--kms-keyring PATH] [--allow-sse-c] [--upload-expiry 7d\|never] [--durability strict\|relaxed\|none] [--key-names portable\|host] [--config FILE]` | Serve a drive over S3 (default `127.0.0.1:9000`) |
| `teifs config show [--config FILE] [serve's flags]` | Print the effective `serve` settings and where each comes from |
| `teifs credentials [DIR]` | Show the access key and where the secret is |
| `teifs bucket list\|create [--layout object\|folder]\|remove` | Manage buckets without a server |
| `teifs ls BUCKET [PREFIX] [-r]` | List objects |
| `teifs key list\|create NAME\|rotate NAME` | Manage the KMS keys that encrypt objects |

## S3 support today

| Area | Supported |
|---|---|
| Buckets | list, create, head, delete, location, tags, CORS, encryption settings, versioning status (always off) |
| Objects | put, get and head (ranges, by part number, conditional requests, response overrides), attributes, tags, rename, delete (conditional), delete many, copy (keep or replace metadata and tags) |
| Listing | ListObjectsV2 and V1, prefixes, delimiters, pagination, `encoding-type=url`; bucket lists page and filter too |
| Multipart | create, upload part, upload part copy, list parts, list uploads, complete, abort |
| Integrity | Content-MD5 and every S3 checksum algorithm (also as trailers), CRC64NVME by default, full-object and composite checksums for multipart uploads, returned with checksum mode |
| Auth | Signature V4 (headers and presigned URLs); path-style and virtual-hosted-style |

**Encryption at rest** in object buckets: SSE-S3 by default (as AWS), SSE-KMS with named
keys, and SSE-C with your own keys. The keys live in a keyring outside the drive
(`teifs key list|create|rotate`), or in a Vault or OpenBao transit engine
(`--kms-transit URL`, token from `VAULT_TOKEN`). **Back the keyring up**: encrypted
objects can't be read without it.

**Not yet:** users and policies, versioning, Object Lock, lifecycle rules, website
hosting, event notifications, replication, several disks or machines.
[COMPATIBILITY.md](docs/COMPATIBILITY.md) tracks what's proven.

**Two kinds of bucket.** An *object bucket* (the default) stores objects by id under
`.teifs/` and takes every key S3 allows. A *folder bucket* is a folder of plain files you
can open anywhere, with the limits below. Choose per bucket (`--layout`, or the
`x-teifs-bucket-layout` header on CreateBucket), or change the default
(`--default-layout`).

**Limits of folder buckets:**
- On a case-insensitive disk (the default on macOS and Windows), two keys that differ
  only in letter case can't both exist. The second is refused with
  `409 XTeiFSKeyConflict`.
- The same goes for keys that differ only in Unicode form (`é` composed or decomposed)
  on macOS.
- A key can't name a file and a folder at once (`a` and `a/b`), and keys with `.`, `..`
  or empty segments are refused.
- Names Windows can't hold (`CON`, `NUL.txt`, `a:b`, `what?`, a name ending in a dot or
  a space) are refused everywhere, so the drive can move between systems;
  `--key-names host` allows them outside Windows.
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
