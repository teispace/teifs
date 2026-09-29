# TeiFS

**S3 for your own disks.** AWS-compatible object storage in one binary, open source.

TeiFS is an S3 server for your own machines. By default it behaves like AWS S3: any key
S3 allows, and every object encrypted at rest (SSE-S3), with SSE-KMS (a local keyring,
Vault or OpenBao) and SSE-C when you want them. When you'd rather keep plain files, a
bucket can instead be a **folder bucket**: a normal folder in Finder, Explorer or `ls`
that is also a bucket for the AWS CLI, rclone, restic, boto3 and every other S3 client.

> **Early development.** The S3 core, encryption and both bucket kinds work and are
> tested with the official AWS SDK, the AWS CLI and the ceph/s3-tests suite. IAM users,
> groups, policies and bucket policies work, managed with `aws iam` and `aws s3api`.
> Versioning, Object Lock and lifecycle rules are next. Don't store data you can't afford to lose with it
> yet.

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

## Install

Download `teifs` for Linux, macOS or Windows from
[Releases](https://github.com/teispace/teifs/releases) (the static `linux-musl` build
runs on any distribution), or build it with `cargo build --release`. Every release file
has a checksum in `SHA256SUMS.txt` and build provenance you can check with
`gh attestation verify FILE --repo teispace/teifs`.

## Quick start

```sh
teifs init ~/Drive    # asks a few questions on a terminal; flags answer instead
teifs serve ~/Drive
```

`teifs init` creates the drive's credentials in `~/Drive/.teifs/credentials.json`
(readable only by you), an encryption keyring in your config folder (back it up), the
drive's settings, and an alias `local` for the client commands below. (`teifs serve` on
its own does the same, without the alias.) `serve` prints the endpoint, the access key
and commands to try. Then use any S3 client:

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

### In Docker

```sh
docker run -d --name teifs -p 9000:9000 \
  -v teifs-data:/data -v teifs-config:/config \
  -e TEIFS_ACCESS_KEY=admin -e TEIFS_SECRET_KEY_FILE=/run/secrets/teifs \
  ghcr.io/teispace/teifs
```

`/data` is the drive and `/config` holds its encryption keyring: keep both volumes, and
back up the keyring. The image runs as a non-root user and reports its health
(`teifs health`, which asks `GET /.teifs/health`); load balancers can ask that path too.

### TeiFS as an S3 client

`teifs` is also a client for TeiFS or any S3 service, with `ALIAS/BUCKET/KEY` paths:

```sh
teifs alias set home http://127.0.0.1:9000 --drive ~/Drive   # or --access-key, then the secret
teifs mb home/photos
teifs cp -r ~/Pictures home/photos/2026/     # parallel parts; an interrupted copy resumes
teifs ls home/photos/2026
teifs mirror ~/Documents home/docs --remove  # copy what changed, delete what's gone
teifs cp home/photos/2026/cat.jpg .
teifs presign home/photos/2026/cat.jpg --expires 1d
teifs presign home/inbox/upload.jpg --put --max-size 10MiB   # an upload link that takes 10 MiB at most
tar c ~/Projects | teifs cp - home/backups/projects.tar   # a stream in, of any size
teifs cp home/backups/projects.tar - | tar x               # and out
```

Output is for people on a terminal (colors, progress bars, questions before deleting
many objects) and plain when piped. `--json` prints JSON Lines, one object with a `type`
per line, errors included; `-q` keeps only results and errors; `-y` answers questions
(`rm -r`); `--color never` or `NO_COLOR` turns colors off.

Aliases live in `aliases.toml` in your config folder, readable only by you (like
`~/.aws/credentials`); secret keys are asked for hidden or read from standard input,
never from the command line. `TEIFS_ALIAS_<NAME>=https://KEY:SECRET@host` sets one for a
single run. Exit codes: 1 other, 2 usage, 3 network, 4 keys refused, 5 not found,
6 conflict.

### Settings file

Every `serve` flag can live in a TOML file instead, under the flag's name. Flags and
`TEIFS_*` environment variables win over it; relative paths in it are relative to the
file. `teifs serve DIR` reads the drive's own `DIR/.teifs/settings.toml` (written by
`teifs init`) unless `--config` names another.

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
| `teifs init [DIR] [--listen ADDR] [--default-layout object\|folder] [--kms-keyring PATH] [--alias NAME\|--no-alias] [--force]` | Set up a drive, its settings and an alias |
| `teifs serve [DIR] [--listen ADDR] [--domain D] [--default-layout object\|folder] [--kms-keyring PATH] [--allow-sse-c] [--allow-sigv2] [--legacy-bucket-defaults] [--upload-expiry 7d\|never] [--durability strict\|relaxed\|none] [--key-names portable\|host] [--header-timeout 30s] [--body-timeout 60s] [--max-connections 4096] [--config FILE]` | Serve a drive over S3 (default `127.0.0.1:9000`) |
| `teifs config show [--config FILE] [serve's flags]` | Print the effective `serve` settings and where each comes from |
| `teifs credentials [DIR]` | Show the access key and where the secret is |
| `teifs bucket list\|create [--layout object\|folder]\|remove [--dir DIR]` | Manage buckets without a server |
| `teifs alias set NAME URL\|ls\|rm NAME` | Name an S3 endpoint and its keys (`TEIFS_ALIAS_NAME=https://KEY:SECRET[:TOKEN]@host` for one run) |
| `teifs ls ALIAS[/BUCKET[/PREFIX]] [-r]` | List buckets or objects |
| `teifs mb\|rb ALIAS/BUCKET` | Make or remove a bucket (`mb --layout folder`, `rb --force`) |
| `teifs cp\|mv SOURCE… DEST [-r]` | Copy or move between local files and S3, or within S3 (`--parallel 8`, `--part-size 8MiB`); `cp -` for standard input or output |
| `teifs mirror SOURCE DEST [--remove] [--dry-run]` | Copy what's new or changed, one way |
| `teifs rm ALIAS/BUCKET/KEY… [-r [--force]]` | Delete objects (`-r` asks first, unless `--force` or `-y`) |
| `teifs cat\|stat ALIAS/BUCKET/KEY` | Print an object, or show its details |
| `teifs presign ALIAS/BUCKET/KEY [--expires 1h] [--put [--max-size 10MiB]]` | A link that works without keys; an upload link can limit its size |
| `teifs key list\|create NAME\|rotate NAME` | Manage the KMS keys that encrypt objects |
| `teifs admin info\|config ALIAS` | A server's version, drive, account, uptime and jobs; how it was started |
| `teifs admin iam export ALIAS [-o FILE [--secrets] [--force]]` \| `iam import ALIAS FILE [--adopt-account]` | Move a server's IAM to another |
| `teifs admin root-key rotate ALIAS` | Replace a server's generated root key; the alias follows |
| `teifs admin user add ALIAS NAME --policy readonly\|readwrite\|admin\|FILE [--bucket B]… --save-alias NEW\|-o FILE` | A user with a policy and an access key, in one step; the key goes into an alias or an owner-only file |
| `teifs admin user ls\|rm\|policy ALIAS …` \| `user key add\|ls\|rm ALIAS NAME …` | List, delete or re-permission users; add, list and delete their keys |
| `teifs admin role add ALIAS NAME --trust account\|user:NAME\|github:OWNER/REPO\|oidc:HOST --sub S\|FILE --policy … [--max-session 12h]` | A role with a policy, in one step, trusting the account, a user, a GitHub repository's workflows or an OpenID Connect provider's subjects |
| `teifs admin role ls\|rm\|policy\|trust ALIAS …` | List roles and whom they trust, delete them (their sessions end), change their policy or trust |
| `teifs admin oidc add ALIAS URL --client-id ID [--thumbprint HEX] [--policy-claim [CLAIM]]` \| `oidc ls\|rm ALIAS …` | OpenID Connect providers whose tokens get credentials, with MinIO's policy claim if asked for |
| `teifs sts whoami ALIAS` | Whom an alias signs as |
| `teifs sts assume ALIAS [ROLE] [--session-name N] [--duration 1h] [--policy FILE] [--external-id ID] [--tag K=V]… --save-alias NEW\|-o FILE` | Temporary credentials: a role's session, or without a role (MinIO's way) the user's own permissions narrowed; saved as an alias that knows when it expires, or as the AWS CLI's `credential_process` output |
| `teifs sts assume-web SERVER [--role ARN] [--token-file F] … --save-alias NEW\|-o FILE` | A CI job's OpenID Connect token for temporary credentials (reads `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`) |
| `teifs health [ADDRESS] [--timeout 5s]` | Check that a server answers its health check |
| `teifs completions bash\|zsh\|fish\|powershell\|elvish` | Print a shell completion script |
| Every command: `--json`, `-q`, `-y`, `--color auto\|always\|never` | JSON Lines, quiet, answer yes, colors |

## S3 support today

| Area | Supported |
|---|---|
| Buckets | list, create, head, delete, location, tags, CORS, encryption settings, versioning status (always off) |
| Objects | put, browser uploads (`POST` with a signed form and policy), get and head (ranges, by part number, conditional requests, response overrides), attributes, tags, rename, delete (conditional), delete many, copy (keep or replace metadata and tags) |
| Listing | ListObjectsV2 and V1, prefixes, delimiters, pagination, `encoding-type=url`; bucket lists page and filter too |
| Multipart | create, upload part, upload part copy, list parts, list uploads, complete, abort |
| Integrity | Content-MD5 and every S3 checksum algorithm (also as trailers), CRC64NVME by default, full-object and composite checksums for multipart uploads, returned with checksum mode |
| Auth | Signature V4 (headers, presigned URLs and POST forms); Signature V2 with `serve --allow-sigv2`; path-style and virtual-hosted-style |
| IAM | users, access keys, groups, roles, OpenID Connect providers, managed and inline policies, versions, permissions boundaries, tags, with AWS's rules and error codes; every S3 request and IAM action decided by the signer's policies; the IAM API and STS on the S3 endpoint (`aws iam --endpoint-url …`) |
| Temporary credentials | STS `AssumeRole` with trust policies, session policies, session tags and source identity; `AssumeRoleWithWebIdentity` for OpenID Connect ID tokens (GitHub Actions, GitLab, Kubernetes, Keycloak…); `GetSessionToken`; `GetFederationToken`; MinIO's `AssumeRole` for a user's own permissions and `AssumeRoleWithWebIdentity` with the policies a token's claim names; signed S3 requests, presigned links and browser uploads with the session token |
| Bucket policies | Put/Get/DeleteBucketPolicy and GetBucketPolicyStatus, AWS's policy language; anonymous requests get only what a policy grants everyone; Block Public Access per bucket, on for every new bucket, `RestrictPublicBuckets` on every read and list; account-wide Block Public Access (`aws s3control put-public-access-block`) |
| Ownership and ACLs | Object Ownership (ACLs disabled on new buckets, as on AWS), bucket and object ACLs where it enables them, canned and granted, under Block Public Access; `serve --legacy-bucket-defaults` for applications that expect S3's pre-2023 buckets |

**The admin API** answers what AWS has no API for, as JSON under `/.teifs/admin/v1/`,
signed like any S3 request:

| Endpoint | What it does | Who may |
|---|---|---|
| `GET info` | Version, drive, account, uptime, background jobs | `teifs:GetServerInfo` |
| `GET config` | How the server was started, without secrets | `teifs:GetServerConfig` |
| `GET iam` | The account's users, groups, policies and keys (without secrets), as JSON | `teifs:ExportIAM` |
| `GET iam/secrets` | The same with the keys' secrets, to move IAM to another drive | root user |
| `PUT iam[?account=adopt]` | Imports an export into an empty IAM, all or nothing; `adopt` also takes its account id | root user |
| `POST root-key` | Replaces the root key the drive generated: answers the new one, saves it in `.teifs/credentials.json`, and the old one stops working at once | root user |

`teifs admin` calls them through an alias (`teifs admin info local`), and
`teifs-client` is the same as a Rust library. The root user may call everything; users
need the action in a policy. An import makes
everything with the IAM API's own checks, gives users, groups and policies new unique
ids (names and ARNs stay), numbers policy versions from `v1`, and skips keys exported
without secrets. With curl, which reads the key from standard input so it stays off the
command line:

```sh
printf 'user = "%s:%s"\n' "$ACCESS_KEY" "$SECRET_KEY" |
  curl --config - --aws-sigv4 aws:amz:us-east-1:s3 http://127.0.0.1:9000/.teifs/admin/v1/info
```

The export with secrets holds every user's keys: keep it like the credentials file. A
root key given through `TEIFS_ACCESS_KEY`/`TEIFS_SECRET_KEY`, flags or a secret key file
is changed there instead (`POST root-key` answers `409`). Aliases copy the key when
they're set, so after a rotation set them again (`teifs alias set local URL --drive DIR`).

**Encryption at rest** in object buckets: SSE-S3 by default (as AWS), SSE-KMS with named
keys, and SSE-C with your own keys. The keys live in a keyring outside the drive
(`teifs key list|create|rotate`), or in a Vault or OpenBao transit engine
(`--kms-transit URL`, token from `VAULT_TOKEN`). **Back the keyring up**: encrypted
objects can't be read without it.

**Not yet:** SAML federation (`AssumeRoleWithSAML`), versioning, Object Lock, lifecycle rules, website
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
