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
> Versioning, Object Lock and lifecycle rules work. Don't store data you can't
> afford to lose with it yet.

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

### HTTPS

```sh
teifs serve /srv/drive --listen 0.0.0.0:9000 --certs-dir /etc/teifs/certs
# or one certificate: --tls-cert fullchain.pem --tls-key privkey.pem
```

A certificates folder has MinIO's layout, so existing ones work as they are:
`public.crt` and `private.key` (or Kubernetes' `tls.crt` and `tls.key`, so a mounted
TLS secret works), plus a subfolder with the same two files for each further
certificate. Each connection gets the certificate for the name it asks for (wildcards
too), else the default one. Certificates reload when their files change (checked every
10 seconds) and at once on `SIGHUP`; one that doesn't load is reported and the ones in
use stay. TLS 1.3 and 1.2 only, HTTP/2 when the client offers it; plain HTTP on the
port gets `400 Client sent an HTTP request to an HTTPS server.` `teifs health` finds
out on its own that a server speaks HTTPS.

For a certificate your own CA signed (or a self-signed one), tell clients to trust it:
`teifs alias set NAME https://host:9000 --ca-cert ca.pem`, or `TEIFS_CA_CERT=ca.pem` for
every alias that doesn't name one. The system's authorities are still trusted too.

Over HTTPS, `aws:SecureTransport` is true, and SSE-C keys are accepted. On plain HTTP
they're refused for every request (as on AWS), except on a server listening only on
this machine (with no proxies trusted), or with `--sse-c-over-http`.

### Behind a reverse proxy

```sh
teifs serve /srv/drive --trusted-proxy 10.0.0.0/8   # repeatable: addresses or networks
```

Only a trusted proxy can say who its clients are (`aws:SourceIp`) and whether they came
over HTTPS (`aws:SecureTransport`, SSE-C); from anyone else those headers change
nothing. Clients are read from `X-Forwarded-For` by default (`--proxy-header forwarded`
or `x-real-ip` for the others), right to left: the first address that isn't a trusted
proxy is the client, so whatever a client writes into the header itself doesn't count.
The scheme comes from `X-Forwarded-Proto` (from `Forwarded`'s `proto` in that mode).
The proxy must pass `Host` unchanged, since requests are signed with it:

```nginx
location / {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_request_buffering off;
    client_max_body_size 0;
}
```

### Monitoring

Every answer carries an `x-amz-request-id`, and `/.teifs/metrics` serves Prometheus
metrics (requests, errors, latency and bytes by operation; disk space; what the drive
and each bucket hold; background jobs and what the scrub found)
to a bearer token that `teifs admin prometheus generate ALIAS` makes, with the scrape
configuration to paste. `--audit-log FILE` (or `-`) keeps a JSON line per request in
MinIO's audit format: who asked what, the answer, bytes and time, never a secret;
`--audit-webhook URL` sends the same to a log collector, and `teifs admin trace` shows
requests live. See
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Commands

| Command | What it does |
|---|---|
| `teifs init [DIR] [--listen ADDR] [--default-layout object\|folder] [--kms-keyring PATH] [--alias NAME\|--no-alias] [--force]` | Set up a drive, its settings and an alias |
| `teifs serve [DIR] [--listen ADDR] [--certs-dir DIR \| --tls-cert FILE --tls-key FILE] [--trusted-proxy CIDR]… [--proxy-header x-forwarded-for\|forwarded\|x-real-ip] [--domain D] [--default-layout object\|folder] [--kms-keyring PATH] [--allow-sse-c] [--allow-sigv2] [--legacy-bucket-defaults] [--public-metrics] [--audit-log FILE\|-] [--audit-webhook URL] [--upload-expiry 7d\|never] [--scrub-every 30d\|never] [--snapshots 3] [--durability strict\|relaxed\|none] [--key-names portable\|host] [--header-timeout 30s] [--body-timeout 60s] [--max-connections 4096] [--config FILE]` | Serve a drive over S3 (default `127.0.0.1:9000`) |
| `teifs config show [--config FILE] [serve's flags]` | Print the effective `serve` settings and where each comes from |
| `teifs credentials [DIR]` | Show the access key and where the secret is |
| `teifs bucket list\|create [--layout object\|folder]\|remove [--dir DIR]` | Manage buckets without a server |
| `teifs alias set NAME URL\|ls\|rm NAME` | Name an S3 endpoint and its keys, and a CA to trust with `--ca-cert` (`TEIFS_ALIAS_NAME=https://KEY:SECRET[:TOKEN]@host` for one run) |
| `teifs ls ALIAS[/BUCKET[/PREFIX]] [-r] [--versions]` | List buckets or objects; `--versions` shows every version and delete marker |
| `teifs mb\|rb ALIAS/BUCKET` | Make or remove a bucket (`mb --layout folder`, `mb --with-lock` for Object Lock, `rb --force`) |
| `teifs cp\|mv SOURCE… DEST [-r]` | Copy or move between local files and S3, or within S3 (`--parallel 8`, `--part-size 8MiB`); `cp -` for standard input or output; `cp --version-id ID` copies an older version; `--enc-s3 PREFIX`, `--enc-kms PREFIX=KEY`, `--enc-dsse PREFIX=KEY` and `--enc-c PREFIX=FILE` (or `TEIFS_ENC_C`) encrypt by key prefix |
| `teifs mirror SOURCE DEST [--remove] [--dry-run]` | Copy what's new or changed, one way (with `cp`'s `--enc-*` options) |
| `teifs rm ALIAS/BUCKET/KEY… [-r [--force]]` | Delete objects (`-r` asks first, unless `--force` or `-y`); `--version-id ID` removes one version for good, `--versions` all of a key's (asks first); `--bypass` removes governance-locked versions |
| `teifs cat\|stat ALIAS/BUCKET/KEY [--version-id ID] [--enc-c PREFIX=FILE]` | Print an object, or show its details with its retention and legal hold (a bucket's too, with its versioning, Object Lock and default encryption) |
| `teifs version enable\|suspend\|info ALIAS/BUCKET` | Turn a bucket's versioning on, suspend it, or show it |
| `teifs retention set governance\|compliance 30d\|1y TARGET` \| `clear\|info TARGET` | Keep objects from deletion for a time (`-r` for a prefix, `--version-id`, `--bypass` to shorten governance), or with `--default` set a bucket's default retention |
| `teifs legalhold set\|clear\|info ALIAS/BUCKET/KEY [-r] [--version-id ID]` | Keep objects from deletion until released |
| `teifs event add ALIAS/BUCKET ARN [--event put,delete,get,ilm] [--prefix P] [--suffix S] [--id ID]` \| `event ls\|rm ALIAS/BUCKET …` | A bucket's notification rules, sending its events to the server's targets (as `mc event`) |
| `teifs watch ALIAS[/BUCKET[/PREFIX]] [--events put,delete,get,ilm,bucket] [--suffix S]` | Show a bucket's events (or every bucket's) as they happen, as `mc watch`; `--json` for S3's event records |
| `teifs ilm rule add\|edit\|ls\|rm\|export\|import ALIAS/BUCKET` | Lifecycle rules: expire objects (`--expire-days 30 --prefix logs/`), older versions and lone delete markers, abort old uploads; `export`/`import` in AWS's JSON |
| `teifs encrypt set sse-s3\|sse-kms\|dsse-kms [KEY] ALIAS/BUCKET` \| `clear\|info ALIAS/BUCKET` | How a bucket encrypts new objects (`--bucket-key`), and whether it takes customer keys (`--block-sse-c`, `--allow-sse-c`) |
| `teifs encrypt update --kms-key KEY ALIAS/BUCKET/KEY [-r] [--version-id ID]` | Move objects to a KMS key in place, without rewriting them (`--bucket-key`) |
| `teifs presign ALIAS/BUCKET/KEY [--expires 1h] [--put [--max-size 10MiB]]` | A link that works without keys; an upload link can limit its size |
| `teifs key list\|create NAME\|rotate NAME\|rewrap NAME` | Manage the KMS keys that encrypt objects; `rewrap` seals objects' keys again under a key's newest version (`--dry-run` counts) |
| `teifs backup [DIR] --to FOLDER` | Copy a drive's metadata (buckets, settings, IAM, object index) into a folder, while no server uses it; objects' bytes stay on the drive |
| `teifs restore [DIR] --from FOLDER\|SNAPSHOT` | Put a backup or one of the drive's daily snapshots back (asks first; what it replaces is kept) |
| `teifs repair [DIR] [--apply] [--forget-missing]` | Find where a drive's metadata and files disagree (after restoring an older snapshot, say) and, with `--apply`, set right what's safe to: objects written since get their versions back; lost ones are forgotten only with `--forget-missing` |
| `teifs verify [--bucket B] [--dir DRIVE] [--kms-keyring PATH]` | Read every stored version back and check it against its checksums and ETag (encrypted ones as they decrypt); exit code 1 when something is damaged |
| `teifs admin info\|config ALIAS` | A server's version, drive, account, uptime, jobs and what its scrubs found; how it was started |
| `teifs admin snapshot ls\|take ALIAS` | A server's daily snapshots of its drive's metadata (buckets, settings, IAM, object index), or one taken now |
| `teifs admin bucket export ALIAS[/BUCKET] [-o FILE [--force]]` \| `bucket import ALIAS FILE` | Move buckets with their settings (policy, lifecycle, Object Lock, encryption, CORS, tags, ACL, Block Public Access, versioning) to another server, as `mc admin cluster bucket export\|import`; each setting is checked and reported |
| `teifs admin iam export ALIAS [-o FILE [--secrets] [--force]]` \| `iam import ALIAS FILE [--adopt-account]` | Move a server's IAM to another |
| `teifs admin trace ALIAS [--errors] [--api NAME]… [--bucket B] [--prefix P] [--status CODE]… [--slower-than 250ms]` | Show each request the server answers, as it answers it (as `mc admin trace`); `--json` for audit entries |
| `teifs admin prometheus generate ALIAS [--expires 90d] [--token-file FILE] [--buckets]` | A Prometheus scrape configuration for the server's metrics, with a token its key signs (as `mc admin prometheus generate`) |
| `teifs admin root-key rotate ALIAS` | Replace a server's generated root key; the alias follows |
| `teifs admin user add ALIAS NAME --policy readonly\|readwrite\|admin\|FILE [--bucket B]… --save-alias NEW\|-o FILE` | A user with a policy and an access key, in one step; the key goes into an alias or an owner-only file |
| `teifs admin user ls\|rm\|policy ALIAS …` \| `user key add\|ls\|rm ALIAS NAME …` | List, delete or re-permission users; add, list and delete their keys |
| `teifs admin role add ALIAS NAME --trust account\|user:NAME\|github:OWNER/REPO\|oidc:HOST --sub S\|FILE --policy … [--max-session 12h]` | A role with a policy, in one step, trusting the account, a user, a GitHub repository's workflows or an OpenID Connect provider's subjects |
| `teifs admin role ls\|rm\|policy\|trust ALIAS …` | List roles and whom they trust, delete them (their sessions end), change their policy or trust |
| `teifs admin oidc add ALIAS URL --client-id ID [--thumbprint HEX] [--policy-claim [CLAIM]]` \| `oidc ls\|rm ALIAS …` | OpenID Connect providers whose tokens get credentials, with MinIO's policy claim if asked for |
| `teifs sts whoami ALIAS` | Whom an alias signs as |
| `teifs sts assume ALIAS [ROLE] [--session-name N] [--duration 1h] [--policy FILE] [--external-id ID] [--tag K=V]… --save-alias NEW\|-o FILE` | Temporary credentials: a role's session, or without a role (MinIO's way) the user's own permissions narrowed; saved as an alias that knows when it expires, or as the AWS CLI's `credential_process` output |
| `teifs sts assume-web SERVER [--role ARN] [--token-file F] … --save-alias NEW\|-o FILE` | A CI job's OpenID Connect token for temporary credentials (reads `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`) |
| `teifs health [ADDRESS\|URL] [--timeout 5s]` | Check that a server answers its health check, over HTTP or HTTPS |
| `teifs completions bash\|zsh\|fish\|powershell\|elvish` | Print a shell completion script |
| Every command: `--json`, `-q`, `-y`, `--color auto\|always\|never` | JSON Lines, quiet, answer yes, colors |

## S3 support today

| Area | Supported |
|---|---|
| Buckets | list, create, head, delete, location, tags, CORS, encryption settings, versioning |
| Objects | put, browser uploads (`POST` with a signed form and policy), get and head (ranges, by part number, conditional requests, response overrides), attributes, tags, rename, delete (conditional), delete many, copy (keep or replace metadata and tags), changing an object's encryption to another KMS key in place (UpdateObjectEncryption) |
| Versions | versioning enabled or suspended, every version readable, taggable and deletable by id, delete markers, ListObjectVersions, restoring a version by copying it |
| Object Lock | buckets created with it or given it later, default retention in days or years, governance and compliance retention and legal holds per version (set on writes, copies, uploads in parts, or later), governance bypassed only with `s3:BypassGovernanceRetention` |
| Lifecycle | rules by prefix, tags and size (alone or combined), expiring current versions by days or date, removing noncurrent versions by age and count and delete markers left alone, aborting old uploads; `x-amz-expiration` on writes and reads, abort dates on uploads; Object Lock always wins |
| Listing | ListObjectsV2 and V1, prefixes, delimiters, pagination, `encoding-type=url`; bucket lists page and filter too |
| Multipart | create, upload part, upload part copy, list parts, list uploads, complete, abort |
| Integrity | Content-MD5 and every S3 checksum algorithm (also as trailers), CRC64NVME by default, full-object and composite checksums for multipart uploads, returned with checksum mode; stored bytes read back and checked against them every 30 days (`--scrub-every`), or on demand with `teifs verify` |
| Auth | Signature V4 (headers, presigned URLs and POST forms); Signature V2 with `serve --allow-sigv2`; path-style and virtual-hosted-style |
| IAM | users, access keys, groups, roles, OpenID Connect providers, managed and inline policies, versions, permissions boundaries, tags, with AWS's rules and error codes; every S3 request and IAM action decided by the signer's policies; the IAM API and STS on the S3 endpoint (`aws iam --endpoint-url …`) |
| Temporary credentials | STS `AssumeRole` with trust policies, session policies, session tags and source identity; `AssumeRoleWithWebIdentity` for OpenID Connect ID tokens (GitHub Actions, GitLab, Kubernetes, Keycloak…); `GetSessionToken`; `GetFederationToken`; MinIO's `AssumeRole` for a user's own permissions and `AssumeRoleWithWebIdentity` with the policies a token's claim names; signed S3 requests, presigned links and browser uploads with the session token |
| Bucket policies | Put/Get/DeleteBucketPolicy and GetBucketPolicyStatus, AWS's policy language; anonymous requests get only what a policy grants everyone; Block Public Access per bucket, on for every new bucket, `RestrictPublicBuckets` on every read and list; account-wide Block Public Access (`aws s3control put-public-access-block`) |
| Ownership and ACLs | Object Ownership (ACLs disabled on new buckets, as on AWS), bucket and object ACLs where it enables them, canned and granted, under Block Public Access; `serve --legacy-bucket-defaults` for applications that expect S3's pre-2023 buckets |

**The admin API** answers what AWS has no API for, as JSON under `/.teifs/admin/v1/`,
signed like any S3 request: the server's version, drive, uptime and background jobs, how
it was started, IAM export and import (to move users, keys and policies to another
drive), and replacing a generated root key. `teifs admin` calls it through an alias
(`teifs admin info local`), and `teifs-client` is the same as a Rust library;
[docs/ADMIN_API.md](docs/ADMIN_API.md) lists every endpoint and who may call it.

The export with secrets holds every user's keys: keep it like the credentials file. A
root key given through `TEIFS_ACCESS_KEY`/`TEIFS_SECRET_KEY`, flags or a secret key file
is changed there instead (`POST root-key` answers `409`). Aliases copy the key when
they're set, so after a rotation set them again (`teifs alias set local URL --drive DIR`).

**Encryption at rest** in object buckets: SSE-S3 by default (as AWS), SSE-KMS with named
keys, DSSE-KMS (two layers: a named key's and the drive's), and SSE-C with your own keys. The keys live in a keyring outside the drive
(`teifs key list|create|rotate`), or in a Vault or OpenBao transit engine
(`--kms-transit URL`, token from `VAULT_TOKEN`). **Back the keyring up**: encrypted
objects can't be read without it.

**Bucket notifications**, as S3's and MinIO's: `teifs serve --notify-webhook
orders=https://hooks.example/s3` (or `--notify-elasticsearch`, `--notify-redis`, `--notify-nsq`, `--notify-nats`, `--notify-mqtt`, `--notify-sqs`) gives the server a target, and a bucket's rules
(`teifs event add`, `aws s3api put-bucket-notification-configuration`, `mc event add`) send it the events
they pick (objects written, deleted, tagged, read, expired), each queued on the drive
before the request is answered and retried until it's taken. `teifs watch` and `mc watch`
show a bucket's events as they happen. See
[OPERATIONS.md](docs/OPERATIONS.md#bucket-notifications).

**Not yet:** SAML federation (`AssumeRoleWithSAML`), lifecycle transitions to other
storage classes (every object is `STANDARD`), website
hosting, replication, several disks or machines.
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
