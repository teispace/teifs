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

On Debian, Ubuntu, Fedora, RHEL and the like, install the `.deb` or `.rpm` from the
release instead: it adds a `teifs` system user and a hardened systemd service.

```sh
sudo apt install ./teifs_X.Y.Z_amd64.deb      # or: sudo dnf install ./teifs-X.Y.Z-1.x86_64.rpm
sudo systemctl enable --now teifs             # serves /var/lib/teifs/drive on 127.0.0.1:9000
```

See [Running as a service](docs/OPERATIONS.md#running-as-a-service) for its settings.
The Docker image is `ghcr.io/teispace/teifs`, and the Helm chart for Kubernetes is in
`packaging/helm/teifs` ([Kubernetes](docs/OPERATIONS.md#kubernetes)).

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
teifs migrate minio home                     # every bucket, with every version and setting
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
file, including a notification target's or the audit webhook's `ca=`, `client_cert=`,
`client_key=`, `creds=`, `nkey=` and `server_public_key=`. `teifs serve DIR` reads the drive's own `DIR/.teifs/settings.toml` (written by
`teifs init`) unless `--config` names another.

```toml
# teifs.toml: teifs serve --config teifs.toml
dir = "/srv/drive"
listen = "0.0.0.0:9000"
domains = ["s3.example.com"]
access-key = "admin"
secret-key-file = "/run/secrets/teifs"
durability = "relaxed"
notify-kafka = ["stream=k1.internal:9093,topic=s3-events,ca=certs/ca.pem"]
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

The main ones. [docs/CLI.md](docs/CLI.md) lists every command and option.

| Command | What it does |
|---|---|
| `teifs init [DIR] [--listen ADDR] [--default-layout object\|folder] [--kms-keyring PATH] [--alias NAME\|--no-alias] [--force]` | Set up a drive, its settings and an alias |
| `teifs serve [DIR] [--listen ADDR] [--certs-dir DIR \| --tls-cert FILE --tls-key FILE] [--trusted-proxy CIDR]… [--proxy-header x-forwarded-for\|forwarded\|x-real-ip] [--domain D] [--website-domain D] [--default-layout object\|folder] [--kms-keyring PATH \| --kms-transit URL \| --kms-kes URL \| --kms-aws] [--kms-default-key NAME] [--ldap-server HOST --ldap-lookup-bind-dn DN --ldap-user-base-dn DN --ldap-user-filter F …] [--allow-sse-c] [--no-root-access] [--allow-sigv2] [--legacy-bucket-defaults] [--public-metrics] [--audit-log FILE\|-] [--audit-webhook URL] [--upload-expiry 7d\|never] [--scrub-every 30d\|never] [--snapshots 3] [--durability strict\|relaxed\|none] [--key-names portable\|host] [--header-timeout 30s] [--body-timeout 60s] [--max-connections 4096] [--config FILE]` | Serve a drive over S3 (default `127.0.0.1:9000`) |
| `teifs config show [--config FILE] [serve's flags]` | Print the effective `serve` settings and where each comes from |
| `teifs credentials [DIR]` | Show the access key and where the secret is |
| `teifs bucket list\|create [--layout object\|folder]\|remove [--dir DIR]` | Manage buckets without a server |
| `teifs alias set NAME URL\|ls\|rm NAME` | Name an S3 endpoint and its keys, and a CA to trust with `--ca-cert` (`TEIFS_ALIAS_NAME=https://KEY:SECRET[:TOKEN]@host` for one run) |
| `teifs ls ALIAS[/BUCKET[/PREFIX]] [-r] [--versions]` | List buckets or objects; `--versions` shows every version and delete marker |
| `teifs mb\|rb ALIAS/BUCKET` | Make or remove a bucket (`mb --layout folder`, `mb --with-lock` for Object Lock, `rb --force`) |
| `teifs cp\|mv SOURCE… DEST [-r]` | Copy or move between local files and S3, or within S3 (`--parallel 8`, `--part-size 8MiB`); `cp -` for standard input or output; `cp --version-id ID` copies an older version; `--enc-s3 PREFIX`, `--enc-kms PREFIX=KEY`, `--enc-dsse PREFIX=KEY` and `--enc-c PREFIX=FILE` (or `TEIFS_ENC_C`) encrypt by key prefix |
| `teifs mirror SOURCE DEST [--remove] [--dry-run]` | Copy what's new or changed, one way (with `cp`'s `--enc-*` options) |
| `teifs migrate SOURCE DEST [--latest] [--dry-run] [--size-only] [--no-configs]` | Move buckets from any S3 service (MinIO, AWS, RustFS…) to another: every version and delete marker in order, objects' headers, metadata, tags, retention and legal holds with the same ETags, and the buckets' settings; running it again carries on, and copies only what's new |
| `teifs rm ALIAS/BUCKET/KEY… [-r [--force]]` | Delete objects (`-r` asks first, unless `--force` or `-y`); `--version-id ID` removes one version for good, `--versions` all of a key's (asks first); `--bypass` removes governance-locked versions |
| `teifs cat\|stat ALIAS/BUCKET/KEY [--version-id ID] [--enc-c PREFIX=FILE]` | Print an object, or show its details with its retention and legal hold (a bucket's too, with its versioning, Object Lock and default encryption) |
| `teifs version enable\|suspend\|info ALIAS/BUCKET` | Turn a bucket's versioning on, suspend it, or show it |
| `teifs retention set governance\|compliance 30d\|1y TARGET` \| `clear\|info TARGET` | Keep objects from deletion for a time (`-r` for a prefix, `--version-id`, `--bypass` to shorten governance), or with `--default` set a bucket's default retention |
| `teifs legalhold set\|clear\|info ALIAS/BUCKET/KEY [-r] [--version-id ID]` | Keep objects from deletion until released |
| `teifs event add ALIAS/BUCKET ARN [--event put,delete,get,ilm] [--prefix P] [--suffix S] [--id ID]` \| `event ls\|rm ALIAS/BUCKET …` \| `event eventbridge ALIAS/BUCKET on\|off` | A bucket's notification rules, sending its events to the server's targets (as `mc event`; an AWS queue's, topic's or function's ARN too), and EventBridge |
| `teifs watch ALIAS[/BUCKET[/PREFIX]] [--events put,delete,get,ilm,bucket] [--suffix S]` | Show a bucket's events (or every bucket's) as they happen, as `mc watch`; `--json` for S3's event records |
| `teifs quota set ALIAS/BUCKET --size SIZE` \| `quota info\|clear ALIAS/BUCKET` | A bucket's hard quota (`MinIO`'s, as `mc quota` sets it): writes that would reach it are refused |
| `teifs inventory add ALIAS/BUCKET ID ALIAS/DEST[/PREFIX] [--prefix P] [--all-versions] [--weekly] [--format csv\|orc\|parquet] [--fields F,…\|all] [--encrypt sse-s3\|KEY] [--disabled] [--no-policy]` \| `inventory ls ALIAS/BUCKET` \| `inventory info\|run\|rm ALIAS/BUCKET ID` | A bucket's inventory reports (S3 Inventory's gzipped CSV and manifest), letting S3 Inventory into the destination's bucket policy |
| `teifs metrics add ALIAS/BUCKET ID [--prefix P] [--tag K=V]…` \| `metrics ls ALIAS/BUCKET` \| `metrics info\|rm ALIAS/BUCKET ID` | A bucket's request metrics configurations: its requests counted as CloudWatch counts them, in the server's Prometheus metrics |
| `teifs analytics add ALIAS/BUCKET ID [--prefix P] [--tag K=V]… [--export ALIAS/DEST[/PREFIX]] [--no-policy]` \| `analytics ls ALIAS/BUCKET` \| `analytics info\|rm ALIAS/BUCKET ID` | A bucket's storage class analyses: how its objects are read by age, each day's figures added to a CSV in the destination, letting S3 into its bucket policy |
| `teifs tiering add ALIAS/BUCKET ID [--prefix P] [--tag K=V]… --archive-days N \| --deep-archive-days N [--disabled]` \| `tiering ls ALIAS/BUCKET` \| `tiering info\|rm ALIAS/BUCKET ID` | A bucket's Intelligent-Tiering configurations, kept with S3's checks (every object stays `STANDARD`) |
| `teifs requester-pays enable\|disable\|info ALIAS/BUCKET` | Requester Pays: a bucket that refuses anonymous requests |
| `teifs website set ALIAS/BUCKET [--index I] [--error E] [--rules FILE] \| --redirect-all URL` \| `website info\|rm ALIAS/BUCKET` | A bucket's website configuration: its index and error documents and redirection rules (JSON as the S3 console takes it), or a redirect of every request |
| `teifs logging set ALIAS/BUCKET ALIAS/TARGET[/PREFIX] [--format simple\|event-time\|delivery-time] [--no-policy]` \| `logging info\|rm ALIAS/BUCKET` | A bucket's server access log: where its records go, letting the logging service into the target's bucket policy |
| `teifs ilm rule add\|edit\|ls\|rm\|export\|import ALIAS/BUCKET` | Lifecycle rules: expire objects (`--expire-days 30 --prefix logs/`), older versions and lone delete markers, abort old uploads; `export`/`import` in AWS's JSON |
| `teifs encrypt set sse-s3\|sse-kms\|dsse-kms [KEY] ALIAS/BUCKET` \| `clear\|info ALIAS/BUCKET` | How a bucket encrypts new objects (`--bucket-key`), and whether it takes customer keys (`--block-sse-c`, `--allow-sse-c`) |
| `teifs encrypt update --kms-key KEY ALIAS/BUCKET/KEY [-r] [--version-id ID]` | Move objects to a KMS key in place, without rewriting them (`--bucket-key`) |
| `teifs presign ALIAS/BUCKET/KEY [--expires 1h] [--put [--max-size 10MiB]]` | A link that works without keys; an upload link can limit its size |
| `teifs key list\|create NAME\|rotate NAME\|rewrap NAME` | Manage the KMS keys that encrypt objects; `rewrap` seals objects' keys again under a key's newest version (`--dry-run` counts) |
| `teifs backup [DIR] --to FOLDER` | Copy a drive's metadata (buckets, settings, IAM, object index) into a folder, while no server uses it; objects' bytes stay on the drive |
| `teifs restore [DIR] --from FOLDER\|SNAPSHOT` | Put a backup or one of the drive's daily snapshots back (asks first; what it replaces is kept) |
| `teifs repair [DIR] [--apply] [--forget-missing]` | Find where a drive's metadata and files disagree (after restoring an older snapshot, say) and, with `--apply`, set right what's safe to: objects written since get their versions back (but small ones, kept only in the index); lost ones are forgotten only with `--forget-missing` |
| `teifs verify [--bucket B] [--dir DRIVE] [--kms-keyring PATH]` | Read every stored version back and check it against its checksums and ETag (encrypted ones as they decrypt); exit code 1 when something is damaged |
| `teifs admin info\|config ALIAS` | A server's version, drive, account, uptime, disks (free, size, kept free), jobs and what its scrubs found; how it was started |
| `teifs admin snapshot ls\|take ALIAS` | A server's daily snapshots of its drive's metadata (buckets, settings, IAM, object index), or one taken now |
| `teifs admin bucket export ALIAS[/BUCKET] [-o FILE [--force]]` \| `bucket import ALIAS FILE` | Move buckets with their settings (policy, lifecycle, Object Lock, encryption, CORS, tags, ACL, Block Public Access, versioning, Requester Pays and reporting configurations) to another server, as `mc admin cluster bucket export\|import`; each setting is checked and reported |
| `teifs admin iam export ALIAS [-o FILE [--secrets] [--force]]` \| `iam import ALIAS FILE [--adopt-account]` | Move a server's IAM to another |
| `teifs admin trace ALIAS [--errors] [--api NAME]… [--bucket B] [--prefix P] [--status CODE]… [--slower-than 250ms]` | Show each request the server answers, as it answers it (as `mc admin trace`); `--json` for audit entries |
| `teifs admin prometheus generate ALIAS [--expires 90d] [--token-file FILE] [--buckets]` | A Prometheus scrape configuration for the server's metrics, with a token its key signs (as `mc admin prometheus generate`) |
| `teifs admin root-key rotate ALIAS` | Replace a server's generated root key; the alias follows |
| `teifs admin user add ALIAS NAME --policy readonly\|readwrite\|admin\|FILE [--bucket B]… --save-alias NEW\|-o FILE` | A user with a policy and an access key, in one step; the key goes into an alias or an owner-only file |
| `teifs admin user ls\|rm\|policy ALIAS …` \| `user key add\|ls\|rm ALIAS NAME …` | List, delete or re-permission users; add, list and delete their keys |
| `teifs admin role add ALIAS NAME --trust account\|user:NAME\|github:OWNER/REPO\|oidc:HOST --sub S\|FILE --policy … [--max-session 12h]` | A role with a policy, in one step, trusting the account, a user, a GitHub repository's workflows or an OpenID Connect provider's subjects |
| `teifs admin role ls\|rm\|policy\|trust ALIAS …` | List roles and whom they trust, delete them (their sessions end), change their policy or trust |
| `teifs admin saml add ALIAS NAME --metadata FILE [--private-key FILE] [--encryption required\|allowed]` \| `saml update ALIAS NAME [--metadata FILE] [--add-key FILE\|--remove-key ID] [--encryption …]` \| `saml ls\|rm ALIAS …` | SAML providers from their metadata, with the private keys that decrypt their encrypted assertions (two at most, to rotate them) |
| `teifs admin oidc add ALIAS URL --client-id ID [--thumbprint HEX] [--policy-claim [CLAIM]] [--role-policy NAMES] [--claim-userinfo]` \| `oidc ls\|rm ALIAS …` | OpenID Connect providers whose tokens get credentials, with MinIO's policy claim or role policies (each client's role ARN is shown), and claims from the provider's userinfo endpoint, if asked for |
| `teifs admin ldap policy attach\|detach ALIAS POLICY… --user DN\|--group DN` \| `ldap policy ls ALIAS [--user DN\|--group DN]` | Managed policies for LDAP users and groups, whose sessions get them (MinIO's `mc idp ldap policy`) |
| `teifs sts whoami ALIAS` | Whom an alias signs as |
| `teifs sts assume ALIAS [ROLE] [--session-name N] [--duration 1h] [--policy FILE] [--external-id ID] [--tag K=V]… --save-alias NEW\|-o FILE` | Temporary credentials: a role's session, or without a role (MinIO's way) the user's own permissions narrowed; saved as an alias that knows when it expires, or as the AWS CLI's `credential_process` output |
| `teifs sts assume-web SERVER [--role ARN] [--token-file F] … --save-alias NEW\|-o FILE` | A CI job's OpenID Connect token for temporary credentials (reads `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`) |
| `teifs sts assume-saml SERVER --role-arn ARN --principal-arn ARN --assertion-file F … --save-alias NEW\|-o FILE` | A SAML identity provider's response (the `SAMLResponse` a browser posts, or its XML) for a role's temporary credentials, as `aws sts assume-role-with-saml` |
| `teifs sts assume-ldap SERVER -u NAME [--password-stdin] … --save-alias NEW\|-o FILE` | An LDAP user's name and password for temporary credentials (MinIO's `AssumeRoleWithLDAPIdentity`; the password from standard input, `TEIFS_LDAP_PASSWORD` or a prompt) |
| `teifs sts assume-cert SERVER --cert FILE --key FILE … --save-alias NEW\|-o FILE` | A client certificate for temporary credentials with the policy its common name names (MinIO's `AssumeRoleWithCertificate`) |
| `teifs sts assume-custom SERVER --role-arn ARN [--token-stdin] … --save-alias NEW\|-o FILE` | A token the server's identity plugin vouches for, for temporary credentials with the plugin role's policies (MinIO's `AssumeRoleWithCustomToken`) |
| `teifs health [ADDRESS\|URL] [--timeout 5s]` | Check that a server answers its health check, over HTTP or HTTPS |
| `teifs status [ALIAS]` | Check how a server is doing: answers and how fast, drive serving and taking writes, clocks, certificate expiry, version, disks, jobs, scrubs; exit code 1 when a check fails |
| `teifs doctor [DIR]` | Check a drive on this machine, with the settings `teifs serve` would use: its format, databases, file system (network or FUSE ones warn), room, keys, keyring, certificates and listen address, each problem with what to do; exit code 1 when a check fails |
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
| IAM | users, access keys, groups, roles, OpenID Connect and SAML providers, managed and inline policies (AWS's and MinIO's built in), versions, permissions boundaries, tags, with AWS's rules and error codes; every S3 request and IAM action decided by the signer's policies; the IAM API and STS on the S3 endpoint (`aws iam --endpoint-url …`) |
| Temporary credentials | STS `AssumeRole` with trust policies, session policies, session tags and source identity; `AssumeRoleWithWebIdentity` for OpenID Connect ID tokens (GitHub Actions, GitLab, Kubernetes, Keycloak…); `GetSessionToken`; `GetFederationToken`; MinIO's `AssumeRoleWithLDAPIdentity` for users of an LDAP directory (Active Directory, OpenLDAP) with the policies mapped to them and their groups; MinIO's `AssumeRoleWithCertificate` for clients with a certificate your CA issued; MinIO's `AssumeRoleWithCustomToken` for tokens your own identity plugin vouches for; MinIO's `AssumeRole` for a user's own permissions and `AssumeRoleWithWebIdentity` with the policies a token's claim names; signed S3 requests, presigned links and browser uploads with the session token |
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
(`teifs key list|create|rotate`), or in an external KMS: a Vault or OpenBao transit engine
(`--kms-transit URL`, token from `VAULT_TOKEN`), KES (`--kms-kes URL`, API key from
`TEIFS_KMS_KES_API_KEY`; MinIO's `MINIO_KMS_KES_*` variables work too) or AWS KMS
(`--kms-aws`, credentials as AWS's tools find them). **Back the keyring up**: encrypted
objects can't be read without it. See [Operations](docs/OPERATIONS.md#encryption-keys).

**LDAP sign-in**, as MinIO's: `teifs serve --ldap-server ldap.example.com
--ldap-lookup-bind-dn … --ldap-user-base-dn … --ldap-user-filter '(uid=%s)'` (the lookup
password from `TEIFS_LDAP_LOOKUP_BIND_PASSWORD`; MinIO's `MINIO_IDENTITY_LDAP_*` variables
work too) lets a directory's users get temporary credentials with their name and password
(`teifs sts assume-ldap`, `mc idp ldap`-style clients), with the managed policies mapped to
them and their groups (`teifs admin ldap policy attach`). See
[Operations](docs/OPERATIONS.md#ldap-sign-in).

**Client certificate sign-in**, as MinIO's: `teifs serve --certs-dir … --identity-tls`
(the authorities in the certificates folder's `CAs`, or `--identity-tls-ca`; MinIO's
`MINIO_IDENTITY_TLS_*` variables work too) lets clients with a certificate your CA issued
get temporary credentials with the policy its common name names (`teifs sts
assume-cert`). See [Operations](docs/OPERATIONS.md#client-certificate-sign-in).

**OpenID Connect providers in the settings**, as MinIO's `identity_openid`: `teifs serve
--openid-config-url … --openid-client-id … [--openid-role-policy NAMES]` (MinIO's
`MINIO_IDENTITY_OPENID_*` variables work too, one provider for each suffix) makes the
provider when the server starts, so its tokens get temporary credentials. See
[Operations](docs/OPERATIONS.md#openid-connect-sign-in).

**Identity plugin sign-in**, as MinIO's: `teifs serve --identity-plugin-url …
--identity-plugin-role-policy readonly` (MinIO's `MINIO_IDENTITY_PLUGIN_*` variables work
too) lets your own service decide whom a token belongs to, and clients exchange it for
temporary credentials with the role's policies (`teifs sts assume-custom`). See
[Operations](docs/OPERATIONS.md#identity-plugin-sign-in).

**Bucket notifications**, as S3's and MinIO's: `teifs serve --notify-webhook
orders=https://hooks.example/s3` (or `--notify-elasticsearch`, `--notify-redis`, `--notify-nsq`, `--notify-nats`, `--notify-mqtt`, `--notify-kafka`, `--notify-amqp`, `--notify-postgresql`, `--notify-mysql`, `--notify-sqs`, `--notify-sns`, `--notify-lambda`, `--notify-eventbridge`) gives the server a target, and a bucket's rules
(`teifs event add`, `aws s3api put-bucket-notification-configuration`, `mc event add`) send it the events
they pick (objects written, deleted, tagged, read, expired), each queued on the drive
before the request is answered and retried until it's taken. `teifs watch` and `mc watch`
show a bucket's events as they happen. See
[OPERATIONS.md](docs/OPERATIONS.md#bucket-notifications).

**Server access logs**, as S3's: `teifs logging set local/app local/logs/app/` (or
`aws s3api put-bucket-logging`) sends every request on a bucket, one record each in
S3's format, to log objects in another bucket (or the same one), which S3's log readers
read. See [OPERATIONS.md](docs/OPERATIONS.md#server-access-logs).

**Static websites**, as S3's website endpoint: with `teifs serve --website-domain
web.example.com`, `teifs website set local/blog --index index.html --error 404.html`
makes `http://blog.web.example.com/` the bucket's site, showing what its policy lets
anybody read, with S3's index and error documents, redirects and error pages. See
[OPERATIONS.md](docs/OPERATIONS.md#static-websites).

**Bucket quotas**, as `MinIO`'s: `teifs quota set local/photos --size 100GiB` (or
`mc quota set`) refuses writes that would take a bucket past it. See
[OPERATIONS.md](docs/OPERATIONS.md#bucket-quotas).

**Not yet:** SAML federation (`AssumeRoleWithSAML`), lifecycle transitions to other
storage classes (every object is `STANDARD`), replication, several disks or
machines.
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
