# Moving from MinIO

MinIO's open-source repository was archived in April 2026. TeiFS serves the same S3 API,
answers most of MinIO's admin API (so `mc` and `mc admin` keep working), reads MinIO's
environment variables where it has the same feature, and copies buckets out of MinIO
with every version and setting. This guide is the whole move: what carries over as it
is, how to copy the data, and what's different.

One thing doesn't carry over: MinIO's drives. TeiFS stores objects in its own format
(or as plain files), so it can't serve a MinIO data folder. Run TeiFS next to MinIO,
copy the buckets through S3, then switch clients over.

## 1. Start TeiFS next to MinIO

With MinIO still on port 9000, start TeiFS on another port with a new, empty folder:

```sh
teifs init /srv/teifs --listen 0.0.0.0:9100 --alias home
teifs serve /srv/teifs
```

Or in Docker, with the same keys MinIO had (see [Docker Compose](#docker-compose) for the
whole file):

```sh
docker run -d --name teifs -p 9100:9000 \
  -v teifs-data:/data -v teifs-config:/config \
  -e MINIO_ROOT_USER -e MINIO_ROOT_PASSWORD \
  ghcr.io/teispace/teifs
```

Objects in TeiFS's object buckets are encrypted at rest by default, with a keyring kept
off the drive (`/config` in the image, your config folder otherwise). Back it up with the
drive: without it, encrypted objects can't be read.

## 2. Copy the buckets

`teifs init` added an alias for TeiFS, `home`; add one for MinIO. Secret keys are asked
for, hidden, or read from standard input; never from the command line.

```sh
teifs alias set minio https://minio.example.com:9000 --access-key admin
teifs alias set home http://127.0.0.1:9100 --access-key admin   # TeiFS in Docker
```

Then copy everything, or one bucket at a time:

```sh
teifs migrate minio home --dry-run     # what would be copied
teifs migrate minio home               # every bucket, with every version and setting
teifs migrate minio/photos home/photos --latest   # one bucket, current objects only
```

`teifs migrate` makes each missing bucket (with Object Lock when MinIO's has it), copies
its settings (versioning, Object Lock's default retention, the policy, lifecycle rules,
CORS, tags, default encryption), and then every version and delete marker in order, with
each object's headers, metadata, tags, retention and legal hold. Multipart objects are
copied in parts of the same sizes, so ETags stay the same, and every copy's ETag is
checked against MinIO's. Objects MinIO encrypted with SSE-S3 or SSE-KMS are read through S3
like any other and encrypted again by TeiFS (SSE-C objects need their keys: copy them with
`teifs cp --enc-c`). [Migrating from MinIO or another S3
service](OPERATIONS.md#migrating-from-minio-or-another-s3-service) has the details.

Running it again copies only what's new, so a migration that stopped carries on, and a
second pass just before you switch over catches up. It never deletes anything on TeiFS:
in a bucket without versioning, an object deleted from MinIO after a pass stays. For the
last pass of such a bucket, `teifs mirror --remove` deletes what's gone:

```sh
teifs mirror minio/photos home/photos --remove --dry-run
```

Things to know:

- **Object ids and dates change.** S3 sets an object's `Last-Modified` and version id when
  it's written, so migrated objects get new ones, and lifecycle rules count their age from
  the migration. To keep them, use a [batch replicate job](#keeping-version-ids-and-dates)
  instead.
- **Public buckets.** New TeiFS buckets block public access, as new AWS buckets do, so a
  public policy (`mc anonymous set download`) is refused, and `migrate` says
  `policy not copied`. Turn the block off for that bucket, then run `migrate` again: it
  copies the policy, since the bucket still has none.

  ```sh
  aws s3api delete-public-access-block --bucket photos --endpoint-url http://127.0.0.1:9100
  ```

- **KMS-encrypted objects.** When MinIO encrypted objects with SSE-KMS, their ETags aren't
  MD5s and won't match after the copy. Add `--size-only` to tell objects apart by size.
- **Notifications and replication** name MinIO's own targets and ARNs: `migrate` lists them
  for you to set up again.
- **Quotas** aren't S3 settings: `mc admin cluster bucket export` and `import` (below)
  carry them, or set them with `teifs quota set` or `mc quota set`.

### Users, groups and policies

`migrate` copies buckets, not identities. MinIO's IAM export moves users, groups, policies
and service accounts with their secrets, so existing keys keep working:

```sh
mc admin cluster iam export minio                         # writes minio-iam-info.zip
mc admin cluster iam import teifs minio-iam-info.zip
```

The root user isn't in the export: give TeiFS the same root keys (`MINIO_ROOT_USER` and
`MINIO_ROOT_PASSWORD` work as they are). Bucket settings move the same way, and make any
bucket TeiFS doesn't have yet:

```sh
mc admin cluster bucket export minio                      # writes minio-bucket-metadata.zip
mc admin cluster bucket import teifs minio-bucket-metadata.zip
```

### Keeping version ids and dates

A MinIO batch `replicate` job run on TeiFS pulls a bucket from MinIO and keeps each
version's id, time and ETag: TeiFS takes the copies in as replicas. Make the buckets
first, with versioning when MinIO's have it (the bucket import above does), then start a
job per bucket:

```yaml
# pull-photos.yaml
replicate:
  apiVersion: v1
  source:
    type: minio
    bucket: photos
    endpoint: https://minio.example.com:9000
    credentials:
      accessKey: admin
      secretKey: MINIO-SECRET-KEY
  target:
    type: minio
    bucket: photos
```

```sh
mc batch start teifs pull-photos.yaml      # prints the job's id
mc batch status teifs JOB-ID
```

TeiFS keeps the job's secret key sealed by its KMS and never shows it again
(`mc batch describe` prints `**REDACTED**`). Delete the YAML file once the job has
started. Versions and delete markers come over; bucket settings don't, so import them
first.

## 3. Switch over

Stop writes to MinIO, run `teifs migrate` (or the batch jobs) once more, then give TeiFS
MinIO's address: stop MinIO, and serve TeiFS on port 9000. Clients keep their endpoint,
keys and bucket names.

MinIO's health checks are answered as a single-drive MinIO answers them, so load
balancer and Kubernetes probes on `/minio/health/live` and `/minio/health/ready` keep
working. A certificates folder in MinIO's layout (`public.crt`, `private.key`, a
subfolder per further certificate, and `CAs`) works as it is with `--certs-dir`.

### Docker Compose

A typical MinIO service:

```yaml
services:
  minio:
    image: quay.io/minio/minio
    command: server /data --console-address ":9001"
    ports: ["9000:9000", "9001:9001"]
    environment:
      MINIO_ROOT_USER: admin
      MINIO_ROOT_PASSWORD: change-this-secret
    volumes: [minio-data:/data]
volumes:
  minio-data:
```

becomes:

```yaml
services:
  teifs:
    image: ghcr.io/teispace/teifs
    ports: ["9000:9000"]
    environment:
      TEIFS_ACCESS_KEY: admin
      TEIFS_SECRET_KEY_FILE: /run/secrets/teifs
    secrets: [teifs]
    volumes:
      - teifs-data:/data       # the drive (a new volume: not MinIO's)
      - teifs-config:/config   # the encryption keyring: keep it and back it up
secrets:
  teifs:
    file: ./teifs-secret.txt
volumes:
  teifs-data:
  teifs-config:
```

The image runs `teifs serve` on `/data`, listening on port 9000, as a non-root user, and
checks its own health, so it needs no `command` or `healthcheck`. There's no console port.
Keeping `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` in `environment` works too, when
nothing else sets the keys.

## Using `mc` with TeiFS

`mc alias set teifs https://s3.example.com ACCESS_KEY SECRET_KEY`, and `mc` works with
TeiFS as with MinIO:

- **Everything S3:** `mc ls`, `cp`, `mirror`, `rm`, `mb`, `rb`, `stat`, `cat`, `tag`,
  `version`, `retention`, `legalhold`, `ilm rule`, `encrypt`, `anonymous`, `event`
  (with MinIO's `arn:minio:sqs::ID:webhook` ARNs), `watch` and `replicate`.
- **Admin:** users, groups, policies and service accounts (`mc admin user`, `group`,
  `policy`, `user svcacct`, `accesskey`), `mc idp ldap` and `mc admin idp`, `mc admin
  config`, `mc admin info`, `trace`, `logs`, `heal`, `service restart|stop|freeze`,
  `kms`, `top locks`, `speedtest`, `decommission status`, `cluster iam` and
  `cluster bucket` export and import; `mc quota`; `mc batch` with `expire`, `keyrotate`
  and `replicate` jobs; `mc support diag`, `inspect`, `profile` and `perf drive`.

For example:

```sh
mc admin user add teifs alice alice-secret-key
mc admin policy attach teifs readwrite --user alice
mc admin user svcacct add teifs alice --name backup
mc admin config get teifs identity_ldap
mc admin info teifs
mc admin trace teifs
mc quota set teifs/photos --size 100GiB
mc batch generate teifs expire
mc support diag teifs
```

[Admin API](ADMIN_API.md#minios-admin-and-kms-apis) lists every MinIO admin call TeiFS
answers, with the `mc` command that makes it, and the action a policy needs for it; the
rows for MinIO in [S3 compatibility](COMPATIBILITY.md) say how each behaves. What a single
server can't do is refused: `mc admin decommission start` and `mc admin rebalance` (one
pool), the network speed tests (one node), and `mc admin update` (TeiFS is updated the way
it was installed). Not served: site replication (`mc admin replicate`), tiers
(`mc admin tier`, `mc ilm tier`) and bucket metrics (`mc admin prometheus generate`
writes MinIO's metrics path: use `teifs admin prometheus generate` instead).

## Settings

`teifs serve` reads MinIO's variables for the features it shares with MinIO, when no
TeiFS flag, `TEIFS_*` variable or settings file sets the same thing. Every setting has a
TeiFS flag too ([command line reference](CLI.md#teifs-serve)).

| MinIO | TeiFS |
|---|---|
| `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` | Read as they are, or `TEIFS_ACCESS_KEY` with `TEIFS_SECRET_KEY` or `--secret-key-file` |
| `MINIO_ROOT_USER_FILE`, `MINIO_ROOT_PASSWORD_FILE` | `--secret-key-file` (`TEIFS_SECRET_KEY_FILE`) with `TEIFS_ACCESS_KEY` |
| `minio server /data` (`MINIO_VOLUMES`) | `teifs serve /data` (`TEIFS_DIR`): one folder |
| `--address :9000` (`MINIO_ADDRESS`) | `--listen 0.0.0.0:9000` (`TEIFS_LISTEN`); the default is `127.0.0.1:9000`, and the Docker image's `0.0.0.0:9000` |
| `--certs-dir`, `~/.minio/certs` | `--certs-dir` (`TEIFS_CERTS_DIR`), the same layout; there's no default folder |
| `MINIO_DOMAIN` | `--domain` (`TEIFS_DOMAINS`) |
| `MINIO_IDENTITY_LDAP_*` | Read as they are, or `--ldap-*` ([LDAP sign-in](OPERATIONS.md#ldap-sign-in)) |
| `MINIO_IDENTITY_OPENID_*` (each provider's suffix too) | Read as they are, or `--openid-*` ([OpenID Connect sign-in](OPERATIONS.md#openid-connect-sign-in)) |
| `MINIO_IDENTITY_TLS_ENABLE`, `MINIO_IDENTITY_TLS_SKIP_VERIFY` | Read as they are, or `--identity-tls` ([client certificate sign-in](OPERATIONS.md#client-certificate-sign-in)) |
| `MINIO_IDENTITY_PLUGIN_*` | Read as they are, or `--identity-plugin-*` ([identity plugin sign-in](OPERATIONS.md#identity-plugin-sign-in)) |
| `MINIO_KMS_KES_ENDPOINT`, `_API_KEY`, `_CERT_FILE`, `_KEY_FILE`, `_CAPATH`, `_KEY_NAME` | Read as they are, or `--kms-kes*` ([encryption keys](OPERATIONS.md#encryption-keys)) |
| `MINIO_KMS_SECRET_KEY` | Not read: TeiFS has its own keyring (`--kms-keyring`), Vault or OpenBao, KES or AWS KMS |
| `MINIO_NOTIFY_<KIND>_<KEY>[_<ID>]` | Read as they are, for webhooks, Elasticsearch, Redis, NSQ, NATS, MQTT, Kafka, AMQP, PostgreSQL and MySQL ([from MinIO's settings](OPERATIONS.md#from-minios-settings)) |
| `MINIO_AUDIT_WEBHOOK_*` | Read as they are, or `--audit-webhook` |
| `MINIO_API_ROOT_ACCESS`, `MINIO_API_STALE_UPLOADS_EXPIRY` | Read as they are, or `--no-root-access` and `--upload-expiry` |
| `MINIO_PROMETHEUS_AUTH_TYPE=public` | `--public-metrics` |
| `MINIO_BROWSER`, `--console-address` | Nothing: there's no web console |
| `MINIO_REGION` | Nothing: buckets are in `us-east-1` |

Settings `mc admin config set` keeps (`identity_ldap`, `identity_openid`, `notify_*`,
`audit_webhook`, `api`) are kept by TeiFS on its drive too, and count after MinIO's
variables ([settings with `mc admin config`](OPERATIONS.md#settings-with-mc-admin-config)).

## What's different

TeiFS follows AWS where MinIO and AWS differ, so a few defaults are stricter:

- **Encryption at rest is on.** New object buckets encrypt with SSE-S3, as AWS's do.
- **New buckets block public access and have ACLs disabled**, as AWS's have since April
  2023. Applications that upload with public ACLs (`public-read`) need
  `teifs serve --legacy-bucket-defaults`, or the bucket's settings changed.
- **SSE-C is blocked** on buckets that don't allow it, as on AWS since April 2026:
  `--allow-sse-c` allows it everywhere.
- **Signature Version 2 is refused**; `--allow-sigv2` accepts it for old clients.
- **Unfinished multipart uploads** are aborted after 7 days (MinIO: 24 hours);
  `--upload-expiry` changes it.
- **One server, one drive.** No erasure coding, pools or multiple nodes yet, and no web
  console; `mc admin info` shows one server.
- **Metrics** are TeiFS's, at `/.teifs/metrics` ([metrics](OPERATIONS.md#metrics)), not
  MinIO's `/minio/v2/metrics/…`.
- **Not served yet:** lifecycle transitions and remote tiers, site replication, and
  MinIO's versioning `ExcludedPrefixes` and lifecycle `ExpiredObjectAllVersions` (both
  `501 NotImplemented`).

TeiFS also has what MinIO dropped: **folder buckets**, where a bucket is a plain folder
your files sit in as they are (`teifs mb home/pictures --layout folder`).
