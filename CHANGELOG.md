# Changelog

All notable changes to TeiFS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and TeiFS follows
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may change
behaviour; the on-disk format is always upgraded automatically.

## Unreleased

- Versioning, with AWS's semantics, in both layouts: `PutBucketVersioning`
  (enabled or suspended), versions stacking under each key, delete markers,
  permanent deletes by version id, `versionId` on reads, tags, ACLs, deletes and a
  copy's source, and `ListObjectVersions` with delete markers and version markers.
  Reads of a delete marker answer as AWS's do (`404` or `405` with
  `x-amz-delete-marker`), and version ids AWS would refuse are refused. In a folder
  bucket the current version stays the plain file, so the folder always shows the
  latest; older versions and delete markers are kept in the drive's system folder, and
  a file changed by another program is kept as the `null` version when it's replaced.
- Versions from the command line: `teifs version enable|suspend|info`,
  `ls --versions`, `--version-id` on `cat`, `stat` and `cp`, and `rm --version-id`
  (one version for good) or `rm --versions` (all of a key's, asking first).
  `stat` shows a bucket's versioning, and `rb --force` removes a bucket's older
  versions and delete markers too.
- Object Lock, with AWS's rules, in both layouts: buckets created with it
  (`x-amz-bucket-object-lock-enabled`) or given it once versioning is on
  (`PutObjectLockConfiguration`), default retention in days or years, and per version
  governance or compliance retention and legal holds (`x-amz-object-lock-*` on writes,
  copies and uploads in parts, `Put/GetObjectRetention`, `Put/GetObjectLegalHold`). A
  locked version can't be removed for good until its retention ends or its legal hold
  is lifted; governance gives way only to a caller allowed
  `s3:BypassGovernanceRetention` who asks. Versioning can't be suspended under Object
  Lock. All 39 Object Lock tests of the s3-tests suite pass.
- Object Lock from the command line, with mc's names: `mb --with-lock`,
  `teifs retention set|clear|info` (for an object, every object under a prefix with
  `-r`, or a bucket's default with `--default`), `teifs legalhold set|clear|info`, and
  `rm --bypass` for governance-locked versions. `stat` shows an object's retention and
  legal hold and a bucket's Object Lock.
- Lifecycle rules, with AWS's rules, in both layouts:
  `Put/Get/DeleteBucketLifecycleConfiguration` (and the older form with a prefix on
  each rule), filters by prefix, tag, object size or all of them together, expiration
  of current versions after days or from a date (a delete marker with versioning),
  removal of noncurrent versions after days, keeping the newest ones
  (`NewerNoncurrentVersions`), removal of delete markers left alone, and aborting
  uploads left unfinished. Writes and reads answer `x-amz-expiration`, and
  CreateMultipartUpload and ListParts the abort date and rule. A background job applies
  the rules through the same checks as requests, so an object written again meanwhile
  and a version Object Lock protects stay. Transitions to other storage classes are
  refused (`InvalidStorageClass`). 20 more tests of the s3-tests suite pass.
- S3 Bucket Key settings per object: the `x-amz-server-side-encryption-bucket-key-enabled`
  header on writes (else the bucket's setting) is recorded with SSE-KMS objects and
  reported on writes, reads and uploads in parts, as AWS does.
- UpdateObjectEncryption: an SSE-S3 or SSE-KMS object (or one version of it) moves to
  SSE-KMS under another key in place, by sealing its data key again: its data, ETag,
  Last-Modified and checksums stay. With AWS's rules: a full KMS key ARN, Signature V4,
  `s3:UpdateObjectEncryption`, nothing for unencrypted, SSE-C or Object Lock-protected
  versions. Objects report `x-amz-server-side-encryption-bucket-key-enabled` when the
  update asked for an S3 Bucket Key.
- Lifecycle rules from the command line, with mc's options: `teifs ilm rule add`
  (`--prefix`, `--tags`, `--size-gt`, `--size-lt`, `--expire-days`, `--expire-date`,
  `--expire-delete-marker`, `--noncurrent-expire-days`, `--noncurrent-expire-newer`,
  `--abort-uploads-days`, transitions), `edit --id` (what's given changes, the rest
  stays), `ls`, `rm --id|--all`, and `export` and `import` in the JSON AWS uses, so a
  configuration moves between `teifs` and the AWS CLI either way.
- Encryption from the command line, with mc's names: `teifs encrypt set sse-s3|sse-kms`
  (with `--bucket-key`, and `--block-sse-c` or `--allow-sse-c`), `clear` and `info` for a
  bucket's default, and `teifs encrypt update --kms-key KEY` to move one object, a
  version (`--version-id`) or everything under a prefix (`-r`) to a KMS key in place; a
  key's name is enough, its ARN is made from the alias's region and account. `stat`
  shows a bucket's default encryption and an object's Bucket Key.
- Encryption on transfers, by key prefix as mc names it: `cp`, `mv` and `mirror` take
  `--enc-s3 PREFIX`, `--enc-kms PREFIX=KEY` and `--enc-c PREFIX=FILE`, and `cat` and
  `stat` take `--enc-c`, for uploads, downloads, streams and copies by the server or
  through the client (source and destination keys apart). A customer key comes from a
  file (32 bytes, or base64 or hex) or `TEIFS_ENC_C` (`PREFIX=KEY,…`), never from the
  command line. Uploads encrypted with a KMS or customer key send SHA-256 part checksums
  so an interrupted one still resumes (their ETags aren't MD5s). `stat` shows an SSE-C
  object's key MD5, and a bare `400` on a read suggests `--enc-c`.
- A Complete of an upload with a `COMPOSITE` checksum must send every part's checksum,
  as on AWS (`400 InvalidRequest` naming the first part without one); it was accepted.
- `teifs key rewrap NAME` seals again, under a KMS key's newest version, the data keys
  its older versions sealed (object versions, locked ones too, and uploads in progress),
  without touching the data; `--dry-run` counts them. Running it again carries on.
- DSSE-KMS (`aws:kms:dsse`) on PutObject, POST forms, CopyObject, uploads in parts and
  as a bucket's default, reported where AWS reports it: each object is encrypted twice,
  under a data key sealed by the KMS key and another sealed by the drive's managed key
  (AES-256-GCM packages, each then under AES-256-CTR), with no change in size. No S3
  Bucket Keys, sealed checksums, and UpdateObjectEncryption refuses it, as on AWS.
  `teifs key rewrap` covers both keys. From the command line: `teifs encrypt set
  dsse-kms KEY ALIAS/BUCKET` and `--enc-dsse PREFIX=KEY` on `cp`, `mv` and `mirror`.
- Encrypted uploads in parts: a part number sent again was encrypted under the same
  key and nonces as the first time; each part now has a random salt in its key
  (encryption format 2). And an encrypted object completed from part numbers with gaps
  (1, 3, 7) couldn't be read; each part's number and key are now recorded with the
  object. Objects stored before keep reading as they did.
- A listing of an object bucket stopped early when a stretch of keys held only delete
  markers; it now carries on past them.
- Metadata snapshots: a running server copies its drive's databases (buckets,
  settings, IAM and the object index) every day into `.teifs/backups/auto/`, keeping
  the newest three (`--snapshots N`, 0 for none), consistently while it serves and
  checked before they're kept. `teifs admin snapshot take|ls ALIAS` (admin API
  `POST|GET snapshots`, `teifs:TakeSnapshot` and `teifs:ListSnapshots`) takes one now or
  lists them. `teifs backup [DIR] --to FOLDER` writes one elsewhere, and
  `teifs restore [DIR] --from FOLDER|SNAPSHOT` puts a backup or snapshot back on a drive
  no server has open, after checking it's of that drive and intact, keeping what it
  replaces.
- Bucket metadata export and import, as MinIO's `mc admin cluster bucket
  export|import`: `teifs admin bucket export ALIAS[/BUCKET]` writes every bucket's
  layout, versioning and settings (policy, lifecycle, Object Lock, encryption, CORS,
  tags, ABAC, ACL, Object Ownership, Block Public Access) as JSON, and
  `teifs admin bucket import ALIAS FILE` creates the missing buckets and applies each
  setting, checked as S3's own calls check it, with a report item by item (admin API
  `GET|PUT buckets`, `teifs:ExportBucketMetadata` and `teifs:ImportBucketMetadata`).
  Objects aren't moved.
- `teifs repair [DIR] [--apply] [--forget-missing]` finds where a drive's metadata
  and its files disagree, on a drive no server has open, and reports it; with
  `--apply` it sets right what's safe to. Objects written after a restored snapshot
  get their versions back from what each data file records, in their place among a
  key's versions; a file a crash left behind after it was replaced, and upload folders
  of no upload, are removed. Versions whose data file is missing are only forgotten
  with `--forget-missing`, and files it can't tell apart safely, or folders of no
  bucket, are reported and left alone. It refuses databases SQLite finds damaged, and
  rebuilds a lost object index from the data files. Exit code 1 while problems are left.
- Prometheus metrics at `/.teifs/metrics` (OpenMetrics text): requests by operation
  and HTTP status, errors by S3 error code, requests in flight and canceled, time to
  first byte and to the last, bytes received and sent, the disk's size and free space,
  and the background jobs' progress. A scrape needs a bearer token whose key may
  `teifs:GetMetrics`: `teifs admin prometheus generate ALIAS [--expires D]
  [--token-file F]` makes one, signed with the alias's key as `mc admin prometheus
  generate` does, and prints the scrape configuration. `teifs serve --public-metrics`
  serves them to anyone instead.
- `teifs_store_stage_seconds{op,stage}`: how long the store's writes spend getting a
  data key, waiting for the commit lock, syncing and committing, and its reads finding a
  version and getting its key, to tell a slow disk or KMS from a slow network.
- Bucket notifications, as S3's and MinIO's: `teifs serve --notify-webhook ID=URL`
  (repeatable; its token from `TEIFS_NOTIFY_WEBHOOK_TOKEN_ID`) gives the server a
  target, `arn:teifs:sqs::ID:webhook` (MinIO's `arn:minio:sqs::ID:webhook` too), and
  `PutBucketNotificationConfiguration` sets a bucket's rules with S3's checks and test
  event (`GetBucketNotificationConfiguration` reads them; `mc event add|ls` work). Objects
  written, removed, tagged, locked, read (MinIO's `ObjectAccessed`) and expired by
  lifecycle rules send S3's event records (version 2.6) in MinIO's envelope, each queued
  on the drive before the request is answered and sent in order, retried until taken, so
  a target that's down or a restart loses nothing. `teifs admin config` lists the targets,
  and the metrics count each target's events sent, failed, dropped and waiting. Bucket
  exports carry the rules.
- Listening for events, as MinIO's API: `GET /BUCKET?events=…` (or `GET /?events=…` for
  every bucket) answers with each event as it happens, filtered by event, prefix and
  suffix, whatever the bucket's rules, with buckets created and removed too; `mc watch`
  works, and `teifs watch ALIAS[/BUCKET[/PREFIX]]` shows them.
- Elasticsearch (and OpenSearch) notification targets, as MinIO's: `teifs serve
  --notify-elasticsearch ID=URL,index=NAME[,format=namespace|access][,user=NAME]`, with
  the password or API key from the environment. The namespace format keeps a document
  per object (removed with it), the access format one per event; the index is created
  when missing.
- Redis notification targets, as MinIO's: `teifs serve --notify-redis
  ID=HOST:PORT,key=NAME[,format=namespace|access][,db=N][,user=NAME][,tls=true][,ca=PATH]`,
  with the password from the environment. The namespace format keeps a hash with a field
  per object, the access format a list with an entry per event. `tls=true` connects over
  TLS, verified with the system's certificates or, with `ca=PATH`, a CA's PEM file.
- NSQ targets over TLS (`tls=true` or `ca=PATH`, as nsqd negotiates it after
  `IDENTIFY`) and with `AUTH`, its secret from `TEIFS_NOTIFY_NSQ_SECRET_ID`, sent only
  over TLS.
- In the settings file, relative paths in notification targets' and the audit webhook's
  options (`ca=`, `client_cert=`, `client_key=`, `creds=`, `nkey=`,
  `server_public_key=`) are relative to the file, as its other paths are.
- Kafka targets compress with Snappy, LZ4 and zstd too (`compression=snappy|lz4|zstd`),
  as Kafka's own readers take them; zstd is produced with Produce v7 (Kafka 2.1 or later).
- Server access logging, as S3's: `PutBucketLogging` and `GetBucketLogging` send a
  bucket's requests, one S3 access log record each (all 27 fields, in S3's format and
  with its operation names), to a target bucket, under a prefix, as log objects named as
  S3 names them (`SimplePrefix`, or `PartitionedPrefix` by event or delivery time).
  Copies also log the read of their source, multi-object deletes each key, and lifecycle
  removals are logged as S3's own (`S3.EXPIRE.OBJECT`, requester `AmazonS3`). The target
  must let the logging service in, as on S3: a bucket policy for the service principal
  `logging.s3.amazonaws.com` (which policies may now name, with `aws:SourceArn` and
  `aws:SourceAccount`) or, where ACLs are on, a grant to the log delivery group, which
  `IgnorePublicAcls` leaves alone as on S3. Records wait in the drive's system folder and
  are delivered every 5 minutes (`serve --access-log-interval`), at 1 MiB or at midnight,
  and after a restart; secrets in a request's query never reach a record. Metrics:
  `teifs_access_log_records_total`, `teifs_access_log_objects_total`,
  `teifs_access_log_dropped_total`.
  Admin exports and imports carry buckets' logging.
- Access logs from the command line: `teifs logging set SOURCE TARGET[/PREFIX]
  [--format simple|event-time|delivery-time]` (which, as the S3 console does, adds the
  logging service to the target's bucket policy unless `--no-policy`), `teifs logging
  info` and `teifs logging rm`.
- An embedded server releases its drive when it stops, so the same process can open it
  again.
- Website configurations, as S3's: `PutBucketWebsite`, `GetBucketWebsite` and
  `DeleteBucketWebsite`, with an index document, an error document and up to 50
  redirection rules, or every request redirected to another host; checked with S3's
  error codes and messages, answered as given, and carried by admin exports and imports.
  From the command line: `teifs website set ALIAS/BUCKET [--index I] [--error E]
  [--rules FILE]` (redirection rules as the S3 console writes them) or `--redirect-all
  URL`, `teifs website info` and `teifs website rm`.
- Static websites, as S3's website endpoint: `teifs serve --website-domain DOMAIN`
  (repeatable; `TEIFS_WEBSITE_DOMAINS`) serves each bucket with a website configuration
  at `BUCKET.DOMAIN`, answering `GET` and `HEAD` with what the bucket lets anybody read:
  index documents, a folder's redirect to its slash, the error document, redirection
  rules, redirects of every request and of single objects, S3's HTML error pages,
  ranges, conditional requests and CORS. Access logs record these requests as
  `WEBSITE.GET.OBJECT`. A domain can't be both a `--domain` and a `--website-domain`.
- `teifs status [ALIAS]`: how a server is doing, as a list of checks (answers and how
  fast, the drive serving and taking writes, the clocks, the certificate's expiry,
  version, disks, jobs, scrubs), with exit code 1 when one fails. `teifs-client` asks
  the health checks too (`Client::health`).
- `teifs migrate SOURCE DEST`: buckets moved from any S3 service (MinIO, AWS,
  RustFS, TeiFS) to another, with every version and delete marker in order, each
  object's headers, metadata, tags, retention and legal hold, the same ETags (objects
  uploaded in parts are copied in parts of the same sizes), and the buckets' settings.
  The two sides are compared key by key, so running it again carries on where it
  stopped and copies only what's new; `--latest`, `--dry-run`, `--size-only`,
  `--no-configs`.
- `teifs cp` and `teifs mirror` between endpoints keep every header a copy by the
  server keeps (`Cache-Control`, `Content-Disposition`, `Content-Encoding`,
  `Content-Language`, `Expires`, website redirect), not only the type and metadata.
- Requester Pays (`Put/GetBucketRequestPayment`): a Requester Pays bucket refuses
  anonymous requests, whatever its policy allows, and can't receive access logs.
- Inventory, analytics, metrics and Intelligent-Tiering configurations
  (`Put/Get/Delete/ListBucket…Configuration`), kept and answered as given with S3's
  checks, 1,000 of a kind per bucket and lists of 100 with continuation tokens. Bucket
  exports and `teifs migrate` carry them, and Requester Pays.
- Inventory reports, as S3 Inventory delivers them: for each enabled inventory
  configuration, daily or weekly (on Sundays, UTC), data files of the bucket's current
  objects or every version with the fields chosen (gzipped CSV, or ORC and Parquet with
  S3's typed columns), a Hive
  `symlink.txt`, and a `manifest.json` with its `manifest.checksum`, written by
  `s3.amazonaws.com` into a destination whose bucket policy lets it in, encrypted as the
  configuration asks. `teifs inventory add|ls|info|rm` manages them and lets S3
  Inventory into the destination.
- Request metrics, as S3's in CloudWatch: each metrics configuration counts the
  requests it matches (every request to its bucket, or those on objects with its prefix
  and tags) as `teifs_request_metrics_…` Prometheus metrics labeled by bucket and
  `filter_id`, with CloudWatch's names: requests by kind, bytes up and down, 4xx and 5xx
  errors, and first-byte and total latency. `teifs metrics add|ls|info|rm` manages them.
- Storage class analysis exports, as S3 writes them: an analytics configuration with an
  export adds each day's figures (storage, uploads, retrievals and requests by object age
  group, and `ALL`) to `PREFIX/BUCKET/ID.csv` in its destination, written by
  `s3.amazonaws.com` into a bucket whose policy lets it in. `teifs analytics
  add|ls|info|rm` manages them and lets S3 into the destination.
- `teifs tiering add|ls|info|rm` for Intelligent-Tiering configurations and
  `teifs requester-pays enable|disable|info`.
- External KMS: a Vault or OpenBao transit engine, KES (MinIO's `MINIO_KMS_KES_*`
  variables work) or AWS KMS hold the keys instead of the local keyring;
  `--kms-default-key` uses an existing key for SSE-S3, and `teifs doctor` asks the KMS.
- LDAP sign-in, as MinIO's `AssumeRoleWithLDAPIdentity`: `teifs serve --ldap-server …`
  (or MinIO's `MINIO_IDENTITY_LDAP_*` variables) lets a directory's users get temporary
  credentials with their name and password (`teifs sts assume-ldap`), with the policies
  mapped to them and their groups (`teifs admin ldap policy attach|detach|ls`). Users
  the directory no longer has lose their sessions within ten minutes.
- Client certificate sign-in, as MinIO's `AssumeRoleWithCertificate`: `teifs serve
  --identity-tls` lets clients with a certificate your CA issued get temporary
  credentials with the policy its common name names (`teifs sts assume-cert`).
- Identity plugin sign-in, as MinIO's `AssumeRoleWithCustomToken`: `teifs serve
  --identity-plugin-url URL --identity-plugin-role-policy NAMES` (or MinIO's
  `MINIO_IDENTITY_PLUGIN_*` variables) lets your own service decide whom a token belongs
  to; clients exchange it for temporary credentials with the role's policies (`teifs sts
  assume-custom`). `teifs doctor` checks that the plugin answers.
- MinIO's OpenID role policies: `teifs admin oidc add … --role-policy NAMES` gives
  each of a provider's clients MinIO's role ARN (`arn:minio:iam:::role/…`, shown by
  `teifs admin oidc ls`), and tokens for that client that name it get those policies.
  A role ARN no provider has is ignored when the token names policies in a claim, as on
  MinIO, and MinIO's `AssumeRoleWithClientGrants` works too. With `--claim-userinfo`,
  a token's claims are completed from the provider's userinfo endpoint with the access
  token a request gives (`WebIdentityAccessToken`), as MinIO's `claim_userinfo`.
- OpenID Connect providers in the server's settings, as MinIO's `identity_openid`:
  `teifs serve --openid-config-url URL --openid-client-id ID [--openid-role-policy
  NAMES | --openid-claim-name CLAIM] [--openid-claim-userinfo]` (or MinIO's
  `MINIO_IDENTITY_OPENID_*` variables, one provider for each suffix) makes the provider
  when the server starts, or brings it in line; `teifs admin config` shows them.
- IAM SAML providers, as on AWS: `CreateSAMLProvider`, `GetSAMLProvider`,
  `ListSAMLProviders`, `UpdateSAMLProvider`, `DeleteSAMLProvider` and their tags, with
  AWS's checks of the metadata document (its issuer and signing certificates), its
  limits (100 providers, two private keys each) and its messages. Private keys for
  encrypted assertions (`AddPrivateKey`, `RemovePrivateKey`,
  `AssertionEncryptionMode`) are stored sealed and never shown; an IAM export carries
  them only with `--secrets`. A role's trust policy can name a SAML provider of the
  account as its `Federated` principal once it exists. `teifs admin saml
  add|ls|update|rm` manages them.
- `AssumeRoleWithSAML`, as on AWS: a SAML 2.0 response of one of the account's SAML
  providers, signed by a key its metadata names (the response, its assertion or both),
  for AWS's sign-in endpoint and audience and within its times, gets the session of a
  role its `Role` attribute pairs with the provider, when the role's trust policy allows
  it with the `saml:` keys (`saml:aud`, `saml:iss`, `saml:sub`, `saml:sub_type`,
  `saml:namequalifier`, `saml:doc`, the eduPerson, Active Directory and X.500
  attributes). `RoleSessionName`,
  `SessionDuration`, `SourceIdentity`, `PrincipalTag:*` and `TransitiveTagKeys` work as
  on AWS, and the answer has `Subject`, `SubjectType`, `Issuer`, `Audience` and
  `NameQualifier`. The session's requests have `saml:sub`, `saml:sub_type` and
  `saml:namequalifier`. XML signatures are checked by TeiFS's own exclusive
  canonicalization and verifier, which refuse signature wrapping, document type
  declarations and entities. The audit log doesn't record a `SAMLAssertion` sent in the
  query.
- `teifs sts assume-saml SERVER --role-arn ARN --principal-arn ARN --assertion-file FILE`
  exchanges a SAML response (base64, or its XML; `-` reads standard input) for a role's
  credentials, saved as an alias or written for `aws`.
- Encrypted SAML assertions, as AWS takes them: an `EncryptedAssertion` whose key is
  encrypted with RSA-OAEP for one of the provider's private keys (the newest tried
  first) and whose assertion is encrypted with AES-128/256-CBC or AES-128/256-GCM is
  decrypted, then checked like a plain one. A provider whose `AssertionEncryptionMode`
  is `Required` refuses plain assertions and takes only its own sign-in endpoint
  (`…/saml/acs/` and its UUID) as the `Recipient`, which `teifs admin saml ls` now
  shows.
- The audit log no longer records the LDAP password, web identity token or custom token
  that MinIO's clients send in an STS request's query.
- `teifs serve` keeps serving on `SIGHUP` (`systemctl reload`) when it has nothing to
  reload; it used to stop.
- Linux packages: a `.deb` and an `.rpm` for x86_64 and arm64 with every release,
  installing `teifs`, its shell completions, a `teifs` system user and a hardened
  systemd service (`systemctl enable --now teifs`) that serves `/var/lib/teifs/drive`
  with settings in `/etc/teifs`. Removing the package keeps the drive.
- `teifs serve` tells systemd when it's ready and when it's stopping (`Type=notify`,
  through `NOTIFY_SOCKET`).
- A Helm chart (`packaging/helm/teifs`): a StatefulSet with volumes for the drive and the
  keyring, root keys from a Secret (made and kept when none is given) passed as a file,
  a non-root pod with a read-only root file system, MinIO's health probes, optional
  `teifs.toml`, HTTPS from a TLS Secret, Ingress and a Prometheus ServiceMonitor, and a
  `helm test`. Its version is TeiFS's.
- Every release carries a Homebrew formula (`teifs.rb`, macOS and Linux, with
  completions and a `brew services` service) and winget manifests, made from its
  checksums. The Docker image goes to Docker Hub as well when the repository has its
  keys.
- `teifs doctor [DIR]`: a drive on this machine checked with the settings
  `teifs serve` would use (its options, environment and the drive's settings file):
  its format, whether a server has it, its databases' integrity, how its file system
  treats names, whether it's on a network or FUSE file system, whether it can be written, its disk's room, the root keys, the keyring,
  the TLS certificates and the listen address, each problem with what to do, and exit
  code 1 when one fails. Nothing on the drive is changed.
- `teifs admin info` (and the admin API's server info) shows the disks the drive uses:
  its own and those of folder buckets linked from elsewhere, with their free space,
  size and the room kept free for deletes.
- `MinIO`'s health checks, as a single-drive `MinIO` answers them:
  `/minio/health/live`, `/minio/health/ready`, `/minio/health/cluster` and
  `/minio/health/cluster/read`, so probes set up for `MinIO` work unchanged.
- Snapshots and backups of a drive whose metadata folder went away (an unmounted disk)
  fail instead of saving an empty index that would pass for a drive with nothing in it,
  and make nothing where the drive was.
- As on AWS, a single upload (`PutObject`, a browser's `POST`, `UploadPart`) is at most
  5 GiB, refused with `EntityTooLarge` before its body when it says it's larger, and a
  copy (`CopyObject`, `UploadPartCopy`) reads at most 5 GiB of its source
  (`InvalidRequest`); larger objects go in parts.
- Bucket quotas, as `MinIO`'s hard quotas: `mc quota set|info|clear` (`MinIO`'s admin
  API, `/minio/admin/v3/set-bucket-quota` and `get-bucket-quota`, with its
  `admin:SetBucketQuota` and `admin:GetBucketQuota` actions) and `teifs quota set
  ALIAS/BUCKET --size SIZE`, `info` and `clear`. Writes that would reach a bucket's quota
  (`PutObject`, `POST`, `CopyObject`, `UploadPart`, `UploadPartCopy`) are refused with
  `MinIO`'s `XMinioAdminBucketQuotaExceeded`. Admin exports and imports carry quotas, and
  `teifs-client` has `bucket_quota` and `set_bucket_quota`.
- Sizes on the command line take `TiB` and `PiB` too.
- A `304 Not Modified` answers the object's `ETag` and `Last-Modified`, as HTTP says
  and S3 does.
- An object's `x-amz-website-redirect-location` must start with `/`, `http://` or
  `https://` (`InvalidRedirectLocation`), as on S3.
- Webhook, audit webhook and Elasticsearch targets over TLS of their own, as MinIO's
  webhooks: `ca=PATH` to verify the server with a CA, and `client_cert=PATH` and
  `client_key=PATH` for a server that asks for a client certificate (mutual TLS).
- MQTT targets over WebSockets: the broker given by its URL, as MinIO takes it
  (`ws://HOST[:PORT]/PATH` or `wss://…`, and `tcp://`, `ssl://`, `tls://`, `mqtt://`,
  `mqtts://`), asking for the `mqtt` subprotocol.
- Nightly CI sends events to a real nsqd, Redis, NATS JetStream and Mosquitto, each
  over TLS and signed in, and checks what each got.
- MySQL and MariaDB notification targets, as MinIO's: `teifs serve --notify-mysql
  ID=HOST:PORT,database=NAME,table=NAME,user=NAME[,format=namespace|access]`, with MinIO's
  tables (made when missing) and statements, prepared once per connection with their
  values bound. It signs in with `caching_sha2_password` (MySQL 8's default),
  `mysql_native_password` (MariaDB's) or `sha256_password`. A password that must be sent
  whole goes only over TLS or encrypted with the server's RSA key
  (`server_public_key=PATH`, or `get_server_public_key=true` to ask for it). The password
  comes from `TEIFS_NOTIFY_MYSQL_PASSWORD_ID`.
- PostgreSQL notification targets, as MinIO's: `teifs serve --notify-postgresql
  ID=HOST:PORT,database=NAME,table=NAME,user=NAME[,format=namespace|access]`. The
  namespace format keeps a row per object (`key`, `value` as JSONB), set by each event and
  deleted with the object; the access format adds a row per event (`event_time`,
  `event_data`). The table is made when missing. It signs in with SCRAM-SHA-256 (the
  server must prove it knows the password) or MD5, and sends a password in the clear only
  over TLS (`tls=true` or `ca=PATH`); values are bound as parameters, never put in the SQL.
  The password comes from `TEIFS_NOTIFY_POSTGRESQL_PASSWORD_ID`.
- AMQP 0-9-1 notification targets (RabbitMQ, LavinMQ), as MinIO's: `teifs serve
  --notify-amqp ID=amqp[s]://HOST[:PORT][/VHOST],exchange=NAME,routing_key=KEY`
  publishes each event to the exchange as JSON, with MinIO's `minio-bucket` and
  `minio-event` headers, persistent, and waits for the broker's publisher confirm. The
  exchange is declared when the connection is made (`exchange_type`, `durable`,
  `auto_delete`, `internal`), or only checked with `declare=false`; `mandatory=true` makes
  a message no queue takes fail and be tried again. The password comes from
  `TEIFS_NOTIFY_AMQP_PASSWORD_ID`, and `amqps://` connects over TLS.
- Kafka notification targets, as MinIO's: `teifs serve --notify-kafka
  ID=BROKER[;BROKER…],topic=NAME` produces each event, keyed `bucket/object`, to the
  partition Kafka's own clients pick for the key, on its leader, so each object's events
  stay in order. Every in-sync replica acknowledges each record (`acks=all`, or `acks=1`),
  a leader that moved is looked up again at once, and `compression=gzip`, SASL (`sasl=plain`,
  `scram-sha-256` or `scram-sha-512` with `user=NAME`, the password from
  `TEIFS_NOTIFY_KAFKA_PASSWORD_ID`) and TLS are optional. Works with Kafka 1.0 and later,
  Kafka 4 included.
- EventBridge, as S3's: with `teifs serve --notify-eventbridge ID=BUS_ARN`, a bucket
  whose notification configuration has `EventBridgeConfiguration` sends every event S3
  sends to EventBridge to the bus, with S3's `detail-type` and `detail`, using
  `PutEvents` signed with Signature Version 4 (source `teifs.s3`, since `aws.` sources are
  AWS's own). It was `501 NotImplemented`. `teifs event eventbridge ALIAS/BUCKET on|off`
  turns it on or off, and `teifs event add` makes a topic or function rule for an SNS or
  Lambda ARN.
- Lambda notification targets, as S3's: `teifs serve --notify-lambda
  ID=FUNCTION_ARN[,endpoint=URL]` invokes the function asynchronously with each event as
  S3 does, signed with Signature Version 4. Rules name it by the function's ARN, as on S3;
  a dry run checks the keys may invoke it when a rule starts naming it.
- SNS notification targets, as S3's: `teifs serve --notify-sns ID=TOPIC_ARN[,endpoint=URL]`
  publishes each event to the topic as S3 does (`{"Records":[...]}`, subject `Amazon S3
  Notification`), with `Publish` signed with Signature Version 4. Rules name it by the
  topic's ARN, as on S3.
- SQS notification targets, as S3's: `teifs serve --notify-sqs ID=QUEUE_URL[,region=NAME]`
  sends each event to the queue as S3 does (`{"Records":[...]}`), with `SendMessage`
  signed with Signature Version 4, keys from `TEIFS_NOTIFY_SQS_ACCESS_KEY_ID` and
  `_SECRET_KEY_ID` or AWS's own variables, FIFO queues grouped by object, and the
  answer's MD5 checked. Any service that speaks SQS's API will do. Rules may name the
  queue by its own ARN (`arn:aws:sqs:REGION:ACCOUNT:NAME`), as on S3.
- MQTT notification targets, as MinIO's: `teifs serve --notify-mqtt
  ID=HOST:PORT,topic=NAME[,qos=0|1|2][,user=NAME][,keepalive=SECONDS]` publishes each
  event over MQTT 3.1.1, acknowledged as its quality of service asks (1 by default), with
  the password from the environment and the same TLS options as Redis.
- NATS notification targets, as MinIO's: `teifs serve --notify-nats
  ID=HOST:PORT,subject=NAME` publishes each event to the subject, or with
  `jetstream=true` to a JetStream stream that acknowledges it (duplicates dropped by
  `Nats-Msg-Id`). It signs in with a user and password, a token (both from the
  environment), an nkey (`nkey=PATH`) or a `.creds` file (`creds=PATH`), over TLS with
  `tls=true` or `ca=PATH` (`tls_first=true` for `handshake_first` servers).
  Redis and NATS targets show a client certificate to a server that asks for one
  (`client_cert=PATH,client_key=PATH`). Redis, NSQ, NATS and MQTT targets keep a connection, and make one the server closed while
  idle again at once.
- NSQ notification targets, as MinIO's: `teifs serve --notify-nsq
  ID=HOST:PORT,topic=NAME` publishes each event to the topic over nsqd's TCP protocol. `teifs event add|ls|rm`
  manages a bucket's notification rules, as `mc event` does. It needs MinIO's
  `s3:ListenBucketNotification` (which bucket policies may grant, anonymous listeners
  included) or `s3:ListenNotification`.
- A client uploading to a server that refuses the upload (access denied, say) reads
  the refusal: a small body is read before the answer, where it used to be left unread
  and the connection closed, which could fail the client's write with a broken pipe.
  A client that waits for `100 Continue` gets the refusal without sending the body.
- `teifs admin trace ALIAS` shows each request the server answers, as it answers it
  (as `mc admin trace`): time, status, operation, bucket and key, client, duration and
  bytes, or with `--json` the audit entry. Filters (`--errors`, `--api`, `--bucket`,
  `--prefix`, `--status`, `--slower-than`) apply on the server. It's
  `GET /.teifs/admin/v1/trace` (JSON lines), which needs `teifs:ServerTrace`.
- The server's log names the request each line belongs to (`request{id=…}`, the id its
  answer carried), for what the store logs as well as the S3 layer.
- What the drive holds, in the metrics and in `teifs admin info`: buckets, objects,
  versions, delete markers and bytes stored, in total, and by bucket for a scrape with
  `?buckets=1` (`teifs admin prometheus generate --buckets`). The index keeps the counts
  as it changes, so reading them costs nothing however many objects there are. What the
  scrub found is in the metrics too: versions and bytes checked, damaged and
  unverifiable, for the pass under way and the last one.
- An audit log: `teifs serve --audit-log FILE` (or `-` for standard output) writes one
  JSON line per request with MinIO's audit fields: the operation, bucket and key, access
  key, client address, status and error code, bytes, time to first byte and to the last,
  the request id, and the request's query and headers and the answer's headers. Secrets
  (signatures, a link's signature, session tokens, cookies, SSE-C keys) are replaced by
  `REDACTED`. The file is created owner-only and reopened on `SIGHUP`; a queue keeps a
  slow disk from slowing requests, and entries it drops are counted in
  `teifs_audit_dropped_total`. `--audit-webhook URL` also sends the entries to a log
  collector, in batches of JSON lines retried until they're taken, with a token read only
  from `TEIFS_AUDIT_WEBHOOK_TOKEN`.
- Every answer has an `x-amz-request-id` (16 hex digits, as S3's), and S3 error bodies
  now name it in `<RequestId>`, as AWS's do; the admin, IAM and STS APIs use the same id.
- Documents printed to standard output (IAM and bucket exports, credentials with
  `--output -`, lifecycle exports) end with a newline.
- Snapshots and backups failed on Windows ("Access is denied"): their copies are now
  synced through a handle that may write.
- Integrity scrubs: a running server reads every stored version back every 30 days
  (`--scrub-every`, or `never`) and checks it against what was recorded when it was
  written, its checksums (each part's too) and its ETag, with encrypted objects
  authenticated as they decrypt; nothing new is stored per object. Passes go at the
  background jobs' pace, stop at shutdown and carry on after a restart. Damage is
  logged, and `GET info` (`teifs admin info`) shows the last pass, the one under way
  and the damaged versions. `teifs verify` does the same on a drive no server is using,
  naming each damaged version (missing, cut short, a checksum or ETag that doesn't
  match, a part that doesn't) and exiting 1; SSE-C objects, and encrypted ones without
  the keyring, are reported as not checked.

- `x-amz-expected-bucket-owner` and `x-amz-source-expected-bucket-owner` are checked,
  as on AWS: a request that expects another account to own the bucket (or a copy's
  source) is refused with `AccessDenied`. They were ignored.

- Attribute-based access control for buckets (ABAC), as AWS added it in November 2025:
  `PutBucketAbac` and `GetBucketAbac`; while it's on, a bucket's tags are
  `aws:ResourceTag` and `s3:BucketTag` in policies on the bucket and its objects, and
  change only one by one through S3 Control's `TagResource` and `UntagResource`
  (`ListTagsForResource` lists them), decided with `aws:RequestTag` and `aws:TagKeys`.
- `CreateBucket` takes tags, which need `s3:TagResource`, and policies see its
  `s3:locationconstraint`. A location constraint other than the drive's region is
  refused with `IllegalLocationConstraintException`; it was ignored.

- Policies can test `s3:TlsVersion` (the HTTPS connection's TLS version) and
  `s3:signatureAge` (how long ago a presigned link or form was signed, in
  milliseconds), as on AWS.
- `docs/ADMIN_API.md`: a reference for the admin API, S3 Control and the IAM and STS
  route: every endpoint, who may call it, its messages and errors.
- HTTPS: `teifs serve --certs-dir DIR` (MinIO's certificates folder layout, or a
  Kubernetes TLS secret's `tls.crt` and `tls.key`) or `--tls-cert` and `--tls-key`.
  Several certificates chosen by the name each client asks for, wildcards included;
  reloaded when their files change and on `SIGHUP`, keeping the ones in use when new
  ones don't load; TLS 1.3 and 1.2, HTTP/2; a handshake must finish within the header
  timeout; plain HTTP on the port is told to use HTTPS. `aws:SecureTransport` is true
  over it. `teifs health` asks over HTTPS when the server speaks it.
- `teifs alias set … --ca-cert FILE` (or `TEIFS_CA_CERT` for every alias) trusts a
  private or self-signed certificate authority besides the system's, for every command
  that uses the alias: S3, `teifs admin`, IAM and STS. A certificate error suggests it.
- Security: conditions on an object's own tags (`s3:ExistingObjectTag/…`) are decided
  with its tags, for every action AWS evaluates them with (reads, `HEAD`, copies from
  it, its ACL and tagging). They were never present, so an Allow on a tag didn't apply
  and a Deny on a tag didn't either.
- Security: IAM and STS answers and the admin API's IAM exports (access keys, session
  tokens) no longer appear in the server's `DEBUG` log.
- A body that doesn't match its signed `x-amz-content-sha256` is refused with AWS's
  `XAmzContentSHA256Mismatch` (was `BadDigest`).
- SSE-C keys are refused on plain HTTP for every request, as on AWS: reads, `HEAD` and
  copy sources too, not only writes.
- Reverse proxies: `teifs serve --trusted-proxy CIDR` (repeatable) lets the proxies there
  say who their clients are (`aws:SourceIp`) and whether they came over HTTPS
  (`aws:SecureTransport`, SSE-C), in `X-Forwarded-For` and `X-Forwarded-Proto`, or with
  `--proxy-header` RFC 7239's `Forwarded` or `X-Real-IP`. The header is read right to
  left, so what a client writes into it itself is never believed, and from anyone else
  it changes nothing (MinIO believes it from anyone).
- IAM, as AWS has it: users, access keys, groups, customer-managed policies with
  versions, inline policies, permissions boundaries and tags, with AWS's rules, quotas
  and error codes. Requests signed with a user's key do only what the user's policies
  allow. Manage it all with `aws iam --endpoint-url …` or any SDK: the IAM API (80
  actions, each authorized with AWS's condition keys) and STS `GetCallerIdentity` are
  served on the S3 endpoint. Access key secrets are stored sealed by the drive's KMS.
- IAM roles: CreateRole and the rest of AWS's role actions (trust policies, inline and
  attached policies, tags, permissions boundaries, maximum session length), in
  `ListEntitiesForPolicy`, `GetAccountSummary` and IAM export and import. A trust policy
  is checked as AWS checks it, and the users and roles it names are bound to their
  unique ids. Only the principals it names (or, with their own policies' consent, its
  account's) may assume the role: no identity policy alone lets anyone in.
- Temporary credentials from STS, as AWS has them: `AssumeRole` (trust policies,
  external ids, session policies, session tags, transitive tags and source identity
  along role chains), `GetSessionToken`, `GetFederationToken` and `GetAccessKeyInfo`,
  with AWS's durations, limits and error codes. They sign S3, IAM and STS requests with
  their session token in the `x-amz-security-token` header, a presigned link or a
  browser upload's form, and do only what they were issued for; deleting a role or user
  ends its sessions at once. MinIO's `AssumeRole` without a role gives a user
  credentials for their own permissions, narrowed by a session policy.
- `MinimumSessionTokenSize` on every STS action that issues credentials, as AWS added
  it: the session token is padded to at least the size asked for (up to 4096 bytes).
- IAM OpenID Connect providers: CreateOpenIDConnectProvider and the rest of AWS's
  provider actions (audiences, certificate thumbprints, tags), with AWS's limits, and in
  IAM export and import. A provider's URL may also have a port, and `http://` for an
  identity provider on the same machine.
- Web identity federation, as AWS has it: `AssumeRoleWithWebIdentity` exchanges an
  OpenID Connect ID token (GitHub Actions, GitLab, Kubernetes, Google, Keycloak, any
  provider with OpenID Connect Discovery) for a role's temporary credentials, unsigned as
  the AWS CLI and SDKs send it. The token's signature (RS256/384/512, PS256/384/512,
  ES256/384/512) is checked with the provider's published keys, fetched and kept as
  its `Cache-Control` says, and its issuer, audience and expiry as AWS checks them.
  Trust policies test the provider's keys (`token.actions.githubusercontent.com:sub`,
  `:aud`, `:amr` and any other claim), `aws:FederatedProvider` and
  `sts:RoleAuthorizedByIdp`; session tags and a source identity come from the token's
  `https://aws.amazon.com/tags` and `source_identity` claims.
- MinIO's `AssumeRoleWithWebIdentity` without a role: for a provider tagged
  `teifs:policy-claim`, a token's `policy` claim (or the claim the tag names) lists the
  managed policies its session gets, narrowed by a session policy, for as long as the
  token lasts or up to 365 days. Deleting the provider ends its sessions.
- `teifs sts`: `whoami`, `assume` (a role's session, or MinIO's session for a user's
  own permissions) and `assume-web` (a CI job's OpenID Connect token, from AWS's
  `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`). Temporary credentials are saved as
  an alias that keeps its session token and expiry (and is refused once expired, with
  what to do), or written in the AWS CLI's `credential_process` format. Aliases in the
  environment take a session token too (`https://KEY:SECRET:TOKEN@host`, as `mc`
  does), and every command, `teifs admin` included, signs with it.
- An OpenID Connect provider's thumbprints are used as AWS uses them: its keys are
  fetched over a certificate the system trusts, or else one whose chain leads to a
  certificate with one of its thumbprints (a company's own certificate authority, or a
  self-signed server), with the host name and dates still checked.
- Bucket policies, as AWS has them: Put/Get/DeleteBucketPolicy and
  GetBucketPolicyStatus, checked when stored and applied to every request, the root
  user's included (who can always fix the policy). Unsigned requests get what a policy
  grants everyone, and nothing else. Block Public Access per bucket
  (Put/Get/DeletePublicAccessBlock), with all four settings on for every new bucket.
- Object Ownership and ACLs, as AWS has them: Put/Get/DeleteBucketOwnershipControls,
  bucket and object ACLs (Get/PutBucketAcl, Get/PutObjectAcl) and ACL headers on
  CreateBucket, PutObject, CopyObject and CreateMultipartUpload. New buckets disable
  ACLs, as on AWS, so a write with a public ACL such as `public-read` now fails with
  `AccessControlListNotSupported` instead of being accepted and ignored; enable ACLs on a
  bucket with PutBucketOwnershipControls, or start the server with
  `--legacy-bucket-defaults` to make new buckets as S3 did before April 2023.
- Browser uploads (PostObject): a web page can upload straight to a bucket with a
  `POST` form signed by the server's owner, whose policy decides the bucket, key, size
  and every other field, as on AWS. The form's `acl`, `tagging`, metadata and redirect
  fields work; the upload is authorized like a PutObject on the key the form names, and
  anonymous forms get only what a bucket policy grants.
- Upload size limits signed into a link: `teifs presign --put --max-size 10MiB` (or
  `x-teifs-max-content-length` in any Signature V4 signed PutObject's query) makes a link
  that refuses a larger body before storing it, and `x-teifs-max-total-object-size` on
  CreateMultipartUpload caps every part of the upload together. The limit is part of the
  signature, so whoever holds the link can't raise or remove it.
- Presigned links refuse `x-amz-*` headers that weren't signed, so whoever holds a link
  can't add an ACL, tags, metadata or encryption to what it uploads (tested).
- With `--allow-sigv2`, requests for a whole bucket (creating, listing, its settings)
  work: they are signed over `/bucket/` as AWS and boto3 sign them. A Signature V2
  request without a valid date is `403 AccessDenied`, as on AWS.
- Account-wide Block Public Access, with AWS's S3 Control API
  (`aws s3control get|put|delete-public-access-block`): it applies with every bucket's
  own settings, the most restrictive winning.
- An admin API for what AWS has no API for: JSON under `/.teifs/admin/v1/`, signed like
  S3 requests (`curl --aws-sigv4` works), authorized with `teifs:*` actions in IAM
  policies. `GET info` reports the version, drive, account, uptime and background jobs;
  `GET config` how the server was started, without secrets.
- Move IAM between drives: `GET /.teifs/admin/v1/iam` exports users, groups, policies
  and keys as JSON (with the keys' secrets from `iam/secrets`, for the root user only),
  and `PUT /.teifs/admin/v1/iam` imports an export into an empty IAM, all or nothing,
  with the IAM API's own checks; `?account=adopt` also takes the export's account id.
- `teifs admin`: `info`, `config`, `iam export|import` and `root-key rotate` through an
  alias, with `--json`; an export with secrets goes only to an owner-only file, and a
  rotation updates the alias. `teifs-client` is the admin API as a Rust library.
- `teifs admin user`: a user with a policy (`readonly`, `readwrite`, `admin` or a policy
  file, optionally limited to buckets) and an access key in one step, saved as an alias
  or to an owner-only file, never printed unless asked for with `--output -`. Also
  `ls`, `rm` (keys, policies and groups first), `policy`, and `key add|ls|rm`. It
  speaks AWS's IAM API, and a user that can't be finished isn't left behind.
- `teifs admin role`: a role with a policy in one step, trusting the account, a user,
  a GitHub repository (`github:OWNER/REPO[:SUBJECT]`) or any OpenID Connect provider's
  subjects (`oidc:HOST --sub PATTERN`), or a trust policy file; `ls` sums up whom each
  role trusts, `policy` and `trust` change them, `rm` ends its sessions. `teifs admin
  oidc add|ls|rm`: OpenID Connect providers, with `--policy-claim` for MinIO's sessions
  without a role.
- Rotate the root key without a restart: `POST /.teifs/admin/v1/root-key` replaces a
  drive-generated root key, saves it in `.teifs/credentials.json` and answers it; the
  old key stops working at once.
- `teifs cp - ALIAS/BUCKET/KEY` uploads standard input of any size (parts sent in
  parallel, holding one per request in memory; an upload that fails is aborted), and
  `teifs cp ALIAS/BUCKET/KEY -` writes an object to standard output.
- Downloading a multipart object no longer logs a warning that its composite checksum
  can't be checked.
- Release builds for Linux (glibc, and static musl for any distribution), macOS
  (universal) and Windows (x64, arm64), with checksums and build provenance, and a Docker
  image (`ghcr.io/teispace/teifs`): static binary on distroless, non-root, `/data` and
  `/config` volumes, a health check.
- A health check for load balancers and containers: `GET /.teifs/health` answers
  `200 OK` without a signature, and `teifs health [ADDRESS]` asks it (exit code 0 when
  healthy).
- mimalloc as the memory allocator: about 4% faster uploads and up to 25% faster
  downloads measured on macOS, and far faster than musl's allocator on Linux.
- `teifs init` sets up a drive: its folder, keys, keyring (kept off the drive), settings
  and an alias, asking on a terminal or taking flags, then says what to run next.
  `teifs serve DIR` reads the drive's `.teifs/settings.toml` unless `--config` names
  another, and starts with a summary: endpoint, access key, keyring, and commands to try.
- One look for every command: `✓` for what was done, `warning:` and `error:` with what
  to do on the next line, aligned tables, and progress bars (bytes, speed, time left)
  for copies. Plain output when piped, `--json` (JSON Lines, errors included) for
  programs, `-q` for quiet, `-y` to answer questions, `--color` and `NO_COLOR`.
  `rm -r` asks before deleting unless `--force` or `-y`. `teifs completions SHELL`
  prints completions for bash, zsh, fish, PowerShell and Elvish.
- `teifs` is an S3 client too, for TeiFS or any S3 service: `alias`, `ls`, `mb`, `rb`,
  `cp`, `mv`, `rm`, `cat`, `stat`, `presign` and `mirror` on `ALIAS/BUCKET/KEY` paths.
  Large files go in parallel parts, an interrupted upload resumes, downloads replace a
  file only once complete, and copies within an endpoint are done by the server.
  Aliases are kept owner-only; secret keys never come from the command line. Exit codes
  tell scripts what failed. `teifs ls` now lists over S3 (it read the drive directly).
- Signature V2 is refused unless `serve --allow-sigv2` turns it on, as AWS does for its
  newer buckets. boto3 makes V2 presigned links by default; set
  `signature_version="s3v4"` or allow V2.
- A client matrix: the AWS CLI, rclone, restic, boto3, the Go and JavaScript SDKs and
  Terraform's S3 backend run their everyday work against TeiFS on both bucket layouts
  (`tests/clients/`), nightly, and the AWS CLI, boto3 and JavaScript on every change.
- Bounds on what a client can hold: headers must arrive within 30 s of connecting or of
  the last response, so silent, slow and idle connections close (`--header-timeout`;
  before, a connection that sent nothing was kept for ever); a stalled upload body fails
  with `400 RequestTimeout` after 60 s (`--body-timeout`); at most 4096 connections at
  once (`--max-connections`); user metadata over 2 KiB is `400 MetadataTooLarge` and a
  header section over 16 KiB is refused. Refused requests no longer log as errors.
- Settings file for `teifs serve` (`--config`, `TEIFS_CONFIG`): TOML under the flags'
  names, below flags and environment variables; `teifs config show` prints the effective
  settings and their sources. The secret key can come from a file
  (`--secret-key-file`, `TEIFS_SECRET_KEY_FILE`), and `MINIO_ROOT_USER` /
  `MINIO_ROOT_PASSWORD` are accepted when nothing else sets the keys.
- Folder buckets only create names every system can hold (no `CON`, `NUL.txt`, `a:b`,
  trailing dots or spaces), so a drive can move between Windows, macOS and Linux;
  `serve --key-names host` allows them outside Windows. On Windows such keys could
  reach something else (`a:b` names a hidden stream of `a`); they're now refused there.
  Keys differing only in Unicode form are refused like letter case on macOS.
- Durability modes (`serve --durability strict|relaxed|none`), one process per drive
  (`.teifs/lock`), and a full disk answers `507 XTeiFSStorageFull` before deletes stop
  working.
- Listing a large folder bucket page by page reads each folder once instead of once
  per page (a full listing of 50,000 files in one folder: 2.6 s → 0.2–0.4 s).
- Folder buckets are indexed in the background: files added or changed outside TeiFS
  get their MD5 ETag, restored files get their metadata back, and rows of deleted files
  are forgotten.
- Background jobs on a running server: unfinished multipart uploads are aborted after
  7 days (`--upload-expiry`), abandoned staged files are swept, and the garbage queue
  is retried without waiting for a restart.
- ListBuckets pages and filters (`max-buckets`, continuation tokens, `prefix`,
  `bucket-region`); an empty ListObjectsV2 continuation token starts from the top.
- CORS: bucket rules, preflight requests and `Access-Control-*` headers, as on S3.
- Object and bucket tagging, with S3's limits; copies keep or replace tags.
- Multipart checksums as on AWS: full-object (CRC32, CRC32C, CRC64NVME combined from
  the parts) and composite checksums, checked at Complete; CRC64NVME by default for
  objects sent without a checksum; retried Completes answer again. Under SSE-KMS and
  SSE-C, part checksums are sealed as soon as a part is stored.
- GetObjectAttributes, GetObject and HeadObject by part number, and HeadObject with a
  range; completed multipart uploads remember each part's size and checksums.
- RenameObject, with source and destination conditions and client tokens.
- Conditional deletes; `If-Match` on a missing object answers `NoSuchKey`, as on AWS.

- Object buckets, the default: every key S3 allows, stored by id and encrypted at rest;
  folder buckets keep plain files and are chosen per bucket.
- Encryption at rest in object buckets: SSE-S3 by default, SSE-KMS, SSE-C, bucket
  encryption settings with SSE-C blocked by default, and `teifs key` to manage KMS keys.

First development version: S3 over plain folders (buckets, objects, listings,
multipart uploads, copies, checksums, SigV4 and presigned URLs), a versioned on-disk
format with automatic upgrades, and the `teifs` command. ListObjectVersions and
`versionId=null` work on buckets without versioning, as on AWS.
