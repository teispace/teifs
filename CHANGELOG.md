# Changelog

All notable changes to TeiFS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and TeiFS follows
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may change
behaviour; the on-disk format is always upgraded automatically.

## Unreleased

- IAM, as AWS has it: users, access keys, groups, customer-managed policies with
  versions, inline policies, permissions boundaries and tags, with AWS's rules, quotas
  and error codes. Requests signed with a user's key do only what the user's policies
  allow. Manage it all with `aws iam --endpoint-url …` or any SDK: the IAM API (50
  actions, each authorized with AWS's condition keys) and STS `GetCallerIdentity` are
  served on the S3 endpoint. Access key secrets are stored sealed by the drive's KMS.
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
