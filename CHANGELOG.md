# Changelog

All notable changes to TeiFS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and TeiFS follows
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may change
behaviour; the on-disk format is always upgraded automatically.

## Unreleased

- `teifs init` sets up a drive: its folder, keys, keyring (kept off the drive), settings
  and an alias, asking on a terminal or taking flags, then says what to run next.
  `teifs serve DIR` reads the drive's `.teifs/settings.toml` unless `--config` names
  another, and starts with a summary: endpoint, access key, keyring, and commands to try.
- One look for every command: `✓` for what was done, `warning:` and `error:` with what
  to do on the next line, aligned tables, and progress bars (bytes, speed, time left)
  for copies. Plain output when piped, `--json` (JSON Lines, errors included) for
  programs, `-q` for quiet, `-y` to answer questions, `--color` and `NO_COLOR`.
  `rm -r` asks before deleting unless `--force` or `-y`.
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
