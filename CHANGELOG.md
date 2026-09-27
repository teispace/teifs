# Changelog

All notable changes to TeiFS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and TeiFS follows
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may change
behaviour; the on-disk format is always upgraded automatically.

## Unreleased

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
