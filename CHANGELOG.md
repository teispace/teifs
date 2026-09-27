# Changelog

All notable changes to TeiFS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and TeiFS follows
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may change
behaviour; the on-disk format is always upgraded automatically.

## Unreleased

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
