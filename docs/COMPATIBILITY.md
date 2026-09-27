# S3 compatibility

What TeiFS supports, how it's proven, and where it differs from AWS on purpose. Claims
here come only from tests; nothing is listed as supported because it "should work".

## How it's proven

| Evidence | What it covers | Where |
|---|---|---|
| AWS SDK for Rust, end to end | A real server driven by the official SDK: signed and presigned requests, chunked uploads with trailer checksums, multipart, copies, listings, conditional requests | `crates/server/tests/sdk.rs` |
| AWS CLI | A release build in CI: `mb`, a 20 MB multipart upload and download compared byte for byte (also on disk), recursive `ls`, `rm`, `rb`. By hand: `sync` both ways, presigned GET | `.github/workflows/ci.yml` |
| Store tests | Keys, paths, atomic writes, listings in S3 order, multipart, copies, outside changes, case and link safety | `crates/store/src/tests.rs` |
| Format fixtures | Drives written by earlier releases open with all metadata | `crates/store/tests/format.rs` |
| ceph/s3-tests | The standard S3 conformance suite, run nightly; every test is in one of three lists (passing, not yet implemented, excluded with a reason) | `tests/s3-tests/` |

**Coming:** a client matrix in CI (AWS CLI, rclone, restic, boto3, the Go and JavaScript
SDKs, the Terraform S3 backend).

## Operations

| Area | Status |
|---|---|
| ListBuckets, CreateBucket, HeadBucket, DeleteBucket, GetBucketLocation | Supported |
| GetBucketVersioning | Supported (always "never enabled") |
| PutObject, GetObject, HeadObject, DeleteObject, DeleteObjects, CopyObject | Supported, with ranges, `If-Match`/`If-None-Match`/`If-Modified-Since`/`If-Unmodified-Since` on reads, response header overrides, `COPY`/`REPLACE` metadata directives |
| ListObjects, ListObjectsV2 | Supported: prefix, delimiter, marker/start-after, continuation tokens, max-keys, `encoding-type=url` |
| ListObjectVersions, and `versionId` on reads, copies and deletes | Supported for buckets without versioning: each object is its only version, `null`; any other version id is `InvalidArgument` |
| Multipart: Create, UploadPart, UploadPartCopy, ListParts, ListMultipartUploads, Complete, Abort | Supported; 5 MiB minimum part size except the last, up to 10,000 parts |
| Checksums: Content-MD5, CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256 | Supported, as headers or trailers; stored and returned with `x-amz-checksum-mode` |
| Signature V4 (headers, presigned, chunked, trailers); path-style and virtual-hosted-style | Supported |
| Conditional writes on PutObject, CompleteMultipartUpload and CopyObject (`If-None-Match: *`, `If-Match`) | Supported; atomic on one server |
| Conditional deletes, RenameObject, GetObjectAttributes, reading one part (`partNumber`), tagging, CORS | Next |
| Server-side encryption: SSE-S3 (`AES256`), SSE-KMS (`aws:kms`, named keys, encryption context), SSE-C (customer keys) on PutObject, GetObject, HeadObject, CopyObject (source and destination keys), multipart uploads and UploadPartCopy | Supported in object buckets, with AWS's rules: SSE-C only over a secure connection, ETags not MD5 for SSE-KMS and SSE-C |
| Get/Put/DeleteBucketEncryption, including `BlockedEncryptionTypes` | Supported. Object buckets default to SSE-S3 with SSE-C blocked, as AWS buckets do since April 2026 |
| DSSE-KMS (`aws:kms:dsse`), UpdateObjectEncryption, S3 Bucket Keys caching | Not yet (Bucket Key settings are recorded and reported) |
| Bucket policies, users, STS, ACLs, POST uploads | Planned |
| Versioning, Object Lock, lifecycle | Planned |
| Notifications, website hosting, logging, replication | Planned |
| S3 Select, Glacier restore, torrents, Object Lambda, accelerate | Not planned for now |

## Bucket layouts

A bucket is either an **object bucket** (objects stored by id, every key S3 allows) or a
**folder bucket** (a folder of plain files). Choose when creating it: the
`x-teifs-bucket-layout: object|folder` header on CreateBucket, `teifs bucket create
--layout`, or the server's `--default-layout`. The differences below apply to folder
buckets only; object buckets have none of them. Folder buckets also can't be encrypted:
their objects are plain files by design.

## Differences from AWS in folder buckets, by design

Storing objects as plain files means some keys can't exist, the same way other S3 servers
that map keys to paths behave:

| Behaviour | TeiFS | AWS |
|---|---|---|
| Key with `.` or `..` segments, an empty segment (`a//b`) or a leading `/` | `400 InvalidArgument` | Accepted |
| Keys `a` and `a/b` at once | The second: `409 XTeiFSKeyConflict` | Both accepted |
| Keys differing only in letter case, on a case-insensitive disk | The second: `409 XTeiFSKeyConflict` | Both accepted |
| A key ending in `/` with content | `400 InvalidRequest` (it's a folder) | Accepted |
| ETag of a file changed outside TeiFS | Provisional `<hex>-1` until TeiFS reads it again | Always the MD5 |

Use an object bucket for data that needs these keys.
