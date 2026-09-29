# S3 compatibility

What TeiFS supports, how it's proven, and where it differs from AWS on purpose. Claims
here come only from tests; nothing is listed as supported because it "should work".

## How it's proven

| Evidence | What it covers | Where |
|---|---|---|
| AWS SDK for Rust, end to end | A real server driven by the official SDK: signed and presigned requests, chunked uploads with trailer checksums, multipart, copies, listings, conditional requests | `crates/server/tests/sdk.rs` |
| AWS CLI | A release build in CI: `mb`, a 20 MB multipart upload and download compared byte for byte (also on disk), recursive `ls`, `rm`, `rb`. By hand: `sync` both ways, presigned GET | `.github/workflows/ci.yml` |
| IAM API, end to end | The AWS SDK for Rust's IAM and STS clients and a real server: a user's whole life, keys users rotate themselves, tampered and unsigned bodies refused; every action refused to a user with no permissions; actions, resources and condition keys checked against AWS's service reference | `crates/server/tests/iam_api.rs`, `crates/iam/src/api/tests.rs` |
| Bucket policies, end to end | The AWS SDK for Rust and unsigned HTTP against a real server: policies and Block Public Access round-trip; malformed policies refused; public policies allow anonymous reads and nothing more; `RestrictPublicBuckets` closes 16 read and list paths (versions and uploads included); a Deny binds users and the root user while the root user keeps the policy; copies read under the source bucket's policy. By hand: the AWS CLI | `crates/server/tests/bucket_policy.rs` |
| Object Ownership and ACLs, end to end | The AWS SDK for Rust and unsigned HTTP on both bucket layouts: ACLs disabled on new buckets and every ACL write refused as AWS refuses it; ownership round-trips; CreateBucket's ACL checked against ownership and Block Public Access; public object and bucket ACLs open exactly the actions AWS maps to them; copies don't take the source's ACL; `IgnorePublicAcls`, disabling and re-enabling ACLs; `BlockPublicAcls`; grants to signed requests under boundaries and a policy Deny; ACL bodies and grant headers | `crates/server/tests/acl.rs` |
| Store tests | Keys, paths, atomic writes, listings in S3 order, multipart, copies, outside changes, case and link safety | `crates/store/src/tests.rs` |
| Format fixtures | Drives written by earlier releases open with all metadata | `crates/store/tests/format.rs` |
| ceph/s3-tests | The standard S3 conformance suite, run nightly; every test is in one of three lists (passing, not yet implemented, excluded with a reason) | `tests/s3-tests/` |
| Client matrix | Real clients doing what people do with them, on both bucket layouts: the AWS CLI, rclone, restic, boto3, the Go and JavaScript SDKs and Terraform's S3 backend with lock files, nightly (the AWS CLI, boto3 and JavaScript on every change) | `tests/clients/` |

## Operations

| Area | Status |
|---|---|
| ListBuckets, CreateBucket, HeadBucket, DeleteBucket, GetBucketLocation | Supported; ListBuckets pages (`max-buckets`, continuation tokens) and filters (`prefix`, `bucket-region`) |
| GetBucketVersioning | Supported (always "never enabled") |
| PutObject, GetObject, HeadObject, DeleteObject, DeleteObjects, CopyObject | Supported, with ranges, `If-Match`/`If-None-Match`/`If-Modified-Since`/`If-Unmodified-Since` on reads, response header overrides, `COPY`/`REPLACE` metadata directives |
| ListObjects, ListObjectsV2 | Supported: prefix, delimiter, marker/start-after, continuation tokens, max-keys, `fetch-owner`, `encoding-type=url` (encoding the fields S3 encodes in each version) |
| ListObjectVersions, and `versionId` on reads, copies and deletes | Supported for buckets without versioning: each object is its only version, `null`; any other version id is `InvalidArgument` |
| A full disk | `507 XTeiFSStorageFull` (S3 never fills up), before the disk is completely full so deletes keep working, as MinIO's `XMinioStorageFull` |
| Multipart: Create, UploadPart, UploadPartCopy, ListParts, ListMultipartUploads, Complete, Abort | Supported; 5 MiB minimum part size except the last, up to 10,000 parts. Unlike AWS, uploads left unfinished for 7 days are aborted (`--upload-expiry`, or `never`) so abandoned parts don't fill the disk |
| Checksums: Content-MD5, CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, SHA-512, MD5, XXHASH64/3/128 | Supported, as headers or trailers; stored and returned with `x-amz-checksum-mode`; objects sent without one get CRC64NVME, as on AWS |
| Multipart checksums: `x-amz-checksum-type` `FULL_OBJECT` (CRC32, CRC32C, CRC64NVME, combined from the parts) and `COMPOSITE` (checksum of the parts' checksums, `-N`), checked at Complete; `x-amz-mp-object-size`; a retried Complete answers again | Supported, with AWS's algorithm and type rules |
| Signature V4 (headers, presigned, chunked, trailers); path-style and virtual-hosted-style | Supported |
| Signature V2 | Refused by default, as AWS does for its newer buckets; `serve --allow-sigv2` accepts it for old clients. boto3 makes V2 presigned links unless the client sets `signature_version="s3v4"` |
| Request limits: user metadata (`x-amz-meta-*` names and values) at most 2 KiB, `400 MetadataTooLarge`; a stalled upload body `400 RequestTimeout` | As AWS. Headers are limited to 16 KiB in all (`400 RequestHeaderSectionTooLarge`), more than AWS's 8 KiB for PUT, so long presigned or signed requests still fit |
| Conditional writes on PutObject, CompleteMultipartUpload and CopyObject (`If-None-Match`, `If-Match`) | Supported; atomic on one server. `If-Match` on a missing object is `404 NoSuchKey`, as on AWS |
| Conditional deletes: `If-Match` on DeleteObject, per-object ETag, size and modification time in DeleteObjects, `x-amz-if-match-size` and `x-amz-if-match-last-modified-time` | Supported; deleting a missing object succeeds whatever the condition, as on AWS |
| RenameObject | Supported in both bucket kinds (AWS offers it in directory buckets): source and destination conditions, `x-amz-client-token` idempotency (remembered for a day). A real rename in folder buckets; encrypted objects rename without being re-encrypted |
| GetObjectAttributes (ETag, size, storage class, checksum, parts with pagination); GetObject and HeadObject by part (`partNumber`); HeadObject with `Range` | Supported |
| Object tagging (Put/Get/DeleteObjectTagging, `x-amz-tagging` on PutObject, CopyObject and CreateMultipartUpload, `x-amz-tagging-directive`, `x-amz-tagging-count`) and bucket tagging | Supported, with S3's limits (10 per object, 50 per bucket, key and value lengths, characters); a tag change keeps Last-Modified and the ETag |
| CORS: Put/Get/DeleteBucketCors, preflight `OPTIONS`, `Access-Control-*` on requests with an `Origin` (errors included) | Supported: first matching rule, one `*` in origins and headers, 100 rules |
| Server-side encryption: SSE-S3 (`AES256`), SSE-KMS (`aws:kms`, named keys, encryption context), SSE-C (customer keys) on PutObject, GetObject, HeadObject, CopyObject (source and destination keys), multipart uploads and UploadPartCopy | Supported in object buckets, with AWS's rules: SSE-C only over a secure connection, ETags not MD5 for SSE-KMS and SSE-C |
| KMS | A local keyring, or a Vault/OpenBao transit engine (tested nightly against OpenBao); `teifs key` lists, creates and rotates keys in either |
| Get/Put/DeleteBucketEncryption, including `BlockedEncryptionTypes` | Supported. Object buckets default to SSE-S3 with SSE-C blocked, as AWS buckets do since April 2026 |
| DSSE-KMS (`aws:kms:dsse`), UpdateObjectEncryption, S3 Bucket Keys caching | Not yet (Bucket Key settings are recorded and reported) |
| IAM: users, access keys, groups, customer-managed policies (five versions), inline policies, attachments, permissions boundaries, user and policy tags | Supported with AWS's names, paths, quotas, size limits and error codes. Every request signed with a user's key is decided by the user's and its groups' policies and boundary, for the bucket, key and copy source the operation acts on |
| The IAM API (Query protocol) on the S3 endpoint: 50 actions, the above and `GetAccountSummary` | Supported: `aws iam --endpoint-url …` and the SDKs work unchanged. Each action is authorized as on AWS, with its condition keys (`iam:PolicyARN`, `iam:PermissionsBoundary`, `aws:RequestTag`, `aws:TagKeys`, `aws:ResourceTag`, `iam:ResourceTag`) on the entity's own ARN, whatever case a name is given in. Roles, MFA, login profiles, SSH and signing keys are not there; key last-use isn't recorded (`N/A`) |
| STS `GetCallerIdentity` | Supported; `AssumeRole` and other temporary credentials planned |
| Bucket policies: Put/Get/DeleteBucketPolicy, GetBucketPolicyStatus | Supported, with AWS's evaluation: a Deny binds everyone, the root user included, except that the root user can always read, replace and delete the policy; a statement naming a user grants it directly, one naming the account needs the user's own policy too; anonymous requests are decided as `Principal: *` and never manage the policy. Policies are checked when stored (`MalformedPolicy`): at most 20 KB, S3 actions and condition keys only, resources only in the bucket. "Public" is decided as AWS does: an Allow for everyone unless a condition pins fixed values of `aws:SourceIp` (no broader than /8, /32 for IPv6), `aws:SourceVpc(e)`, `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOwner`, `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:userid` or `s3:DataAccessPoint*` |
| Block Public Access: Put/Get/DeletePublicAccessBlock on buckets | Supported: all four settings on for every new bucket (and for folders made by hand), as on AWS. `BlockPublicPolicy` refuses a public policy; `RestrictPublicBuckets` makes a public policy grant nothing to anonymous requests, on every operation; `BlockPublicAcls` refuses public ACLs (`AccessDenied`); `IgnorePublicAcls` makes stored ones grant nothing. Account-level settings are planned with the admin API |
| Object Ownership: Put/Get/DeleteBucketOwnershipControls, `x-amz-object-ownership` on CreateBucket | Supported. New buckets are `BucketOwnerEnforced`, as on AWS: ACLs are disabled, writes with any ACL but `bucket-owner-full-control` fail with `AccessControlListNotSupported`, and reading an ACL answers the owner's full control. ACLs can't be disabled while the bucket's ACL grants others (`InvalidBucketAclWithObjectOwnership`); a bucket with no setting has ACLs, as S3's buckets from before April 2023. `serve --legacy-bucket-defaults` makes new buckets that way (no setting, no Block Public Access) |
| ACLs: Get/PutBucketAcl, Get/PutObjectAcl, canned ACLs and `x-amz-grant-*` on CreateBucket, PutObject, CopyObject and CreateMultipartUpload | Supported where Object Ownership enables them, with AWS's evaluation: an ACL allows what no policy decided (never past an explicit Deny or a permissions boundary), with AWS's mapping of ACL permissions to actions. A drive is one account, so a grant names the owner (`id=teifs`) or a group: everyone (`AllUsers`), every signed request (`AuthenticatedUsers`) or log delivery; other ids are `InvalidArgument`, email addresses `UnresolvableGrantByEmailAddress`. A copy never takes its source's ACL |
| POST uploads | Planned |
| Versioning, Object Lock, lifecycle | Planned |
| Notifications, website hosting, logging, replication | Planned |
| S3 Select, Glacier restore, torrents, Object Lambda, accelerate | Not planned for now |

## Bucket layouts

A bucket is either an **object bucket** (the default: objects stored by id, every key S3
allows, encrypted at rest) or a **folder bucket** (a folder of plain files). Choose when
creating it: the `x-teifs-bucket-layout: object|folder` header on CreateBucket, `teifs
bucket create --layout`, or the server's `--default-layout`. The differences below apply to folder
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
| Keys differing only in Unicode form (`é` composed or decomposed), on a disk that treats them as one name (APFS, HFS+) | The second: `409 XTeiFSKeyConflict` | Both accepted |
| Names Windows can't hold: device names (`CON`, `NUL.txt`, `COM1`, `LPT1`, …), any of `<>:"\|?*`, control characters, a segment ending in `.` or a space | `400 InvalidArgument` on every system, so the drive can move between them; `serve --key-names host` allows them except on Windows. Such files put there by other programs are still listed, read and deleted | Accepted |
| Folder bucket named after a Windows device (`con`, `nul`, `aux`, `prn`, `com1`, …) | `400 InvalidBucketName` | Accepted |
| A key ending in `/` with content | `400 InvalidRequest` (it's a folder) | Accepted |
| ETag of a file changed outside TeiFS | Provisional `<hex>-1` until the background indexer hashes it (within one pass, 30 minutes apart) | Always the MD5 |

Use an object bucket for data that needs these keys.
