# Admin API

Everything TeiFS serves besides S3's operations: its admin API, for what AWS has no API
for, and the parts of AWS's other APIs it serves on the S3 endpoint (S3 Control, IAM and
STS). `teifs admin` calls the admin API through an alias, and the `teifs-client` crate
is the same as a Rust library.

## Requests

The admin API is JSON under `/.teifs/admin/v1/`, signed with Signature V4 like any S3
request (service `s3`). A bucket name can't start with a dot, so no path-style bucket
request reaches it; a virtual-hosted-style request (`photos.example.com/.teifs/…`) is a
key in that bucket, never the admin API. S3 Control requests are told apart from a
bucket's by the `x-amz-account-id` header, which must name the drive's account, and IAM
and STS requests by their form body, as the AWS SDKs and CLI send them.

With curl, which reads the key from standard input so it stays off the command line:

```sh
printf 'user = "%s:%s"\n' "$ACCESS_KEY" "$SECRET_KEY" |
  curl --config - --aws-sigv4 aws:amz:us-east-1:s3 http://127.0.0.1:9000/.teifs/admin/v1/info
```

## Who may call it

Unsigned requests and keys IAM doesn't know are refused before any endpoint runs. The
root user may call everything; an IAM user or role session needs the endpoint's action
in its policies (the resource is `*` for the admin API, the account for Block Public
Access), and endpoints marked *root user* are the root user's alone, whatever policies
say. S3 Control's calls on a bucket's tags are decided on the bucket
(`arn:aws:s3:::bucket`), with its bucket policy and, while its ABAC is on, its tags
(`aws:ResourceTag`); the tags a call adds are `aws:RequestTag` and `aws:TagKeys`, and
the keys it removes are `aws:TagKeys`. A bucket policy's Deny binds the root user here
too. The calls of `MinIO`'s admin API TeiFS serves (bucket quotas) are decided on the
bucket their `?bucket=NAME` names (`arn:aws:s3:::bucket`), with `MinIO`'s actions
(`admin:SetBucketQuota`, `admin:GetBucketQuota`) in the caller's policies; `s3:*` grants
none of them. Credentials from `GetSessionToken` and federated
users' sessions can't call the admin API or `MinIO`'s, as they can't call IAM on AWS.

## Endpoints

The table is generated from the server's route table (`crates/s3/src/routes.rs`), and a
test fails when it's out of date: `UPDATE_DOCS=1 cargo nextest run -p teifs-s3 -E
'test(admin_api_reference)'` writes it again.

<!-- generated: endpoints -->

### The admin API

| Method | Path | What it does | Who may |
|---|---|---|---|
| `GET` | `/.teifs/admin/v1/info` | Version, drive, account, uptime, what the drive holds, background jobs and what scrubs found: `ServerInfo` | `teifs:GetServerInfo` |
| `GET` | `/.teifs/admin/v1/config` | How the server was started, without secrets: `ServerConfig` | `teifs:GetServerConfig` |
| `GET` | `/.teifs/admin/v1/snapshots` | The drive's metadata snapshots, oldest first: `Snapshot`s | `teifs:ListSnapshots` |
| `POST` | `/.teifs/admin/v1/snapshots` | Snapshots the drive's metadata now (both databases, kept with the daily ones): `Snapshot` | `teifs:TakeSnapshot` |
| `GET` | `/.teifs/admin/v1/buckets` | Every bucket (`?bucket=NAME`: one) with its layout, versioning and settings: `BucketsExport` | `teifs:ExportBucketMetadata` |
| `PUT` | `/.teifs/admin/v1/buckets` | Imports a `BucketsExport`: creates missing buckets and applies the settings given, checked as S3's calls check them: `BucketsImportReport` | `teifs:ImportBucketMetadata` |
| `GET` | `/.teifs/admin/v1/trace` | A live trace: each request answered from now on, as its audit entry, one JSON line each (`application/x-ndjson`), until the caller leaves; the query filters it (`errors`, `api`, `bucket`, `prefix`, `status`, `slowerThanMs`) | `teifs:ServerTrace` |
| `GET` | `/.teifs/admin/v1/iam` | The account's IAM, access keys without their secrets: `IamExport` | `teifs:ExportIAM` |
| `GET` | `/.teifs/admin/v1/iam/secrets` | The account's IAM with access keys' secrets, to move it to another drive | root user |
| `PUT` | `/.teifs/admin/v1/iam` | Imports an `IamExport` into an empty IAM, all or nothing: `ImportReport`; `?account=adopt` also takes its account id | root user |
| `POST` | `/.teifs/admin/v1/root-key` | Replaces a root key the drive generated and answers the new one: `RootKeyRotated` | root user |

### S3 Control

| Method | Path | What it does | Who may |
|---|---|---|---|
| `GET` | `/v20180820/configuration/publicAccessBlock` | The account's Block Public Access settings | `s3:GetAccountPublicAccessBlock` |
| `PUT` | `/v20180820/configuration/publicAccessBlock` | Sets the account's Block Public Access, combined with every bucket's own | `s3:PutAccountPublicAccessBlock` |
| `DELETE` | `/v20180820/configuration/publicAccessBlock` | Removes the account's Block Public Access, leaving each bucket's own | `s3:PutAccountPublicAccessBlock` |
| `GET` | `/v20180820/tags/{resourceArn}` | A bucket's tags (`ListTagsForResource`) | `s3:ListTagsForResource` |
| `POST` | `/v20180820/tags/{resourceArn}` | Adds tags to a bucket, or changes their values (`TagResource`), with ABAC too | `s3:TagResource` |
| `DELETE` | `/v20180820/tags/{resourceArn}` | Removes a bucket's tags by key (`UntagResource`), with ABAC too | `s3:UntagResource` |

### IAM and STS

| Method | Path | What it does | Who may |
|---|---|---|---|
| `POST` | `/` | The IAM and STS Query APIs: each call names its action in the signed form | the action each call names |

### MinIO's admin API

| Method | Path | What it does | Who may |
|---|---|---|---|
| `PUT` | `/minio/admin/v3/set-bucket-quota` | Sets `?bucket=NAME`'s hard quota in bytes (`{"size":N,"quotatype":"hard"}`, or `quota` for `size`), or clears it with none: `mc quota set` and `clear` | `admin:SetBucketQuota` |
| `GET` | `/minio/admin/v3/get-bucket-quota` | `?bucket=NAME`'s quota (`quota` and `size` in bytes, `0` for none): `mc quota info` | `admin:GetBucketQuota` |

<!-- end generated -->

## Messages

Requests and answers are JSON objects with camelCase fields, defined with their
documentation in `teifs_types::admin` (`crates/types/src/admin.rs`), which the server and
clients share. Times are milliseconds since the Unix epoch (`startedMs`), and values that
name a choice (a layout, a durability) are strings, so a client keeps working when a
later server adds one. A client should ignore fields it doesn't know; an IAM import is
the exception, and refuses them, so nothing in an export is silently dropped.

An IAM export (`teifs-iam/1`) names users, groups, roles, policies and OpenID Connect
providers by name, not by id, so it can be imported into another drive's account. An
import makes everything with the IAM API's own checks, in one transaction or not at all;
gives everything new unique ids (names and ARNs stay); numbers policy versions from
`v1`; and skips, and reports, keys exported without secrets.

## Errors

Errors are JSON with the HTTP status that fits, and the request id (16 hex digits, as
every answer's, S3's included) also in the `x-amz-request-id` header:

```json
{"code":"AccessDenied","message":"…","requestId":"…"}
```

IAM's own errors keep IAM's code and status (`EntityAlreadyExists`, `409`). A path or
method the admin API doesn't serve is `404 NotFound`. Requests refused before they reach
the admin API (a signature that doesn't match, an unknown key) get S3's XML errors, as
from any S3 request; `teifs-client` reads both. `MinIO`'s admin API answers errors as
`MinIO` does, the JSON its clients read:

```json
{"Code":"NoSuchBucket","Message":"…","Resource":"/minio/admin/v3/get-bucket-quota","RequestId":"…"}
```

## Metrics

`GET /.teifs/metrics` serves Prometheus metrics in the OpenMetrics text format, beside
the admin API rather than in it: Prometheus can't sign requests, so a scrape carries a
bearer token instead, which `teifs admin prometheus generate ALIAS` makes and
[OPERATIONS.md](OPERATIONS.md) describes with every metric.
