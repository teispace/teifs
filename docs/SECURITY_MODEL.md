# Security model

TeiFS holds people's files and answers requests from the network, so security is part of
the design, not a later pass. This document lists the rules the code follows, what each
protects against, and where it's enforced. Rules marked *planned* belong to features that
don't exist yet; they're written down now so those features are built to them.

Many of these rules come from studying the published security advisories of other S3
servers: most were authorization gaps on secondary endpoints, policy logic errors, default
secrets, secrets in logs and path traversal. Each class has a rule here and, as the
feature lands, a regression test named after what it prevents.

## Threats

- **Anyone on the network** who can reach the endpoint: unsigned or forged requests,
  malformed input, resource exhaustion.
- **A holder of valid but limited credentials** trying to reach more than they're
  allowed.
- **Crafted object keys and bodies** trying to escape the bucket or corrupt the drive.
- **Local users** on the same machine: TeiFS's own files are readable only by its owner.

Out of scope: an attacker who already controls the machine or the account TeiFS runs as.

## Rules

### 1. Every request is authenticated or explicitly public
Requests must carry a valid AWS Signature V4 (headers or presigned URL), checked by s3s
before any operation runs; chunked uploads verify each chunk's signature as it streams.
There's no anonymous access today. *Planned:* anonymous access only where a bucket policy
grants it.

### 2. Every endpoint declares what it authorizes (*planned*)
Admin, health and metrics endpoints will be registered in one route table where each
route declares its action, and the server refuses to start a route without one. A test
walks the table and proves anonymous and under-privileged callers are rejected.
Profiling and debug endpoints are off by default and admin-only.

### 3. Policies are evaluated by a pure, heavily tested engine (*planned*)
Explicit deny wins over allow, and anything not allowed is denied. Condition keys come
only from facts the server establishes, never from request headers by name. Every S3
operation maps to the actions AWS documents for it, checked by a test.

### 4. Credentials can't be escalated (*planned*)
A key can only create keys with a subset of its own rights, never for another user; the
root account has no service accounts; bulk import goes through the same checks as single
changes.

### 5. No default secrets
There is no built-in access key or password. The first run generates random credentials
(256-bit secret) into `.teifs/credentials.json`, created with mode `0600`
(`crates/server/src/credentials.rs`). The secret key is only read from the environment,
never from a command-line flag, so it doesn't show in process lists.

### 6. Secrets never reach logs
Types holding secrets leave them out of `Debug` output (`Credentials`). *Planned:* a
`Secret<T>` wrapper everywhere, and a test that runs a request cycle at the most verbose
log level and searches the output for the secret.

### 7. Keys can't escape their bucket
Every key is parsed into an `ObjectKey` (`crates/types/src/names.rs`) that refuses empty,
`.` and `..` segments, a leading `/`, backslashes and NUL bytes. Paths are built only
from checked parts, and the store compares the canonical path with the expected one
before using it, so symbolic links inside a bucket and names that differ only in case are
never followed or overwritten (`Inner::find` and `Inner::make_parents` in
`crates/store/src/lib.rs`). *Planned:* fuzzing of the parser and the path mapping.

### 8. Only trusted proxies can set the client's address (*planned*)
`X-Forwarded-For` and similar headers will be read only from configured proxy addresses.

### 9. Untrusted content is never rendered in a privileged page (*planned*)
Any web interface that previews files renders them from a separate, sandboxed origin.

### 10. CORS never reflects arbitrary origins (*planned*)
CORS headers come only from a bucket's CORS rules; an origin is echoed with credentials
only when a rule names it.

### 11. Input is bounded
Request bodies stream to disk instead of memory; listings are paged (1000 keys at most);
`DeleteObjects` takes at most 1000 keys. `unwrap` is denied outside tests, so malformed
input produces an error, not a crash. *Planned:* header, idle and body-stall timeouts and
connection limits before the first release, fuzzing of every parser.

### 12. Retention fails closed (*planned*)
When Object Lock arrives, any error reading an object's retention denies the delete or
overwrite.

### 13. Authorization before existence
*Planned with policies:* a caller without access learns nothing about whether an object
exists, including through conditional requests.

### 14. Encryption at rest keeps its keys away from the data
Objects in object buckets are encrypted by default (SSE-S3), as specified in
[ENCRYPTION_FORMAT.md](ENCRYPTION_FORMAT.md): a random key per object, sealed by a KMS
key and bound to the object's drive, bucket and object ids; 64 KiB authenticated
packages that can't be reordered, cut short or moved. The KMS keyring lives outside the
drive (`<config dir>/teifs/keys/<drive id>.json`, mode `0600`), so a copy of the drive
alone reveals nothing; or the keys stay in a Vault or OpenBao transit engine, whose token
comes only from the environment. SSE-C keys are never stored (only a salted HMAC to recognize
them), are refused over plain HTTP except on loopback, and are blocked on buckets by
default. Keys are wiped from memory when dropped. Tests prove no plaintext reaches the
disk and tampered data fails to decrypt (`crates/store/src/sse_tests.rs`).

### 15. Browsers get only what a bucket's CORS rules grant
No bucket answers cross-origin requests until its owner adds CORS rules. A preflight is
answered from the first rule whose origin, method and every requested header match, and
refused otherwise. Credentials are allowed only for origins a rule names (not `*`), as
S3 does. CORS never grants access by itself: requests are still signed and authorized.

## Data safety

- Writes are atomic (stage, sync, rename, sync the folder), so a crash never leaves a
  half-written object. The metadata databases commit with `synchronous=FULL`.
- The on-disk format is versioned; upgrades back up the metadata first
  ([ON_DISK_FORMAT.md](ON_DISK_FORMAT.md)).

## Supply chain

- `unsafe` code is forbidden in every crate (`unsafe_code = "forbid"`).
- Dependencies are few and reviewed; *planned:* `cargo-deny` (advisories, licenses,
  sources) in CI, GitHub Actions pinned by commit, and provenance attestations on
  release artifacts.

## Reporting

See [SECURITY.md](../SECURITY.md).
