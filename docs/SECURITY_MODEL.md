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
Signature V2 (HMAC-SHA1) is refused unless the operator turns it on with
`serve --allow-sigv2` for clients too old for V4.
The one unsigned request is the health check, `GET`/`HEAD /.teifs/health`: it answers
`200 OK` and nothing else (no version, no drive details), can't shadow a bucket (bucket
names never start with a dot), and on a virtual-hosted bucket's host the path is an
ordinary key that needs a signature. Otherwise there's no anonymous access today.
*Planned:* anonymous access only where a bucket policy grants it.

### 2. Every endpoint declares what it authorizes (*planned*)
Admin, health and metrics endpoints will be registered in one route table where each
route declares its action, and the server refuses to start a route without one. A test
walks the table and proves anonymous and under-privileged callers are rejected.
Profiling and debug endpoints are off by default and admin-only.

### 3. Policies are evaluated by a pure, heavily tested engine (*built; enforced for IAM users; bucket policies planned*)
`teifs-policy` has no I/O and decides in AWS's order: an explicit Deny in any policy
wins, then the root user, then a resource policy naming the principal, then identity
policies, which a permissions boundary and session policies can only narrow; anything
not allowed is denied. Condition keys come only from a typed context the server fills
in, never from request headers by name, and an unknown key is simply absent. The set
operators follow AWS exactly, negations included (`ForAllValues:` holds when the key is
absent: the known pitfall is kept, not "fixed"). Policies are refused, not half-read,
when anything in them is invalid, and a JSON key given twice is refused. `NotPrincipal`
goes only with Deny, and an account named in it spares only its root user. Every S3
operation maps to the actions AWS documents for it (`…Version` actions for a version),
checked against AWS's own reference by a test; a rename needs read and delete on the
source as well as write on the target.

Every request signed with an IAM user's key is decided before its operation runs
(`crates/s3/src/access.rs`), for exactly the bucket, key and copy or rename source the
operation will act on (both parse them with the same functions). A permission TeiFS
can't name a resource for is refused, never skipped. `DeleteObjects` decides each key on
its own, and a denied key is reported in the answer while the others go ahead.
Permissions that only add to an answer (a `GetObject`'s tag count, owners in a listing)
are withheld without failing the request. Multipart uploads belong to the user who
started them (any of their keys); only that user or the root user can continue them.
A key that's deactivated or deleted stops working at the next request.

### 4. Credentials can't be escalated (*secrets built; the rest planned*)
IAM access keys' secrets are stored sealed (AES-256-GCM, each bound to its access key
id) under an IAM key the drive's KMS seals, so `system.db` alone doesn't reveal them;
they're never logged, and shown once, when the key is created.
A key can only create keys with a subset of its own rights, never for another user; the
root account has no service accounts; bulk import goes through the same checks as single
changes.

### 5. No default secrets
There is no built-in access key or password. The first run generates random credentials
(256-bit secret) into `.teifs/credentials.json`, created with mode `0600`
(`crates/server/src/credentials.rs`). A secret key set by the operator is only read from
the environment or from a file of its own (`--secret-key-file`), never from a
command-line flag or the settings file, so it doesn't show in process lists or in copies
of the settings; `teifs config show` names its source and never prints it (tested in
`apps/cli/tests/config.rs`). Secrets shorter than 8 characters are refused.

### 6. Secrets never reach logs
Types holding secrets leave them out of `Debug` output (`Credentials`). *Planned:* a
`Secret<T>` wrapper everywhere, and a test that runs a request cycle at the most verbose
log level and searches the output for the secret.

### 7. Keys can't escape their bucket
Every key is parsed into an `ObjectKey` (`crates/types/src/names.rs`) that refuses empty,
`.` and `..` segments, a leading `/`, backslashes and NUL bytes, and on Windows the names
its path layer would redirect (devices such as `NUL.txt`, `a:b` streams, trailing dots and
spaces). Paths are built only
from checked parts, and the store compares the canonical path with the expected one
before using it, so symbolic links inside a bucket and names that differ only in case or
Unicode form (or an NTFS short name) are never followed or overwritten (`Inner::find` and `Inner::make_parents` in
`crates/store/src/folder.rs`). *Planned:* fuzzing of the parser and the path mapping.

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
input produces an error, not a crash. What one client can hold is bounded
(`crates/server/src/serve.rs`, `crates/s3/src/limits.rs`, tested over raw connections in
`crates/server/tests/limits.rs`): a client must send its headers within 30 s of
connecting or of its last response (`--header-timeout`), so silent, slow-header and idle
connections close; an upload body that stops arriving for 60 s fails with
`RequestTimeout` (`--body-timeout`), counting only time the server waits on the client;
at most 4096 connections are served at once, the rest wait in the system's queue
(`--max-connections`); header sections over 16 KiB and user metadata over 2 KiB are
refused before anything else looks at them. *Planned:* fuzzing of every parser.

### 12. Retention fails closed (*planned*)
When Object Lock arrives, any error reading an object's retention denies the delete or
overwrite.

### 13. Authorization before existence
A caller without access learns nothing about whether an object exists: requests are
authorized before they touch the drive, so conditional requests reveal nothing either,
and reading a missing key answers `403 AccessDenied` instead of `404 NoSuchKey` to a
caller who may not list the bucket, as AWS does.

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

### 16. The client keeps keys private and never writes outside its destination
`teifs` as a client keeps aliases in a file only its owner can read, written whole and
renamed into place; secret keys come from a hidden prompt, standard input, the
environment or a drive's own credentials file, never from the command line, and are
never printed (`Debug` leaves them out). A download writes only below the folder it was
given: keys with `..`, `.`, empty or absolute parts (and, on Windows, `\` or `:`) are
refused instead of mapped to a path. `teifs init` never prints the secret key (aliases
read it from the drive's file), writes no secret into the drive's settings, and refuses a
keyring on the drive itself. `--json` output and error records carry no secrets. Tests:
`apps/cli/tests/client.rs`, `apps/cli/tests/init.rs`, `apps/cli/src/client/target.rs`.

## Data safety

- Writes are atomic (stage, sync, rename, sync the folder), so a crash never leaves a
  half-written object. The metadata databases commit with `synchronous=FULL` (relaxable
  with `--durability`, never to the point of corruption).
- One process at a time opens a drive (`.teifs/lock`), so two servers can't break each
  other's atomic steps.
- A nearly full disk refuses new data before deletes stop working.
- The on-disk format is versioned; upgrades back up the metadata first
  ([ON_DISK_FORMAT.md](ON_DISK_FORMAT.md)).

## Supply chain

- `unsafe` code is forbidden in every crate (`unsafe_code = "forbid"`).
- Dependencies are few and reviewed; `cargo-deny` checks advisories, licenses, bans and
  sources on every change, and GitHub Actions are pinned by commit.
- Releases are built by `.github/workflows/release.yml` from a tag, with SHA256 checksums
  and build provenance attestations for every file; the Docker image is built from the
  release's own static binaries after verifying both, runs as a non-root user on a
  distroless base pinned by digest, and carries its own provenance and SBOM.

## Reporting

See [SECURITY.md](../SECURITY.md).
