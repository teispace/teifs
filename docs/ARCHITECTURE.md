# Architecture

A tour of the code for contributors: what each part does, how a request flows, and the
rules the design depends on. It describes the code as it is; when you change what it
says, change it in the same pull request.

## Bird's-eye view

TeiFS turns a folder (a **drive**) into an S3 endpoint with two kinds of bucket: **folder
buckets** (a folder at the drive's root, each object a plain file at its key's path) and
**object buckets** (every key S3 allows, stored by id under `.teifs/buckets/`). What S3
needs beyond the bytes lives in two SQLite databases in `.teifs/`. The layout is specified in
[ON_DISK_FORMAT.md](ON_DISK_FORMAT.md).

```
S3 client ──HTTP──▶ teifs-server ──▶ s3s (HTTP ↔ S3, signatures) ──▶ teifs-s3 (S3 operations)
                                                                        │
                                                                        ▼
                                                   teifs-store (buckets, objects, multipart)
                                                      │                      │
                                                      ▼                      ▼
                                             plain files on disk     teifs-meta (index.db, system.db)
```

## Code map

```
crates/types    teifs-types    Bucket names and object keys with their rules, object
                               attributes, file stamps, ETags, and the admin API's
                               messages (`admin`). No I/O.
crates/meta     teifs-meta     SQLite: the object index (index.db) and the system
                               database (system.db). All SQL lives here.
crates/crypto   teifs-crypto   Encryption at rest (docs/ENCRYPTION_FORMAT.md): data keys,
                               sealing, 64 KiB authenticated packages, SSE-C keys, the
                               KMS trait and the local keyring. aws-lc-rs only.
crates/policy   teifs-policy   The IAM policy language: parsing, conditions, policy
                               variables, the allow/deny decision, and which S3
                               actions each S3 operation needs. Pure: no I/O.
crates/iam      teifs-iam      IAM's users, access keys, groups, managed and inline
                               policies (AWS's rules and quotas), kept in system.db
                               with sealed secrets; who signed a request and which
                               policies apply to them.
crates/store    teifs-store    The storage engine: opening a drive (and upgrading its
                               format), folder buckets (folder.rs) and object buckets
                               (objects.rs) behind one API, staging and committing
                               writes, reads (ObjectBody), listings in S3 order,
                               copies, multipart uploads.
crates/s3       teifs-s3       The S3 operations: implements s3s's `S3` trait over a
                               store; checksums, S3 errors, continuation tokens; CORS,
                               the health check and trusted proxies (`src/proxy.rs`,
                               who the client is) in front of it.
crates/server   teifs-server   Credentials, the HTTP listener (HTTP/1.1 and HTTP/2,
                               plain or TLS: `src/tls.rs` loads certificates, picks one
                               per SNI name, reloads them), graceful shutdown, and
                               `Server::bind` / `run`, which the command and embedders
                               use.
crates/notify   teifs-notify   Bucket notifications' delivery: the server's targets
                               (webhooks, Elasticsearch, Redis, NSQ, NATS, MQTT,
                               Kafka (`kafka/`, its wire format in `wire.rs`, SASL
                               SCRAM in `scram.rs`), AMQP 0-9-1 (`amqp/`),
                               PostgreSQL (`postgres.rs`), MySQL (`mysql/`), both
                               through `sql.rs`, and AWS's SQS, SNS, Lambda and
                               EventBridge, signed in `aws.rs`), the queue on the drive (events.db, SQLite)
                               and a sender per target; the webhook code the audit log
                               shares; test doubles behind the `testing` feature.
crates/client   teifs-client   A typed client for the admin API (reqwest, Signature V4),
                               for `teifs admin` and apps that manage a server.
apps/cli        teifs          The `teifs` command: parses arguments, calls the crates,
                               prints results. `src/client/` is its S3 client (aliases,
                               cp/mirror with parallel, resumable transfers) on the AWS
                               SDK, for TeiFS or any S3 service; `client/migrate/` is
                               `teifs migrate` (listings compared key by key, exact
                               copies that keep ETags, buckets' settings). `src/ui.rs` does all its
                               output: styles, tables, progress bars, prompts, `--json`.
                               `src/init.rs` is `teifs init`; `src/admin/` is
                               `teifs admin`, on `teifs-client`, and its `users.rs`
                               `teifs admin user`, `roles.rs` `teifs admin role`
                               and `oidc.rs` `teifs admin oidc`, on the AWS SDK's
                               IAM client, with `policy.rs` their policy presets;
                               `src/sts.rs` is `teifs sts`, on its STS client.
                               `Alias::credentials` gives every client the alias's
                               keys and session token, and `client/trust.rs` the CA
                               it trusts besides the system's.
                               `src/checks.rs` reports the checks of `teifs status`
                               (`client/status.rs`, a server) and `teifs doctor`
                               (`src/doctor.rs`, a drive, through the store's
                               `diagnose`, which looks without opening it).
                               `src/notify.rs` tells systemd `serve` is ready or
                               stopping (`NOTIFY_SOCKET`).
packaging/      —              The Linux packages: `linux/` has
                               the systemd service, its sysusers entry, settings,
                               scripts and `nfpm.yaml`; `build.sh` makes the .deb and
                               .rpm, and `test-deb.sh` installs one and checks it.
                               `helm/teifs` is the Helm chart; `helm/check.sh` lints and
                               renders it, `helm/test-kind.sh` installs it on kind.
xtask           —              `cargo xtask`: verify, releases, and a release's Homebrew
                               formula and winget manifests (`manifests.rs`).
```

Dependencies point one way: `types` ← `meta` ← `store` ← `s3` ← `server` ← `cli`.
`policy` depends on no other TeiFS crate; `iam` depends on `meta`, `crypto` and `policy`.
Library crates never depend on the command line, and nothing depends on a user
interface, so the server can be embedded (Teitunnel will run it this way).

### Policies

`teifs-policy` reads IAM policies strictly: an unknown element, a repeated JSON key, a
malformed action, ARN, principal or condition is refused when the policy is stored,
never skipped when it's evaluated. `evaluate` decides one action on one resource from
the principal's identity policies, the resource's policy, a permissions boundary and
session policies, in AWS's order (`evaluate.rs` says it step by step). Conditions read
only a typed `Context` the server fills in: condition keys are closed enums
(`key.rs`), so no request header is ever looked up by a name a policy chose.
`authorizations` (`actions.rs`) says which actions an S3 operation needs, on which
resource, given the request's version id, tag, ACL and lock headers.

The tests hold it to AWS's behaviour three ways: `tests/reference.rs` checks the action
table and condition keys against AWS's machine-readable Service Authorization Reference
(`tests/fixtures/s3-reference.json`); `tests/corpus.json` has 270 requests against
policies from AWS's documentation and its known pitfalls, with the documented decision;
`tests/properties.rs` checks laws such as "a Deny anywhere wins" and "a boundary only
narrows" on thousands of random policies.

### IAM

`teifs-iam` keeps a drive's users, access keys, groups, roles, OpenID Connect providers
and policies in `system.db` and
the whole state in memory. A change (`Iam::change`) edits a copy of the state (entities
are behind `Arc`s, so the copy is cheap), checks AWS's rules against it, writes every
row it touched in one transaction, and only then swaps the copy in and rebuilds the
lookup that authentication reads: access key → secret and identity (principal, tags,
the user's and its groups' policies, parsed once, and the permissions boundary). Requests
never touch SQLite. The drive's root credentials are the account's root user.

Access keys' secrets can't be hashed (SigV4 signs with them), so each is sealed with
AES-256-GCM under an IAM key, bound to its access key id; the IAM key is sealed by the
drive's KMS under the context `{teifs:drive, teifs:purpose=iam}`. A stored policy that
no longer parses stops IAM from starting rather than being skipped, since skipping a
Deny would widen access.

A role's trust policy is a policy of its own kind (`Kind::Trust`): principals and `sts:`
actions only, no `Resource` (it's the role). When it's set, the account's users and roles
it names are resolved to their unique ids and kept with the role (`principals`), which
is how AWS keeps a principal that's deleted and made again under the same name from
inheriting the trust.

An OpenID Connect provider (`ops/oidc.rs`) is the issuer URL a web identity token must
name, the audiences it may be for and the certificate thumbprints it may be pinned to;
its ARN ends in the URL without the scheme, which is also what makes it unique.

`AssumeRoleWithWebIdentity` (`oidc/`) checks such a token before the trust policy sees
it. `oidc/jwt.rs` reads the token strictly (a JSON member named twice is refused) and
verifies its signature with aws-lc-rs, only with asymmetric algorithms and only with a
key that fits the algorithm; `oidc/keys.rs` fetches each provider's keys (OpenID
Connect Discovery, then its `jwks_uri`) with reqwest and keeps them in memory, one
fetch per provider at a time, with one client per set of thumbprints whose rustls
verifier (`oidc/tls.rs`) tries the system's trust store and then the pinned
certificates; `oidc/mod.rs` matches the issuer to a provider and checks
audience, subject and times, and turns the claims into the provider's condition keys.
Fetching is async and the STS API is not, so the S3 layer calls
`Iam::serve_web_identity`, which makes sure the keys the token needs are known before it
answers the request as any other STS call. The request is served as the anonymous
identity whatever signed it: the trust policy's `Federated` principal matches a
`WebIdentityUser` principal of that provider, and nothing else. Without a `RoleArn`,
for a provider tagged `teifs:policy-claim` (`oidc::policy_claim`), the session is
MinIO's: `Who::Web` keeps the provider's and the named managed policies' unique ids,
and `Snapshot` resolves them on every request, so a deleted provider ends the session
and a deleted policy drops out of it.

Temporary credentials (`sessions.rs`) are stateless: nothing about a session is
stored. Its access key id is `TSIA` and 16 random base32 characters; its secret is
derived from the id under the IAM key (HKDF, then HMAC), so a signature can be checked
from the id alone; its session token is its claims (whom it acts as by unique id, when
it was issued and expires, its session policies' documents, its tags, which of them are
transitive, its source identity, and for a web identity's session the provider and the
token's `aud`, `sub` and `amr`, and filler when `MinimumSessionTokenSize` asks for a
longer token) as JSON sealed with AES-256-GCM under the IAM key and
bound to the access key id, at most 6 KiB. A token works only with its own key and
can't be forged or changed. Every request turns the claims into an `Identity` against
IAM as it is now (`Snapshot::add_session`), so a role's or user's permissions changing
reaches its sessions at once, and a deleted one takes them with it (`Revoked`). The
identity is cached per access key id, with the token it was built from, until IAM next
changes (at most 4096, then the cache starts again). `Session::kind` says how it was
made, which decides the APIs it may call: role and MinIO-style sessions may use IAM and
the admin API; `GetSessionToken`'s and federated users' may not, as on AWS without MFA.
Session policies narrow `Identity::decide` and `within_boundary` to what one of them
allows (a federated user always has them, so none allows nothing).

`teifs-s3` enforces it (`access.rs`): `Auth` gives s3s each key's secret (a temporary
key's derived one), and `Access` runs before every operation, identifying the signer
with `Iam::identify` and the session token from the `x-amz-security-token` header, a
presigned URL's query or a browser upload's form. It builds the request's condition context (the connection
from `Client`, which the server sets per connection, the headers and query parameters that
are condition keys, request and principal tags), asks `authorizations` what the operation
needs and decides each permission for its bucket, object or copy/rename source. It leaves
a `Caller` in the request's extensions for what operations decide themselves: each key of
a `DeleteObjects`, optional details (tag counts, owners), who owns a multipart upload, and
whether a missing key may be reported as missing. Unsigned requests are decided the same
way as `Identity::anonymous()`. Each permission is decided with the bucket's rules
(`bucket_access.rs`): the bucket policy, parsed, whether it's public, its Block Public
Access settings, its Object Ownership and its ACL, read from the bucket's settings in
`system.db` once and cached until the drive changes them (a generation counter keeps a
read that raced a change from being cached; buckets that don't exist aren't cached).
`decide` applies `RestrictPublicBuckets` and the root user's policy rescue, then
`Identity::decide`. What no policy decides (an implicit deny, never an explicit one) an
ACL may still allow, where the bucket's ACLs apply (Object Ownership enables them and
`IgnorePublicAcls` is off): the bucket's ACL for bucket permissions, the object's (read
from its attributes only then) for object permissions, as AWS maps ACL permissions to
actions, and never past the caller's permissions boundary. Root requests on buckets
without a policy skip all of it.

A bucket with ABAC on has its tags in its rules (`BucketRules::resource_tags`), and
`with_resource_tags` adds them to the context (`aws:ResourceTag`, `s3:BucketTag`) of
each permission on the bucket or its objects, a copy's source with its own bucket's.
`CreateBucket`'s tags and location are in its body, which s3s parses after `check`, so
`check` leaves a `Deferred` in the extensions and the `S3Access::create_bucket` hook,
which s3s runs after parsing, decides it (`s3:TagResource` with the tags as
`aws:RequestTag`); the handler refuses a request still `Deferred`.

ACLs (`acl.rs`) are read from canned ACLs, `x-amz-grant-*` headers or an
`AccessControlPolicy` body into `teifs_types::Acl`, whose grantees are the owner and
S3's groups (a drive is one account). A bucket's ACL and Object Ownership live in its
settings, which the store changes atomically so ACLs can't be disabled while the
bucket's ACL grants others; an object's ACL is one of its attributes, never copied.

IAM is managed with AWS's own API: `teifs-iam`'s `api` module speaks the Query protocol
(a form body, answers in XML) for 80 IAM actions and STS's `AssumeRole` (AWS's, and
MinIO's without a role), `GetSessionToken`, `GetFederationToken`, `GetCallerIdentity`
and `GetAccessKeyInfo` (`api/sts.rs`). Actions are tables (`api/mod.rs`,
`api/sts.rs`) of name, resource kind and the condition keys they set; a test checks
both against AWS's service reference (`crates/iam/tests/fixtures`). `AssumeRole`
decides `sts:AssumeRole` (and `sts:TagSession`, `sts:SetSourceIdentity` when asked
for) with the role's trust policy as the resource policy, so a trust policy that names
a user needs nothing from the user's own policies, and one that names the account does. Each action
resolves the names it's given to the entity's own ARN and tags first, asks the caller's
`Identity::allows` (the same decision S3 requests get), then runs the operation.
`teifs-s3` serves it on the S3 endpoint (`iam_api.rs`): a signed `POST /` with a form is
dispatched on the signature's service (`iam` or `sts`). SDKs don't send
`x-amz-content-sha256` for the Query protocol, which s3s needs to check the signature,
so `cors::Service` adds it from the body before s3s sees the request, and the route
checks it again (`routes::signed_body`), so only the body that was signed is acted on.

Everything that isn't an S3 operation goes through one table (`routes.rs`), because s3s
hands such requests to a single custom route, before it parses a path as a bucket and
key and after it checks the signature. Each entry names its method, path and what it
needs of its caller (`Needs`: an action on a resource, an action on the bucket the path
names (`OnBucket`, decided with the bucket's rules and what the call asks for, read
first), or `PerCall` for the Query APIs, where IAM decides the action each call names),
with no default; a path ending in `{label}` matches anything in its place, and the table refuses
unsigned requests and unknown keys and decides the action before any handler runs. A
test walks `teifs_s3::endpoints()` with an anonymous caller and a user without
permissions, and another writes the table into `docs/ADMIN_API.md` (each entry's
`about`), failing when the reference is out of date. S3 Control (`control.rs`) is told apart from a bucket named `v20180820` by
its `x-amz-account-id` header, answers errors in its own `ErrorResponse` format, and
serves the account's Block Public Access, kept in `system.db`'s `settings` table: every
bucket's rules combine it with the bucket's own (`PublicAccessBlock::or`), and changing
it forgets every bucket's cached rules. It also serves buckets' tags
(`/v20180820/tags/{resourceArn}`), whose ARN is encoded in the path: botocore signs the
path as sent, and AWS's other SDKs encode it again first, which s3s doesn't check, so
`cors::Service` hands such a request to `control::call_encoded`, which buffers its small
body and, when the signature doesn't match, tries it once more with the path encoded
again, marking it so the route decodes it twice. The admin API (`admin.rs`) is JSON under
`/.teifs/admin/v1/`, which no path-style bucket request can reach (a bucket name can't
start with a dot); a virtual-hosted-style request (`bucket.domain/.teifs/…`) is that
bucket's key, so the route compares the `Host` header with the served domains, which
s3s doesn't pass to it. Its actions are `teifs:*`, or `Needs::Root` for what only the
root user may do. Bucket import (`bucket_export.rs`) applies each setting with the
checks S3's calls make (the same `from_dto` conversions, policy parsing and Block Public
Access checks), and forgets the bucket's cached access rules after each change that
feeds them. Requests s3s refuses before the route (a signature that doesn't match,
an unknown key) get S3's XML errors, everything after the admin API's JSON;
`teifs-client` reads both. The few calls of `MinIO`'s admin API TeiFS serves (bucket
quotas, `quota.rs`) are `Api::Minio` routes at `MinIO`'s exact paths
(`/minio/admin/v3/…`, and `v4` taken as `v3`), matched only path-style, so a bucket named
`minio` keeps its keys; they're decided with `MinIO`'s `admin:*` actions on the bucket
their query names (`Needs::OnQueryBucket`) and answer `MinIO`'s JSON errors. Quotas are
enforced in `Drive::check_write`, before a write's body is read, against the bucket's
usage counters (`Store::bucket_usage`, every version), so the check reads counters,
never a listing. Its messages are in `teifs_types::admin`, for the server and
clients alike; the server hands the service its settings (`Options::config`), and the drive
keeps its jobs' status (`Store::job_status`) for whoever holds it. IAM's changing
operations are methods of a `Draft` (a copy of the state and the writes to make), each
with all of its checks; `Iam`'s public methods run one per change, and `Iam::import`
(`transfer.rs`) runs many in one, so an import is checked exactly as the IAM API is and
lands in one transaction or not at all. The root key is part of IAM's locked state:
`Iam::replace_root_key` saves a new one through the server's `RootKeyStore` (only for
drive-generated credentials) before swapping it into the credential lookup.

The website endpoint (`website/serve.rs`) comes first in `cors::Service`: a `Host` of
`BUCKET.DOMAIN` for a website domain is answered there, before virtual hosts, the
health check and metrics. Each object it serves is read by an internal path-style
request (no `Host` header, no signature: anonymous) through the S3 service itself, with
the request's `Seen` so metrics and access logs count it as the website's
(`WEBSITE.GET.OBJECT`), and with only its range and conditional headers; the probe for a
folder's index and the error document are read with a `Seen` of their own, counted
nowhere. Answers the S3 service gives are passed on as they are (a success, `304`) or
turned into S3's HTML error page, whose code `observe` reads from `x-amz-error-code`.

### The protocol layer: s3s

[s3s](https://github.com/s3s-project/s3s) turns HTTP requests into typed S3 operations and
back: routing, XML, SigV4 (headers, presigned URLs, chunked and trailer bodies) and the
S3 error format. TeiFS implements the `S3` trait in `teifs-s3` (`drive.rs`). Nothing
outside `teifs-s3` and `teifs-server` knows about s3s.

`cors::Service` sees each request before s3s does, for what s3s answers differently from
AWS or can't tell TeiFS. `sig_v2.rs` refuses a Signature V2 request without a valid date
as AWS does, and gives a path-style V2 request for a whole bucket the `/` its signature
covers (`/bucket/`, as AWS and botocore sign it; s3s signs the path as sent). `post_form.rs` reads a browser upload's form fields (everything before the
file, at most 64 KiB) with s3s's own multipart parser, the same way s3s reads them, and
puts the bytes back in front of the body, so s3s parses exactly what TeiFS read. The
fields go into the request's extensions as a `Form`: `Access` authorizes the key it names
(the path names only the bucket) with its ACL, tags and `s3:authType` `POST`, and
`post_object` in `drive.rs` checks the key again and makes the upload a PutObject with
the fields s3s doesn't map (`acl`, `tagging` as XML). A PostObject that reaches `Access`
without a `Form` is refused, so no form is ever decided without being read. s3s checks
the signature, the policy and every field against it; `post_form.rs` checks the policy's
conditions again only to answer `403 AccessDenied` as AWS does.

`cors::Service` also watches each request (`observe.rs`): it gives it an id and a `Seen`
in its extensions, which `Access::check` and the routes name with the operation (s3s
resolves it before checking the signature but tells nobody until the access hook, so a
request refused by the signature check stays `unknown`). The request body is counted as
it's read and the answer's body as it's sent; the request is recorded in `metrics.rs`
when the answer's body is dropped, as canceled if that was before its end. On the way
out, an S3 error body without `<RequestId>` gets the request's id, since s3s leaves it
out. With an audit log, what the request asked (path, query and headers, secrets
redacted in `audit.rs`) is kept from its arrival, and `Access::check` records the key
and the bucket and key it's on; the entry goes to an `AuditSink` when the metrics
record the request, and to the sink even when the client left before an answer (`499`).
The server's sink (`crates/server/src/audit.rs`) gives each target (a file, standard
output, a webhook) a bounded queue and a writer task of its own: a file's reopens on
`SIGHUP`, a webhook's sends batches of JSON lines and retries each until it's taken.
Live traces (`trace.rs`) get the same entries from a broadcast channel, each watcher
through a task (`lines.rs`, shared with listeners) that applies its filter and feeds its
answer's body; entries are made
while a sink exists or anyone watches, and `Service::stopping` ends every trace when the
server stops, so shutdown doesn't wait on them.
Bucket notifications: a bucket's rules (`teifs_types::notify`: event names, the
overlap rule, target ARNs) are checked in `notification.rs` and kept with the bucket's
settings, read once into memory (`SettingCache`, as lifecycle rules are). After an
operation succeeds, `drive.rs` tells `events.rs` what happened to which objects; when the
server has targets, the rules that match pick the targets (`Notifier::resolve` reads a
rule's ARN: ours, MinIO's, or an AWS queue's, topic's or function's own), a bucket with
EventBridge on adds the server's bus for the events S3 sends there, and each event (S3's
record in MinIO's envelope; AWS targets unwrap it as S3 sends to them) is queued by `teifs-notify` in one SQLite transaction before the
request is answered. Each target's sender reads its events in order and deletes them once
taken, retrying with the audit webhook's backoff. The store's lifecycle job reports what
it removes through the `Expirations` hook, which `events.rs` implements, so expirations
are queued the same way before the job goes on. While someone listens (`listen.rs`,
MinIO's `GET /BUCKET?events=…`, claimed by the custom route before s3s reads the path),
`events.rs` also broadcasts each event, and buckets' creations and removals, as
ready-made lines that each listener's task filters.
Server access logs: a bucket's logging (`logging.rs`, checked as S3 checks it, with the
target's policy decided for the service principal `logging.s3.amazonaws.com`) is kept
with its settings. While any bucket logs, `cors::Service` keeps each request's arrival
(`access_log::Arrival`: the redacted URI, headers S3 logs, the client), `Access::check`
adds the requester, the signature and the records a request adds besides its own (a
copy's source, each key of a multi-object delete: `observe::also`), and `Watch::done`
turns them into records (`access_log/record.rs`: S3's fields and operation names) on a
bounded queue. The `AccessLogWorker`, which the server runs with the service's other
background jobs (`Workers`), appends them to a spool per
bucket in the drive's `access-logs/` folder and rolls each into a log object
(`Drive::deliver` with `logging::delivery`, which decides the delivery for the service
principal again: `delivery.rs`) on
the interval, at 1 MiB or on a new day; spools left by a stop are delivered at the next
start. Lifecycle removals are logged through the same `Expirations` hook as their
events; the store holds that hook weakly, since it holds a `Drive` that holds the store.
Inventory reports (`inventory/`): the inventory worker, also one of the `Workers`, looks
for due configurations 96 times a (drive's) day, lists the bucket a page at a time into
rows of typed values (`inventory/report.rs`) into data files in the configuration's
format (`inventory/files.rs`: gzipped CSV, or ORC and Parquet from Arrow batches), and
delivers them, the Hive
symlink, the manifest and its checksum through `Drive::deliver` as `s3.amazonaws.com`.
The day or week each configuration last had its report is a store note (`Store::note`),
so restarts neither repeat nor skip one; stopping ends a report after its current page,
never in the middle of a store call.
Request metrics (`request_metrics.rs`): once some bucket has a metrics configuration
or an analytics configuration that exports (`Store::any_bucket_counting_requests` at the
start, or a put or an import), `Watch::done` queues
each S3 request on a bucket (its method, which `Seen` keeps, operation, key, status,
bytes and times) on a bounded queue without waiting. The request metrics worker, one of
the `Workers`, matches it against the bucket's cached configurations (reading the
object's tags only for a tag filter) and moves the Prometheus families registered with
the server's `Metrics`, labeled by bucket and `filter_id`; every minute it removes the
series of configurations that are gone. For analytics configurations that export, it
counts successful `GetObject`, `PutObject` and `CopyObject` requests by the object's age
group into `analytics::Activity`, shared with the analytics worker (`analytics.rs`),
which keeps the counts as a store note every check and, once a day is over, lists each
configuration's objects by age group and adds the day's rows to its CSV through
`Drive::deliver`, the day each last exported being another note.
`GET /.teifs/metrics` is answered before s3s, like the health check, because a
scrape carries a bearer token (`teifs_iam::metrics_token`, a JWT signed with an access
key's secret) rather than a signature.

Upload size caps (`caps.rs`) are query parameters a Signature V4 signature covers.
`Access` reads and checks them for every request (where they apply, and only when
signed with V4) and passes them on as a request extension; `put_object` checks the
declared length and `stage` cuts off a body past it. A multipart upload's cap is stored
with the upload (`uploads.max_size`): each part is admitted against the room its other
parts leave (`Store::part_room`), and `put_part` checks the total again under the
store's lock, which also covers copied parts, before the part replaces any other.

## Two layouts, one API

`Store` resolves a bucket name to `Bucket::Folder` (a folder at the root) or
`Bucket::Object` (a record in `system.db`), and every operation dispatches on it. The
shared step is `Inner::commit_to`: a finished temporary file becomes the object `key`,
either renamed to its path (folder) or given a footer and stored by id with a row in
`object_versions` (object). An object bucket's versioning decides the version id a
write gets (`ObjectBucket::new_version_id`: a new one while enabled, else `null`) and
what a delete does (`Inner::delete_object`: remove the `null` version, add a delete
marker, or replace the `null` version with one); `Inner::version_row` finds the version
a read names and turns a delete marker into `StoreError::DeleteMarker`, which the S3
layer answers as AWS does. A folder bucket with versioning keeps the same semantics
with the file as the current version (`crates/store/src/folder_versions.rs`): before a
write or delete replaces the file, `Inner::archive_for_write` hard-links it into the
bucket's version store (the object-bucket machinery, under the folder bucket's record
id) as an older version; removing the current version by id puts the newest older one
back at the key's path (`Inner::restore_newest`); reads, tags and copies that name an
older version go to the version store; `Store::list_folder_versions` merges the files
with the version rows, key by key. `Index::batch` nests (savepoints), so these steps
join the batch that records the file. Object Lock (`crates/store/src/lock.rs`) rides on
the same paths: a version's retention and legal hold are part of its `ObjectAttrs`, so
archiving and restoring carry them; `Inner::lock_new_version` gives each new version
(in `commit_object` and `commit_file`, so every write, copy and completed upload) the
bucket's default retention or refuses a lock the bucket can't give; and
`lock::check_removal` runs in both permanent-delete paths (`delete_object_version`,
`delete_folder_version`). The bucket's configuration is its record's `objectLock`
setting, looked up by record id. Reads return an `ObjectBody`, which only ever yields the
object's own bytes (whole or a range). Copies between layouts clone the bytes where
the disk can. The tests in `crates/store/src/layout_tests.rs` run the same S3 behaviour
against both layouts.

## Encryption

`crates/store/src/sse.rs` turns what a write asks for (`Encryption`: none, SSE-S3,
SSE-KMS, SSE-C) into a data key through the KMS (or the customer's key) and records how
the object is encrypted (the row's `crypt` column and the data file's footer).
`Store::stage_for` gives a staged upload that encrypts as bytes arrive; `read_with`
unseals the key and returns an `ObjectBody` that decrypts only the packages a range
needs. Copies of encrypted objects are decrypted and encrypted again under the copy's own
key. The S3 layer (`crates/s3/src/sse.rs`) maps the SSE headers, the bucket's default
(`settings.rs`) and AWS's rules onto this. The server attaches a `LocalKms` keyring kept
outside the drive.

## How a write works

`PutObject` (`crates/s3/src/drive.rs` → `crates/store/src/lib.rs`):

1. **Stage.** The body streams into a new file in `.teifs/tmp/`, hashed as it goes (MD5
   for the ETag, plus any checksums the client sent or asked for). s3s has already
   checked the signature, and checks each chunk's signature as it streams.
2. **Verify.** Checksums the client sent must match what arrived, or the request fails
   with `BadDigest` and the staged file is deleted.
3. **Commit.** Under the drive's commit lock, the store checks preconditions against the
   current object, creates the parent folders (refusing to go through a file, a link or
   a name that differs only in case), renames the staged file into place, syncs the
   folder, and records the object's row in the index. The rename is atomic, so readers
   see either the old object or the new one.

A read opens the file first and then describes it from the index, so the bytes and the
metadata returned belong together even if the object is replaced during the read.

## Files are the source of truth

- A row in the index applies only while its file's size and modification time match
  (`Stamp::matches` in `crates/types/src/object.rs`). A file changed by anything else
  gets a provisional ETag (`<hex>-1`) and a content type guessed from its name, until
  the `index-folders` job (`crates/store/src/reconcile.rs`) hashes it: a file whose
  content still matches its old row (a restore that lost modification times) gets the
  row back with its metadata; any other gets a new row with its MD5. Rows of deleted
  files are forgotten.
- Listing a folder bucket walks its folders in S3's byte order
  (`crates/store/src/list.rs`), so objects added outside TeiFS appear immediately.
  Large folders' sorted contents are cached (`crates/store/src/folders.rs`) and used
  only while the folder's modification time is unchanged, so paging through a folder of
  a million files reads it once, not once per page; each page starts with a binary
  search.
  Object buckets list from the index with range queries, jumping past rolled-up common
  prefixes.
- Folders created on purpose (a `key/` object) stay when their last file is deleted;
  folders created only to hold a file are removed with it.

## Opening a drive

`Store::open` (`crates/store/src/lib.rs`) canonicalizes the folder, clears
`.teifs/tmp/`, reads or creates `format.json` and upgrades older formats
(`crates/store/src/format.rs`), then opens `index.db` and `system.db`. A drive from a
newer release is refused.

What each bucket holds (objects, versions, delete markers, bytes) is counted by SQLite
triggers on `object_versions` (by bucket id) and `objects` (a folder bucket's current
files, by name), in the same transactions as the rows (`crates/meta/src/usage.rs`, with
a test that checks the counters against a recount after thousands of random writes).
`Store::usage` (`crates/store/src/usage.rs`) joins them to the buckets; a scrape and
`GET info` read them without scanning anything. The store also times the stages of its
reads and writes (`crates/store/src/stages.rs`: histograms the server's metrics register
as `teifs_store_stage_seconds`).

## Background jobs

A running server keeps the drive tidy with jobs (`crates/store/src/jobs.rs`), started by
`Server::run` and stopped at shutdown:

| Job | Does |
|---|---|
| `expire-uploads` | Aborts multipart uploads unfinished after `--upload-expiry` (7 days by default) |
| `sweep-staging` | Removes staged files no write has touched for an hour (a crashed client's leftovers) |
| `housekeeping` | Retries data files the garbage queue holds; forgets retry answers older than a day |
| `index-folders` | Walks folder buckets page by page: hashes files added or changed outside TeiFS, re-adopts rows of restored files, forgets rows of deleted ones; rests 30 minutes after a full pass |
| `snapshot` | Copies `index.db` and `system.db` into `.teifs/backups/auto/<UTC time>/` once a day (`crates/store/src/snapshots.rs`, `VACUUM INTO`, checked, then renamed into place), the first when a server first starts the drive; keeps the newest `--snapshots` (3); `POST snapshots` takes one on request |
| `scrub` | Reads every stored version back and checks it (`crates/store/src/jobs/scrub.rs`, with `crates/store/src/verify.rs`): a pass starts `--scrub-every` (30 days by default) after the last one started, the first a full interval after the drive is first served; steps of up to 256 versions or 64 MiB, stopped mid-object at shutdown; where it is and what it found (the first 100 damaged versions) are kept in the system database's `scrub` setting, so a restart carries on; damage is logged as an error and shown by `GET info` |
| `lifecycle` | Applies buckets' lifecycle rules (`crates/store/src/jobs/lifecycle.rs`): walks each bucket with enabled rules a page of versions at a time (a key's versions always together), expires, removes and aborts through the store's own delete and abort operations, with the listed object's ETag, size and modification time as the delete's conditions; rests an hour after a full pass |

Lifecycle configurations are part of a bucket's settings (`crates/store/src/lifecycle.rs`
keeps them as they were given and evaluates them); a small cache, cleared whenever any
bucket's settings change, answers `x-amz-expiration` without reading them for every
request. `serve` has a hidden `--lifecycle-day` (`TEIFS_LIFECYCLE_DAY`) that makes a
lifecycle day seconds long, for testing rules; answers still count real days.

Offline tools work on a drive no server has open, holding its lock:
`teifs_store::restore` (`crates/store/src/snapshots.rs`) puts a snapshot back, and
`Store::repair` (`crates/store/src/repair.rs`) sets metadata and files in step again by
walking every object bucket's data folder (unlisted files get their rows back from their
footers through `Index::adopt_version`, which places a version by its modification
time) and every version with a data file (missing ones are reported).

Each job works in bounded steps on the blocking pool. After a step that did something it
sleeps for as long as the step took (so it uses at most half a core), and after a step
with nothing to do it waits for its idle interval. A job never loops without progress:
work that can't be done yet (a file still open on Windows) doesn't count. Each job's
steps, items and last error are kept for `teifs status`.

## Concurrency

- Blocking file and database work runs on Tokio's blocking pool (`Store::blocking`).
- One mutex around the index serves as the commit lock: whoever changes a file holds it
  until the file and its row agree again. The system database has its own lock, always
  taken after the index lock when both are needed.
- Reads don't take the commit lock while streaming.

## Errors

- `NameError` (types) for names that break the rules, `MetaError` (meta) for SQLite,
  `StoreError` (store) for everything the engine can report. `teifs-s3` maps each to the
  S3 error a client expects (`crates/s3/src/errors.rs`); unexpected I/O or database
  errors become `InternalError` and are logged.
- Request data never panics the server: `unwrap` is denied outside tests, and `expect`
  is used only for invariants.

## Tests

- Unit tests sit beside the code (`#[cfg(test)] mod tests`).
- `crates/store/tests/format.rs` opens a drive written by every earlier on-disk format.
- `crates/server/tests/sdk.rs` runs a real server and drives it with the official AWS
  SDK for Rust: signed requests, chunked bodies with trailer checksums, multipart,
  presigned URLs.
- Run everything with `cargo test --workspace`.
