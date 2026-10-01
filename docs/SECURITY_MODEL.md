# Security model

TeiFS holds people's files and answers requests from the network, so security is part of
the design, not a later pass. This document lists the rules the code follows, what each
protects against, and where it's enforced. Rules marked *planned* belong to features that
don't exist yet; they're written down now so those features are built to them.

Many of these rules come from studying the published security advisories of other S3
servers: most were authorization gaps on secondary endpoints, policy logic errors, default
secrets, secrets in logs and path traversal. Each class has a rule here and, as the
feature lands, a regression test named after what it prevents. The security suite
(`crates/server/tests/security/`, a module per class) holds those tests, naming the
advisories each one answers, and points to the other tests that prove a rule.

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
Every `x-amz-*` header of a signed request must be signed, presigned links included:
whoever holds a link can't add an ACL, tags, metadata or encryption to it, nor turn an
upload into a copy of another object (`x-amz-copy-source`), and nobody on the way can add
one to a signed request. Only `x-amz-content-sha256` may be added unsigned, as the AWS
SDKs do. A body that isn't what that header signed is refused
(`XAmzContentSHA256Mismatch`), each chunk's signature chains to the one before (so none
can be changed, repeated, reordered or left out), a trailer is signed and its checksum
checked, and a presigned link can't carry a streamed body at all. A copy needs read on
its source and write on its destination, as `CopyObject` or `UploadPartCopy`
(`crates/server/tests/security/signatures.rs`).
An upload link can carry a size cap in its query, which its Signature V4 signature
covers (`x-teifs-max-content-length`, and `x-teifs-max-total-object-size` for multipart
uploads): the declared length is checked before the body is read, the body is cut off if
it runs past the cap, and a multipart upload's parts are summed under the store's lock,
so parts sent at once can't add up past it. A cap that the signature wouldn't cover (an
unsigned or Signature V2 request) is refused, never quietly ignored.
A browser upload (`POST` with a form) is signed by its policy, which must name every
field the form sends. Its fields are read before any decision, at most 64 KiB of them,
and the upload is authorized on the key the form names, as a PutObject would be; a form
that couldn't be read is refused, never decided as if it had no fields. Error messages
that quote a request are XML-escaped.
The one unsigned request besides `AssumeRoleWithWebIdentity`, `AssumeRoleWithLDAPIdentity`, `AssumeRoleWithCertificate` and `AssumeRoleWithCustomToken` (section 4) is the health check, `GET`/`HEAD /.teifs/health`: it answers
`200 OK` and nothing else (no version, no drive details), can't shadow a bucket (bucket
names never start with a dot), and on a virtual-hosted bucket's host the path is an
ordinary key that needs a signature. `MinIO`'s health checks (`/minio/health/live`,
`ready`, `cluster`, `cluster/read`) answer the same way, with a status and `MinIO`'s
fixed headers only; as they can name a bucket called `minio`, only unsigned requests
for them are health checks, and a signed request reaches the bucket. Any other unsigned request is anonymous: it's
decided like any other, as `Principal: *`, so it gets only what a bucket policy grants
everyone. A new bucket blocks public access (all four Block Public Access settings on,
as on AWS), so a bucket becomes public only when its owner turns that off and writes a
public policy. With `RestrictPublicBuckets` on, a public policy grants anonymous
requests nothing, and the check sits in the one decision every operation goes through,
so no read or list path escapes it (the known bypass, anonymous `ListObjectVersions`,
has its own test with 15 other paths). Anonymous requests can never read or change a
bucket's policy.
A bucket's website (`serve --website-domain`) is read the same way: each request to it
is an anonymous `GetObject` or `HeadObject` through the same decision, never the owner's,
so a site shows only what its bucket already lets everybody read, and a private bucket's
site answers `403`. Only `GET` and `HEAD` reach it. A website domain can't also be a
`--domain`, so a website host is never mistaken for a signed virtual-hosted request, or
the other way round. Values an error page quotes are HTML-escaped, and an object's
`x-amz-website-redirect-location` must be a key of the bucket (`/…`) or an `http`/`https`
URL, checked when it's written.
A bucket's quota is set and read only with `MinIO`'s admin actions
(`admin:SetBucketQuota`, `admin:GetBucketQuota`) on that bucket, which `s3:*` doesn't
grant, so a user who may write objects can't lift the quota that limits them.

ACLs are disabled on every new bucket (Object Ownership `BucketOwnerEnforced`, as on
AWS): a request with an ACL other than the bucket owner's full control is refused, and
stored ACLs grant nothing. Where the owner enables them, an ACL can only add what no
policy decided: an explicit Deny still wins, a permissions boundary still limits, and
`BlockPublicAcls` refuses public ACLs while `IgnorePublicAcls` makes stored ones grant
nothing. A copy never takes its source's ACL. `serve --legacy-bucket-defaults` makes new
buckets as S3 did before April 2023 (ACLs enabled, no Block Public Access) for
applications that upload with public ACLs; it is off by default. The account's Block
Public Access settings (S3 Control) apply with every bucket's, each setting on where
either has it, so one setting closes every bucket at once.

Prometheus metrics (`/.teifs/metrics`) name operations, error codes, the disk's size and
(with request metrics) buckets and their metrics configurations' ids,
so they need a bearer token (a JWT signed with an access key's secret, checked against
that key's current policies for `teifs:GetMetrics`) unless the operator serves them
with `--public-metrics` (`crates/server/tests/metrics.rs`). A live trace
(`GET /.teifs/admin/v1/trace`) shows every user's requests, so it needs
`teifs:ServerTrace`; its entries are audit entries, secrets redacted the same way
(`crates/server/tests/trace.rs`).

### 2. Every endpoint declares what it authorizes (*built for IAM, STS, S3 Control and the admin API*)
Everything served besides S3's operations is one table (`crates/s3/src/routes.rs`) in
which each endpoint states what it needs: an action on a resource, the root user only,
or, for the IAM and STS Query APIs, the action each call names, which IAM decides. The
field has no default, so an endpoint can't be added without it. S3 Control's calls on a
bucket's tags are decided on the bucket, with its policy and ABAC tags and the tags or
keys the call names, read (at most 64 KiB, and only as signed) before the decision.
Their paths carry an ARN, which botocore signs as sent and AWS's other SDKs encode
again first; s3s checks only the first, so a failed signature is checked once more
with the path encoded again, before anything runs. The admin API's actions
are `teifs:*`, which only a policy naming them grants (`s3:*` doesn't); it never
returns secrets unless an endpoint says so and only the root user may call it: the IAM
export with secrets (sent `Cache-Control: no-store`) and the import, which sets secrets
and may change the account's id. An import goes through the same checks as the IAM API
(names, documents, quotas; imported secrets must be at least 32 printable characters;
no key may take the root's id), only into an empty IAM, in one transaction. The root
user can replace a root key the drive generated (`POST root-key`): the new key is saved
to the owner-only credentials file first (written beside it and renamed over it), and
only then does the old key stop working, so a failure leaves the old key in use. A key
given through the environment, flags or a file is never rewritten by the server. The table refuses unsigned requests
and unknown keys and decides the action before the handler runs; a test walks every
endpoint as an anonymous caller and as a user without permissions. The health check is
the one unsigned endpoint (above). Profiling and debug endpoints will be off by default
and admin-only.

### 3. Policies are evaluated by a pure, heavily tested engine (*built; enforced for IAM users, bucket policies and anonymous requests*)
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
source as well as write on the target. An object's own tags (`s3:ExistingObjectTag`)
decide the actions AWS lists for them (reads, copies from it, its ACL and tags): they
are read when a policy that decides the request tests them, and a failure to read them
refuses the request rather than deciding without them, so a Deny on a tag can't be
dodged, nor a denied object retagged into an allowed one. A bucket's tags decide
access only while its ABAC is on (`aws:ResourceTag`, `s3:BucketTag`, for the bucket,
its objects and a copy's source with its own bucket's), and then change only through
S3 Control's calls, decided with the tags or keys they name, so a tag can't be removed
by replacing the whole set; tags given to CreateBucket need `s3:TagResource`, decided
once its body is read, and a CreateBucket that wasn't decided never runs
(`crates/server/tests/security/abac.rs`). The suite
(`crates/server/tests/security/policy.rs`) proves this, headers that name condition keys
changing nothing, negated set operators with partly overlapping sets, and versions
needing the `…Version` actions.

A bucket policy is checked when it's stored (`MalformedPolicy`: the policy language,
S3 actions and condition keys only, resources only in its own bucket, at most 20 KB)
and read with every request to its bucket, and with a copy's source bucket's policy for
the source. Its Deny binds the root user too, except for reading, replacing and deleting
the policy itself, so a policy can't lock the owner out. A stored policy that can no
longer be read denies everything but that rescue, rather than being skipped.

Server access logs are written by the server acting as S3's logging service, and only
where the target lets it in: before `PutBucketLogging` stores a target and again before
each delivery, the service principal `logging.s3.amazonaws.com` must be allowed
`s3:PutObject` on the log object's key by the target's bucket policy, with
`aws:SourceArn` and `aws:SourceAccount` naming the source bucket and account, or by a
log delivery grant in the target's ACL. So whoever may configure one bucket's logging
can't write into a bucket that didn't agree, and removing the permission stops
deliveries (the records are dropped, as on S3). A `Service` principal names one
service, never a wildcard, and no signed request is ever that principal
(`crates/server/tests/logging.rs`). Inventory reports are written the same way, as
`s3.amazonaws.com`, which must be allowed `s3:PutObject` with those conditions and
`s3:x-amz-acl` `bucket-owner-full-control` before each file
(`crates/server/tests/inventory.rs`).

Every request signed with an IAM user's key is decided before its operation runs
(`crates/s3/src/access.rs`), for exactly the bucket, key and copy or rename source the
operation will act on (both parse them with the same functions). A permission TeiFS
can't name a resource for is refused, never skipped. `DeleteObjects` decides each key on
its own, and a denied key is reported in the answer while the others go ahead.
Permissions that only add to an answer (a `GetObject`'s tag count, owners in a listing)
are withheld without failing the request. Multipart uploads belong to the user who
started them (any of their keys); only that user or the root user can continue them.
A key that's deactivated or deleted stops working at the next request.

### 4. Credentials can't be escalated (*built for IAM users, roles and temporary credentials*)
IAM access keys' secrets are stored sealed (AES-256-GCM, each bound to its access key
id) under an IAM key the drive's KMS seals, so `system.db` alone (or a snapshot of it in
`.teifs/backups/`) doesn't reveal them;
they're never logged, and shown once, when the key is created.
Changing IAM is itself an IAM permission: every action of the IAM API is authorized
before it runs, as on AWS, so a user can manage only what its policies grant, and
delegated administrators can be held to specific policies and boundaries
(`iam:PolicyARN`, `iam:PermissionsBoundary`). A name given in another case is resolved
to the entity's own ARN before policies are read, since ARNs compare with case and a
Deny must not be dodged by spelling. A user without a permission is refused every
action (a test runs all of them). An IAM request's body is acted on only if it's the
body the signature covers (`UNSIGNED-PAYLOAD` is refused). A role's trust policy binds
the users and roles it names to their unique ids when it's set, so deleting a principal
and making another of the same name doesn't hand it the role. The root user's key belongs
to the drive's configuration and can't be created or changed through IAM; bulk import
will go through the same checks as single changes.

Temporary credentials never have more than what they were issued for, and never outlive
it. Nothing about a session is stored: its secret is derived from its access key id
under the IAM key, and its session token is its claims sealed with AES-256-GCM under
the same key and bound to the access key id, so a token can't be forged, changed or
used with another key, and a long-term key sent with a token is refused. Every request
rebuilds the session's permissions from IAM as it is now: a role's or user's policies
changing reach their sessions at once, and deleting the role or user ends them, even
if one of the same name is made again (sessions name it by unique id). A role session
has only the role's permissions, narrowed by its session policies; `AssumeRole` is
decided by the trust policy, `sts:TagSession` and `sts:SetSourceIdentity` too when
tags or a source identity are asked for, and the trust policy must name the principal
(or its account, and then the principal's own policies must allow it too): an identity
policy alone, even one that allows everything, never lets anyone assume a role, as on
AWS; the root user can't assume roles; a chain of
roles lasts at most an hour, and its source identity and transitive tags can't be
changed along it. `GetSessionToken`'s and federated users' credentials can't call IAM or
the admin API, nor start other sessions (federated users' only ask `GetCallerIdentity`);
a federated user has what both the caller's policies and the session policies allow,
so none allows nothing. MinIO's `AssumeRole` without a role gives a user's own
permissions narrowed, only to the user's own long-term key, and a policy may deny it.
A session with an MFA code is refused, since TeiFS has no MFA devices.

`AssumeRoleWithWebIdentity` is the one IAM or STS request answered unsigned, as on AWS,
and a signature on it counts for nothing: only the token and the role's trust policy
decide. The token must be signed by a key its provider publishes, with RS, PS or ES
signatures only (`none` and `HS…`, whose key would be public, are refused before any key
is looked at), by a key whose type, curve, `alg` and `use` fit; a header with `crit`
is refused. Headers and claims are read strictly, so no two readers see different
claims. The issuer must be one of the account's providers, the audience one of its
client ids (a provider with none accepts no token), the token unexpired (`exp` is
required; `nbf` and `iat` get a minute's leeway), and the subject present. Keys are
fetched only from providers an administrator created, over `https` (or `http` to this
machine), from the `jwks_uri` of a discovery document whose issuer is the provider's,
with no redirects, a 5-second timeout and at most 256 KiB read; the provider's
certificate must be one the system trusts or chain to one its administrator pinned by
thumbprint (SHA-1 is only a pin there, never a signature check: the chain's signatures,
dates and host name are verified as for any certificate); a flood of tokens naming
unknown keys asks a provider at most once in 30 seconds. A trust policy's `Federated`
principal names one provider's ARN, without wildcards. A token names managed policies
for itself (MinIO's way, without a role) only for a provider an administrator tagged
`teifs:policy-claim`, and only policies that exist; its session ends when the provider
is deleted, and loses a policy that's deleted. A MinIO role policy (a provider tagged
`teifs:role-policy`) is given only to a token of that provider for the client whose
role ARN it names (its `aud` or `azp`), so one client's tokens can't take another's
role. Tests:
`crates/iam/src/api/tests/sessions.rs`, `crates/iam/src/api/tests/web_identity.rs`,
`crates/iam/src/oidc/`, `crates/iam/src/sessions.rs`, `crates/server/tests/sts.rs`,
`crates/server/tests/admin.rs`.

MinIO's `AssumeRoleWithCertificate` is answered unsigned as well: the TLS connection's
client certificate decides who is asking. The server asks every client for a certificate
but takes the connection without one; the handshake proves a client that sends one holds
its private key (rustls checks the signature), and the certificate itself is checked when
it signs in: issued by one of the configured authorities (only those: the system's never
count, since any public CA could issue a certificate named after a policy), valid now,
marked for client authentication, with at most ten intermediate CAs. A session lasts no
longer than the certificate, and has only the managed policy its common name names; a
policy that doesn't exist means no session. Verification can be turned off for tests
only, which `teifs doctor` flags.

MinIO's `AssumeRoleWithCustomToken` is answered unsigned too: the identity plugin, a
service the operator runs, decides whom the token belongs to. The request is checked
before the plugin is asked (a token, the plugin role's ARN, a duration, a role policy
that exists), so nobody can make the server call the plugin with a malformed request.
The token goes to the plugin's configured URL only, in its query as MinIO sends it,
with the operator's `Authorization` header (from the environment only); the call has a
five-second limit, follows no redirect and reads at most 64 KiB. The token is
redacted from the audit log (with `LDAPPassword` and `WebIdentityToken`, which MinIO's
clients also send in the query), never logged, and dropped from errors; the URL's query
is never shown. A session has only the role's policies that existed when it began, lasts
no longer than the plugin allows, and loses a policy that's deleted.

MinIO's `AssumeRoleWithLDAPIdentity` is answered unsigned too, and only the directory
decides who is asking. Both the name and the password are needed: an empty password is
refused before the directory is asked, since LDAP takes it as an unauthenticated bind
that always succeeds. The name is escaped before it goes into a search filter (RFC 4515),
so `*` or `)(uid=*` finds no one; a filter that finds two users is refused. An unknown
user and a wrong password get the same answer. TeiFS reaches the directory over TLS
unless told otherwise (`--ldap-starttls`, or `--ldap-insecure`, which sends passwords as
they are), checks its certificate against the system's authorities or the CA file given,
and gives each step a timeout. The lookup account's password is read only from the
environment, and neither it nor a user's password is ever logged or stored (the lookup
password is wiped from memory when dropped). Sessions get only the managed
policies an administrator mapped to the user's DN or its groups' (none means no session),
and mapping takes `teifs:AttachLDAPPolicy`, with the DN looked up in the directory first.
A session has its policies decided at each request, from mappings as they are then; a
user the directory no longer has (checked every ten minutes) loses its sessions, through
a generation number that a new sign-in can't bring back. Tests:
`crates/iam/src/ldap/directory_tests.rs`, `crates/iam/src/ldap/sign_in_tests.rs`,
`crates/server/tests/ldap.rs`, `crates/server/tests/security/logs.rs`.

### 5. No default secrets
There is no built-in access key or password. The first run generates random credentials
(256-bit secret) into `.teifs/credentials.json`, created with mode `0600`
(`crates/server/src/credentials.rs`). A secret key set by the operator is only read from
the environment or from a file of its own (`--secret-key-file`), never from a
command-line flag or the settings file, so it doesn't show in process lists or in copies
of the settings; `teifs config show` names its source and never prints it (tested in
`apps/cli/tests/config.rs`). Secrets shorter than 8 characters are refused.

### 6. Secrets never reach logs
Types holding secrets leave them out of `Debug` output (credentials, access keys,
sessions, KMS keys, transit tokens and KES API keys, LDAP settings, IAM state), and secrets are wiped from memory when
dropped (`Zeroizing`). The S3 layer logs every response at `DEBUG`, so answers that carry
secrets (IAM and STS answers with access keys or session tokens, the admin API's IAM
exports) are sent as bodies that log only their size. A test runs a full cycle at
`TRACE`, with an SSE-C key, an IAM user's new key, a session and its token, an IAM
export and import with secrets and a wrongly signed request, and finds none of the
secrets, nor the signing keys they give, in the log
(`crates/server/tests/security/logs.rs`). The audit log replaces what could sign or
replay a request (`Authorization`, `X-Amz-Signature` and V2's `Signature` in a link,
session tokens, cookies, SSE-C keys) with `REDACTED` before an entry is made, and is
created readable only by its owner; a test sends each of them and looks for none in the
file (`crates/server/tests/audit.rs`). Server access log records replace the same
secrets in a request's query (`crates/s3/src/access_log/mod.rs`), and record no
headers but the referrer, user agent and host. An audit webhook's token is read only from the
environment, is marked sensitive in the request that carries it, and is never shown:
the webhook's `Debug` and `teifs admin config` show its URL without the user, password,
query or fragment. Redirects aren't followed, so entries go nowhere but the URL given. A
webhook or Elasticsearch target given `ca=PATH` verifies its https server with only that
CA, and one given `client_cert=PATH` and `client_key=PATH` shows that certificate to a
server that asks, each with a client of its own; an http URL with either is refused.
The files are read when the server starts. Notification
targets' secrets are read the same way (`TEIFS_NOTIFY_WEBHOOK_TOKEN_ID`,
`TEIFS_NOTIFY_ELASTICSEARCH_PASSWORD_ID` or `_API_KEY_ID`, `TEIFS_NOTIFY_REDIS_PASSWORD_ID`,
`TEIFS_NOTIFY_NSQ_SECRET_ID`, `TEIFS_NOTIFY_NATS_PASSWORD_ID` or `_TOKEN_ID`,
`TEIFS_NOTIFY_MQTT_PASSWORD_ID`, `TEIFS_NOTIFY_KAFKA_PASSWORD_ID`,
`TEIFS_NOTIFY_AMQP_PASSWORD_ID`, `TEIFS_NOTIFY_POSTGRESQL_PASSWORD_ID`,
`TEIFS_NOTIFY_MYSQL_PASSWORD_ID`), sent as sensitive headers, Redis's or NSQ's `AUTH`
(NSQ's only over TLS), NATS's or MQTT's `CONNECT`, Kafka's SASL, AMQP's `StartOk`,
PostgreSQL's password message or MySQL's authentication answers (built in memory that's
wiped), and never shown; an AMQP URL with a user or password in it
is refused. With
SASL SCRAM a Kafka password is never sent: the client proves it knows it, and the broker
must prove it knows it too before any event is sent (an impostor is refused); SASL PLAIN
sends it as it is, so use it only over TLS; a URL with a user or password in it is refused.
PostgreSQL's SCRAM-SHA-256 works the same way (a server that answers without proving it
knows the password is refused); with MD5 only a salted hash is sent, and a server that
asks for the password in the clear gets it only over TLS. MySQL's `caching_sha2_password`
and `mysql_native_password` send a proof, not the password; one that must be sent whole
goes only over TLS or encrypted (RSA-OAEP) with the server's key, which the operator gives
(`server_public_key=PATH`) or explicitly lets TeiFS ask the server for
(`get_server_public_key=true`, open to a machine in between, as MySQL's own client warns).
A PostgreSQL or MySQL target's events and keys are bound to its statements as parameters,
never put in their SQL, and its table's name is checked when the server starts (letters,
digits, `_` and `$`, or a quoted name without its quote), so an object's key can't change
what's run. An SQS, SNS,
Lambda or EventBridge target's secret key (`TEIFS_NOTIFY_KIND_SECRET_KEY_ID`, else
`AWS_SECRET_ACCESS_KEY`) is kept in
memory that's wiped and only signs requests (Signature Version 4); it is never sent, and
only the access key is shown.
A Redis, NSQ, NATS, MQTT, Kafka, PostgreSQL, MySQL or AMQP (`amqps://`) target asked for TLS (`tls=true`, `ca=PATH`, or an MQTT broker's `ssl://` or `wss://` URL) verifies the server's
certificate and name with the system's certificates or only the given CA, never skipping
the check, before its password is sent; a NATS server that requires TLS gets it, or no
credentials. A NATS nkey or `.creds` file is read from its path when the server starts,
its seed kept only as the key that signs the server's nonce (a `.creds` file whose JWT is
for another key is refused), and never shown. A client certificate's key
(`client_key=PATH`) is likewise read once, from its file, into memory that's wiped after
the TLS configuration takes it, and never shown.

Bucket notifications can't reach anything the operator didn't name: a bucket's rules
pick among the server's targets by ARN (an unknown one is refused when the rules are
set, and when a bucket export is imported), so whoever may `s3:PutBucketNotification`
chooses what's sent where, not what the server calls. Events carry what a request did
(keys, sizes, ETags, the signing access key and the client's address), never object
data, metadata or secrets, and the queue on the drive (`.teifs/events.db`) sits with the
rest of the drive's metadata. Watching a bucket's events as they happen (MinIO's listen
API) is decided as any bucket request, with the caller's policies and the bucket's:
it needs `s3:ListenBucketNotification` on the bucket, and every bucket's events
`s3:ListenNotification`, which only identity policies grant. Block Public Access applies
to a policy that lets anyone listen.

### 7. Keys can't escape their bucket
Every key is parsed into an `ObjectKey` (`crates/types/src/names.rs`) that refuses empty,
`.` and `..` segments, a leading `/`, backslashes and NUL bytes, and on Windows the names
its path layer would redirect (devices such as `NUL.txt`, `a:b` streams, trailing dots and
spaces). Paths are built only
from checked parts, and the store compares the canonical path with the expected one
before using it, so symbolic links inside a bucket and names that differ only in case or
Unicode form (or an NTFS short name) are never followed or overwritten (`Inner::find` and `Inner::make_parents` in
`crates/store/src/folder.rs`). Raw requests in a bucket anyone may read, with `..`,
encoded slashes and dots, backslashes and a link to another bucket, reach nothing outside
it (`crates/server/tests/security/paths.rs`). *Planned:* fuzzing of the parser and the
path mapping.

### 8. Only trusted proxies can set the client's address
Forwarding headers are read only when the connection's peer is a configured proxy
(`--trusted-proxy`, none by default), and only the one header chosen
(`--proxy-header`, `X-Forwarded-For` by default): a header the proxy passes on untouched
would be the client's own word. It's read right to left, past trusted proxies, at most
20 addresses; the first that isn't a trusted proxy is the client, and an unreadable
entry stops the walk at the last trusted proxy, never at an address the client could
have written (`crates/s3/src/proxy.rs`, tested in `crates/server/tests/proxy.rs`). The
scheme a proxy reports (`X-Forwarded-Proto`, or `Forwarded`'s `proto`) decides
`aws:SecureTransport` and SSE-C; a client that could lie about it would only weaken its
own connection. A proxy never reports a TLS version, so once it names a client or a
scheme, `s3:TlsVersion` is absent rather than the proxy's own hop's. With a proxy trusted, a server listening on loopback no longer counts
plain HTTP as secure, since the proxy may be passing on plain HTTP from anywhere.

### 9. Untrusted content is never rendered in a privileged page (*planned*)
Any web interface that previews files renders them from a separate, sandboxed origin.

### 10. CORS never reflects arbitrary origins
CORS headers come only from a bucket's CORS rules; an origin is echoed with credentials
only when a rule names it. Nothing else answers a browser's `Origin`: not the bucket
list, a bucket without rules, the admin, IAM or STS APIs, nor their preflights
(`crates/server/tests/security/cors.rs`).

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
refused before anything else looks at them. Over HTTPS the TLS handshake must finish
within the header timeout too. *Planned:* fuzzing of every parser.

### 12. Retention fails closed
A version's retention and legal hold are part of its own record, checked by the store
itself before anything removes the version, so no request path can skip them and no
bucket setting has to be read to enforce them: a record that can't be read refuses the
delete. A bucket setting that can't be read refuses the write instead of writing without
its default retention. Governance is bypassed only when the request asks
(`x-amz-bypass-governance-retention`) and the caller is allowed
`s3:BypassGovernanceRetention` on that object; a legal hold or compliance retention
holds whoever asks. Lifecycle rules remove versions through the same store operations,
so they never remove a protected one either. In a folder bucket this binds S3 requests
only: another program with access to the folder can still change its files.

### 13. Authorization before existence
A caller without access learns nothing about whether an object exists: requests are
authorized before they touch the drive, so conditional requests reveal nothing either,
and reading a missing key answers `403 AccessDenied` instead of `404 NoSuchKey` to a
caller who may not list the bucket, as AWS does. A refused read gets the same `403`
whatever it asks (`If-None-Match`, `If-Modified-Since`, a range, a part, its tags or
attributes), with no ETag, date, size or metadata in it
(`crates/server/tests/security/disclosure.rs`).

### 14. Encryption at rest keeps its keys away from the data
Objects in object buckets are encrypted by default (SSE-S3), as specified in
[ENCRYPTION_FORMAT.md](ENCRYPTION_FORMAT.md): a random key per object, sealed by a KMS
key and bound to the object's drive, bucket and object ids; 64 KiB authenticated
packages that can't be reordered, cut short or moved. The KMS keyring lives outside the
drive (`<config dir>/teifs/keys/<drive id>.json`, mode `0600`), so a copy of the drive
alone reveals nothing; or the keys stay in an external KMS (a Vault or OpenBao transit
engine, KES, AWS KMS) whose credentials come only from the environment (or AWS's own
credential sources, or a client certificate file for KES), never a flag or the settings
file. Each sealed key is bound to its object's context there too (the transit engine's
associated data, KES's context, AWS's encryption context). SSE-C keys are never stored (only a salted HMAC to recognize
them), are blocked on buckets by default, and are refused on plain HTTP (except on a
server listening only on loopback, or with `--sse-c-over-http`) for every request that
carries one, reads and copy sources included: one check in front of every operation
(`crates/s3/src/cors.rs`, tested in `crates/server/tests/tls.rs`). Changing an
object's encryption (UpdateObjectEncryption) only seals its data key again, needs
`s3:UpdateObjectEncryption` and Signature V4, and is refused for a version Object Lock
protects. Keys are wiped from memory when dropped. Tests prove no plaintext reaches the
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
keyring on the drive itself. `--json` output and error records carry no secrets.
Customer keys (SSE-C) for transfers come from a file (`--enc-c PREFIX=FILE`) or
`TEIFS_ENC_C`, never from the command line: a key given where a file belongs is refused
without being repeated, and keys are held in memory that's wiped when dropped.
Temporary credentials (`teifs sts`) are kept the same way, their session token as secret
as the key; they go to the terminal only with `--output -`, never replace an alias with
long-term keys, and an alias whose credentials expired is refused before it's used. A
new user's key saved as an alias never inherits the session of the alias that made it.
Tests: `apps/cli/tests/client.rs`, `apps/cli/tests/init.rs`, `apps/cli/tests/sts.rs`,
`apps/cli/src/client/target.rs`.

### 17. TLS is modern and certificates can't be half-loaded
HTTPS uses rustls with aws-lc-rs: TLS 1.3 and 1.2 only, rustls's default cipher suites,
no client certificates (`crates/server/src/tls.rs`). Every certificate must parse and
match its key before the server starts or a reload uses it; a reload that fails keeps
the certificates in use, and is reported once per change. Each connection's `secure`
flag (`aws:SecureTransport`, SSE-C) and TLS version (`s3:TlsVersion`) come from the
listener, never from a header.
`teifs health` checks a server's handshake signature but not whom its certificate names
(it sends nothing secret and reads only a status), so it works with private CAs and
certificates for public names while it asks `127.0.0.1`.

The `teifs` client checks every server fully: chain, dates and host name. An alias's
`ca-cert` (or `TEIFS_CA_CERT`) adds one authority to the system's, never replaces them
and never turns checking off (`apps/cli/src/client/trust.rs`); the S3, IAM, STS and
admin clients all use it, and check with it the same way (webpki, the system's
authorities as `rustls-native-certs` finds them), so a server passes or fails alike. A CA file that is missing or isn't PEM stops the command
before anything is sent, rather than falling back to the system's authorities alone.

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
