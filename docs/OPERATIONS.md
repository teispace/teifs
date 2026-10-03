# Operations

Watching a TeiFS server: its request ids, health check, Prometheus metrics, audit log
and live trace.

## Running as a service

The Linux packages (`.deb` and `.rpm` on every release) install:

| What | Where |
|---|---|
| The program | `/usr/bin/teifs`, with bash, zsh and fish completions |
| The service | `/usr/lib/systemd/system/teifs.service`, run as the `teifs` system user |
| Its settings | `/etc/teifs/teifs.toml` (the `teifs serve` settings) and `/etc/teifs/teifs.env` (`TEIFS_*` variables), both `root:teifs 0640`; an upgrade never replaces them |
| The drive | `/var/lib/teifs/drive`, and its encryption keyring `/var/lib/teifs/keyring.json` (the folder is `0700`, the service's own) |

Installing doesn't start it. `sudo systemctl enable --now teifs` does; on its first
start it creates the drive, its keys (`sudo teifs credentials
/var/lib/teifs/drive` shows them) and the keyring. Back up both the drive and the
keyring: objects can't be read without it. To choose the keys, set
`TEIFS_ACCESS_KEY` and `TEIFS_SECRET_KEY` in `teifs.env` before the first start.

The service is `Type=notify`: `systemctl start` returns once the server listens, and
`systemctl stop` waits for requests in flight. `systemctl reload teifs` reopens the
audit log and reloads the TLS certificates. It runs with systemd's sandboxing (no
capabilities, a read-only system, no home folders, private `/tmp` and devices, a
system-call filter); `systemd-analyze security teifs` scores it. It answers only this
machine until `listen` in `teifs.toml` says otherwise. To keep the drive
elsewhere, set `TEIFS_DIR` in `teifs.env` and allow its folder with `systemctl edit teifs`:

```ini
[Service]
ReadWritePaths=/srv/drive
```

To listen on a port below 1024, add `AmbientCapabilities=CAP_NET_BIND_SERVICE` and
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE` the same way. Removing the package stops
the service and keeps `/var/lib/teifs`; delete it yourself when it's no longer needed.

## Kubernetes

The Helm chart in `packaging/helm/teifs` runs TeiFS as a StatefulSet of one pod, with a
volume for the drive (`/data`) and one for the encryption keyring (`/config`):

```sh
helm install teifs packaging/helm/teifs --set persistence.data.size=100Gi
helm test teifs        # the server answers its health check through its Service
```

Without `auth.existingSecret` the chart makes the root keys (a Secret named after the
release, kept across upgrades and after an uninstall, so a reinstall opens the same
drive); the install's notes say how to read them. The secret key reaches the server as
a file, never a variable. The pod runs as a non-root user with a read-only root file
system and no capabilities; probes ask `/minio/health/live` and `/minio/health/ready`.

| Value | What |
|---|---|
| `auth.existingSecret` | A Secret of yours with `accessKey` and `secretKey` (names set by `auth.accessKeyKey`, `auth.secretKeyKey`) |
| `config` | `teifs.toml`, as `teifs serve` reads it: `{default-layout: folder, domain: [s3.example.com]}` |
| `env`, `envFrom` | More `TEIFS_*` variables, such as a notification target's secret from a Secret |
| `tls.existingSecret` | A `kubernetes.io/tls` Secret (cert-manager's): the server speaks HTTPS, and the probes too |
| `persistence.data`, `persistence.config` | Each volume's `size`, `storageClass`, `accessModes`, or an `existingClaim` |
| `ingress` | An Ingress to the Service, with its hosts and TLS |
| `metrics.serviceMonitor` | A Prometheus Operator ServiceMonitor; `bearerTokenSecret` names the Secret holding the token `teifs admin prometheus generate` makes |

Back up the keyring volume with the drive: objects can't be read without it.

## Request ids

Every answer has an `x-amz-request-id` header: 16 hex digits, unique on the server, as
S3's are. An error's body names it too (`<RequestId>` in S3's XML, `requestId` in the
admin API's JSON), so a failure a client reports can be found in the server's logs and
metrics. The AWS SDKs keep it with the error (`request_id()`), and the AWS CLI prints it
with `--debug`.

The server's own log names it too: whatever is logged while a request is answered, by
the S3 layer or the store, is in a `request` span with its id, so `TEIFS_LOG=debug`
shows each line as `request{id=18DA16C11FC2F0D0}: …`, and a client's failure can be
followed through the log with the id it got.

## Health

`GET /.teifs/health` answers `200 OK` without a signature and tells nothing about the
drive: for load balancers, orchestrators and container health checks. `teifs health`
asks it.

`MinIO`'s health checks are answered too, as a single-drive `MinIO` answers them, so
probes and load balancers set up for `MinIO` work unchanged. Each answers `GET` and
`HEAD` without a signature and with an empty body:

| Path | `200` when | Otherwise |
|---|---|---|
| `/minio/health/live` | the server answers | (it doesn't answer) |
| `/minio/health/ready` | the drive can serve: its index is there | `503`, `MinIO-ServerStatus: offline` |
| `/minio/health/cluster` | the drive can take writes: it can serve, and its disk has more room than the space kept free for deletes | `503` |
| `/minio/health/cluster/read` | the drive can serve reads | `503` |

The cluster checks send `MinIO-WriteQuorum: 1` (or `MinIO-ReadQuorum: 1`) and
`MinIO-StorageClassDefaults: true`. With `?maintenance=true`, which asks whether the
server can be taken down without losing the drive, they answer `412`: it's the only
node. In Kubernetes, point the liveness probe at `/minio/health/live` and the readiness
probe at `/minio/health/ready`. Only unsigned requests are health checks: a signed
request for one of those paths reaches a bucket named `minio`, as any request does.

`teifs status ALIAS` checks a server from anywhere its alias reaches it, and exits with
code 1 when a check fails:

```text
CHECK        STATE    DETAIL
Server       ok       answers in 2 ms
Clock        ok       agrees with this machine's
Drive        ok       serves
Writes       ok       taken
Certificate  ok       valid until 2027-01-02
Version      ok       TeiFS 0.1.0
Disk         ok       /srv/drive: 412.3 GiB free of 931.5 GiB
Scrub        ok       found no damage
```

The clock check fails when the two clocks are 15 minutes or more apart, since signed
requests fail then, and warns from a minute. The certificate check (HTTPS only) warns 14
days before it expires. Version, disks, jobs and scrubs come from the server's info, which
needs `teifs:GetServerInfo`; without it they're skipped with a warning. A disk with no room
left beyond what's kept free for deletes fails, and one with less than 5 % of its size
left warns. `--json` prints one `{"type":"check","name","state","detail","server"}`
record per check.

`mc admin info` reads the same server through `MinIO`'s admin API (`info`,
`storageinfo` and `datausageinfo`): one server with one pool of one set, whose drives
are the disks the drive uses (its own, and those of folder buckets kept elsewhere),
what it holds, and whether the KMS and the LDAP directory answer, each asked for at most
10 seconds. It needs `admin:ServerInfo`; `storageinfo` needs `admin:StorageInfo` and
`datausageinfo` `admin:DataUsageInfo`.

```sh
mc admin info teifs
```

`teifs admin service restart ALIAS` (or `mc admin service restart`) restarts a server:
it finishes what it's answering, then starts again as it was started, with the binary
now at its path (a package upgrade's). On Unix it's the same process, so systemd hears
it reloading and then ready again; on Windows the new server is a child the old one
waits for. `stop` makes it exit (only whatever started it can start it again, so it
asks first). `freeze` holds S3's requests, not the admin API's or health checks, until
as many `unfreeze`s have come or the server stops. They need `admin:ServiceRestart`,
`admin:ServiceStop` and `admin:ServiceFreeze`; `--dry-run` only checks the alias may.

```sh
teifs admin service restart prod
teifs admin service freeze prod && teifs admin service unfreeze prod
```

`mc admin update` is refused (`405 MethodNotAllowed`): TeiFS doesn't replace its own
binary. Update it the way it was installed (the release download, the `.deb` or `.rpm`,
the container image or the Helm chart), then restart it as above.

### Doctor

`teifs doctor [DIR]` looks at a drive on the machine it's on, with the settings
`teifs serve` would use (the same options, environment and the drive's own
`.teifs/settings.toml`), for what would stop the server or make it serve badly. Each
problem says what to do, and it exits with code 1 when a check fails:

```text
CHECK            STATE    DETAIL
Drive            ok       /srv/drive: drive 6f1c…
In use           ok       by nothing
Index            ok       intact
System database  ok       intact
Names            ok       told apart by case
File system      ok       on this machine
Writable         ok       yes
Disk             ok       /srv/drive: 412.3 GiB free of 931.5 GiB
Root keys        ok       in /srv/drive/.teifs/credentials.json
Keyring          ok       in /home/teifs/.config/teifs/keys/6f1c….json
Certificate      ok       /etc/teifs/certs/public.crt: valid until 2027-01-02
Listen           ok       0.0.0.0:9000 is free
```

It checks the drive's format (a newer TeiFS's drive fails; an older one is upgraded
when it's served), whether a running server has it, both databases with SQLite's
integrity check (a damaged one fails, pointing at `teifs restore --from`), whether two
names that differ only in case are one file on its file system (they can't both be in a
folder bucket then), whether it's on a file system over the network or in user space
(NFS, SMB, FUSE: it warns, since their locks, renames and syncs may not hold as a drive
needs), whether it can be written, its disk's room as `teifs status`
judges it, the root keys (given halfway fails; a file others can read warns), the
keyring (missing for a drive that has one warns: objects encrypted with it can't be read
without it), each TLS certificate (it loads with its key, and its expiry as
`teifs status` judges it) and whether the listen address is free. Nothing is changed: a
folder that isn't a drive yet stays one, and while a server runs the drive, the listen
address isn't tried. `--json` prints one `{"type":"check","name","state","detail","drive"}`
record per check.

## Encryption keys

Objects are encrypted with a key of their own, which a KMS key seals (see
[ENCRYPTION_FORMAT.md](ENCRYPTION_FORMAT.md)). The KMS keys live in one of:

| KMS | Settings | Secrets (environment only) | Rotation |
|---|---|---|---|
| A keyring file (default) | `--kms-keyring PATH`, default `<config dir>/teifs/keys/<drive id>.json` | none: the file itself (back it up) | `teifs key rotate` adds a version |
| A Vault or OpenBao transit engine | `--kms-transit URL`, `--kms-transit-mount`, `--kms-transit-namespace` | `VAULT_TOKEN` or `BAO_TOKEN` | the engine's versions |
| KES, one or more servers | `--kms-kes URL[,URL…]`, `--kms-kes-ca FILE`; `--kms-kes-cert FILE --kms-kes-key FILE` instead of an API key | `TEIFS_KMS_KES_API_KEY` (`kes:v1:…`) | none over KES's API: make a new key, set it as the buckets' (`teifs encrypt set`) and move objects to it (`teifs encrypt update`) |
| AWS KMS | `--kms-aws`, `--kms-aws-region`, `--kms-aws-endpoint` (a VPC endpoint, an emulator) | AWS's usual places: `AWS_ACCESS_KEY_ID`…, shared config and SSO profiles (`AWS_PROFILE`), container and instance roles, web identity | `teifs key rotate` rotates the key material on demand (AWS allows 25); automatic rotation counts too |

Each setting is also an environment variable (`TEIFS_KMS_KES`, `TEIFS_KMS_AWS_REGION`, …)
and a settings file key (`kms-kes = ["https://kes1:7373", "https://kes2:7373"]`). The
key commands take the same settings: `teifs key list|create|rotate|rewrap --kms-kes …`.

TeiFS seals SSE-S3 objects, SSE-KMS objects that name no key, and the drive's own
secrets (IAM) with the key `teifs-default`: create it in a transit engine, KES or AWS KMS
before serving (`teifs key create teifs-default --kms-aws`), or use a key that's already
there with `--kms-default-key NAME`. Keys sealed under the old name keep opening.

A running server's KMS is also reachable over the network, as `mc admin kms` reaches
MinIO's: `teifs admin kms status ALIAS` shows its kind, default key and whether each
endpoint answers; `teifs admin kms key create|list|status ALIAS [NAME]` creates a key,
lists them, or checks that one (the default key by default) seals a new data key and
unseals it again. They need `kms:Status`, `kms:CreateKey`, `kms:ListKeys` and
`kms:KeyStatus`; as on MinIO, a policy can limit the last three to some keys:

```json
{"Effect": "Allow", "Action": ["kms:CreateKey", "kms:ListKeys", "kms:KeyStatus"],
 "Resource": "arn:minio:kms:::app-*"}
```

**KES.** TeiFS proves who it is with a client certificate: the one KES's API key stands
for (as KES's own clients make it), or the certificate and key files given. KES knows it
by its *identity*, which `teifs serve`, `teifs key create` and `teifs admin config` show:
allow it in KES's policy
`/v1/key/create/*`, `/v1/key/describe/*`, `/v1/key/list/*`, `/v1/key/encrypt/*` and
`/v1/key/decrypt/*`. With several servers, each call goes to the one that last answered,
and on to the next when one can't be reached. MinIO's variables work as they are when no
TeiFS KMS setting is given: `MINIO_KMS_KES_ENDPOINT` (a comma-separated list),
`MINIO_KMS_KES_API_KEY`, `MINIO_KMS_KES_CERT_FILE`, `MINIO_KMS_KES_KEY_FILE`,
`MINIO_KMS_KES_CAPATH` and `MINIO_KMS_KES_KEY_NAME` (the default key's name).

**AWS KMS.** A name is an alias: `photos` is `alias/photos`; key ids, key ARNs and
`alias/…` names are used as they are. `teifs key create` makes a symmetric key with that
alias (tagged `teifs-key`), `teifs key list` lists the account's aliases (not AWS's own
`alias/aws/…`). The object's ids are the encryption context, so CloudTrail shows which
object each `Decrypt` was for. A key's version is one more than its completed rotations,
counted at most hourly; `teifs key rewrap` seals data keys again under the newest
material. The identity needs `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey` and
`kms:ListKeyRotations` on the keys, and for the key commands `kms:CreateKey`,
`kms:CreateAlias`, `kms:TagResource`, `kms:ListAliases` and `kms:RotateKeyOnDemand`.

`teifs doctor` asks an external KMS: whether it answers, takes TeiFS's credentials, and
has the default key (with the command that makes it when it hasn't).

## Built-in policies

Every drive has AWS's managed policies for what TeiFS serves and MinIO's canned
policies, at `arn:aws:iam::aws:policy/NAME`, ready to attach:

| Policy | Grants |
|---|---|
| `AdministratorAccess` | Everything |
| `AmazonS3FullAccess`, `AmazonS3ReadOnlyAccess` | All of S3, or its reads and lists |
| `IAMFullAccess`, `IAMReadOnlyAccess` | All of IAM, or its reads and lists |
| `readwrite`, `readonly`, `writeonly`, `consolereadonly` | MinIO's: all of S3, reading objects, writing them, reading and listing them |
| `consoleAdmin` | MinIO's: everything, the admin API and KMS included |
| `diagnostics`, `iamAdmin`, `infraAdmin`, `replicationAdmin`, `securityAuditAdmin` | MinIO's admin roles |

```sh
aws iam attach-user-policy --user-name alice \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess --endpoint-url https://s3.example.com
aws iam list-policies --scope AWS --endpoint-url https://s3.example.com
```

They can't be changed or deleted. Where a policy is given by name (LDAP mappings,
certificates' common names, OpenID Connect claims and roles, the identity plugin), a
policy of the account's own with that name comes first.

## Users with `mc admin`

MinIO's admin client manages TeiFS's users, groups and policies as it manages MinIO's:

```sh
mc alias set teifs https://s3.example.com ACCESS_KEY SECRET_KEY
mc admin user add teifs alice alice-secret-key
mc admin policy attach teifs readwrite --user alice
mc admin group add teifs devs alice
mc admin policy create teifs photos-reader photos-reader.json
mc admin policy attach teifs photos-reader --group devs
mc admin user disable teifs alice     # alice's keys stop signing until enabled
mc admin policy entities teifs --user alice
```

A user made this way is an IAM user named as its access key, which signs with a key of
that id, so the IAM API and `teifs iam` see it too (and `mc admin user add` of an IAM
user's name gives it that key). A canned policy is a managed policy by name; a built-in
one is replaced only when the client asks to override it (madmin's `overrideBuiltin`),
as on MinIO. Each
call needs MinIO's admin action (`admin:CreateUser`, `admin:UpdatePolicyAssociation`…),
which `consoleAdmin` and `iamAdmin` grant; a user may always read itself and change its
own secret.

### Service accounts

A service account is an access key a user (or the root user) makes for a program: it
acts as its user, narrowed by a policy of its own when it has one, and it can expire.

```sh
mc admin user svcacct add teifs alice --name backup --expiry 2027-06-30T00:00
mc admin user svcacct add teifs alice --policy only-backups.json
mc admin user svcacct ls teifs alice
mc admin user svcacct disable teifs TKIA...
mc admin accesskey ls teifs --all
mc admin user svcacct rm teifs TKIA...
```

Anyone may make, list, read and delete service accounts for their own user unless a
policy denies it; for another user's they need `admin:CreateServiceAccount`,
`admin:ListServiceAccounts` or `admin:RemoveServiceAccount`. Signing with a service
account's or temporary keys, making or deleting even your own needs the action too.
Changing one, even your own, needs `admin:UpdateServiceAccount`. An expiry is between 15 minutes and 365 days
away. A disabled or expired service account doesn't sign, and it can't get temporary
credentials from STS. When its user is disabled it stops signing, and when its user is
removed it goes too. The IAM API refuses to delete a user that still has service
accounts. They're kept in IAM exports (`teifs admin iam export`), with their secrets
when the export includes secrets.

## Settings with `mc admin config`

The sign-in settings below can also be set on a running server, as `mc admin config`
sets MinIO's, and are kept on its drive (`.teifs/config.kv`, readable only by its
owner):

```sh
teifs admin config set ALIAS identity_ldap server_addr=ldap.example.com:636 \
  'lookup_bind_dn=cn=teifs,ou=services,dc=example,dc=com' lookup_bind_password=…
teifs admin config get ALIAS identity_ldap     # never the secrets
teifs admin config keys ALIAS identity_ldap    # what it takes (--env: as variables)
teifs admin service restart ALIAS              # takes effect when it starts again
```

`identity_openid[:NAME]`, `identity_ldap`, `identity_plugin`, `identity_tls`, the
notification targets (`notify_webhook[:NAME]`, `notify_kafka[:NAME]`…, see
[Bucket notifications](#from-minios-settings)), `audit_webhook[:NAME]` and `api` are
kept; another sub-system is refused. Each value stands for MinIO's variable
(`MINIO_IDENTITY_LDAP_SERVER_ADDR`…) and counts only when nothing else sets it: flags,
`TEIFS_*` variables, the settings file and MinIO's variables all come first. A change
`teifs serve` wouldn't start with is refused, and nothing is kept. `reset` puts keys
(or a whole target) back to their defaults; `history` lists the changes (by target,
never their values), `restore ALIAS ID` sets one again and `clear-history ALIAS ID|all`
forgets them; `export ALIAS -o FILE` writes everything, secrets included, to a file
only you can read, and `import ALIAS FILE` replaces everything with one. Each needs
`admin:ConfigUpdate`.

MinIO's client manages the identity providers the same way, one at a time:
`mc admin idp ldap|openid add|update|remove|info|list` sets, shows and removes the
`identity_ldap` target and the `identity_openid` targets (by name). `info` lists each
value with where it comes from, never a secret; a configuration MinIO's variables set
can't be removed with it.

Of `api`'s keys, TeiFS uses two and keeps the rest unused:

- `root_access=off` (or `MINIO_API_ROOT_ACCESS=off`, or `teifs serve --no-root-access`)
  refuses the root key, the service accounts it made and the sessions it started, as
  MinIO does: only IAM's users sign in. Give one `admin:*` before turning it off, or set
  it back on in the environment to get in again.
- `stale_uploads_expiry` (Go's durations: `24h`, `1h30m`) aborts unfinished multipart
  uploads after that long when `--upload-expiry` isn't set by a flag, a variable or the
  settings file. Set to MinIO's own default, 24 hours, it leaves TeiFS's 7 days.

## LDAP sign-in

Users of an LDAP directory (Active Directory, OpenLDAP, FreeIPA…) can get temporary
credentials with their name and password, as with MinIO's `AssumeRoleWithLDAPIdentity`.
Their sessions have the managed policies mapped to their DN and to the DNs of their
groups.

```sh
TEIFS_LDAP_LOOKUP_BIND_PASSWORD=… teifs serve /srv/drive \
  --ldap-server ldap.example.com \
  --ldap-lookup-bind-dn 'cn=teifs,ou=services,dc=example,dc=com' \
  --ldap-user-base-dn 'ou=people,dc=example,dc=com' \
  --ldap-user-filter '(uid=%s)' \
  --ldap-group-base-dn 'ou=groups,dc=example,dc=com' \
  --ldap-group-filter '(&(objectclass=groupOfNames)(member=%d))'
```

| Setting | What it is |
|---|---|
| `--ldap-server HOST[:PORT]` | The directory; port 636 when none is given. With `--ldap-srv-record on\|ldap\|ldaps`, a domain whose DNS SRV records list the servers |
| `--ldap-starttls`, `--ldap-insecure` | StartTLS on the plain port, or plain LDAP (passwords cross the network as they are); LDAP over TLS by default |
| `--ldap-ca FILE`, `--ldap-tls-skip-verify` | The certificate authorities the server's certificate is checked against (default: the system's), or no check at all (testing only) |
| `--ldap-lookup-bind-dn DN` | The account TeiFS searches with; its password comes from `TEIFS_LDAP_LOOKUP_BIND_PASSWORD` only |
| `--ldap-user-base-dn DN[;DN…]`, `--ldap-user-filter F` | Where users are, and the filter that finds one: `%s` is the name signed in with |
| `--ldap-user-attributes A[,A…]` | User attributes to read at sign-in |
| `--ldap-group-base-dn DN[;DN…]`, `--ldap-group-filter F` | Where groups are, and the filter that finds a user's: `%s` is the name, `%d` the user's DN. Without a filter, groups aren't looked up |

Each is also an environment variable (`TEIFS_LDAP_SERVER`, …) and a settings file key.
When `--ldap-server` isn't given, MinIO's variables work as they are:
`MINIO_IDENTITY_LDAP_SERVER_ADDR`, `_SRV_RECORD_NAME`, `_SERVER_INSECURE`,
`_SERVER_STARTTLS`, `_TLS_SKIP_VERIFY`, `_LOOKUP_BIND_DN`, `_LOOKUP_BIND_PASSWORD`,
`_USER_DN_SEARCH_BASE_DN`, `_USER_DN_SEARCH_FILTER`, `_USER_DN_ATTRIBUTES`,
`_GROUP_SEARCH_BASE_DN` and `_GROUP_SEARCH_FILTER` (and `_ENABLE=off` turns them off).
TeiFS checks the settings when it starts (filters, DNs, base DNs that overlap) and says
how to fix what's wrong; `teifs doctor` also connects, signs the lookup account in and
looks for each base DN.

Map policies to users and groups, by DN in any spelling (MinIO's canned policies, such
as `readwrite` or `consoleAdmin`, are built in; see [Built-in policies](#built-in-policies)): TeiFS looks the DN up in the
directory and keeps it as the directory spells it.

```sh
teifs admin ldap policy attach local readwrite --group 'cn=engineers,ou=groups,dc=example,dc=com'
teifs admin ldap policy attach local home --user 'uid=dillon,ou=people,dc=example,dc=com'
teifs admin ldap policy ls local
teifs sts assume-ldap local -u dillon --save-alias dillon   # asks for the password
```

`teifs sts assume-ldap` reads the password from standard input with `--password-stdin`,
else from `TEIFS_LDAP_PASSWORD`, else asks. Any client of MinIO's API works too: the call
is an unsigned `POST /` with `Action=AssumeRoleWithLDAPIdentity`, `LDAPUsername`,
`LDAPPassword`, and optionally `Policy` (a session policy that narrows it) and
`DurationSeconds` (15 minutes to 365 days, an hour by default).

A mapping's change reaches existing sessions at their next request. Every ten minutes
the server asks the directory about each user with live sessions: a user it no longer
has loses them all, and the others' sessions follow their groups as they are now.
Policies can use `${ldap:username}`, `${ldap:user}` (the DN) and `ldap:groups` in
conditions. A policy mapped to a user or group can't be deleted until it's detached.
The mappings move with the IAM export (`teifs admin iam export`).

MinIO's client works too: `mc idp ldap policy attach|detach|entities` maps and lists
policies, and `mc idp ldap accesskey create|ls` makes and lists directory users' service
accounts. A user signed in with LDAP makes its own (unless its session was narrowed by a
policy); an admin makes one for a user named as it signs in (not a DN), once a policy is
mapped to the user or one of its groups. The account has the policies mapped to its
user and the user's groups, follows the groups at each check, and is removed with its
secret when the directory no longer has the user.

## Client certificate sign-in

Clients that hold a certificate your own certificate authority issued can get temporary
credentials with it, as with MinIO's `AssumeRoleWithCertificate`: the session has the
managed policy the certificate's subject common name names (`CN=readonly` gets the
`readonly` policy). It needs HTTPS.

```sh
mkdir -p /etc/teifs/certs/CAs
cp clients-ca.crt /etc/teifs/certs/CAs/
teifs serve /srv/drive --certs-dir /etc/teifs/certs --identity-tls
teifs sts assume-cert https://s3.example.com --cert client.crt --key client.key --save-alias ci
```

| Setting | What it is |
|---|---|
| `--identity-tls` | Take client certificates. MinIO's `MINIO_IDENTITY_TLS_ENABLE=on` works too |
| `--identity-tls-ca PATH` | The CA certificates (PEM: a file, or a folder of files) that must have issued them. By default the certificates folder's `CAs`, as MinIO has it; the system's authorities never count, since any public CA could otherwise issue `CN=consoleAdmin` |
| `--identity-tls-skip-verify` | Take any certificate, whoever issued it: for testing only. MinIO's `MINIO_IDENTITY_TLS_SKIP_VERIFY=on` works too |

The server asks every client for a certificate but needs none: browsers and S3 clients
without one connect as before. A certificate must be issued by one of the authorities
(the client may send intermediate CAs after it, at most ten), be valid now, say it's for
client authentication (extended key usage `clientAuth`), and have a common name; TeiFS
checks this when it signs in, after the TLS handshake proved the client holds its key.
The session lasts an hour unless `DurationSeconds` asks for 15 minutes to 365 days, and
never past the certificate's expiry; a `Policy` narrows it. Deleting the policy takes
the sessions' permissions with it.

Any client of MinIO's API works: the call is a `POST /` over the TLS connection with
`Action=AssumeRoleWithCertificate&Version=2011-06-15` (and optionally `DurationSeconds`,
`Policy`) in the query or a form body, unsigned. `teifs doctor` reads the authorities
and says when each expires; `teifs admin config` shows how many there are.

## OpenID Connect sign-in

Tokens of an OpenID Connect provider (a company's single sign-on, Keycloak, a CI job's)
get temporary credentials from `AssumeRoleWithWebIdentity` once the account has the
provider: add it with `teifs admin oidc add`, or name it in the server's settings, as
MinIO's `identity_openid` configuration does, and the server makes it when it starts.

```sh
teifs serve /srv/drive \
  --openid-config-url https://sso.example.com/realms/main/.well-known/openid-configuration \
  --openid-client-id teifs --openid-role-policy readonly
teifs admin config local          # shows the role ARN the client's tokens name
```

| Setting | What it is |
|---|---|
| `--openid-config-url URL` | The provider's discovery URL, or its issuer: what's before `/.well-known/openid-configuration` is the issuer its tokens must name |
| `--openid-client-id ID` | The client its tokens are for (`aud` or `azp`); needed |
| `--openid-role-policy NAMES` | The managed policies every token for the client gets when it names the client's role ARN, `arn:minio:iam:::role/<id>` (comma-separated or repeated) |
| `--openid-claim-name CLAIM` | Without role policies, the claim that names a token's policies (`policy` by default) |
| `--openid-claim-userinfo` | Complete tokens' claims from the provider's userinfo endpoint, with the access token a request gives (`WebIdentityAccessToken`) |

When the server starts it makes the provider, or brings the one it has for that issuer
in line: the client is added (others stay), and the tags that decide how its tokens get
policies (`teifs:role-policy`, `teifs:policy-claim`, `teifs:claim-userinfo`) are set as
the settings say. Its thumbprints and other tags stay as they are, and a provider
removed from the settings stays until `teifs admin oidc rm`. Settings that can't be
(both role policies and a claim name, a URL that isn't `https`) stop the server.

MinIO's variables work when `--openid-config-url` isn't given, one provider for each
suffix: `MINIO_IDENTITY_OPENID_CONFIG_URL`, `_CLIENT_ID`, `_ROLE_POLICY`, `_CLAIM_NAME`,
`_CLAIM_USERINFO` and `_ENABLE`, or `MINIO_IDENTITY_OPENID_CONFIG_URL_KEYCLOAK` and so on
for another. Their client secrets, scopes and redirect URLs are for MinIO's console and
aren't needed. Roles with trust policies, as on AWS, need none of this: a role that
trusts the provider is assumed with `teifs sts assume-web`.

A user signed in this way makes its own long-lived keys with its session, as with
MinIO: `mc admin accesskey create` (or `mc admin user svcacct add`) with the session's
credentials, unless a session policy narrowed it. The key acts as the user with the
policies the session had, and goes when the provider is removed. `mc idp openid
accesskey ls teifs --all` lists every user's, each by MinIO's name for the user and its
`sub`.

## SAML providers

A SAML identity provider (Okta, Microsoft Entra ID, Keycloak, AD FS) is added to the
account from the metadata document its administration exports, as on AWS:

```sh
teifs admin saml add local Okta --metadata okta-metadata.xml
teifs admin saml ls local
```

When the provider encrypts its assertions, give it the private key that decrypts them
(`--private-key key.pem`, a PEM file, unencrypted) and, to refuse plain assertions,
`--encryption required`. A provider holds two keys at most, so a key is rotated by adding
the new one (`teifs admin saml update local Okta --add-key new.pem`), switching the
provider over, then removing the old one (`--remove-key ID`, the id `ls` shows). A new
metadata document, when the provider's certificates change, is `update … --metadata
FILE` (`-` reads standard input). Private keys are stored sealed under the drive's IAM
key, never shown, and carried by `teifs admin iam export` only with `--secrets`.

Users then exchange the provider's response for a role's credentials with
`AssumeRoleWithSAML`, as on AWS: tools that sign in to AWS with SAML (they post the
response the provider gives the browser) work against TeiFS's endpoint. Configure the
provider for AWS as its documentation says (audience `urn:amazon:webservices`, the
`https://signin.aws.amazon.com/saml` endpoint, the `Role` and `RoleSessionName`
attributes), with role ARNs of the drive's account, and trust the provider in the role.
To encrypt assertions, give the provider the certificate of the private key added to
TeiFS and the endpoint `https://signin.aws.amazon.com/saml/acs/UUID` (the UUID `teifs
admin saml ls` shows), which `--encryption required` insists on:

```json
{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::ACCOUNT:saml-provider/Okta"},
 "Action": "sts:AssumeRoleWithSAML",
 "Condition": {"StringEquals": {"saml:aud": "https://signin.aws.amazon.com/saml"}}}
```

From the command line, `teifs sts assume-saml` takes the response (the `SAMLResponse`
form field the provider has the browser post, base64, or its XML) from a file or
standard input and saves the role's credentials as an alias or writes them for `aws`:

```sh
teifs sts assume-saml https://s3.example.com --role-arn arn:aws:iam::ACCOUNT:role/staff \
  --principal-arn arn:aws:iam::ACCOUNT:saml-provider/Okta --assertion-file response.txt \
  --save-alias staff
```

## Identity plugin sign-in

An identity plugin is your own web service that decides who an opaque token belongs to:
an internal SSO session, an API key of another system, anything. As with MinIO's
`AssumeRoleWithCustomToken`, clients exchange such a token for temporary credentials with
the policies of the plugin's role.

```sh
export TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN="Bearer $(cat /etc/teifs/plugin.token)"
teifs serve /srv/drive --identity-plugin-url https://auth.internal/teifs \
  --identity-plugin-role-policy readonly
teifs admin config local          # shows the role ARN clients name
printf %s "$TOKEN" | teifs sts assume-custom https://s3.example.com \
  --role-arn arn:minio:iam:::role/idmp-… --token-stdin --save-alias me
```

| Setting | What it is |
|---|---|
| `--identity-plugin-url URL` | Where the plugin is asked (`http` or `https`). MinIO's `MINIO_IDENTITY_PLUGIN_URL` works too |
| `--identity-plugin-role-policy NAMES` | The managed policies its users' sessions get (comma-separated or repeated); at least one must exist when someone signs in |
| `--identity-plugin-role-id ID` | The id in the role ARN, `arn:minio:iam:::role/idmp-<ID>`; by default derived from the URL as MinIO derives it, so a MinIO deployment's ARN stays the same |
| `--identity-plugin-ca PATH` | Certificate authorities (PEM: a file, or a folder of files) the plugin's certificate may be issued by, besides the system's |
| `TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN` | The `Authorization` header sent to the plugin, as it is (`Bearer …`). Only from the environment; MinIO's `MINIO_IDENTITY_PLUGIN_AUTH_TOKEN` works too |

For each sign-in TeiFS sends `POST <URL>?token=<token>` with that header, waits at most
five seconds and follows no redirect. The plugin answers:

- `200` with `{"user": "alice", "maxValiditySeconds": 3600, "claims": {…}}`: the
  session is `alice`'s, and lasts `maxValiditySeconds` (15 minutes to 365 days), or
  `DurationSeconds` if the client asks for less;
- `403` with `{"reason": "…"}`: the client gets `AccessDenied` with that reason;
- anything else: the client gets `InvalidParameterValue`.

The request is checked before the plugin is asked (a token, the role ARN, a duration
TeiFS allows, a role policy that exists), so a malformed request never reaches it. The
token never appears in TeiFS's logs, errors, or audit log, and the URL's query is
hidden in `teifs admin config`. `teifs doctor` checks the settings and that the plugin
answers (`HEAD`). Clients send `POST /` with
`Action=AssumeRoleWithCustomToken&Version=2011-06-15&RoleArn=…&Token=…` (and optionally
`DurationSeconds`, `Policy`) in a form body or, as MinIO's clients do, in the query,
unsigned.

## Metrics

`GET /.teifs/metrics` serves Prometheus metrics in the OpenMetrics text format, which
Prometheus, VictoriaMetrics, Grafana Agent and the OpenTelemetry Collector read. Like the
health check it's never a virtual-hosted bucket's key.

### Who may scrape

Metrics name operations, error codes and the drive's size, so a scrape needs a bearer
token, made from an access key (as `mc admin prometheus generate` makes one for MinIO):

```sh
teifs admin user add local prometheus --policy metrics.json --save-alias prom
teifs admin prometheus generate prom --token-file /etc/prometheus/teifs.token
```

where `metrics.json` allows the one action a scrape needs:

```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"teifs:GetMetrics","Resource":"*"}]}
```

`generate` prints a scrape configuration to paste under Prometheus's `scrape_configs`:

```yaml
scrape_configs:
  - job_name: teifs
    metrics_path: /.teifs/metrics
    scheme: http
    authorization:
      credentials_file: "/etc/prometheus/teifs.token"
    static_configs:
      - targets: ["127.0.0.1:9000"]
```

Without `--token-file` the token is in the configuration itself (`credentials:`). The
token is a JWT signed with the key's secret, so it's checked without a signature on the
request; the key's policies decide at every scrape, and deleting or deactivating the key
revokes it. `--expires 90d` makes one that ends sooner. Temporary credentials can't make
one. A scrape without a token, or with one that's forged, expired or of a deleted key,
is `401` (with `WWW-Authenticate: Bearer`); one whose key may not `teifs:GetMetrics` is
`403`.

On a network only Prometheus shares, `teifs serve --public-metrics` serves them to
anyone who can reach the server.

### What's measured

Requests are counted when their answer is done with: after its last byte, or when the
client leaves. `api` is the operation (`PutObject`, `ListObjectsV2`, the admin API's
`GetServerInfo`, `IAM` and `STS` for those APIs, `PreflightRequest` for CORS), or
`unknown` for a request refused before its signature was accepted.

| Metric | Type | Labels | What |
|---|---|---|---|
| `teifs_s3_requests_total` | counter | `api`, `code` | Requests answered, by HTTP status |
| `teifs_s3_errors_total` | counter | `api`, `error` | Error answers, by S3 error code (`NoSuchKey`, `SlowDown`…) |
| `teifs_s3_canceled_total` | counter | `api` | Requests whose client left before the whole answer was sent |
| `teifs_s3_requests_inflight` | gauge | | Requests being served |
| `teifs_s3_ttfb_seconds` | histogram | `api` | Time until the answer's headers were ready |
| `teifs_s3_duration_seconds` | histogram | `api` | Time until the answer's last byte was sent |
| `teifs_s3_received_bytes_total` | counter | `api` | Request body bytes read |
| `teifs_s3_sent_bytes_total` | counter | `api` | Answer body bytes sent |
| `teifs_store_stage_seconds` | histogram | `op`, `stage` | Time in each stage of the store's writes (`key`: a data key from the KMS; `lock`: waiting for the commit lock; `sync`: making the data file durable, which small objects kept in the index skip; `folder`: syncing a folder so a file added to it or removed survives a power cut, with `durability = "strict"`; `commit`: the part under the lock, with the index's sync) and reads (`locate`: finding the version and opening its file; `key`) |
| `teifs_drive_total_bytes` | gauge | | The size of the disk the drive is on |
| `teifs_drive_free_bytes` | gauge | | The space free on it for TeiFS |
| `teifs_job_steps_total` | counter | `job` | Steps each background job has run since the server started |
| `teifs_job_items_total` | counter | `job` | Items each has handled (uploads expired, files swept…) |
| `teifs_job_failing` | gauge | `job` | 1 when a job's last step failed |
| `teifs_buckets` | gauge | | Buckets |
| `teifs_usage_objects` | gauge | | Objects: keys whose current version isn't a delete marker |
| `teifs_usage_versions` | gauge | | Versions kept, current ones included, delete markers not |
| `teifs_usage_delete_markers` | gauge | | Delete markers |
| `teifs_usage_stored_bytes` | gauge | | The size of every version kept |
| `teifs_bucket_objects`, `teifs_bucket_versions`, `teifs_bucket_delete_markers`, `teifs_bucket_stored_bytes` | gauge | `bucket` | The same by bucket, with `?buckets=1` |
| `teifs_scrub_checked_versions`, `teifs_scrub_checked_bytes` | gauge | `pass` | What the scrub read, in the pass under way (`current`) and the last finished (`last`) |
| `teifs_scrub_damaged_versions` | gauge | `pass` | Versions it found damaged |
| `teifs_scrub_unverifiable_versions` | gauge | `pass` | Versions it couldn't check (SSE-C, whose keys it doesn't have) |
| `teifs_scrub_last_finished_seconds` | gauge | | When the last pass finished (Unix time) |
| `teifs_notify_sent_total` | counter | `target` | Events each notification target took |
| `teifs_notify_failed_total` | counter | `target` | Tries it didn't take (each is tried again) |
| `teifs_notify_dropped_total` | counter | `target` | Events dropped because too many waited for it |
| `teifs_notify_queued` | gauge | `target` | Events waiting on the drive for it |
| `teifs_notify_online` | gauge | `target` | 1 when it took its last try |
| `teifs_access_log_records_total` | counter | | Server access log records kept for delivery |
| `teifs_access_log_objects_total` | counter | | Log objects delivered to target buckets |
| `teifs_access_log_dropped_total` | counter | | Records lost: too many waited, the spool couldn't be written, or the target refused them |
| `teifs_request_metrics_…` | | `bucket`, `filter_id` | Each bucket's [request metrics](#request-metrics), by metrics configuration |
| `teifs_request_metrics_dropped_total` | counter | | Requests left out of them because too many waited |
| `teifs_start_time_seconds` | gauge | | When the server started (Unix time) |
| `teifs_build_info` | info | `version` | The TeiFS version |

Usage is counted by the index as it changes, so a scrape reads a row per bucket however
many objects there are, and it's exact the moment a write is. A folder bucket's files
added outside TeiFS count once the `index-folders` job has found them. What each bucket
holds is left out unless the scrape asks, as a drive can have many buckets:
`teifs admin prometheus generate ALIAS --buckets` adds `params: {buckets: ["1"]}`.
`teifs admin info` shows the totals.

Request histograms' buckets double from 1 ms to about a minute; the store's from 100 µs
to about 52 s. A slow `sync` is the disk, a slow `key` the KMS (an external KMS's
network), a slow `lock` many writes waiting their turn. Some queries to start with:

```promql
sum by (api) (rate(teifs_s3_requests_total[5m]))                  # requests per second
sum(rate(teifs_s3_requests_total{code=~"5.."}[5m]))                 # server errors
histogram_quantile(0.99, sum by (le, api) (rate(teifs_s3_ttfb_seconds_bucket[5m])))
teifs_drive_free_bytes / teifs_drive_total_bytes < 0.1              # disk nearly full
max(teifs_job_failing) > 0                                          # a job keeps failing
max(teifs_scrub_damaged_versions) > 0                               # damage on the disk
max(teifs_notify_queued) > 1000                                     # a target is falling behind
histogram_quantile(0.99, sum by (le, stage) (rate(teifs_store_stage_seconds_bucket{op="write"}[5m])))
topk(5, teifs_bucket_stored_bytes)                                  # the largest buckets
```

## Audit log

```sh
teifs serve /srv/drive --audit-log /var/log/teifs/audit.log   # or - for standard output
```

One JSON object per request, on a line of its own, with MinIO's field names, so what
reads MinIO's audit log reads TeiFS's. The file is appended to and created readable only
by its owner; after logrotate moves it, `SIGHUP` makes the server write a new one
(logrotate's `postrotate kill -HUP $(pidof teifs)`, or `copytruncate`). Entries are
queued for the writer, so a slow disk never slows requests; any the queue can't take are
counted in `teifs_audit_dropped_total`.

To send the entries to a log collector (Vector, Fluent Bit, Logstash, Splunk's HTTP
Event Collector), give a webhook, alone or with a file:

```sh
export TEIFS_AUDIT_WEBHOOK_TOKEN=…   # sent as Authorization: Bearer …
teifs serve /srv/drive --audit-webhook https://logs.example.com/teifs
```

Entries are `POST`ed in batches of up to 100, as JSON lines (`application/x-ndjson`), and
any `2xx` answer takes a batch. A batch that isn't taken (an error, another status, no
answer in 10 seconds) is tried again after half a second, then twice as long each time up
to 30 seconds, in order, so the collector gets every entry once it's back; entries
arriving meanwhile wait in the webhook's own queue, and those it can't hold are counted as
dropped. A server that's stopping tries a failing batch three more times. Redirects aren't
followed. The token is read only from the environment, never a flag, so it's not in the
process list; one that names its scheme (`Basic dXNlcjpwYXNz`, `Splunk …`) is sent as
given. `teifs admin config` shows the URL without its user, password or query.

An https collector is verified with the system's certificates, or only a CA's with
`,ca=PATH` after the URL; `,client_cert=PATH,client_key=PATH` are the certificate and key
shown to a collector that asks for one (mutual TLS):

```sh
teifs serve /srv/drive --audit-webhook https://logs.internal/teifs,ca=/etc/teifs/ca.pem,client_cert=/etc/teifs/teifs.pem,client_key=/etc/teifs/teifs.key
```

```json
{"version":"1","deploymentid":"…","time":"2026-09-30T12:00:00.123456789Z","type":"S3",
 "trigger":"incoming","api":{"name":"PutObject","bucket":"photos","object":"a.jpg",
 "status":"OK","statusCode":200,"rx":52431,"tx":0,"timeToFirstByte":"1834000ns",
 "timeToResponse":"1901000ns","timeToResponseInNS":"1901000"},"remotehost":"10.0.0.7",
 "requestID":"18DA16C11FC2F0D0","userAgent":"aws-cli/2.17 …","requestPath":"/photos/a.jpg",
 "requestHost":"s3.example.com","requestHeader":{"authorization":"REDACTED","…":"…"},
 "responseHeader":{"etag":"\"…\"","x-amz-request-id":"18DA16C11FC2F0D0"},
 "accessKey":"TFABCDEF…"}
```

| Field | What |
|---|---|
| `time` | When the request arrived (RFC 3339, UTC) |
| `type` | `S3`, `Admin`, `IAM`, `STS` or `Control` |
| `api.name` | The operation, as in the metrics; `unknown` when refused before its signature was accepted |
| `api.bucket`, `api.object` | What it was on |
| `api.statusCode`, `api.status` | The answer's status; `499` (`Client Closed Request`) when the client left before it was answered |
| `api.rx`, `api.tx` | Body bytes read and sent |
| `api.timeToFirstByte`, `api.timeToResponse` | Until the answer's headers were ready, and until its last byte (nanoseconds) |
| `remotehost` | The client's address (a trusted proxy's client, behind one) |
| `requestID` | The answer's `x-amz-request-id` |
| `accessKey` | The key it was signed with; none when unsigned |
| `error` | The error code it was answered with (`NoSuchKey`, `AccessDenied`) |
| `requestQuery`, `requestHeader`, `responseHeader` | The request's query and headers and the answer's headers |

Secrets never reach it: `Authorization`, `Proxy-Authorization`, `Cookie`, session tokens
(`X-Amz-Security-Token`, as a header or in a link), a link's signature (`X-Amz-Signature`,
V2's `Signature`) and SSE-C keys (`…-customer-key`, the copy source's too) are replaced
by `REDACTED`; a key's MD5 digest, which reveals nothing, is kept.
`GET /.teifs/admin/v1/config` (`teifs admin config`) says where the log goes.

## Live trace

`teifs admin trace ALIAS` shows each request the server answers, as it answers it, until
Ctrl-C (as `mc admin trace` shows MinIO's):

```text
12:50:26.602 200 PutObject pics/a.txt 127.0.0.1 14.9ms ↑6 B ↓0 B
12:50:26.753 404 GetObject pics/missing 127.0.0.1 681µs ↑0 B ↓166 B NoSuchKey
```

Filters narrow it on the server, so a narrow trace of a busy server costs little:
`--errors` (answers from 400 up), `--api PutObject` (repeat for more), `--bucket NAME`,
`--prefix KEY`, `--status 404` (repeat for more) and `--slower-than 250ms`. With
`--json` each request is its audit entry (above), secrets redacted the same way. It needs
`teifs:ServerTrace`, as entries show other users' requests.

A trace is `GET /.teifs/admin/v1/trace`, signed as any admin call, whose answer is the
entries as JSON lines (`application/x-ndjson`) for as long as the caller reads, with an
empty line every 10 seconds so proxies keep a quiet trace open; the query holds the
filters (`errors=true`, `api`, `bucket`, `prefix`, `status`, `slowerThanMs`). The server
makes entries only while an audit log is kept or someone traces. A trace that reads too
slowly skips entries rather than slow requests down, and every trace ends when the server
stops.

`mc admin trace` works too: `GET /minio/admin/v3/trace` answers each request as the
`madmin.TraceInfo` MinIO would send, with a space every second while it's quiet. S3's
requests are MinIO's `s3` type (`s3.GetObject`); the admin, IAM, STS and control APIs'
are its `internal` type (`admin.ServerInfo`), which `mc admin trace --all` shows.
`--errors` and `--response-threshold` are applied on the server; `mc`'s other filters
(`--path`, `--funcname`, `--status-code`…) on the client, as with MinIO. Types TeiFS has
no counterpart for (`storage`, `os`, `scanner`, `healing`…) are accepted and show nothing.
It needs `admin:ServerTrace`.

## Server log

`mc admin logs` reads what the server logged (`GET /minio/admin/v3/log`): the last lines
first (`--last N`, 10 by default, of the 10,000 kept), then each line as it's logged,
until Ctrl-C. `--type error|warning|info` picks one kind. Errors and warnings come as
MinIO's do, with where they were logged and their fields; information as a message with
its fields after it. Only what `TEIFS_LOG` lets through is kept (information and above
by default; debug lines never are), and the kept lines start again when the server does.
A server is one node, so `--node` with another name shows nothing. It needs
`admin:ConsoleLog`.

## Live metrics and locks

MinIO's realtime metrics (`GET /minio/admin/v3/metrics`, which the MinIO console's
realtime view and `mc admin scanner status` read) answer one document a second (or every
`interval`), `n` times or until the caller leaves. They hold MinIO's API metrics: the S3
requests being served, and those answered since the server started with their bytes,
4xx and 5xx errors, cancellations and times. A server is one node, so its figures are
the whole. Other metric types are accepted and come back empty; the scanner, drive and
heal figures are in `teifs admin info` and the Prometheus metrics. It needs
`admin:ServerInfo`.

`mc admin top locks` lists no locks: a request holds none past its own answer, so there
is never one to wait on or force open, and `mc admin force-unlock` has nothing to do.
They need `admin:TopLocksInfo` and `admin:ForceUnlock`.

## Heal with `mc admin heal`

A drive keeps one copy of each object, so there is no other to heal from: `mc admin heal`
checks what the drive holds and reports it, and changes nothing. It goes through every
bucket (`mc admin heal ALIAS`), or one bucket's objects (`ALIAS/BUCKET`), or those under a
prefix (`ALIAS/BUCKET/PREFIX`); `--recursive` goes into every folder under it, otherwise
only the objects right under it are checked. A normal scan reads each version's metadata;
`--scan deep` also reads its bytes and compares them with what was recorded, as
`teifs verify` does, and reports a damaged one as `corrupt` (or `missing`, when
its data is gone) with what's wrong. `--dry-run` and `--remove` change nothing either.

One heal runs at a time on a path and on the paths inside or around it; `--force-start`
stops the one running and starts again, `--force-stop` stops it. Results are kept for
the caller to read: up to 1,000 unread before the heal waits, and for 10 minutes after
it ends. The background heal (`mc admin heal` without a target, its status) is the
drive's [scrub](#metrics): it reports the versions the scrub checked. Both need
`admin:Heal`.

## Speed tests

`mc admin speedtest ALIAS` measures what the drive and the store can do: it writes
objects (64 MiB, 32 writers, 10 seconds unless `--size`, `--concurrent` and
`--duration` say otherwise) and then reads them back for as long, and reports the
throughput, objects a second and response times of each. `--autotune` keeps adding
writers while reads get faster. The test runs inside the server, so it measures the
drive and not the network; S3's requests wait until it ends, as with
`mc admin service freeze`. It writes to `minio-perf-test-tmp-bucket`, which it makes and
removes, or to `--bucket`'s `speedtest/` prefix, and removes what it wrote unless asked
not to (`--noclear`). It needs room for one object per writer.

`mc support perf drive ALIAS` writes a file (1 GiB in 4 MiB blocks unless
`--filesize` and `--blocksize` say otherwise) to each disk the drive uses, syncs it,
reads it back and removes it. The read may come from the operating system's cache, so it
can be faster than the disk. The files go where the drive stages its writes:
`.teifs/tmp/` on the drive's disk, `.teifs-tmp` on a bucket's other disk. A server is one
node, so `mc support perf net` and `site` have no network to measure. Both tests need
`admin:OBDInfo`.

## Health report

`mc support diag ALIAS` gathers what support asks for first: the host's CPUs, disks,
operating system, memory, network interfaces and settings (open files limit, clock, and on
Linux transparent huge pages and XFS's error retries), problems MinIO warns of (the
kernel's audit on, `updatedb` installed), SELinux's mode, the server's own process, the
drive's configuration with its secrets shown as `*redacted*`, and what `mc admin info`
shows with the TLS certificates the server presents. `--anonymize strict` names the server
`server1` instead of its address and host name. The report is written to a file
`mc` names, for you to read or send; TeiFS sends nothing anywhere. It needs
`admin:OBDInfo`.

## Object inspection

When support asks how the drive keeps an object, `mc support inspect ALIAS/BUCKET/KEY/xl.meta`
downloads what its index keeps about that key: each version's row (its id, size, ETag,
attributes, how it's encrypted, its parts) and, in a folder bucket, the file's row, as
`teifs.meta.json`, with the drive's `format.json`. A pattern names several keys
(`ALIAS/BUCKET/photos/*/xl.meta`, `ALIAS/BUCKET/**`), up to 1,000 at a time. Objects' bytes
are never included. The zip is encrypted: `mc` prints the key to give support with it, or,
with `--public-key FILE` (an RSA public key in PKCS #1 form), only the matching private key
opens it. It needs `admin:InspectData`.

## Pools

`mc admin decommission status ALIAS` lists the drive as the server's only pool, named by
its path. A drive keeps everything in one place, so there is no other pool to move its
objects to: `mc admin decommission start` and `mc admin rebalance start` are refused, as
MinIO refuses them on one pool. To move a drive's buckets to another server, use
[`teifs migrate`](#migrating-from-minio-or-another-s3-service).

## Profiling

`mc admin profile ALIAS --type cpu --duration 30s` takes a CPU profile of the server for
the time asked (a minute unless told, an hour at most) and saves it in a zip with a
`cluster.info` that describes the drive, as MinIO's. The profile samples the server 100
times a second and is in pprof's format: `go tool pprof profile-*-cpu.pprof` (or any pprof
viewer) shows where the time went, by function. CPU profiles are taken on Linux and
macOS; the other types `mc` offers are a Go program's and aren't taken. Profiling needs
`admin:Profiling`, and the names in a profile are the server's own functions, so give it
only to the people who run the server.

## Server access logs

A bucket's access log, as S3's server access logging, records every request on the
bucket and its objects in S3's format and delivers the records as objects to a target
bucket, where any tool that reads S3's access logs reads them.

```sh
teifs logging set local/app local/logs/app/      # app's requests, as log objects under logs/app/
teifs logging info local/app
teifs logging rm local/app
```

`teifs logging set` also adds a statement to the target's bucket policy that lets the
logging service (`logging.s3.amazonaws.com`) write there for this bucket, as the S3
console does; with `--no-policy`, grant it yourself (or, where the target's ACLs are on,
give the log delivery group `WRITE`). A target without that permission, with a default
Object Lock retention, or that doesn't exist is refused (`InvalidTargetBucketForLogging`),
as on S3. `--format` names the log objects as S3 does: `simple` (the default,
`PREFIX/YYYY-mm-DD-HH-MM-SS-UNIQUE`), or partitioned by `event-time` or
`delivery-time` (`PREFIX/ACCOUNT/REGION/BUCKET/YYYY/MM/DD/YYYY-mm-DD-HH-MM-SS-UNIQUE`).

Records are written first to the drive's system folder (`access-logs/`), then delivered:
every 5 minutes (`serve --access-log-interval`, or `TEIFS_ACCESS_LOG_INTERVAL`), when
a bucket's pending records reach 1 MiB, and when a new day (UTC) begins; what's pending
when the server stops is delivered when it starts again. A delivery the target refuses (its
permission was removed, it was deleted) drops those records, as S3 does, with a warning
and `teifs_access_log_dropped_total`; a failure of the drive is tried again every minute.
Delivered objects are written like any other: encrypted as the target's default says,
counted in its usage, and announced by its notifications. Secrets in a request's query
(a presigned link's signature and security token) are replaced by `REDACTED`. As on S3,
logging is best effort: a record can arrive in a later object than its neighbours, and
records of the last second before a crash can be lost. A request to a
[website](#static-websites) is recorded as S3 records it: `WEBSITE.GET.OBJECT` or
`WEBSITE.HEAD.OBJECT`, on the object it answered with.

## Request metrics

A bucket's metrics configurations count its requests as S3's request metrics do in
CloudWatch, served with the server's [metrics](#metrics) and labeled by `bucket` and
`filter_id` (the configuration's id). A configuration without a filter counts every
request to the bucket (the S3 console names it `EntireBucket`); one with a prefix or
tags counts only requests on objects whose key starts with the prefix and that carry
every tag.

```sh
teifs metrics add local/app EntireBucket
teifs metrics add local/app docs --prefix docs/ --tag team=red
teifs metrics ls local/app
teifs metrics info local/app docs
teifs metrics rm local/app docs
```

Like any other configuration it can be set through S3 (`PutBucketMetricsConfiguration`).

| Metric | CloudWatch's | What |
|---|---|---|
| `teifs_request_metrics_all_requests_total` | `AllRequests` | Every request |
| `teifs_request_metrics_get_requests_total` | `GetRequests` | `GET` on objects (`ListParts` too), not listings |
| `teifs_request_metrics_put_requests_total` | `PutRequests` | `PUT` on objects (uploads, parts, copies, tags…) |
| `teifs_request_metrics_delete_requests_total` | `DeleteRequests` | `DELETE` on objects, and `DeleteObjects` |
| `teifs_request_metrics_head_requests_total` | `HeadRequests` | `HEAD` on objects |
| `teifs_request_metrics_post_requests_total` | `PostRequests` | `POST`s, but `DeleteObjects` and `SelectObjectContent` |
| `teifs_request_metrics_list_requests_total` | `ListRequests` | `ListObjects`, `ListObjectsV2`, `ListObjectVersions`, `ListMultipartUploads` |
| `teifs_request_metrics_select_object_content_requests_total` | `SelectObjectContentRequests` | `SelectObjectContent` |
| `teifs_request_metrics_downloaded_bytes_total` | `BytesDownloaded` | Answer body bytes sent |
| `teifs_request_metrics_uploaded_bytes_total` | `BytesUploaded` | Request body bytes read |
| `teifs_request_metrics_4xx_errors_total` | `4xxErrors` | Requests answered with a 4xx status |
| `teifs_request_metrics_5xx_errors_total` | `5xxErrors` | Requests answered with a 5xx status |
| `teifs_request_metrics_first_byte_latency_seconds` | `FirstByteLatency` | Histogram: time until the answer's headers were ready |
| `teifs_request_metrics_total_request_latency_seconds` | `TotalRequestLatency` | Histogram: time until its last byte was sent |

CloudWatch's sums are Prometheus counters (take their `rate`), its averages and
percentiles of latency the histograms' (in seconds, not milliseconds):

```promql
sum by (bucket) (rate(teifs_request_metrics_all_requests_total{filter_id="EntireBucket"}[5m]))
rate(teifs_request_metrics_4xx_errors_total[5m]) / rate(teifs_request_metrics_all_requests_total[5m])
histogram_quantile(0.99, rate(teifs_request_metrics_first_byte_latency_seconds_bucket{bucket="app"}[5m]))
```

Requests are watched from the moment a bucket has a configuration, or an exporting
[storage class analysis](#storage-class-analysis) (from the start, when one has one as
the server starts), and counted once their answer is done with, a few
milliseconds later. A client that leaves early is counted, but not as an error. Tags are
the object's once the request is answered, so a deleted object's requests match no tag
filter. Access point filters match nothing: TeiFS has no access points. A configuration's
series go within a minute of it being removed; with many requests on tag filters, the
ones too many to count are left out and counted in `teifs_request_metrics_dropped_total`.

## Inventory reports

A bucket's inventory, as S3 Inventory makes it, lists its objects (or every version) daily
or weekly in files any tool that reads S3 Inventory reads (Athena, Spark, `s3 cp`).

```sh
teifs inventory add local/app daily local/reports --fields size,etag,lastmodifieddate
teifs inventory add local/app weekly local/reports/inv --all-versions --weekly --fields all --format parquet
teifs inventory ls local/app
teifs inventory info local/app daily
teifs inventory run local/app daily
teifs inventory rm local/app daily
```

`teifs inventory add` also adds a statement to the destination's bucket policy that lets
S3 Inventory (`s3.amazonaws.com`) write there for this bucket, as the S3 console does;
with `--no-policy`, grant it yourself. Like any other configuration it can be set through
S3 (`PutBucketInventoryConfiguration`).

The first report is made within 15 minutes of the configuration, the next each day
(UTC) or each Sunday; a report already made isn't made again after a restart. Each is,
under `PREFIX/BUCKET/ID/` in the destination:

- `data/UUID.csv.gz`, `.orc` or `.parquet`, in the configuration's format (`--format`):
  `Bucket, Key` (with `--all-versions`, then `VersionId, IsLatest, IsDeleteMarker`) and
  the chosen fields in S3's order. CSV is gzipped, without a header, every value quoted
  and keys URL-encoded; ORC (zlib) and Parquet (Snappy) have S3's typed columns
  (`bucket`, `key`, `size` as a 64-bit integer, `last_modified_date` as a timestamp in
  milliseconds…), with nulls where a value doesn't apply. Each file holds up to about
  32 MiB.
- `hive/dt=YYYY-MM-DD-HH-MM/symlink.txt`: the data files' `s3://` URLs, for Hive and
  Athena.
- `YYYY-MM-DDTHH-MMZ/manifest.json`, then `manifest.checksum` (its MD5): the source and
  destination, the schema, and each data file's key, size and MD5. A report is complete
  once its checksum is there.

`teifs inventory run` makes a report now, whatever the schedule and even when the
configuration is disabled, and says where its manifest is; the next scheduled report
comes when it would have (admin API `POST inventory?bucket=NAME&id=ID`, which needs
`teifs:RunInventoryReport`). It fails as the delivery did: `AccessDenied` when the
destination doesn't let S3 Inventory in.

Every object is `STANDARD` and Object Lock has no event
holds, so those fields are empty or `STANDARD`; `ObjectOwner` is `teifs`. A destination
that doesn't let the service in, or doesn't exist, gets nothing that day (with a warning
in the server's log); a failure of the drive is tried again within 15 minutes. Reports
are written like any other object: encrypted as `--encrypt` or the destination's default
says (a folder bucket takes no encryption, so give such a destination none), counted in
its usage, and announced by its notifications.

## Storage class analysis

A bucket's analytics configurations analyse how its objects are read by age, as S3's
storage class analysis does; one that exports adds each day's figures to a CSV in a
destination bucket, the same file S3 writes, for a spreadsheet or Quick.

```sh
teifs analytics add local/app docs --prefix docs/ --export local/reports/analytics
teifs analytics add local/app red --tag team=red
teifs analytics ls local/app
teifs analytics info local/app docs
teifs analytics rm local/app docs
```

`teifs analytics add --export` also adds a statement to the destination's bucket policy
that lets S3 (`s3.amazonaws.com`) write there for this bucket, as the S3 console does;
with `--no-policy`, grant it yourself. Like any other configuration it can be set through
S3 (`PutBucketAnalyticsConfiguration`).

The export is `PREFIX/BUCKET/ID.csv` in the destination. Each day (UTC) once it's over,
13 rows are added: one for each age group of objects of 128 KiB or more (`000-014` days
since they were written, `015-029`, … `365-729`, `730+`), then `ALL`, for every object
the configuration matches. Rows are sorted by date within age group, `ALL` last, under
S3's header:

| Column | What |
|---|---|
| `Date` | When the row was made, `MM-DD-YYYY` |
| `ConfigId` | The configuration's id |
| `Filter` | Empty, as on S3 |
| `StorageClass` | `STANDARD`: every object is |
| `ObjectAge` | The age group, or `ALL` |
| `ObjectCount` | Objects (`ALL` only) |
| `DataUploaded_MB` | Bytes written that day by `PutObject` and `CopyObject`, not multipart uploads (`ALL` only) |
| `Storage_MB` | Bytes stored at the end of the day |
| `DataRetrieved_MB` | Bytes read by `GetObject` that day |
| `GetRequestCount` | Successful `GetObject`, `PutObject` and `CopyObject` requests that day (S3's name; it counts both) |
| `CumulativeAccessRatio` | Bytes retrieved over bytes stored, for the age group and every older one (`ALL`: every object); empty when nothing is stored |
| `ObjectAgeForSIATransition`, `RecommendedObjectAgeForSIATransition` | Empty |

A megabyte is 1,048,576 bytes; figures have up to six decimals. A configuration's first
row is of its first whole day. Requests are counted as they're answered, by the object's
tags and age then; the day's counts are kept with the drive every 15 minutes and when
the server stops, so a crash loses at most 15 minutes of them. S3's transition recommendations come from a model of 30
days of access it doesn't publish, so TeiFS leaves their columns empty; read the age
groups' `CumulativeAccessRatio` instead: an age from which it stays low is where S3
would move objects to `STANDARD_IA`. A destination that doesn't let the
service in, or doesn't exist, gets nothing that day (with a warning in the server's log);
a failure of the drive is tried again within 15 minutes.

## Intelligent-Tiering and Requester Pays

A bucket's Intelligent-Tiering configurations are kept and answered as S3 answers them,
with its checks (the Archive Access tier after 90 to 730 days without access, Deep
Archive Access after 180 to 730 and later than Archive Access), so tools that set them
work. Every object is `STANDARD`, so none is moved to an archive tier.

```sh
teifs tiering add local/app cold --prefix logs/ --archive-days 90 --deep-archive-days 180
teifs tiering ls local/app
teifs tiering rm local/app cold
```

A Requester Pays bucket refuses anonymous requests, whatever its policy allows, and
can't be an access log's target; TeiFS bills no one, so that's all it changes.

```sh
teifs requester-pays enable local/app
teifs requester-pays info local/app
teifs requester-pays disable local/app
```

## Static websites

A bucket with a website configuration is a static website, as on S3's website endpoint,
at `BUCKET.DOMAIN` for each `serve --website-domain DOMAIN` (repeatable, or
`TEIFS_WEBSITE_DOMAINS`), on the server's own listener:

```sh
teifs serve --website-domain web.example.com       # *.web.example.com resolves to the server
teifs website set local/blog --index index.html --error 404.html
aws s3api put-bucket-policy --bucket blog --policy file://public-read.json
# http://blog.web.example.com:9000/ answers blog/index.html
```

A website shows only what anybody may read: each request reads its object as an
anonymous S3 request, so the bucket's policy, ACLs and Block Public Access decide, as on
S3, and a private bucket's site answers `403 Forbidden`. Grant `s3:GetObject` on the
bucket's objects to `"Principal": "*"` (and turn off the bucket's Block Public Access);
grant `s3:ListBucket` too for a missing page to be `404 Not Found` rather than `403`, as
AWS advises. A website answers as S3's does:

- `GET` and `HEAD` only (`405 MethodNotAllowed` otherwise); `OPTIONS` is a CORS
  preflight, and answers follow the bucket's CORS rules.
- `/` and every `…/` answer the folder's index document; `/about` answers `302` to
  `/about/` when `about/index.html` exists.
- Errors answer S3's HTML page, with `x-amz-error-code` and `x-amz-error-message`; a
  `4XX` answers the error document, if there is one, with the error's status.
- Redirection rules apply in order: those without an error code before the object is
  read, those with one after its read fails with that status. `RedirectAllRequestsTo`
  sends every request elsewhere with `301`, and an object's
  `x-amz-website-redirect-location` (`/key`, `http://…` or `https://…`) sends its page
  there with `301`.
- Ranges and conditional requests (`If-None-Match`, …) work, and encrypted objects are
  served decrypted, as through the S3 API.

A website domain can't also be a `--domain` (the server refuses to start): their hosts
look the same. For a site under a name of its own (`www.example.com`), put a reverse
proxy in front that forwards to the server with `Host: BUCKET.DOMAIN`, and TLS there
too; redirects keep the scheme the server was reached with (`X-Forwarded-Proto` from a
`--trusted-proxy`).

## Bucket quotas

A bucket's quota, as `MinIO`'s hard quota, is the most it may hold: a write that would
reach it is refused with `MinIO`'s error, `400 XMinioAdminBucketQuotaExceeded` ("Bucket
quota exceeded"). It's set through `MinIO`'s admin API, so `mc quota` works as it does
against `MinIO`:

```sh
teifs quota set local/photos --size 100GiB    # or: mc quota set local/photos --size 100GiB
teifs quota info local/photos
teifs quota clear local/photos
```

What a bucket holds is every version of every object (and, in a folder bucket, its
files), as its usage counts them; uploads in progress count once they're completed. As
on `MinIO`, `PutObject` (and a browser's `POST`), `CopyObject`, `UploadPart` and
`UploadPartCopy` are refused, before their bodies are read, when what the bucket holds
and what they write would reach the quota; so uploads that run at the same time can pass
it together, and overwriting an object counts its new bytes in full until the old ones
go. A quota set below what a bucket holds stops its writes until deletes (or lifecycle
expirations) bring it under. Deliveries of access logs into a bucket at its quota are
dropped, with a warning, as other refused deliveries are. Setting and reading quotas
take `MinIO`'s actions, `admin:SetBucketQuota` and `admin:GetBucketQuota`, on the bucket
(see [ADMIN_API.md](ADMIN_API.md)); admin exports and imports carry them.

## Replication

A bucket with a replication configuration (`PutBucketReplication`, `mc replicate add`)
has each new version its rules take copied by a background job: woken as objects are
written, and every minute for anything a restart or a failed attempt left waiting (each
version keeps where it stands, so nothing is lost). Both buckets must keep versions. The
copy is a *replica*: the same version id, last-modified time, metadata, tags and Object
Lock settings, marked `REPLICA` and not replicated again. `x-amz-replication-status`
on the source says `PENDING` until every destination has it, then `COMPLETED`, or
`FAILED` when a destination can't take it (it was removed, or its versioning
suspended). In a folder bucket a replica is a plain file like any other, its
modification time the version's. Objects encrypted with SSE-C
fail: the server never holds their keys. Destinations on other S3 services are
replication targets (below): each version goes there as a `PutObject` signed with the
target's keys, streamed with its `Content-MD5`, or as a multipart upload above 5 GiB. A
target that answers `4xx` (it refused the keys, or the bucket isn't there) fails the
version; one that can't be reached, or answers `5xx`, has it tried again on later
passes. Another TeiFS (or a `MinIO`) keeps the version's id, time and ETag when the
target's keys may `s3:ReplicateObject` there as well as `s3:PutObject`; give the
replicating user both. A `MinIO` replicates into TeiFS the same way, keeping its version
ids, once `mc replicate add` on it names a TeiFS bucket. Versions encrypted with SSE-S3
arrive encrypted as the target bucket's default says (a `MinIO` without a KMS stores
them unencrypted); SSE-KMS versions ask for the rule's replica KMS key.

Delete markers are replicated when the rule says so (`DeleteMarkerReplication`, always
for a rule of the configuration's first version): the destination's current version
becomes a marker with the same id and time (on AWS, a marker of its own). Markers made
by lifecycle expirations aren't replicated, as on S3, and neither is removing a version
by its id. A replicating user on another TeiFS needs `s3:ReplicateDelete` and
`s3:DeleteObject` for markers. Replicating existing objects and metadata changes is
still to come.

### Replication targets

A bucket's replication rules name where its objects go: another bucket on the same drive
(`arn:aws:s3:::NAME`), or a *target*, a bucket on another S3 service (another TeiFS,
MinIO, AWS…). Targets are added, listed and removed through `MinIO`'s admin API
(`set-remote-target`, `list-remote-targets` and `remove-remote-target`, as madmin-go
calls them), which answers the ARN the rules name. `mc replicate` adds the target and
its rule together, as it does against `MinIO`:

```sh
mc replicate add local/photos --priority 1 \
  --remote-bucket 'https://ACCESS_KEY:SECRET_KEY@backup.example.com:9000/photos-copy'
mc replicate ls local/photos
mc replicate update local/photos --id RULE_ID --state disable
mc replicate rm local/photos --id RULE_ID      # the rule, then its target
mc replicate rm local/photos --all --force     # every rule (targets stay)
```

A target's ARN is `arn:minio:replication:REGION:ID:BUCKET`; adding the same endpoint and
bucket again changes that target (its settings and secret key) and keeps the ARN. The
secret key comes encrypted with the caller's, is kept sealed by the drive's KMS (so a
target needs one) and is never answered. A target is removed only once no rule of the
bucket's replication configuration names it (`400 XMinioAdminRemoteRemoveDisallowed`).
Certificates are always checked (`insecureTLS` is refused). Adding, changing and removing
targets take `admin:SetBucketTarget` on the bucket, listing them `admin:GetBucketTarget`.
Admin exports don't carry targets, as they'd carry their secrets: a configuration naming
one is imported once the target is added on the other server.

## Migrating from MinIO or another S3 service

`teifs migrate SOURCE DEST` moves buckets from any S3 service to another, through the S3
API with the keys of two aliases: from MinIO, AWS, RustFS or another TeiFS into TeiFS,
say. `SOURCE` is an alias (every bucket, each keeping its name) or
`ALIAS/BUCKET[/PREFIX]`; `DEST` is an alias or `ALIAS/BUCKET[/PREFIX]`.

```sh
teifs alias set minio https://minio.example.com:9000 --access-key admin
teifs alias set home http://127.0.0.1:9000 --drive ~/Drive
teifs migrate minio home --dry-run     # what would be copied
teifs migrate minio home               # every bucket
teifs migrate minio/photos home/pictures --latest   # one bucket, current objects only
```

What's carried:

- **Buckets.** A missing destination bucket is made, with Object Lock when the source
  has it. Its settings are copied where the destination has none of its own:
  versioning, Object Lock's default retention, the policy (the source bucket's ARN made
  the destination's), lifecycle rules, CORS, tags, default encryption, the website,
  object ownership, the public access block, Requester Pays and the inventory, analytics,
  metrics and Intelligent-Tiering configurations. A setting the destination already has
  is kept, and said. Notifications, access logging and replication name things on the
  source (its queues, buckets and roles), so they're listed for you to set up again.
  `--no-configs` copies none of them.
- **Versions.** When the source bucket has versioning, every version and delete marker
  goes, oldest first, so the destination's history is the source's. With `--latest`,
  only the current objects go.
- **Objects.** Each keeps its `Content-Type`, `Cache-Control`, `Content-Disposition`,
  `Content-Encoding`, `Content-Language`, `Expires`, website redirect, user metadata,
  tags, retention (when it hasn't ended) and legal hold. An object uploaded in parts is
  copied in parts of the same sizes, so its ETag is the same, and each copy's ETag is
  checked against the source's before it counts. Copies within one service are done by
  the service; otherwise the bytes pass through `teifs`, several objects and parts at
  once (`--parallel`, `--part-size`), without being held in memory whole.

What isn't: an object's `Last-Modified` and version id (S3 sets both when it's written,
so lifecycle rules count a migrated object's age from the migration), ACL grants (they
name accounts of the source) and additional checksums (the destination computes its
own).

Only what the destination lacks is copied: the source and destination are listed side
by side, a page at a time, so a migration that stopped (or failed for some objects)
carries on when it's run again, and a later run copies only what's new. A key whose
versions at the destination aren't the source's first ones is a conflict: it's
reported, left alone, and the command exits with code 1. Objects are told apart by
size and ETag; `--size-only` uses size alone, for services whose ETags aren't MD5s (as
for objects encrypted with KMS keys on AWS). Users and their policies aren't part of
`migrate`: between TeiFS servers `teifs admin iam export` and `import` move them; from
MinIO, `mc admin cluster iam export` and `import` move users, groups, policies and
service accounts either way (the root user's alone, since the zip holds secrets), and
`mc admin cluster bucket export` and `import` buckets' settings; from
another service, make them with `teifs admin user` or `aws iam`.

## Bucket notifications

A bucket's rules send events (an object written, read, tagged, deleted, expired…) to
targets the server has, as S3 sends them to queues and MinIO to its targets. The server
names its targets; a bucket's rules pick among them, so whoever may configure a bucket
can't make the server call anything else.

### Targets

```sh
teifs serve --notify-webhook orders=https://hooks.example/s3 --notify-webhook audit=http://10.0.0.5/in
export TEIFS_NOTIFY_WEBHOOK_TOKEN_ORDERS=…   # sent as Authorization: Bearer …
```

Each target is `ID=URL` (letters, digits, `-` and `_` in the ID); in the environment,
`TEIFS_NOTIFY_WEBHOOK` holds them separated by spaces. A token is read only from the
environment, `TEIFS_NOTIFY_WEBHOOK_TOKEN_ID` (the ID in capitals, `-` as `_`), and one
that names its scheme (`Basic …`) is sent as given. A target's ARN is
`arn:teifs:sqs::ID:webhook`; MinIO's `arn:minio:sqs::ID:webhook` names it too, so `mc
event add` works unchanged. `teifs admin config` lists the targets, without secrets.
An https webhook takes the audit webhook's `ca=PATH`, `client_cert=PATH` and
`client_key=PATH` after its URL (`orders=https://hooks.internal/s3,ca=/etc/teifs/ca.pem`),
as MinIO's `client_cert` and `client_key` do; options are taken from the URL's end, so a
comma in the URL stays in it.

```sh
teifs serve --notify-elasticsearch objects=https://es.example:9200,index=objects \
            --notify-elasticsearch log=https://es.example:9200,index=s3-log,format=access,user=teifs
export TEIFS_NOTIFY_ELASTICSEARCH_PASSWORD_LOG=…   # or TEIFS_NOTIFY_ELASTICSEARCH_API_KEY_ID
```

An Elasticsearch (or OpenSearch) target, `arn:teifs:sqs::ID:elasticsearch`, keeps events
in an index it creates when missing, each as a document `{"Records":[record]}`: with
`format=namespace` (the default) one per object, its id a hash of `BUCKET/KEY`, replaced
by each event and removed when the object is (`s3:ObjectRemoved:Delete`,
`s3:LifecycleExpiration:Delete`), so the index mirrors the bucket; with `format=access`
one per event. Basic authentication takes `user=NAME` and the password from
`TEIFS_NOTIFY_ELASTICSEARCH_PASSWORD_ID`; an API key comes from
`TEIFS_NOTIFY_ELASTICSEARCH_API_KEY_ID`. A rule that starts naming it checks that the
cluster answers and the index exists, without writing a test document. For an https
cluster, `ca=PATH`, `client_cert=PATH` and `client_key=PATH` work as they do for a
webhook.

```sh
teifs serve --notify-redis objects=redis.internal:6379,key=s3:objects \
            --notify-redis log=redis.internal:6379,key=s3:log,format=access,db=1
export TEIFS_NOTIFY_REDIS_PASSWORD_OBJECTS=…   # with user=NAME for a Redis 6 ACL user
```

A Redis target, `arn:teifs:sqs::ID:redis`, keeps events under a key: with
`format=namespace` (the default) a hash with a field per object (`BUCKET/KEY`) holding
`{"Records":[record]}`, set by each event and removed with the object; with
`format=access` a list with an entry per event pushed on its end,
`[{"Event":[record],"EventTime":"…"}]`, as MinIO's. `db=N` selects a database. A key that
already holds another type is refused. Starting to name it checks that the server
answers, takes the password and has a key of the right type, without writing to it.
`tls=true` reaches it over TLS, the server verified with the system's certificates, and
`ca=PATH` with a CA's PEM file instead (a managed Redis's or your own); a file with no
certificate stops the server from starting. For a server that wants a client
certificate, `client_cert=PATH` and `client_key=PATH` give the PEM chain and key TeiFS
shows it (NATS targets take them too).

`--notify-nsq queue=nsqd.internal:4150,topic=s3-events` publishes each event to an NSQ
topic, as a webhook is sent it, over nsqd's TCP protocol; rules name it
`arn:teifs:sqs::ID:nsq`, and starting to name it checks that the nsqd answers.
`tls=true` or `ca=PATH` (with `client_cert` and `client_key` for an nsqd that asks) upgrades
the connection to TLS as nsqd negotiates it after `IDENTIFY`, verified with the system's
certificates or the CA; an nsqd without TLS is refused. An nsqd that wants `AUTH`
(`--auth-http-address`) is sent the secret in `TEIFS_NOTIFY_NSQ_SECRET_ID`, only over
TLS.

```sh
teifs serve --notify-nats bus=nats.internal:4222,subject=s3.events,user=teifs \
            --notify-nats stream=nats.internal:4222,subject=s3.stream,jetstream=true,creds=/etc/teifs/teifs.creds,tls=true
export TEIFS_NOTIFY_NATS_PASSWORD_BUS=…   # or TEIFS_NOTIFY_NATS_TOKEN_ID for a token
```

A NATS target, `arn:teifs:sqs::ID:nats`, publishes each event to a subject, as a webhook
is sent it; the server's answer to a `PING` after each one confirms it took it. With
`jetstream=true` a JetStream stream that takes the subject must acknowledge each event,
and each carries a `Nats-Msg-Id` made from its content, so an event sent again after a
lost acknowledgement is dropped as a duplicate within the stream's duplicate window.
It signs in with `user=NAME` and a password, a token, an nkey (`nkey=PATH`, a file holding
a user seed) or a `.creds` file's user JWT (`creds=PATH`, as `nsc` writes it). `tls=true`
or `ca=PATH` connects over TLS (a server that requires TLS asks for it), and
`tls_first=true` starts TLS before the server's greeting, for a server set to
`handshake_first`. Starting to name it checks that the server takes the credentials and,
for JetStream, that a stream takes the subject, without publishing.

```sh
teifs serve --notify-mqtt iot=broker.internal:8883,topic=s3/events,user=teifs,tls=true
export TEIFS_NOTIFY_MQTT_PASSWORD_IOT=…
```

An MQTT target, `arn:teifs:sqs::ID:mqtt`, publishes each event to a topic over MQTT
3.1.1, as a webhook is sent it, with a clean session and a random client id. `qos=1`
(the default) waits for the broker's `PUBACK`, `qos=2` for its `PUBREC` and `PUBCOMP`,
and `qos=0` for the answer to a ping sent after it; messages aren't retained.
`keepalive=SECONDS` (60 by default) is how long the broker waits for a packet before it
drops the connection. TLS takes the same options as Redis's. The broker can also be
given by its URL, as MinIO takes it: `tcp://` or `mqtt://`, `ssl://`, `tls://` or
`mqtts://` for TLS (verified with the system's certificates unless `ca=PATH` says
otherwise), and `ws://` or `wss://` for a broker reached over WebSockets at the URL's
path (`wss://broker.example/mqtt`), asking for the `mqtt` subprotocol; a URL without a
port has its scheme's (1883, 8883, 80, 443). Starting to name it checks that the broker
takes the connection and the user and password, without publishing.

```sh
teifs serve --notify-kafka 'stream=k1.internal:9093;k2.internal:9093,topic=s3-events,sasl=scram-sha-512,user=teifs,tls=true'
export TEIFS_NOTIFY_KAFKA_PASSWORD_STREAM=…
```

A Kafka target, `arn:teifs:sqs::ID:kafka`, produces each event to a topic, as a webhook
is sent it, keyed `bucket/object` (the key as written, as MinIO's is). The brokers given
(separated by `;`) are asked, in turn, for the topic's partitions and their leaders; each
record goes to the partition Kafka's own clients pick for its key (murmur2), so one
object's events stay in order on one partition, and to that partition's leader, which
answers once every in-sync replica has it (`acks=all`, the default) or once it has it
(`acks=1`). A leader that moved or a partition being elected is looked up again at once;
a record the broker refuses (`NOT_ENOUGH_REPLICAS`, say) is tried again later, like any
event a target doesn't take. `compression=gzip`, `snappy`, `lz4` or `zstd` compresses
each record, as MinIO's names do (zstd needs Kafka 2.1 or later; an older broker is
refused by name). `sasl=plain`,
`scram-sha-256` or `scram-sha-512` with `user=NAME` signs in, the password from
`TEIFS_NOTIFY_KAFKA_PASSWORD_ID`; SCRAM never sends the password, and PLAIN is for TLS
only. TLS takes the same options as Redis's, for every broker. The topic must exist, or
the brokers must make topics. Starting to name it checks that a broker takes the
connection and knows the topic, without producing. It needs Kafka 1.0 or later (Kafka 4
included); nightly CI runs it against a real broker.

```sh
teifs serve --notify-amqp rabbit=amqps://mq.internal/prod,exchange=s3,routing_key=events,user=teifs
export TEIFS_NOTIFY_AMQP_PASSWORD_RABBIT=…
```

An AMQP target, `arn:teifs:sqs::ID:amqp`, publishes each event over AMQP 0-9-1
(RabbitMQ, LavinMQ) to an exchange with a routing key, as a webhook is sent it:
`application/json`, with MinIO's headers `minio-bucket` and `minio-event`, and persistent
(`persistent=false` for transient messages). Each waits for the broker's publisher
confirm, so an event is removed from the queue only once the broker has it. The exchange
is declared when the connection is made, a durable `direct` one unless `exchange_type`,
`durable`, `auto_delete` or `internal` say otherwise; one that exists with other settings
is named, and `declare=false` only checks that it exists (for a user that may not
configure). Without an exchange, the routing key names a queue on the default exchange.
`mandatory=true` makes a message no queue is bound for fail and be tried again, rather than
be dropped by the broker. The URL is `amqp://HOST[:PORT][/VHOST]` (the virtual host `/`
when none is given; `%2F` for a `/` in its name), or `amqps://` for TLS, verified with the
system's certificates or `ca=PATH`, with `client_cert` and `client_key` for a broker that
asks. The user is `user=NAME` and its password comes from
`TEIFS_NOTIFY_AMQP_PASSWORD_ID`; without them, AMQP's `guest`. Starting to name it checks
that the broker takes the user, the virtual host and the exchange, without publishing.
Nightly CI runs it against a real RabbitMQ.

```sh
teifs serve --notify-postgresql db=pg.internal:5432,database=teifs,table=s3_objects,user=teifs,ca=/etc/teifs/pg-ca.pem
export TEIFS_NOTIFY_POSTGRESQL_PASSWORD_DB=…
```

A PostgreSQL target, `arn:teifs:sqs::ID:postgresql`, keeps events in a table, in
MinIO's formats: `namespace` (the default) keeps a row per object, `key` (`bucket/object`,
the primary key) and `value` (`{"Records":[record]}` as JSONB), set by each event and
deleted when the object is; `access` adds a row per event, `event_time` (a timestamp with
time zone) and `event_data` (the event as a webhook is sent it, as JSONB). The table is made
when it's missing (`CREATE TABLE IF NOT EXISTS`, so the user needs `CREATE` on the schema
the first time, and `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the table after); a name in
double quotes keeps its capitals (`table="S3Events"`), and a table made beforehand must have
the same columns. It signs in as `user=NAME` with the password from
`TEIFS_NOTIFY_POSTGRESQL_PASSWORD_ID` by SCRAM-SHA-256 (PostgreSQL's default) or MD5, or
with none under `trust`; a server that asks for the password in the clear gets it only over
TLS. `tls=true` or `ca=PATH` asks for TLS before anything else is sent, verified with the
system's certificates or the CA, with `client_cert` and `client_key` for a server that
asks. Starting to name it checks that the server takes the user and the database and that
the table is there or can be made. Nightly CI runs it against a real PostgreSQL 17.

```sh
teifs serve --notify-mysql db=mysql.internal:3306,database=teifs,table=s3_objects,user=teifs,server_public_key=/etc/teifs/mysql-public_key.pem
export TEIFS_NOTIFY_MYSQL_PASSWORD_DB=…
```

A MySQL target, `arn:teifs:sqs::ID:mysql`, keeps events in a MySQL (5.7 or later) or
MariaDB table, in MinIO's formats and with MinIO's tables: `namespace` (the default) keeps a
row per object, `key_name` (`bucket/object`), `key_hash` (its SHA-256, the primary key) and
`value` (`{"Records":[record]}` as JSON), set by each event and deleted when the object is;
`access` adds a row per event, `event_time` (a `DATETIME`, in UTC) and `event_data` (the
event as a webhook is sent it). On MariaDB, which takes no generated primary key,
`key_hash` is a unique key instead. The table is made when it's missing, as for PostgreSQL; a
name in backquotes keeps its capitals (`` table=`S3Events` ``). Each statement is prepared
once per connection and run with its values bound.

It signs in as `user=NAME` with the password from `TEIFS_NOTIFY_MYSQL_PASSWORD_ID`, by the
user's plugin: `caching_sha2_password` (MySQL 8's default), `mysql_native_password`
(MariaDB's default and older MySQL's) or `sha256_password`; `mysql_clear_password` only over
TLS. `caching_sha2_password` proves the password without sending it once the server has
the user cached; the first time after the server starts it wants the password whole, which
TeiFS sends only over TLS (`tls=true` or `ca=PATH`, with `client_cert` and `client_key` for
a server that asks) or encrypted with the server's RSA key: `server_public_key=PATH` (a copy
of the server's `public_key.pem`), or `get_server_public_key=true` to ask the server for it,
which a machine between them could answer with its own. Without one of these, a target
that needs it says so. Starting to name it checks that the server takes the user and the
database and that the table is there or can be made. Nightly CI runs it against real
MySQL 8.4 and MariaDB 11.4.

Redis, NSQ, NATS, MQTT, Kafka, AMQP, PostgreSQL and MySQL targets each keep their
connections. One the server closed while it was idle (nsqd does after missed heartbeats,
NATS after missed pings, an MQTT broker after its keep alive, Kafka after
`connections.max.idle.ms`, Redis with a `timeout` set, MySQL after `wait_timeout`) is made
again at once, rather than failing the event and waiting to retry it.
Nightly CI sends events to a real nsqd, Redis, NATS JetStream and Mosquitto, each over
TLS verified with a CA and signed in, and reads back what each got.

```sh
teifs serve --notify-sqs orders=https://sqs.eu-west-1.amazonaws.com/123456789012/orders
export TEIFS_NOTIFY_SQS_ACCESS_KEY_ORDERS=AKIA… TEIFS_NOTIFY_SQS_SECRET_KEY_ORDERS=…
```

An SQS target, `arn:teifs:sqs::ID:sqs`, sends each event to a queue as S3 does: the
message is S3's `{"Records":[...]}`, without MinIO's envelope, sent with `SendMessage` in
SQS's JSON protocol and signed with Signature Version 4. The region is the one the
queue's host names (`region=NAME` for another host, `us-east-1` if neither says), so any
service that speaks SQS's API will do. A FIFO queue (`….fifo`) gets each object's events
in order, grouped by `BUCKET/KEY`, with the message's SHA-256 as its deduplication id.
The keys come from `TEIFS_NOTIFY_SQS_ACCESS_KEY_ID`, `TEIFS_NOTIFY_SQS_SECRET_KEY_ID` and
`TEIFS_NOTIFY_SQS_SESSION_TOKEN_ID`, else from `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`; with none, requests go unsigned. The
answer's `MD5OfMessageBody` is checked, as AWS's SDKs check it. Starting to name it sends
the queue S3's test event, as S3 does, so a queue that doesn't exist or keys it refuses
(`QueueDoesNotExist`, `InvalidSignatureException`) are named at once. The keys need
`sqs:SendMessage` on the queue.

Rules can also name the queue by its own ARN, as on S3:
`arn:aws:sqs:eu-west-1:123456789012:orders` names the target above, so an existing
`put-bucket-notification-configuration` works unchanged. The ARN is read from the queue's
URL (`…/ACCOUNT/NAME`) and region, and `teifs admin config` shows it; the rule keeps the
ARN it was given. Two targets for the same queue are refused. A FIFO message group is
the object's `BUCKET/KEY` when SQS takes it (up to 128 ASCII letters, digits and
punctuation), else the key's SHA-256, so each object keeps one group.

```sh
teifs serve --notify-sns uploads=arn:aws:sns:eu-west-1:123456789012:uploads
export TEIFS_NOTIFY_SNS_ACCESS_KEY_UPLOADS=AKIA… TEIFS_NOTIFY_SNS_SECRET_KEY_UPLOADS=…
```

An SNS target publishes each event to a topic as S3 does: `Publish` in SNS's Query
protocol, signed with Signature Version 4, the message S3's `{"Records":[...]}` and the
subject `Amazon S3 Notification`. Rules name it by the topic's ARN, as on S3 (a
`TopicConfiguration`), or `arn:teifs:sqs::ID:sns`. Requests go to SNS in the topic's
region; `endpoint=URL` sends them to another service that speaks SNS's API. A FIFO topic
(`….fifo`) gets the same groups and deduplication ids as a FIFO queue. The keys come from
`TEIFS_NOTIFY_SNS_ACCESS_KEY_ID`, `TEIFS_NOTIFY_SNS_SECRET_KEY_ID` and
`TEIFS_NOTIFY_SNS_SESSION_TOKEN_ID`, else AWS's variables, and need `sns:Publish` on the
topic. Starting to name it publishes S3's test event, so a topic that doesn't exist
(`NotFound`) or refused keys are named at once.

```sh
teifs serve --notify-lambda thumbs=arn:aws:lambda:eu-west-1:123456789012:function:thumbs
```

A Lambda target invokes a function with each event as S3 does: asynchronously
(`InvocationType` `Event`), with S3's `{"Records":[...]}` as the payload, signed with
Signature Version 4. Rules name it by the function's ARN, as on S3 (a
`LambdaFunctionConfiguration`), or `arn:teifs:sqs::ID:lambda`; a version or alias goes
after the name (`…:function:thumbs:live`). Requests go to Lambda in the function's region,
or to `endpoint=URL`. Keys come from `TEIFS_NOTIFY_LAMBDA_ACCESS_KEY_ID`,
`TEIFS_NOTIFY_LAMBDA_SECRET_KEY_ID` and `TEIFS_NOTIFY_LAMBDA_SESSION_TOKEN_ID`, else AWS's
variables, and need `lambda:InvokeFunction`. As on S3, a function isn't sent a test event:
starting to name it makes a `DryRun` invocation, which checks the keys may invoke it
without running it, so a function that doesn't exist (`ResourceNotFoundException`) or
refused keys are named at once.

```sh
teifs serve --notify-eventbridge bus=arn:aws:events:eu-west-1:123456789012:event-bus/default
aws s3api put-bucket-notification-configuration --bucket photos \
  --notification-configuration '{"EventBridgeConfiguration":{}}'
```

EventBridge works as on S3: the server has one event bus, and a bucket whose
configuration has `EventBridgeConfiguration` sends it every event S3 sends there, besides
what its rules send and without choosing events: `Object Created` (with `reason`
`PutObject`, `POST Object`, `CopyObject` or `CompleteMultipartUpload`), `Object Deleted`
(`DeleteObject` or `Lifecycle Expiration`, with `deletion-type` `Permanently Deleted` or
`Delete Marker Created`), `Object Tags Added`, `Object Tags Deleted`, `Object ACL Updated`
and `Object Retention Updated`, each with S3's `detail` (the key not URL-encoded). They're
sent with `PutEvents`, signed with Signature Version 4, and an entry EventBridge fails is
retried. Only AWS's services may send events whose source starts with `aws.`, so the
source is `teifs.s3` (`source=NAME` for another): a rule written for S3's events matches
them once its `source` names it. Keys come from `TEIFS_NOTIFY_EVENTBRIDGE_ACCESS_KEY_ID`,
`…_SECRET_KEY_ID` and `…_SESSION_TOKEN_ID`, else AWS's variables, and need
`events:PutEvents` on the bus; `endpoint=URL` sends to another service. Turning it on
where the server has no bus is refused (`400 InvalidArgument`), and rules can't name the
bus.

### From MinIO's settings

The targets MinIO's variables or `mc admin config` name are the server's too, so a
MinIO deployment's notifications carry over unchanged:

```sh
export MINIO_NOTIFY_WEBHOOK_ENABLE_PRIMARY=on
export MINIO_NOTIFY_WEBHOOK_ENDPOINT_PRIMARY=https://hooks.example/s3
export MINIO_NOTIFY_WEBHOOK_AUTH_TOKEN_PRIMARY=…
teifs admin config set ALIAS notify_kafka:events brokers=k1:9092,k2:9092 topic=s3 \
  sasl=on sasl_username=teifs sasl_password=…   # then teifs admin service restart ALIAS
```

Each of `notify_webhook`, `notify_elasticsearch`, `notify_redis`, `notify_nsq`,
`notify_nats`, `notify_mqtt`, `notify_kafka`, `notify_amqp`, `notify_postgres` and
`notify_mysql` takes MinIO's keys (`teifs admin config keys ALIAS notify_kafka`). A
target counts once it's on: a stored one when `enable` is on, which `set` turns on, and
one only the environment names when its `MINIO_NOTIFY_KIND_ENABLE[_ID]` is. A key's
variable wins over what's stored. The default target's ID is `_`
(`arn:teifs:sqs::_:webhook`); a named one keeps its name as it's spelled. A flag's
target with the same ARN wins, and a `TEIFS_NOTIFY_KIND_WHAT_ID` variable wins over the
secret the settings give.

They're checked as the flags are, so a change the server wouldn't start with is refused.
A few of MinIO's keys work differently:

- `tls_skip_verify=on` is refused: TeiFS always checks a server's certificate, so give
  the CA that signed it (`cert_authority` for NATS). So is NATS Streaming, which NATS
  retired; `jetstream=on` publishes to a stream.
- PostgreSQL's `connection_string` (libpq's `host=… user=… dbname=…` or a `postgres://`
  URL) and MySQL's `dsn_string` (`USER:PASSWORD@tcp(HOST:PORT)/DATABASE`) are read for
  their host, user, password and database; `sslmode=require` or `verify-…`
  (`sslrootcert` for its CA) and `tls=true` connect with TLS, verified. TeiFS connects
  over TCP only.
- AMQP's user and password come out of its `url`; `delivery_mode=2` keeps events on
  disk, and an exchange that's named is declared with `durable`, `auto_deleted` and
  `internal` as given. TeiFS always waits for the server's confirmation.
- `queue_dir`, `queue_limit` and the keys MinIO's help marks unused are kept but not
  used: every target's events wait in the server's own queue on the drive.
- Values can't hold a comma, except Kafka's `brokers`.

`audit_webhook[:NAME]` (`MINIO_AUDIT_WEBHOOK_ENABLE`, `…_ENDPOINT`, `…_AUTH_TOKEN`,
`…_CLIENT_CERT`, `…_CLIENT_KEY`) sends the [audit log](#audit-log) to more webhooks,
besides `--audit-webhook`'s. `identity_tls`'s `skip_verify` is read as
`MINIO_IDENTITY_TLS_SKIP_VERIFY` is.

### Rules

`PutBucketNotificationConfiguration` sets a bucket's rules, as on S3:

```sh
aws s3api put-bucket-notification-configuration --bucket photos --endpoint-url … \
  --notification-configuration '{"QueueConfigurations": [{
    "Id": "new-images", "QueueArn": "arn:teifs:sqs::orders:webhook",
    "Events": ["s3:ObjectCreated:*"],
    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "images/"},
                                       {"Name": "suffix", "Value": ".jpg"}]}}}]}'
mc event add local/photos arn:minio:sqs::orders:webhook --event put --prefix images/
teifs event add local/photos arn:teifs:sqs::orders:webhook --event put --prefix images/ --suffix .jpg
```

`teifs event add ALIAS/BUCKET ARN` adds a rule (`--event` takes `put`, `delete`, `get`,
`ilm` or S3's names, `put,delete,get` by default; `--id` names it), refusing one the
bucket already has unless `--ignore-existing`; `teifs event ls ALIAS/BUCKET [ARN]` lists
them, and `teifs event rm ALIAS/BUCKET` removes one (`--id`), those sending to an ARN, or
all of them (`--all`). An SNS topic's or Lambda function's ARN makes the rule S3 is given
for it (a `TopicConfiguration` or `LambdaFunctionConfiguration`); anything else is a
queue's. `teifs event eventbridge ALIAS/BUCKET on|off` turns EventBridge on or off, and
`ls` shows it. Each reads the bucket's configuration and writes it back whole, keeping
what it doesn't change, so the server checks the whole configuration.

A rule is a `QueueConfiguration`, `TopicConfiguration` or `CloudFunctionConfiguration`
(all the same here): the target's ARN, events, and a key prefix and suffix (URL-encoded,
`+` for a space). S3's checks apply, each refused with `400 InvalidArgument`: events S3
and MinIO name, a group's `*` (`s3:ObjectCreated:*`), at most one prefix and one suffix,
at most 100 rules, a target the server has, and no two rules that could send the same
event for the same key (they share an event and their prefixes and suffixes overlap). A
rule without an id gets one. Each target a rule starts naming is sent S3's test event
first (`{"Service":"TeiFS","Event":"s3:TestEvent",…}`), and one that doesn't take it
fails the request and nothing changes, unless the request sends
`x-amz-skip-destination-validation: true`. An empty configuration removes the rules
and turns EventBridge off. Bucket exports carry the rules, and an import checks
them against the new server's targets.

| Event | When |
|---|---|
| `s3:ObjectCreated:Put`, `:Post`, `:Copy`, `:CompleteMultipartUpload` | An object was written, by PutObject, a browser form, CopyObject or a multipart upload |
| `s3:ObjectRemoved:Delete` | A version was removed (or an object, without versioning), by DeleteObject or DeleteObjects |
| `s3:ObjectRemoved:DeleteMarkerCreated` | A delete made a delete marker |
| `s3:LifecycleExpiration:Delete`, `:DeleteMarkerCreated` | A lifecycle rule removed a version or a delete marker, or hid an object behind a marker |
| `s3:ObjectTagging:Put`, `:Delete` | An object's tags were set or removed |
| `s3:ObjectAcl:Put` | An object's ACL changed |
| `s3:ObjectRetention:Put` | An object's retention was set |
| `s3:ObjectCreated:PutLegalHold` | Its legal hold was set (MinIO's name) |
| `s3:ObjectAccessed:Get`, `:Head`, `:Attributes`, `:GetRetention`, `:GetLegalHold` | An object was read (MinIO's) |

MinIO's `s3:ObjectCreated:PutTagging`, `:DeleteTagging` and `:PutRetention` name the
tagging and retention events too.

### What's sent

Each event is `POST`ed on its own as JSON: MinIO's envelope around the record S3 sends
(`eventVersion` 2.6), so consumers of either read it.

```json
{"EventName":"s3:ObjectCreated:Put","Key":"photos/images/my cat.jpg","Records":[{
  "eventVersion":"2.6","eventSource":"aws:s3","awsRegion":"us-east-1",
  "eventTime":"2026-09-30T12:00:00.123Z","eventName":"ObjectCreated:Put",
  "userIdentity":{"principalId":"TFABCDEF…"},
  "requestParameters":{"sourceIPAddress":"10.0.0.7"},
  "responseElements":{"x-amz-request-id":"18DA16C11FC2F0D0","x-amz-id-2":"…"},
  "s3":{"s3SchemaVersion":"1.0","configurationId":"new-images",
    "bucket":{"name":"photos","ownerIdentity":{"principalId":"teifs"},"arn":"arn:aws:s3:::photos"},
    "object":{"key":"images/my+cat.jpg","size":52431,"eTag":"…","versionId":"…",
      "sequencer":"18DA16C11FC2F0D0"}}}]}
```

The key is URL-encoded as S3 sends it (`unquote_plus` reads it). `principalId` is the
access key that signed the request (empty for anonymous requests and lifecycle rules),
and `x-amz-request-id` the request's id, also in the audit log. A key's events have
growing `sequencer`s.

### Delivery

An event is written to the drive (`.teifs/events.db`) before the request that made it is
answered. Each target is sent its events one at a time, in order; any `2xx` takes one.
One that isn't taken (an error, another status, no answer in 10 seconds) is tried again
after half a second, then twice as long each time up to 30 seconds, until it is, so a
target that's down gets everything once it's back, and a restart loses nothing. Delivery
is at least once: an event whose answer was lost is sent again. A target with 100 000
events waiting drops new ones (`teifs_notify_dropped_total`). Redirects aren't followed.
Events waiting for a target the server no longer has stay on the drive until it's
configured again.

### Watching events

`teifs watch ALIAS/BUCKET[/PREFIX]` shows a bucket's events as they happen, until Ctrl-C
(as `mc watch` shows MinIO's); `teifs watch ALIAS` shows every bucket's:

```text
$ teifs watch local/photos/images/ --events put,delete
12:00:00.123 ObjectCreated:Put photos/images/my cat.jpg 51.2 KiB
12:00:04.518 ObjectRemoved:Delete photos/images/my cat.jpg
```

`--events` takes `put`, `delete`, `get`, `ilm` (lifecycle expirations), `bucket` (buckets
created and removed) or S3's names, comma-separated (`put,delete,get` by default), and
`--suffix .jpg` narrows it further. With `--json` each event is S3's record. Watching
needs no target and no rule: it gets every event the bucket has, whatever its rules. It
needs MinIO's `s3:ListenBucketNotification` on the bucket, which a bucket policy may grant
(to anyone, even, with Block Public Access off), or `s3:ListenNotification` for every
bucket's.

A watch is MinIO's listen API, `GET /BUCKET?events=s3:ObjectCreated:*&prefix=…&suffix=…&ping=10`
(or `GET /?events=…`), so `mc watch` and minio-go's `ListenBucketNotification` work too.
Its answer is one `{"Records":[record]}` line per event, as long as the caller reads, with
`{"Records":[]}` every `ping` seconds (10 by default) so proxies keep a quiet one open.
Events are made only while the server has targets or someone watches; a watcher that
reads too slowly skips events rather than slow requests down, and every watch ends when
the server stops.
