# Operations

Watching a TeiFS server: its request ids, health check, Prometheus metrics, audit log
and live trace.

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
| `teifs_store_stage_seconds` | histogram | `op`, `stage` | Time in each stage of the store's writes (`key`: a data key from the KMS; `lock`: waiting for the commit lock; `sync`: making the data durable; `commit`: all of it under the lock) and reads (`locate`: finding the version and opening its file; `key`) |
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
| `teifs_bucket_objects`, `_versions`, `_delete_markers`, `_stored_bytes` | gauge | `bucket` | The same by bucket, with `?buckets=1` |
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
| `teifs_start_time_seconds` | gauge | | When the server started (Unix time) |
| `teifs_build_info` | info | `version` | The TeiFS version |

Usage is counted by the index as it changes, so a scrape reads a row per bucket however
many objects there are, and it's exact the moment a write is. A folder bucket's files
added outside TeiFS count once the `index-folders` job has found them. What each bucket
holds is left out unless the scrape asks, as a drive can have many buckets:
`teifs admin prometheus generate ALIAS --buckets` adds `params: {buckets: ["1"]}`.
`teifs admin info` shows the totals.

Request histograms' buckets double from 1 ms to about a minute; the store's from 100 µs
to about 52 s. A slow `sync` is the disk, a slow `key` the KMS (a transit engine's
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
