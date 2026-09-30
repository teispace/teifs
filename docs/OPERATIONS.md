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
cluster answers and the index exists, without writing a test document.

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
all of them (`--all`). Each reads the bucket's rules and writes them back, so the server
checks the whole configuration.

A rule is a `QueueConfiguration`, `TopicConfiguration` or `CloudFunctionConfiguration`
(all the same here): the target's ARN, events, and a key prefix and suffix (URL-encoded,
`+` for a space). S3's checks apply, each refused with `400 InvalidArgument`: events S3
and MinIO name, a group's `*` (`s3:ObjectCreated:*`), at most one prefix and one suffix,
at most 100 rules, a target the server has, and no two rules that could send the same
event for the same key (they share an event and their prefixes and suffixes overlap). A
rule without an id gets one. Each target a rule starts naming is sent S3's test event
first (`{"Service":"TeiFS","Event":"s3:TestEvent",…}`), and one that doesn't take it
fails the request and nothing changes, unless the request sends
`x-amz-skip-destination-validation: true`. An empty configuration removes the rules;
EventBridge is `501 NotImplemented`. Bucket exports carry the rules, and an import checks
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

Not yet: other kinds of targets (NATS, Kafka, AMQP, MQTT, NSQ, databases), and Redis over
TLS.
