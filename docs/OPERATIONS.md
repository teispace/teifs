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
| `teifs_start_time_seconds` | gauge | | When the server started (Unix time) |
| `teifs_build_info` | info | `version` | The TeiFS version |

Usage is counted by the index as it changes, so a scrape reads a row per bucket however
many objects there are, and it's exact the moment a write is. A folder bucket's files
added outside TeiFS count once the `index-folders` job has found them. What each bucket
holds is left out unless the scrape asks, as a drive can have many buckets:
`teifs admin prometheus generate ALIAS --buckets` adds `params: {buckets: ["1"]}`.
`teifs admin info` shows the totals.

Histograms' buckets double from 1 ms to about a minute. Some queries to start with:

```promql
sum by (api) (rate(teifs_s3_requests_total[5m]))                  # requests per second
sum(rate(teifs_s3_requests_total{code=~"5.."}[5m]))                 # server errors
histogram_quantile(0.99, sum by (le, api) (rate(teifs_s3_ttfb_seconds_bucket[5m])))
teifs_drive_free_bytes / teifs_drive_total_bytes < 0.1              # disk nearly full
max(teifs_job_failing) > 0                                          # a job keeps failing
max(teifs_scrub_damaged_versions) > 0                               # damage on the disk
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
