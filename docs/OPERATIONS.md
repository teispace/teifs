# Operations

Watching a TeiFS server: its request ids, Prometheus metrics and health check.

## Request ids

Every answer has an `x-amz-request-id` header: 16 hex digits, unique on the server, as
S3's are. An error's body names it too (`<RequestId>` in S3's XML, `requestId` in the
admin API's JSON), so a failure a client reports can be found in the server's logs and
metrics. The AWS SDKs keep it with the error (`request_id()`), and the AWS CLI prints it
with `--debug`.

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
| `teifs_start_time_seconds` | gauge | | When the server started (Unix time) |
| `teifs_build_info` | info | `version` | The TeiFS version |

Histograms' buckets double from 1 ms to about a minute. Some queries to start with:

```promql
sum by (api) (rate(teifs_s3_requests_total[5m]))                  # requests per second
sum(rate(teifs_s3_requests_total{code=~"5.."}[5m]))                 # server errors
histogram_quantile(0.99, sum by (le, api) (rate(teifs_s3_ttfb_seconds_bucket[5m])))
teifs_drive_free_bytes / teifs_drive_total_bytes < 0.1              # disk nearly full
max(teifs_job_failing) > 0                                          # a job keeps failing
```
