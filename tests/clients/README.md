# Client matrix

Real S3 clients doing what people do with them, against a fresh TeiFS server. Each
`<client>.sh` here is one client's scenario; `run.sh` builds `teifs`, serves an empty
drive on port 9313 (`CLIENTS_PORT`), and runs them.

| Client | What it does | Needs |
|---|---|---|
| `aws` | Buckets, single and multipart uploads, checksums, `sync` both ways, listings, presigned links | `aws` (v2) |
| `rclone` | Copy and check, multipart, server-side copy, `sync` with deletes, purge | `rclone` |
| `restic` | A repository in a bucket: backups, `check --read-data`, forget and prune, restore; then in a bucket with Object Lock (governance by default): prune leaves delete markers, the pruned versions stay and can't be removed | `restic`, `aws` |
| `kopia` | A repository with Kopia's own Object Lock (`--retention-mode=GOVERNANCE`): locked blobs, snapshots, `verify` of every file, restore, full maintenance under the lock | `kopia`, `aws`, `python3` |
| `boto3` | Metadata and checksums, the transfer manager, ranges, paginators, presigned GET and PUT, conditional writes; that its default (Version 2) presigned links are refused | `python3` |
| `go` | The AWS SDK for Go v2: default checksums, the transfer manager, paginators, presigned links | `go` |
| `js` | The AWS SDK for JavaScript v3: default checksums, `lib-storage` multipart from a stream, paginators, presigned links | `npm` |
| `terraform` | The S3 state backend with `use_lockfile`: two applies, and a held lock stopping a third | `terraform`, `aws` |

## Running

```sh
tests/clients/run.sh                        # every client whose tool is installed
tests/clients/run.sh aws boto3              # only these
CLIENTS_LAYOUT=folder tests/clients/run.sh  # buckets are folder buckets (default: object)
CLIENTS_REQUIRE=1 tests/clients/run.sh      # a missing tool fails instead of skipping
```

boto3, the JavaScript SDK and the Go SDK are installed into `target/clients` at the
versions pinned here (`boto3/requirements.txt`, `js/package-lock.json`, `go/go.mod`).
Each client's output is in `target/clients/<client>.log`.

CI runs the AWS CLI, boto3 and JavaScript on every change, and every client on both
layouts nightly (`install-ci.sh` installs rclone, restic, Kopia and Terraform at pinned versions,
checked against their published checksums). A failing night opens or updates an issue.
