# Benchmarks

TeiFS and the servers it's compared with, measured the same way: each in Docker on one
network, with the same CPU and memory limits and a fresh volume, driven by
[warp](https://github.com/minio/warp) (run as a container; it's AGPL and only ever used
as an outside tool). TeiFS is built from this checkout in Docker
(`teifs.Dockerfile`), so it runs on the same kernel and file system as the others.

| Server | What runs | Notes |
|---|---|---|
| `teifs` | This checkout, object buckets, `--durability strict` | The default: objects encrypted (SSE-S3) and every write synced before it's acknowledged |
| `teifs-relaxed` | The same, `--durability relaxed` | File data synced; the last moments' writes may be lost on a power cut |
| `teifs-folder` | The same, folder buckets | Plain files, not encrypted |
| `rustfs` | RustFS 1.0.0, one drive | |
| `minio` | MinIO (the pgsty community build), one drive | |
| `garage` | Garage v2.4.1, `--single-node`, LMDB | |
| `versity` | Versity Gateway v1.8.0, POSIX backend | |
| `seaweedfs` | SeaweedFS 4.48, `weed server -s3` | |

Every image is pinned in `run.sh`, and each run records the digests it used.

## Running

Needs Docker and Python 3.

```sh
tests/bench/run.sh                         # every server, the quick cells (about an hour)
tests/bench/run.sh teifs rustfs            # only these
BENCH_PROFILE=full tests/bench/run.sh      # the full matrix (many hours)
BENCH_OPS=put BENCH_SIZES=4KiB BENCH_CONCURRENCY=16 tests/bench/run.sh teifs teifs-relaxed
```

| Setting | Quick | Full |
|---|---|---|
| `BENCH_SIZES` | `4KiB 1MiB 10MiB` | `4KiB 100KiB 1MiB 4MiB 10MiB 32MiB` |
| `BENCH_CONCURRENCY` | `1 16 64` | `1 8 16 32 64 128` |
| `BENCH_DURATION` | `20s` | `120s` |
| `BENCH_ROUNDS` | `1` | `3` |

Also: `BENCH_OPS` (`put get`), `BENCH_CPUS` (`4`) and `BENCH_MEMORY` (`4g`) per server,
`BENCH_GET_BYTES` (how much a GET cell uploads first, 2 GiB at most), `BENCH_WORK`
(where results go) and `BENCH_TEIFS_IMAGE` (a TeiFS image to run instead of building
this checkout: tag a build, change the code, and compare the two).

## Results

`target/bench/<time>/` holds `environment.txt` (host, Docker, limits, image digests,
commit), each cell's warp output (`<server>/<op>-<size>-c<concurrency>-r<round>.txt`),
its data (`.json.zst`, for `warp analyze` or `warp cmp`) and analysis (`.json`), and
`summary.md` / `summary.csv` made by `summarize.py`: per operation and size, each server's
median throughput over the rounds and its median and 99th percentile request time.

Numbers depend on the machine more than on anything here. On macOS and Windows, Docker
runs in a virtual machine, so its disks and network aren't the host's: compare servers
within one run, not runs across machines.

## Millions of objects

`crates/store/examples/scale.rs` fills an object bucket with tiny objects through the
store (no server, no network) and times what grows with it: reopening the drive,
listings (first page, deep in, by prefix, rolled up by `/`, all of it), HEADs, deletes,
and the index's size. A drive left by an earlier run with the same count is reused.

```sh
cargo run --release -p teifs-store --example scale -- /tmp/scale 10000000
```

