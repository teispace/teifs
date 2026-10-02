#!/usr/bin/env bash
# Benchmarks TeiFS and the servers it's compared with, each in Docker on the same network,
# limits and kind of volume, driven by warp (see README.md here).
#
#   tests/bench/run.sh                       every server, the quick cells
#   tests/bench/run.sh teifs rustfs          only these
#   BENCH_PROFILE=full tests/bench/run.sh    the full matrix (hours)
#
# Results land in target/bench/<time>/: one warp analysis per cell, the environment, and
# summary.md / summary.csv.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ALL=(teifs teifs-relaxed teifs-folder rustfs minio garage versity seaweedfs)

# The images compared, pinned. TeiFS is built from this checkout.
WARP=quay.io/minio/aistor/warp:v1.8.2
RUSTFS=rustfs/rustfs:1.0.0
MINIO=pgsty/minio:RELEASE.2026-08-04T00-00-00Z
GARAGE=dxflrs/garage:v2.4.1
VERSITY=versity/versitygw:v1.8.0
SEAWEEDFS=chrislusf/seaweedfs:4.48
BUSYBOX=busybox:1.37

if [ "${BENCH_PROFILE:-quick}" = full ]; then
  # RustFS's matrix, so the numbers compare with theirs.
  : "${BENCH_SIZES:=4KiB 100KiB 1MiB 4MiB 10MiB 32MiB}"
  : "${BENCH_CONCURRENCY:=1 8 16 32 64 128}"
  : "${BENCH_DURATION:=120s}"
  : "${BENCH_ROUNDS:=3}"
else
  : "${BENCH_SIZES:=4KiB 1MiB 10MiB}"
  : "${BENCH_CONCURRENCY:=1 16 64}"
  : "${BENCH_DURATION:=20s}"
  : "${BENCH_ROUNDS:=1}"
fi
OPS="${BENCH_OPS:-put get}"
CPUS="${BENCH_CPUS:-4}"
MEMORY="${BENCH_MEMORY:-4g}"
# How much a GET cell uploads first, at most (warp reads those objects back).
GET_BYTES="${BENCH_GET_BYTES:-$((2 * 1024 * 1024 * 1024))}"
WORK="${BENCH_WORK:-$ROOT/target/bench/$(date -u +%Y%m%dT%H%M%SZ)}"
NET=teifs-bench
BUCKET=warp-benchmark-bucket

# Benchmark-only keys, in the form every server takes (Garage's is the strictest).
ACCESS=GK0123456789abcdef01234567
SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

servers=("$@")
[ ${#servers[@]} -gt 0 ] || servers=("${ALL[@]}")
for server in "${servers[@]}"; do
  case " ${ALL[*]} " in
    *" $server "*) ;;
    *) echo "no server called $server (${ALL[*]})" >&2; exit 2 ;;
  esac
done

mkdir -p "$WORK"
docker network inspect "$NET" > /dev/null 2>&1 || docker network create "$NET" > /dev/null

# Bytes in a warp size: 4KiB, 10MiB, 1GiB.
bytes() {
  local n="${1%[KMG]iB}"
  case "$1" in
    *KiB) echo $((n * 1024)) ;;
    *MiB) echo $((n * 1024 * 1024)) ;;
    *GiB) echo $((n * 1024 * 1024 * 1024)) ;;
    *) echo "$1" ;;
  esac
}

# Starts `$1` in a fresh container with a fresh volume; prints its host:port.
start() {
  local name="bench-$1" volume="bench-$1-data"
  docker rm -f "$name" > /dev/null 2>&1 || true
  docker volume rm "$volume" > /dev/null 2>&1 || true
  local run=(docker run -d --name "$name" --network "$NET" --cpus "$CPUS" --memory "$MEMORY"
    -v "$volume:/data")
  case "$1" in
    teifs | teifs-relaxed | teifs-folder)
      local durability=strict layout=object
      [ "$1" = teifs-relaxed ] && durability=relaxed
      [ "$1" = teifs-folder ] && layout=folder
      "${run[@]}" -e TEIFS_ACCESS_KEY="$ACCESS" -e TEIFS_SECRET_KEY="$SECRET" \
        -e TEIFS_DURABILITY="$durability" -e TEIFS_DEFAULT_LAYOUT="$layout" \
        teifs-bench:local > /dev/null
      echo "$name:9000" ;;
    rustfs)
      "${run[@]}" -e RUSTFS_ACCESS_KEY="$ACCESS" -e RUSTFS_SECRET_KEY="$SECRET" \
        "$RUSTFS" /data > /dev/null
      echo "$name:9000" ;;
    minio)
      "${run[@]}" -e MINIO_ROOT_USER="$ACCESS" -e MINIO_ROOT_PASSWORD="$SECRET" \
        "$MINIO" server /data > /dev/null
      echo "$name:9000" ;;
    garage)
      "${run[@]}" -v "$HERE/garage.toml:/etc/garage.toml:ro" \
        -e GARAGE_DEFAULT_ACCESS_KEY="$ACCESS" -e GARAGE_DEFAULT_SECRET_KEY="$SECRET" \
        -e GARAGE_DEFAULT_BUCKET="$BUCKET" \
        "$GARAGE" /garage server --single-node --default-bucket > /dev/null
      echo "$name:3900" ;;
    versity)
      "${run[@]}" "$VERSITY" --access "$ACCESS" --secret "$SECRET" posix /data > /dev/null
      echo "$name:7070" ;;
    seaweedfs)
      sed -e "s/@ACCESS@/$ACCESS/" -e "s/@SECRET@/$SECRET/" "$HERE/seaweedfs.json" \
        > "$WORK/seaweedfs.json"
      "${run[@]}" -v "$WORK/seaweedfs.json:/etc/seaweedfs/s3.json:ro" \
        "$SEAWEEDFS" server -dir=/data -s3 -s3.config=/etc/seaweedfs/s3.json \
        -master.volumeSizeLimitMB=1024 > /dev/null
      echo "$name:8333" ;;
  esac
}

stop() {
  docker logs "bench-$1" > "$WORK/$1/server.log" 2>&1 || true
  docker rm -f "bench-$1" > /dev/null 2>&1 || true
  docker volume rm "bench-$1-data" > /dev/null 2>&1 || true
}

# Waits until server `$1`, at `$2` (host:port), takes connections.
wait_for() {
  for _ in $(seq 120); do
    [ "$(docker inspect --format '{{.State.Running}}' "bench-$1" 2> /dev/null)" = true ] || return 1
    docker run --rm --network "$NET" "$BUSYBOX" nc -z "${2%:*}" "${2#*:}" 2> /dev/null && {
      sleep 2
      return 0
    }
    sleep 1
  done
  return 1
}

warp() {
  docker run --rm --network "$NET" -v "$WORK:/out" -w /out "$WARP" "$@"
}

{
  echo "time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "teifs: $(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet || echo ' (changed)')"
  echo "host: $(uname -srm)"
  docker info --format 'docker: {{.ServerVersion}}, {{.NCPU}} CPUs, {{.MemTotal}} bytes, kernel {{.KernelVersion}}, {{.Driver}}'
  echo "limits: --cpus $CPUS --memory $MEMORY per server; warp unlimited"
  echo "cells: ops [$OPS] sizes [$BENCH_SIZES] concurrency [$BENCH_CONCURRENCY] $BENCH_DURATION x $BENCH_ROUNDS"
  for image in "$WARP" "$RUSTFS" "$MINIO" "$GARAGE" "$VERSITY" "$SEAWEEDFS"; do
    docker pull --quiet "$image" > /dev/null
    echo "image: $(docker image inspect --format '{{index .RepoDigests 0}}' "$image")"
  done
} | tee "$WORK/environment.txt"

case " ${servers[*]} " in
  *" teifs"*)
    docker build --quiet -f "$HERE/teifs.Dockerfile" -t teifs-bench:local "$ROOT" > /dev/null
    echo "image: teifs-bench:local $(docker image inspect --format '{{.Id}}' teifs-bench:local)" \
      | tee -a "$WORK/environment.txt" ;;
esac

trap 'status=$?; for s in "${servers[@]}"; do docker rm -f "bench-$s" > /dev/null 2>&1 || true; done; exit $status' EXIT

for server in "${servers[@]}"; do
  mkdir -p "$WORK/$server"
  host="$(start "$server")"
  if ! wait_for "$server" "$host"; then
    echo "✗ $server didn't start" >&2
    stop "$server"
    continue
  fi
  for op in $OPS; do
    for size in $BENCH_SIZES; do
      for concurrency in $BENCH_CONCURRENCY; do
        for round in $(seq "$BENCH_ROUNDS"); do
          cell="$server/$op-$size-c$concurrency-r$round"
          extra=()
          if [ "$op" = get ]; then
            objects=$((GET_BYTES / $(bytes "$size")))
            [ "$objects" -gt 2500 ] && objects=2500
            [ "$objects" -lt "$concurrency" ] && objects="$concurrency"
            extra=(--objects "$objects")
          fi
          echo "▶ $cell"
          if warp "$op" --no-color --host "$host" --access-key "$ACCESS" --secret-key "$SECRET" \
            --region us-east-1 --bucket "$BUCKET" --obj.size "$size" \
            --concurrent "$concurrency" --duration "$BENCH_DURATION" ${extra[@]+"${extra[@]}"} \
            --benchdata "/out/$cell" > "$WORK/$cell.txt" 2>&1; then
            warp analyze --json "/out/$cell.json.zst" > "$WORK/$cell.json" 2> /dev/null || true
          else
            echo "  ✗ failed: $(tail -1 "$WORK/$cell.txt")"
          fi
        done
      done
    done
  done
  stop "$server"
done

python3 "$HERE/summarize.py" "$WORK"
echo "Results: $WORK"
