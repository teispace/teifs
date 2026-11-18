#!/usr/bin/env python3
"""Writes the published benchmark page from a run of tests/bench/run.sh:

    tests/bench/publish.py target/bench/<time> docs/BENCHMARKS.md

The page says what ran where and how (versions, image digests, the machine, the exact
command), then a table per operation and size, as summarize.py makes them. The
Benchmarks workflow (.github/workflows/bench.yml) runs both and uploads the page.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import summarize  # noqa: E402

SERVERS = {
    "teifs": "TeiFS, object buckets (encrypted with SSE-S3), `--durability strict`: every write synced before it's acknowledged",
    "teifs-relaxed": "TeiFS, object buckets, `--durability relaxed`: file data synced; the last moments' writes may be lost on a power cut",
    "teifs-folder": "TeiFS, folder buckets: plain files, not encrypted",
    "rustfs": "RustFS, one drive",
    "minio": "MinIO, the pgsty community build of the last open-source release, one drive",
    "garage": "Garage, `--single-node`, LMDB",
    "versity": "Versity Gateway, POSIX backend",
    "seaweedfs": "SeaweedFS, `weed server -s3`",
}


def environment(work):
    path = work / "environment.txt"
    return path.read_text().rstrip().splitlines() if path.exists() else []


def field(lines, name):
    return next((l.split(": ", 1)[1] for l in lines if l.startswith(name + ": ")), "")


def main():
    work, out = Path(sys.argv[1]), Path(sys.argv[2])
    env = environment(work)
    cells = summarize.collect(work)
    found = {s for by in cells.values() for s in by}
    servers = [s for s in SERVERS if s in found] + sorted(found - SERVERS.keys())
    order = sorted(cells, key=lambda k: (k[0], summarize.size_bytes(k[1]), k[2]))
    run_url = ""
    if os.environ.get("GITHUB_RUN_ID"):
        run_url = "{}/{}/actions/runs/{}".format(
            os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ["GITHUB_RUN_ID"],
        )
    command = os.environ.get("BENCH_COMMAND", "tests/bench/run.sh")

    lines = [
        "# Benchmarks",
        "",
        "TeiFS and other single-node S3 servers, measured the same way by",
        "[warp](https://github.com/minio/warp): each server in Docker on one network, with the",
        "same CPU and memory limits and a fresh volume, one after another on the same machine.",
        "This page is generated (`tests/bench/publish.py`) from a run of the Benchmarks",
        "workflow (`.github/workflows/bench.yml`); `tests/bench/README.md` says how to run",
        "the same benchmarks yourself.",
        "",
        "## Read these numbers with care",
        "",
        "- The run is on a **shared GitHub Actions runner**: a virtual machine whose CPU, disk",
        "  and neighbours aren't ours and change from run to run. Compare servers within this",
        "  run, not this run with another, and not with numbers from other hardware.",
        "- warp runs on the same machine as the server, outside its limits, so on a small",
        "  runner the client competes with the server for CPU, most at high concurrency.",
        "- Each cell is short (see the cells below) and the disk is the runner's: a",
        "  production disk, a longer run or another kernel can order the servers differently.",
        "- The servers don't promise the same thing. `teifs` syncs every write to disk before",
        "  answering and encrypts objects at rest; servers that acknowledge before data is",
        "  on disk will look faster on writes. Each server runs with its defaults otherwise.",
        "- A blank cell (—) means warp measured nothing there: the server failed or refused",
        "  the workload; the run's artifact has its log.",
        "",
        "## What ran",
        "",
    ]
    if run_url:
        lines += [f"Run: <{run_url}> · commit `{field(env, 'teifs')}` · {field(env, 'time')}", ""]
    lines += ["| Server | What runs |", "|---|---|"]
    for server in servers:
        lines.append(f"| `{server}` | {SERVERS.get(server, '')} |")
    lines += [
        "",
        "Images (as pulled, with digests), the machine and the limits:",
        "",
        "```",
        *env,
        "```",
        "",
        "Command:",
        "",
        "```sh",
        command,
        "```",
        "",
        "Warp, MinIO and Garage are AGPL-licensed; they run here as unmodified container images,",
        "and no code of theirs is part of TeiFS.",
        "",
        "## Results",
        "",
        "Each cell: throughput (MiB/s, objects/s), then median / 99th percentile request time.",
    ]
    current = None
    for key in order:
        op, size, conc = key
        if (op, size) != current:
            current = (op, size)
            lines += [
                "",
                f"### {op.upper()} {size}",
                "",
                "| Concurrency | " + " | ".join(f"`{s}`" for s in servers) + " |",
                "|---" * (len(servers) + 1) + "|",
            ]
        row = [
            summarize.fmt(summarize.median_of(cells[key][s])) if s in cells[key] else "—"
            for s in servers
        ]
        lines.append(f"| {conc} | " + " | ".join(row) + " |")
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
