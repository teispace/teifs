#!/usr/bin/env python3
"""Summarizes a benchmark run (tests/bench/run.sh): one table per operation and size,
a row per concurrency, a column per server, each cell the median of its rounds as
throughput (MiB/s and objects/s) and median / 99th percentile request time.

    tests/bench/summarize.py target/bench/<time>

Writes summary.md and summary.csv next to the results.
"""

import csv
import json
import re
import statistics
import sys
from pathlib import Path

CELL = re.compile(r"^(?P<op>[a-z]+)-(?P<size>\d+[KMG]iB)-c(?P<conc>\d+)-r(?P<round>\d+)\.json$")
UNITS = {"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}


def size_bytes(size):
    return int(size[:-3]) * UNITS[size[-3:]]


def measure(path, op):
    """Throughput and request times of one cell, or None when warp measured nothing."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    total = data.get("by_op_type", {}).get(op.upper())
    if not total:
        return None
    throughput = total["throughput"]
    seconds = throughput["measure_duration_millis"] / 1000
    if seconds <= 0:
        return None
    requests = [
        r["single_sized_requests"]
        for rs in total.get("requests_by_client", {}).values()
        for r in rs
        if "single_sized_requests" in r
    ]
    return {
        "mib_s": throughput["bytes"] / seconds / (1 << 20),
        "obj_s": throughput["objects"] / seconds,
        "p50_ms": statistics.median(r["dur_median_millis"] for r in requests) if requests else None,
        "p99_ms": statistics.median(r["dur_99_millis"] for r in requests) if requests else None,
        "errors": total.get("total_errors", 0),
    }


def collect(work):
    """{(op, size, concurrency): {server: [round measures]}}."""
    cells = {}
    for server_dir in sorted(p for p in work.iterdir() if p.is_dir()):
        for path in server_dir.glob("*.json"):
            m = CELL.match(path.name)
            if not m:
                continue
            measured = measure(path, m["op"])
            if measured is None:
                continue
            key = (m["op"], m["size"], int(m["conc"]))
            cells.setdefault(key, {}).setdefault(server_dir.name, []).append(measured)
    return cells


def median_of(rounds):
    out = {}
    for field in ("mib_s", "obj_s", "p50_ms", "p99_ms"):
        values = [r[field] for r in rounds if r[field] is not None]
        out[field] = statistics.median(values) if values else None
    out["errors"] = sum(r["errors"] for r in rounds)
    out["rounds"] = len(rounds)
    return out


def fmt(cell):
    if cell is None:
        return "—"
    text = f"{cell['mib_s']:.1f} MiB/s, {cell['obj_s']:.0f} obj/s"
    if cell["p50_ms"] is not None:
        text += f" ({cell['p50_ms']:.1f} / {cell['p99_ms']:.1f} ms)"
    if cell["errors"]:
        text += f" ⚠ {cell['errors']} errors"
    return text


def main():
    work = Path(sys.argv[1])
    cells = collect(work)
    servers = sorted({s for by in cells.values() for s in by})
    order = sorted(cells, key=lambda k: (k[0], size_bytes(k[1]), k[2]))

    with open(work / "summary.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["op", "size", "concurrency", "server", "rounds", "mib_s", "obj_s", "p50_ms", "p99_ms", "errors"])
        for key in order:
            for server in servers:
                if server in cells[key]:
                    c = median_of(cells[key][server])
                    writer.writerow([*key, server, c["rounds"], c["mib_s"], c["obj_s"], c["p50_ms"], c["p99_ms"], c["errors"]])

    lines = ["# Benchmark summary", ""]
    environment = work / "environment.txt"
    if environment.exists():
        lines += ["```", environment.read_text().rstrip(), "```", ""]
    lines += [
        "Each cell: median throughput of its rounds, then median / 99th percentile request time.",
        "",
    ]
    current = None
    for key in order:
        op, size, conc = key
        if (op, size) != current:
            current = (op, size)
            lines += ["", f"## {op.upper()} {size}", "", "| Concurrency | " + " | ".join(servers) + " |",
                      "|---" * (len(servers) + 1) + "|"]
        row = [fmt(median_of(cells[key][s])) if s in cells[key] else "—" for s in servers]
        lines.append(f"| {conc} | " + " | ".join(row) + " |")
    (work / "summary.md").write_text("\n".join(lines) + "\n")
    print((work / "summary.md").read_text())


if __name__ == "__main__":
    main()
