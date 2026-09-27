"""Compares an s3-tests JUnit report with TeiFS's lists.

Fails when a test in implemented.txt didn't pass, or when a test the report ran is in
no list. With --update, moves tests that now pass from unimplemented.txt to
implemented.txt (never the other way: a regression needs a person to look at it).
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).parent


def read_list(name):
    """Test names in a list file; `#` starts a comment (the reason, for exclusions)."""
    names = set()
    for line in (HERE / name).read_text().splitlines():
        name_part = line.split("#", 1)[0].strip()
        if name_part:
            names.add(name_part)
    return names


def results(report):
    """Test name → passed, from a JUnit XML report."""
    out = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        name = case.get("name")
        failed = any(child.tag in ("failure", "error", "skipped") for child in case)
        out[name] = out.get(name, True) and not failed
    return out


def write_list(name, header, names):
    lines = [line for line in (HERE / name).read_text().splitlines() if line.startswith("#")]
    body = sorted(names)
    (HERE / name).write_text("\n".join(lines + body) + "\n")


def main():
    report = sys.argv[1]
    update = "--update" in sys.argv
    # A run filtered with -k checks only what it ran.
    partial = "--partial" in sys.argv
    folder = "--layout=folder" in sys.argv
    ran = results(report)
    implemented = read_list("implemented.txt")
    unimplemented = read_list("unimplemented.txt")
    excluded = read_list("excluded.txt")
    if folder:
        # Folder buckets skip what they can't hold by design; the rest must still pass.
        skipped = read_list("folder-excluded.txt")
        implemented -= skipped
        excluded |= skipped

    regressions = sorted(t for t in implemented if t in ran and not ran[t])
    missing = [] if partial else sorted(t for t in implemented if t not in ran)
    now_passing = sorted(t for t in unimplemented if ran.get(t))
    unknown = sorted(t for t in ran if t not in implemented | unimplemented | excluded)

    passed = sum(1 for ok in ran.values() if ok)
    print(f"s3-tests: {passed} of {len(ran)} passed; "
          f"lists: {len(implemented)} implemented, {len(unimplemented)} not yet, "
          f"{len(excluded)} excluded")
    for title, names in [
        ("Implemented tests that failed (regressions)", regressions),
        ("Implemented tests that didn't run", missing),
        ("Tests in no list (add them to one)", unknown),
        ("Now passing (move to implemented.txt, or run with --update)", now_passing),
    ]:
        if names:
            print(f"\n{title}:")
            for name in names:
                print(f"  {name}")

    if update and now_passing and not folder:
        write_list("implemented.txt", None, implemented | set(now_passing))
        write_list("unimplemented.txt", None, unimplemented - set(now_passing))
        print(f"\nMoved {len(now_passing)} tests to implemented.txt")

    return 1 if regressions or missing or unknown else 0


if __name__ == "__main__":
    sys.exit(main())
