# S3 compatibility tests

TeiFS runs [ceph/s3-tests](https://github.com/ceph/s3-tests), the most widely used S3
conformance suite, against a fresh server. Every test it runs is in exactly one list:

| List | Meaning |
|---|---|
| `implemented.txt` | Must pass. A failure here is a regression and fails the run |
| `unimplemented.txt` | Standard S3 behaviour TeiFS doesn't support yet |
| `excluded.txt` | Not a goal, each with the reason after `#` (another server's own behaviour) |
| `folder-excluded.txt` | Tests folder buckets can't pass by design (keys a folder can't hold); they must pass on object buckets |

[docs/COMPATIBILITY.md](../../docs/COMPATIBILITY.md) claims only what these lists prove.

## Running

You need Python 3 and `curl`; the script makes its own virtual environment.

```sh
tests/s3-tests/run.sh                          # everything, then compare with the lists
S3TESTS_K='multipart' tests/s3-tests/run.sh    # only tests whose name matches
S3TESTS_LAYOUT=folder tests/s3-tests/run.sh    # buckets are folder buckets (default: object)
tests/s3-tests/run.sh --update                 # also move newly passing tests to implemented.txt
```

It clones the suite at a pinned commit into `target/s3-tests/src` (`S3TESTS_WORK` moves
the whole work folder), builds `teifs`, serves
an empty drive on port 9312 (`S3TESTS_PORT` to change it), and writes the pytest output to
`target/s3-tests/pytest.log` and a JUnit report to `target/s3-tests/report.xml`.

## When you implement a feature

Run the tests for it, then `--update`: tests that now pass move from `unimplemented.txt`
to `implemented.txt`. Commit the lists with the feature, and update
`docs/COMPATIBILITY.md`. A test never moves back out of `implemented.txt` without a
reason in the pull request.

## One set of credentials

Until TeiFS has users, every user the suite knows (main, alt, tenant, IAM) uses the same
credentials. Tests that need a second user fail and stay in `unimplemented.txt`.
