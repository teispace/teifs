#!/usr/bin/env bash
# Runs ceph/s3-tests against a fresh TeiFS server and compares the results with the
# lists in this folder (see README.md here).
#
#   tests/s3-tests/run.sh             run and compare
#   tests/s3-tests/run.sh --update    also move newly passing tests to implemented.txt
#   S3TESTS_K='bucket_list' tests/s3-tests/run.sh   only tests matching a pytest -k filter
#   S3TESTS_LAYOUT=folder tests/s3-tests/run.sh     buckets the suite creates are folder buckets
#                                                  (default: object)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$ROOT/target/s3-tests"
# The ceph/s3-tests commit the lists are written against. Moving it is a change of its
# own: run with --update, look at every new failure, and commit the lists with it.
COMMIT=5522d1c351f75bc00ae0f64f742f3f095f5939d9
ACCESS_KEY=TFS3TESTSACCESSKEY01
SECRET_KEY=s3-tests-only-secret-key-not-a-real-one-01
PORT="${S3TESTS_PORT:-9312}"
LAYOUT="${S3TESTS_LAYOUT:-object}"

mkdir -p "$WORK"

if [ ! -d "$WORK/src/.git" ]; then
  git clone --quiet https://github.com/ceph/s3-tests "$WORK/src"
fi
git -C "$WORK/src" fetch --quiet origin "$COMMIT" 2>/dev/null || true
git -C "$WORK/src" checkout --quiet "$COMMIT"

if [ ! -x "$WORK/venv/bin/python" ]; then
  python3 -m venv "$WORK/venv"
fi
"$WORK/venv/bin/pip" install --quiet --requirement "$HERE/requirements.txt"

cargo build --quiet --release --locked -p teifs --manifest-path "$ROOT/Cargo.toml"

rm -rf "$WORK/drive"
mkdir -p "$WORK/drive"
TEIFS_ACCESS_KEY="$ACCESS_KEY" TEIFS_SECRET_KEY="$SECRET_KEY" TEIFS_LOG=warn \
  TEIFS_DEFAULT_LAYOUT="$LAYOUT" \
  "$ROOT/target/release/teifs" serve "$WORK/drive" --listen "127.0.0.1:$PORT" \
  > "$WORK/server.log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
for _ in $(seq 100); do
  curl --silent --output /dev/null "http://127.0.0.1:$PORT" && break
  sleep 0.1
done

sed -e "s/@PORT@/$PORT/" -e "s/@ACCESS_KEY@/$ACCESS_KEY/" -e "s/@SECRET_KEY@/$SECRET_KEY/" \
  "$HERE/s3tests.conf.in" > "$WORK/s3tests.conf"

# Tests marked fails_on_aws check another server's own behaviour, not S3's.
set +e
(
  cd "$WORK/src"
  S3TEST_CONF="$WORK/s3tests.conf" "$WORK/venv/bin/python" -m pytest \
    s3tests/functional/test_s3.py s3tests/functional/test_headers.py \
    -q -p no:cacheprovider --timeout 60 -m "not fails_on_aws" \
    ${S3TESTS_K:+-k "$S3TESTS_K"} \
    --junitxml "$WORK/report.xml" > "$WORK/pytest.log" 2>&1
)
set -e

"$WORK/venv/bin/python" "$HERE/compare.py" "$WORK/report.xml" "--layout=$LAYOUT" \
  ${S3TESTS_K:+--partial} "$@"
