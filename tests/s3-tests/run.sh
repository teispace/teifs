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
WORK="${S3TESTS_WORK:-$ROOT/target/s3-tests}"
# The ceph/s3-tests commit the lists are written against. Moving it is a change of its
# own: run with --update, look at every new failure, and commit the lists with it.
COMMIT=5522d1c351f75bc00ae0f64f742f3f095f5939d9
ACCESS_KEY=TFS3TESTSACCESSKEY01
SECRET_KEY=s3-tests-only-secret-key-not-a-real-one-01
PORT="${S3TESTS_PORT:-9312}"
LAYOUT="${S3TESTS_LAYOUT:-object}"

mkdir -p "$WORK"

checkout() {
  git -C "$WORK/src" fetch --quiet origin "$COMMIT" 2>/dev/null || true
  git -C "$WORK/src" checkout --quiet --force "$COMMIT"
}
if [ ! -d "$WORK/src/.git" ] || ! checkout 2>/dev/null; then
  # Missing, or damaged (a restored cache): clone again.
  rm -rf "$WORK/src"
  git clone --quiet https://github.com/ceph/s3-tests "$WORK/src"
  checkout
fi

if [ ! -x "$WORK/venv/bin/python" ]; then
  python3 -m venv "$WORK/venv"
fi
"$WORK/venv/bin/pip" install --quiet --requirement "$HERE/requirements.txt"

cargo build --quiet --release --locked -p teifs --manifest-path "$ROOT/Cargo.toml"

rm -rf "$WORK/drive" "$WORK/keyring.json"
mkdir -p "$WORK/drive"
# The KMS keys the suite's SSE-KMS tests name (its defaults).
for key in testkey-1 testkey-2; do
  "$ROOT/target/release/teifs" key create "$key" --kms-keyring "$WORK/keyring.json" > /dev/null
done
# The suite predates AWS's 2023 and 2026 defaults: its buckets take public ACLs and
# SSE-C keys, as S3's did before, and it signs forms and some requests with Signature V2.
TEIFS_ACCESS_KEY="$ACCESS_KEY" TEIFS_SECRET_KEY="$SECRET_KEY" TEIFS_LOG=warn \
  TEIFS_DEFAULT_LAYOUT="$LAYOUT" TEIFS_KMS_KEYRING="$WORK/keyring.json" \
  TEIFS_ALLOW_SSE_C=true TEIFS_LEGACY_BUCKET_DEFAULTS=true TEIFS_ALLOW_SIGV2=true \
  "$ROOT/target/release/teifs" serve "$WORK/drive" --listen "127.0.0.1:$PORT" \
  > "$WORK/server.log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
for _ in $(seq 100); do
  curl --silent --output /dev/null "http://127.0.0.1:$PORT" && break
  sleep 0.1
done

S3TESTS_PORT="$PORT" S3TESTS_ACCESS_KEY="$ACCESS_KEY" S3TESTS_SECRET_KEY="$SECRET_KEY" \
  "$WORK/venv/bin/python" "$HERE/users.py" "$HERE/s3tests.conf.in" "$WORK/s3tests.conf"

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
