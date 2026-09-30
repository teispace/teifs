#!/usr/bin/env bash
# Runs real S3 clients against a fresh TeiFS server: each client's script in this folder
# does what people do with it (see README.md here).
#
#   tests/clients/run.sh                 every client whose tool is installed
#   tests/clients/run.sh aws rclone      only these
#   CLIENTS_REQUIRE=1 tests/clients/run.sh   a missing tool fails instead of skipping (CI)
#   CLIENTS_LAYOUT=folder tests/clients/run.sh   buckets are folder buckets (default: object)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="${CLIENTS_WORK:-$ROOT/target/clients}"
PORT="${CLIENTS_PORT:-9313}"
LAYOUT="${CLIENTS_LAYOUT:-object}"
ALL=(aws rclone restic kopia boto3 go js terraform)

# The tool each client needs.
tool() {
  case "$1" in
    boto3) echo python3 ;;
    js) echo npm ;;
    *) echo "$1" ;;
  esac
}

clients=("$@")
[ ${#clients[@]} -gt 0 ] || clients=("${ALL[@]}")
for client in "${clients[@]}"; do
  [ -f "$HERE/$client.sh" ] || { echo "no client called $client (${ALL[*]})" >&2; exit 2; }
done

cargo build --quiet --release --locked -p teifs --manifest-path "$ROOT/Cargo.toml"

rm -rf "$WORK/drive" "$WORK/keyring.json"
mkdir -p "$WORK/drive"
export AWS_ACCESS_KEY_ID=TFCLIENTSACCESSKEY01
export AWS_SECRET_ACCESS_KEY=clients-only-secret-key-not-a-real-one-01
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
export ENDPOINT="http://127.0.0.1:$PORT"
# The machine's own AWS settings and profiles stay out of it.
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
unset AWS_PROFILE AWS_SESSION_TOKEN AWS_ENDPOINT_URL

TEIFS_ACCESS_KEY="$AWS_ACCESS_KEY_ID" TEIFS_SECRET_KEY="$AWS_SECRET_ACCESS_KEY" \
  TEIFS_LOG=warn TEIFS_DEFAULT_LAYOUT="$LAYOUT" TEIFS_KMS_KEYRING="$WORK/keyring.json" \
  "$ROOT/target/release/teifs" serve "$WORK/drive" --listen "127.0.0.1:$PORT" \
  > "$WORK/server.log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
for _ in $(seq 100); do
  curl --silent --output /dev/null "$ENDPOINT" && break
  sleep 0.1
done

passed=() failed=() skipped=()
for client in "${clients[@]}"; do
  if ! command -v "$(tool "$client")" > /dev/null; then
    if [ -n "${CLIENTS_REQUIRE:-}" ]; then
      echo "✗ $client: $(tool "$client") isn't installed"
      failed+=("$client")
    else
      echo "- $client: skipped ($(tool "$client") isn't installed)"
      skipped+=("$client")
    fi
    continue
  fi
  dir="$WORK/$client"
  rm -rf "$dir" && mkdir -p "$dir"
  started=$SECONDS
  if (cd "$dir" && CLIENT_WORK="$dir" BUCKET="client-$client" HERE="$HERE" \
      bash "$HERE/$client.sh") > "$WORK/$client.log" 2>&1; then
    echo "✓ $client ($((SECONDS - started)) s)"
    passed+=("$client")
  else
    echo "✗ $client: failed; last lines of $WORK/$client.log:"
    tail -n 20 "$WORK/$client.log" | sed 's/^/    /'
    failed+=("$client")
  fi
done

echo "clients: ${#passed[@]} passed, ${#failed[@]} failed, ${#skipped[@]} skipped (layout: $LAYOUT)"
[ ${#failed[@]} -eq 0 ]
