#!/usr/bin/env bash
# Builds the fuzz targets and runs each for a while: fuzz/run.sh [SECONDS] [TARGET…]
# (60 seconds each, every target, by default). Needs nightly Rust and cargo-fuzz.
# Each target's corpus grows in fuzz/corpus/<target>, starting from fuzz/seeds/<target>;
# an input that crashes one is kept in fuzz/artifacts/<target>/ and the script fails at
# the end, after every target has had its turn.
set -euo pipefail
cd "$(dirname "$0")"

seconds="${1:-60}"
shift || true
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  mapfile -t targets < <(cargo +nightly fuzz list)
fi

# The workspace's lock file, so the targets build the dependencies the server does.
cp ../Cargo.lock Cargo.lock
cargo +nightly fuzz build -O

failed=()
for target in "${targets[@]}"; do
  mkdir -p "corpus/$target"
  args=(-max_total_time="$seconds" -rss_limit_mb=2048 -timeout=10 -print_final_stats=1)
  case "$target" in
    *_xml) args+=(-dict=xml.dict -max_len=65536) ;;
    manifest_csv|policy_json|config_kv) args+=(-max_len=65536) ;;
  esac
  echo "::group::$target (${seconds}s)"
  if ! cargo +nightly fuzz run -O "$target" "corpus/$target" "seeds/$target" -- "${args[@]}"; then
    failed+=("$target")
  fi
  echo "::endgroup::"
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "crashed: ${failed[*]} (inputs in fuzz/artifacts/)" >&2
  exit 1
fi
echo "every target ran ${seconds}s without a crash"
