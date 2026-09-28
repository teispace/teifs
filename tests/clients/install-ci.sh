#!/usr/bin/env bash
# Installs the clients a Linux x86-64 CI runner lacks, at pinned versions, checking each
# download against the checksum its project publishes. (The AWS CLI comes with the
# runner; Go, Node.js and Python come from setup actions.)
set -euo pipefail

BIN="${1:-$HOME/.local/bin}"
mkdir -p "$BIN"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() { # url sha256 file
  curl --fail --silent --show-error --location --output "$tmp/$3" "$1"
  echo "$2  $tmp/$3" | sha256sum --check --quiet
}

fetch https://github.com/rclone/rclone/releases/download/v1.75.1/rclone-v1.75.1-linux-amd64.zip \
  982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab rclone.zip
unzip -q -j "$tmp/rclone.zip" '*/rclone' -d "$BIN"

fetch https://github.com/restic/restic/releases/download/v0.19.1/restic_0.19.1_linux_amd64.bz2 \
  f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c restic.bz2
bunzip2 --stdout "$tmp/restic.bz2" > "$BIN/restic"

fetch https://releases.hashicorp.com/terraform/1.16.4/terraform_1.16.4_linux_amd64.zip \
  dc94af0eef1147718ad7c8daea792ed199e3e0492eec180d0adafa2a65a879df terraform.zip
unzip -q "$tmp/terraform.zip" terraform -d "$BIN"

chmod +x "$BIN/rclone" "$BIN/restic" "$BIN/terraform"
"$BIN/rclone" version | head -1
"$BIN/restic" version
"$BIN/terraform" version | head -1
