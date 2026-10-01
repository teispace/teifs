#!/usr/bin/env bash
# Builds the .deb and .rpm packages of a teifs binary:
#   packaging/linux/build.sh VERSION ARCH BINARY OUTDIR
# ARCH is amd64 or arm64. Run from the repository's root. Uses nfpm from PATH, or
# downloads the pinned release and checks its SHA-256 first. The binary must run on
# this machine (it writes the shell completions) unless COMPLETIONS names a folder of
# them already.
set -euo pipefail

version=$1 arch=$2 binary=$3 out=$4
NFPM_VERSION=2.47.0
declare -A NFPM_SHA256=(
    [x86_64]=0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783
    [arm64]=1c0f5f2999b9a974bfb04fdb0cc3306096de530ac5dbb25d739cc5f5219c919c
)

case $arch in amd64|arm64) ;; *) echo "ARCH is amd64 or arm64, not $arch" >&2; exit 2 ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

nfpm=$(command -v nfpm || true)
if [ -z "$nfpm" ]; then
    host=$(uname -m)
    [ "$host" = aarch64 ] && host=arm64
    file="nfpm_${NFPM_VERSION}_Linux_${host}.tar.gz"
    curl -fsSL -o "$work/$file" \
        "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/$file"
    echo "${NFPM_SHA256[$host]}  $work/$file" | sha256sum --check --strict --quiet
    tar -xzf "$work/$file" -C "$work" nfpm
    nfpm=$work/nfpm
fi

completions=${COMPLETIONS:-}
if [ -z "$completions" ]; then
    completions=$work/completions
    mkdir -p "$completions"
    "$binary" completions bash > "$completions/teifs.bash"
    "$binary" completions zsh > "$completions/_teifs"
    "$binary" completions fish > "$completions/teifs.fish"
fi

mkdir -p "$out"
for packager in deb rpm; do
    VERSION=$version ARCH=$arch BINARY=$binary COMPLETIONS=$completions \
        "$nfpm" package --config packaging/linux/nfpm.yaml --packager "$packager" --target "$out"
done
ls -l "$out"
