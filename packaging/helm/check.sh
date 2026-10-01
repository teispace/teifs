#!/usr/bin/env bash
# Lints the chart and renders it with its defaults and with every option on, checking
# what it must always say. Uses helm from PATH, or downloads the pinned release and
# checks its SHA-256 first (linux-amd64). Run from the repository's root.
set -euo pipefail

HELM_VERSION=4.3.0
HELM_SHA256=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb
chart=packaging/helm/teifs

helm=$(command -v helm || true)
if [ -z "$helm" ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    file=helm-v${HELM_VERSION}-linux-amd64.tar.gz
    curl -fsSL -o "$work/$file" "https://get.helm.sh/$file"
    echo "$HELM_SHA256  $work/$file" | sha256sum --check --strict --quiet
    tar -xzf "$work/$file" -C "$work" linux-amd64/helm
    helm=$work/linux-amd64/helm
fi

# The chart's version is TeiFS's.
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
grep -qx "version: $version" "$chart/Chart.yaml"
grep -qx "appVersion: \"$version\"" "$chart/Chart.yaml"

"$helm" lint --strict "$chart"
"$helm" lint --strict "$chart" -f "$chart/ci/full-values.yaml"

defaults=$("$helm" template t "$chart")
full=$("$helm" template t "$chart" -f "$chart/ci/full-values.yaml")
has() { grep -qF -- "$2" <<< "$1" || { echo "missing: $2" >&2; exit 1; }; }
lacks() { if grep -qF -- "$2" <<< "$1"; then echo "unexpected: $2" >&2; exit 1; fi; }

has "$defaults" "image: \"ghcr.io/teispace/teifs:$version\""
has "$defaults" "kind: Secret"
has "$defaults" "readOnlyRootFilesystem: true"
has "$defaults" "runAsNonRoot: true"
has "$defaults" "path: /minio/health/ready"
has "$defaults" "name: TEIFS_SECRET_KEY_FILE"
# The secret is a file, never a variable.
if grep -qE 'name: TEIFS_SECRET_KEY$' <<< "$defaults"; then echo "secret in env" >&2; exit 1; fi
lacks "$defaults" "kind: Ingress"
lacks "$defaults" "kind: ServiceMonitor"
lacks "$defaults" "TEIFS_CONFIG"

lacks "$full" "kind: Secret"
has "$full" "name: teifs-keys"
has "$full" "default-layout = \"folder\""
has "$full" "name: TEIFS_CONFIG"
has "$full" "name: TEIFS_CERTS_DIR"
has "$full" "scheme: HTTPS"
has "$full" "claimName: teifs-drive"
has "$full" "storageClassName: fast"
has "$full" "kind: Ingress"
has "$full" "kind: ServiceMonitor"
# The ServiceMonitor without its token's Secret is refused.
if "$helm" template t "$chart" --set metrics.serviceMonitor.enabled=true >/dev/null 2>&1; then
    echo "a ServiceMonitor without a token was rendered" >&2; exit 1
fi
echo "chart: ok"
