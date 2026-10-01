#!/usr/bin/env bash
# Installs the chart on a kind cluster with the image `teifs:test` and checks it: it
# serves, keeps its objects (still decryptable) and keys through a pod restart and an
# upgrade, and `helm test` passes. Needs docker, kind, kubectl, helm and the AWS CLI.
# Run from the repository's root.
set -euo pipefail

chart=packaging/helm/teifs
cluster=teifs-chart
kind create cluster --name "$cluster" --wait 120s
trap 'kind delete cluster --name "$cluster"' EXIT
kind load docker-image teifs:test --name "$cluster"

install() {
    helm upgrade --install t "$chart" -f "$chart/ci/kind-values.yaml" --wait --timeout 5m
}
key() {
    kubectl get secret t-teifs -o "jsonpath={.data.$1}" | base64 -d
}
forward() {
    # After a pod is deleted, its StatefulSet makes it again a moment later.
    for _ in $(seq 60); do kubectl get pod t-teifs-0 >/dev/null 2>&1 && break; sleep 1; done
    kubectl wait --for=condition=Ready pod/t-teifs-0 --timeout 120s
    kubectl port-forward svc/t-teifs 9000:9000 >/dev/null &
    forwarded=$!
    for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:9000 && return; sleep 0.2; done
    echo "the port-forward didn't answer" >&2; return 1
}

install
helm test t --logs
AWS_ACCESS_KEY_ID=$(key accessKey)
AWS_SECRET_ACCESS_KEY=$(key secretKey)
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION=us-east-1 AWS_ENDPOINT_URL=http://127.0.0.1:9000

forward
echo kept > kept.txt
aws s3 mb s3://chart
aws s3 cp kept.txt s3://chart/kept.txt
kill "$forwarded"

# A new pod has the same drive, keyring and keys.
kubectl delete pod t-teifs-0 --wait
forward
[ "$(aws s3 cp s3://chart/kept.txt -)" = kept ]
kill "$forwarded"

# An upgrade keeps the generated keys.
install
[ "$(key secretKey)" = "$AWS_SECRET_ACCESS_KEY" ]
forward
[ "$(aws s3 cp s3://chart/kept.txt -)" = kept ]
kill "$forwarded"

# It runs as the chart's user.
[ "$(kubectl get pod t-teifs-0 -o 'jsonpath={.spec.securityContext.runAsUser}')" = 65532 ]
[ "$(kubectl exec t-teifs-0 -- /usr/local/bin/teifs -q health && echo ok)" = ok ]

# Uninstalling keeps the keys (and the volumes), so a reinstall opens the same drive.
helm uninstall t --wait
kubectl get secret t-teifs
install
forward
[ "$(aws s3 cp s3://chart/kept.txt -)" = kept ]
kill "$forwarded"
echo "kind: ok"
