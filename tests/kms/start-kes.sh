#!/usr/bin/env bash
# Starts a KES server for the external KMS tests (crates/server/tests/external_kms.rs):
# a throwaway CA and server certificate, a new API key whose identity a policy allows to
# create, list and use keys, and a keystore in a folder. Writes TEIFS_TEST_KES_ENDPOINT,
# TEIFS_TEST_KES_CA and TEIFS_KMS_KES_API_KEY to $GITHUB_ENV (the key masked in the log)
# or, outside GitHub Actions, to the file given as the first argument.
set -euo pipefail

image=quay.io/minio/kes:2025-03-12T09-35-18Z
out=${GITHUB_ENV:-${1:?give a file for the settings}}
dir=$(mktemp -d)
mkdir -p "$dir/keys"
cd "$dir"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -keyout ca.key -out ca.pem -subj "/CN=TeiFS test CA" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' >server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile server.ext -out server.pem 2>/dev/null

docker run --rm "$image" identity new >identity.txt
api_key=$(grep -o 'kes:v1:[A-Za-z0-9+/=]*' identity.txt | head -1)
identity=$(grep -o '[0-9a-f]\{64\}' identity.txt | head -1)
rm identity.txt
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  echo "::add-mask::$api_key"
fi

cat >config.yml <<CONFIG
version: v1
address: 0.0.0.0:7373
admin:
  identity: disabled
tls:
  key: /cfg/server.key
  cert: /cfg/server.pem
policy:
  teifs:
    allow:
    - /v1/key/create/*
    - /v1/key/describe/*
    - /v1/key/list/*
    - /v1/key/encrypt/*
    - /v1/key/decrypt/*
    - /v1/key/generate/*
    identities:
    - $identity
keystore:
  fs:
    path: /cfg/keys
CONFIG
chmod -R a+rwX "$dir"
docker run -d --name teifs-kes -p 7373:7373 -v "$dir:/cfg" "$image" server --config /cfg/config.yml >/dev/null

for _ in $(seq 1 60); do
  if (exec 3<>/dev/tcp/127.0.0.1/7373) 2>/dev/null; then
    break
  fi
  sleep 1
done
(exec 3<>/dev/tcp/127.0.0.1/7373) 2>/dev/null || { docker logs teifs-kes; exit 1; }

{
  echo "TEIFS_TEST_KES_ENDPOINT=https://127.0.0.1:7373"
  echo "TEIFS_TEST_KES_CA=$dir/ca.pem"
  echo "TEIFS_KMS_KES_API_KEY=$api_key"
} >>"$out"
