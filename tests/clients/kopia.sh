# Kopia: a repository in a bucket with Object Lock, which Kopia keeps extending on its
# blobs (--retention-mode): snapshots, verification of every file, restore, and full
# maintenance under the lock.
source "$HERE/lib.sh"
make_data
s3api() { aws --endpoint-url "$ENDPOINT" s3api "$@"; }
export KOPIA_PASSWORD=client-matrix-only KOPIA_CHECK_FOR_UPDATES=false
kopia() {
  command kopia --config-file="$CLIENT_WORK/kopia.config" --log-dir="$CLIENT_WORK/logs" "$@"
}

step "a bucket with Object Lock"
s3api create-bucket --bucket "$BUCKET" --object-lock-enabled-for-bucket > /dev/null

step "create the repository with governance retention"
kopia repository create s3 --bucket="$BUCKET" --endpoint="${ENDPOINT#http://}" \
  --disable-tls --access-key="$AWS_ACCESS_KEY_ID" --secret-access-key="$AWS_SECRET_ACCESS_KEY" \
  --region="$AWS_REGION" --cache-directory="$CLIENT_WORK/cache" \
  --retention-mode=GOVERNANCE --retention-period=24h

step "Kopia's own check of the provider"
kopia repository validate-provider

step "snapshot twice and verify every file"
kopia snapshot create tree
kopia snapshot create tree big.bin
kopia snapshot verify --verify-files-percent=100

step "data blobs are locked"
# Pack blobs (p…) hold the data; Kopia writes its own configuration unlocked.
blob=$(s3api list-objects-v2 --bucket "$BUCKET" --prefix p --query 'Contents[0].Key' --output text)
[ "$(s3api get-object-retention --bucket "$BUCKET" --key "$blob" \
  --query 'Retention.Mode' --output text)" = GOVERNANCE ]

step "restore"
id=$(kopia snapshot list tree --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[-1]["id"])')
kopia snapshot restore "$id" restored
same_tree tree restored

step "full maintenance under the lock"
kopia maintenance run --full --safety=none
kopia snapshot verify --verify-files-percent=100
