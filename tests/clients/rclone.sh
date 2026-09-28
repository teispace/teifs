# rclone: copy, check, sync with deletes, server-side copy, multipart, purge.
source "$HERE/lib.sh"
make_data
export RCLONE_CONFIG_T_TYPE=s3 RCLONE_CONFIG_T_PROVIDER=Other
export RCLONE_CONFIG_T_ENDPOINT="$ENDPOINT" RCLONE_CONFIG_T_REGION=us-east-1
export RCLONE_CONFIG_T_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
export RCLONE_CONFIG_T_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
export RCLONE_CONFIG_T_FORCE_PATH_STYLE=true
# Multipart from 5 MiB, so big.bin goes in parts.
flags=(--config /dev/null --s3-upload-cutoff 5M --s3-chunk-size 5M)
rc() { rclone "${flags[@]}" "$@"; }

step "make a bucket, copy a tree and check it"
rc mkdir "t:$BUCKET"
rc copy tree "t:$BUCKET/tree"
rc check tree "t:$BUCKET/tree"

step "multipart upload, checked by downloading"
rc copyto big.bin "t:$BUCKET/big.bin"
rc check --download . "t:$BUCKET" --include big.bin

step "server-side copy"
rc copyto "t:$BUCKET/big.bin" "t:$BUCKET/copy.bin"
rc copyto "t:$BUCKET/copy.bin" copy.back
cmp big.bin copy.back

step "sync deletes what's gone locally"
rm tree/a/f1.bin
rc sync tree "t:$BUCKET/tree"
rc check tree "t:$BUCKET/tree"
[ -z "$(rc lsf "t:$BUCKET/tree/a" --include f1.bin)" ] || { echo "f1.bin survived the sync"; exit 1; }

step "purge"
rc purge "t:$BUCKET"
