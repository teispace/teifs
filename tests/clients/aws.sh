# AWS CLI v2: buckets, single and multipart uploads, checksums, sync both ways,
# listings, presigned links, deletes.
source "$HERE/lib.sh"
make_data
s3() { aws --endpoint-url "$ENDPOINT" "$@"; }

step "make a bucket"
s3 s3 mb "s3://$BUCKET"

step "upload and download, single part and multipart"
s3 s3 cp small.txt "s3://$BUCKET/small.txt"
s3 s3 cp big.bin "s3://$BUCKET/big.bin"
s3 s3 cp "s3://$BUCKET/big.bin" big.back
cmp big.bin big.back

step "checksums sent, stored and returned"
s3 s3api put-object --bucket "$BUCKET" --key crc.txt --body small.txt \
  --checksum-algorithm CRC32C > /dev/null
s3 s3api head-object --bucket "$BUCKET" --key crc.txt --checksum-mode ENABLED \
  | grep -q ChecksumCRC32C

step "sync up, again (nothing to do), and down"
s3 s3 sync tree "s3://$BUCKET/tree/"
[ -z "$(s3 s3 sync tree "s3://$BUCKET/tree/")" ]
s3 s3 sync "s3://$BUCKET/tree/" tree.back
same_tree tree tree.back

step "list"
[ "$(s3 s3 ls --recursive "s3://$BUCKET/tree/" | wc -l)" -eq 7 ]

step "presigned link"
curl --silent --fail "$(s3 s3 presign "s3://$BUCKET/small.txt")" | cmp - small.txt

step "delete everything and the bucket"
s3 s3 rm --recursive "s3://$BUCKET"
s3 s3 rb "s3://$BUCKET"
