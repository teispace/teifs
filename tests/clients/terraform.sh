# Terraform's S3 backend: state in a bucket, locked with a lock file written only if
# absent (use_lockfile), across two applies and a refresh.
source "$HERE/lib.sh"
cp "$HERE/terraform/main.tf" .
aws --endpoint-url "$ENDPOINT" s3 mb "s3://$BUCKET"
export TF_IN_AUTOMATION=1 TF_INPUT=0

step "init with the S3 backend"
printf 'bucket = "%s"\nendpoints = { s3 = "%s" }\n' "$BUCKET" "$ENDPOINT" > backend.hcl
terraform init -no-color -backend-config=backend.hcl

step "apply, and apply a change"
terraform apply -no-color -auto-approve -var generation=1
terraform apply -no-color -auto-approve -var generation=2
[ "$(terraform output -raw generation)" = 2 ]

step "the state is in the bucket and the lock is released"
aws --endpoint-url "$ENDPOINT" s3 ls "s3://$BUCKET/client-matrix/" > listing
grep -q 'terraform.tfstate$' listing
if grep -q tflock listing; then echo "the lock file was left behind"; exit 1; fi

step "a held lock stops a second apply"
printf '{"ID":"held-by-test"}' | aws --endpoint-url "$ENDPOINT" s3 cp - \
  "s3://$BUCKET/client-matrix/terraform.tfstate.tflock"
if terraform apply -no-color -auto-approve -lock-timeout=1s -var generation=3; then
  echo "applied while another run held the lock"
  exit 1
fi
aws --endpoint-url "$ENDPOINT" s3 rm "s3://$BUCKET/client-matrix/terraform.tfstate.tflock"
terraform apply -no-color -auto-approve -var generation=3
