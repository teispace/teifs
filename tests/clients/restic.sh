# restic: a repository in a bucket; backup, deduplicated backup, check with data,
# forget and prune, restore.
source "$HERE/lib.sh"
make_data
export RESTIC_REPOSITORY="s3:$ENDPOINT/$BUCKET" RESTIC_PASSWORD=client-matrix-only
export RESTIC_CACHE_DIR="$CLIENT_WORK/cache"

step "init and back up twice"
restic init
restic backup --quiet tree
restic backup --quiet tree big.bin
[ "$(restic snapshots --json | grep -o '"id"' | wc -l)" -eq 2 ]

step "check every byte"
restic check --read-data

step "forget and prune"
# Both snapshots in one group, whatever paths they hold.
restic forget --keep-last 1 --group-by host --prune
[ "$(restic snapshots --json | grep -o '"id"' | wc -l)" -eq 1 ]
restic check

step "restore"
restic restore latest --target restored
same_tree tree restored/tree
cmp big.bin restored/big.bin

# The same in a bucket with Object Lock, as restic's docs suggest for backups nothing
# can erase: every object kept a day under governance retention. Pruning still works
# (a delete only adds a delete marker), and what it pruned is still there.
LOCKED="$BUCKET-locked"
s3api() { aws --endpoint-url "$ENDPOINT" s3api "$@"; }

step "a bucket with Object Lock"
s3api create-bucket --bucket "$LOCKED" --object-lock-enabled-for-bucket > /dev/null
s3api put-object-lock-configuration --bucket "$LOCKED" --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":1}}}'
export RESTIC_REPOSITORY="s3:$ENDPOINT/$LOCKED"
restic init
restic backup --quiet tree
restic backup --quiet tree big.bin
restic check --read-data

step "forget and prune under Object Lock"
restic forget --keep-last 1 --group-by host --prune
restic check --read-data
restic restore latest --target restored-locked
same_tree tree restored-locked/tree

step "what was pruned is still kept, and can't be removed"
markers=$(s3api list-object-versions --bucket "$LOCKED" --query 'length(DeleteMarkers)')
[ "$markers" -gt 0 ]
read -r key version < <(s3api list-object-versions --bucket "$LOCKED" \
  --query 'Versions[?IsLatest==`false`] | [0].[Key,VersionId]' --output text)
[ -n "$version" ] && [ "$version" != None ]
if s3api delete-object --bucket "$LOCKED" --key "$key" --version-id "$version" 2> denied.txt; then
  echo "a locked version was removed" >&2
  exit 1
fi
grep -q AccessDenied denied.txt
