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
restic forget --keep-last 1 --prune
[ "$(restic snapshots --json | grep -o '"id"' | wc -l)" -eq 1 ]
restic check

step "restore"
restic restore latest --target restored
same_tree tree restored/tree
cmp big.bin restored/big.bin
