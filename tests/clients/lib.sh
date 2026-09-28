# Shared by the client scripts: test data and checks. Sourced, not run.
set -euo pipefail

# small.txt, big.bin (20 MiB: multipart for every client) and tree/, a folder with
# nested, Unicode and spaced names.
make_data() {
  printf 'hello from %s\n' "$BUCKET" > small.txt
  head -c 20971520 /dev/urandom > big.bin
  mkdir -p "tree/a/b" "tree/ünïcødé" "tree/with space"
  for i in 1 2 3; do head -c $((i * 1000)) /dev/urandom > "tree/a/f$i.bin"; done
  printf 'deep\n' > tree/a/b/deep.txt
  printf 'unicode\n' > "tree/ünïcødé/naïve café.txt"
  printf 'spaced\n' > "tree/with space/file name.txt"
  printf '' > tree/empty
}

# Fails unless the two folders hold the same files with the same bytes.
same_tree() {
  diff -r "$1" "$2"
}

step() {
  echo "== $*"
}
