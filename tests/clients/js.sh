# The AWS SDK for JavaScript v3 (Node.js), pinned by tests/clients/js/package-lock.json.
source "$HERE/lib.sh"
APP="$CLIENT_WORK/../js-app"
mkdir -p "$APP"
cp "$HERE/js/package.json" "$HERE/js/package-lock.json" "$HERE/js/check.mjs" "$APP/"
(cd "$APP" && npm ci --silent --no-audit --no-fund)
make_data
node "$APP/check.mjs"
