# The AWS SDK for Go v2 and madmin-go, at the versions tests/clients/go/go.mod pins.
source "$HERE/lib.sh"
APP="$CLIENT_WORK/../go-app"
mkdir -p "$APP"
cp "$HERE/go/go.mod" "$HERE/go/main.go" "$APP/"
(cd "$APP" && go mod tidy && go build -o client .)
make_data
"$APP/client"
