#!/usr/bin/env bash
# Installs a .deb on this machine (a CI runner with systemd) and checks it: the user,
# the settings' owners, the service starting hardened and serving, and removal keeping
# the drive. Run as root: packaging/linux/test-deb.sh dist/teifs_X_amd64.deb
set -euo pipefail

deb=$1
dpkg -i "$deb"
getent passwd teifs
[ "$(stat -c '%U:%G %a' /etc/teifs/teifs.env)" = "root:teifs 640" ]
[ "$(stat -c '%U:%G %a' /etc/teifs)" = "root:teifs 750" ]
if systemctl is-enabled --quiet teifs; then echo "installing shouldn't enable it" >&2; exit 1; fi

# Type=notify: once started, it listens.
systemctl start teifs
systemctl is-active teifs
teifs health 127.0.0.1:9000
[ "$(stat -c '%U %a' /var/lib/teifs)" = "teifs 700" ]
test -f /var/lib/teifs/drive/.teifs/credentials.json
test -f /var/lib/teifs/keyring.json
# Its own keys make a bucket, and a reload keeps it serving.
XDG_CONFIG_HOME=$(mktemp -d)
export XDG_CONFIG_HOME
teifs alias set local http://127.0.0.1:9000 --drive /var/lib/teifs/drive >/dev/null
teifs mb --layout folder local/packaged
systemctl reload teifs
systemctl is-active teifs

# How exposed it is, as systemd scores it (0 best, 10 worst).
report=$(systemd-analyze security teifs.service --no-pager)
score=$(grep -o 'Overall exposure level for teifs.service: [0-9.]*' <<< "$report" | awk '{print $NF}')
echo "exposure: $score"
[ -n "$score" ] || { echo "$report"; exit 1; }
awk -v s="$score" 'BEGIN { exit !(s < 2.5) }'

systemctl stop teifs
dpkg -r teifs
if systemctl cat teifs.service >/dev/null 2>&1; then echo "the service is still there" >&2; exit 1; fi
# The drive stays, and so do the settings (until a purge).
test -d /var/lib/teifs/drive/packaged
test -f /etc/teifs/teifs.toml
dpkg --purge teifs
