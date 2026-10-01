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
sudo -u teifs teifs alias set local http://127.0.0.1:9000 --drive /var/lib/teifs/drive >/dev/null
sudo -u teifs teifs mb local/packaged
systemctl reload teifs
systemctl is-active teifs

# How exposed it is, as systemd scores it (0 best, 10 worst).
score=$(systemd-analyze security teifs.service --no-pager | awk '/Overall exposure level/ {print $(NF-1)}')
echo "exposure: $score"
awk -v s="$score" 'BEGIN { exit !(s < 2.5) }'

systemctl stop teifs
dpkg -r teifs
! systemctl cat teifs.service >/dev/null 2>&1
# The drive stays, and so do the settings (until a purge).
test -d /var/lib/teifs/drive/packaged
test -f /etc/teifs/teifs.toml
dpkg --purge teifs
