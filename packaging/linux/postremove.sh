#!/bin/sh
# After the package is removed: systemd told. /var/lib/teifs (the drive and its
# keyring) is kept; remove it yourself once it's no longer needed.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
