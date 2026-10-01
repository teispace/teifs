#!/bin/sh
# After the package is installed or upgraded: the service's user, and systemd told.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/teifs.conf
elif ! getent passwd teifs >/dev/null; then
    useradd --system --user-group --home-dir /var/lib/teifs --no-create-home \
        --shell /usr/sbin/nologin --comment TeiFS teifs
fi
# Settings readable by the service, not by everyone (it may hold secrets).
chown root:teifs /etc/teifs /etc/teifs/teifs.env /etc/teifs/teifs.toml
chmod 0750 /etc/teifs
chmod 0640 /etc/teifs/teifs.env /etc/teifs/teifs.toml
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    # An upgrade restarts a running server; a new install waits to be started.
    systemctl try-restart teifs.service || true
fi
if [ "$1" = configure ] && [ -z "$2" ] || [ "$1" = 1 ]; then
    echo "TeiFS is installed. Start it with: sudo systemctl enable --now teifs"
    echo "Settings: /etc/teifs/teifs.toml; the drive: /var/lib/teifs/drive"
fi
