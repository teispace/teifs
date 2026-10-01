#!/bin/sh
# Before the package is removed (not upgraded): the server stopped. The drive stays.
set -e
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now teifs.service || true
        fi
        ;;
esac
