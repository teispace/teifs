#!/bin/sh
# The disk under the crash test's drive when it runs with TEIFS_CRASH_DISK (the nightly
# "Failing disk" job): a device-mapper device on a loop device, with ext4 on it.
#
#   failing-disk.sh setup FILE MOUNT   makes the device on FILE and mounts it at MOUNT
#   failing-disk.sh fail               from now on, every write to it fails with EIO
#   failing-disk.sh heal               unmounts it, makes it whole and mounts it again,
#                                      which throws away what the kernel had cached
#   failing-disk.sh teardown           unmounts and removes it
#
# Writes fail through dm-flakey's error_writes when the kernel has it, and through the
# error target (reads fail too) when it doesn't. Runs as root, through sudo if need be.
set -eu
[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"

name=teifs-failing
state=/run/$name

healthy() {
  echo "0 $size linear $loop 0"
}

case "$1" in
setup)
  truncate -s 4G "$2"
  loop=$(losetup -f --show "$2")
  size=$(blockdev --getsz "$loop")
  printf 'loop=%s\nsize=%s\nmount=%s\n' "$loop" "$size" "$3" > "$state"
  dmsetup create "$name" --table "$(healthy)"
  dmsetup mknodes "$name" # where no udev makes the node (a container)
  mkfs.ext4 -q "/dev/mapper/$name"
  mkdir -p "$3"
  mount "/dev/mapper/$name" "$3"
  chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$3"
  ;;
fail)
  . "$state"
  modprobe dm-flakey 2> /dev/null || true
  if dmsetup targets | grep -q '^flakey'; then
    # Up for no time, down for an hour, failing writes while down.
    table="0 $size flakey $loop 0 0 3600 1 error_writes"
  else
    table="0 $size error"
  fi
  # No flush and no freeze: the writes in flight meet the failing disk.
  dmsetup suspend --noflush --nolockfs "$name"
  dmsetup load "$name" --table "$table"
  dmsetup resume "$name"
  ;;
heal)
  . "$state"
  umount "$mount"
  dmsetup suspend "$name"
  dmsetup load "$name" --table "$(healthy)"
  dmsetup resume "$name"
  mount "/dev/mapper/$name" "$mount"
  ;;
teardown)
  . "$state"
  umount "$mount" || true
  dmsetup remove "$name" || true
  losetup -d "$loop" || true
  rm -f "$state"
  ;;
*)
  echo "usage: $0 setup FILE MOUNT | fail | heal | teardown" >&2
  exit 2
  ;;
esac
