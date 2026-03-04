#!/usr/bin/env bash
# /lib/mdev/mount-data.sh — called by mdev on block partition add/remove events.
#
# Environment variables set by mdev:
#   MDEV   — device name, e.g. "sda1" (node is at /dev/$MDEV)
#   ACTION — "add" or "remove"
#
# Only acts on the SB-ENEMA data partition, identified by FAT volume UUID
# BEEF-CAFE (volume serial 0xBEEFCAFE, set at build time via mkfs.fat -i BEEFCAFE).
# BusyBox blkid does not support -s/-o flags; its output is parsed with grep/cut.

set -euo pipefail

DATA_UUID="BEEF-CAFE"
MOUNT_POINT="/mnt/data"
DEV="/dev/${MDEV}"

case "${ACTION}" in
    add)
        # Read the UUID of the newly appeared device.  Retry up to 3 times with
        # a short delay: blkid can return empty output if called the instant the
        # device node appears, before the kernel finishes reading the partition.
        # blkid exits non-zero if the device has no recognisable filesystem —
        # ignore that silently.
        dev_uuid=""
        for _attempt in 1 2 3; do
            # BusyBox blkid takes no flags; output is: /dev/sdX: KEY="val" ...
            # Extract the UUID field with grep/cut.
            dev_uuid=$(blkid "${DEV}" 2>/dev/null \
                | grep -o 'UUID="[^"]*"' | cut -d'"' -f2 || true)
            [ -n "${dev_uuid}" ] && break
            sleep 1
        done
        if [ "${dev_uuid}" != "${DATA_UUID}" ]; then
            exit 0
        fi

        if mountpoint -q "${MOUNT_POINT}" 2>/dev/null; then
            # Already mounted (e.g. from a previous mdev pass); nothing to do.
            exit 0
        fi

        mkdir -p "${MOUNT_POINT}"
        if mount "${DEV}" "${MOUNT_POINT}"; then
            echo "mdev: mounted ${DEV} on ${MOUNT_POINT}"
        else
            echo "mdev: WARNING — mount ${DEV} -> ${MOUNT_POINT} failed" >&2
        fi
        ;;

    remove)
        # Only unmount if this device is the one currently mounted there.
        if grep -q "^${DEV} " /proc/mounts 2>/dev/null; then
            umount "${MOUNT_POINT}" 2>/dev/null \
                && echo "mdev: unmounted ${MOUNT_POINT}" \
                || echo "mdev: WARNING — umount ${MOUNT_POINT} failed (busy?)" >&2
        fi
        ;;
esac
