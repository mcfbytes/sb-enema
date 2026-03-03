#!/usr/bin/env bash
# mount.sh — Partition mount helpers for SB-ENEMA runtime scripts.
# Requires common.sh to be sourced first (provides DATA_MOUNT, DATA_LABEL,
# DATA_UUID, DATA_PART_TYPE_GUID, EFIVARS_DIR, and the log_* helpers from log.sh).
set -euo pipefail

# ---------------------------------------------------------------------------
# mount_efivars() — mount efivarfs at EFIVARS_DIR if it is not already
#   mounted.  efivarfs is required before any EFI variable can be read or
#   written.
# ---------------------------------------------------------------------------
mount_efivars() {
    if mountpoint -q "${EFIVARS_DIR}" 2>/dev/null; then
        log_info "efivarfs already mounted at ${EFIVARS_DIR}"
        return
    fi
    log_info "Mounting efivarfs at ${EFIVARS_DIR}"
    mkdir -p "${EFIVARS_DIR}"
    mount -t efivarfs efivarfs "${EFIVARS_DIR}" \
        || die "Failed to mount efivarfs at ${EFIVARS_DIR}"
    log_success "efivarfs mounted"
}

# ---------------------------------------------------------------------------
# _find_data_partition() — locate the FAT32 data partition block device.
#   Tries the filesystem UUID first (most reliable; uses blkid so it works
#   with devtmpfs+mdev where /dev/disk/by-uuid/ symlinks are not created),
#   then falls back to the disk label, and finally scans by partition type
#   GUID.  Prints the block device path on success; returns 1 on failure.
# ---------------------------------------------------------------------------
_find_data_partition() {
    # 0. Try filesystem UUID via blkid (deterministic, burned in at build time).
    #    DATA_UUID is the FAT volume serial formatted as UUID (BEEF-CAFE), not
    #    a GPT partition UUID (/dev/disk/by-partuuid/).  blkid scans directly
    #    so this works without udev/mdev creating /dev/disk/by-uuid/ symlinks.
    local dev
    dev=$(blkid -t UUID="${DATA_UUID}" -o device 2>/dev/null | head -n1)
    if [[ -n "${dev}" ]]; then
        echo "${dev}"
        return 0
    fi

    # 1. Try well-known label
    dev=$(blkid -t LABEL="${DATA_LABEL}" -o device 2>/dev/null | head -n1)
    if [[ -n "${dev}" ]]; then
        echo "${dev}"
        return 0
    fi

    # 2. Fall back to partition type GUID scan
    dev=$(blkid -t PART_ENTRY_TYPE="${DATA_PART_TYPE_GUID}" -o device 2>/dev/null | head -n1)
    if [[ -n "${dev}" ]]; then
        echo "${dev}"
        return 0
    fi

    return 1
}

# ---------------------------------------------------------------------------
# _wait_for_data_partition() — poll blkid until the data partition is
#   visible to the kernel or MOUNT_WAIT_TIMEOUT seconds have elapsed.
#   USB devices may take several seconds to enumerate; this prevents a
#   race condition where the mount is attempted before the device appears.
#   Returns 0 if the partition is found within the timeout, 1 otherwise.
# ---------------------------------------------------------------------------
MOUNT_WAIT_TIMEOUT="${MOUNT_WAIT_TIMEOUT:-15}"
_wait_for_data_partition() {
    local waited=0
    while [[ "${waited}" -lt "${MOUNT_WAIT_TIMEOUT}" ]]; do
        _find_data_partition >/dev/null 2>&1 && return 0
        log_info "Waiting for data partition to appear (${waited}/${MOUNT_WAIT_TIMEOUT}s)…"
        sleep 1
        waited=$(( waited + 1 ))
    done
    return 1
}

# ---------------------------------------------------------------------------
# mount_data_partition() — find and mount the FAT32 data partition at
#   DATA_MOUNT.  Idempotent: does nothing if already mounted.  Waits up to
#   MOUNT_WAIT_TIMEOUT seconds for the device to appear (USB enumeration).
# ---------------------------------------------------------------------------
mount_data_partition() {
    if mountpoint -q "${DATA_MOUNT}" 2>/dev/null; then
        log_info "Data partition already mounted at ${DATA_MOUNT}"
        return
    fi

    local dev
    if ! _wait_for_data_partition || ! dev=$(_find_data_partition); then
        die "Cannot locate data partition (label=${DATA_LABEL}) after ${MOUNT_WAIT_TIMEOUT}s. Is the SB-ENEMA USB inserted?"
    fi

    log_info "Mounting data partition ${dev} at ${DATA_MOUNT}"
    mkdir -p "${DATA_MOUNT}"
    mount -t auto "${dev}" "${DATA_MOUNT}" \
        || die "Failed to mount ${dev} at ${DATA_MOUNT}"
    log_success "Data partition mounted at ${DATA_MOUNT}"
}

# ---------------------------------------------------------------------------
# unmount_data_partition() — unmount the FAT32 data partition if it is
#   currently mounted.  Errors are logged but do not abort the script.
# ---------------------------------------------------------------------------
unmount_data_partition() {
    if ! mountpoint -q "${DATA_MOUNT}" 2>/dev/null; then
        log_info "Data partition is not mounted; nothing to do"
        return
    fi
    log_info "Unmounting data partition at ${DATA_MOUNT}"
    if umount "${DATA_MOUNT}"; then
        log_success "Data partition unmounted"
    else
        log_warn "Failed to unmount data partition at ${DATA_MOUNT}"
    fi
}
