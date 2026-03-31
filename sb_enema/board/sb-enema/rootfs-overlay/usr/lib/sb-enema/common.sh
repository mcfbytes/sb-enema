#!/usr/bin/env bash
# common.sh — Shared constants and environment setup for SB-ENEMA runtime scripts.
# Source this file from all SB-ENEMA lib and sbin scripts.
# shellcheck disable=SC2034  # Constants are used by scripts that source this file.
set -euo pipefail
[[ -n "${_SB_ENEMA_COMMON_SH:-}" ]] && return 0
readonly _SB_ENEMA_COMMON_SH=1

# ---------------------------------------------------------------------------
# Library directory — override via SB_ENEMA_LIB_DIR for local development.
# ---------------------------------------------------------------------------
SB_ENEMA_LIB_DIR="${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}"

# ---------------------------------------------------------------------------
# EFI variable paths
# ---------------------------------------------------------------------------
EFIVARS_DIR="${EFIVARS_DIR:-/sys/firmware/efi/efivars}"
EFIVARS_SETUP_MODE="${EFIVARS_DIR}/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"

# ---------------------------------------------------------------------------
# Mount points
# ---------------------------------------------------------------------------
DATA_MOUNT="${DATA_MOUNT:-/mnt/data}"
DATA_LABEL="SB-ENEMA"
# FAT filesystem UUID (volume serial) burned in at build time via
# `mformat -N BEEFCAFE`, yielding UUID BEEF-CAFE.  Used by blkid in
# _find_data_partition() for reliable, udev-independent UUID lookup.
# NOTE: /etc/fstab is populated with the build-time UUID and is not
# affected by overriding this variable.  DATA_UUID is env-overridable
# only for controlled local testing where you also mount the target
# partition manually or adjust /etc/fstab accordingly.
DATA_UUID="${DATA_UUID:-BEEF-CAFE}"
# Partition type GUID for the SB-ENEMA data partition (Microsoft Basic Data)
DATA_PART_TYPE_GUID="EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_BASE_DIR="${DATA_MOUNT}/sb-enema/logs"
# LOG_FILE is set by log_init() at runtime
LOG_FILE=""

# ---------------------------------------------------------------------------
# Color codes (used only when writing to a terminal)
# ---------------------------------------------------------------------------
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
DIM="\033[2m"
BOLD="\033[1m"
RESET="\033[0m"

# ANSI clear-screen + cursor-home sequence (VT100/ANSI compatible).
# Used by ui_capture_and_show and preview_display to clear the dialog
# chrome before writing color output directly to /dev/tty.
ANSI_CLEAR=$'\033[2J\033[H'

# ---------------------------------------------------------------------------
# die() — print an error message and exit nonzero.
#   Usage: die "Something went wrong"
# ---------------------------------------------------------------------------
die() {
    if [[ -t 2 ]]; then
        echo -e "${RED}FATAL: $*${RESET}" >&2
    else
        echo "FATAL: $*" >&2
    fi
    exit 1
}

# ---------------------------------------------------------------------------
# require_root() — abort if the script is not running as root.
# ---------------------------------------------------------------------------
require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This script must be run as root."
    fi
}

# ---------------------------------------------------------------------------
# require_setup_mode() — abort if the firmware is not in UEFI Setup Mode.
#   Reads the SetupMode EFI variable; a value of 0x01 means Setup Mode is
#   active and the PK can be written without authentication.
# ---------------------------------------------------------------------------
require_setup_mode() {
    if [[ ! -f "${EFIVARS_SETUP_MODE}" ]]; then
        die "SetupMode EFI variable not found. Is efivarfs mounted?"
    fi
    # The variable has a 4-byte attribute header followed by a 1-byte value.
    local raw
    raw=$(od -An -tx1 -j4 -N1 "${EFIVARS_SETUP_MODE}" | tr -d ' \n')
    if [[ "${raw}" != "01" ]]; then
        die "System is not in UEFI Setup Mode (SetupMode=${raw}). Enroll keys from firmware setup first."
    fi
}
