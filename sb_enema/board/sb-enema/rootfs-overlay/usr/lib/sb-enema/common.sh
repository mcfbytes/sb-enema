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

# ---------------------------------------------------------------------------
# efivar_is_auth_file <file>
#   Returns 0 if <file> looks like a well-formed
#   EFI_VARIABLE_AUTHENTICATION_2 descriptor (UEFI 2.x §8.2.2); returns 1 if
#   it is anything else (raw EFI Signature List, DER certificate, junk, etc.).
#
#   File layout validated (UEFI 2.x):
#     offset  size   field                 expected
#     0       16     EFI_TIME TimeStamp    (any value; not validated here)
#     16      4      WIN_CERTIFICATE.dwLength (uint32 LE, must be >= 24 and
#                                          16 + dwLength must be <= file size)
#     20      2      WIN_CERTIFICATE.wRevision   == 0x0200 (little-endian
#                                                 bytes 00 02)
#     22      2      WIN_CERTIFICATE.wCertificateType == 0x0EF1 (LE bytes
#                                                       F1 0E,
#                                                       WIN_CERT_TYPE_EFI_GUID)
#     24      16     EFI_GUID CertType    == EFI_CERT_TYPE_PKCS7_GUID
#                                           (4aafd29d-68df-49ee-8aa9-347d375665a7
#                                            -> mixed-endian raw bytes
#                                              9dd2af4adf68ee498aa9347d375665a7)
#
#   Anything failing those checks is treated as a non-auth payload (a raw ESL
#   or unrelated file).  Unreadable files / I/O errors return 1 so that the
#   caller falls through to the raw-ESL path; the underlying tool
#   (efi-updatevar, sign-efi-sig-list, etc.) will surface any real I/O error
#   when it actually tries to use the file.
# ---------------------------------------------------------------------------
efivar_is_auth_file() {
    local file="$1"
    [[ -f "${file}" && -r "${file}" ]] || return 1
    local fsize
    fsize=$(wc -c < "${file}" 2>/dev/null || echo 0)
    # 16 (EFI_TIME) + 8 (WIN_CERTIFICATE) + 16 (CertType GUID) = 40 bytes minimum.
    [[ "${fsize}" -ge 40 ]] || return 1
    # Read the 24-byte WIN_CERTIFICATE_UEFI_GUID header (offsets 16..39) in a
    # single dd call to minimize subshell churn and avoid races on slow I/O.
    local hdr
    hdr=$(dd if="${file}" bs=1 skip=16 count=24 2>/dev/null | od -An -tx1 -v | tr -d ' \n') || return 1
    [[ "${#hdr}" -eq 48 ]] || return 1
    # wRevision (bytes 20..21, LE 0x0200)
    [[ "${hdr:8:4}" == "0002" ]] || return 1
    # wCertificateType (bytes 22..23, LE 0x0EF1, WIN_CERT_TYPE_EFI_GUID)
    [[ "${hdr:12:4}" == "f10e" ]] || return 1
    # CertType (bytes 24..39, EFI_CERT_TYPE_PKCS7_GUID raw little-endian form)
    [[ "${hdr:16:32}" == "9dd2af4adf68ee498aa9347d375665a7" ]] || return 1
    # dwLength (uint32 LE at bytes 16..19): must cover at least the
    # WIN_CERTIFICATE_UEFI_GUID header (24 bytes) and not exceed file size - 16.
    local dwlen
    dwlen=$(( 16#${hdr:6:2} * 16777216 + 16#${hdr:4:2} * 65536 + \
              16#${hdr:2:2} * 256     + 16#${hdr:0:2} ))
    (( dwlen >= 24 )) || return 1
    (( 16 + dwlen <= fsize )) || return 1
    return 0
}
