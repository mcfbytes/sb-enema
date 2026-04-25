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
# EFI binary structure constants
#
# These named constants document the on-disk byte layout of the UEFI
# structures parsed and emitted by SB-ENEMA.  They replace bare integer
# offsets and hex literals scattered across stage.sh, enroll.sh, and
# efivar.sh.  Spec references are to the UEFI Specification 2.x (current at
# time of writing: 2.10) unless noted otherwise.
#
# All multi-byte integer fields are little-endian on disk.  Hex string
# constants below are therefore the *little-endian byte sequence* of the
# logical value, expressed as lowercase hex with no separators (the form
# produced by `od -An -tx1 | tr -d ' \n'` after a `dd` of the raw bytes).
# ---------------------------------------------------------------------------

# EFI_TIME (UEFI §8.3) — fixed 16-byte timestamp prefixed to every
# EFI_VARIABLE_AUTHENTICATION_2 descriptor.
readonly EFI_TIME_SIZE=16

# WIN_CERTIFICATE / WIN_CERTIFICATE_UEFI_GUID (UEFI §32.4.1) — the
# authentication header that follows EFI_TIME inside an
# EFI_VARIABLE_AUTHENTICATION_2 descriptor.  Offsets are relative to the
# start of the descriptor (i.e. the start of the file for an .auth payload).
#
#   offset 16 (= EFI_TIME_SIZE):                uint32 dwLength (LE)
#   offset 20:                                  uint16 wRevision (LE, == 0x0200)
#   offset 22:                                  uint16 wCertificateType
#                                               (LE, == 0x0EF1 =
#                                                WIN_CERT_TYPE_EFI_GUID)
#   offset 24:                                  EFI_GUID CertType (16 bytes)
#   offset 40:                                  variable-length CertData
readonly EFI_AUTH2_WINCERT_LEN_OFFSET=16
readonly EFI_AUTH2_WINCERT_REV_OFFSET=20
readonly EFI_AUTH2_WINCERT_TYPE_OFFSET=22
readonly EFI_AUTH2_WINCERT_GUID_OFFSET=24

# Size of the WIN_CERTIFICATE_UEFI_GUID fixed header (dwLength + wRevision +
# wCertificateType + CertType GUID).  This is the minimum legal value of
# dwLength for a well-formed descriptor.
readonly EFI_AUTH2_WINCERT_UEFI_GUID_HDR_SIZE=24

# Total size of the EFI_TIME + WIN_CERTIFICATE_UEFI_GUID fixed prefix; any
# valid EFI_VARIABLE_AUTHENTICATION_2 file must be at least this large.
# Derived from its components so it can never silently diverge if either
# component size is ever adjusted.
readonly EFI_AUTH2_FIXED_HEADER_SIZE=$((EFI_TIME_SIZE + EFI_AUTH2_WINCERT_UEFI_GUID_HDR_SIZE))

# wRevision == 0x0200 little-endian (UEFI §32.4.1).
readonly EFI_WIN_CERT_REVISION_LE_HEX="0002"

# wCertificateType == 0x0EF1 = WIN_CERT_TYPE_EFI_GUID, little-endian
# (UEFI §32.4.1).  This marks the WIN_CERTIFICATE as a
# WIN_CERTIFICATE_UEFI_GUID.
readonly EFI_AUTH2_WIN_CERT_TYPE_GUID_LE_HEX="f10e"

# EFI_CERT_TYPE_PKCS7_GUID (UEFI §32.2.4 / appendix "EFI System Table"):
#   {4aafd29d-68df-49ee-8aa9-347d375665a7}
# Stored on disk in mixed-endian EFI_GUID byte order (data1/data2/data3 are
# little-endian, data4 is big-endian byte array), giving the raw bytes:
#   9d d2 af 4a  df 68  ee 49  8a a9 34 7d 37 56 65 a7
readonly EFI_CERT_TYPE_PKCS7_GUID_LE_HEX="9dd2af4adf68ee498aa9347d375665a7"

# EFI_SIGNATURE_LIST (UEFI §32.4.1) — header layout.  All uint32 fields
# are little-endian.
#
#   offset  0: SignatureType GUID (16 bytes)
#   offset 16: SignatureListSize  (uint32)
#   offset 20: SignatureHeaderSize (uint32)
#   offset 24: SignatureSize       (uint32)
#   offset 28: SignatureHeader     (SignatureHeaderSize bytes)
#   offset 28+SHS: N * SignatureSize bytes of EFI_SIGNATURE_DATA entries
readonly EFI_SIGLIST_LIST_SIZE_OFFSET=16
readonly EFI_SIGLIST_HDR_SIZE_OFFSET=20
readonly EFI_SIGLIST_SIG_SIZE_OFFSET=24
readonly EFI_SIGNATURE_LIST_HEADER_SIZE=28

# EFI_SIGNATURE_DATA (UEFI §32.4.1) — each entry begins with a 16-byte
# SignatureOwner GUID followed by SignatureSize-16 bytes of payload (a DER
# certificate for X.509 entries).
readonly EFI_SIGNATURE_OWNER_GUID_SIZE=16

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

# ---------------------------------------------------------------------------
# _fp_normalize <raw_fingerprint_string>
#   Normalize a SHA-1/SHA-256 fingerprint string into canonical form:
#   strip everything up to and including the last '=' (drops the
#   "SHA256 Fingerprint=" / "sha1 Fingerprint=" prefix produced by
#   `openssl x509 ... -fingerprint`), remove colon separators, and
#   lowercase the result.  Trailing whitespace is also stripped.
#
#   This is the single canonical normalization used for fingerprint
#   comparison across the codebase; previously the pipeline
#     sed 's/.*Fingerprint=//;s/://g' | tr '[:upper:]' '[:lower:]'
#   was duplicated (with minor variants) at many call sites.
#
#   Input may be:
#     * the full openssl line, e.g. "SHA256 Fingerprint=AA:BB:..."
#     * a colon-separated hex fingerprint, e.g. "AA:BB:..."
#     * an already-normalized lowercase hex string (idempotent).
#
#   Usage:
#     fp=$(_fp_normalize "$(openssl x509 ... -fingerprint -sha256)")
#   or piped:
#     fp=$(openssl x509 ... -fingerprint -sha256 | _fp_normalize)
# ---------------------------------------------------------------------------
_fp_normalize() {
    local raw
    if [[ $# -gt 0 ]]; then
        raw="$1"
    else
        raw=$(cat)
    fi
    # Strip everything up to and including the last '=' (handles both
    # "SHA256 Fingerprint=..." and inputs that contain no '=' at all).
    raw="${raw##*=}"
    # Strip trailing whitespace/newline that openssl may emit.
    raw="${raw%%[[:space:]]*}"
    # Remove colon separators, lowercase.
    printf '%s' "${raw}" | tr -d ':' | tr '[:upper:]' '[:lower:]'
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
    # EFI_TIME (16) + WIN_CERTIFICATE_UEFI_GUID fixed header (24) = 40 bytes minimum.
    [[ "${fsize}" -ge ${EFI_AUTH2_FIXED_HEADER_SIZE} ]] || return 1
    # Read the 24-byte WIN_CERTIFICATE_UEFI_GUID header (offsets 16..39) in a
    # single dd call to minimize subshell churn and avoid races on slow I/O.
    local hdr
    hdr=$(dd if="${file}" bs=1 skip="${EFI_AUTH2_WINCERT_LEN_OFFSET}" \
                              count="${EFI_AUTH2_WINCERT_UEFI_GUID_HDR_SIZE}" 2>/dev/null \
            | od -An -tx1 -v | tr -d ' \n') || return 1
    [[ "${#hdr}" -eq $((EFI_AUTH2_WINCERT_UEFI_GUID_HDR_SIZE * 2)) ]] || return 1
    # Hex-string offsets within hdr are 2 chars/byte, relative to byte
    # EFI_AUTH2_WINCERT_LEN_OFFSET (=16) where dd started reading.
    local rev_hex_off=$(( (EFI_AUTH2_WINCERT_REV_OFFSET  - EFI_AUTH2_WINCERT_LEN_OFFSET) * 2 ))
    local type_hex_off=$(( (EFI_AUTH2_WINCERT_TYPE_OFFSET - EFI_AUTH2_WINCERT_LEN_OFFSET) * 2 ))
    local guid_hex_off=$(( (EFI_AUTH2_WINCERT_GUID_OFFSET - EFI_AUTH2_WINCERT_LEN_OFFSET) * 2 ))
    # wRevision == 0x0200 little-endian
    [[ "${hdr:${rev_hex_off}:4}" == "${EFI_WIN_CERT_REVISION_LE_HEX}" ]] || return 1
    # wCertificateType == WIN_CERT_TYPE_EFI_GUID (0x0EF1 LE)
    [[ "${hdr:${type_hex_off}:4}" == "${EFI_AUTH2_WIN_CERT_TYPE_GUID_LE_HEX}" ]] || return 1
    # CertType GUID == EFI_CERT_TYPE_PKCS7_GUID (raw mixed-endian form)
    [[ "${hdr:${guid_hex_off}:32}" == "${EFI_CERT_TYPE_PKCS7_GUID_LE_HEX}" ]] || return 1
    # dwLength (uint32 LE at bytes 16..19): must cover at least the
    # WIN_CERTIFICATE_UEFI_GUID fixed header and not extend past EOF.
    # hdr offsets 0..7 are the four little-endian bytes of dwLength (b0,b1,b2,b3);
    # reconstruct via shifts to keep the byte-order intent explicit.
    local dwlen
    dwlen=$(( (16#${hdr:6:2} << 24) | (16#${hdr:4:2} << 16) | \
              (16#${hdr:2:2} <<  8) |  16#${hdr:0:2} ))
    (( dwlen >= EFI_AUTH2_WINCERT_UEFI_GUID_HDR_SIZE )) || return 1
    (( EFI_AUTH2_WINCERT_LEN_OFFSET + dwlen <= fsize )) || return 1
    return 0
}
