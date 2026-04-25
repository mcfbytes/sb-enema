#!/usr/bin/env bash
# test-auth-detect.sh — Validate efivar_is_auth_file() against real
# EFI_VARIABLE_AUTHENTICATION_2 payloads from the upstream
# microsoft/secureboot_objects submodule and a battery of synthetic
# edge cases.
#
# Coverage:
#   1. Real signed PostSignedObjects/DBX/<arch>/DBXUpdate.bin payloads
#      (EFI_VARIABLE_AUTHENTICATION_2)         → must detect as auth.
#   2. Real signed PostSignedObjects/KEK/*/KEKUpdate_*.bin payloads
#      (EFI_VARIABLE_AUTHENTICATION_2)         → must detect as auth.
#   3. Real raw DER certificates from PreSignedObjects
#      (no EFI auth wrapper)                   → must NOT detect as auth.
#   4. The PreSignedObjects/DBX/dbx.empty marker (plain ASCII)
#                                               → must NOT detect as auth.
#   5. Synthetic edge cases:
#        - Empty file
#        - 23-byte file (just below previous heuristic threshold)
#        - 39-byte file (just below new 40-byte minimum)
#        - 40-byte file with valid header but truncated to header only
#        - Header with correct wCertificateType but wrong wRevision
#        - Header with correct wRevision/wCertificateType but bogus CertType
#          GUID — guards against false positives the old 2-byte heuristic
#          would have accepted.
#        - Header with valid GUID/revision/type but a dwLength that overruns
#          the file size.
#        - Header with valid GUID/revision/type and exactly-fitting dwLength.
#
# Requirements on the host:
#   - bash 4+
#   - dd, od, wc, head, printf (coreutils or BusyBox)
#
# Usage:
#   bash scripts/test-auth-detect.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SUBMODULE="${REPO_ROOT}/third_party/secureboot_objects"

export SB_ENEMA_LIB_DIR="${REPO_ROOT}/sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema"

# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/common.sh
source "${SB_ENEMA_LIB_DIR}/common.sh"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
skip() { echo "SKIP: $*"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

assert_auth() {
    local label="$1" file="$2"
    if efivar_is_auth_file "${file}"; then
        pass "${label}: detected as auth"
    else
        fail "${label}: expected auth, got non-auth (${file})"
    fi
}

assert_not_auth() {
    local label="$1" file="$2"
    if efivar_is_auth_file "${file}"; then
        fail "${label}: expected non-auth, got auth (${file})"
    else
        pass "${label}: correctly classified as non-auth"
    fi
}

echo "=== SB-ENEMA efivar_is_auth_file() detection test ==="
echo

# ---------------------------------------------------------------------------
# Real fixtures from third_party/secureboot_objects
# ---------------------------------------------------------------------------
if [[ ! -d "${SUBMODULE}/PostSignedObjects" ]]; then
    skip "secureboot_objects submodule not initialized; skipping real-fixture tests"
    skip "  run: git submodule update --init --recursive third_party/secureboot_objects"
else
    echo "--- Real signed DBXUpdate payloads (must detect as auth) ---"
    found_dbx=0
    while IFS= read -r -d '' f; do
        assert_auth "DBXUpdate.bin ($(basename "$(dirname "$f")"))" "$f"
        found_dbx=$((found_dbx + 1))
    done < <(find "${SUBMODULE}/PostSignedObjects/DBX" -type f -name "DBXUpdate.bin" -print0 2>/dev/null)
    [[ "${found_dbx}" -gt 0 ]] || fail "no DBXUpdate.bin fixtures found under PostSignedObjects/DBX"

    echo "--- Real signed KEKUpdate payloads (sample, must detect as auth) ---"
    found_kek=0
    # Sample up to 5 KEK update payloads — testing every vendor would be
    # noisy; the format is identical across all.
    while IFS= read -r -d '' f; do
        assert_auth "KEKUpdate ($(basename "$f"))" "$f"
        found_kek=$((found_kek + 1))
        [[ "${found_kek}" -ge 5 ]] && break
    done < <(find "${SUBMODULE}/PostSignedObjects/KEK" -type f -name "KEKUpdate_*.bin" -print0 2>/dev/null)
    [[ "${found_kek}" -gt 0 ]] || fail "no KEKUpdate_*.bin fixtures found under PostSignedObjects/KEK"

    echo "--- Real raw DER certificates (must NOT detect as auth) ---"
    found_der=0
    while IFS= read -r -d '' f; do
        assert_not_auth "DER cert ($(basename "$f"))" "$f"
        found_der=$((found_der + 1))
        [[ "${found_der}" -ge 5 ]] && break
    done < <(find "${SUBMODULE}/PreSignedObjects" -type f -name "*.der" -print0 2>/dev/null)
    [[ "${found_der}" -gt 0 ]] || fail "no .der fixtures found under PreSignedObjects"

    if [[ -f "${SUBMODULE}/PreSignedObjects/DBX/dbx.empty" ]]; then
        echo "--- dbx.empty marker file (must NOT detect as auth) ---"
        assert_not_auth "dbx.empty marker" "${SUBMODULE}/PreSignedObjects/DBX/dbx.empty"
    fi
fi

# ---------------------------------------------------------------------------
# Synthetic edge cases
# ---------------------------------------------------------------------------
echo
echo "--- Synthetic edge cases ---"

# Empty file
: > "${WORK}/empty.bin"
assert_not_auth "empty file" "${WORK}/empty.bin"

# 23-byte file — would have failed even the old heuristic
dd if=/dev/zero of="${WORK}/short23.bin" bs=1 count=23 2>/dev/null
assert_not_auth "23-byte file" "${WORK}/short23.bin"

# 39-byte file — passes the old 24-byte threshold but fails the new 40-byte one
# (and lacks a valid GUID anyway).
dd if=/dev/zero of="${WORK}/short39.bin" bs=1 count=39 2>/dev/null
# Place the F1 0E type marker at offsets 22-23 so the OLD heuristic would
# have wrongly classified this as auth; the new check rejects it.
printf '\xf1\x0e' | dd of="${WORK}/short39.bin" bs=1 seek=22 count=2 conv=notrunc 2>/dev/null
assert_not_auth "39-byte file with only the wCertificateType marker" "${WORK}/short39.bin"

# Helper: build a valid 40-byte EFI_VARIABLE_AUTHENTICATION_2 header.
# Args: out_file, dwlength_value, revision_le_hex (4 chars), certtype_le_hex
#       (4 chars), guid_le_hex (32 chars), tail_size
build_auth_header() {
    local out="$1" dwlen="$2" rev="$3" ctype="$4" guid="$5" tail="$6"
    # 16 bytes of zeroed EFI_TIME
    dd if=/dev/zero of="${out}" bs=1 count=16 2>/dev/null
    # dwLength (uint32 LE)
    local b0 b1 b2 b3
    b0=$(printf '%02x' $((  dwlen        & 0xff )))
    b1=$(printf '%02x' $(( (dwlen >>  8) & 0xff )))
    b2=$(printf '%02x' $(( (dwlen >> 16) & 0xff )))
    b3=$(printf '%02x' $(( (dwlen >> 24) & 0xff )))
    # Concatenate hex string and emit raw bytes via printf '\xNN'
    local hex="${b0}${b1}${b2}${b3}${rev}${ctype}${guid}"
    local i byte
    for (( i = 0; i < ${#hex}; i += 2 )); do
        byte="${hex:i:2}"
        printf '\\x%s' "${byte}"
    done | xargs -0 printf >> "${out}"
    if (( tail > 0 )); then
        dd if=/dev/zero bs=1 count="${tail}" 2>/dev/null >> "${out}"
    fi
}

# Valid GUID (PKCS7) in raw EFI_GUID byte order
GUID_PKCS7="9dd2af4adf68ee498aa9347d375665a7"
# Bogus GUID (the one the old 2-byte heuristic would not have caught)
GUID_BOGUS="00112233445566778899aabbccddeeff"

# Header with correct type+rev+GUID but file is exactly 40 bytes and dwLength
# claims 24 → 16+24=40 == fsize, so it's a well-formed (if minimal) auth file.
build_auth_header "${WORK}/min_valid.bin" 24 "0002" "f10e" "${GUID_PKCS7}" 0
assert_auth "minimal 40-byte well-formed auth header" "${WORK}/min_valid.bin"

# Wrong revision (0x0001 instead of 0x0200)
build_auth_header "${WORK}/bad_rev.bin" 24 "0100" "f10e" "${GUID_PKCS7}" 0
assert_not_auth "header with wrong wRevision (0x0001)" "${WORK}/bad_rev.bin"

# Wrong cert type (0x0EF0 instead of 0x0EF1)
build_auth_header "${WORK}/bad_ctype.bin" 24 "0002" "f00e" "${GUID_PKCS7}" 0
assert_not_auth "header with wrong wCertificateType" "${WORK}/bad_ctype.bin"

# Bogus CertType GUID — would fool the old 2-byte heuristic, must be rejected
build_auth_header "${WORK}/bad_guid.bin" 24 "0002" "f10e" "${GUID_BOGUS}" 0
assert_not_auth "header with non-PKCS7 CertType GUID" "${WORK}/bad_guid.bin"

# dwLength that overruns the file (claims 1024 but file is only 40 bytes)
build_auth_header "${WORK}/overrun.bin" 1024 "0002" "f10e" "${GUID_PKCS7}" 0
assert_not_auth "header with dwLength overrunning file size" "${WORK}/overrun.bin"

# dwLength too small (< 24, the WIN_CERTIFICATE_UEFI_GUID minimum)
build_auth_header "${WORK}/dwlen_small.bin" 23 "0002" "f10e" "${GUID_PKCS7}" 0
assert_not_auth "header with dwLength < 24" "${WORK}/dwlen_small.bin"

# Valid header with payload tail that fits within dwLength
build_auth_header "${WORK}/valid_with_tail.bin" 1024 "0002" "f10e" "${GUID_PKCS7}" 1000
assert_auth "valid header with 1000-byte signature tail" "${WORK}/valid_with_tail.bin"

# Non-existent file — must not crash, must return non-auth
assert_not_auth "non-existent file" "${WORK}/does-not-exist.bin"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed, ${SKIP_COUNT} skipped"
[[ "${FAIL_COUNT}" -eq 0 ]]
