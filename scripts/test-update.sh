#!/usr/bin/env bash
# test-update.sh — Run the SB-ENEMA update_compute delta engine in a local
# mock environment.
#
# This script exercises the update/preview functions that are called from
# custom_enroll, verifying:
#   1. efivar_is_empty pre-check skips efi-readvar for empty variables.
#   2. Binary ESL hash bundle (.bin) files in the payload directory are
#      represented as synthetic ADD entries in the delta output.
#   3. The preview correctly displays PK, KEK, db, and dbx for a full
#      custom-owner enrollment scenario.
#
# Requirements on the host:
#   - bash 4+
#   - openssl  (for certificate generation)
#   - jq       (for JSON parsing in preview)
#
# Usage:
#   bash scripts/test-update.sh
#
# shellcheck disable=SC2154  # ADD_* / REMOVE_* / KEEP_* arrays set by sourced update.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export SB_ENEMA_LIB_DIR="${REPO_ROOT}/sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema"
export CERTDB_DIR="${SB_ENEMA_LIB_DIR}/known-certs"

# ---------------------------------------------------------------------------
# Mock environment
# ---------------------------------------------------------------------------
MOCK_EFIVARS="$(mktemp -d)"
MOCK_DATA="$(mktemp -d)"
trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}"' EXIT

export EFIVARS_DIR="${MOCK_EFIVARS}"
export DATA_MOUNT="${MOCK_DATA}"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# ---------------------------------------------------------------------------
# Source libraries
# ---------------------------------------------------------------------------
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/common.sh
source "${SB_ENEMA_LIB_DIR}/common.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/log.sh
source "${SB_ENEMA_LIB_DIR}/log.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/efivar.sh
source "${SB_ENEMA_LIB_DIR}/efivar.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/certdb.sh
source "${SB_ENEMA_LIB_DIR}/certdb.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/update.sh
source "${SB_ENEMA_LIB_DIR}/update.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/preview.sh
source "${SB_ENEMA_LIB_DIR}/preview.sh"

log_init

echo "=== SB-ENEMA update_compute local test ==="
echo

# ---------------------------------------------------------------------------
# Test 1: efivar_is_empty pre-check — efivar_extract_certs on empty variable
#   should return 0 immediately without calling efi-readvar.
# ---------------------------------------------------------------------------
echo "--- Test 1: efivar_extract_certs skips empty variable ---"
tmpout="$(mktemp -d)"

# Shadow efi-readvar with a stub that always fails to prove the efivar_is_empty
# pre-check fires before efi-readvar is consulted.  This makes the test
# deterministic regardless of whether efi-readvar is installed on the host.
_stub_bin="$(mktemp -d)"
cat > "${_stub_bin}/efi-readvar" <<'STUB'
#!/usr/bin/env bash
echo "efi-readvar stub: should not be called" >&2
exit 1
STUB
chmod +x "${_stub_bin}/efi-readvar"
_saved_PATH="${PATH}"
export PATH="${_stub_bin}:${PATH}"

# PK not present → efivar_is_empty returns 0 (empty); stub must NOT be reached
rc=0
efivar_extract_certs PK "${tmpout}/certs" 2>/dev/null || rc=$?
if [[ "${rc}" -eq 0 ]]; then
    pass "efivar_extract_certs returned 0 for empty PK variable"
else
    fail "efivar_extract_certs returned ${rc} for empty PK variable (expected 0)"
fi

# Confirm no .der files were created
der_count=$(find "${tmpout}/certs" -name "*.der" 2>/dev/null | wc -l)
if [[ "${der_count}" -eq 0 ]]; then
    pass "No .der files created for empty PK variable"
else
    fail "Expected 0 .der files for empty PK, got ${der_count}"
fi

rm -rf "${tmpout}" "${_stub_bin}"
export PATH="${_saved_PATH}"
unset _stub_bin _saved_PATH

# ---------------------------------------------------------------------------
# Test 2: update_compute — Setup Mode (all variables empty)
#   PK/KEK/db staged as certs; dbx staged as binary ESL.
#   Expected: all staged items appear in ADD arrays; nothing in REMOVE/KEEP.
# ---------------------------------------------------------------------------
echo "--- Test 2: update_compute with staged certs and dbx binary ---"

# Generate a self-signed cert for PK and KEK staging
STAGED_DIR="${DATA_MOUNT}/sb-enema/payloads"
mkdir -p "${STAGED_DIR}/PK" "${STAGED_DIR}/KEK" "${STAGED_DIR}/db" "${STAGED_DIR}/dbx"

# PK cert
openssl req -new -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
    -subj "/CN=Test PK" -keyout /dev/null -out "${STAGED_DIR}/PK/PK.crt" \
    2>/dev/null

# KEK cert
openssl req -new -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
    -subj "/CN=Test KEK" -keyout /dev/null -out "${STAGED_DIR}/KEK/KEK.crt" \
    2>/dev/null

# db cert
openssl req -new -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
    -subj "/CN=Test DB cert" -keyout /dev/null -out "${STAGED_DIR}/db/db.crt" \
    2>/dev/null

# dbx binary ESL stub (16 zero bytes — simulates a hash bundle)
printf '\x00%.0s' {1..16} > "${STAGED_DIR}/dbx/dbx.bin"

# Run update_compute
update_compute "custom-owner"

# PK: expect 1 ADD, 0 REMOVE, 0 KEEP
if [[ "${#ADD_PK[@]}" -eq 1 ]]; then
    pass "ADD_PK has 1 entry (staged PK cert)"
else
    fail "ADD_PK has ${#ADD_PK[@]} entries (expected 1)"
fi
if [[ "${#REMOVE_PK[@]}" -eq 0 ]] && [[ "${#KEEP_PK[@]}" -eq 0 ]]; then
    pass "REMOVE_PK and KEEP_PK are empty (Setup Mode)"
else
    fail "Expected empty REMOVE_PK/KEEP_PK, got remove=${#REMOVE_PK[@]} keep=${#KEEP_PK[@]}"
fi

# KEK: expect 1 ADD
if [[ "${#ADD_KEK[@]}" -eq 1 ]]; then
    pass "ADD_KEK has 1 entry (staged KEK cert)"
else
    fail "ADD_KEK has ${#ADD_KEK[@]} entries (expected 1)"
fi

# db: expect 1 ADD
if [[ "${#ADD_db[@]}" -eq 1 ]]; then
    pass "ADD_db has 1 entry (staged db cert)"
else
    fail "ADD_db has ${#ADD_db[@]} entries (expected 1)"
fi

# dbx: expect 1 ADD (hash bundle synthetic entry)
if [[ "${#ADD_dbx[@]}" -eq 1 ]]; then
    pass "ADD_dbx has 1 entry (staged dbx hash bundle)"
else
    fail "ADD_dbx has ${#ADD_dbx[@]} entries (expected 1 hash bundle entry)"
fi

# Verify the dbx entry subject mentions "Hash bundle"
dbx_subj=$(printf '%s' "${ADD_dbx[0]}" | jq -r '.subject' 2>/dev/null) || dbx_subj=""
if [[ "${dbx_subj}" == "Hash bundle:"* ]]; then
    pass "ADD_dbx entry subject correctly identifies hash bundle: ${dbx_subj}"
else
    fail "ADD_dbx entry subject unexpected: '${dbx_subj}' (expected 'Hash bundle:...')"
fi

# ---------------------------------------------------------------------------
# Test 3: preview_display output contains dbx section
# ---------------------------------------------------------------------------
echo "--- Test 3: preview_display includes dbx section ---"
preview_out=$(preview_display 2>/dev/null)
if echo "${preview_out}" | grep -q "dbx"; then
    pass "preview_display output contains dbx section"
else
    fail "preview_display output missing dbx section"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi
