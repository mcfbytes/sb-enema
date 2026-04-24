#!/usr/bin/env bash
# test-safety.sh — Test safety_check_payload_integrity() in a local mock
# environment.
#
# Validates the following scenarios:
#   1. Missing manifest with no flag  → hard block (returns 1).
#   2. Missing manifest + --skip-integrity-check → passes (returns 0).
#   3. Present manifest + valid checksums → passes (returns 0).
#   4. Present manifest + tampered payload → fails (returns 1).
#   5. Present manifest + missing payload file → fails (returns 1).
#
# Requirements on the host:
#   - bash 4.2+  (associative arrays, [[ ]], ${var:-default})
#
# Usage:
#   bash scripts/test-safety.sh
#
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
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/safety.sh
source "${SB_ENEMA_LIB_DIR}/safety.sh"

log_init

echo "=== SB-ENEMA safety_check_payload_integrity test ==="
echo

PAYLOADS_DIR="${DATA_MOUNT}/sb-enema/payloads"

# ---------------------------------------------------------------------------
# Test 1: Missing manifest, no flag → hard block (must return 1)
# ---------------------------------------------------------------------------
echo "--- Test 1: missing manifest, no flag → hard block ---"

rm -rf "${PAYLOADS_DIR}"
if safety_check_payload_integrity 2>/dev/null; then
    fail "safety_check_payload_integrity returned 0 for missing manifest (should be 1)"
else
    pass "safety_check_payload_integrity correctly returned 1 for missing manifest"
fi

# ---------------------------------------------------------------------------
# Test 2: Missing manifest + --skip-integrity-check → passes (must return 0)
# ---------------------------------------------------------------------------
echo "--- Test 2: missing manifest + --skip-integrity-check → passes ---"

rm -rf "${PAYLOADS_DIR}"
if safety_check_payload_integrity --skip-integrity-check 2>/dev/null; then
    pass "safety_check_payload_integrity returned 0 with --skip-integrity-check and missing manifest"
else
    fail "safety_check_payload_integrity returned 1 with --skip-integrity-check for missing manifest (should be 0)"
fi

# ---------------------------------------------------------------------------
# Test 3: Present manifest + valid checksums → passes (must return 0)
# ---------------------------------------------------------------------------
echo "--- Test 3: present manifest + valid checksums → passes ---"

mkdir -p "${PAYLOADS_DIR}"
printf 'payload content for test\n' > "${PAYLOADS_DIR}/test.auth"
(cd "${PAYLOADS_DIR}" && sha256sum test.auth > SHA256SUMS)

if safety_check_payload_integrity 2>/dev/null; then
    pass "safety_check_payload_integrity returned 0 for valid manifest and matching checksums"
else
    fail "safety_check_payload_integrity returned 1 for valid manifest and matching checksums (should be 0)"
fi

# ---------------------------------------------------------------------------
# Test 4: Present manifest + tampered payload → fails (must return 1)
# ---------------------------------------------------------------------------
echo "--- Test 4: present manifest + tampered payload → fails ---"

# Tamper with the payload after the manifest was written
printf 'tampered content\n' > "${PAYLOADS_DIR}/test.auth"

if safety_check_payload_integrity 2>/dev/null; then
    fail "safety_check_payload_integrity returned 0 for tampered payload (should be 1)"
else
    pass "safety_check_payload_integrity correctly returned 1 for tampered payload"
fi

# ---------------------------------------------------------------------------
# Test 5: Present manifest + missing payload file → fails (must return 1)
# ---------------------------------------------------------------------------
echo "--- Test 5: present manifest + missing payload file → fails ---"

# Re-create the payload so we can generate a valid manifest entry for it,
# then remove the payload to simulate a file that was listed but is absent.
printf 'payload content for test\n' > "${PAYLOADS_DIR}/test.auth"
(cd "${PAYLOADS_DIR}" && sha256sum test.auth > SHA256SUMS)
rm -f "${PAYLOADS_DIR}/test.auth"

if safety_check_payload_integrity 2>/dev/null; then
    fail "safety_check_payload_integrity returned 0 for missing payload file (should be 1)"
else
    pass "safety_check_payload_integrity correctly returned 1 for missing payload file"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi
exit 0
