#!/usr/bin/env bash
# test-enroll.sh — Test _enroll_var() timeout handling in a local mock environment.
#
# Validates three scenarios for the efi-updatevar call in _enroll_var():
#   1. efi-updatevar succeeds (exit 0) — variable is added to enrolled list.
#   2. efi-updatevar times out (exit 124) — specific timeout error message shown.
#   3. efi-updatevar fails with a generic error — generic failure message shown.
#
# Requirements on the host:
#   - bash 4+
#   - openssl  (for sha256sum used by _enroll_var on success)
#
# Usage:
#   bash scripts/test-enroll.sh
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
MOCK_PAYLOADS="$(mktemp -d)"
MOCK_KEYS="$(mktemp -d)"
trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}" "${MOCK_PAYLOADS}" "${MOCK_KEYS}"' EXIT

export EFIVARS_DIR="${MOCK_EFIVARS}"
export DATA_MOUNT="${MOCK_DATA}"
export KEYS_DIR="${MOCK_KEYS}"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# ---------------------------------------------------------------------------
# Source libraries (same pattern as other test scripts)
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
# update.sh defines PAYLOAD_DIR which enroll.sh references at source time
export PAYLOAD_DIR="${MOCK_PAYLOADS}"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/update.sh
source "${SB_ENEMA_LIB_DIR}/update.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/preview.sh
source "${SB_ENEMA_LIB_DIR}/preview.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/keygen.sh
source "${SB_ENEMA_LIB_DIR}/keygen.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/enroll.sh
source "${SB_ENEMA_LIB_DIR}/enroll.sh"

log_init

echo "=== SB-ENEMA _enroll_var() timeout handling test ==="
echo

# Create a minimal dummy auth file for testing
DUMMY_AUTH="$(mktemp --suffix=.auth)"
trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}" "${MOCK_PAYLOADS}" "${MOCK_KEYS}" "${DUMMY_AUTH}"' EXIT
# Write a fake WIN_CERTIFICATE header so _enroll_is_auth_file() returns 1 (raw ESL path)
# — we just need any valid file for the tests
dd if=/dev/zero bs=1 count=32 2>/dev/null > "${DUMMY_AUTH}"

# Stub safety_verify_write to always succeed (not the focus of these tests)
safety_verify_write() { return 0; }

# ---------------------------------------------------------------------------
# Test 1: efi-updatevar succeeds (exit 0)
# ---------------------------------------------------------------------------
echo "--- Test 1: efi-updatevar succeeds ---"

# Stub timeout + efi-updatevar: succeed immediately.
# The first argument to timeout must be a numeric duration; shift it and run
# the rest of the command normally.
timeout() {
    [[ "$1" =~ ^[0-9]+$ ]] || { echo "stub: expected numeric timeout, got '$1'" >&2; return 1; }
    shift
    "$@"
}
efi-updatevar() { return 0; }
export -f timeout efi-updatevar

enrolled=()
if _enroll_var "db" "${DUMMY_AUTH}" enrolled 2>/dev/null; then
    pass "_enroll_var returns 0 on success"
else
    fail "_enroll_var unexpectedly returned non-zero on success"
fi

if [[ "${enrolled[*]:-}" == "db" ]]; then
    pass "_enroll_var added 'db' to enrolled array on success"
else
    fail "_enroll_var did not add 'db' to enrolled array; got: '${enrolled[*]:-}'"
fi

# ---------------------------------------------------------------------------
# Test 2: efi-updatevar times out (exit 124)
# ---------------------------------------------------------------------------
echo "--- Test 2: efi-updatevar times out (exit 124) ---"

# Stub timeout to simulate a timeout: return 124 without executing the wrapped
# command, matching the real `timeout` exit code when the deadline is exceeded.
timeout() {
    shift
    return 124
}
efi-updatevar() { return 0; }
export -f timeout efi-updatevar

enrolled=()
output=$(_enroll_var "KEK" "${DUMMY_AUTH}" enrolled 2>&1) && rc=0 || rc=$?

if [[ "${rc}" -ne 0 ]]; then
    pass "_enroll_var returns non-zero on timeout"
else
    fail "_enroll_var unexpectedly returned 0 on timeout"
fi

if echo "${output}" | grep -qi "reboot\|timed out\|firmware did not respond"; then
    pass "_enroll_var shows timeout-specific message (reboot/timed out/firmware did not respond)"
else
    fail "_enroll_var did not show timeout-specific message; got: '${output}'"
fi

if [[ "${enrolled[*]:-}" == "" ]]; then
    pass "_enroll_var did not add variable to enrolled array on timeout"
else
    fail "_enroll_var incorrectly added variable to enrolled array on timeout: '${enrolled[*]:-}'"
fi

# ---------------------------------------------------------------------------
# Test 3: efi-updatevar fails with generic error (exit 1)
# ---------------------------------------------------------------------------
echo "--- Test 3: efi-updatevar fails with generic error ---"

# Stub timeout to simulate a generic non-timeout failure: return 1 without
# executing the wrapped command, matching any non-zero, non-124 exit code.
timeout() {
    shift
    return 1
}
efi-updatevar() { return 0; }
export -f timeout efi-updatevar

enrolled=()
output=$(_enroll_var "PK" "${DUMMY_AUTH}" enrolled 2>&1) && rc=0 || rc=$?

if [[ "${rc}" -ne 0 ]]; then
    pass "_enroll_var returns non-zero on generic failure"
else
    fail "_enroll_var unexpectedly returned 0 on generic failure"
fi

# Must NOT show the timeout-specific reboot message
if ! echo "${output}" | grep -qi "reboot and retry"; then
    pass "_enroll_var does not show timeout-specific reboot message on generic failure"
else
    fail "_enroll_var incorrectly showed timeout-specific reboot message on generic failure"
fi

if [[ "${enrolled[*]:-}" == "" ]]; then
    pass "_enroll_var did not add variable to enrolled array on generic failure"
else
    fail "_enroll_var incorrectly added variable to enrolled array on generic failure"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi
