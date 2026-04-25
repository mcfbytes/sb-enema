#!/usr/bin/env bash
# test-enroll-fingerprints.sh — Test _enroll_staged_fingerprints() exit codes.
#
# Validates that the function distinguishes:
#   1. No staged dir or empty dir              → exit 1 (warn and skip)
#   2. At least one cert parses successfully   → exit 0
#   3. Cert files present but ALL fail to parse → exit 2 (HARD FAILURE)
#
# Also validates that enroll_apply() aborts when staged certs cannot be
# parsed, instead of silently skipping post-write verification.
#
# Requirements on the host:
#   - bash 4+
#   - openssl (to generate a test cert)
#
# Usage:
#   bash scripts/test-enroll-fingerprints.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export SB_ENEMA_LIB_DIR="${REPO_ROOT}/sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema"
export CERTDB_DIR="${SB_ENEMA_LIB_DIR}/known-certs"

# Track every temp path in a single array and use one cleanup function so
# items can't accidentally be dropped from cleanup (and so a partial setup
# failure still removes whatever was created so far).
TMP_PATHS=()
cleanup() {
    local p
    for p in "${TMP_PATHS[@]:-}"; do
        [[ -n "${p}" ]] && rm -rf "${p}"
    done
}
trap cleanup EXIT

MOCK_EFIVARS="$(mktemp -d)";  TMP_PATHS+=("${MOCK_EFIVARS}")
MOCK_DATA="$(mktemp -d)";     TMP_PATHS+=("${MOCK_DATA}")
MOCK_PAYLOADS="$(mktemp -d)"; TMP_PATHS+=("${MOCK_PAYLOADS}")
MOCK_KEYS="$(mktemp -d)";     TMP_PATHS+=("${MOCK_KEYS}")

export EFIVARS_DIR="${MOCK_EFIVARS}"
export DATA_MOUNT="${MOCK_DATA}"
export KEYS_DIR="${MOCK_KEYS}"

PASS_COUNT=0
FAIL_COUNT=0
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

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

echo "=== SB-ENEMA _enroll_staged_fingerprints() exit-code test ==="
echo

# ---------------------------------------------------------------------------
# Test 1: No staged directory at all → exit 1
# ---------------------------------------------------------------------------
echo "--- Test 1: missing staged dir → exit 1 ---"
rm -rf "${PAYLOAD_DIR}/PK"
out=""; rc=0
out=$(_enroll_staged_fingerprints "PK") || rc=$?
[[ "${rc}" -eq 1 ]] && pass "exit 1 when staged dir is missing" \
    || fail "expected exit 1 for missing dir, got ${rc}"
[[ -z "${out}" ]] && pass "no fingerprints emitted when staged dir is missing" \
    || fail "unexpected output: ${out}"

# ---------------------------------------------------------------------------
# Test 2: Empty staged directory (no .der/.crt/.cer files) → exit 1
# ---------------------------------------------------------------------------
echo "--- Test 2: empty staged dir → exit 1 ---"
mkdir -p "${PAYLOAD_DIR}/PK"
# A non-cert file should not count as a candidate
echo "noise" > "${PAYLOAD_DIR}/PK/README.txt"
rc=0
out=$(_enroll_staged_fingerprints "PK") || rc=$?
[[ "${rc}" -eq 1 ]] && pass "exit 1 when no .der/.crt/.cer files are present" \
    || fail "expected exit 1 for empty dir, got ${rc}"
[[ -z "${out}" ]] && pass "no fingerprints emitted when no cert files present" \
    || fail "unexpected output: ${out}"
rm -rf "${PAYLOAD_DIR}/PK"

# ---------------------------------------------------------------------------
# Test 3: Cert files present but ALL fail to parse → exit 2 (hard failure)
# ---------------------------------------------------------------------------
echo "--- Test 3: corrupt cert files → exit 2 ---"
mkdir -p "${PAYLOAD_DIR}/PK"
printf 'not a real certificate' > "${PAYLOAD_DIR}/PK/bad1.der"
printf 'still not a cert'        > "${PAYLOAD_DIR}/PK/bad2.crt"
rc=0
out=$(_enroll_staged_fingerprints "PK" 2>/dev/null) || rc=$?
[[ "${rc}" -eq 2 ]] && pass "exit 2 when all cert files fail to parse" \
    || fail "expected exit 2 for corrupt certs, got ${rc}"
[[ -z "${out}" ]] && pass "no fingerprints emitted when all certs fail to parse" \
    || fail "unexpected output: ${out}"

# ---------------------------------------------------------------------------
# Test 4: enroll_apply() aborts (returns 1) when staged certs are unparseable
# ---------------------------------------------------------------------------
echo "--- Test 4: enroll_apply() refuses to proceed on parse-failure ---"
# Stage a PK.auth so enroll_apply would otherwise call _enroll_var for PK.
: > "${PAYLOAD_DIR}/PK.auth"
# Stub destructive helpers in case anything slips through.
_enroll_var() { fail "enroll_apply continued past parse-failure: _enroll_var called for $1"; return 1; }
_keygen_sign_bootx64() { :; }
keygen_backup_instructions() { :; }

rc=0
enroll_apply >/dev/null 2>&1 || rc=$?
[[ "${rc}" -eq 1 ]] && pass "enroll_apply returns 1 when staged PK certs cannot be parsed" \
    || fail "expected enroll_apply to return 1, got ${rc}"

# Restore so subsequent tests can call into _enroll_var if needed.
unset -f _enroll_var

# ---------------------------------------------------------------------------
# Test 5: At least one parseable cert → exit 0 + fingerprint printed
# ---------------------------------------------------------------------------
echo "--- Test 5: one good cert → exit 0 ---"
rm -rf "${PAYLOAD_DIR}/PK"
mkdir -p "${PAYLOAD_DIR}/PK"

# Generate a self-signed cert in DER form.  Uses RSA-2048 + SHA-256 to keep
# the test cheap; the cert is purely synthetic and never trusted.
TMP_KEY="$(mktemp)"; TMP_PATHS+=("${TMP_KEY}")
TMP_PEM="$(mktemp)"; TMP_PATHS+=("${TMP_PEM}")
openssl req -x509 -nodes -newkey rsa:2048 -sha256 \
    -keyout "${TMP_KEY}" -out "${TMP_PEM}" \
    -subj "/CN=sb-enema-test" -days 1 >/dev/null 2>&1
openssl x509 -in "${TMP_PEM}" -outform DER -out "${PAYLOAD_DIR}/PK/good.der"
# Add an unparseable file alongside; should not change the exit code.
printf 'garbage' > "${PAYLOAD_DIR}/PK/bad.der"

rc=0
out=$(_enroll_staged_fingerprints "PK" 2>/dev/null) || rc=$?
[[ "${rc}" -eq 0 ]] && pass "exit 0 when at least one cert parses" \
    || fail "expected exit 0 for good cert, got ${rc}"
expected_fp=$(openssl x509 -in "${TMP_PEM}" -noout -fingerprint -sha256 | _fp_normalize)
if grep -qxF "${expected_fp}" <<<"${out}"; then
    pass "expected fingerprint emitted for parseable cert"
else
    fail "expected fingerprint ${expected_fp} not found in output: ${out}"
fi

echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
[[ "${FAIL_COUNT}" -eq 0 ]]
