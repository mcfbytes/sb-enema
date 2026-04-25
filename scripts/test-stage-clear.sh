#!/usr/bin/env bash
# test-stage-clear.sh — Test _stage_assert_payload_dir_safe() and stage_clear()
# in a local mock environment.
#
# Validates the following scenarios:
#   1.  Empty PAYLOAD_DIR → guard dies (returns non-zero).
#   2.  Relative PAYLOAD_DIR → guard dies (returns non-zero).
#   3.  Absolute path without expected prefix (/etc/...) → guard dies.
#   4.  Exact mount root /tmp → guard dies.
#   5.  Exact mount root /tmp/ → guard dies.
#   6.  Exact mount root /mnt → guard dies.
#   7.  Path traversal /tmp/.. → guard dies.
#   8.  Path traversal /tmp/valid/../.. → guard dies.
#   9.  Symlink PAYLOAD_DIR pointing to a real /tmp/... dir → guard dies.
#   10. Valid /tmp/... path → guard passes.
#   11. Valid /mnt/... path → guard passes.
#   12. stage_clear() removes non-microsoft items and preserves microsoft/ contents.
#   13. stage_clear() on a non-existent PAYLOAD_DIR creates the directory.
#
# Requirements on the host:
#   - bash 4+
#
# Usage:
#   bash scripts/test-stage-clear.sh
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
STAGE_DIR=""   # set later, once mktemp is called for Test 6
trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}"; [[ -n "${STAGE_DIR:-}" && "${STAGE_DIR}" == /tmp/* ]] && rm -rf "${STAGE_DIR}"' EXIT

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
# update.sh defines PAYLOAD_DIR which stage.sh references at source time
export PAYLOAD_DIR="${MOCK_DATA}/sb-enema/payloads"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/update.sh
source "${SB_ENEMA_LIB_DIR}/update.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/preview.sh
source "${SB_ENEMA_LIB_DIR}/preview.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/keygen.sh
source "${SB_ENEMA_LIB_DIR}/keygen.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/stage.sh
source "${SB_ENEMA_LIB_DIR}/stage.sh"

log_init

echo "=== SB-ENEMA _stage_assert_payload_dir_safe() and stage_clear() test ==="
echo

# ---------------------------------------------------------------------------
# Test 1: Empty PAYLOAD_DIR → guard must die (return non-zero)
# ---------------------------------------------------------------------------
echo "--- Test 1: empty PAYLOAD_DIR → guard must reject ---"

(
    PAYLOAD_DIR=""
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for empty PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected empty PAYLOAD_DIR"

# ---------------------------------------------------------------------------
# Test 2: Relative PAYLOAD_DIR → guard must die
# ---------------------------------------------------------------------------
echo "--- Test 2: relative PAYLOAD_DIR → guard must reject ---"

(
    PAYLOAD_DIR="relative/path/payloads"
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for relative PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected relative PAYLOAD_DIR"

# ---------------------------------------------------------------------------
# Test 3: Absolute path without expected prefix → guard must die
# ---------------------------------------------------------------------------
echo "--- Test 3: /etc/... PAYLOAD_DIR → guard must reject ---"

(
    PAYLOAD_DIR="/etc/payloads"
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for /etc/... PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected /etc/... PAYLOAD_DIR"

# ---------------------------------------------------------------------------
# Test 4: Exact mount root /tmp → guard must die
# ---------------------------------------------------------------------------
echo "--- Test 4: exact /tmp PAYLOAD_DIR → guard must reject ---"

(
    PAYLOAD_DIR="/tmp"
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for /tmp PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected /tmp PAYLOAD_DIR"

# ---------------------------------------------------------------------------
# Test 5: Exact mount root /tmp/ → guard must die
# ---------------------------------------------------------------------------
echo "--- Test 5: exact /tmp/ PAYLOAD_DIR → guard must reject ---"

(
    PAYLOAD_DIR="/tmp/"
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for /tmp/ PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected /tmp/ PAYLOAD_DIR"

# ---------------------------------------------------------------------------
# Test 6: Exact mount root /mnt → guard must die
# ---------------------------------------------------------------------------
echo "--- Test 6: exact /mnt PAYLOAD_DIR → guard must reject ---"

(
    PAYLOAD_DIR="/mnt"
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for /mnt PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected /mnt PAYLOAD_DIR"

# ---------------------------------------------------------------------------
# Test 7: Path traversal /tmp/.. → guard must die
# ---------------------------------------------------------------------------
echo "--- Test 7: /tmp/.. PAYLOAD_DIR → guard must reject ---"

(
    PAYLOAD_DIR="/tmp/.."
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for /tmp/.. PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected /tmp/.. PAYLOAD_DIR"

# ---------------------------------------------------------------------------
# Test 8: Path traversal /tmp/valid/../.. → guard must die
# ---------------------------------------------------------------------------
echo "--- Test 8: /tmp/valid/../.. PAYLOAD_DIR → guard must reject ---"

(
    PAYLOAD_DIR="/tmp/valid/../.."
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for /tmp/valid/../.. PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected /tmp/valid/../.. PAYLOAD_DIR"

# ---------------------------------------------------------------------------
# Test 9: Symlink pointing to a real /tmp/... directory → guard must die
# ---------------------------------------------------------------------------
echo "--- Test 9: symlink PAYLOAD_DIR → guard must reject ---"

_sym_target="$(mktemp -d -t sb-enema-symtarget-XXXXXX)"
_sym_link="$(mktemp -u -t sb-enema-symlink-XXXXXX)"
ln -s "${_sym_target}" "${_sym_link}"
(
    PAYLOAD_DIR="${_sym_link}"
    _stage_assert_payload_dir_safe 2>/dev/null
) && fail "guard passed for symlink PAYLOAD_DIR (should have rejected)" \
   || pass "guard correctly rejected symlink PAYLOAD_DIR"
rm -f "${_sym_link}"
rm -rf "${_sym_target}"

# ---------------------------------------------------------------------------
# Test 10: Valid /tmp/... path → guard must pass
# ---------------------------------------------------------------------------
echo "--- Test 10: /tmp/... PAYLOAD_DIR → guard must accept ---"

(
    PAYLOAD_DIR="/tmp/sb-enema-test/payloads"
    _stage_assert_payload_dir_safe 2>/dev/null
) && pass "guard accepted /tmp/... PAYLOAD_DIR" \
   || fail "guard rejected valid /tmp/... PAYLOAD_DIR (should have accepted)"

# ---------------------------------------------------------------------------
# Test 11: Valid /mnt/... path → guard must pass
# ---------------------------------------------------------------------------
echo "--- Test 11: /mnt/data/... PAYLOAD_DIR → guard must accept ---"

(
    PAYLOAD_DIR="/mnt/data/sb-enema/payloads"
    _stage_assert_payload_dir_safe 2>/dev/null
) && pass "guard accepted /mnt/data/... PAYLOAD_DIR" \
   || fail "guard rejected valid /mnt/data/... PAYLOAD_DIR (should have accepted)"

# ---------------------------------------------------------------------------
# Test 12: stage_clear() removes non-microsoft items and preserves microsoft/
# ---------------------------------------------------------------------------
echo "--- Test 12: stage_clear() removes non-microsoft, preserves microsoft/ ---"

STAGE_DIR="$(mktemp -d -t sb-enema-stage-XXXXXX)"

mkdir -p "${STAGE_DIR}/microsoft"
touch "${STAGE_DIR}/microsoft/PK.auth"
mkdir -p "${STAGE_DIR}/PK"
touch "${STAGE_DIR}/KEK.auth"
touch "${STAGE_DIR}/db.auth"

PAYLOAD_DIR="${STAGE_DIR}"
if stage_clear 2>/dev/null; then
    if [[ -d "${STAGE_DIR}/microsoft" && -f "${STAGE_DIR}/microsoft/PK.auth" ]]; then
        pass "stage_clear() preserved microsoft/ subdirectory"
    else
        fail "stage_clear() removed or corrupted microsoft/ subdirectory"
    fi
    if [[ -d "${STAGE_DIR}/PK" || -f "${STAGE_DIR}/KEK.auth" || -f "${STAGE_DIR}/db.auth" ]]; then
        fail "stage_clear() left non-microsoft items behind"
    else
        pass "stage_clear() removed all non-microsoft items"
    fi
else
    fail "stage_clear() failed unexpectedly for a valid /tmp/... PAYLOAD_DIR"
fi
[[ -n "${STAGE_DIR:-}" && "${STAGE_DIR}" == /tmp/* ]] && rm -rf "${STAGE_DIR}"

# ---------------------------------------------------------------------------
# Test 13: stage_clear() on a non-existent PAYLOAD_DIR creates the directory
# ---------------------------------------------------------------------------
echo "--- Test 13: stage_clear() creates PAYLOAD_DIR if absent ---"

NEW_DIR="$(mktemp -d -t sb-enema-newdir-XXXXXX)"
[[ -n "${NEW_DIR:-}" && "${NEW_DIR}" == /tmp/* ]] && rm -rf "${NEW_DIR}"   # ensure it does not exist yet

PAYLOAD_DIR="${NEW_DIR}"
if stage_clear 2>/dev/null; then
    if [[ -d "${NEW_DIR}" ]]; then
        pass "stage_clear() created the staging directory when absent"
    else
        fail "stage_clear() returned 0 but directory was not created"
    fi
else
    fail "stage_clear() failed unexpectedly when PAYLOAD_DIR did not exist"
fi
[[ -n "${NEW_DIR:-}" && "${NEW_DIR}" == /tmp/* ]] && rm -rf "${NEW_DIR}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi
exit 0
