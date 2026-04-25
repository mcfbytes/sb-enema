#!/usr/bin/env bash
# test-common-safe-rm.sh — Test the shared rm -rf path-safety helpers in
# common.sh: _path_has_dot_segments() and _safe_rm_dir_assert().
#
# Validates the contract enforced by _safe_rm_dir_assert(), including:
#   - Misuse: missing args, empty path/label.
#   - Path checks: empty, relative, mount-root, dot segments, prefix
#     mismatch, symlinks, non-directory existing paths, traversal whose
#     canonical form escapes an allowed prefix.
#   - Prefix-contract checks: prefixes must be absolute, end in "/", and
#     not be "/" alone (the latter would whitelist the entire filesystem).
#   - Happy paths: non-existent valid path, existing directory, custom
#     allowed prefixes.
#   - _path_has_dot_segments() unit checks.
#
# Usage:
#   bash scripts/test-common-safe-rm.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export SB_ENEMA_LIB_DIR="${REPO_ROOT}/sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema"

# ---------------------------------------------------------------------------
# Source common.sh in a controlled environment.  No other libs are needed
# because _safe_rm_dir_assert / _path_has_dot_segments are self-contained.
# ---------------------------------------------------------------------------
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/common.sh
source "${SB_ENEMA_LIB_DIR}/common.sh"

PASS_COUNT=0
FAIL_COUNT=0
TMP_DIRS=()

cleanup() {
    local d
    for d in "${TMP_DIRS[@]}"; do
        [[ -n "${d}" && "${d}" == /tmp/* ]] && rm -rf "${d}" 2>/dev/null || true
    done
}
trap cleanup EXIT

pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# expect_die "<description>" -- <command...>
#   Run <command...> in a subshell with stderr suppressed and assert it
#   exits non-zero (i.e. die() fired).  Reports PASS/FAIL.
expect_die() {
    local desc="$1"
    shift
    if ( "$@" 2>/dev/null ); then
        fail "${desc} (expected die(), got success)"
    else
        pass "${desc}"
    fi
}

# expect_ok "<description>" -- <command...>
#   Run <command...> in a subshell with stderr suppressed and assert it
#   exits zero.  Reports PASS/FAIL.
expect_ok() {
    local desc="$1"
    shift
    if ( "$@" 2>/dev/null ); then
        pass "${desc}"
    else
        fail "${desc} (expected success, got die())"
    fi
}

echo "=== SB-ENEMA _safe_rm_dir_assert() / _path_has_dot_segments() test ==="
echo

# ---------------------------------------------------------------------------
# _path_has_dot_segments() unit tests
# ---------------------------------------------------------------------------
echo "--- _path_has_dot_segments() ---"

# Returns 0 when dot segments are present.
_path_has_dot_segments "/tmp/./x"      && pass "/tmp/./x detected"     || fail "/tmp/./x not detected"
_path_has_dot_segments "/tmp/../x"     && pass "/tmp/../x detected"    || fail "/tmp/../x not detected"
_path_has_dot_segments "/tmp/x/."      && pass "/tmp/x/. detected"     || fail "/tmp/x/. not detected"
_path_has_dot_segments "/tmp/x/.."     && pass "/tmp/x/.. detected"    || fail "/tmp/x/.. not detected"

# Returns 1 when no dot segments.
_path_has_dot_segments "/tmp/x"        && fail "/tmp/x false positive"        || pass "/tmp/x clean"
_path_has_dot_segments "/tmp/x.y/z"    && fail "/tmp/x.y/z false positive"    || pass "/tmp/x.y/z clean (dot in name only)"
_path_has_dot_segments "/tmp/.hidden"  && fail "/tmp/.hidden false positive"  || pass "/tmp/.hidden clean (dotfile)"
_path_has_dot_segments "/tmp/..hidden" && fail "/tmp/..hidden false positive" || pass "/tmp/..hidden clean"

# ---------------------------------------------------------------------------
# Misuse: missing args
# ---------------------------------------------------------------------------
echo "--- _safe_rm_dir_assert() misuse: missing args ---"
expect_die "no args"                _safe_rm_dir_assert
expect_die "only path"              _safe_rm_dir_assert /tmp/x

# ---------------------------------------------------------------------------
# Path checks (default prefixes /mnt/ and /tmp/)
# ---------------------------------------------------------------------------
echo "--- _safe_rm_dir_assert() path checks ---"

expect_die "empty path"             _safe_rm_dir_assert ""           "TEST"
expect_die "relative path"          _safe_rm_dir_assert "rel/path"   "TEST"
expect_die "no allowed prefix"      _safe_rm_dir_assert "/etc/x"     "TEST"
expect_die "/tmp mount root"        _safe_rm_dir_assert "/tmp"       "TEST"
expect_die "/tmp/ mount root"       _safe_rm_dir_assert "/tmp/"      "TEST"
expect_die "/mnt mount root"        _safe_rm_dir_assert "/mnt"       "TEST"
expect_die "/mnt/ mount root"       _safe_rm_dir_assert "/mnt/"      "TEST"
expect_die "/tmp/.. dot segments"   _safe_rm_dir_assert "/tmp/.."    "TEST"
expect_die "/tmp/a/../.. dots"      _safe_rm_dir_assert "/tmp/a/../.." "TEST"

# Prefix sibling: "/tmpfoo" must not match "/tmp/" (trailing slash matters).
expect_die "/tmpfoo prefix sibling" _safe_rm_dir_assert "/tmpfoo/x"  "TEST"

# ---------------------------------------------------------------------------
# Prefix-contract checks
# ---------------------------------------------------------------------------
echo "--- _safe_rm_dir_assert() prefix-contract checks ---"

expect_die "prefix '/' rejected"    _safe_rm_dir_assert "/tmp/x" "TEST" "/"
expect_die "prefix without trailing slash rejected" \
                                    _safe_rm_dir_assert "/tmp/x" "TEST" "/tmp"
expect_die "relative prefix rejected" \
                                    _safe_rm_dir_assert "/tmp/x" "TEST" "tmp/"
expect_die "empty prefix rejected"  _safe_rm_dir_assert "/tmp/x" "TEST" ""
# Mixed valid + invalid: should still die on the invalid one.
expect_die "mixed valid+invalid prefix rejected" \
                                    _safe_rm_dir_assert "/tmp/x" "TEST" "/tmp/" "/"

# ---------------------------------------------------------------------------
# Existing-path checks
# ---------------------------------------------------------------------------
echo "--- _safe_rm_dir_assert() existing-path checks ---"

# Valid non-existent path under /tmp/ → success.
expect_ok "valid non-existent /tmp/... path" \
    _safe_rm_dir_assert "/tmp/sb-enema-nonexistent-$$" "TEST"

# Valid existing directory → success.
real_dir="$(mktemp -d -t sb-enema-real-XXXXXX)"
TMP_DIRS+=("${real_dir}")
expect_ok "valid existing /tmp/... directory" \
    _safe_rm_dir_assert "${real_dir}" "TEST"

# Existing regular file (not a directory) → die.
real_file="$(mktemp -t sb-enema-file-XXXXXX)"
TMP_DIRS+=("${real_file}")
expect_die "existing regular file rejected" \
    _safe_rm_dir_assert "${real_file}" "TEST"

# Symlink under /tmp/ pointing at a real /tmp/... dir → die.
sym_target="$(mktemp -d -t sb-enema-symtgt-XXXXXX)"
sym_link="$(mktemp -u -t sb-enema-symlink-XXXXXX)"
TMP_DIRS+=("${sym_target}" "${sym_link}")
ln -s "${sym_target}" "${sym_link}"
expect_die "symlink rejected" _safe_rm_dir_assert "${sym_link}" "TEST"

# Custom prefix: a path under /var/tmp/ must succeed when /var/tmp/ is
# allowed but fail with the default prefixes.
var_tmp_dir="$(mktemp -d -p /var/tmp sb-enema-vartmp-XXXXXX 2>/dev/null || true)"
if [[ -n "${var_tmp_dir}" && -d "${var_tmp_dir}" ]]; then
    expect_die "default prefixes reject /var/tmp/..." \
        _safe_rm_dir_assert "${var_tmp_dir}" "TEST"
    expect_ok "custom prefix /var/tmp/ accepts /var/tmp/..." \
        _safe_rm_dir_assert "${var_tmp_dir}" "TEST" "/var/tmp/"
    rm -rf "${var_tmp_dir}"
else
    echo "SKIP: /var/tmp not writable; skipping custom-prefix tests"
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
