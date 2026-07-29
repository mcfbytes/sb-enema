#!/usr/bin/env bash
# test-defconfig.sh — Consistency checks on the Buildroot defconfig.
#
# Background
# ----------
# Pinning the kernel with BR2_LINUX_KERNEL_CUSTOM_VERSION means Buildroot can no
# longer derive the kernel-headers series from the version string; it falls back
# to the choice default in package/linux-headers/Config.in.host, which is
# BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_REALLY_OLD (2.6).
#
# That failure is silent and destructive. With headers advertised as 2.6,
# glibc's minimum-version dependency is unsatisfiable, so kconfig quietly drops
# BR2_TOOLCHAIN_BUILDROOT_GLIBC and selects uClibc instead — changing the C
# library of the shipped image. The build only fails thousands of lines later
# with "Incorrect selection of kernel headers: expected 2.6.x, got 6.18.x".
#
# A full build catches it, but slowly and with a misleading error. These are
# pure text checks over the defconfig, so they run in milliseconds and point at
# the actual cause.
#
# Validates:
#   1. A pinned kernel version has a matching headers-series selection.
#   2. The libc is explicitly selected (guards against a silent kconfig
#      fallback going unnoticed in review).
#   3. The pinned kernel version has a corresponding hash line.
#
# Usage:
#   bash scripts/test-defconfig.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFCONFIG="${REPO_ROOT}/sb_enema/configs/sb_enema_defconfig"
KERNEL_HASH="${REPO_ROOT}/sb_enema/patches/linux/linux.hash"

PASS_COUNT=0
FAIL_COUNT=0
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

echo "=== SB-ENEMA defconfig consistency test ==="
echo

if [[ ! -f "${DEFCONFIG}" ]]; then
    echo "FAIL: defconfig not found at ${DEFCONFIG}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Test 1: pinned kernel version and headers series agree
# ---------------------------------------------------------------------------
echo "--- Test 1: kernel pin and headers series are in step ---"

kernel_version=$(sed -n 's/^BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="\([^"]*\)".*/\1/p' "${DEFCONFIG}")

if [[ -z "${kernel_version}" ]]; then
    echo "SKIP: no BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE set; nothing to check"
    exit 0
fi

pass "Kernel pinned to ${kernel_version}"

# 6.18.40 -> 6_18
kernel_series="${kernel_version%.*}"
expected_symbol="BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_${kernel_series//./_}"

if grep -qE "^${expected_symbol}=y$" "${DEFCONFIG}"; then
    pass "Headers series ${expected_symbol}=y matches the pinned kernel"
else
    actual=$(grep -oE '^BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_[A-Z0-9_]+=y$' "${DEFCONFIG}" || true)
    fail "Expected ${expected_symbol}=y for kernel ${kernel_version}; found: ${actual:-<none>}"
    echo "      Without it Buildroot defaults the headers series to 2.6, which" >&2
    echo "      silently drops glibc in favour of uClibc and fails the build" >&2
    echo "      much later with a misleading headers-mismatch error." >&2
fi

# ---------------------------------------------------------------------------
# Test 2: the C library is explicitly selected
# ---------------------------------------------------------------------------
echo
echo "--- Test 2: C library is explicitly selected ---"

libc_selected=$(grep -oE '^BR2_TOOLCHAIN_BUILDROOT_(GLIBC|UCLIBC|MUSL)=y$' "${DEFCONFIG}" || true)
if [[ -n "${libc_selected}" ]]; then
    pass "C library explicitly selected: ${libc_selected}"
else
    fail "No BR2_TOOLCHAIN_BUILDROOT_{GLIBC,UCLIBC,MUSL}=y in the defconfig"
fi

# ---------------------------------------------------------------------------
# Test 3: the pinned kernel has a hash line
# ---------------------------------------------------------------------------
echo
echo "--- Test 3: pinned kernel has a matching hash entry ---"

if [[ ! -f "${KERNEL_HASH}" ]]; then
    fail "Kernel hash file not found at ${KERNEL_HASH}"
elif grep -qE "^sha256[[:space:]]+[0-9a-f]{64}[[:space:]]+linux-${kernel_version//./\\.}\.tar\.xz$" "${KERNEL_HASH}"; then
    pass "linux-${kernel_version}.tar.xz has a sha256 line in linux.hash"
else
    fail "No sha256 line for linux-${kernel_version}.tar.xz in ${KERNEL_HASH}"
    echo "      The build fails closed on this (BR2_DOWNLOAD_FORCE_CHECK_HASHES=y)," >&2
    echo "      but catching it here is faster than a failed download." >&2
fi

# BR2_DOWNLOAD_FORCE_CHECK_HASHES is what makes that hash mandatory rather than
# advisory -- Buildroot exempts custom-pinned versions from hash checking.
if grep -qE '^BR2_DOWNLOAD_FORCE_CHECK_HASHES=y$' "${DEFCONFIG}"; then
    pass "BR2_DOWNLOAD_FORCE_CHECK_HASHES=y (kernel hash is enforced)"
else
    fail "BR2_DOWNLOAD_FORCE_CHECK_HASHES=y missing — a pinned kernel version is exempt from hash checking, so a stale hash file would be silently ignored"
fi

echo
echo "=== Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
[[ "${FAIL_COUNT}" -eq 0 ]]
