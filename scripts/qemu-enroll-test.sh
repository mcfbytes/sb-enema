#!/usr/bin/env bash
# qemu-enroll-test.sh — Boot the built image under OVMF and run a real
# Custom-Owned enrollment, then verify the firmware variable store actually
# contains the certificates we intended to enroll.
#
# Why this exists
# ---------------
# The scripts/test-*.sh suite exercises the staging logic with stubs. It cannot
# catch a failure in the parts that only exist on real firmware: efivarfs, the
# authenticated-variable write path in efi-updatevar, the kernel actually
# booting with the pinned config, or the enrollment order (db -> dbx -> KEK ->
# PK). This does, end to end, in about three minutes.
#
# It also directly guards the certificate policy this project exists to get
# right: it asserts that "Microsoft Windows Production PCA 2011" and "Microsoft
# Corporation KEK CA 2011" are present in the enrolled variables, so a
# regression that filters them out again fails here even if it somehow slips
# past the unit tests.
#
# Deliberately NOT named test-*.sh: it requires a built image plus qemu and
# OVMF, so it must not be picked up by the fast unit-test glob.
#
# Requirements:
#   - qemu-system-x86_64
#   - OVMF secure-boot firmware (Debian/Ubuntu: ovmf package)
#   - a built image at output/br-out/images/sb-enema.img
# Skips (exit 0) if qemu or OVMF are unavailable; fails if the image is missing.
#
# Usage:
#   make            # build the image first
#   bash scripts/qemu-enroll-test.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE="${IMAGE:-${REPO_ROOT}/output/br-out/images/sb-enema.img}"
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-120}"
ENROLL_TIMEOUT="${ENROLL_TIMEOUT:-240}"

PASS_COUNT=0
FAIL_COUNT=0
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "SKIP: qemu-system-x86_64 not available"
    exit 0
fi
if [[ ! -r "${OVMF_CODE}" || ! -r "${OVMF_VARS}" ]]; then
    echo "SKIP: OVMF firmware not found (${OVMF_CODE}, ${OVMF_VARS})"
    exit 0
fi
if [[ ! -f "${IMAGE}" ]]; then
    echo "FAIL: image not found at ${IMAGE} — build it first with 'make'" >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
QEMU_PID=""

# Preserve the serial log outside the temp dir so CI can upload it when this
# fails; a failure here is otherwise very hard to diagnose after the fact.
SERIAL_LOG_COPY="${SERIAL_LOG_COPY:-/tmp/qemu-serial.log}"

cleanup() {
    # Written as an explicit if rather than `A && B || C`: that idiom is not
    # if-then-else -- C also runs when A succeeds but B fails -- and here that
    # would silently swallow a kill failure.
    if [[ -n "${QEMU_PID}" ]]; then
        kill "${QEMU_PID}" 2>/dev/null || true
    fi
    if [[ -f "${WORKDIR}/serial.log" ]]; then
        cp "${WORKDIR}/serial.log" "${SERIAL_LOG_COPY}" 2>/dev/null || true
    fi
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

VARS="${WORKDIR}/vars.fd"
LOG="${WORKDIR}/serial.log"
FIFO="${WORKDIR}/stdin"

# A pristine varstore has no PK, so the firmware comes up in Setup Mode, which
# is what the enrollment path requires.
cp "${OVMF_VARS}" "${VARS}"
mkfifo "${FIFO}"

echo "=== SB-ENEMA QEMU enrollment test ==="
echo "  image:    ${IMAGE}"
echo "  firmware: ${OVMF_CODE}"
echo

# strip ANSI escapes and CRs so patterns match plain text
clean_log() { sed 's/\x1b\[[0-9;]*[A-Za-z]//g' "${LOG}" 2>/dev/null | tr -d '\r'; }

wait_for() {
    local pattern="$1" timeout="$2" label="$3" waited=0
    while [[ "${waited}" -lt "${timeout}" ]]; do
        if clean_log | grep -qaE "${pattern}"; then
            return 0
        fi
        if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
            echo "FAIL: qemu exited while waiting for ${label}" >&2
            return 1
        fi
        sleep 2
        waited=$((waited + 2))
    done
    echo "FAIL: timed out after ${timeout}s waiting for ${label}" >&2
    return 1
}

send() { printf '%s\n' "$1" > "${FIFO}"; }

qemu-system-x86_64 \
    -machine q35 -m 1024 \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF_CODE}" \
    -drive if=pflash,format=raw,file="${VARS}" \
    -drive if=none,id=usbdisk,file="${IMAGE}",format=raw \
    -device qemu-xhci,id=xhci \
    -device usb-storage,bus=xhci.0,drive=usbdisk \
    -boot order=d -serial mon:stdio -display none -no-reboot \
    < "${FIFO}" > "${LOG}" 2>&1 &
QEMU_PID=$!

# Hold the FIFO open for the lifetime of the run, otherwise the first write
# closes it and qemu sees EOF on stdin.
exec 3>"${FIFO}"

if wait_for 'Run /init as init process' "${BOOT_TIMEOUT}" "kernel to reach userspace"; then
    pass "Image boots: kernel reached userspace"
else
    fail "Image did not boot"; clean_log | tail -30 >&2; exit 1
fi

if clean_log | grep -qa 'Linux version 6\.18\.'; then
    pass "Running the pinned 6.18.x kernel"
else
    fail "Unexpected kernel version"; clean_log | grep -a 'Linux version' >&2
fi

# The serial line gets a plain shell (see rootfs-overlay/root/.profile), so the
# tool is started explicitly in CLI mode -- deterministic, no menu navigation.
wait_for 'sb-enema login|# $|~#' 60 "serial login" || true
sleep 2
send ""
sleep 2
send "sb-enema full-colonic"

if wait_for 'Apply these changes' "${ENROLL_TIMEOUT}" "enrollment preview"; then
    pass "Custom enrollment staged and preview shown"
else
    fail "Never reached the confirmation prompt"; clean_log | tail -40 >&2; exit 1
fi

send "y"

if wait_for 'Enrollment complete' "${ENROLL_TIMEOUT}" "enrollment to complete"; then
    pass "Enrollment reported complete"
else
    fail "Enrollment did not complete"; clean_log | tail -40 >&2; exit 1
fi

for var in db dbx KEK PK; do
    if clean_log | grep -qaE "action=ENROLL target=${var} status=(WRITE_OK|VERIFIED)"; then
        pass "${var} written"
    else
        fail "${var} was not written"
    fi
done

for var in KEK PK; do
    if clean_log | grep -qaE "action=ENROLL target=${var} status=VERIFIED"; then
        pass "${var} verified by read-back from efivarfs"
    else
        fail "${var} was not verified after write"
    fi
done

# Let the varstore settle, then stop the VM before inspecting it.
sleep 3
kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
QEMU_PID=""
exec 3>&-

# ---------------------------------------------------------------------------
# Verify the firmware variable store itself, rather than trusting the log.
#
# The certificates are searched for by their exact DER encoding. This is the
# assertion that actually protects the certificate policy: if a change filters
# one of these out again, it is absent here regardless of what the tool logged.
# ---------------------------------------------------------------------------
echo
echo "--- Enrolled variable store contents ---"

if VERIFY=$(python3 - "${VARS}" "${REPO_ROOT}/third_party/secureboot_objects/PreSignedObjects" <<'PYEOF'
import pathlib, sys

store = pathlib.Path(sys.argv[1]).read_bytes()
presigned = pathlib.Path(sys.argv[2])

expected = {
    "db": [
        ("Windows UEFI CA 2023",               "DB/Certificates/windows uefi ca 2023.der"),
        ("Microsoft UEFI CA 2023",             "DB/Certificates/microsoft uefi ca 2023.der"),
        ("Microsoft Option ROM UEFI CA 2023",  "DB/Certificates/microsoft option rom uefi ca 2023.der"),
        ("Microsoft Windows Production PCA 2011", "DB/Certificates/MicWinProPCA2011_2011-10-19.der"),
        ("Microsoft Corporation UEFI CA 2011", "DB/Certificates/MicCorUEFCA2011_2011-06-27.der"),
    ],
    "KEK": [
        ("Microsoft Corporation KEK 2K CA 2023", "KEK/Certificates/microsoft corporation kek 2k ca 2023.der"),
        ("Microsoft Corporation KEK CA 2011",    "KEK/Certificates/MicCorKEKCA2011_2011-06-24.der"),
    ],
}

missing = 0
for variable, entries in expected.items():
    for name, relpath in entries:
        path = presigned / relpath
        if not path.is_file():
            print(f"MISSING-SOURCE {variable} {name}")
            missing += 1
            continue
        if path.read_bytes() in store:
            print(f"PRESENT {variable} {name}")
        else:
            print(f"ABSENT {variable} {name}")
            missing += 1

sys.exit(1 if missing else 0)
PYEOF
); then
    echo "${VERIFY}" | while read -r status var name; do
        pass "${var}: ${name} enrolled"
    done
    PASS_COUNT=$((PASS_COUNT + $(echo "${VERIFY}" | wc -l)))
else
    echo "${VERIFY}"
    while read -r status var name; do
        [[ "${status}" == "PRESENT" ]] || fail "${var}: ${name} NOT enrolled (${status})"
    done <<< "${VERIFY}"
fi

echo
echo "=== Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
[[ "${FAIL_COUNT}" -eq 0 ]]
