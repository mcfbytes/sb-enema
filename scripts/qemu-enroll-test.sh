#!/usr/bin/env bash
# qemu-enroll-test.sh — Boot the built image under OVMF and run real enrollments,
# then verify the firmware variable store actually contains the certificates we
# intended to enroll.
#
# Why this exists
# ---------------
# The scripts/test-*.sh suite exercises the staging logic with stubs. It cannot
# catch a failure in the parts that only exist on real firmware: efivarfs, the
# authenticated-variable write path in efi-updatevar, the kernel actually
# booting with the pinned config, or the enrollment order (db -> dbx -> KEK ->
# PK). This does, end to end.
#
# It also directly guards the certificate policy this project exists to get
# right: it asserts that "Microsoft Windows Production PCA 2011" and "Microsoft
# Corporation KEK CA 2011" are present in the enrolled variables, so a
# regression that filters them out again fails here even if it somehow slips
# past the unit tests.
#
# Scenarios
# ---------
#   custom-owned     full-colonic          user PK/KEK + Microsoft db/dbx
#   microsoft-chain  microsoft-suppository Microsoft KEK/db/dbx, PK untouched
#
# The Microsoft-owned PK (`microsoft-colonic`) is deliberately NOT covered, and
# cannot be: OVMF enforces a self-signed-PK requirement in Setup Mode, so the
# payload must be signed by the private key of the certificate inside it.  That
# key is Microsoft's.  See docs/microsoft-pk-ovmf.md for the measurements.
# microsoft-suppository exercises the identical Microsoft payload chain for
# KEK/db/dbx, which is the part that carries the certificate policy.
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
#   make                                  # build the image first
#   bash scripts/qemu-enroll-test.sh      # both scenarios
#   SCENARIOS=custom-owned bash scripts/qemu-enroll-test.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE="${IMAGE:-${REPO_ROOT}/output/br-out/images/sb-enema.img}"
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-120}"
ENROLL_TIMEOUT="${ENROLL_TIMEOUT:-240}"
SCENARIOS="${SCENARIOS:-custom-owned microsoft-chain}"
PRESIGNED="${REPO_ROOT}/third_party/secureboot_objects/PreSignedObjects"

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
if [[ ! -d "${PRESIGNED}" ]]; then
    echo "FAIL: secureboot_objects submodule not checked out" >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
QEMU_PID=""

# Preserve the serial logs outside the temp dir so CI can upload them when this
# fails; a failure here is otherwise very hard to diagnose after the fact.
SERIAL_LOG_COPY="${SERIAL_LOG_COPY:-/tmp/qemu-serial.log}"

cleanup() {
    if [[ -n "${QEMU_PID}" ]]; then
        kill "${QEMU_PID}" 2>/dev/null || true
    fi
    if compgen -G "${WORKDIR}/*.log" >/dev/null; then
        cat "${WORKDIR}"/*.log > "${SERIAL_LOG_COPY}" 2>/dev/null || true
    fi
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

echo "=== SB-ENEMA QEMU enrollment test ==="
echo "  image:     ${IMAGE}"
echo "  firmware:  ${OVMF_CODE}"
echo "  scenarios: ${SCENARIOS}"

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

# ---------------------------------------------------------------------------
# run_scenario <name> <cli-operation> <variables-expected-to-be-written...>
#   Boots a fresh Setup Mode machine, runs the operation, and asserts on the
#   tool's own audit log.  Leaves the resulting variable store at ${VARS} for
#   the caller to inspect independently.
# ---------------------------------------------------------------------------
run_scenario() {
    local name="$1" operation="$2"
    shift 2
    local expected_vars=("$@")

    VARS="${WORKDIR}/${name}-vars.fd"
    LOG="${WORKDIR}/${name}-serial.log"
    FIFO="${WORKDIR}/${name}-stdin"

    # A pristine varstore has no PK, so the firmware comes up in Setup Mode,
    # which is what the enrollment path requires.
    cp "${OVMF_VARS}" "${VARS}"
    mkfifo "${FIFO}"

    echo
    echo "--- Scenario: ${name} (sb-enema ${operation}) ---"

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
        pass "${name}: image boots, kernel reached userspace"
    else
        fail "${name}: image did not boot"
        clean_log | tail -30 >&2
        exec 3>&-
        return 1
    fi

    if clean_log | grep -qa 'Linux version 6\.18\.'; then
        pass "${name}: running the pinned 6.18.x kernel"
    else
        fail "${name}: unexpected kernel version"
        clean_log | grep -a 'Linux version' >&2
    fi

    # The serial line gets a plain shell (see rootfs-overlay/root/.profile), so
    # the tool is started explicitly in CLI mode -- deterministic, no menu
    # navigation.
    wait_for 'sb-enema login|# $|~#' 60 "serial login" || true
    sleep 2
    send ""
    sleep 2
    send "sb-enema ${operation}"

    if wait_for 'Apply these changes' "${ENROLL_TIMEOUT}" "enrollment preview"; then
        pass "${name}: enrollment staged and preview shown"
    else
        fail "${name}: never reached the confirmation prompt"
        clean_log | tail -40 >&2
        exec 3>&-
        return 1
    fi

    send "y"

    if wait_for 'Enrollment complete' "${ENROLL_TIMEOUT}" "enrollment to complete"; then
        pass "${name}: enrollment reported complete"
    else
        fail "${name}: enrollment did not complete"
        clean_log | tail -40 >&2
        exec 3>&-
        return 1
    fi

    local var
    for var in "${expected_vars[@]}"; do
        if clean_log | grep -qaE "action=ENROLL target=${var} status=(WRITE_OK|VERIFIED)"; then
            pass "${name}: ${var} written"
        else
            fail "${name}: ${var} was not written"
        fi
    done

    # Let the varstore settle, then stop the VM before inspecting it.
    sleep 3
    kill "${QEMU_PID}" 2>/dev/null || true
    wait "${QEMU_PID}" 2>/dev/null || true
    QEMU_PID=""
    exec 3>&-
}

# ---------------------------------------------------------------------------
# verify_store <name> <varstore> <expect-pk: yes|no>
#   Inspect the firmware variable store itself rather than trusting the log.
#   Certificates are searched for by their exact DER encoding, so a change that
#   filters one out is caught here regardless of what the tool reported.
# ---------------------------------------------------------------------------
verify_store() {
    local name="$1" store="$2" expect_pk="$3"
    local report

    # The helper's exit status only summarises what its per-line output already
    # says, and each line is turned into its own assertion below, so a non-zero
    # status here is expected and deliberately not treated as fatal.
    report=$(python3 - "${store}" "${PRESIGNED}" "${expect_pk}" <<'PYEOF'
import pathlib, sys

store = pathlib.Path(sys.argv[1]).read_bytes()
presigned = pathlib.Path(sys.argv[2])
expect_pk = sys.argv[3] == "yes"

expected = [
    ("db",  "Windows UEFI CA 2023",                  "DB/Certificates/windows uefi ca 2023.der"),
    ("db",  "Microsoft UEFI CA 2023",                "DB/Certificates/microsoft uefi ca 2023.der"),
    ("db",  "Microsoft Option ROM UEFI CA 2023",     "DB/Certificates/microsoft option rom uefi ca 2023.der"),
    ("db",  "Microsoft Windows Production PCA 2011", "DB/Certificates/MicWinProPCA2011_2011-10-19.der"),
    ("db",  "Microsoft Corporation UEFI CA 2011",    "DB/Certificates/MicCorUEFCA2011_2011-06-27.der"),
    ("KEK", "Microsoft Corporation KEK 2K CA 2023",  "KEK/Certificates/microsoft corporation kek 2k ca 2023.der"),
    ("KEK", "Microsoft Corporation KEK CA 2011",     "KEK/Certificates/MicCorKEKCA2011_2011-06-24.der"),
]

problems = 0
for variable, name, relpath in expected:
    path = presigned / relpath
    if not path.is_file():
        print(f"MISSING-SOURCE|{variable}|{name}")
        problems += 1
        continue
    if path.read_bytes() in store:
        print(f"PRESENT|{variable}|{name}")
    else:
        print(f"ABSENT|{variable}|{name}")
        problems += 1

# The Microsoft PK is only expected on a path that enrolls it. Asserting its
# ABSENCE on the suppository path is the point: that path must leave PK alone.
#
# A missing source file is a failure, not a reason to skip: silently dropping
# the assertion would let an incomplete submodule turn this check into a no-op,
# which is exactly the failure mode the rest of this script exists to prevent.
pk = presigned / "PK/Certificate/WindowsOEMDevicesPK.der"
if not pk.is_file():
    print("MISSING-SOURCE|PK|Microsoft PK certificate not found in the submodule")
    problems += 1
else:
    found = pk.read_bytes() in store
    if found == expect_pk:
        print(f"PRESENT|PK|Microsoft PK {'enrolled' if found else 'correctly left untouched'}")
    else:
        print(f"ABSENT|PK|Microsoft PK {'missing' if expect_pk else 'was enrolled but should not have been'}")
        problems += 1

sys.exit(1 if problems else 0)
PYEOF
    ) || true

    while IFS='|' read -r status variable detail; do
        [[ -n "${status}" ]] || continue
        if [[ "${status}" == "PRESENT" ]]; then
            pass "${name}: ${variable}: ${detail}"
        else
            fail "${name}: ${variable}: ${detail} (${status})"
        fi
    done <<< "${report}"

    return 0
}

for scenario in ${SCENARIOS}; do
    case "${scenario}" in
        custom-owned)
            run_scenario custom-owned full-colonic db dbx KEK PK || true
            # This path generates its own PK, so Microsoft's must NOT appear.
            verify_store custom-owned "${WORKDIR}/custom-owned-vars.fd" no
            LOG="${WORKDIR}/custom-owned-serial.log"
            for var in KEK PK; do
                if clean_log | grep -qaE "action=ENROLL target=${var} status=VERIFIED"; then
                    pass "custom-owned: ${var} verified by read-back from efivarfs"
                else
                    fail "custom-owned: ${var} was not verified after write"
                fi
            done
            ;;
        microsoft-chain)
            # Microsoft's own pre-signed KEK/db/dbx payloads, PK left alone.
            run_scenario microsoft-chain microsoft-suppository db dbx KEK || true
            verify_store microsoft-chain "${WORKDIR}/microsoft-chain-vars.fd" no
            ;;
        *)
            fail "unknown scenario: ${scenario}"
            ;;
    esac
done

echo
echo "=== Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
[[ "${FAIL_COUNT}" -eq 0 ]]
