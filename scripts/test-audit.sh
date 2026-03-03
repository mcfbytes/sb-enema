#!/usr/bin/env bash
# test-audit.sh — Run the SB-ENEMA audit and report in a local mock environment.
#
# This script does not need root access, a USB drive, or EFI hardware.
# It creates a temporary mock environment that redirects all EFI variable and
# data-partition paths to harmless temporary directories, allowing the audit
# and report logic to be exercised on any Linux machine.
#
# Requirements on the host:
#   - bash 4+
#   - openssl  (for certificate parsing; available on most distros)
#   - efi-readvar (from efitools) — optional; certificate extraction is skipped
#     gracefully when absent and findings are reported at WARNING level.
#
# Usage:
#   bash scripts/test-audit.sh [SCENARIO]
#
# Scenarios:
#   setup-mode  (default) All Secure Boot variables absent — simulates a
#               machine in UEFI Setup Mode with no keys enrolled.
#   with-vars             Stub EFI variable files are created so that
#               efivar_is_empty() returns false for PK/KEK/db/dbx; the
#               variable payloads are not valid EFI Signature Lists so
#               certificate extraction will fail gracefully.
#   secure-boot-on        SecureBoot byte is 0x03 (bit 0 set plus reserved bits)
#               to verify that the bit-mask check correctly detects enabled.
#   secure-boot-off       SecureBoot byte is 0x06 (bit 0 clear, other bits set)
#               to verify that the bit-mask check correctly detects disabled.
#   setup-mode-on         SetupMode byte is 0x01 (bit 0 set), matching the exact
#               QEMU case from the bug report (attrs=0x06, value=0x01).
#   setup-mode-off        SetupMode byte is 0x06 (bit 0 clear, other bits set)
#               to verify that Setup Mode is correctly reported as inactive.
#   efivar-is-empty       Verify efivar_is_empty() correctly reports non-empty
#               for variables whose files have a payload beyond the 4-byte
#               attribute header.  This validates the read-based check used
#               to work around kernels where stat(2) returns 0 for efivarfs.
#   extract-certs         Build a synthetic EFI_SIGNATURE_LIST binary containing
#               a real X509 cert and verify that efivar_extract_certs() correctly
#               parses the binary ESL and extracts the DER cert with matching
#               fingerprint.
#
# Examples:
#   bash scripts/test-audit.sh
#   bash scripts/test-audit.sh setup-mode
#   bash scripts/test-audit.sh with-vars
#   bash scripts/test-audit.sh secure-boot-on
#   bash scripts/test-audit.sh secure-boot-off
#   bash scripts/test-audit.sh setup-mode-on
#   bash scripts/test-audit.sh setup-mode-off
#   bash scripts/test-audit.sh efivar-is-empty
#   bash scripts/test-audit.sh extract-certs
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Point SB_ENEMA_LIB_DIR at the in-tree library files.
# audit.sh and report.sh check ${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema} for
# their internal source calls, so setting this env var is all that is needed
# to redirect them away from the system-installed path.
# ---------------------------------------------------------------------------
export SB_ENEMA_LIB_DIR="${REPO_ROOT}/sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema"
export CERTDB_DIR="${SB_ENEMA_LIB_DIR}/known-certs"

# ---------------------------------------------------------------------------
# Create temporary directories for mock efivarfs and data partition.
# ---------------------------------------------------------------------------
MOCK_EFIVARS="$(mktemp -d)"
MOCK_DATA="$(mktemp -d)"
trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}"' EXIT

export EFIVARS_DIR="${MOCK_EFIVARS}"
export DATA_MOUNT="${MOCK_DATA}"

# ---------------------------------------------------------------------------
# Populate the mock efivarfs according to the requested scenario.
# ---------------------------------------------------------------------------
SCENARIO="${1:-setup-mode}"

case "${SCENARIO}" in
    setup-mode)
        # No EFI variable files → all variables appear empty.
        # Audit will report: PK empty (Setup Mode), KEK/db/dbx empty (HIGH).
        echo "Scenario: setup-mode — all Secure Boot variables absent"
        ;;
    with-vars)
        # Create minimal stub files (4-byte attribute header + 1-byte payload).
        # efivar_is_empty() checks that size > 4 bytes, so these will be
        # treated as present.  The payload is not a valid EFI Signature List,
        # so certificate extraction will fail with WARNING-level findings.
        EFI_GLOBAL="8be4df61-93ca-11d2-aa0d-00e098032b8c"
        EFI_IMAGES="d719b2cb-3d3a-4596-a3bc-dad00e67656f"
        printf '\x07\x00\x00\x00\x01' > "${MOCK_EFIVARS}/PK-${EFI_GLOBAL}"
        printf '\x07\x00\x00\x00\x01' > "${MOCK_EFIVARS}/KEK-${EFI_GLOBAL}"
        printf '\x07\x00\x00\x00\x01' > "${MOCK_EFIVARS}/db-${EFI_IMAGES}"
        printf '\x07\x00\x00\x00\x01' > "${MOCK_EFIVARS}/dbx-${EFI_IMAGES}"
        printf '\x07\x00\x00\x00\x00' > "${MOCK_EFIVARS}/SecureBoot-${EFI_GLOBAL}"
        printf '\x07\x00\x00\x00\x00' > "${MOCK_EFIVARS}/SetupMode-${EFI_GLOBAL}"
        echo "Scenario: with-vars — stub EFI variable files present (no real certs)"
        ;;
    secure-boot-on)
        # SecureBoot byte is 0x03 (bit 0 set plus a reserved bit), SetupMode 0x00.
        # Validates that the bit-mask check (16#raw & 1) correctly detects
        # Secure Boot as enabled even when extra bits beyond bit 0 are set.
        # (The old string comparison "== 01" would fail for this value.)
        EFI_GLOBAL="8be4df61-93ca-11d2-aa0d-00e098032b8c"
        printf '\x07\x00\x00\x00\x03' > "${MOCK_EFIVARS}/SecureBoot-${EFI_GLOBAL}"
        printf '\x07\x00\x00\x00\x00' > "${MOCK_EFIVARS}/SetupMode-${EFI_GLOBAL}"

        source "${SB_ENEMA_LIB_DIR}/common.sh"
        source "${SB_ENEMA_LIB_DIR}/log.sh"
        source "${SB_ENEMA_LIB_DIR}/efivar.sh"
        result=$(efivar_get_secure_boot_state)
        if [[ "${result}" == "1" ]]; then
            echo "PASS: SecureBoot 0x03 correctly detected as enabled (bit 0 set)"
        else
            echo "FAIL: SecureBoot 0x03 incorrectly reported as disabled" >&2
            exit 1
        fi
        exit 0
        ;;
    secure-boot-off)
        # SecureBoot byte is 0x06 (bit 0 clear, other reserved bits set), SetupMode 0x00.
        # Validates that the bit-mask check (16#raw & 1) correctly reports
        # Secure Boot as disabled when bit 0 is clear, even though the byte is non-zero.
        EFI_GLOBAL="8be4df61-93ca-11d2-aa0d-00e098032b8c"
        printf '\x07\x00\x00\x00\x06' > "${MOCK_EFIVARS}/SecureBoot-${EFI_GLOBAL}"
        printf '\x07\x00\x00\x00\x00' > "${MOCK_EFIVARS}/SetupMode-${EFI_GLOBAL}"

        source "${SB_ENEMA_LIB_DIR}/common.sh"
        source "${SB_ENEMA_LIB_DIR}/log.sh"
        source "${SB_ENEMA_LIB_DIR}/efivar.sh"
        result=$(efivar_get_secure_boot_state)
        if [[ "${result}" == "0" ]]; then
            echo "PASS: SecureBoot 0x06 correctly detected as disabled (bit 0 clear)"
        else
            echo "FAIL: SecureBoot 0x06 incorrectly reported as enabled" >&2
            exit 1
        fi
        exit 0
        ;;
    setup-mode-on)
        # SetupMode byte is 0x01 (bit 0 set); attribute bytes are 0x06 (matching the
        # exact QEMU case from the bug report where od -j4 was returning the attribute
        # byte 0x06 instead of the value byte 0x01).
        # Validates that tail-based byte extraction correctly reads the value byte.
        EFI_GLOBAL="8be4df61-93ca-11d2-aa0d-00e098032b8c"
        printf '\x06\x00\x00\x00\x01' > "${MOCK_EFIVARS}/SetupMode-${EFI_GLOBAL}"

        source "${SB_ENEMA_LIB_DIR}/common.sh"
        source "${SB_ENEMA_LIB_DIR}/log.sh"
        source "${SB_ENEMA_LIB_DIR}/efivar.sh"
        result=$(efivar_get_setup_mode)
        if [[ "${result}" == "1" ]]; then
            echo "PASS: SetupMode 0x01 (attrs=0x06) correctly detected as Setup Mode active"
        else
            echo "FAIL: SetupMode 0x01 incorrectly reported as inactive (bug: od -j4 returned attr byte)" >&2
            exit 1
        fi
        exit 0
        ;;
    setup-mode-off)
        # SetupMode byte is 0x06 (bit 0 clear, other bits set), attribute bytes 0x07.
        # Validates that bit 0 mask correctly reports Setup Mode as inactive even
        # when the value byte is non-zero.
        EFI_GLOBAL="8be4df61-93ca-11d2-aa0d-00e098032b8c"
        printf '\x07\x00\x00\x00\x06' > "${MOCK_EFIVARS}/SetupMode-${EFI_GLOBAL}"

        source "${SB_ENEMA_LIB_DIR}/common.sh"
        source "${SB_ENEMA_LIB_DIR}/log.sh"
        source "${SB_ENEMA_LIB_DIR}/efivar.sh"
        result=$(efivar_get_setup_mode)
        if [[ "${result}" == "0" ]]; then
            echo "PASS: SetupMode 0x06 correctly detected as Setup Mode inactive (bit 0 clear)"
        else
            echo "FAIL: SetupMode 0x06 incorrectly reported as active" >&2
            exit 1
        fi
        exit 0
        ;;
    efivar-is-empty)
        # Verify that efivar_is_empty() correctly detects non-empty variables
        # using the read-based check (tail -c +5 | head -c 1 | wc -c).
        # This exercises the fix for kernels where stat(2) returns 0 for
        # efivarfs files even when the variable has payload content.
        EFI_GLOBAL="8be4df61-93ca-11d2-aa0d-00e098032b8c"
        EFI_IMAGES="d719b2cb-3d3a-4596-a3bc-dad00e67656f"
        # Create stub files with a 4-byte attribute header and 1 payload byte.
        # These simulate an efivarfs file that would look empty to a stat-based
        # check if stat returned 4 (attributes only) but are non-empty by read.
        printf '\x07\x00\x00\x00\x01' > "${MOCK_EFIVARS}/PK-${EFI_GLOBAL}"
        printf '\x07\x00\x00\x00\x01' > "${MOCK_EFIVARS}/KEK-${EFI_GLOBAL}"
        printf '\x07\x00\x00\x00\x01' > "${MOCK_EFIVARS}/db-${EFI_IMAGES}"
        printf '\x07\x00\x00\x00\x01' > "${MOCK_EFIVARS}/dbx-${EFI_IMAGES}"

        source "${SB_ENEMA_LIB_DIR}/common.sh"
        source "${SB_ENEMA_LIB_DIR}/log.sh"
        source "${SB_ENEMA_LIB_DIR}/efivar.sh"

        all_pass=1
        for varname in PK KEK db dbx; do
            if efivar_is_empty "${varname}"; then
                echo "FAIL: efivar_is_empty ${varname} returned empty for a non-empty file" >&2
                all_pass=0
            else
                echo "PASS: efivar_is_empty ${varname} correctly reports non-empty"
            fi
        done

        # Also verify truly-absent variables are reported empty.
        if efivar_is_empty SecureBoot; then
            echo "PASS: efivar_is_empty SecureBoot correctly reports empty (file absent)"
        else
            echo "FAIL: efivar_is_empty SecureBoot reported non-empty for absent file" >&2
            all_pass=0
        fi

        if [[ "${all_pass}" -eq 1 ]]; then
            exit 0
        else
            exit 1
        fi
        ;;
    extract-certs)
        # Verify that efivar_extract_certs() correctly extracts a real X509 DER
        # certificate from a synthetic EFI_SIGNATURE_LIST binary.
        # This directly tests the binary ESL parsing introduced to replace the
        # broken efi-readvar text-output PEM parsing approach.
        #
        # Steps:
        #   1. Generate a real X509 certificate with openssl.
        #   2. Build a valid EFI_SIGNATURE_LIST binary in memory.
        #   3. Write it as a mock efivarfs file (4-byte attribute prefix + ESL).
        #   4. Call efivar_extract_certs and verify the DER cert is extracted.
        #   5. Compare fingerprints to confirm the correct cert was extracted.

        if ! command -v openssl >/dev/null 2>&1; then
            echo "SKIP: openssl not available; skipping extract-certs test"
            exit 0
        fi

        source "${SB_ENEMA_LIB_DIR}/common.sh"
        source "${SB_ENEMA_LIB_DIR}/log.sh"
        source "${SB_ENEMA_LIB_DIR}/efivar.sh"
        log_init

        EXTRACT_WORKDIR="$(mktemp -d)"
        trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}" "${EXTRACT_WORKDIR}"' EXIT

        echo "Scenario: extract-certs — binary ESL parsing"
        echo

        all_pass=1

        # --- Step 1: generate a test certificate ---
        openssl req -new -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
            -subj "/CN=SB-ENEMA Extract Test" \
            -keyout "${EXTRACT_WORKDIR}/test.key" \
            -out "${EXTRACT_WORKDIR}/test.crt" 2>/dev/null

        # Convert to DER (the format embedded in ESL)
        openssl x509 -in "${EXTRACT_WORKDIR}/test.crt" \
            -outform DER -out "${EXTRACT_WORKDIR}/test.der"

        EXPECTED_FP=$(openssl x509 -in "${EXTRACT_WORKDIR}/test.crt" -noout \
            -fingerprint -sha256 2>/dev/null \
            | sed 's/.*Fingerprint=//;s/://g' | tr '[:upper:]' '[:lower:]')

        # --- Step 2: build EFI_SIGNATURE_LIST binary ---
        # Helper: write a uint32 as 4 little-endian bytes using octal escapes.
        _write_u32_le() {
            local v=$1
            local b0 b1 b2 b3
            b0=$(printf '%03o' $((v & 0xff)))
            b1=$(printf '%03o' $(((v >> 8) & 0xff)))
            b2=$(printf '%03o' $(((v >> 16) & 0xff)))
            b3=$(printf '%03o' $(((v >> 24) & 0xff)))
            printf "\\${b0}\\${b1}\\${b2}\\${b3}"
        }

        DER_SIZE=$(wc -c < "${EXTRACT_WORKDIR}/test.der")
        # SignatureSize = 16-byte owner GUID + DER cert
        SIG_SIZE=$((16 + DER_SIZE))
        # SignatureListSize = 28-byte ESL header + SignatureSize (one entry, no header)
        LIST_SIZE=$((28 + SIG_SIZE))

        EFI_GLOBAL="8be4df61-93ca-11d2-aa0d-00e098032b8c"

        {
            # EFI_CERT_X509_GUID (LE): a1 59 c0 a5 e4 94 a7 4a 87 b5 ab 15 5c 2b f0 72
            printf '\xa1\x59\xc0\xa5\xe4\x94\xa7\x4a\x87\xb5\xab\x15\x5c\x2b\xf0\x72'
            _write_u32_le "${LIST_SIZE}"   # SignatureListSize
            _write_u32_le 0               # SignatureHeaderSize = 0
            _write_u32_le "${SIG_SIZE}"   # SignatureSize
            # SignatureOwner GUID (dummy: 07e0c377-e6ac-4623-882f-e63f7ba7e013)
            printf '\x07\xe0\xc3\x77\xe6\xac\x46\x23\x88\x2f\xe6\x3f\x7b\xa7\xe0\x13'
            # DER certificate data
            cat "${EXTRACT_WORKDIR}/test.der"
        } > "${EXTRACT_WORKDIR}/esl_payload.bin"

        # --- Step 3: write mock efivarfs file (4-byte attr prefix + ESL) ---
        {
            printf '\x07\x00\x00\x00'
            cat "${EXTRACT_WORKDIR}/esl_payload.bin"
        } > "${MOCK_EFIVARS}/KEK-${EFI_GLOBAL}"

        # --- Step 4: call efivar_extract_certs ---
        EXTRACT_OUT="${EXTRACT_WORKDIR}/out"
        mkdir -p "${EXTRACT_OUT}"

        if efivar_extract_certs KEK "${EXTRACT_OUT}" 2>/dev/null; then
            echo "PASS: efivar_extract_certs returned 0"
        else
            echo "FAIL: efivar_extract_certs returned non-zero" >&2
            all_pass=0
        fi

        # --- Step 5: verify DER was extracted ---
        if [[ -f "${EXTRACT_OUT}/KEK-0.der" ]]; then
            echo "PASS: KEK-0.der was created by efivar_extract_certs"
        else
            echo "FAIL: KEK-0.der was NOT created — binary ESL parsing failed" >&2
            all_pass=0
        fi

        # --- Step 6: compare fingerprints ---
        if [[ -f "${EXTRACT_OUT}/KEK-0.der" ]]; then
            ACTUAL_FP=$(openssl x509 -in "${EXTRACT_OUT}/KEK-0.der" -inform DER -noout \
                -fingerprint -sha256 2>/dev/null \
                | sed 's/.*Fingerprint=//;s/://g' | tr '[:upper:]' '[:lower:]')

            if [[ "${EXPECTED_FP}" == "${ACTUAL_FP}" ]]; then
                echo "PASS: extracted cert fingerprint matches original (${ACTUAL_FP})"
            else
                echo "FAIL: fingerprint mismatch" >&2
                echo "  Expected: ${EXPECTED_FP}" >&2
                echo "  Actual:   ${ACTUAL_FP}" >&2
                all_pass=0
            fi
        fi

        if [[ "${all_pass}" -eq 1 ]]; then
            exit 0
        else
            exit 1
        fi
        ;;
    *)
        echo "Unknown scenario '${SCENARIO}'. Valid choices: setup-mode (default), with-vars, secure-boot-on, secure-boot-off, setup-mode-on, setup-mode-off, efivar-is-empty, extract-certs" >&2
        exit 1
        ;;
esac
echo

# ---------------------------------------------------------------------------
# Source all required library files from the repository tree.
# The idempotency guards (_SB_ENEMA_*_SH variables) in each file ensure that
# the subsequent source calls inside audit.sh / report.sh do not re-execute
# the file bodies, even though they use hardcoded-fallback paths.
# ---------------------------------------------------------------------------
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/common.sh
source "${SB_ENEMA_LIB_DIR}/common.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/log.sh
source "${SB_ENEMA_LIB_DIR}/log.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/efivar.sh
source "${SB_ENEMA_LIB_DIR}/efivar.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/certdb.sh
source "${SB_ENEMA_LIB_DIR}/certdb.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/audit.sh
source "${SB_ENEMA_LIB_DIR}/audit.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/report.sh
source "${SB_ENEMA_LIB_DIR}/report.sh"

# ---------------------------------------------------------------------------
# Initialize logging to the mock data directory, then run the full report.
# ---------------------------------------------------------------------------
log_init

echo "=== SB-ENEMA local audit (mock environment) ==="
echo

report_full

echo
echo "Log saved to: ${LOG_FILE:-none}"
