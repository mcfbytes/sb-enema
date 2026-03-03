#!/usr/bin/env bash
# test-enroll-custom.sh — Test _custom_load_or_generate_owner_guid() in a
# local mock environment.
#
# Validates three scenarios:
#   1. No owner-guid.txt file — a new UUID must be generated and persisted.
#   2. owner-guid.txt with a valid UUID — that UUID must be loaded unchanged.
#   3. owner-guid.txt with an invalid value — a new UUID must be generated.
#
# Requirements on the host:
#   - bash 4+
#   - /proc/sys/kernel/random/uuid  (available on any Linux 2.6+ kernel)
#
# Usage:
#   bash scripts/test-enroll-custom.sh
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
# update.sh defines PAYLOAD_DIR which enroll-custom.sh references at source time
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/update.sh
source "${SB_ENEMA_LIB_DIR}/update.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/preview.sh
source "${SB_ENEMA_LIB_DIR}/preview.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/report.sh
source "${SB_ENEMA_LIB_DIR}/report.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/enroll-custom.sh
source "${SB_ENEMA_LIB_DIR}/enroll-custom.sh"

log_init

echo "=== SB-ENEMA _custom_load_or_generate_owner_guid test ==="
echo

# UUID format regex (8-4-4-4-12 hex digits, case-insensitive)
UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

GUID_FILE="${DATA_MOUNT}/sb-enema/owner-guid.txt"

# ---------------------------------------------------------------------------
# Test 1: No owner-guid.txt — a new UUID must be generated and persisted.
# ---------------------------------------------------------------------------
echo "--- Test 1: no owner-guid.txt — generate and persist ---"

rm -f "${GUID_FILE}"

guid1=$(_custom_load_or_generate_owner_guid)

if [[ "${guid1}" =~ ${UUID_RE} ]]; then
    pass "Generated UUID has correct format: ${guid1}"
else
    fail "Generated UUID has incorrect format: '${guid1}'"
fi

if [[ -f "${GUID_FILE}" ]]; then
    pass "owner-guid.txt was created at ${GUID_FILE}"
else
    fail "owner-guid.txt was not created"
fi

persisted=$(tr -d '[:space:]' < "${GUID_FILE}")
if [[ "${persisted}" == "${guid1}" ]]; then
    pass "Persisted UUID matches the returned value"
else
    fail "Persisted UUID '${persisted}' does not match returned value '${guid1}'"
fi

# ---------------------------------------------------------------------------
# Test 2: Valid owner-guid.txt — that UUID must be loaded unchanged.
# ---------------------------------------------------------------------------
echo "--- Test 2: valid owner-guid.txt — load without regeneration ---"

KNOWN_GUID="deadbeef-1234-5678-9abc-def012345678"
printf '%s\n' "${KNOWN_GUID}" > "${GUID_FILE}"

guid2=$(_custom_load_or_generate_owner_guid)

if [[ "${guid2}" == "${KNOWN_GUID}" ]]; then
    pass "Loaded UUID matches the file contents: ${guid2}"
else
    fail "Loaded UUID '${guid2}' does not match expected '${KNOWN_GUID}'"
fi

# Confirm the file was not overwritten
still_on_disk=$(tr -d '[:space:]' < "${GUID_FILE}")
if [[ "${still_on_disk}" == "${KNOWN_GUID}" ]]; then
    pass "owner-guid.txt was not overwritten"
else
    fail "owner-guid.txt was overwritten; expected '${KNOWN_GUID}', got '${still_on_disk}'"
fi

# ---------------------------------------------------------------------------
# Test 3: Invalid owner-guid.txt — a new UUID must be generated.
# ---------------------------------------------------------------------------
echo "--- Test 3: invalid owner-guid.txt — regenerate ---"

printf 'not-a-valid-guid\n' > "${GUID_FILE}"

guid3=$(_custom_load_or_generate_owner_guid)

if [[ "${guid3}" =~ ${UUID_RE} ]]; then
    pass "Regenerated UUID has correct format: ${guid3}"
else
    fail "Regenerated UUID has incorrect format: '${guid3}'"
fi

# The new UUID must differ from the invalid placeholder
if [[ "${guid3}" != "not-a-valid-guid" ]]; then
    pass "Regenerated UUID replaced the invalid placeholder"
else
    fail "Regenerated UUID still equals the invalid placeholder"
fi

# The file must now contain the new valid UUID
new_on_disk=$(tr -d '[:space:]' < "${GUID_FILE}")
if [[ "${new_on_disk}" == "${guid3}" ]]; then
    pass "owner-guid.txt updated with the regenerated UUID"
else
    fail "owner-guid.txt contains '${new_on_disk}' but expected '${guid3}'"
fi

# ---------------------------------------------------------------------------
# Tests for _custom_build_db_esl() — DER and PEM certificate handling
# ---------------------------------------------------------------------------
echo "--- Test 4: _custom_build_db_esl converts .der/.cer to PEM before ESL conversion ---"

if command -v openssl >/dev/null 2>&1; then
    # Set up mock work/payload directories; clean up at script exit (not RETURN,
    # which would fire on every function return due to bash RETURN trap semantics).
    MOCK_DB_WORKDIR="$(mktemp -d)"
    MOCK_DB_PAYLOADS="$(mktemp -d)"
    # Extend the existing EXIT trap to also remove the new dirs.
    trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}" "${MOCK_DB_WORKDIR}" "${MOCK_DB_PAYLOADS}"' EXIT

    # Generate a temporary test certificate (PEM)
    TEMP_KEY="${MOCK_DB_WORKDIR}/test.key"
    TEMP_CRT="${MOCK_DB_WORKDIR}/test.crt"
    openssl req -new -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
        -subj "/CN=SB-ENEMA Test" \
        -keyout "${TEMP_KEY}" -out "${TEMP_CRT}" 2>/dev/null

    # Create DER-encoded versions (.der and .cer) and a PEM copy (.crt)
    mkdir -p "${MOCK_DB_PAYLOADS}/db"
    openssl x509 -in "${TEMP_CRT}" -outform DER -out "${MOCK_DB_PAYLOADS}/db/test-cert.der"
    openssl x509 -in "${TEMP_CRT}" -outform DER -out "${MOCK_DB_PAYLOADS}/db/test-cert.cer"
    cp "${TEMP_CRT}" "${MOCK_DB_PAYLOADS}/db/test-cert.crt"

    # Stub cert-to-efi-sig-list: verify input is PEM, write a placeholder ESL.
    # Log paths are passed via exported env vars so the stub can find them even
    # though bash functions do not inherit local variables from caller scope.
    export _STUB_CALLS_LOG="${MOCK_DB_WORKDIR}/calls.log"
    export _STUB_ERRORS_LOG="${MOCK_DB_WORKDIR}/errors.log"
    : > "${_STUB_CALLS_LOG}"
    : > "${_STUB_ERRORS_LOG}"

    cert-to-efi-sig-list() {
        # Parse args: [-g guid] <crt_file> <esl_file>
        local crt_file="" esl_file=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -g) shift 2 ;;
                *)
                    if [[ -z "${crt_file}" ]]; then
                        crt_file="$1"
                    else
                        esl_file="$1"
                    fi
                    shift
                    ;;
            esac
        done
        # Verify the input file is PEM format (begins with "-----BEGIN")
        if ! head -c 11 "${crt_file}" | grep -qF -- "-----BEGIN"; then
            printf 'non-PEM input: %s\n' "${crt_file}" >> "${_STUB_ERRORS_LOG}"
        fi
        printf '%s\n' "${crt_file}" >> "${_STUB_CALLS_LOG}"
        # Write a minimal non-empty placeholder so the combined ESL is non-empty
        printf '\x00' > "${esl_file}"
    }
    export -f cert-to-efi-sig-list

    export CUSTOM_OWNER_GUID="deadbeef-1234-5678-9abc-def012345678"
    export CUSTOM_PAYLOADS_DIR="${MOCK_DB_PAYLOADS}"

    _custom_build_db_esl "${MOCK_DB_WORKDIR}"

    # No format errors should have occurred (all inputs must be PEM)
    if [[ ! -s "${_STUB_ERRORS_LOG}" ]]; then
        pass "_custom_build_db_esl: no DER/CER files passed raw to cert-to-efi-sig-list"
    else
        fail "_custom_build_db_esl: DER/CER file(s) passed without PEM conversion:"
        cat "${_STUB_ERRORS_LOG}" >&2
    fi

    # All three certs should have been processed
    call_count=$(wc -l < "${_STUB_CALLS_LOG}")
    if [[ "${call_count}" -eq 3 ]]; then
        pass "_custom_build_db_esl: cert-to-efi-sig-list called for all 3 certificates"
    else
        fail "_custom_build_db_esl: expected 3 cert-to-efi-sig-list calls, got ${call_count}"
    fi

    # Combined ESL must be non-empty
    if [[ -s "${MOCK_DB_WORKDIR}/db.esl" ]]; then
        pass "_custom_build_db_esl: combined db.esl is non-empty"
    else
        fail "_custom_build_db_esl: combined db.esl is empty or missing"
    fi

    unset -f cert-to-efi-sig-list
    unset _STUB_CALLS_LOG _STUB_ERRORS_LOG
else
    echo "SKIP: openssl not available; skipping _custom_build_db_esl tests"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi
