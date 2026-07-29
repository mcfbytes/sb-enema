#!/usr/bin/env bash
# test-bios-entries.sh — Regression tests for stage_bios_entries().
#
# Background
# ----------
# stage_bios_entries() preserves the OEM's factory Secure Boot certificates —
# the ones firmware keeps in the read-only KEKDefault/dbDefault variables — so
# that re-provisioning does not silently destroy OEM recovery tooling (HP Sure
# Recover, Dell SupportAssist OS Recovery, Lenovo UEFI diagnostics) or the
# signatures on OEM option ROMs.
#
# It used to gate every candidate certificate on its SHA-1 appearing as a key in
# kek_update_map.json. That was a type error: the map is keyed on *Platform Key*
# fingerprints (one entry per OEM platform, mapping a vendor PK to that
# platform's KEK update package), while the certificates being tested are
# KEKDefault/dbDefault members — KEK and db certificates, not PKs. They
# essentially never appear as keys, so the gate discarded nearly every OEM
# certificate and the operation became a near no-op.
#
# Validates:
#   1. A genuine vendor certificate is staged even though its fingerprint is
#      absent from kek_update_map.json (the regression).
#   2. Known test/placeholder certificates are still rejected.
#   3. Microsoft-owned certificates are still skipped (handled elsewhere).
#   4. KEKDefault certs land under PAYLOAD_DIR/KEK, dbDefault under .../db.
#
# Usage:
#   bash scripts/test-bios-entries.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export SB_ENEMA_LIB_DIR="${REPO_ROOT}/sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema"
export CERTDB_DIR="${SB_ENEMA_LIB_DIR}/known-certs"

SUBMODULE="${REPO_ROOT}/third_party/secureboot_objects"

PASS_COUNT=0
FAIL_COUNT=0
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

for tool in openssl jq; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "SKIP: ${tool} not available"; exit 0; }
done
[[ -d "${SUBMODULE}/PreSignedObjects" ]] || { echo "SKIP: submodule not checked out"; exit 0; }

MOCK_EFIVARS="$(mktemp -d)"
MOCK_DATA="$(mktemp -d)"
FIXTURES="$(mktemp -d)"
trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}" "${FIXTURES}"' EXIT

export EFIVARS_DIR="${MOCK_EFIVARS}"
export DATA_MOUNT="${MOCK_DATA}"

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
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/update.sh
source "${SB_ENEMA_LIB_DIR}/update.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/preview.sh
source "${SB_ENEMA_LIB_DIR}/preview.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/report.sh
source "${SB_ENEMA_LIB_DIR}/report.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/keygen.sh
source "${SB_ENEMA_LIB_DIR}/keygen.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/stage.sh
source "${SB_ENEMA_LIB_DIR}/stage.sh"

log_init

echo "=== SB-ENEMA stage_bios_entries test ==="
echo

# A realistic vendor certificate: self-signed, not in kek_update_map.json, not
# a known test PK, not Microsoft-owned. Exactly the case the old gate dropped.
openssl req -new -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -subj "/CN=Example OEM Platform Certificate" \
    -keyout "${FIXTURES}/vendor.key" -outform DER -out "${FIXTURES}/vendor.der" >/dev/null 2>&1

VENDOR_SHA1=$(openssl x509 -in "${FIXTURES}/vendor.der" -inform DER -noout -fingerprint -sha1 | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')

# A known Microsoft db cert, which must still be skipped.
cp "${SUBMODULE}/PreSignedObjects/DB/Certificates/windows uefi ca 2023.der" "${FIXTURES}/microsoft.der"

# A known test PK from the shipped deny-list, which must still be rejected.
TEST_PK_FP=$(grep -oE '^[0-9a-f]{64}' "${CERTDB_DIR}/known-test-pks.txt" | head -1)

# kek_update_map.json is required by the platform-recognition step; give it a
# real one with an unrelated key so the vendor cert is definitively absent.
mkdir -p "${MOCK_DATA}/sb-enema"
printf '{"0000000000000000000000000000000000000000":{"KEKUpdate":"Nobody/none.bin"}}\n' \
    > "${MOCK_DATA}/sb-enema/kek_update_map.json"
KEK_UPDATE_MAP="${MOCK_DATA}/sb-enema/kek_update_map.json"

if jq -e --arg k "${VENDOR_SHA1}" 'has($k)' "${KEK_UPDATE_MAP}" >/dev/null 2>&1; then
    fail "fixture error: vendor cert unexpectedly present in the map"
else
    pass "Fixture: vendor certificate is absent from kek_update_map.json"
fi

# Stub the firmware read: KEKDefault gets the vendor cert, dbDefault gets the
# vendor cert plus a Microsoft cert.
efivar_extract_certs() {
    local varname="$1" outdir="$2"
    mkdir -p "${outdir}"
    case "${varname}" in
        KEKDefault)
            cp "${FIXTURES}/vendor.der" "${outdir}/KEKDefault-0.der"
            ;;
        dbDefault)
            cp "${FIXTURES}/vendor.der"    "${outdir}/dbDefault-0.der"
            cp "${FIXTURES}/microsoft.der" "${outdir}/dbDefault-1.der"
            ;;
        PK|PKDefault)
            return 1  # unrecognised platform; must not block staging
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}

# Force the test-PK deny-list to match our vendor cert only in test 2.
_orig_certdb_is_test_pk() { return 1; }
certdb_is_test_pk() { _orig_certdb_is_test_pk "$@"; }

rm -rf "${PAYLOAD_DIR}"
stage_bios_entries >/dev/null 2>&1 || true

echo
echo "--- Test 1: a genuine vendor certificate is preserved ---"

if compgen -G "${PAYLOAD_DIR}/KEK/default-KEKDefault-*.der" >/dev/null; then
    pass "KEKDefault vendor certificate staged despite being absent from the map"
else
    fail "KEKDefault vendor certificate was discarded — the map is keyed on PKs, not KEK members"
fi

if compgen -G "${PAYLOAD_DIR}/db/default-dbDefault-*.der" >/dev/null; then
    pass "dbDefault vendor certificate staged despite being absent from the map"
else
    fail "dbDefault vendor certificate was discarded"
fi

echo
echo "--- Test 2: Microsoft-owned certificates are skipped ---"

ms_staged=0
for f in "${PAYLOAD_DIR}/db"/default-dbDefault-*.der; do
    [[ -f "${f}" ]] || continue
    if cmp -s "${f}" "${FIXTURES}/microsoft.der"; then
        ms_staged=1
    fi
done
if [[ "${ms_staged}" -eq 0 ]]; then
    pass "Microsoft certificate in dbDefault was not staged"
else
    fail "Microsoft certificate was staged; it should be handled by stage_microsoft_kek_db_dbx"
fi

echo
echo "--- Test 3: known test/placeholder certificates are rejected ---"

if [[ -z "${TEST_PK_FP}" ]]; then
    echo "SKIP: no fingerprints in known-test-pks.txt"
else
    # Treat the vendor cert as a known test PK for this pass only.
    _orig_certdb_is_test_pk() { return 0; }
    rm -rf "${PAYLOAD_DIR}"
    stage_bios_entries >/dev/null 2>&1 || true

    if compgen -G "${PAYLOAD_DIR}/KEK/default-KEKDefault-*.der" >/dev/null; then
        fail "A certificate on the test/placeholder deny-list was staged"
    else
        pass "Test/placeholder certificate rejected"
    fi
    _orig_certdb_is_test_pk() { return 1; }
fi

echo
echo "=== Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
[[ "${FAIL_COUNT}" -eq 0 ]]
