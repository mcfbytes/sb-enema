#!/usr/bin/env bash
# test-cert-policy.sh — Regression tests for SB-ENEMA's Secure Boot certificate
# policy.
#
# Background
# ----------
# Earlier revisions filtered two Microsoft certificates out of the Custom-Owned
# enrollment path on the grounds that both expire in 2026:
#
#   * "Microsoft Windows Production PCA 2011" was dropped from db.  It signs the
#     Windows Boot Manager on every installation that has not yet received
#     Microsoft's 2023-signed boot manager, so dropping it leaves a healthy
#     Windows install unbootable under Secure Boot.
#   * "Microsoft Corporation KEK CA 2011" was dropped from KEK.  Every Microsoft
#     Secure Boot servicing package published to date is signed under it, so
#     dropping it means the machine can never apply a Microsoft dbx update.
#
# Neither exclusion was covered by a test, which is why both survived.  These
# tests assert the certificates are present, so a future "cleanup" of expired
# certificates fails loudly instead of shipping a brick.
#
# Validates:
#   1. _stage_build_db_esl includes every Microsoft db certificate shipped in
#      PreSignedObjects — in particular Windows Production PCA 2011.
#   2. _stage_build_kek_esl includes both Microsoft KEKs — in particular
#      KEK CA 2011.
#   3. The SbEnemaRecovery keystore template declares the expected PK/KEK/db set.
#   4. check-secureboot-policy.py accepts a compliant key set and rejects a dbx
#      that revokes a certificate our db depends on.
#
# Requirements on the host:
#   - bash 4+, openssl, python3
#   - third_party/secureboot_objects submodule checked out
#
# Usage:
#   bash scripts/test-cert-policy.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export SB_ENEMA_LIB_DIR="${REPO_ROOT}/sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema"
export CERTDB_DIR="${SB_ENEMA_LIB_DIR}/known-certs"

SUBMODULE="${REPO_ROOT}/third_party/secureboot_objects"
TEMPLATE="${REPO_ROOT}/sb_enema/secureboot-templates/SbEnemaRecovery.toml"
POLICY_CHECK="${REPO_ROOT}/scripts/check-secureboot-policy.py"

# SHA-256 fingerprints of the two certificates whose removal this file guards.
WIN_PCA_2011_FP="e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
KEK_CA_2011_FP="a1117f516a32cefcba3f2d1ace10a87972fd6bbe8fe0d0b996e09e65d802a503"

PASS_COUNT=0
FAIL_COUNT=0
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

for tool in openssl python3; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "SKIP: ${tool} not available; skipping certificate policy tests"
        exit 0
    fi
done

if [[ ! -d "${SUBMODULE}/PreSignedObjects" ]]; then
    echo "SKIP: secureboot_objects submodule not checked out; skipping"
    exit 0
fi

# ---------------------------------------------------------------------------
# Mock environment
# ---------------------------------------------------------------------------
MOCK_EFIVARS="$(mktemp -d)"
MOCK_DATA="$(mktemp -d)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}" "${WORKDIR}"' EXIT

export EFIVARS_DIR="${MOCK_EFIVARS}"
export DATA_MOUNT="${MOCK_DATA}"

# stage.sh reads Microsoft certificates from ${DATA_MOUNT}/PreSignedObjects,
# mirroring what post-image.sh copies onto the data partition.
cp -r "${SUBMODULE}/PreSignedObjects" "${MOCK_DATA}/PreSignedObjects"

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

echo "=== SB-ENEMA certificate policy test ==="
echo

OWNER_GUID="77fa9abd-0359-4d32-bd60-28f4e78f784b"

# Records the fingerprint of every certificate handed to cert-to-efi-sig-list,
# which is exactly the set that ends up in the enrolled ESL.
CONVERTED_FPS="${WORKDIR}/converted-fps.txt"

install_cert_stub() {
    : > "${CONVERTED_FPS}"
    cert-to-efi-sig-list() {
        local cert="" out=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -g) shift 2 ;;
                *)  if [[ -z "${cert}" ]]; then cert="$1"; else out="$1"; fi; shift ;;
            esac
        done
        openssl x509 -in "${cert}" -noout -fingerprint -sha256 2>/dev/null \
            | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z' >> "${CONVERTED_FPS}"
        printf 'stub-esl' > "${out}"
    }
    export -f cert-to-efi-sig-list
}

# ---------------------------------------------------------------------------
# Test 1: db must contain every shipped Microsoft certificate
# ---------------------------------------------------------------------------
echo "--- Test 1: _stage_build_db_esl includes Windows Production PCA 2011 ---"

install_cert_stub
mkdir -p "${PAYLOAD_DIR}/db"
cp "${MOCK_DATA}/PreSignedObjects/DB/Certificates/"*.der "${PAYLOAD_DIR}/db/"

shipped_db_count=$(find "${MOCK_DATA}/PreSignedObjects/DB/Certificates" -name '*.der' | wc -l)

_stage_build_db_esl "${WORKDIR}" "${OWNER_GUID}"

db_converted=$(wc -l < "${CONVERTED_FPS}")
if [[ "${db_converted}" -eq "${shipped_db_count}" ]]; then
    pass "_stage_build_db_esl: all ${shipped_db_count} shipped db certificates enrolled (none filtered)"
else
    fail "_stage_build_db_esl: expected ${shipped_db_count} certificates, got ${db_converted}"
fi

if grep -qF "${WIN_PCA_2011_FP}" "${CONVERTED_FPS}"; then
    pass "_stage_build_db_esl: Microsoft Windows Production PCA 2011 is present in db"
else
    fail "_stage_build_db_esl: Microsoft Windows Production PCA 2011 was filtered out of db — an unmigrated Windows install would not boot"
fi

if [[ -s "${WORKDIR}/db.esl" ]]; then
    pass "_stage_build_db_esl: combined db.esl is non-empty"
else
    fail "_stage_build_db_esl: combined db.esl is empty or missing"
fi

# ---------------------------------------------------------------------------
# Test 2: KEK must contain both Microsoft KEKs
# ---------------------------------------------------------------------------
echo
echo "--- Test 2: _stage_build_kek_esl includes Microsoft KEK CA 2011 ---"

install_cert_stub

USER_KEK_KEY="${WORKDIR}/user-kek.key"
USER_KEK_CRT="${WORKDIR}/user-kek.crt"
openssl req -new -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -subj "/CN=SB-ENEMA Test KEK" \
    -keyout "${USER_KEK_KEY}" -out "${USER_KEK_CRT}" >/dev/null 2>&1

shipped_kek_count=$(find "${MOCK_DATA}/PreSignedObjects/KEK/Certificates" -name '*.der' | wc -l)

_stage_build_kek_esl "${WORKDIR}" "${USER_KEK_CRT}" "${OWNER_GUID}"

# user KEK + every shipped Microsoft KEK
expected_kek=$((shipped_kek_count + 1))
kek_converted=$(wc -l < "${CONVERTED_FPS}")
if [[ "${kek_converted}" -eq "${expected_kek}" ]]; then
    pass "_stage_build_kek_esl: user KEK + all ${shipped_kek_count} Microsoft KEKs enrolled (none filtered)"
else
    fail "_stage_build_kek_esl: expected ${expected_kek} certificates, got ${kek_converted}"
fi

if grep -qF "${KEK_CA_2011_FP}" "${CONVERTED_FPS}"; then
    pass "_stage_build_kek_esl: Microsoft KEK CA 2011 is present in KEK"
else
    fail "_stage_build_kek_esl: Microsoft KEK CA 2011 was filtered out of KEK — Microsoft dbx updates would never apply"
fi

unset -f cert-to-efi-sig-list

# ---------------------------------------------------------------------------
# Test 3: the keystore template declares the expected certificate set
# ---------------------------------------------------------------------------
echo
echo "--- Test 3: SbEnemaRecovery.toml declares the expected certificate set ---"

if [[ ! -f "${TEMPLATE}" ]]; then
    fail "keystore template not found at ${TEMPLATE}"
else
    template_report=$(python3 - "${TEMPLATE}" <<'PYEOF'
import sys, tomllib
want = {
    "PK":  {"WindowsOEMDevicesPK.der"},
    "KEK": {"microsoft corporation kek 2k ca 2023.der",
            "MicCorKEKCA2011_2011-06-24.der"},
    "DB":  {"windows uefi ca 2023.der",
            "microsoft uefi ca 2023.der",
            "microsoft option rom uefi ca 2023.der",
            "MicWinProPCA2011_2011-10-19.der",
            "MicCorUEFCA2011_2011-06-27.der"},
}
with open(sys.argv[1], "rb") as fh:
    ks = tomllib.load(fh)
ok = True
for var, expected in want.items():
    got = {f["path"].split("/")[-1] for f in ks.get(var, {}).get("files", [])}
    if got != expected:
        ok = False
        for miss in sorted(expected - got):
            print(f"MISSING {var}: {miss}")
        for extra in sorted(got - expected):
            print(f"UNEXPECTED {var}: {extra}")
print("OK" if ok else "MISMATCH")
PYEOF
)
    if [[ "${template_report}" == "OK" ]]; then
        pass "SbEnemaRecovery.toml: PK/KEK/db sets are exactly as expected"
    else
        fail "SbEnemaRecovery.toml: certificate set mismatch:"
        echo "${template_report}" >&2
    fi
fi

# ---------------------------------------------------------------------------
# Test 4: the build-time policy guard accepts good and rejects bad key sets
# ---------------------------------------------------------------------------
echo
echo "--- Test 4: check-secureboot-policy.py enforces the db/dbx invariant ---"

# Build a minimal db ESL containing the real Microsoft db certificates, plus a
# dbx that is hash-only (compliant) and one that revokes PCA 2011 (must fail).
python3 - "${MOCK_DATA}/PreSignedObjects" "${WORKDIR}" "${POLICY_CHECK}" <<'PYEOF'
import hashlib, importlib.util, pathlib, struct, sys, uuid

presigned, out_dir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
certs_dir = presigned / "DB" / "Certificates"
kek_dir = presigned / "KEK" / "Certificates"

# Reuse the checker's own TBSCertificate extractor so the test cannot silently
# diverge from the implementation it is exercising.
spec = importlib.util.spec_from_file_location("policy", sys.argv[3])
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
SHA256 = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
X509_SHA256 = uuid.UUID("3bd2a492-96c0-4079-b420-fcf98ef103ed")
MADE_UP = uuid.UUID("00000000-dead-beef-0000-000000000001")
OWNER = uuid.UUID("77fa9abd-0359-4d32-bd60-28f4e78f784b").bytes_le

def esl(sig_type, payload):
    sig = OWNER + payload
    return sig_type.bytes_le + struct.pack("<III", 28 + len(sig), 0, len(sig)) + sig

db = b"".join(esl(X509, p.read_bytes()) for p in sorted(certs_dir.glob("*.der")))
(out_dir / "DB.bin").write_bytes(db)

# Compliant dbx: image hashes only.
(out_dir / "DBX-ok.bin").write_bytes(b"".join(esl(SHA256, bytes([i]) * 32) for i in range(4)))

# Non-compliant: revokes Windows Production PCA 2011 by value, which db relies on.
pca = (certs_dir / "MicWinProPCA2011_2011-10-19.der").read_bytes()
(out_dir / "DBX-bad.bin").write_bytes(esl(SHA256, b"\x01" * 32) + esl(X509, pca))

# Non-compliant: same revocation expressed as a TBSCertificate hash, which is
# how firmware actually revokes a CA.
tbs_digest = hashlib.sha256(policy.tbs_certificate(pca)).digest()
(out_dir / "DBX-tbs.bin").write_bytes(esl(SHA256, b"\x02" * 32) + esl(X509_SHA256, tbs_digest))

# A signature type the checker does not know must fail, not be ignored.
(out_dir / "DBX-unknown.bin").write_bytes(esl(SHA256, b"\x03" * 32) + esl(MADE_UP, b"\x04" * 32))

# KEK variants: 2023 only (must fail) and both Microsoft KEKs (must pass).
kek_2023 = (kek_dir / "microsoft corporation kek 2k ca 2023.der").read_bytes()
kek_2011 = (kek_dir / "MicCorKEKCA2011_2011-06-24.der").read_bytes()
(out_dir / "KEK-2023only.bin").write_bytes(esl(X509, kek_2023))
(out_dir / "KEK-both.bin").write_bytes(esl(X509, kek_2023) + esl(X509, kek_2011))
PYEOF

if python3 "${POLICY_CHECK}" "${WORKDIR}/DB.bin" "${WORKDIR}/DBX-ok.bin" >/dev/null 2>&1; then
    pass "check-secureboot-policy.py: accepts a compliant key set"
else
    fail "check-secureboot-policy.py: rejected a compliant key set"
fi

# Assert the exact invariant-violation status (1), not merely "non-zero" — a
# usage or parse regression exits 2 and would otherwise read as a PASS.
policy_rc=0
policy_out=$(python3 "${POLICY_CHECK}" "${WORKDIR}/DB.bin" "${WORKDIR}/DBX-bad.bin" 2>&1) || policy_rc=$?
if [[ "${policy_rc}" -eq 1 ]]; then
    pass "check-secureboot-policy.py: rejects a dbx revoking a certificate db depends on"
else
    fail "check-secureboot-policy.py: expected exit 1 (invariant violated), got ${policy_rc}"
    echo "${policy_out}" >&2
fi

# Same, for a certificate revoked by TBSCertificate hash rather than by value —
# the encoding firmware actually uses to revoke a CA.
policy_rc=0
policy_out=$(python3 "${POLICY_CHECK}" "${WORKDIR}/DB.bin" "${WORKDIR}/DBX-tbs.bin" 2>&1) || policy_rc=$?
if [[ "${policy_rc}" -eq 1 ]]; then
    pass "check-secureboot-policy.py: rejects a dbx revoking a db certificate by TBS hash"
else
    fail "check-secureboot-policy.py: expected exit 1 for TBS-hash revocation, got ${policy_rc}"
    echo "${policy_out}" >&2
fi

# An unrecognised dbx signature type must fail rather than be ignored.
policy_rc=0
policy_out=$(python3 "${POLICY_CHECK}" "${WORKDIR}/DB.bin" "${WORKDIR}/DBX-unknown.bin" 2>&1) || policy_rc=$?
if [[ "${policy_rc}" -eq 1 ]]; then
    pass "check-secureboot-policy.py: rejects an unrecognised dbx signature type"
else
    fail "check-secureboot-policy.py: expected exit 1 for unknown signature type, got ${policy_rc}"
    echo "${policy_out}" >&2
fi

# KEK is checked when supplied: a KEK missing the 2011 Microsoft KEK must fail.
policy_rc=0
policy_out=$(python3 "${POLICY_CHECK}" "${WORKDIR}/DB.bin" "${WORKDIR}/DBX-ok.bin" "${WORKDIR}/KEK-2023only.bin" 2>&1) || policy_rc=$?
if [[ "${policy_rc}" -eq 1 ]]; then
    pass "check-secureboot-policy.py: rejects a KEK missing Microsoft KEK CA 2011"
else
    fail "check-secureboot-policy.py: expected exit 1 for 2023-only KEK, got ${policy_rc}"
    echo "${policy_out}" >&2
fi

policy_rc=0
policy_out=$(python3 "${POLICY_CHECK}" "${WORKDIR}/DB.bin" "${WORKDIR}/DBX-ok.bin" "${WORKDIR}/KEK-both.bin" 2>&1) || policy_rc=$?
if [[ "${policy_rc}" -eq 0 ]]; then
    pass "check-secureboot-policy.py: accepts a KEK carrying both Microsoft KEKs"
else
    fail "check-secureboot-policy.py: expected exit 0 for a complete KEK, got ${policy_rc}"
    echo "${policy_out}" >&2
fi

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Test 5: the hardened profile and its coupling to db
# ---------------------------------------------------------------------------
echo
echo "--- Test 5: hardened profile couples dbx revocations to db removals ---"

HARDENED="${REPO_ROOT}/sb_enema/secureboot-templates/SbEnemaHardened.toml"
APPENDER="${REPO_ROOT}/scripts/append-dbx-revocations.py"

if [[ ! -f "${HARDENED}" ]]; then
    fail "hardened template not found at ${HARDENED}"
elif [[ ! -f "${APPENDER}" ]]; then
    fail "append-dbx-revocations.py not found at ${APPENDER}"
else
    hardened_report=$(python3 - "${HARDENED}" <<'PYEOF'
import sys, tomllib
with open(sys.argv[1], "rb") as fh:
    ks = tomllib.load(fh)
db = {f["path"].split("/")[-1] for f in ks["DB"]["files"]}
banned = {"MicWinProPCA2011_2011-10-19.der", "MicCorUEFCA2011_2011-06-27.der"}
problems = []
if db & banned:
    problems.append(f"hardened db still trusts revoked/legacy certs: {sorted(db & banned)}")
if not ks.get("DBX", {}).get("include_certificates"):
    problems.append("hardened DBX does not set include_certificates")
if not ks.get("DBX", {}).get("include_svns"):
    problems.append("hardened DBX does not set include_svns")
print("\n".join(problems) if problems else "OK")
PYEOF
)
    if [[ "${hardened_report}" == "OK" ]]; then
        pass "SbEnemaHardened.toml enables extra revocations and drops the 2011 db certs"
    else
        fail "SbEnemaHardened.toml is incoherent:"
        echo "${hardened_report}" >&2
    fi

    # Build a hardened-style dbx (image hashes + the PCA 2011 TBS revocation)
    # and confirm it is rejected against a db that still trusts that CA. This is
    # the combination that would brick a machine, so it must never build.
    python3 "${APPENDER}" "${WORKDIR}/DBX-ok.bin" \
        "${MOCK_DATA}/PreSignedObjects/DBX/dbx_info_msft_latest.json" \
        "${MOCK_DATA}/PreSignedObjects" --certificates --svns >/dev/null 2>&1 || true

    policy_rc=0
    policy_out=$(python3 "${POLICY_CHECK}" "${WORKDIR}/DB.bin" "${WORKDIR}/DBX-ok.bin" 2>&1) || policy_rc=$?
    if [[ "${policy_rc}" -eq 1 ]]; then
        pass "recovery db + hardened dbx is rejected (would brick unmigrated Windows)"
    else
        fail "expected exit 1 for recovery db against hardened dbx, got ${policy_rc}"
        echo "${policy_out}" >&2
    fi
fi

echo
echo "=== Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
[[ "${FAIL_COUNT}" -eq 0 ]]
