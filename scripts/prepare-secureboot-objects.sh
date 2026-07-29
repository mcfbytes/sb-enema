#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SUBMODULE="${SUBMODULE:-${ROOT_DIR}/third_party/secureboot_objects}"
VENV_DIR="${VENV_DIR:-${ROOT_DIR}/output/secureboot-venv}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/output/secureboot-artifacts}"
STAGING_DIR="${STAGING_DIR:-${ROOT_DIR}/output/secureboot-staging}"

# Keystore template driving what lands in PK/KEK/db/dbx.
#
# This is SB-ENEMA's own template, NOT one of the stock
# third_party/secureboot_objects/Templates/*.toml.  None of the stock templates
# fit a recovery tool: the ones that keep "Microsoft Windows Production PCA
# 2011" in db drop the 2011 KEK, and vice versa.  See the header of
# SbEnemaRecovery.toml for the full rationale and evidence.
#
# Keeping it outside third_party/ means a submodule bump cannot silently change
# which certificates we enroll.  Override with KEYSTORE=/path/to/other.toml to
# build a different policy (e.g. one of the stock Microsoft templates).
KEYSTORE="${KEYSTORE:-${ROOT_DIR}/sb_enema/secureboot-templates/SbEnemaRecovery.toml}"

# secure_boot_default_keys.py names its output directory after the keystore's
# basename, so TEMPLATE_NAME must be derived from KEYSTORE rather than set
# independently — otherwise the rsync below reads a path that does not exist.
TEMPLATE_NAME="$(basename "${KEYSTORE}")"
TEMPLATE_NAME="${TEMPLATE_NAME%%.*}"

ARCH="${ARCH:-X64}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [ ! -d "${SUBMODULE}" ]; then
    echo "Secure Boot objects submodule not found at ${SUBMODULE}" >&2
    exit 1
fi

if [ ! -f "${KEYSTORE}" ]; then
    echo "Keystore template not found at ${KEYSTORE}" >&2
    exit 1
fi

# The generator runs from the submodule root, so a relative KEYSTORE would
# resolve against the wrong directory there even though the check above passed.
KEYSTORE="$(cd "$(dirname "${KEYSTORE}")" && pwd)/$(basename "${KEYSTORE}")"

git -C "${ROOT_DIR}" submodule update --init --recursive third_party/secureboot_objects

if [ ! -x "${VENV_DIR}/bin/python" ]; then
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

"${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
"${VENV_DIR}/bin/pip" install -r "${SUBMODULE}/pip-requirements.txt" >/dev/null

# Verify that every certificate the keystore names still hashes to the value the
# keystore records.  secure_boot_default_keys.py ignores the `sha1` fields
# entirely, so without this they are decorative: a submodule bump that swapped a
# certificate's contents while keeping its filename would silently change what
# gets enrolled.  Pinning the template's paths only helps if the bytes behind
# them are pinned too.
echo "Verifying keystore certificate fingerprints..."
"${PYTHON_BIN}" - "${KEYSTORE}" "${SUBMODULE}" <<'PYEOF'
import hashlib
import pathlib
import sys
import tomllib

keystore_path, submodule = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
with keystore_path.open("rb") as handle:
    keystore = tomllib.load(handle)

problems = []
checked = 0
for variable, section in keystore.items():
    for entry in section.get("files", []):
        path = submodule / entry["path"]
        expected = entry.get("sha1")
        if expected is None:
            continue
        if not path.is_file():
            problems.append(f"{variable}: missing file {entry['path']}")
            continue
        # Only certificates carry a meaningful thumbprint; the DBX json entry's
        # sha1 describes the source document and is checked the same way.
        actual = hashlib.sha1(path.read_bytes()).hexdigest()
        if actual != f"{expected:040x}".lower():
            problems.append(
                f"{variable}: {entry['path']}\n"
                f"      keystore says 0x{expected:040X}\n"
                f"      file is     0x{actual.upper()}"
            )
        checked += 1

if problems:
    print("\nERROR: keystore fingerprint mismatch:", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    print(
        "\nA certificate's contents changed without its sha1 in the keystore "
        "being updated.\nIf this followed a secureboot_objects bump, review what "
        "changed before\nupdating the keystore -- this is the check that stops a "
        "submodule bump from\nsilently altering which certificates get enrolled.",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(f"  {checked} keystore fingerprint(s) verified")
PYEOF

mkdir -p "${ARTIFACT_DIR}"

(
    # The generator resolves every `path` in the keystore relative to its own
    # working directory, so it must run from the submodule root.  KEYSTORE is
    # absolute for exactly this reason.
    cd "${SUBMODULE}"
    PYTHONPATH="scripts" "${VENV_DIR}/bin/python" scripts/secure_boot_default_keys.py \
        --keystore "${KEYSTORE}" \
        -o "${ARTIFACT_DIR}"
)

# Fail the build before staging anything if the generated key set violates the
# certificate-policy invariants (see check-secureboot-policy.py for what and why).
echo "Checking Secure Boot certificate policy invariants..."
"${PYTHON_BIN}" "${ROOT_DIR}/scripts/check-secureboot-policy.py" \
    "${ARTIFACT_DIR}/${ARCH}/${TEMPLATE_NAME}/Firmware/DB.bin" \
    "${ARTIFACT_DIR}/${ARCH}/${TEMPLATE_NAME}/Firmware/DBX.bin" \
    "${ARTIFACT_DIR}/${ARCH}/${TEMPLATE_NAME}/Firmware/KEK.bin"

rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/secureboot_artifacts"

rsync -a "${ARTIFACT_DIR}/${ARCH}/${TEMPLATE_NAME}/" "${STAGING_DIR}/secureboot_artifacts/"

# Include source materials for transparency/debugging inside the image data partition.
rsync -a --exclude='.git' --exclude='Artifacts' "${SUBMODULE}/PreSignedObjects" "${STAGING_DIR}/"
rsync -a --exclude='.git' --exclude='__pycache__' "${SUBMODULE}/scripts" "${STAGING_DIR}/"
rsync -a "${SUBMODULE}/Templates" "${STAGING_DIR}/"

# Stage pre-built Microsoft .auth payloads for Microsoft PK Recovery Mode.
# These are consumed at runtime via MSFT_PAYLOADS_DIR by the stage.sh/enroll.sh
# enrollment flow.
MSFT_PAYLOAD_STAGING="${STAGING_DIR}/sb-enema/payloads/microsoft"
FIRMWARE_DIR="${STAGING_DIR}/secureboot_artifacts/Firmware"
IMAGING_DIR="${STAGING_DIR}/secureboot_artifacts/Imaging"
mkdir -p "${MSFT_PAYLOAD_STAGING}"
if [ -d "${FIRMWARE_DIR}" ]; then
    # PK.auth: use the pre-signed EFI_VARIABLE_AUTHENTICATION_2 file from Imaging/.
    # Firmware/PK.bin is a raw ESL; efi-updatevar refuses raw ESLs for PK (the tool
    # requires a signing key for PK even with -e, and some firmware non-compliantly
    # exits Setup Mode after KEK is written).  Imaging/PK.bin wraps the same cert in
    # a valid EFI_VARIABLE_AUTHENTICATION_2 structure; the stale 2010 timestamp is
    # fine for first-time PK enrollment because UEFI spec §32.3.2 says any valid auth
    # payload is accepted when PK is NULL (no previous timestamp to compare against).
    if [ -f "${IMAGING_DIR}/PK.bin" ]; then
        cp "${IMAGING_DIR}/PK.bin" "${MSFT_PAYLOAD_STAGING}/PK.auth"
    else
        echo "Warning: ${IMAGING_DIR}/PK.bin not found; Microsoft PK.auth payload will not be staged" >&2
    fi
    # KEK, db, dbx: use raw ESLs from Firmware/ — these are written via
    # efi-updatevar -e -f in Setup Mode and do not require authentication.
    [ -f "${FIRMWARE_DIR}/KEK.bin" ] && cp "${FIRMWARE_DIR}/KEK.bin" "${MSFT_PAYLOAD_STAGING}/KEK.auth"
    [ -f "${FIRMWARE_DIR}/DB.bin"  ] && cp "${FIRMWARE_DIR}/DB.bin"  "${MSFT_PAYLOAD_STAGING}/db.auth"
    [ -f "${FIRMWARE_DIR}/DBX.bin" ] && cp "${FIRMWARE_DIR}/DBX.bin" "${MSFT_PAYLOAD_STAGING}/dbx.auth"
    echo "Staged Microsoft .auth payloads in ${MSFT_PAYLOAD_STAGING}"

    # Generate SHA256SUMS manifest for payload integrity verification at runtime.
    PAYLOADS_BASE="${STAGING_DIR}/sb-enema/payloads"
    if [ -d "${PAYLOADS_BASE}" ]; then
        (cd "${PAYLOADS_BASE}" && find . -name '*.auth' -type f -exec sha256sum {} + | sort > SHA256SUMS)
        echo "Generated SHA256SUMS in ${PAYLOADS_BASE}"
    fi
else
    echo "Warning: ${FIRMWARE_DIR} not found; Microsoft PK Recovery Mode payloads will not be available" >&2
fi

# Copy kek_update_map.json for runtime vendor cert filtering in stage_bios_entries().
# Used to match KEKDefault/dbDefault certs against known legitimate vendor PKs.
KEK_UPDATE_MAP="${SUBMODULE}/PostSignedObjects/KEK/kek_update_map.json"
if [ -f "${KEK_UPDATE_MAP}" ]; then
    cp "${KEK_UPDATE_MAP}" "${STAGING_DIR}/sb-enema/kek_update_map.json"
    echo "Staged kek_update_map.json in ${STAGING_DIR}/sb-enema/"
else
    echo "Warning: ${KEK_UPDATE_MAP} not found; stage_bios_entries vendor filtering will be unavailable" >&2
fi

echo "Prepared secure boot artifacts in ${ARTIFACT_DIR} and staged content in ${STAGING_DIR}"
