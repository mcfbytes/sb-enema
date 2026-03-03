#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SUBMODULE="${SUBMODULE:-${ROOT_DIR}/third_party/secureboot_objects}"
VENV_DIR="${VENV_DIR:-${ROOT_DIR}/output/secureboot-venv}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/output/secureboot-artifacts}"
STAGING_DIR="${STAGING_DIR:-${ROOT_DIR}/output/secureboot-staging}"
TEMPLATE_NAME="${TEMPLATE_NAME:-MicrosoftAndThirdParty}"
ARCH="${ARCH:-X64}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [ ! -d "${SUBMODULE}" ]; then
    echo "Secure Boot objects submodule not found at ${SUBMODULE}" >&2
    exit 1
fi

git -C "${ROOT_DIR}" submodule update --init --recursive third_party/secureboot_objects

if [ ! -x "${VENV_DIR}/bin/python" ]; then
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

"${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
"${VENV_DIR}/bin/pip" install -r "${SUBMODULE}/pip-requirements.txt" >/dev/null

mkdir -p "${ARTIFACT_DIR}"

(
    cd "${SUBMODULE}"
    PYTHONPATH="scripts" "${VENV_DIR}/bin/python" scripts/secure_boot_default_keys.py \
        --keystore "Templates/${TEMPLATE_NAME}.toml" \
        -o "${ARTIFACT_DIR}"
)

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

echo "Prepared secure boot artifacts in ${ARTIFACT_DIR} and staged content in ${STAGING_DIR}"
