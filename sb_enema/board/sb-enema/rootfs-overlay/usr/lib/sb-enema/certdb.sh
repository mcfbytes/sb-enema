#!/usr/bin/env bash
# certdb.sh — Known-certificate fingerprint database lookup functions for SB-ENEMA.
# Source common.sh first for shared helpers; this script defines CERTDB_DIR itself
# (override CERTDB_DIR before sourcing if the default path is wrong).
# shellcheck disable=SC2034  # Variables may be used by sourcing scripts.
set -euo pipefail
[[ -n "${_SB_ENEMA_CERTDB_SH:-}" ]] && return 0
readonly _SB_ENEMA_CERTDB_SH=1

# ---------------------------------------------------------------------------
# Path to the known-certs database directory.
# Override CERTDB_DIR before sourcing this file if the default is wrong.
# ---------------------------------------------------------------------------
CERTDB_DIR="${CERTDB_DIR:-/usr/lib/sb-enema/known-certs}"

# ---------------------------------------------------------------------------
# _certdb_lookup_file <sha256> <file>
#   Internal helper: return 0 if <sha256> appears in <file>, else 1.
#   Uses grep -qF for a fast, literal fixed-string search.
# ---------------------------------------------------------------------------
_certdb_lookup_file() {
    local sha256="$1"
    local file="$2"
    grep -qE -- "^${sha256}([[:space:]]|\$)" "${file}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# certdb_is_test_pk <sha256>
#   Return 0 if <sha256> matches a known test/placeholder PK.
#   A match means the platform key is NOT production-grade.
# ---------------------------------------------------------------------------
certdb_is_test_pk() {
    local sha256="$1"
    _certdb_lookup_file "${sha256}" "${CERTDB_DIR}/known-test-pks.txt"
}

# ---------------------------------------------------------------------------
# certdb_is_known_vendor_pk <sha256>
#   Return 0 if <sha256> matches a known legitimate vendor PK.
#   Note: absence from this list does not mean the key is invalid.
# ---------------------------------------------------------------------------
certdb_is_known_vendor_pk() {
    local sha256="$1"
    _certdb_lookup_file "${sha256}" "${CERTDB_DIR}/known-vendor-pks.txt"
}

# ---------------------------------------------------------------------------
# certdb_is_microsoft_kek <sha256>
#   Return 0 if <sha256> matches a known Microsoft KEK certificate.
# ---------------------------------------------------------------------------
certdb_is_microsoft_kek() {
    local sha256="$1"
    _certdb_lookup_file "${sha256}" "${CERTDB_DIR}/known-microsoft-keks.txt"
}

# ---------------------------------------------------------------------------
# certdb_is_microsoft_db <sha256>
#   Return 0 if <sha256> matches a known Microsoft db certificate
#   (UEFI CA, Windows Production PCA, or 2023 replacements).
# ---------------------------------------------------------------------------
certdb_is_microsoft_db() {
    local sha256="$1"
    _certdb_lookup_file "${sha256}" "${CERTDB_DIR}/known-microsoft-db.txt"
}

# ---------------------------------------------------------------------------
# _certdb_is_user_pk <sha256>
#   Internal helper: return 0 if <sha256> matches the SHA-256 fingerprint of
#   the PK certificate stored on the exFAT data partition at
#   ${DATA_MOUNT}/PK/PK.crt.  Returns 1 if the file does not exist, cannot
#   be parsed, or the fingerprint does not match.
# ---------------------------------------------------------------------------
_certdb_is_user_pk() {
    local pk_sha256="$1"
    local user_pk_cert="${DATA_MOUNT:-/mnt/data}/PK/PK.crt"

    if [[ ! -f "${user_pk_cert}" ]]; then
        return 1
    fi

    local cert_fp
    cert_fp=$(openssl x509 -in "${user_pk_cert}" -noout -fingerprint -sha256 2>/dev/null \
              | sed 's/.*Fingerprint=//;s/://g' \
              | tr '[:upper:]' '[:lower:]') || return 1

    local pk_sha256_lower
    pk_sha256_lower=$(printf '%s' "${pk_sha256}" | tr '[:upper:]' '[:lower:]')

    [[ "${cert_fp}" == "${pk_sha256_lower}" ]]
}

# ---------------------------------------------------------------------------
# _certdb_is_user_kek <sha256>
#   Internal helper: return 0 if <sha256> matches the SHA-256 fingerprint of
#   the KEK certificate stored on the exFAT data partition at
#   ${DATA_MOUNT}/KEK/KEK.crt.  Returns 1 if the file does not exist, cannot
#   be parsed, or the fingerprint does not match.
# ---------------------------------------------------------------------------
_certdb_is_user_kek() {
    local kek_sha256="$1"
    local user_kek_cert="${DATA_MOUNT:-/mnt/data}/KEK/KEK.crt"

    if [[ ! -f "${user_kek_cert}" ]]; then
        return 1
    fi

    local cert_fp
    cert_fp=$(openssl x509 -in "${user_kek_cert}" -noout -fingerprint -sha256 2>/dev/null \
              | sed 's/.*Fingerprint=//;s/://g' \
              | tr '[:upper:]' '[:lower:]') || return 1

    local kek_sha256_lower
    kek_sha256_lower=$(printf '%s' "${kek_sha256}" | tr '[:upper:]' '[:lower:]')

    [[ "${cert_fp}" == "${kek_sha256_lower}" ]]
}

# ---------------------------------------------------------------------------
# certdb_lookup <sha256>
#   Print the description string for the given fingerprint if it appears in
#   any of the known-certs files, or print nothing if not found.
#   The description is the text after the SHA-256 hex on the matching line.
# ---------------------------------------------------------------------------
certdb_lookup() {
    local sha256="$1"
    local file desc

    for file in \
        "${CERTDB_DIR}/known-microsoft-pk.txt" \
        "${CERTDB_DIR}/known-microsoft-keks.txt" \
        "${CERTDB_DIR}/known-microsoft-db.txt" \
        "${CERTDB_DIR}/known-test-pks.txt" \
        "${CERTDB_DIR}/known-vendor-pks.txt"
    do
        if [[ ! -f "${file}" ]]; then
            continue
        fi
        desc=$(grep -F "${sha256}" "${file}" 2>/dev/null \
               | grep -v '^#' \
               | head -1 \
               | sed "s/^${sha256}[[:space:]]*//" || true)
        if [[ -n "${desc}" ]]; then
            echo "${desc}"
            return 0
        fi
    done
    return 0
}

# ---------------------------------------------------------------------------
# certdb_identify_ownership_model <pk_sha256>
#   Return a string classifying who controls the Platform Key:
#     "microsoft"  — PK is the Microsoft OEM Devices PK (Surface/WHCP devices)
#     "test"       — PK is a known test/placeholder key (insecure)
#     "vendor"     — PK is a known legitimate OEM/ODM vendor key
#     "user"       — PK fingerprint matches the PK certificate saved on the
#                    exFAT data partition (${DATA_MOUNT}/PK/PK.crt)
#     "unknown"    — PK is not in any known database
# ---------------------------------------------------------------------------
certdb_identify_ownership_model() {
    local pk_sha256="$1"

    if _certdb_lookup_file "${pk_sha256}" "${CERTDB_DIR}/known-microsoft-pk.txt"; then
        echo "microsoft"
    elif certdb_is_test_pk "${pk_sha256}"; then
        echo "test"
    elif certdb_is_known_vendor_pk "${pk_sha256}"; then
        echo "vendor"
    elif _certdb_is_user_pk "${pk_sha256}"; then
        echo "user"
    else
        echo "unknown"
    fi
}
