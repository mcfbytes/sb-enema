#!/usr/bin/env bash
# audit.sh — Secure Boot audit engine for SB-ENEMA.
# Sources common.sh, log.sh, efivar.sh, and certdb.sh. Analyzes the current
# Secure Boot state and produces structured findings with severity levels.
# shellcheck disable=SC2034  # Global arrays are consumed by other modules.
set -euo pipefail
[[ -n "${_SB_ENEMA_AUDIT_SH:-}" ]] && return 0
readonly _SB_ENEMA_AUDIT_SH=1

# ---------------------------------------------------------------------------
# Source required libraries
# ---------------------------------------------------------------------------
# shellcheck source=common.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/common.sh"
# shellcheck source=log.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/log.sh"
# shellcheck source=efivar.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/efivar.sh"
# shellcheck source=certdb.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/certdb.sh"
# shellcheck source=bootloader-scan.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/bootloader-scan.sh"

# ---------------------------------------------------------------------------
# Global findings arrays
# Each entry in AUDIT_FINDINGS is "severity|component|message".
# AUDIT_SEVERITIES mirrors the severity of each finding for fast lookup.
# ---------------------------------------------------------------------------
AUDIT_FINDINGS=()
AUDIT_SEVERITIES=()
AUDIT_2026_READY=""

# ---------------------------------------------------------------------------
# Internal tracking flags (set by individual audit functions, consumed by
# audit_2026_ready for the composite readiness check).
# ---------------------------------------------------------------------------
_AUDIT_PK_VALID=""
_AUDIT_PK_IS_TEST=""
_AUDIT_DB_HAS_2023=""
_AUDIT_DBX_CURRENT=""

# ---------------------------------------------------------------------------
# Known Microsoft certificate fingerprints (lowercase hex, no colons).
# These are used to distinguish between legacy (2011) and current (2023)
# certificates in the KEK and db databases.
# ---------------------------------------------------------------------------
readonly _AUDIT_MS_KEK_2011="a1117f516a32cefcba3f2d1ace10a87972fd6bbe8fe0d0b996e09e65d802a503"
readonly _AUDIT_MS_KEK_2023="3cd3f0309edae228767a976dd40d9f4affc4fbd5218f2e8cc3c9dd97e8ac6f9d"

readonly _AUDIT_MS_WIN_PCA_2011="e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
readonly _AUDIT_MS_UEFI_CA_2023="f6124e34125bee3fe6d79a574eaa7b91c0e7bd9d929c1a321178efd611dad901"
readonly _AUDIT_MS_WIN_UEFI_CA_2023="076f1fea90ac29155ebf77c17682f75f1fdd1be196da302dc8461e350a9ae330"

# Minimum number of SHA-256 hashes expected in a reasonably current dbx.
readonly _AUDIT_DBX_MIN_HASHES=100

# ---------------------------------------------------------------------------
# _audit_add_finding <severity> <component> <message>
#   Append a finding to the global arrays.
# ---------------------------------------------------------------------------
_audit_add_finding() {
    local severity="$1"
    local component="$2"
    local message="$3"
    AUDIT_FINDINGS+=("${severity}|${component}|${message}")
    AUDIT_SEVERITIES+=("${severity}")
}

# ---------------------------------------------------------------------------
# _audit_cert_fingerprint <der_file>
#   Print the SHA-256 fingerprint of a DER-encoded certificate as lowercase
#   hex without colons.
# ---------------------------------------------------------------------------
_audit_cert_fingerprint() {
    local der_file="$1"
    openssl x509 -in "${der_file}" -inform DER -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/.*Fingerprint=//;s/://g' \
        | tr '[:upper:]' '[:lower:]'
}

# ---------------------------------------------------------------------------
# _audit_sort_findings
#   Re-order AUDIT_FINDINGS (and AUDIT_SEVERITIES) so that CRITICAL findings
#   come first, followed by HIGH, WARNING, and INFO.
# ---------------------------------------------------------------------------
_audit_sort_findings() {
    if [[ ${#AUDIT_FINDINGS[@]} -le 1 ]]; then
        return
    fi

    local -a sorted=()
    local sev i
    for sev in CRITICAL HIGH WARNING INFO; do
        for i in "${!AUDIT_FINDINGS[@]}"; do
            if [[ "${AUDIT_SEVERITIES[$i]}" == "${sev}" ]]; then
                sorted+=("${AUDIT_FINDINGS[$i]}")
            fi
        done
    done

    AUDIT_FINDINGS=("${sorted[@]}")

    # Rebuild severities from sorted findings
    AUDIT_SEVERITIES=()
    local finding
    for finding in "${AUDIT_FINDINGS[@]}"; do
        AUDIT_SEVERITIES+=("${finding%%|*}")
    done
}

# ---------------------------------------------------------------------------
# audit_pk() — Analyze the Platform Key.
# ---------------------------------------------------------------------------
audit_pk() {
    local component="PK"

    # Check if PK is empty (Setup Mode)
    if efivar_is_empty PK; then
        _audit_add_finding "INFO" "${component}" "PK is empty — system is in Setup Mode"
        _AUDIT_PK_VALID="no"
        _AUDIT_PK_IS_TEST="no"
        return 0
    fi

    # Extract PK certificates to a temporary directory
    local tmpdir
    tmpdir=$(mktemp -d) || { log_error "Failed to create temp dir for PK audit"; return 1; }

    if ! efivar_extract_certs PK "${tmpdir}"; then
        _audit_add_finding "WARNING" "${component}" "Failed to extract PK certificates"
        _AUDIT_PK_VALID="no"
        _AUDIT_PK_IS_TEST="no"
        rm -rf "${tmpdir}"
        return 0
    fi

    if [[ ! -f "${tmpdir}/PK-0.der" ]]; then
        _audit_add_finding "WARNING" "${component}" "No certificates found in PK variable"
        _AUDIT_PK_VALID="no"
        _AUDIT_PK_IS_TEST="no"
        rm -rf "${tmpdir}"
        return 0
    fi

    # Assume valid until proven otherwise
    _AUDIT_PK_VALID="yes"
    _AUDIT_PK_IS_TEST="no"

    # Count PK entries — multiple PKs is unusual and worth noting
    local pk_count=0
    while [[ -f "${tmpdir}/PK-${pk_count}.der" ]]; do
        pk_count=$((pk_count + 1))
    done
    if [[ "${pk_count}" -gt 1 ]]; then
        _audit_add_finding "INFO" "${component}" \
            "PK contains ${pk_count} certificates (typically only one is expected)"
    fi

    # Iterate over all extracted PK certificates
    local index=0
    while [[ -f "${tmpdir}/PK-${index}.der" ]]; do
        local der_file="${tmpdir}/PK-${index}.der"
        local fingerprint
        fingerprint=$(_audit_cert_fingerprint "${der_file}")

        # Check if it is a known test PK
        if certdb_is_test_pk "${fingerprint}"; then
            _audit_add_finding "CRITICAL" "${component}" \
                "PK certificate [${index}] is a known test/placeholder key (${fingerprint})"
            _AUDIT_PK_IS_TEST="yes"
            _AUDIT_PK_VALID="no"
        fi

        # Check if expired
        if ! openssl x509 -in "${der_file}" -inform DER -checkend 0 >/dev/null 2>&1; then
            _audit_add_finding "HIGH" "${component}" "PK certificate [${index}] is expired"
            _AUDIT_PK_VALID="no"
        else
            # Check if it expires before 2026-06-01
            local now_epoch target_epoch seconds_remaining
            now_epoch=$(date +%s)
            target_epoch=$(date -d "2026-06-01T00:00:00Z" +%s 2>/dev/null) || target_epoch=1780272000
            if [[ "${now_epoch}" -lt "${target_epoch}" ]]; then
                seconds_remaining=$((target_epoch - now_epoch))
                if ! openssl x509 -in "${der_file}" -inform DER \
                        -checkend "${seconds_remaining}" >/dev/null 2>&1; then
                    _audit_add_finding "WARNING" "${component}" \
                        "PK certificate [${index}] may not survive 2026 update cycle"
                fi
            fi
        fi

        # Identify ownership model
        local ownership
        ownership=$(certdb_identify_ownership_model "${fingerprint}")
        _audit_add_finding "INFO" "${component}" \
            "Ownership model: ${ownership} (certificate [${index}], fingerprint: ${fingerprint})"

        index=$((index + 1))
    done

    rm -rf "${tmpdir}"
    return 0
}

# ---------------------------------------------------------------------------
# audit_kek() — Analyze the Key Exchange Key database.
# ---------------------------------------------------------------------------
audit_kek() {
    local component="KEK"

    if efivar_is_empty KEK; then
        _audit_add_finding "HIGH" "${component}" "KEK database is empty"
        return 0
    fi

    local tmpdir
    tmpdir=$(mktemp -d) || { log_error "Failed to create temp dir for KEK audit"; return 1; }

    if ! efivar_extract_certs KEK "${tmpdir}"; then
        _audit_add_finding "WARNING" "${component}" "Failed to extract KEK certificates"
        rm -rf "${tmpdir}"
        return 0
    fi

    local has_ms_kek_2023="no"
    local has_ms_kek_2011="no"
    local has_user_kek="no"
    local index=0

    while [[ -f "${tmpdir}/KEK-${index}.der" ]]; do
        local der_file="${tmpdir}/KEK-${index}.der"
        local fp
        fp=$(_audit_cert_fingerprint "${der_file}")

        if [[ "${fp}" == "${_AUDIT_MS_KEK_2023}" ]]; then
            has_ms_kek_2023="yes"
        elif [[ "${fp}" == "${_AUDIT_MS_KEK_2011}" ]]; then
            has_ms_kek_2011="yes"
        elif ! certdb_is_microsoft_kek "${fp}"; then
            # Check if this is the user's own KEK (custom-owner mode)
            if _certdb_is_user_kek "${fp}"; then
                has_user_kek="yes"
                _audit_add_finding "INFO" "${component}" "User-owned KEK entry [${index}] (fingerprint: ${fp})"
            else
                local desc
                desc=$(certdb_lookup "${fp}")
                if [[ -n "${desc}" ]]; then
                    _audit_add_finding "INFO" "${component}" "Non-Microsoft KEK entry: ${desc}"
                else
                    _audit_add_finding "INFO" "${component}" "Unknown/unrecognized KEK entry (${fp})"
                fi
            fi
        fi

        index=$((index + 1))
    done

    # Only flag Microsoft KEK 2023 as missing when the system is NOT using a
    # user-managed KEK chain.  In custom-owner mode the user signs db/dbx
    # updates with their own KEK, so Microsoft KEK 2023 is not required.
    if [[ "${has_ms_kek_2023}" != "yes" ]] && [[ "${has_user_kek}" != "yes" ]]; then
        _audit_add_finding "HIGH" "${component}" "Microsoft Production KEK 2023 is missing"
    fi

    if [[ "${has_ms_kek_2011}" == "yes" ]] && [[ "${has_ms_kek_2023}" != "yes" ]]; then
        _audit_add_finding "WARNING" "${component}" \
            "Legacy Microsoft KEK (2011) present without 2023 replacement"
    fi

    rm -rf "${tmpdir}"
    return 0
}

# ---------------------------------------------------------------------------
# audit_db() — Analyze the Allowed Signatures Database (db).
# ---------------------------------------------------------------------------
audit_db() {
    local component="db"

    if efivar_is_empty db; then
        _audit_add_finding "HIGH" "${component}" "Allowed signatures database (db) is empty"
        _AUDIT_DB_HAS_2023="no"
        return 0
    fi

    local tmpdir
    tmpdir=$(mktemp -d) || { log_error "Failed to create temp dir for db audit"; return 1; }

    if ! efivar_extract_certs db "${tmpdir}"; then
        _audit_add_finding "WARNING" "${component}" "Failed to extract db certificates"
        _AUDIT_DB_HAS_2023="no"
        rm -rf "${tmpdir}"
        return 0
    fi

    local has_win_pca_2011="no"
    local has_any_2023="no"
    local has_only_legacy="yes"
    local index=0

    while [[ -f "${tmpdir}/db-${index}.der" ]]; do
        local der_file="${tmpdir}/db-${index}.der"
        local fp
        fp=$(_audit_cert_fingerprint "${der_file}")

        # Track specific certificates
        if [[ "${fp}" == "${_AUDIT_MS_WIN_PCA_2011}" ]]; then
            has_win_pca_2011="yes"
        fi
        if [[ "${fp}" == "${_AUDIT_MS_UEFI_CA_2023}" ]] || \
           [[ "${fp}" == "${_AUDIT_MS_WIN_UEFI_CA_2023}" ]]; then
            has_any_2023="yes"
            has_only_legacy="no"
        fi
        # Any non-legacy Microsoft cert means not "only legacy"
        if certdb_is_microsoft_db "${fp}" && [[ "${fp}" != "${_AUDIT_MS_WIN_PCA_2011}" ]]; then
            local known_db_desc
            known_db_desc=$(certdb_lookup "${fp}")
            if [[ "${known_db_desc}" == *"2023"* ]]; then
                has_only_legacy="no"
            fi
        fi

        # Check for expired certificates
        if ! openssl x509 -in "${der_file}" -inform DER -checkend 0 >/dev/null 2>&1; then
            local expired_desc
            expired_desc=$(certdb_lookup "${fp}")
            _audit_add_finding "WARNING" "${component}" \
                "Expired certificate in db: ${expired_desc:-${fp}}"
        fi

        index=$((index + 1))
    done

    if [[ "${has_win_pca_2011}" != "yes" ]]; then
        _audit_add_finding "INFO" "${component}" \
            "Microsoft Windows Production PCA 2011 not in db (expected absent in current provisioning)"
    fi

    if [[ "${has_any_2023}" == "yes" ]]; then
        _AUDIT_DB_HAS_2023="yes"
    else
        _AUDIT_DB_HAS_2023="no"
        _audit_add_finding "HIGH" "${component}" \
            "Microsoft UEFI CA 2023 certificates missing — required for 2026 readiness"
    fi

    if [[ "${has_only_legacy}" == "yes" ]] && [[ "${index}" -gt 0 ]]; then
        _audit_add_finding "HIGH" "${component}" \
            "db has no 2023 Microsoft certificates (only pre-2023 Microsoft and/or non-Microsoft entries) — not 2026-ready"
    fi

    rm -rf "${tmpdir}"
    return 0
}

# ---------------------------------------------------------------------------
# audit_dbx() — Analyze the Forbidden Signatures Database (dbx).
# ---------------------------------------------------------------------------
audit_dbx() {
    local component="dbx"

    if efivar_is_empty dbx; then
        _audit_add_finding "HIGH" "${component}" \
            "Revocation list (dbx) is missing or empty"
        _AUDIT_DBX_CURRENT="no"
        return 0
    fi

    # Estimate hash count from raw payload size.
    # EFI Signature List header = 28 bytes; each SHA-256 entry = 48 bytes
    # (16-byte owner GUID + 32-byte hash).
    local raw_size=0
    raw_size=$(efivar_read_raw dbx 2>/dev/null | wc -c) || raw_size=0

    local min_size=$(( 28 + _AUDIT_DBX_MIN_HASHES * 48 ))

    if [[ "${raw_size}" -lt "${min_size}" ]]; then
        local estimated_hashes=0
        if [[ "${raw_size}" -gt 28 ]]; then
            estimated_hashes=$(( (raw_size - 28) / 48 ))
        fi
        _audit_add_finding "HIGH" "${component}" \
            "Revocation list missing or outdated (estimated ${estimated_hashes} hashes, minimum ${_AUDIT_DBX_MIN_HASHES} expected)"
        _AUDIT_DBX_CURRENT="no"
    else
        _audit_add_finding "INFO" "${component}" \
            "Revocation list appears current (${raw_size} bytes)"
        _AUDIT_DBX_CURRENT="yes"
    fi

    return 0
}

# ---------------------------------------------------------------------------
# audit_bootloader_chain_ca() — Check EFI bootloader signing CA.
#   Calls the bootloader scanner to determine whether PCA 2011 is still in
#   use, and records the result as an audit finding.
# ---------------------------------------------------------------------------
audit_bootloader_chain_ca() {
    local component="bootloader"

    # Guard is handled by _SB_ENEMA_BOOTLOADER_SCAN_SH; source already done.
    bootloader_scan_pca2011_in_use || true

    case "${BSCAN_VERDICT:-}" in
        CLEAR)
            _audit_add_finding "INFO" "${component}" \
                "All detected bootloaders signed by post-2023 Microsoft CA — DBX2024 safe to apply"
            ;;
        PCA2011_IN_USE)
            _audit_add_finding "HIGH" "${component}" \
                "One or more bootloaders still signed by Microsoft Windows Production PCA 2011 — update Windows before applying DBX2024"
            ;;
        *)
            _audit_add_finding "WARNING" "${component}" \
                "Bootloader CA scan failed or found no EFI binaries — DBX2024 applicability unknown"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# audit_2026_ready() — Composite readiness check.
#   Calls audit_pk, audit_kek, audit_db, and audit_dbx, then evaluates
#   whether the system meets the requirements for the 2026 Secure Boot
#   certificate transition.
# ---------------------------------------------------------------------------
audit_2026_ready() {
    audit_pk
    audit_kek
    audit_db
    audit_dbx

    if [[ "${_AUDIT_PK_VALID}" == "yes" ]] && \
       [[ "${_AUDIT_PK_IS_TEST}" != "yes" ]] && \
       [[ "${_AUDIT_DB_HAS_2023}" == "yes" ]] && \
       [[ "${_AUDIT_DBX_CURRENT}" == "yes" ]]; then
        AUDIT_2026_READY="yes"
        _audit_add_finding "INFO" "2026" "System is 2026-ready"
    else
        AUDIT_2026_READY="no"
        _audit_add_finding "INFO" "2026" "System is NOT 2026-ready"
        [[ "${_AUDIT_PK_VALID}" != "yes" ]] && _audit_add_finding "HIGH" "2026" "PK-invalid"
        [[ "${_AUDIT_PK_IS_TEST}" == "yes" ]] && _audit_add_finding "HIGH" "2026" "PK-is-test-key"
        [[ "${_AUDIT_DB_HAS_2023}" != "yes" ]] && _audit_add_finding "HIGH" "2026" "db-missing-2023-certs"
        [[ "${_AUDIT_DBX_CURRENT}" != "yes" ]] && _audit_add_finding "HIGH" "2026" "dbx-outdated"
    fi
}

# ---------------------------------------------------------------------------
# audit_run_all() — Orchestrator.
#   Initialize findings arrays, run all audit functions, sort findings by
#   severity, and return 0 if no CRITICAL/HIGH findings exist, 1 otherwise.
# ---------------------------------------------------------------------------
audit_run_all() {
    # Initialize
    AUDIT_FINDINGS=()
    AUDIT_SEVERITIES=()
    AUDIT_2026_READY=""
    _AUDIT_PK_VALID=""
    _AUDIT_PK_IS_TEST=""
    _AUDIT_DB_HAS_2023=""
    _AUDIT_DBX_CURRENT=""

    # Run composite check (which calls all individual audit functions)
    audit_2026_ready

    # Run bootloader CA scan (after db audit, as it is supplemental)
    audit_bootloader_chain_ca

    # Sort findings by severity
    _audit_sort_findings

    # Return 0 if no CRITICAL/HIGH findings, 1 otherwise
    if [[ ${#AUDIT_SEVERITIES[@]} -gt 0 ]]; then
        local sev
        for sev in "${AUDIT_SEVERITIES[@]}"; do
            if [[ "${sev}" == "CRITICAL" ]] || [[ "${sev}" == "HIGH" ]]; then
                return 1
            fi
        done
    fi
    return 0
}

# ---------------------------------------------------------------------------
# audit_get_findings()
#   Print all findings (one per line) in "severity|component|message" format
#   for consumption by the report module.
# ---------------------------------------------------------------------------
audit_get_findings() {
    if [[ ${#AUDIT_FINDINGS[@]} -eq 0 ]]; then
        return
    fi
    local finding
    for finding in "${AUDIT_FINDINGS[@]}"; do
        echo "${finding}"
    done
}
