#!/usr/bin/env bash
# safety.sh — Safety guardrails for SB-ENEMA enrollment operations.
# Requires common.sh, log.sh, and efivar.sh to be sourced first.
set -euo pipefail
[[ -n "${_SB_ENEMA_SAFETY_SH:-}" ]] && return 0
readonly _SB_ENEMA_SAFETY_SH=1

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

# ---------------------------------------------------------------------------
# safety_check_setup_mode()
#   Hard block: refuse any write operation if:
#     1. The system is NOT in Setup Mode, OR
#     2. The current PK already matches the PK on the exFAT volume.
#   Prints guidance on how to enter Setup Mode.
#   Returns 0 if safe to proceed, 1 if blocked.
# ---------------------------------------------------------------------------
safety_check_setup_mode() {
    local setup_mode
    setup_mode=$(efivar_get_setup_mode)

    if [[ "${setup_mode}" != "1" ]]; then
        log_error "SAFETY BLOCK: System is NOT in UEFI Setup Mode."
        echo
        echo -e "${RED}══════════════════════════════════════════════════════════════${RESET}"
        echo -e "${RED}  BLOCKED: System is not in UEFI Setup Mode${RESET}"
        echo -e "${RED}══════════════════════════════════════════════════════════════${RESET}"
        echo
        echo "  Secure Boot variables can only be modified in Setup Mode."
        echo
        echo -e "${BOLD}  How to enter Setup Mode:${RESET}"
        echo "    1. Reboot and enter your BIOS/UEFI firmware setup (DEL, F2, or F10)"
        echo "    2. Navigate to Security → Secure Boot"
        echo "    3. Look for 'Clear Secure Boot Keys' or 'Delete All Secure Boot Variables'"
        echo "    4. Confirm the deletion — this enables Setup Mode"
        echo "    5. Save and reboot into SB-ENEMA"
        echo
        return 1
    fi

    # Check if PK already matches the user-owned certificate on the USB drive.
    if ! efivar_is_empty PK; then
        local tmpdir
        tmpdir=$(mktemp -d) || {
            log_warn "Cannot check PK match: failed to create temp dir"
            return 0
        }
        if efivar_extract_certs PK "${tmpdir}" 2>/dev/null && \
                [[ -f "${tmpdir}/PK-0.der" ]]; then
            local fp
            fp=$(openssl x509 -in "${tmpdir}/PK-0.der" -inform DER -noout \
                    -fingerprint -sha256 2>/dev/null \
                    | sed 's/.*Fingerprint=//;s/://g' \
                    | tr '[:upper:]' '[:lower:]') || fp=""
            if [[ -n "${fp}" ]]; then
                local ownership
                ownership=$(certdb_identify_ownership_model "${fp}")
                if [[ "${ownership}" == "user" ]]; then
                    rm -rf "${tmpdir}"
                    log_error "SAFETY BLOCK: PK already matches the certificate on this USB drive."
                    echo
                    echo -e "${RED}══════════════════════════════════════════════════════════════${RESET}"
                    echo -e "${RED}  BLOCKED: PK already matches the USB drive certificate${RESET}"
                    echo -e "${RED}══════════════════════════════════════════════════════════════${RESET}"
                    echo
                    echo "  Re-enrollment is not needed. The PK in firmware already matches"
                    echo "  the certificate on this exFAT volume."
                    echo
                    echo "  If you need to re-enroll, first enter Setup Mode:"
                    echo "    1. Reboot into BIOS/UEFI firmware setup"
                    echo "    2. Clear all Secure Boot keys to enable Setup Mode"
                    echo "    3. Boot SB-ENEMA again"
                    echo
                    return 1
                fi
            fi
        fi
        rm -rf "${tmpdir}"
    fi

    return 0
}

# ---------------------------------------------------------------------------
# safety_check_battery()
#   If running on a laptop (check /sys/class/power_supply/), warn if battery
#   is below 20%. Does NOT block — only warns prominently.
#   Returns 0 always (advisory only).
# ---------------------------------------------------------------------------
safety_check_battery() {
    local supply_dir="/sys/class/power_supply"

    if [[ ! -d "${supply_dir}" ]]; then
        return 0
    fi

    local bat_dir
    for bat_dir in "${supply_dir}"/BAT* "${supply_dir}"/battery; do
        [[ -d "${bat_dir}" ]] || continue

        local capacity_file="${bat_dir}/capacity"
        if [[ -r "${capacity_file}" ]]; then
            local capacity
            capacity=$(cat "${capacity_file}" 2>/dev/null) || continue
            if [[ "${capacity}" -lt 20 ]]; then
                log_warn "SAFETY WARNING: Battery is at ${capacity}%. Plug in AC power before modifying Secure Boot variables!"
                echo
                echo -e "${YELLOW}══════════════════════════════════════════════════════════════${RESET}"
                echo -e "${YELLOW}  WARNING: Battery at ${capacity}%${RESET}"
                echo -e "${YELLOW}══════════════════════════════════════════════════════════════${RESET}"
                echo
                echo -e "  ${YELLOW}Modifying Secure Boot variables with low battery is risky.${RESET}"
                echo -e "  ${YELLOW}A power loss during enrollment could leave your system in${RESET}"
                echo -e "  ${YELLOW}a partially-enrolled state. Plug in AC power if possible.${RESET}"
                echo
            fi
            return 0
        fi
    done

    return 0
}

# ---------------------------------------------------------------------------
# safety_check_payload_integrity()
#   Verify SHA-256 checksums of all .auth payload files against the manifest
#   at /mnt/data/sb-enema/payloads/SHA256SUMS.
#   Returns 0 if all checksums match or no manifest exists, 1 on mismatch.
# ---------------------------------------------------------------------------
safety_check_payload_integrity() {
    local manifest="${DATA_MOUNT}/sb-enema/payloads/SHA256SUMS"

    if [[ ! -f "${manifest}" ]]; then
        log_warn "No SHA256SUMS manifest found at ${manifest}; skipping payload integrity check"
        return 0
    fi

    log_info "Verifying payload integrity against ${manifest}"

    local manifest_dir
    manifest_dir="$(dirname "${manifest}")"

    local fail=0
    local line
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "${line}" ]] && continue
        [[ "${line}" == \#* ]] && continue

        local expected_hash file_rel
        expected_hash=$(echo "${line}" | awk '{print $1}')
        file_rel=$(echo "${line}" | awk '{print $2}')

        # Strip leading ./ prefix
        file_rel="${file_rel#./}"

        local file_path="${manifest_dir}/${file_rel}"

        if [[ ! -f "${file_path}" ]]; then
            log_error "Payload file missing: ${file_path}"
            fail=1
            continue
        fi

        local actual_hash
        actual_hash=$(sha256sum "${file_path}" | awk '{print $1}')

        if [[ "${expected_hash}" != "${actual_hash}" ]]; then
            log_error "INTEGRITY MISMATCH: ${file_rel}"
            log_error "  Expected: ${expected_hash}"
            log_error "  Actual:   ${actual_hash}"
            fail=1
        else
            log_info "Payload OK: ${file_rel} (SHA256=${actual_hash})"
        fi
    done < "${manifest}"

    if [[ "${fail}" -ne 0 ]]; then
        echo
        echo -e "${RED}══════════════════════════════════════════════════════════════${RESET}"
        echo -e "${RED}  BLOCKED: Payload integrity check FAILED${RESET}"
        echo -e "${RED}══════════════════════════════════════════════════════════════${RESET}"
        echo
        echo "  One or more .auth payload files do not match the expected"
        echo "  SHA-256 checksums. This may indicate file corruption or tampering."
        echo
        echo "  Re-create the USB drive from a trusted source."
        echo
        return 1
    fi

    log_success "All payload checksums verified"
    return 0
}

# ---------------------------------------------------------------------------
# safety_verify_write <varname> <expected_fingerprints>
#   After writing a variable, re-read it and verify at least one enrolled
#   cert fingerprint matches at least one expected fingerprint.
#   <expected_fingerprints> is a newline-separated list of SHA-256 fingerprints
#   (typically all staged cert fingerprints for <varname>).  A payload ESL may
#   contain only a subset of the staged certs, so checking any-of-any is correct.
#   Passing a single fingerprint is also supported (backward compatible).
#   Returns 0 if verified, 1 if verification fails.
# ---------------------------------------------------------------------------
safety_verify_write() {
    local varname="$1"
    local expected_fps_raw="$2"

    # Build normalized set of expected fingerprints (lowercase, no colons).
    local -a expected_normalized=()
    local fp
    while IFS= read -r fp; do
        [[ -n "${fp}" ]] || continue
        expected_normalized+=("$(printf '%s' "${fp}" | tr -d ':' | tr '[:upper:]' '[:lower:]')")
    done <<< "${expected_fps_raw}"

    if [[ ${#expected_normalized[@]} -eq 0 ]]; then
        log_error "Cannot verify ${varname}: no expected fingerprints provided"
        return 1
    fi

    log_info "Verifying ${varname}: reading back enrolled certificate from efivarfs"
    if [[ ${#expected_normalized[@]} -eq 1 ]]; then
        log_info "  Expected SHA-256: ${expected_fps_raw}"
        log_info "  Expected (normalized): ${expected_normalized[0]}"
    else
        log_info "  Expected SHA-256 (any of ${#expected_normalized[@]}):"
        while IFS= read -r fp; do
            [[ -n "${fp}" ]] && log_info "    ${fp}"
        done <<< "${expected_fps_raw}"
    fi

    local tmpdir
    tmpdir=$(mktemp -d) || {
        log_error "Cannot verify ${varname}: failed to create temp dir"
        return 1
    }

    if ! efivar_extract_certs "${varname}" "${tmpdir}"; then
        log_error "VERIFY FAILED: Cannot read back ${varname} after write"
        rm -rf "${tmpdir}"
        return 1
    fi

    # Check if any enrolled cert matches any expected fingerprint.
    local idx=0
    local found=0
    local -a actual_fps=()
    while [[ -f "${tmpdir}/${varname}-${idx}.der" ]]; do
        local actual_fp
        log_info "  Checking cert ${idx}: openssl x509 -in ${varname}-${idx}.der -inform DER -noout -fingerprint -sha256"
        actual_fp=$(openssl x509 -in "${tmpdir}/${varname}-${idx}.der" -inform DER -noout \
                -fingerprint -sha256 2>/dev/null \
                | sed 's/.*Fingerprint=//;s/://g' \
                | tr '[:upper:]' '[:lower:]') || actual_fp=""
        log_info "  Cert ${idx} fingerprint: ${actual_fp}"
        actual_fps+=("${actual_fp}")
        local efp
        for efp in "${expected_normalized[@]}"; do
            if [[ "${actual_fp}" == "${efp}" ]]; then
                found=1
                break 2
            fi
        done
        idx=$((idx + 1))
    done

    rm -rf "${tmpdir}"

    if [[ "${found}" -eq 0 ]]; then
        log_error "VERIFY FAILED: No expected fingerprint found in ${varname} after write"
        if [[ ${#expected_normalized[@]} -eq 1 ]]; then
            log_error "  Expected: ${expected_fps_raw}"
        else
            log_error "  Expected (any of):"
            while IFS= read -r fp; do
                [[ -n "${fp}" ]] && log_error "    ${fp}"
            done <<< "${expected_fps_raw}"
        fi
        if [[ ${#actual_fps[@]} -eq 0 ]]; then
            log_error "  Found:    (no certificates extracted)"
        else
            local i=0
            for fp in "${actual_fps[@]}"; do
                log_error "  Found[${i}]: ${fp}"
                i=$((i + 1))
            done
        fi
        return 1
    fi

    log_success "Verified ${varname}: fingerprint confirmed"
    return 0
}

# ---------------------------------------------------------------------------
# safety_preflight <mode>
#   Run all applicable safety checks before enrollment.
#   Returns 0 if all hard-block checks pass, 1 otherwise.
# ---------------------------------------------------------------------------
safety_preflight() {
    local mode="${1:-}"
    local blocked=0

    log_info "Running safety preflight checks (mode: ${mode})"

    # Hard block: must be in Setup Mode and PK must not already match USB cert
    if ! safety_check_setup_mode; then
        blocked=1
    fi

    # Hard block: payload integrity
    if ! safety_check_payload_integrity; then
        blocked=1
    fi

    # Advisory: battery check (never blocks)
    safety_check_battery

    if [[ "${blocked}" -ne 0 ]]; then
        log_error "Safety preflight FAILED — enrollment blocked"
        log_action "PREFLIGHT" "${mode}" "FAIL" "safety checks blocked enrollment"
        return 1
    fi

    log_success "Safety preflight checks passed"
    log_action "PREFLIGHT" "${mode}" "SUCCESS" "all checks passed"
    return 0
}
