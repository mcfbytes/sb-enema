#!/usr/bin/env bash
# report.sh — Secure Boot Health Report renderer for SB-ENEMA.
# Consumes findings from audit_run_all() and renders a human-readable,
# terminal-friendly report to stdout and the log file.
# Requires common.sh, log.sh, efivar.sh, and audit.sh to be sourced first,
# or sources them itself when executed directly.
set -euo pipefail
[[ -n "${_SB_ENEMA_REPORT_SH:-}" ]] && return 0
readonly _SB_ENEMA_REPORT_SH=1

# ---------------------------------------------------------------------------
# Source required libraries
# ---------------------------------------------------------------------------
# shellcheck source=common.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/common.sh"
# shellcheck source=log.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/log.sh"
# shellcheck source=efivar.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/efivar.sh"
# shellcheck source=audit.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/audit.sh"

# ---------------------------------------------------------------------------
# Report output directory (on the exFAT data partition)
# ---------------------------------------------------------------------------
REPORT_DIR="${DATA_MOUNT}/sb-enema/reports"

# ---------------------------------------------------------------------------
# _report_print [text]
#   Emit text to stdout (with ANSI color support) and write the plain-text
#   version (ANSI stripped) to the log file via _log_raw.
# ---------------------------------------------------------------------------
_report_print() {
    local text="${1:-}"
    echo -e "${text}"
    local plain
    plain=$(printf '%s' "${text}" | sed "s/$(printf '\033')\[[0-9;]*m//g")
    _log_raw "${plain}"
}

# ---------------------------------------------------------------------------
# _report_hr
#   Print an 80-column horizontal rule of '=' characters.
# ---------------------------------------------------------------------------
_report_hr() {
    _report_print "$(printf '=%.0s' {1..80})"
}

# ---------------------------------------------------------------------------
# _report_section_hr
#   Print an 80-column section separator of '-' characters.
# ---------------------------------------------------------------------------
_report_section_hr() {
    _report_print "$(printf -- '-%.0s' {1..80})"
}

# ---------------------------------------------------------------------------
# _report_dmi_field <path>
#   Read a single DMI sysfs field, strip newlines and surrounding whitespace.
#   Returns "(unknown)" if the file is absent, unreadable, or empty/blank.
# ---------------------------------------------------------------------------
_report_dmi_field() {
    local path="$1"
    local value
    if [[ -r "${path}" ]]; then
        # Strip newlines and surrounding whitespace; tolerate read errors.
        value=$(tr -d '\n' < "${path}" 2>/dev/null \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//') || true
        if [[ -n "${value}" ]]; then
            printf '%s' "${value}"
        else
            echo "(unknown)"
        fi
    else
        echo "(unknown)"
    fi
}

# ---------------------------------------------------------------------------
# _report_cert_icon <der_file>
#   Print a one-word bracketed status tag for the given DER certificate:
#     [OK]   — valid and not expiring before 2026-06-01
#     [WARN] — valid but expiring before 2026-06-01
#     [EXP]  — already expired
# ---------------------------------------------------------------------------
_report_cert_icon() {
    local der_file="$1"
    if ! openssl x509 -in "${der_file}" -inform DER -checkend 0 >/dev/null 2>&1; then
        printf '%s' "${RED}[EXP]${RESET}"
        return
    fi
    local target_epoch
    target_epoch=$(date -d "2026-06-01T00:00:00Z" +%s 2>/dev/null) || target_epoch=1780272000
    local now_epoch
    now_epoch=$(date +%s)
    if [[ "${now_epoch}" -lt "${target_epoch}" ]]; then
        local seconds_remaining=$(( target_epoch - now_epoch ))
        if ! openssl x509 -in "${der_file}" -inform DER \
                -checkend "${seconds_remaining}" >/dev/null 2>&1; then
            printf '%s' "${YELLOW}[WARN]${RESET}"
            return
        fi
    fi
    printf '%s' "${GREEN}[OK]${RESET}"
}

# ---------------------------------------------------------------------------
# report_header()
#   Print the report header: host/date, all SMBIOS Type 0-3 fields, Secure
#   Boot state, Setup Mode flag, and PK ownership model.
# ---------------------------------------------------------------------------
report_header() {
    local hostname date_str
    hostname=$(hostname 2>/dev/null) || hostname="(unknown)"
    date_str=$(date -u "+%Y-%m-%d %H:%M:%S UTC" 2>/dev/null) || date_str="(unknown)"

    # Type 0 — BIOS Information
    local bios_vendor bios_version bios_date
    bios_vendor=$(_report_dmi_field /sys/class/dmi/id/bios_vendor)
    bios_version=$(_report_dmi_field /sys/class/dmi/id/bios_version)
    bios_date=$(_report_dmi_field /sys/class/dmi/id/bios_date)

    # Type 1 — System Information
    local sys_vendor product_name product_version product_family
    sys_vendor=$(_report_dmi_field /sys/class/dmi/id/sys_vendor)
    product_name=$(_report_dmi_field /sys/class/dmi/id/product_name)
    product_version=$(_report_dmi_field /sys/class/dmi/id/product_version)
    product_family=$(_report_dmi_field /sys/class/dmi/id/product_family)

    # Type 2 — Base Board Information
    local board_vendor board_name board_version
    board_vendor=$(_report_dmi_field /sys/class/dmi/id/board_vendor)
    board_name=$(_report_dmi_field /sys/class/dmi/id/board_name)
    board_version=$(_report_dmi_field /sys/class/dmi/id/board_version)

    # Type 3 — Chassis Information
    local chassis_vendor chassis_type chassis_version
    chassis_vendor=$(_report_dmi_field /sys/class/dmi/id/chassis_vendor)
    chassis_type=$(_report_dmi_field /sys/class/dmi/id/chassis_type)
    chassis_version=$(_report_dmi_field /sys/class/dmi/id/chassis_version)

    local sb_state setup_mode
    sb_state=$(efivar_get_secure_boot_state)
    setup_mode=$(efivar_get_setup_mode)

    local sb_str sm_str
    if [[ "${sb_state}" == "1" ]]; then
        sb_str="${GREEN}enabled${RESET}"
    else
        sb_str="${RED}disabled${RESET}"
    fi
    if [[ "${setup_mode}" == "1" ]]; then
        sm_str="${YELLOW}yes${RESET}"
    else
        sm_str="no"
    fi

    # Identify PK ownership model from the first PK certificate fingerprint.
    local ownership="unknown"
    if ! efivar_is_empty PK; then
        local tmpdir
        tmpdir=$(mktemp -d)
        if efivar_extract_certs PK "${tmpdir}" 2>/dev/null && \
                [[ -f "${tmpdir}/PK-0.der" ]]; then
            local fp
            fp=$(openssl x509 -in "${tmpdir}/PK-0.der" -inform DER -noout \
                    -fingerprint -sha256 2>/dev/null \
                    | sed 's/.*Fingerprint=//;s/://g' \
                    | tr '[:upper:]' '[:lower:]') || fp=""
            if [[ -n "${fp}" ]]; then
                ownership=$(certdb_identify_ownership_model "${fp}")
            fi
        fi
        rm -rf "${tmpdir}"
    fi

    _report_hr
    _report_print "${BOLD}  SB-ENEMA Secure Boot Health Report${RESET}"
    _report_hr
    _report_print ""
    _report_print "$(printf '  %-20s %s' "Host:"         "${hostname}")"
    _report_print "$(printf '  %-20s %s' "Date:"         "${date_str}")"
    _report_print ""
    _report_print "  ${BOLD}BIOS (Type 0)${RESET}"
    _report_print "$(printf '  %-24s %s' "  BIOS Vendor:"    "${bios_vendor}")"
    _report_print "$(printf '  %-24s %s' "  BIOS Version:"   "${bios_version}")"
    _report_print "$(printf '  %-24s %s' "  BIOS Date:"      "${bios_date}")"
    _report_print ""
    _report_print "  ${BOLD}System (Type 1)${RESET}"
    _report_print "$(printf '  %-24s %s' "  System Vendor:"  "${sys_vendor}")"
    _report_print "$(printf '  %-24s %s' "  Product Name:"   "${product_name}")"
    _report_print "$(printf '  %-24s %s' "  Product Version:" "${product_version}")"
    _report_print "$(printf '  %-24s %s' "  Product Family:" "${product_family}")"
    _report_print ""
    _report_print "  ${BOLD}Base Board (Type 2)${RESET}"
    _report_print "$(printf '  %-24s %s' "  Board Vendor:"   "${board_vendor}")"
    _report_print "$(printf '  %-24s %s' "  Board Name:"     "${board_name}")"
    _report_print "$(printf '  %-24s %s' "  Board Version:"  "${board_version}")"
    _report_print ""
    _report_print "  ${BOLD}Chassis (Type 3)${RESET}"
    _report_print "$(printf '  %-24s %s' "  Chassis Vendor:"  "${chassis_vendor}")"
    _report_print "$(printf '  %-24s %s' "  Chassis Type:"    "${chassis_type}")"
    _report_print "$(printf '  %-24s %s' "  Chassis Version:" "${chassis_version}")"
    _report_print ""
    _report_print "  Secure Boot:         ${sb_str}"
    _report_print "  Setup Mode:          ${sm_str}"
    _report_print "  Ownership Model:     ${ownership}"
    _report_print ""
}

# ---------------------------------------------------------------------------
# report_variable_summary()
#   For each Secure Boot variable (PK, KEK, db, dbx), list the certificates
#   with subject, issuer, expiry, and known-cert identification.
#   Uses [OK]/[WARN]/[EXP] tags for certificate validity.
# ---------------------------------------------------------------------------
report_variable_summary() {
    _report_section_hr
    _report_print "${BOLD}  Variable Summary${RESET}"
    _report_section_hr
    _report_print ""

    local varname
    for varname in PK KEK db dbx; do
        if efivar_is_empty "${varname}"; then
            _report_print "  ${YELLOW}[WARN]${RESET} ${BOLD}${varname}${RESET}: (empty)"
            _report_print ""
            continue
        fi

        local tmpdir
        tmpdir=$(mktemp -d)

        if ! efivar_extract_certs "${varname}" "${tmpdir}" 2>/dev/null; then
            _report_print "  ${RED}[ERR]${RESET}  ${BOLD}${varname}${RESET}: failed to extract certificates"
            rm -rf "${tmpdir}"
            _report_print ""
            continue
        fi

        # Count extracted certificates.
        local count=0
        while [[ -f "${tmpdir}/${varname}-${count}.der" ]]; do
            count=$(( count + 1 ))
        done

        _report_print "  ${BOLD}${varname}${RESET} (${count} certificate(s))"

        local index=0
        while [[ -f "${tmpdir}/${varname}-${index}.der" ]]; do
            local der_file="${tmpdir}/${varname}-${index}.der"

            local subject issuer not_after fp known_desc icon
            subject=$(openssl x509 -in "${der_file}" -inform DER -noout -subject 2>/dev/null \
                | sed 's/^subject= *//;s/^subject=//') || subject="(unknown)"
            issuer=$(openssl x509 -in "${der_file}" -inform DER -noout -issuer 2>/dev/null \
                | sed 's/^issuer= *//;s/^issuer=//') || issuer="(unknown)"
            not_after=$(openssl x509 -in "${der_file}" -inform DER -noout -enddate 2>/dev/null \
                | sed 's/^notAfter=//') || not_after="(unknown)"
            fp=$(openssl x509 -in "${der_file}" -inform DER -noout \
                    -fingerprint -sha256 2>/dev/null \
                    | sed 's/.*Fingerprint=//;s/://g' \
                    | tr '[:upper:]' '[:lower:]') || fp="(unknown)"
            known_desc=$(certdb_lookup "${fp}") || known_desc=""
            icon=$(_report_cert_icon "${der_file}")

            _report_print "    [${index}] ${icon} ${subject}"
            _report_print "        Issuer:  ${issuer}"
            _report_print "        Expires: ${not_after}"
            if [[ -n "${known_desc}" ]]; then
                _report_print "        Known:   ${GREEN}${known_desc}${RESET}"
            else
                _report_print "        Known:   (not in known-certs database)"
            fi

            index=$(( index + 1 ))
        done

        rm -rf "${tmpdir}"
        _report_print ""
    done
}

# ---------------------------------------------------------------------------
# report_findings()
#   Display audit findings grouped by severity (CRITICAL, HIGH, WARNING, INFO)
#   with color coding.  Expects AUDIT_FINDINGS to be populated.
# ---------------------------------------------------------------------------
report_findings() {
    _report_section_hr
    _report_print "${BOLD}  Audit Findings${RESET}"
    _report_section_hr
    _report_print ""

    if [[ ${#AUDIT_FINDINGS[@]} -eq 0 ]]; then
        _report_print "  ${GREEN}No findings.${RESET}"
        _report_print ""
        return
    fi

    local sev
    for sev in CRITICAL HIGH WARNING INFO; do
        local found=0
        local finding
        for finding in "${AUDIT_FINDINGS[@]}"; do
            local fsev fcomp fmsg
            fsev="${finding%%|*}"
            fcomp="${finding#*|}"
            fcomp="${fcomp%%|*}"
            fmsg="${finding##*|}"

            [[ "${fsev}" != "${sev}" ]] && continue

            local color
            case "${sev}" in
                CRITICAL) color="${RED}"    ;;
                HIGH)     color="${RED}"    ;;
                WARNING)  color="${YELLOW}" ;;
                *)        color="${RESET}"  ;;
            esac

            _report_print "  ${color}[${sev}]${RESET} ${BOLD}${fcomp}${RESET}: ${fmsg}"
            found=1
        done
        if [[ "${found}" -eq 1 ]]; then
            _report_print ""
        fi
    done
}

# ---------------------------------------------------------------------------
# report_2026_readiness()
#   Display a clear PASS or FAIL banner for 2026 Secure Boot readiness.
#   Expects AUDIT_2026_READY and AUDIT_FINDINGS to be populated.
# ---------------------------------------------------------------------------
report_2026_readiness() {
    _report_section_hr
    _report_print "${BOLD}  2026 Readiness${RESET}"
    _report_section_hr
    _report_print ""

    if [[ "${AUDIT_2026_READY}" == "yes" ]]; then
        _report_print "${GREEN}  +------------------------------------------+${RESET}"
        _report_print "${GREEN}  |  OK  2026-READY                          |${RESET}"
        _report_print "${GREEN}  +------------------------------------------+${RESET}"
    else
        _report_print "${RED}  +------------------------------------------+${RESET}"
        _report_print "${RED}  |  !!  NOT 2026-READY                      |${RESET}"
        _report_print "${RED}  +------------------------------------------+${RESET}"
        _report_print ""
        _report_print "  What's missing:"
        local finding
        for finding in "${AUDIT_FINDINGS[@]}"; do
            local fsev fcomp fmsg
            fsev="${finding%%|*}"
            fcomp="${finding#*|}"
            fcomp="${fcomp%%|*}"
            fmsg="${finding##*|}"
            if [[ "${fsev}" == "CRITICAL" ]] || [[ "${fsev}" == "HIGH" ]]; then
                _report_print "    ${RED}* [${fsev}] ${fcomp}: ${fmsg}${RESET}"
            fi
        done
    fi
    _report_print ""
}

# ---------------------------------------------------------------------------
# report_full()
#   Orchestrator: run the full audit and render all report sections.
# ---------------------------------------------------------------------------
report_full() {
    # Enable cert extraction cache so each EFI variable is read from efivarfs
    # only once per report cycle (audit functions populate it, report functions
    # serve from it without re-extracting).
    efivar_cert_cache_init
    # Guarantee cleanup even if a report step fails or returns early.
    trap 'efivar_cert_cache_clear' RETURN
    audit_run_all || true
    report_header
    report_variable_summary
    report_findings
    report_2026_readiness
    _report_hr
    efivar_cert_cache_clear
}

# ---------------------------------------------------------------------------
# report_save()
#   Save the full report without ANSI color codes to the exFAT data partition
#   at /mnt/data/sb-enema/reports/report-YYYYMMDD-HHMMSS.txt.
#   Prints the saved file path on success.
# ---------------------------------------------------------------------------
report_save() {
    mkdir -p "${REPORT_DIR}" || {
        log_error "Failed to create report directory: ${REPORT_DIR}"
        return 1
    }
    local outfile
    outfile="${REPORT_DIR}/report-$(date -u +%Y%m%d-%H%M%S).txt"
    report_full | sed "s/$(printf '\033')\[[0-9;]*m//g" > "${outfile}"
    log_info "Report saved to ${outfile}"
    echo "${outfile}"
}
