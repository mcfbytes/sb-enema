#!/usr/bin/env bash
# enroll.sh — Generic Secure Boot enrollment for SB-ENEMA.
# Applies staged .auth payloads from PAYLOAD_DIR in the correct order.
# shellcheck disable=SC2034  # Variables may be used by sourcing scripts.
set -euo pipefail
[[ -n "${_SB_ENEMA_ENROLL_SH:-}" ]] && return 0
readonly _SB_ENEMA_ENROLL_SH=1

# ---------------------------------------------------------------------------
# Source required libraries
# ---------------------------------------------------------------------------
# shellcheck source=common.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/common.sh"
# shellcheck source=log.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/log.sh"
# shellcheck source=safety.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/safety.sh"
# shellcheck source=update.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/update.sh"
# shellcheck source=preview.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/preview.sh"
# shellcheck source=keygen.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/keygen.sh"

# ---------------------------------------------------------------------------
# _enroll_staged_fingerprints <varname>
#   Print the SHA-256 fingerprint of every staged certificate for a variable
#   from PAYLOAD_DIR/<varname>/, one per line.  Used to verify writes.
#   A payload ESL may contain only a subset of the staged certs (e.g. the
#   KEK auth ESL holds only the 2023 cert while the staged dir also has the
#   2011 cert for preview).  Returning all fingerprints lets the caller pass
#   the full set to safety_verify_write, which succeeds when ANY enrolled cert
#   matches ANY expected fingerprint.
#   Returns 1 (empty output) if no certs are available.
# ---------------------------------------------------------------------------
_enroll_staged_fingerprints() {
    local varname="$1"
    local staged_dir="${PAYLOAD_DIR}/${varname}"

    [[ -d "${staged_dir}" ]] || return 1

    local _old_nullglob
    _old_nullglob=$(shopt -p nullglob) || true
    shopt -s nullglob

    local cert_file found=0
    for cert_file in "${staged_dir}"/*.der "${staged_dir}"/*.crt "${staged_dir}"/*.cer; do
        [[ -f "${cert_file}" ]] || continue
        local fp
        fp=$(openssl x509 -in "${cert_file}" -inform DER -noout -fingerprint -sha256 2>/dev/null \
                | sed 's/.*Fingerprint=//') \
        || fp=$(openssl x509 -in "${cert_file}" -inform PEM -noout -fingerprint -sha256 2>/dev/null \
                | sed 's/.*Fingerprint=//') \
        || continue
        echo "${fp}"
        found=1
    done
    # Restore nullglob after the loop: glob expansion happens once at loop entry,
    # so restoring here (rather than inside the loop) is safe.  We never return
    # early from inside the loop, so cleanup is always reached.

    eval "${_old_nullglob}"
    [[ "${found}" -eq 1 ]]
}

# ---------------------------------------------------------------------------
# _enroll_report_partial_failure <failed_var> <enrolled_vars>
#   Log and display a summary of what was and wasn't applied when an
#   enrollment step fails.
# ---------------------------------------------------------------------------
_enroll_report_partial_failure() {
    local failed_var="$1"
    local enrolled="$2"

    log_error "Enrollment stopped at ${failed_var}"
    log_error "Successfully enrolled: ${enrolled}"
    log_error "NOT enrolled: ${failed_var} and any remaining variables"

    echo
    echo -e "${RED}ENROLLMENT INCOMPLETE${RESET}"
    echo -e "${RED}  Failed on: ${failed_var}${RESET}"
    echo -e "${RED}  Applied:   ${enrolled}${RESET}"
    echo -e "${RED}  The remaining variables were not written.${RESET}"
    echo
}

# ---------------------------------------------------------------------------
# _enroll_is_auth_file <file>
#   Returns 0 if <file> is an EFI_VARIABLE_AUTHENTICATION_2 signed auth file;
#   returns 1 if it is a raw EFI Signature List (no auth header).
#   Detection: WIN_CERTIFICATE.wCertificateType == 0x0EF1 at byte offset 22,
#   which is the same heuristic used by _dbx_esl_from_auth_or_raw() in stage.sh.
#
#   Signed auth files must be written via:  efi-updatevar -f <file> <var>
#   Raw ESLs (Setup Mode only) must use:    efi-updatevar -e -f <file> <var>
# ---------------------------------------------------------------------------
_enroll_is_auth_file() {
    local file="$1"
    # File must be at least 24 bytes to contain the WIN_CERTIFICATE type field at offset 22.
    # Too-small files (or unreadable ones) are treated as raw ESLs; efi-updatevar will catch
    # any real I/O error.  dd stderr is suppressed to avoid spurious enrollment log noise.
    local fsize
    fsize=$(wc -c < "${file}" 2>/dev/null || echo 0)
    if [[ "${fsize}" -lt 24 ]]; then
        return 1
    fi
    local type_bytes
    type_bytes=$(dd if="${file}" bs=1 skip=22 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [[ "${type_bytes}" == "f10e" ]]
}

# ---------------------------------------------------------------------------
# _enroll_var <varname> <auth_file> <enrolled_vars_ref> [expected_fps]
#   Internal helper: write one EFI variable using efi-updatevar, verify,
#   log, and handle failure.
#   <enrolled_vars_ref> is a nameref to the array tracking enrolled vars.
#   <expected_fps> is a newline-separated list of SHA-256 fingerprints from
#   all staged certs for <varname>; verification succeeds when ANY enrolled
#   cert matches ANY expected fingerprint.
#   Returns 0 on success, calls _enroll_report_partial_failure and returns 1
#   on failure.
# ---------------------------------------------------------------------------
_enroll_var() {
    local varname="$1"
    local auth_file="$2"
    local -n _enrolled_ref="$3"
    local expected_fps="${4:-}"

    local var_label
    case "${varname}" in
        PK)  var_label="PK (Platform Key)" ;;
        KEK) var_label="KEK (Key Exchange Key)" ;;
        db)  var_label="db (Allowed Signatures Database)" ;;
        dbx) var_label="dbx (Forbidden Signatures Database)" ;;
        *)   var_label="${varname}" ;;
    esac

    log_info "Enrolling ${var_label}"

    # Use -f for signed EFI_VARIABLE_AUTHENTICATION_2 auth files:
    #   • microsoft/PK.auth (from Imaging/PK.bin — pre-signed MS auth)
    #   • user-signed payloads from stage_sign_db(), stage_user_pk_kek(), etc.
    # Use -e -f for raw EFI Signature Lists (Setup Mode only):
    #   • microsoft/KEK.auth, db.auth, dbx.auth (from Firmware/*.bin raw ESLs)
    local -a efi_args
    if _enroll_is_auth_file "${auth_file}"; then
        efi_args=("-f")
    else
        efi_args=("-e" "-f")
        log_info "Payload is a raw ESL; using Setup Mode write (-e -f)"
    fi

    log_info "Running: efi-updatevar ${efi_args[*]} ${auth_file} ${varname}"

    local rc=0
    efi-updatevar "${efi_args[@]}" "${auth_file}" "${varname}" || rc=$?

    if [[ "${rc}" -eq 0 ]]; then
        local sha256
        sha256=$(sha256sum "${auth_file}" | awk '{print $1}')
        log_action "ENROLL" "${varname}" "SUCCESS" "SHA256=${sha256}"
        _enrolled_ref+=("${varname}")

        # Post-write verification (if expected fingerprints provided)
        if [[ -n "${expected_fps}" ]] && ! safety_verify_write "${varname}" "${expected_fps}"; then
            log_action "VERIFY" "${varname}" "FAIL" "post-write verification failed"
            local enrolled_str="${_enrolled_ref[*]:-}"
            _enroll_report_partial_failure "${varname} (verification)" "${enrolled_str:-(none)}"
            echo -e "${RED}  Re-enter Setup Mode and try again.${RESET}"
            return 1
        fi
        return 0
    else
        log_action "ENROLL" "${varname}" "FAIL" "efi-updatevar returned exit code ${rc}"
        log_error "Failed to enroll ${varname}"
        local enrolled_str="${_enrolled_ref[*]:-}"
        _enroll_report_partial_failure "${varname}" "${enrolled_str:-(none)}"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# enroll() — Apply staged .auth payloads in correct order: db → dbx → KEK → PK
#   Skips variables that have no staged .auth file.
#   Calls safety_preflight, update_compute "generic", preview_display,
#   preview_confirm, then efi-updatevar for each staged variable.
# ---------------------------------------------------------------------------
enroll() {
    # Safety preflight
    if ! safety_preflight "generic"; then
        return 1
    fi

    # Compute delta and show preview
    update_compute "generic"
    preview_display
    preview_log

    if ! preview_confirm; then
        log_info "User declined enrollment"
        return 1
    fi

    # Collect all staged cert fingerprints for post-write verification.
    # A payload ESL may contain only a subset of the staged certs (e.g. the
    # microsoft/ KEK ESL holds only the 2023 cert; the staged dir also has
    # the 2011 cert for preview).  Passing all staged fingerprints ensures
    # verification passes when ANY enrolled cert matches ANY staged cert.
    local pk_fps kek_fps
    pk_fps=$(_enroll_staged_fingerprints "PK") || pk_fps=""
    kek_fps=$(_enroll_staged_fingerprints "KEK") || kek_fps=""

    [[ -z "${pk_fps}" ]]  && log_warn "No staged PK certificate found; PK post-write verification will be skipped"
    [[ -z "${kek_fps}" ]] && log_warn "No staged KEK certificate found; KEK post-write verification will be skipped"

    # Enroll variables in order: db → dbx → KEK → PK
    # PK MUST be last because writing PK transitions from Setup Mode to User Mode.
    local enrolled_vars=()

    # 1. db
    if [[ -f "${PAYLOAD_DIR}/db.auth" ]]; then
        _enroll_var "db" "${PAYLOAD_DIR}/db.auth" enrolled_vars || return 1
    fi

    # 2. dbx
    if [[ -f "${PAYLOAD_DIR}/dbx.auth" ]]; then
        _enroll_var "dbx" "${PAYLOAD_DIR}/dbx.auth" enrolled_vars || return 1
    fi

    # 3. KEK
    if [[ -f "${PAYLOAD_DIR}/KEK.auth" ]]; then
        _enroll_var "KEK" "${PAYLOAD_DIR}/KEK.auth" enrolled_vars "${kek_fps}" || return 1
    fi

    # 4. PK (LAST — writing PK exits Setup Mode)
    if [[ -f "${PAYLOAD_DIR}/PK.auth" ]]; then
        _enroll_var "PK" "${PAYLOAD_DIR}/PK.auth" enrolled_vars "${pk_fps}" || return 1
    fi

    if [[ ${#enrolled_vars[@]} -eq 0 ]]; then
        log_warn "No .auth files staged — nothing to enroll"
        echo -e "${YELLOW}  No staged payloads found. Stage content before enrolling.${RESET}"
        return 0
    fi

    log_success "Enrollment complete. Variables enrolled: ${enrolled_vars[*]}"

    # Sign BOOTX64.EFI with user DB cert if user keys are available
    if [[ -f "${KEYS_DIR}/PK.key" ]]; then
        _keygen_sign_bootx64
        keygen_backup_instructions
    fi
}
