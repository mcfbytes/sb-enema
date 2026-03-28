#!/usr/bin/env bash
# stage.sh — Staging functions for SB-ENEMA Secure Boot enrollment pipeline.
# Populates PAYLOAD_DIR subdirectories with certificate files and .auth payloads
# ready for the generic enroll() function to apply.
# shellcheck disable=SC2034  # Variables may be used by sourcing scripts.
set -euo pipefail
[[ -n "${_SB_ENEMA_STAGE_SH:-}" ]] && return 0
readonly _SB_ENEMA_STAGE_SH=1

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
# shellcheck source=update.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/update.sh"
# shellcheck source=preview.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/preview.sh"
# shellcheck source=keygen.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/keygen.sh"

# ---------------------------------------------------------------------------
# Pre-signed Microsoft .auth payload directory (read-only, from build time)
# ---------------------------------------------------------------------------
MSFT_PAYLOADS_SUBDIR="${PAYLOAD_DIR}/microsoft"

# Pre-signed Microsoft objects staged on the data partition at build time
MSFT_PRESIGNED_DIR="${DATA_MOUNT}/PreSignedObjects"

# ---------------------------------------------------------------------------
# SHA-256 fingerprints of legacy Microsoft certificates excluded from the
# Custom-Owned (user-key) enrollment path.  Both are expiring in 2026 and
# are superseded by their 2023 counterparts.
# ---------------------------------------------------------------------------
readonly _STAGE_MS_KEK_CA_2011_FP="a1117f516a32cefcba3f2d1ace10a87972fd6bbe8fe0d0b996e09e65d802a503"
readonly _STAGE_MS_WIN_PCA_2011_FP="e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"

# ---------------------------------------------------------------------------
# Path to kek_update_map.json — maps SHA-1 PK fingerprints to KEK update bins.
# Populated at build time by prepare-secureboot-objects.sh from the
# third_party/secureboot_objects submodule (PostSignedObjects/KEK/).
# ---------------------------------------------------------------------------
KEK_UPDATE_MAP="${DATA_MOUNT}/sb-enema/kek_update_map.json"

# ---------------------------------------------------------------------------
# stage_clear()
#   Remove all staged content from PAYLOAD_DIR except the microsoft/
#   subdirectory (which contains read-only pre-built payloads).
# ---------------------------------------------------------------------------
stage_clear() {
    log_info "Clearing staging area (preserving microsoft/ subdirectory)"

    if [[ ! -d "${PAYLOAD_DIR}" ]]; then
        mkdir -p "${PAYLOAD_DIR}"
        log_info "Created empty staging area at ${PAYLOAD_DIR}"
        return 0
    fi

    local _old_nullglob
    _old_nullglob=$(shopt -p nullglob) || true
    shopt -s nullglob

    local item
    for item in "${PAYLOAD_DIR}"/*; do
        [[ -e "${item}" ]] || continue
        [[ "$(basename "${item}")" == "microsoft" ]] && continue
        rm -rf "${item}"
        log_info "Removed staged item: ${item}"
    done

    eval "${_old_nullglob}"
    log_success "Staging area cleared"
}

# ---------------------------------------------------------------------------
# stage_show()
#   Display what is currently staged in PAYLOAD_DIR.
# ---------------------------------------------------------------------------
stage_show() {
    echo
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  Currently Staged Content${RESET}"
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo

    if [[ ! -d "${PAYLOAD_DIR}" ]]; then
        echo -e "${DIM}  Staging area is empty (${PAYLOAD_DIR} does not exist)${RESET}"
        echo
        return
    fi

    local found_any=0

    local varname
    for varname in PK KEK db dbx; do
        local subdir="${PAYLOAD_DIR}/${varname}"
        if [[ -d "${subdir}" ]]; then
            local _old_nullglob
            _old_nullglob=$(shopt -p nullglob) || true
            shopt -s nullglob
            local files=("${subdir}"/*)
            eval "${_old_nullglob}"
            if [[ ${#files[@]} -gt 0 ]]; then
                echo -e "  ${BOLD}${varname}/${RESET}"
                local f
                for f in "${files[@]}"; do
                    echo "    $(basename "${f}")"
                done
                found_any=1
            fi
        fi
        local auth_file="${PAYLOAD_DIR}/${varname}.auth"
        if [[ -f "${auth_file}" ]]; then
            local sha256
            sha256=$(sha256sum "${auth_file}" | awk '{print $1}') || sha256="(unknown)"
            echo -e "  ${GREEN}${varname}.auth${RESET} (SHA256: ${sha256})"
            found_any=1
        fi
    done

    if [[ "${found_any}" -eq 0 ]]; then
        echo -e "${DIM}  No staged content found${RESET}"
    fi

    echo
}

# ---------------------------------------------------------------------------
# stage_show_delta()
#   Show what would change between staged content and current EFI state.
#   Calls update_compute "generic" then preview_display without confirming.
# ---------------------------------------------------------------------------
stage_show_delta() {
    log_info "Computing delta between staged content and current EFI state"
    update_compute "generic"
    preview_display
    preview_log
}

# ---------------------------------------------------------------------------
# _pk_is_auth_file <file>
#   Returns 0 if <file> has a WIN_CERT_TYPE_EFI_GUID marker (0x0EF1) at
#   byte offset 22, indicating an EFI_VARIABLE_AUTHENTICATION_2 auth file.
#   Returns 1 for raw EFI Signature Lists (no auth header).
# ---------------------------------------------------------------------------
_pk_is_auth_file() {
    local file="$1"
    local fsize type_bytes
    fsize=$(wc -c < "${file}" 2>/dev/null || echo 0)
    [[ "${fsize}" -ge 24 ]] || return 1
    type_bytes=$(dd if="${file}" bs=1 skip=22 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [[ "${type_bytes}" == "f10e" ]]
}

# ---------------------------------------------------------------------------
# _pk_wrap_esl <src_esl> <dst_auth>
#   Prepend a 77-byte EFI_VARIABLE_AUTHENTICATION_2 header to the raw ESL
#   <src_esl> and write the result to <dst_auth>.
#
#   Header layout (77 bytes):
#     EFI_TIME (16):        2010-03-06T19:17:21Z, TZ=0x07FF (unspecified)
#     WIN_CERT_UEFI_GUID:   dwLength=0x3D, wRevision=0x0200,
#                           wCertificateType=0x0EF1 (WIN_CERT_TYPE_EFI_GUID),
#                           CertType=EFI_CERT_TYPE_PKCS7_GUID,
#                           + empty PKCS7 CMS structure (37 bytes)
#
#   This matches what the Microsoft secureboot_objects Python script writes to
#   Imaging/PK.bin.  UEFI spec §32.3.2: when PK is NULL the firmware MUST
#   accept any valid EFI_VARIABLE_AUTHENTICATION_2 payload unconditionally,
#   so the empty PKCS7 signature is sufficient for first-time PK enrollment.
# ---------------------------------------------------------------------------
_pk_wrap_esl() {
    local src="$1"
    local dst="$2"
    # shellcheck disable=SC2059
    if ! printf '\xda\x07\x03\x06\x13\x11\x15\x00\x00\x00\x00\x00\xff\x07\x00\x00\x3d\x00\x00\x00\x00\x02\xf1\x0e\x9d\xd2\xaf\x4a\xdf\x68\xee\x49\x8a\xa9\x34\x7d\x37\x56\x65\xa7\x30\x23\x02\x01\x01\x31\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\x31\x00' > "${dst}" || \
       ! cat "${src}" >> "${dst}"; then
        rm -f "${dst}"
        die "_pk_wrap_esl: failed to write auth-wrapped PK payload to ${dst}"
    fi
}

# ---------------------------------------------------------------------------
# stage_microsoft_pk()
#   Stage Microsoft PK certificate files from PreSignedObjects and copy
#   PK.auth from the microsoft/ subdirectory into PAYLOAD_DIR.
#
#   The microsoft/PK.auth payload is from Imaging/PK.bin (new builds), which
#   is a pre-signed EFI_VARIABLE_AUTHENTICATION_2 auth file.  Older builds
#   stored Firmware/PK.bin (raw ESL) there; _pk_wrap_esl() adds the required
#   auth header at runtime so these devices do not need a full reflash.
#   Does NOT overwrite an existing PAYLOAD_DIR/PK.auth.
# ---------------------------------------------------------------------------
stage_microsoft_pk() {
    log_info "Staging Microsoft PK"

    if [[ ! -f "${MSFT_PAYLOADS_SUBDIR}/PK.auth" ]]; then
        die "Microsoft PK.auth not found at ${MSFT_PAYLOADS_SUBDIR}/PK.auth"
    fi

    mkdir -p "${PAYLOAD_DIR}/PK"

    local _old_nullglob
    _old_nullglob=$(shopt -p nullglob) || true
    shopt -s nullglob

    local pk_certs_dir="${MSFT_PRESIGNED_DIR}/PK/Certificate"
    if [[ -d "${pk_certs_dir}" ]]; then
        local cert_file
        for cert_file in "${pk_certs_dir}"/*.der "${pk_certs_dir}"/*.crt "${pk_certs_dir}"/*.cer; do
            [[ -f "${cert_file}" ]] || continue
            cp "${cert_file}" "${PAYLOAD_DIR}/PK/"
            log_info "Staged MS PK cert: $(basename "${cert_file}")"
        done
    else
        log_warn "Microsoft PK Certificate directory not found: ${pk_certs_dir}"
    fi

    eval "${_old_nullglob}"

    if [[ ! -f "${PAYLOAD_DIR}/PK.auth" ]]; then
        local src="${MSFT_PAYLOADS_SUBDIR}/PK.auth"
        if _pk_is_auth_file "${src}"; then
            cp "${src}" "${PAYLOAD_DIR}/PK.auth"
        else
            log_info "microsoft/PK.auth is a raw ESL (pre-Imaging build); wrapping with time-based auth header"
            _pk_wrap_esl "${src}" "${PAYLOAD_DIR}/PK.auth"
        fi
        local sha256
        sha256=$(sha256sum "${PAYLOAD_DIR}/PK.auth" | awk '{print $1}')
        log_action "STAGE" "PK.auth" "SUCCESS" "from microsoft/ SHA256=${sha256}"
    else
        log_info "PK.auth already staged; not overwriting with Microsoft version"
    fi

    log_success "Microsoft PK staged"
}

# ---------------------------------------------------------------------------
# stage_microsoft_kek_db_dbx()
#   Stage Microsoft KEK, DB, and DBX certificates and copy .auth files from
#   the microsoft/ subdirectory into PAYLOAD_DIR.
#   Additive: does NOT overwrite existing .auth files already staged.
# ---------------------------------------------------------------------------
stage_microsoft_kek_db_dbx() {
    log_info "Staging Microsoft KEK, DB, DBX"

    for payload in KEK.auth db.auth dbx.auth; do
        if [[ ! -f "${MSFT_PAYLOADS_SUBDIR}/${payload}" ]]; then
            die "Microsoft payload missing: ${MSFT_PAYLOADS_SUBDIR}/${payload}"
        fi
    done

    mkdir -p "${PAYLOAD_DIR}/KEK" "${PAYLOAD_DIR}/db" "${PAYLOAD_DIR}/dbx"

    local _old_nullglob
    _old_nullglob=$(shopt -p nullglob) || true
    shopt -s nullglob

    # Stage KEK certificates
    local kek_certs_dir="${MSFT_PRESIGNED_DIR}/KEK/Certificates"
    if [[ -d "${kek_certs_dir}" ]]; then
        local cert_file
        for cert_file in "${kek_certs_dir}"/*.der "${kek_certs_dir}"/*.crt "${kek_certs_dir}"/*.cer; do
            [[ -f "${cert_file}" ]] || continue
            cp "${cert_file}" "${PAYLOAD_DIR}/KEK/"
            log_info "Staged MS KEK cert: $(basename "${cert_file}")"
        done
    else
        log_warn "Microsoft KEK Certificates directory not found: ${kek_certs_dir}"
    fi

    # Stage DB certificates
    local db_certs_dir="${MSFT_PRESIGNED_DIR}/DB/Certificates"
    if [[ -d "${db_certs_dir}" ]]; then
        local cert_file
        for cert_file in "${db_certs_dir}"/*.der "${db_certs_dir}"/*.crt "${db_certs_dir}"/*.cer; do
            [[ -f "${cert_file}" ]] || continue
            cp "${cert_file}" "${PAYLOAD_DIR}/db/"
            log_info "Staged MS DB cert: $(basename "${cert_file}")"
        done
    else
        log_warn "Microsoft DB Certificates directory not found: ${db_certs_dir}"
    fi

    eval "${_old_nullglob}"

    # Stage raw dbx ESL for preview engine (strip auth header if source is a pre-signed
    # auth file; skip if _stage_build_dbx_payload already staged the ESL)
    local dbx_src=""
    dbx_src=$(_find_dbx_binary) || true
    if [[ -n "${dbx_src}" ]] && [[ ! -f "${PAYLOAD_DIR}/dbx/dbx.esl" ]]; then
        _dbx_esl_from_auth_or_raw "${dbx_src}" "${PAYLOAD_DIR}/dbx/dbx.esl"
        log_info "Staged DBX raw ESL for preview"
    fi

    # Copy .auth files — do not overwrite existing staged auth files
    local payload varname
    for payload in KEK.auth db.auth dbx.auth; do
        varname="${payload%.auth}"
        if [[ ! -f "${PAYLOAD_DIR}/${payload}" ]]; then
            cp "${MSFT_PAYLOADS_SUBDIR}/${payload}" "${PAYLOAD_DIR}/${payload}"
            local sha256
            sha256=$(sha256sum "${PAYLOAD_DIR}/${payload}" | awk '{print $1}')
            log_action "STAGE" "${payload}" "SUCCESS" "from microsoft/ SHA256=${sha256}"
        else
            log_info "${payload} already staged; not overwriting with Microsoft version"
        fi
    done

    log_success "Microsoft KEK, DB, DBX staged"
}

# ---------------------------------------------------------------------------
# _stage_cert_fp <pem_file>
#   Print the SHA-256 fingerprint of a PEM certificate as lowercase hex
#   without colons.  Returns an empty string on error.
# ---------------------------------------------------------------------------
_stage_cert_fp() {
    [[ -f "$1" && -r "$1" ]] || return 0
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/.*Fingerprint=//;s/://g' \
        | tr '[:upper:]' '[:lower:]'
}

# ---------------------------------------------------------------------------
# _stage_build_kek_esl <workdir> <kek_crt> <owner_guid>
#   Internal helper: combine user KEK + Microsoft KEK + any vendor-staged KEK
#   certificates into a single ESL at <workdir>/KEK.esl.
#   Vendor-staged certs are files matching "default-KEKDefault-*.der" in
#   PAYLOAD_DIR/KEK/ (placed there by stage_bios_entries()).  Only that glob
#   is used so that Microsoft-owned .der files copied into PAYLOAD_DIR/KEK/
#   by stage_microsoft_kek_db_dbx() are not double-counted.
# ---------------------------------------------------------------------------
_stage_build_kek_esl() {
    local workdir="$1"
    local kek_crt="$2"
    local owner_guid="$3"
    local combined_esl="${workdir}/KEK.esl"

    : > "${combined_esl}"

    local user_kek_esl="${workdir}/KEK-user.esl"
    cert-to-efi-sig-list -g "${owner_guid}" "${kek_crt}" "${user_kek_esl}"
    cat "${user_kek_esl}" >> "${combined_esl}"
    log_info "Added user KEK certificate"

    local kek_certs_dir="${MSFT_PRESIGNED_DIR}/KEK/Certificates"
    if [[ -d "${kek_certs_dir}" ]]; then
        local _old_nullglob
        _old_nullglob=$(shopt -p nullglob) || true
        shopt -s nullglob
        local cert_file
        for cert_file in "${kek_certs_dir}"/*.der \
                         "${kek_certs_dir}"/*.crt \
                         "${kek_certs_dir}"/*.cer; do
            local tmp_esl cert_pem
            tmp_esl="${workdir}/KEK-ms-$(basename "${cert_file}").esl"
            case "${cert_file}" in
                *.der|*.cer)
                    cert_pem="${workdir}/KEK-ms-$(basename "${cert_file%.*}").pem"
                    openssl x509 -inform DER -in "${cert_file}" -out "${cert_pem}"
                    ;;
                *)
                    cert_pem="${cert_file}"
                    ;;
            esac
            # Exclude legacy Microsoft Corporation KEK CA 2011 from Custom-Owned
            # enrollments.  The 2023 replacement (KEK 2K CA 2023) is the current
            # recommended KEK for all new provisioning.
            local cert_fp
            cert_fp=$(_stage_cert_fp "${cert_pem}")
            if [[ -z "${cert_fp}" ]]; then
                log_warn "Could not compute fingerprint for KEK cert $(basename "${cert_file}"); including it"
            elif [[ "${cert_fp}" == "${_STAGE_MS_KEK_CA_2011_FP}" ]]; then
                log_info "Excluding legacy Microsoft Corporation KEK CA 2011 from Custom-Owned KEK"
                continue
            fi
            cert-to-efi-sig-list -g "${owner_guid}" "${cert_pem}" "${tmp_esl}"
            cat "${tmp_esl}" >> "${combined_esl}"
            log_info "Added Microsoft KEK certificate: $(basename "${cert_file}")"
        done
        eval "${_old_nullglob}"
    else
        log_warn "Microsoft KEK certificates not found in ${kek_certs_dir}; KEK will contain only user key"
    fi

    # Include vendor default KEK certs staged by stage_bios_entries().
    # Only files matching the naming convention "default-KEKDefault-*.der" are
    # included, so that Microsoft-owned .der files copied into PAYLOAD_DIR/KEK/
    # by stage_microsoft_kek_db_dbx() are not accidentally double-counted.
    if [[ -d "${PAYLOAD_DIR}/KEK" ]]; then
        local _old_nullglob_vendor
        _old_nullglob_vendor=$(shopt -p nullglob) || true
        shopt -s nullglob
        local vendor_der
        for vendor_der in "${PAYLOAD_DIR}/KEK"/default-KEKDefault-*.der; do
            local vendor_tmp_esl vendor_cert_pem
            vendor_tmp_esl="${workdir}/KEK-vendor-$(basename "${vendor_der}").esl"
            vendor_cert_pem="${workdir}/KEK-vendor-$(basename "${vendor_der%.*}").pem"
            openssl x509 -inform DER -in "${vendor_der}" -out "${vendor_cert_pem}"
            cert-to-efi-sig-list -g "${owner_guid}" "${vendor_cert_pem}" "${vendor_tmp_esl}"
            cat "${vendor_tmp_esl}" >> "${combined_esl}"
            log_info "Added staged vendor KEK certificate: $(basename "${vendor_der}")"
        done
        eval "${_old_nullglob_vendor}"
    fi
}

# ---------------------------------------------------------------------------
# _stage_build_db_esl <workdir> <owner_guid>
#   Internal helper: combine all staged db certificates into a single ESL.
#   Reads from PAYLOAD_DIR/db/ which must be populated before calling.
# ---------------------------------------------------------------------------
_stage_build_db_esl() {
    local workdir="$1"
    local owner_guid="$2"
    local combined_esl="${workdir}/db.esl"

    : > "${combined_esl}"

    local _old_nullglob
    _old_nullglob=$(shopt -p nullglob) || true
    shopt -s nullglob

    if [[ -d "${PAYLOAD_DIR}/db" ]]; then
        local cert_file
        for cert_file in "${PAYLOAD_DIR}/db"/*.der \
                         "${PAYLOAD_DIR}/db"/*.crt \
                         "${PAYLOAD_DIR}/db"/*.cer; do
            local tmp_esl cert_pem
            tmp_esl="${workdir}/db-$(basename "${cert_file}").esl"
            case "${cert_file}" in
                *.der|*.cer)
                    cert_pem="${workdir}/db-$(basename "${cert_file%.*}").pem"
                    openssl x509 -inform DER -in "${cert_file}" -out "${cert_pem}"
                    ;;
                *)
                    cert_pem="${cert_file}"
                    ;;
            esac
            # Exclude legacy Microsoft Windows Production PCA 2011 from Custom-Owned
            # db enrollments.  This PCA is superseded by Windows UEFI CA 2023 and is
            # not a UEFI Secure Boot certificate.  The 2023 replacement certificates
            # (Microsoft UEFI CA 2023, Microsoft Option ROM UEFI CA 2023) are present
            # in PreSignedObjects and will be included via this same loop.
            local cert_fp
            cert_fp=$(_stage_cert_fp "${cert_pem}")
            if [[ -z "${cert_fp}" ]]; then
                log_warn "Could not compute fingerprint for db cert $(basename "${cert_file}"); including it"
            elif [[ "${cert_fp}" == "${_STAGE_MS_WIN_PCA_2011_FP}" ]]; then
                log_info "Excluding Microsoft Windows Production PCA 2011 from Custom-Owned db"
                continue
            fi
            cert-to-efi-sig-list -g "${owner_guid}" "${cert_pem}" "${tmp_esl}"
            cat "${tmp_esl}" >> "${combined_esl}"
            log_info "Added db certificate: $(basename "${cert_file}")"
        done
    fi

    eval "${_old_nullglob}"

    if [[ ! -s "${combined_esl}" ]]; then
        die "No db certificates found in ${PAYLOAD_DIR}/db"
    fi
}

# ---------------------------------------------------------------------------
# _dbx_esl_from_auth_or_raw <source_file> <out_esl_file>
#   Extract the raw EFI Signature List from <source_file> and write it to
#   <out_esl_file>.  Handles two input formats:
#
#   EFI_VARIABLE_AUTHENTICATION_2 (.auth / .bin pre-signed by MS):
#     Detected by WIN_CERTIFICATE.wCertificateType == 0x0EF1 at byte offset 22.
#     The auth header (EFI_TIME + WIN_CERTIFICATE) is stripped; only the raw
#     EFI Signature List payload that follows is written to <out_esl_file>.
#
#   Raw EFI Signature List:
#     Copied verbatim to <out_esl_file>.
#
#   If sign-efi-sig-list receives a pre-signed auth file instead of a raw ESL,
#   it double-wraps it, producing a malformed payload the firmware rejects.
# ---------------------------------------------------------------------------
_dbx_esl_from_auth_or_raw() {
    local src="$1"
    local out="$2"

    # Detect EFI_VARIABLE_AUTHENTICATION_2: wCertificateType = 0x0EF1 at offset 22
    local type_bytes
    type_bytes=$(dd if="${src}" bs=1 skip=22 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')

    if [[ "${type_bytes}" == "f10e" ]]; then
        # Auth file: read WIN_CERTIFICATE.dwLength (uint32 LE) at offset 16
        local len_bytes win_cert_len esl_offset
        len_bytes=$(dd if="${src}" bs=1 skip=16 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
        win_cert_len=$(( 16#${len_bytes:6:2} * 16777216 + 16#${len_bytes:4:2} * 65536 + \
                         16#${len_bytes:2:2} * 256 + 16#${len_bytes:0:2} ))
        esl_offset=$(( 16 + win_cert_len ))
        tail -c "+$((esl_offset + 1))" "${src}" > "${out}"  # tail -c +N is 1-indexed
        log_info "Stripped EFI_VARIABLE_AUTHENTICATION_2 header from $(basename "${src}") (ESL at offset ${esl_offset})"
    else
        cp "${src}" "${out}"
        log_info "Using $(basename "${src}") as raw ESL (no auth header detected)"
    fi

    [[ -s "${out}" ]] || die "Extracted ESL is empty from ${src}"
}

# ---------------------------------------------------------------------------
# _find_dbx_binary()
#   Internal helper: locate the pre-built dbx binary on the data partition.
#   Checked in order:
#     1. secureboot_artifacts/Firmware/DBX.bin (raw ESL from Python build script,
#        only present when the full build artefacts are on the data partition)
#     2. PreSignedObjects/DBX/DBX.bin (raw ESL from MS submodule; rarely present)
#     3. sb-enema/payloads/microsoft/dbx.auth (always present — baked into the
#        image by prepare-secureboot-objects.sh as a copy of Firmware/DBX.bin;
#        despite the .auth extension this file is a raw ESL)
#   Known sources are raw EFI Signature Lists; callers should still pass the
#   result through _dbx_esl_from_auth_or_raw() as a defensive measure in case
#   an auth-wrapped variant is ever present in one of these locations.
#   Prints the path on success; returns 1 if no usable file is found.
# ---------------------------------------------------------------------------
_find_dbx_binary() {
    if [[ -f "${DATA_MOUNT}/secureboot_artifacts/Firmware/DBX.bin" ]] && \
       [[ -s "${DATA_MOUNT}/secureboot_artifacts/Firmware/DBX.bin" ]]; then
        echo "${DATA_MOUNT}/secureboot_artifacts/Firmware/DBX.bin"
        return 0
    fi
    if [[ -f "${MSFT_PRESIGNED_DIR}/DBX/DBX.bin" ]] && \
       [[ -s "${MSFT_PRESIGNED_DIR}/DBX/DBX.bin" ]]; then
        echo "${MSFT_PRESIGNED_DIR}/DBX/DBX.bin"
        return 0
    fi
    # Guaranteed fallback: prepare-secureboot-objects.sh always copies
    # Firmware/DBX.bin (raw ESL) to this path at build time.
    # Note: secureboot_artifacts/ is not deployed to the data partition at
    # runtime (post-image.sh only copies sb-enema/ and PreSignedObjects/),
    # so this fallback is the normal runtime source.
    if [[ -f "${MSFT_PAYLOADS_SUBDIR}/dbx.auth" ]] && \
       [[ -s "${MSFT_PAYLOADS_SUBDIR}/dbx.auth" ]]; then
        echo "${MSFT_PAYLOADS_SUBDIR}/dbx.auth"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# _stage_build_dbx_payload <workdir> <kek_key> <kek_crt> <owner_guid>
#   Internal helper: locate the pre-built dbx raw ESL, optionally strip any
#   auth wrapper (see _dbx_esl_from_auth_or_raw()), sign it with the user KEK
#   to produce PAYLOAD_DIR/dbx.auth with a fresh timestamp, and save the raw
#   ESL to PAYLOAD_DIR/dbx/dbx.esl for the preview engine.
#
#   Always sign with user KEK — never use the pre-staged microsoft/dbx.auth
#   directly, because:
#   1. That file is a raw ESL (no auth wrapper), which efi-updatevar refuses.
#   2. Even if a pre-signed MS auth payload were available, its timestamp would
#      be stale; firmware monotonic counters reject replays even in Setup Mode.
#   3. dbx is enrolled before KEK, so MS KEK is not yet installed when written.
# ---------------------------------------------------------------------------
_stage_build_dbx_payload() {
    local workdir="$1"
    local kek_key="$2"
    local kek_crt="$3"
    local owner_guid="$4"

    local dbx_src=""
    dbx_src=$(_find_dbx_binary) || true

    if [[ -z "${dbx_src}" ]] || [[ ! -s "${dbx_src}" ]]; then
        log_warn "No pre-built dbx payload found; skipping dbx staging"
        return 0
    fi

    # Extract raw ESL (strip auth header if source is a pre-signed auth file)
    local raw_esl="${workdir}/dbx-raw.esl"
    _dbx_esl_from_auth_or_raw "${dbx_src}" "${raw_esl}"

    # Save raw ESL to PAYLOAD_DIR/dbx/ for the preview engine hash count
    cp "${raw_esl}" "${PAYLOAD_DIR}/dbx/dbx.esl"

    sign-efi-sig-list -g "${owner_guid}" \
        -k "${kek_key}" -c "${kek_crt}" \
        dbx "${raw_esl}" "${PAYLOAD_DIR}/dbx.auth"
    local sha256
    sha256=$(sha256sum "${PAYLOAD_DIR}/dbx.auth" | awk '{print $1}')
    log_action "STAGE" "dbx.auth" "SUCCESS" "signed by user KEK SHA256=${sha256}"
}

# ---------------------------------------------------------------------------
# stage_user_pk_kek()
#   Stage user-generated PK and KEK certificates and create signed .auth
#   payloads.  Requires keygen_generate_keys() to have been called first.
#   Creates: PAYLOAD_DIR/PK.auth, PAYLOAD_DIR/KEK.auth; PAYLOAD_DIR/dbx.auth
#            is created on a best-effort basis when a dbx source is present.
#   Stages:  PAYLOAD_DIR/PK/PK.crt, PAYLOAD_DIR/KEK/KEK.crt
# ---------------------------------------------------------------------------
stage_user_pk_kek() {
    log_info "Staging user-generated PK and KEK"

    local pk_key="${KEYS_DIR}/PK.key"
    local pk_crt="${KEYS_DIR}/PK.crt"
    local kek_key="${KEYS_DIR}/KEK.key"
    local kek_crt="${KEYS_DIR}/KEK.crt"

    local f
    for f in "${pk_key}" "${pk_crt}" "${kek_key}" "${kek_crt}"; do
        [[ -f "${f}" ]] || die "Required key file missing: ${f}. Run keygen_generate_keys first."
    done

    OWNER_GUID=$(keygen_load_or_generate_guid)

    mkdir -p "${PAYLOAD_DIR}/PK" "${PAYLOAD_DIR}/KEK" "${PAYLOAD_DIR}/dbx"

    cp "${pk_crt}" "${PAYLOAD_DIR}/PK/PK.crt"
    log_info "Staged user PK cert"

    cp "${kek_crt}" "${PAYLOAD_DIR}/KEK/KEK.crt"
    log_info "Staged user KEK cert"

    local workdir
    workdir=$(mktemp -d) || die "Failed to create temp directory"
    # shellcheck disable=SC2064
    trap "rm -rf '${workdir}'" RETURN

    # Stage user DB cert for db preview (if it exists)
    local db_crt="${KEYS_DIR}/DB.crt"
    if [[ -f "${db_crt}" ]]; then
        mkdir -p "${PAYLOAD_DIR}/db"
        cp "${db_crt}" "${PAYLOAD_DIR}/db/DB-user.crt"
        log_info "Staged user DB cert"
    fi

    # PK.auth — self-signed by PK private key
    log_info "Creating PK.auth (self-signed by PK)"
    cert-to-efi-sig-list -g "${OWNER_GUID}" "${pk_crt}" "${workdir}/PK.esl"
    sign-efi-sig-list -g "${OWNER_GUID}" \
        -k "${pk_key}" -c "${pk_crt}" \
        PK "${workdir}/PK.esl" "${PAYLOAD_DIR}/PK.auth"
    local pk_sha256
    pk_sha256=$(sha256sum "${PAYLOAD_DIR}/PK.auth" | awk '{print $1}')
    log_action "STAGE" "PK.auth" "SUCCESS" "self-signed by PK SHA256=${pk_sha256}"

    # KEK.auth — signed by PK, containing user KEK + Microsoft KEK
    log_info "Creating KEK.auth (signed by PK, user KEK + MS KEK)"
    _stage_build_kek_esl "${workdir}" "${kek_crt}" "${OWNER_GUID}"
    sign-efi-sig-list -g "${OWNER_GUID}" \
        -k "${pk_key}" -c "${pk_crt}" \
        KEK "${workdir}/KEK.esl" "${PAYLOAD_DIR}/KEK.auth"
    local kek_sha256
    kek_sha256=$(sha256sum "${PAYLOAD_DIR}/KEK.auth" | awk '{print $1}')
    log_action "STAGE" "KEK.auth" "SUCCESS" "signed by PK SHA256=${kek_sha256}"

    # dbx.auth — signed by user KEK (fresh timestamp; never use pre-signed MS version)
    log_info "Creating dbx.auth (signed by user KEK, fresh timestamp)"
    _stage_build_dbx_payload "${workdir}" "${kek_key}" "${kek_crt}" "${OWNER_GUID}"

    log_success "User PK and KEK staged"
}

# ---------------------------------------------------------------------------
# stage_user_kek_db()
#   Stage user-generated KEK and Microsoft DB certificates and create signed
#   .auth payloads.  Does NOT stage or modify PK.
#   Creates: PAYLOAD_DIR/KEK.auth (signed by PK), PAYLOAD_DIR/db.auth (signed by KEK)
# ---------------------------------------------------------------------------
stage_user_kek_db() {
    log_info "Staging user-generated KEK and DB"

    local pk_key="${KEYS_DIR}/PK.key"
    local pk_crt="${KEYS_DIR}/PK.crt"
    local kek_key="${KEYS_DIR}/KEK.key"
    local kek_crt="${KEYS_DIR}/KEK.crt"

    local f
    for f in "${pk_key}" "${pk_crt}" "${kek_key}" "${kek_crt}"; do
        [[ -f "${f}" ]] || die "Required key file missing: ${f}. Run keygen_generate_keys first."
    done

    OWNER_GUID=$(keygen_load_or_generate_guid)

    mkdir -p "${PAYLOAD_DIR}/KEK" "${PAYLOAD_DIR}/db"

    cp "${kek_crt}" "${PAYLOAD_DIR}/KEK/KEK.crt"
    log_info "Staged user KEK cert"

    # Stage user DB cert + MS DB certs
    local db_crt="${KEYS_DIR}/DB.crt"
    if [[ -f "${db_crt}" ]]; then
        cp "${db_crt}" "${PAYLOAD_DIR}/db/DB-user.crt"
        log_info "Staged user DB cert"
    fi

    local _old_nullglob
    _old_nullglob=$(shopt -p nullglob) || true
    shopt -s nullglob
    local db_certs_dir="${MSFT_PRESIGNED_DIR}/DB/Certificates"
    if [[ -d "${db_certs_dir}" ]]; then
        local cert_file
        for cert_file in "${db_certs_dir}"/*.der "${db_certs_dir}"/*.crt "${db_certs_dir}"/*.cer; do
            [[ -f "${cert_file}" ]] || continue
            cp "${cert_file}" "${PAYLOAD_DIR}/db/"
            log_info "Staged MS DB cert: $(basename "${cert_file}")"
        done
    fi
    eval "${_old_nullglob}"

    local workdir
    workdir=$(mktemp -d) || die "Failed to create temp directory"
    # shellcheck disable=SC2064
    trap "rm -rf '${workdir}'" RETURN

    # KEK.auth — signed by PK
    log_info "Creating KEK.auth (signed by PK)"
    _stage_build_kek_esl "${workdir}" "${kek_crt}" "${OWNER_GUID}"
    sign-efi-sig-list -g "${OWNER_GUID}" \
        -k "${pk_key}" -c "${pk_crt}" \
        KEK "${workdir}/KEK.esl" "${PAYLOAD_DIR}/KEK.auth"
    local kek_sha256
    kek_sha256=$(sha256sum "${PAYLOAD_DIR}/KEK.auth" | awk '{print $1}')
    log_action "STAGE" "KEK.auth" "SUCCESS" "signed by PK SHA256=${kek_sha256}"

    # db.auth — signed by user KEK
    log_info "Creating db.auth (signed by user KEK)"
    _stage_build_db_esl "${workdir}" "${OWNER_GUID}"
    sign-efi-sig-list -g "${OWNER_GUID}" \
        -k "${kek_key}" -c "${kek_crt}" \
        db "${workdir}/db.esl" "${PAYLOAD_DIR}/db.auth"
    local db_sha256
    db_sha256=$(sha256sum "${PAYLOAD_DIR}/db.auth" | awk '{print $1}')
    log_action "STAGE" "db.auth" "SUCCESS" "signed by KEK SHA256=${db_sha256}"

    log_success "User KEK and DB staged"
}

# ---------------------------------------------------------------------------
# stage_sign_db()
#   Build a fresh db.auth from whatever certificates are currently staged in
#   PAYLOAD_DIR/db/, signed by the user KEK with a fresh timestamp.
#   Always overwrites any existing PAYLOAD_DIR/db.auth.
#
#   Call this after all desired db certs have been staged (user + Microsoft)
#   to ensure db.auth carries a current timestamp.  Pre-signed Microsoft
#   db.auth payloads carry old timestamps; firmware monotonic counters reject
#   them even in Setup Mode, causing "Invalid argument" from efi-updatevar.
#   Requires keygen_generate_keys() to have been run first.
# ---------------------------------------------------------------------------
stage_sign_db() {
    log_info "Building fresh db.auth signed by user KEK from staged certs"

    local kek_key="${KEYS_DIR}/KEK.key"
    local kek_crt="${KEYS_DIR}/KEK.crt"

    local f
    for f in "${kek_key}" "${kek_crt}"; do
        [[ -f "${f}" ]] || die "Required key file missing: ${f}. Run keygen_generate_keys first."
    done

    if [[ ! -d "${PAYLOAD_DIR}/db" ]]; then
        log_warn "No db certs staged in ${PAYLOAD_DIR}/db; skipping db.auth creation"
        return 0
    fi

    OWNER_GUID=$(keygen_load_or_generate_guid)

    local workdir
    workdir=$(mktemp -d) || die "Failed to create temp directory"
    # shellcheck disable=SC2064
    trap "rm -rf '${workdir}'" RETURN

    _stage_build_db_esl "${workdir}" "${OWNER_GUID}"
    sign-efi-sig-list -g "${OWNER_GUID}" \
        -k "${kek_key}" -c "${kek_crt}" \
        db "${workdir}/db.esl" "${PAYLOAD_DIR}/db.auth"
    local sha256
    sha256=$(sha256sum "${PAYLOAD_DIR}/db.auth" | awk '{print $1}')
    log_action "STAGE" "db.auth" "SUCCESS" "signed by user KEK SHA256=${sha256}"

    log_success "db.auth built from all staged db certs and signed by user KEK"
}

# ---------------------------------------------------------------------------
# stage_sign_kek()
#   Rebuild KEK.auth from all staged KEK certs — user KEK, Microsoft KEK, and
#   any vendor default KEK certs placed in PAYLOAD_DIR/KEK/ by
#   stage_bios_entries() — signed by the user PK with a fresh timestamp.
#   Always overwrites any existing PAYLOAD_DIR/KEK.auth.
#   Requires keygen_generate_keys() to have been run first.
# ---------------------------------------------------------------------------
stage_sign_kek() {
    log_info "Building fresh KEK.auth signed by user PK from staged certs"

    local pk_key="${KEYS_DIR}/PK.key"
    local pk_crt="${KEYS_DIR}/PK.crt"
    local kek_crt="${KEYS_DIR}/KEK.crt"

    local f
    for f in "${pk_key}" "${pk_crt}" "${kek_crt}"; do
        [[ -f "${f}" ]] || die "Required key file missing: ${f}. Run keygen_generate_keys first."
    done

    # Run in a subshell so that the EXIT trap for tempdir cleanup does not
    # clobber any RETURN trap set by a calling function.
    (
        OWNER_GUID=$(keygen_load_or_generate_guid)

        local workdir
        workdir=$(mktemp -d) || die "Failed to create temp directory"
        trap 'rm -rf "${workdir}"' EXIT

        _stage_build_kek_esl "${workdir}" "${kek_crt}" "${OWNER_GUID}"
        sign-efi-sig-list -g "${OWNER_GUID}" \
            -k "${pk_key}" -c "${pk_crt}" \
            KEK "${workdir}/KEK.esl" "${PAYLOAD_DIR}/KEK.auth"
        local sha256
        sha256=$(sha256sum "${PAYLOAD_DIR}/KEK.auth" | awk '{print $1}')
        log_action "STAGE" "KEK.auth" "SUCCESS" "signed by user PK SHA256=${sha256}"

        log_success "KEK.auth built from all staged KEK certs and signed by user PK"
    )
}

# ---------------------------------------------------------------------------
# _is_in_kek_update_map <sha1_fingerprint>
#   Return 0 if <sha1_fingerprint> (lowercase hex, no colons) appears as a
#   top-level key in KEK_UPDATE_MAP (kek_update_map.json).
#   The JSON maps SHA-1 PK certificate fingerprints to vendor KEK update bins.
#   Returns 1 if the file is absent or the fingerprint is not found.
#   File-existence is cached in _KEK_UPDATE_MAP_STATUS so that a single warning
#   is emitted even when called repeatedly from stage_bios_entries().
# ---------------------------------------------------------------------------
_is_in_kek_update_map() {
    local sha1="$1"
    # _KEK_UPDATE_MAP_STATUS is a module-level cache variable (set on first call,
    # persists for the lifetime of the sourced script).  Values: "present" or
    # "missing"; empty/unset means not yet checked.  This avoids repeating the
    # file-existence test and emitting a warning for every certificate when
    # stage_bios_entries() iterates over multiple certs.
    if [[ -z "${_KEK_UPDATE_MAP_STATUS:-}" ]]; then
        if [[ -f "${KEK_UPDATE_MAP}" ]]; then
            _KEK_UPDATE_MAP_STATUS="present"
        else
            log_warn "kek_update_map.json not found at ${KEK_UPDATE_MAP}; vendor cert check skipped"
            _KEK_UPDATE_MAP_STATUS="missing"
        fi
    fi
    if [[ "${_KEK_UPDATE_MAP_STATUS}" != "present" ]]; then
        return 1
    fi
    jq -e --arg key "${sha1}" 'has($key)' "${KEK_UPDATE_MAP}" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# stage_bios_entries()
#   Stage vendor default firmware entries from KEKDefault and dbDefault —
#   the read-only NVRAM variables that hold the OEM-factory Secure Boot
#   certificates before any user modification.
#
#   The user may have wiped KEK/db prior to running this tool; KEKDefault and
#   dbDefault are preserved by the firmware and represent the vendor-installed
#   baseline that should be re-instated.
#
#   Inclusion criteria (both must pass):
#   1. The cert's SHA-1 fingerprint appears as a key in kek_update_map.json
#      (the Microsoft OEM vendor PK → KEK update map from the
#      secureboot_objects submodule).  Certs not in this map are skipped.
#   2. The cert's SHA-256 fingerprint does NOT appear in known-test-pks.txt.
#      Test/placeholder certificates are never staged.
#
#   Microsoft-signed KEK/db certs are also excluded (they are handled by
#   stage_microsoft_kek_db_dbx).
#
#   Applies to KEKDefault → staged under PAYLOAD_DIR/KEK/
#             dbDefault   → staged under PAYLOAD_DIR/db/
# ---------------------------------------------------------------------------
stage_bios_entries() {
    log_info "Staging vendor default entries from KEKDefault and dbDefault"

    local tmpdir
    tmpdir=$(mktemp -d) || { log_error "Failed to create temp directory"; return 1; }
    # shellcheck disable=SC2064
    trap "rm -rf '${tmpdir}'" RETURN

    local varname stagedir
    for varname in KEKDefault dbDefault; do
        case "${varname}" in
            KEKDefault) stagedir="${PAYLOAD_DIR}/KEK" ;;
            dbDefault)  stagedir="${PAYLOAD_DIR}/db"  ;;
        esac

        local extractdir="${tmpdir}/${varname}"
        mkdir -p "${extractdir}"

        if ! efivar_extract_certs "${varname}" "${extractdir}" 2>/dev/null; then
            log_info "Could not extract ${varname} certs from firmware; skipping"
            continue
        fi

        local idx=0
        local staged_count=0
        while [[ -f "${extractdir}/${varname}-${idx}.der" ]]; do
            local der="${extractdir}/${varname}-${idx}.der"

            # Compute SHA-1 fingerprint — used to look up certs in kek_update_map.json
            local sha1_hex
            sha1_hex=$(openssl x509 -in "${der}" -inform DER -noout -fingerprint -sha1 2>/dev/null \
                       | sed 's/.*Fingerprint=//;s/://g' | tr '[:upper:]' '[:lower:]') || {
                log_warn "Could not compute SHA-1 for ${varname}-${idx}.der; skipping"
                idx=$((idx + 1))
                continue
            }

            # Compute SHA-256 fingerprint — used for test-cert and Microsoft-cert checks
            local sha256_hex
            sha256_hex=$(openssl x509 -in "${der}" -inform DER -noout -fingerprint -sha256 2>/dev/null \
                         | sed 's/.*Fingerprint=//;s/://g' | tr '[:upper:]' '[:lower:]') || {
                log_warn "Could not compute SHA-256 for ${varname}-${idx}.der; skipping"
                idx=$((idx + 1))
                continue
            }

            # Skip certs not present in the vendor kek_update_map.json
            if ! _is_in_kek_update_map "${sha1_hex}"; then
                log_info "${varname} cert ${idx} not in kek_update_map.json (SHA1=${sha1_hex}); skipping"
                idx=$((idx + 1))
                continue
            fi

            # Skip known test/placeholder certificates
            if certdb_is_test_pk "${sha256_hex}"; then
                log_info "Skipping test certificate in ${varname} (SHA256=${sha256_hex})"
                idx=$((idx + 1))
                continue
            fi

            # Skip Microsoft-owned certs (handled by stage_microsoft_kek_db_dbx)
            if certdb_is_microsoft_kek "${sha256_hex}" || certdb_is_microsoft_db "${sha256_hex}"; then
                log_info "Skipping known Microsoft cert in ${varname} (SHA256=${sha256_hex})"
                idx=$((idx + 1))
                continue
            fi

            # Stage the vendor cert
            mkdir -p "${stagedir}"
            local dest="${stagedir}/default-${varname}-${idx}.der"
            cp "${der}" "${dest}"
            log_info "Staged ${varname} cert ${idx}: SHA1=${sha1_hex}"
            staged_count=$((staged_count + 1))
            idx=$((idx + 1))
        done

        log_info "Staged ${staged_count} recognized vendor ${varname} entries"
    done

    log_success "Vendor default entries staging complete"

    # Rebuild auth payloads to include the newly staged vendor certs.  Only
    # possible if user keys and certs have already been generated.
    local pk_key="${KEYS_DIR}/PK.key"
    local kek_key="${KEYS_DIR}/KEK.key"
    local pk_crt="${KEYS_DIR}/PK.crt"
    local kek_crt="${KEYS_DIR}/KEK.crt"
    if [[ -f "${pk_key}" && -f "${kek_key}" && -f "${pk_crt}" && -f "${kek_crt}" ]]; then
        log_info "Rebuilding KEK.auth and db.auth to include staged vendor certs"
        stage_sign_kek
        stage_sign_db
    else
        log_info "User keys/certs not yet generated; skipping auth payload rebuild (run keygen first, then re-stage)"
    fi
}
