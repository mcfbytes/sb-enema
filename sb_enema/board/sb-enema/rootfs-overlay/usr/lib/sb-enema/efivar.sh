#!/usr/bin/env bash
# efivar.sh — EFI variable reading and certificate extraction for SB-ENEMA.
# Requires common.sh and log.sh to be sourced first (provides EFIVARS_DIR,
# color codes, and the log_* helpers).
# shellcheck disable=SC2034  # Constants are used by scripts that source this file.
set -euo pipefail
[[ -n "${_SB_ENEMA_EFIVAR_SH:-}" ]] && return 0
readonly _SB_ENEMA_EFIVAR_SH=1

# ---------------------------------------------------------------------------
# Standard EFI GUIDs
# ---------------------------------------------------------------------------
readonly EFI_GLOBAL_GUID="8be4df61-93ca-11d2-aa0d-00e098032b8c"
readonly EFI_IMAGE_SECURITY_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"

# Map variable names to their GUIDs
_efivar_guid_for() {
    local varname="$1"
    case "${varname}" in
        PK|KEK|SecureBoot|SetupMode)
            echo "${EFI_GLOBAL_GUID}"
            ;;
        db|dbx)
            echo "${EFI_IMAGE_SECURITY_GUID}"
            ;;
        *)
            log_error "Unknown EFI variable: ${varname}"
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# efivar_read_raw <varname>
#   Read a raw EFI variable (PK, KEK, db, dbx) from sysfs, stripping the
#   4-byte Linux attributes prefix.  Raw bytes are written to stdout.
#   Returns 1 if the variable does not exist or cannot be read.
# ---------------------------------------------------------------------------
efivar_read_raw() {
    local varname="$1"
    local guid
    guid=$(_efivar_guid_for "${varname}") || return 1

    local path="${EFIVARS_DIR}/${varname}-${guid}"

    if [[ ! -f "${path}" ]]; then
        log_warn "EFI variable not found: ${path}"
        return 1
    fi

    if [[ ! -r "${path}" ]]; then
        log_error "Permission denied reading EFI variable: ${path}"
        return 1
    fi

    # Skip the 4-byte attribute header that Linux prepends to efivarfs entries.
    tail -c +5 "${path}"
}

# ---------------------------------------------------------------------------
# efivar_is_empty <varname>
#   Return 0 if the variable does not exist or is empty, 1 otherwise.
# ---------------------------------------------------------------------------
efivar_is_empty() {
    local varname="$1"
    local guid
    guid=$(_efivar_guid_for "${varname}") || return 0

    local path="${EFIVARS_DIR}/${varname}-${guid}"

    if [[ ! -f "${path}" ]]; then
        return 0
    fi

    if [[ ! -r "${path}" ]]; then
        log_error "Permission denied probing EFI variable for emptiness: ${path}"
        return 1
    fi

    # efivarfs files may report size 0 via stat on some kernel/firmware
    # combinations even when content is present.  Read one byte past the
    # 4-byte attribute header to reliably detect an actual payload.
    local payload_byte_count
    payload_byte_count=$(tail -c +5 "${path}" | head -c 1 | wc -c) || {
        log_error "Failed to probe EFI variable payload for emptiness: ${path}"
        return 1
    }
    if [[ "${payload_byte_count}" -le 0 ]]; then
        return 0
    fi

    return 1
}

# ---------------------------------------------------------------------------
# Cert extraction cache.  When active (non-empty _EFIVAR_CERT_CACHE_DIR),
# efivar_extract_certs() stores extracted certs on first call and serves
# them from disk on subsequent calls within the same cycle, avoiding
# redundant reads from efivarfs.
# Activate with efivar_cert_cache_init(); release with efivar_cert_cache_clear().
# ---------------------------------------------------------------------------
_EFIVAR_CERT_CACHE_DIR=""

# _efivar_copy_cert_files <src_dir> <dst_dir>
#   Copy all .der and .txt cert files from <src_dir> to <dst_dir> using
#   nullglob so missing files are silently skipped.
_efivar_copy_cert_files() {
    local src="$1" dst="$2"
    local _old_nullglob
    _old_nullglob=$(shopt -p nullglob) || true
    shopt -s nullglob
    local _cf
    for _cf in "${src}/"*.der "${src}/"*.txt; do
        cp "${_cf}" "${dst}/"
    done
    eval "${_old_nullglob}"
}

# efivar_cert_cache_init()
#   Start a fresh cert extraction cache.
efivar_cert_cache_init() {
    efivar_cert_cache_clear
    _EFIVAR_CERT_CACHE_DIR=$(mktemp -d) || {
        log_warn "Failed to create cert cache directory; caching disabled"
        _EFIVAR_CERT_CACHE_DIR=""
        return 0
    }
}

# efivar_cert_cache_clear()
#   Release the cert extraction cache.
efivar_cert_cache_clear() {
    if [[ -n "${_EFIVAR_CERT_CACHE_DIR}" ]]; then
        rm -rf "${_EFIVAR_CERT_CACHE_DIR}"
        _EFIVAR_CERT_CACHE_DIR=""
    fi
}

# ---------------------------------------------------------------------------
# _efivar_read_u32_le <file> <offset>
#   Read a 4-byte little-endian uint32 from <file> at byte <offset>.
#   Prints the decimal value to stdout.  Returns 1 on failure.
# ---------------------------------------------------------------------------
_efivar_read_u32_le() {
    local file="$1"
    local offset="$2"
    local hex
    hex=$(dd if="${file}" bs=1 skip="${offset}" count=4 2>/dev/null \
        | od -An -tx1 | tr -d ' \n')
    if [[ ${#hex} -ne 8 ]]; then
        echo "0"
        return 1
    fi
    # Reverse byte order (LE → BE) and interpret as a hex integer.
    echo $(( (16#${hex:6:2} << 24) | (16#${hex:4:2} << 16) | (16#${hex:2:2} << 8) | 16#${hex:0:2} ))
}

# ---------------------------------------------------------------------------
# efivar_extract_certs <varname> <output_dir>
#   Extract X509 DER certificates from a Secure Boot EFI variable by parsing
#   the raw EFI_SIGNATURE_LIST binary directly from efivarfs.
#   For each X509 certificate found, store:
#     <output_dir>/<varname>-N.der  — raw DER certificate
#     <output_dir>/<varname>-N.txt  — human-readable summary
#   Returns 0 on success (certificates extracted if present), or 1 on error.
# ---------------------------------------------------------------------------
efivar_extract_certs() {
    local varname="$1"
    local output_dir="$2"

    # --- Serve from cache if this variable was already extracted this cycle ---
    # A sentinel file .extracted marks a completed cache entry (even if empty).
    if [[ -n "${_EFIVAR_CERT_CACHE_DIR}" ]] && \
            [[ -f "${_EFIVAR_CERT_CACHE_DIR}/${varname}/.extracted" ]]; then
        mkdir -p "${output_dir}"
        _efivar_copy_cert_files "${_EFIVAR_CERT_CACHE_DIR}/${varname}" "${output_dir}"
        return 0
    fi

    if efivar_is_empty "${varname}"; then
        log_info "EFI variable ${varname} is empty; skipping certificate extraction"
        mkdir -p "${output_dir}"
        # Cache the empty result (sentinel only, no cert files)
        if [[ -n "${_EFIVAR_CERT_CACHE_DIR}" ]]; then
            mkdir -p "${_EFIVAR_CERT_CACHE_DIR}/${varname}"
            touch "${_EFIVAR_CERT_CACHE_DIR}/${varname}/.extracted"
        fi
        return 0
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        log_error "openssl not found; required for certificate extraction"
        return 1
    fi

    mkdir -p "${output_dir}"

    # Run the extraction in a subshell so the EXIT trap for temp dir cleanup
    # is confined to this scope and does not affect callers.
    (
        local tmpdir
        tmpdir=$(mktemp -d) || { log_error "Failed to create temp directory"; return 1; }
        # shellcheck disable=SC2064
        trap "rm -rf '${tmpdir}'" EXIT

        # Read the raw EFI_SIGNATURE_LIST payload from efivarfs.
        local esl_file="${tmpdir}/esl.bin"
        log_info "Reading raw EFI variable ${varname} from efivarfs"
        if ! efivar_read_raw "${varname}" > "${esl_file}" 2>/dev/null; then
            log_error "Failed to read EFI variable ${varname} from efivarfs"
            return 1
        fi

        local file_size
        file_size=$(wc -c < "${esl_file}")
        log_info "EFI variable ${varname}: ${file_size} bytes raw"

        # EFI_CERT_X509_GUID in mixed-endian memory layout:
        # {0xa5c059a1, 0x94e4, 0x4aa7, {0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72}}
        # Bytes: a1 59 c0 a5  e4 94  a7 4a  87 b5 ab 15 5c 2b f0 72
        local X509_GUID_HEX="a159c0a5e494a74a87b5ab155c2bf072"

        local offset=0
        local cert_index=0

        # Walk each EFI_SIGNATURE_LIST entry.
        # EFI_SIGNATURE_LIST layout (all uint32 fields are little-endian):
        #   offset  0: SignatureType GUID (16 bytes)
        #   offset 16: SignatureListSize  (uint32)
        #   offset 20: SignatureHeaderSize (uint32)
        #   offset 24: SignatureSize       (uint32)
        #   offset 28: SignatureHeader     (SignatureHeaderSize bytes, usually 0)
        #   offset 28+SHS: N * SignatureSize bytes of EFI_SIGNATURE_DATA entries
        # Each EFI_SIGNATURE_DATA entry:
        #   offset  0: SignatureOwner GUID (16 bytes)
        #   offset 16: SignatureData       (SignatureSize - 16 bytes; DER cert for X509)
        while [[ $((offset + 28)) -le ${file_size} ]]; do
            # Read the SignatureType GUID (16 bytes) as a hex string.
            local guid_hex
            guid_hex=$(dd if="${esl_file}" bs=1 skip="${offset}" count=16 2>/dev/null \
                | od -An -tx1 | tr -d ' \n')

            local list_size hdr_size sig_size
            list_size=$(_efivar_read_u32_le "${esl_file}" $((offset + 16))) || break
            hdr_size=$(_efivar_read_u32_le  "${esl_file}" $((offset + 20))) || break
            sig_size=$(_efivar_read_u32_le  "${esl_file}" $((offset + 24))) || break

            log_info "ESL entry at offset ${offset}: type=${guid_hex} list_size=${list_size} sig_size=${sig_size}"

            if [[ "${list_size}" -eq 0 ]]; then
                log_warn "Zero-length EFI_SIGNATURE_LIST at offset ${offset}; stopping parse"
                break
            fi

            # Validate that list_size covers at least the 28-byte fixed header
            # and that the entry fits within the file, to handle corrupt payloads.
            if [[ "${list_size}" -lt 28 ]]; then
                log_warn "EFI_SIGNATURE_LIST at offset ${offset} has list_size=${list_size} < 28; stopping parse"
                break
            fi
            if [[ $((offset + list_size)) -gt ${file_size} ]]; then
                log_warn "EFI_SIGNATURE_LIST at offset ${offset} extends beyond file (offset+size=$((offset + list_size)) > ${file_size}); stopping parse"
                break
            fi

            if [[ "${guid_hex}" == "${X509_GUID_HEX}" ]] && [[ "${sig_size}" -gt 16 ]]; then
                # Signature data section starts after fixed 28-byte header + optional header.
                local data_start=$((offset + 28 + hdr_size))
                local data_len=$((list_size - 28 - hdr_size))

                if [[ "${data_len}" -gt 0 ]] && [[ "${sig_size}" -gt 0 ]]; then
                    local num_entries=$(( data_len / sig_size ))
                    local i=0
                    while [[ $i -lt $num_entries ]]; do
                        # DER cert starts after the 16-byte SignatureOwner GUID.
                        local der_offset=$(( data_start + i * sig_size + 16 ))
                        local der_size=$(( sig_size - 16 ))
                        local der_file="${output_dir}/${varname}-${cert_index}.der"

                        log_info "Extracting X509 cert ${cert_index} from ${varname}: offset=${der_offset}, size=${der_size} bytes"
                        if dd if="${esl_file}" bs=1 skip="${der_offset}" count="${der_size}" \
                                of="${der_file}" 2>/dev/null \
                                && openssl x509 -in "${der_file}" -inform DER -noout 2>/dev/null; then
                            _efivar_cert_summary "${der_file}" \
                                > "${output_dir}/${varname}-${cert_index}.txt" 2>/dev/null || true
                            cert_index=$(( cert_index + 1 ))
                        else
                            log_warn "Could not validate extracted certificate ${cert_index} from ${varname}"
                            rm -f "${der_file}"
                        fi
                        i=$(( i + 1 ))
                    done
                fi
            fi

            offset=$(( offset + list_size ))
        done

        if [[ "${cert_index}" -eq 0 ]]; then
            log_info "No X509 certificates extracted from ${varname}"
        else
            log_info "Extracted ${cert_index} certificate(s) from ${varname}"
        fi

        return 0
    )
    local status=$?

    # --- Populate cache after successful extraction ---
    if [[ "${status}" -eq 0 ]] && [[ -n "${_EFIVAR_CERT_CACHE_DIR}" ]]; then
        mkdir -p "${_EFIVAR_CERT_CACHE_DIR}/${varname}"
        _efivar_copy_cert_files "${output_dir}" "${_EFIVAR_CERT_CACHE_DIR}/${varname}"
        touch "${_EFIVAR_CERT_CACHE_DIR}/${varname}/.extracted"
    fi

    return "${status}"
}

# ---------------------------------------------------------------------------
# _efivar_cert_summary <der_file>
#   Print a human-readable summary of a DER-encoded certificate to stdout.
# ---------------------------------------------------------------------------
_efivar_cert_summary() {
    local der_file="$1"

    local subject issuer serial not_before not_after fingerprint

    subject=$(openssl x509 -in "${der_file}" -inform DER -noout -subject 2>/dev/null \
        | sed 's/^subject= *//') || subject="(unknown)"
    issuer=$(openssl x509 -in "${der_file}" -inform DER -noout -issuer 2>/dev/null \
        | sed 's/^issuer= *//') || issuer="(unknown)"
    serial=$(openssl x509 -in "${der_file}" -inform DER -noout -serial 2>/dev/null \
        | sed 's/^serial=//') || serial="(unknown)"
    not_before=$(openssl x509 -in "${der_file}" -inform DER -noout -startdate 2>/dev/null \
        | sed 's/^notBefore=//') || not_before="(unknown)"
    not_after=$(openssl x509 -in "${der_file}" -inform DER -noout -enddate 2>/dev/null \
        | sed 's/^notAfter=//') || not_after="(unknown)"
    fingerprint=$(openssl x509 -in "${der_file}" -inform DER -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*Fingerprint=//') || fingerprint="(unknown)"

    echo "Subject:     ${subject}"
    echo "Issuer:      ${issuer}"
    echo "Serial:      ${serial}"
    echo "Not Before:  ${not_before}"
    echo "Not After:   ${not_after}"
    echo "SHA-256:     ${fingerprint}"
}

# ---------------------------------------------------------------------------
# efivar_list_certs <varname>
#   Print a human-readable one-line summary of each certificate in the
#   given Secure Boot variable.
#   Format: [N] CN=... | Issuer=... | Expires=... | SHA256=...
# ---------------------------------------------------------------------------
efivar_list_certs() {
    (
        local varname="$1"

        if ! command -v efi-readvar >/dev/null 2>&1; then
            log_error "efi-readvar not found; install efitools"
            return 1
        fi

        # Extract certs to a temporary directory
        local tmpdir
        tmpdir=$(mktemp -d) || { log_error "Failed to create temp directory"; return 1; }
        # shellcheck disable=SC2064
        trap 'rm -rf "${tmpdir}"' EXIT

        if ! efivar_extract_certs "${varname}" "${tmpdir}"; then
            return 1
        fi

        local index=0
        while [[ -f "${tmpdir}/${varname}-${index}.der" ]]; do
            local der_file="${tmpdir}/${varname}-${index}.der"

            local subject issuer not_after fingerprint
            subject=$(openssl x509 -in "${der_file}" -inform DER -noout -subject 2>/dev/null \
                | sed 's/^subject= *//') || subject="(unknown)"
            issuer=$(openssl x509 -in "${der_file}" -inform DER -noout -issuer 2>/dev/null \
                | sed 's/^issuer= *//') || issuer="(unknown)"
            not_after=$(openssl x509 -in "${der_file}" -inform DER -noout -enddate 2>/dev/null \
                | sed 's/^notAfter=//') || not_after="(unknown)"
            fingerprint=$(openssl x509 -in "${der_file}" -inform DER -noout -fingerprint -sha256 2>/dev/null \
                | sed 's/^.*Fingerprint=//') || fingerprint="(unknown)"

            echo "[${index}] ${subject} | Issuer=${issuer} | Expires=${not_after} | SHA256=${fingerprint}"
            index=$((index + 1))
        done

        if [[ "${index}" -eq 0 ]]; then
            log_info "No certificates found in ${varname}"
        fi
    )
}

# ---------------------------------------------------------------------------
# efivar_get_setup_mode()
#   Return "1" if in Setup Mode, "0" if in User Mode.
#   Falls back to "0" if the variable cannot be read.
# ---------------------------------------------------------------------------
efivar_get_setup_mode() {
    # SetupMode is a single-byte value after the 4-byte efivarfs attribute
    # prefix.  Bit 0 set (0x01) means Setup Mode; mask with 0x01 to ignore
    # reserved bits.  Uses efivar_read_raw() to strip the attribute header
    # (centralises the BusyBox-safe tail -c +5 workaround).
    local raw
    raw=$(efivar_read_raw SetupMode 2>/dev/null | head -c 1 | od -An -tx1 | tr -d ' \n') || {
        log_warn "Failed to read SetupMode; assuming User Mode"
        echo "0"
        return
    }

    if [[ ! "${raw}" =~ ^[0-9a-fA-F]+$ ]]; then
        log_warn "SetupMode value unparseable ('${raw}'); assuming User Mode"
        echo "0"
        return
    fi

    if (( 16#${raw} & 1 )); then
        echo "1"
    else
        echo "0"
    fi
}

# ---------------------------------------------------------------------------
# efivar_get_secure_boot_state()
#   Return "1" if Secure Boot is enabled, "0" if disabled.
#   Falls back to "0" if the variable cannot be read.
# ---------------------------------------------------------------------------
efivar_get_secure_boot_state() {
    # SecureBoot is a single-byte value after the 4-byte efivarfs attribute
    # prefix.  Bit 0 set (0x01) means Secure Boot is enabled; mask with 0x01
    # to ignore reserved bits.  Uses efivar_read_raw() to strip the attribute
    # header (centralises the BusyBox-safe tail -c +5 workaround).
    local raw
    raw=$(efivar_read_raw SecureBoot 2>/dev/null | head -c 1 | od -An -tx1 | tr -d ' \n') || {
        log_warn "Failed to read SecureBoot; assuming disabled"
        echo "0"
        return
    }

    if [[ ! "${raw}" =~ ^[0-9a-fA-F]+$ ]]; then
        log_warn "SecureBoot value unparseable ('${raw}'); assuming disabled"
        echo "0"
        return
    fi

    if (( 16#${raw} & 1 )); then
        echo "1"
    else
        echo "0"
    fi
}
