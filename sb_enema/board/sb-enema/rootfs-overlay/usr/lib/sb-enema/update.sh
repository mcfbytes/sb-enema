#!/usr/bin/env bash
# update.sh — Compute delta between current Secure Boot state and proposed
# target state for SB-ENEMA.
# Requires bash 4.3+ (for nameref variables).
# Requires common.sh, log.sh, efivar.sh, and certdb.sh to be sourced first.
# shellcheck disable=SC2034  # Result arrays are used by scripts that source this file.
set -euo pipefail

# ---------------------------------------------------------------------------
# Payload staging directory on the data partition
# ---------------------------------------------------------------------------
PAYLOAD_DIR="${DATA_MOUNT}/sb-enema/payloads"

# ---------------------------------------------------------------------------
# Result arrays — populated by update_compute().
# Each entry is a JSON object: {"subject":"...","fingerprint":"..."}
# ---------------------------------------------------------------------------
ADD_PK=()    REMOVE_PK=()    KEEP_PK=()
ADD_KEK=()   REMOVE_KEK=()   KEEP_KEK=()
ADD_db=()    REMOVE_db=()    KEEP_db=()
ADD_dbx=()   REMOVE_dbx=()   KEEP_dbx=()

# ---------------------------------------------------------------------------
# _update_cert_fingerprint <der_or_crt_file>
#   Print the SHA-256 fingerprint of a DER- or PEM-encoded certificate.
#   Output format: colon-separated hex (e.g., AB:CD:EF:...).
# ---------------------------------------------------------------------------
_update_cert_fingerprint() {
    local cert_file="$1"
    local fp

    fp=$(openssl x509 -in "${cert_file}" -inform DER -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/.*Fingerprint=//') \
    || fp=$(openssl x509 -in "${cert_file}" -inform PEM -noout -fingerprint -sha256 2>/dev/null \
            | sed 's/.*Fingerprint=//') \
    || { log_warn "Cannot read certificate: ${cert_file}"; return 1; }

    echo "${fp}"
}

# ---------------------------------------------------------------------------
# _update_cert_subject <der_or_crt_file>
#   Print the subject of a DER- or PEM-encoded certificate.
# ---------------------------------------------------------------------------
_update_cert_subject() {
    local cert_file="$1"
    local subj

    subj=$(openssl x509 -in "${cert_file}" -inform DER -noout -subject 2>/dev/null \
           | sed 's/^subject= *//') \
    || subj=$(openssl x509 -in "${cert_file}" -inform PEM -noout -subject 2>/dev/null \
              | sed 's/^subject= *//') \
    || subj="(unknown)"

    echo "${subj}"
}

# ---------------------------------------------------------------------------
# _update_make_entry <subject> <fingerprint>
#   Produce a JSON object string for a certificate entry.
# ---------------------------------------------------------------------------
_update_make_entry() {
    local subj="$1"
    local fp="$2"
    jq -n --arg s "${subj}" --arg f "${fp}" '{subject: $s, fingerprint: $f}'
}

# ---------------------------------------------------------------------------
# _update_hex_to_fp <lowercase_hex_string>
#   Convert a raw lowercase hex digest (e.g. from sha256sum) to a
#   colon-separated uppercase fingerprint (AB:CD:EF:...).
# ---------------------------------------------------------------------------
_update_hex_to_fp() {
    printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | sed 's/../&:/g;s/:$//'
}

# ---------------------------------------------------------------------------
# _update_collect_current <varname> <tmpdir>
#   Extract certificates from the live EFI variable and store per-fingerprint
#   JSON files under <tmpdir>/cur/<fp_hex>.json.
# ---------------------------------------------------------------------------
_update_collect_current() {
    local varname="$1"
    local workdir="$2"
    local certdir="${workdir}/current-certs"

    mkdir -p "${certdir}" "${workdir}/cur"

    if ! efivar_extract_certs "${varname}" "${certdir}" 2>/dev/null; then
        return 0
    fi

    local idx=0
    while [[ -f "${certdir}/${varname}-${idx}.der" ]]; do
        local der="${certdir}/${varname}-${idx}.der"
        local fp subj fp_hex
        fp=$(_update_cert_fingerprint "${der}") || { idx=$((idx + 1)); continue; }
        subj=$(_update_cert_subject "${der}") || subj="(unknown)"
        # Normalize fingerprint to lowercase hex without colons for use as key
        fp_hex=$(printf '%s' "${fp}" | tr -d ':' | tr '[:upper:]' '[:lower:]')
        _update_make_entry "${subj}" "${fp}" > "${workdir}/cur/${fp_hex}.json"
        idx=$((idx + 1))
    done
}

# ---------------------------------------------------------------------------
# _update_count_esl_hashes <esl_file>
#   Parse an EFI Signature List file and print the total number of signature
#   entries across all EFI_SIGNATURE_LIST records.  Used to show a meaningful
#   hash count for dbx rather than listing every individual revocation hash.
# ---------------------------------------------------------------------------
_update_count_esl_hashes() {
    local esl_file="$1"
    local total=0 offset=0 file_size
    file_size=$(stat -c '%s' "${esl_file}" 2>/dev/null) || return 1

    while [[ $((offset + 28)) -le file_size ]]; do
        # Read SignatureListSize (offset+16), SignatureHeaderSize (offset+20),
        # and SignatureSize (offset+24) — three consecutive uint32 LE fields
        local raw
        raw=$(dd if="${esl_file}" bs=1 skip=$((offset + 16)) count=12 2>/dev/null \
              | od -An -tx1 | tr -d ' \n')
        [[ ${#raw} -lt 24 ]] && return 1

        local list_size hdr_size sig_size
        list_size=$(( 16#${raw:6:2}  * 16777216 + 16#${raw:4:2}  * 65536 + \
                      16#${raw:2:2}  * 256       + 16#${raw:0:2} ))
        hdr_size=$(( 16#${raw:14:2} * 16777216 + 16#${raw:12:2} * 65536 + \
                     16#${raw:10:2} * 256       + 16#${raw:8:2} ))
        sig_size=$(( 16#${raw:22:2} * 16777216 + 16#${raw:20:2} * 65536 + \
                     16#${raw:18:2} * 256       + 16#${raw:16:2} ))
        [[ list_size -le 28 || sig_size -eq 0 ]] && return 1

        total=$(( total + (list_size - 28 - hdr_size) / sig_size ))
        offset=$(( offset + list_size ))
    done
    echo "${total}"
}

# ---------------------------------------------------------------------------
# _update_collect_target <varname> <tmpdir>
#   Read certificate files from the payload staging directory and store
#   per-fingerprint JSON files under <tmpdir>/tgt/<fp_hex>.json.
# ---------------------------------------------------------------------------
_update_collect_target() {
    local varname="$1"
    local workdir="$2"

    local payload_subdir="${PAYLOAD_DIR}/${varname}"
    if [[ ! -d "${payload_subdir}" ]]; then
        log_info "No target payloads for ${varname} in ${payload_subdir}"
        return 0
    fi

    mkdir -p "${workdir}/tgt"

    local cert_file
    for cert_file in "${payload_subdir}"/*.der \
                     "${payload_subdir}"/*.crt \
                     "${payload_subdir}"/*.pem \
                     "${payload_subdir}"/*.cer; do
        [[ -f "${cert_file}" ]] || continue
        local fp subj fp_hex
        fp=$(_update_cert_fingerprint "${cert_file}") || continue
        subj=$(_update_cert_subject "${cert_file}") || subj="(unknown)"
        fp_hex=$(printf '%s' "${fp}" | tr -d ':' | tr '[:upper:]' '[:lower:]')
        if [[ -f "${workdir}/tgt/${fp_hex}.json" ]]; then
            log_warn "Duplicate certificate fingerprint for ${varname}: ${fp} (file: ${cert_file})"
            continue
        fi
        _update_make_entry "${subj}" "${fp}" > "${workdir}/tgt/${fp_hex}.json"
    done

    # Handle binary ESL hash bundles (e.g. dbx which contains SHA-256 hashes
    # rather than X.509 certificates).  Create a synthetic preview entry so
    # the delta display shows the hash bundle will be applied.
    local bin_file
    for bin_file in "${payload_subdir}"/*.bin \
                    "${payload_subdir}"/*.esl; do
        [[ -f "${bin_file}" ]] || continue
        local bin_size bin_sha256 bin_fp bin_fp_hex bin_subj
        bin_size=$(stat -c '%s' "${bin_file}" 2>/dev/null) || bin_size="?"
        bin_sha256=$(sha256sum "${bin_file}" 2>/dev/null | awk '{print $1}') || {
            log_warn "Cannot checksum hash bundle: ${bin_file}"
            continue
        }
        bin_fp=$(_update_hex_to_fp "${bin_sha256}")
        bin_fp_hex=$(printf '%s' "${bin_sha256}" | tr '[:upper:]' '[:lower:]')
        # For .esl files (raw EFI Signature Lists) count individual hash entries
        # rather than treating the whole file as a single opaque blob.
        case "${bin_file}" in
            *.esl)
                local entry_count
                if ! entry_count=$(_update_count_esl_hashes "${bin_file}"); then
                    log_warn "Could not count ESL entries in ${bin_file}; ESL may be malformed"
                    entry_count="?"
                fi
                bin_subj="${entry_count} SHA-256 revocation hashes"
                ;;
            *)
                bin_subj="Hash bundle: $(basename "${bin_file}") (${bin_size} bytes)"
                ;;
        esac
        if [[ -f "${workdir}/tgt/${bin_fp_hex}.json" ]]; then
            log_warn "Duplicate hash bundle fingerprint for ${varname}: ${bin_fp}"
            continue
        fi
        _update_make_entry "${bin_subj}" "${bin_fp}" > "${workdir}/tgt/${bin_fp_hex}.json"
    done
}

# ---------------------------------------------------------------------------
# _update_compute_var <varname>
#   Compute the delta for a single variable and populate ADD_<var>,
#   REMOVE_<var>, and KEEP_<var> arrays.
# ---------------------------------------------------------------------------
_update_compute_var() {
    local varname="$1"
    local workdir
    workdir=$(mktemp -d) || { log_error "Failed to create temp directory"; return 1; }
    # shellcheck disable=SC2064
    trap "rm -rf '${workdir}'" RETURN

    _update_collect_current "${varname}" "${workdir}"
    _update_collect_target  "${varname}" "${workdir}"

    local -n _add="ADD_${varname}"
    local -n _remove="REMOVE_${varname}"
    local -n _keep="KEEP_${varname}"

    local fp_hex json_entry

    # Certificates in target
    for f in "${workdir}"/tgt/*.json; do
        [[ -f "${f}" ]] || continue
        fp_hex=$(basename "${f}" .json)
        json_entry=$(cat "${f}")
        if [[ -f "${workdir}/cur/${fp_hex}.json" ]]; then
            # Present in both — KEEP
            _keep+=("${json_entry}")
        else
            # Present in target only — ADD
            _add+=("${json_entry}")
        fi
    done

    # Certificates in current but not in target — REMOVE
    for f in "${workdir}"/cur/*.json; do
        [[ -f "${f}" ]] || continue
        fp_hex=$(basename "${f}" .json)
        if [[ ! -f "${workdir}/tgt/${fp_hex}.json" ]]; then
            json_entry=$(cat "${f}")
            _remove+=("${json_entry}")
        fi
    done
}

# ---------------------------------------------------------------------------
# update_compute <mode>
#   Compute the full delta for all variables based on provisioning mode.
#   Modes: "custom-owner", "microsoft-pk-recovery", "update-db-dbx"
# ---------------------------------------------------------------------------
update_compute() {
    [[ -z "${1:-}" ]] && { log_error "Mode parameter required"; return 1; }
    local mode="$1"

    log_info "Computing update delta for mode: ${mode}"

    # Reset result arrays
    ADD_PK=()    REMOVE_PK=()    KEEP_PK=()
    ADD_KEK=()   REMOVE_KEK=()   KEEP_KEK=()
    ADD_db=()    REMOVE_db=()    KEEP_db=()
    ADD_dbx=()   REMOVE_dbx=()   KEEP_dbx=()

    case "${mode}" in
        custom-owner|microsoft-pk-recovery|generic)
            _update_compute_var PK
            _update_compute_var KEK
            _update_compute_var db
            _update_compute_var dbx
            ;;
        update-db-dbx)
            _update_compute_var db
            _update_compute_var dbx
            ;;
        *)
            log_error "Unknown provisioning mode: ${mode}"
            return 1
            ;;
    esac

    log_info "Delta computation complete for mode: ${mode}"
}
