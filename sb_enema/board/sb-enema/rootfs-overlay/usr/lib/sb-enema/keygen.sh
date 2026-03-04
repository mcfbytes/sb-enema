#!/usr/bin/env bash
# keygen.sh — Key generation, GUID management, and backup instructions for SB-ENEMA.
# shellcheck disable=SC2034  # Variables may be used by sourcing scripts.
set -euo pipefail
[[ -n "${_SB_ENEMA_KEYGEN_SH:-}" ]] && return 0
readonly _SB_ENEMA_KEYGEN_SH=1

# ---------------------------------------------------------------------------
# Source required libraries
# ---------------------------------------------------------------------------
# shellcheck source=common.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/common.sh"
# shellcheck source=log.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/log.sh"
# shellcheck source=report.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/report.sh"

# ---------------------------------------------------------------------------
# Key storage directory on the data partition
# ---------------------------------------------------------------------------
KEYS_DIR="${DATA_MOUNT}/sb-enema/keys"

# ---------------------------------------------------------------------------
# EFI owner GUID for user-generated certificates.
# Populated by keygen_load_or_generate_guid().
# ---------------------------------------------------------------------------
OWNER_GUID=""

# ---------------------------------------------------------------------------
# CN prefix for user-generated certificates.
# Defaults to "Custom"; may be overridden before calling keygen_generate_keys().
# ---------------------------------------------------------------------------
CERT_CN_PREFIX="${CERT_CN_PREFIX:-Custom}"

# ---------------------------------------------------------------------------
# keygen_load_or_generate_guid() — Load the owner GUID from the FAT volume
#   or generate a new one randomly and persist it.
#   Prints the GUID to stdout; callers should capture via $().
# ---------------------------------------------------------------------------
keygen_load_or_generate_guid() {
    local guid_file="${DATA_MOUNT}/sb-enema/owner-guid.txt"
    local guid

    if [[ -f "${guid_file}" ]]; then
        guid=$(tr -d '[:space:]' < "${guid_file}")
        if [[ "${guid}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
            log_info "Loaded owner GUID from ${guid_file}: ${guid}" >&2
            printf '%s' "${guid}"
            return 0
        fi
        log_warn "owner-guid.txt contains invalid UUID '${guid}'; generating a new one" >&2
    fi

    guid=$(cat /proc/sys/kernel/random/uuid)
    mkdir -p "$(dirname "${guid_file}")"
    printf '%s\n' "${guid}" > "${guid_file}"
    log_info "Generated new owner GUID: ${guid} (saved to ${guid_file})" >&2
    printf '%s' "${guid}"
}

# ---------------------------------------------------------------------------
# _keygen_sanitize_dn_field <string>
#   Sanitize a string for use in an X.509 Distinguished Name field.
# ---------------------------------------------------------------------------
_keygen_sanitize_dn_field() {
    local value="$1"
    value=$(printf '%s' "${value}" | tr -d '[:cntrl:]' | tr -d '/\\",+<>;=' | tr -s ' ')
    value=$(printf '%s' "${value}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [[ -z "${value}" ]]; then
        value="Unknown"
    fi
    printf '%s' "${value}"
}

# ---------------------------------------------------------------------------
# _keygen_generate_keypair <subject> <key_file> <crt_file>
#   Internal helper: generate a 4096-bit RSA key pair and self-signed cert.
# ---------------------------------------------------------------------------
_keygen_generate_keypair() {
    local subject="$1"
    local key_file="$2"
    local crt_file="$3"
    local old_umask

    log_info "Generating certificate: ${subject}"
    old_umask=$(umask)
    umask 077
    openssl req -new -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -subj "${subject}" \
        -keyout "${key_file}" \
        -out "${crt_file}"
    umask "${old_umask}"

    local fp
    fp=$(openssl x509 -in "${crt_file}" -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/.*Fingerprint=//') || fp="(unknown)"
    log_info "Fingerprint: ${fp}"
}

# ---------------------------------------------------------------------------
# keygen_generate_keys() — Generate PK, KEK, and DB key pairs.
#   Creates 4096-bit RSA keys with 10-year validity.  Skips generation
#   if valid certificates already exist.  Stores keys and certs in KEYS_DIR.
#   Also copies PK/KEK/DB certs to ${DATA_MOUNT}/{PK,KEK,DB}/ for certdb
#   ownership detection.
# ---------------------------------------------------------------------------
keygen_generate_keys() {
    log_info "Generating custom owner keys"
    mkdir -p "${KEYS_DIR}"

    # Type 1 — System Information: used for PK (platform owner) and DB (boot scope)
    local sys_vendor product_name product_family
    sys_vendor=$(_report_dmi_field /sys/class/dmi/id/sys_vendor)
    product_name=$(_report_dmi_field /sys/class/dmi/id/product_name)
    product_family=$(_report_dmi_field /sys/class/dmi/id/product_family)

    [[ -z "${sys_vendor}"     || "${sys_vendor}"     == "(unknown)" ]] && sys_vendor="Unknown Vendor"
    [[ -z "${product_name}"   || "${product_name}"   == "(unknown)" ]] && product_name="Unknown Product"
    [[ -z "${product_family}" || "${product_family}" == "(unknown)" ]] && product_family="${product_name}"

    sys_vendor=$(_keygen_sanitize_dn_field "${sys_vendor}")
    product_name=$(_keygen_sanitize_dn_field "${product_name}")
    product_family=$(_keygen_sanitize_dn_field "${product_family}")

    # Type 2 — Base Board Information: used for KEK (firmware/board identity)
    local board_vendor board_name
    board_vendor=$(_report_dmi_field /sys/class/dmi/id/board_vendor)
    board_name=$(_report_dmi_field /sys/class/dmi/id/board_name)

    [[ -z "${board_vendor}" || "${board_vendor}" == "(unknown)" ]] && board_vendor="Unknown Vendor"
    [[ -z "${board_name}"   || "${board_name}"   == "(unknown)" ]] && board_name="Unknown Board"

    board_vendor=$(_keygen_sanitize_dn_field "${board_vendor}")
    board_name=$(_keygen_sanitize_dn_field "${board_name}")

    local cn_prefix
    cn_prefix=$(_keygen_sanitize_dn_field "${CERT_CN_PREFIX}")

    # PK: system-level owner identity (Type 1 — sys_vendor / product_name)
    local pk_subject="/CN=${cn_prefix} Platform Key/O=${sys_vendor}/OU=${product_name}"
    local pk_key="${KEYS_DIR}/PK.key"
    local pk_crt="${KEYS_DIR}/PK.crt"

    if [[ -f "${pk_crt}" ]] && [[ -f "${pk_key}" ]]; then
        if openssl x509 -in "${pk_crt}" -noout -checkend 0 >/dev/null 2>&1; then
            log_info "Existing PK certificate is still valid; skipping generation"
            local fp
            fp=$(openssl x509 -in "${pk_crt}" -noout -fingerprint -sha256 2>/dev/null \
                | sed 's/.*Fingerprint=//') || fp="(unknown)"
            log_info "PK fingerprint: ${fp}"
        else
            log_warn "Existing PK certificate is expired; generating new one"
            _keygen_generate_keypair "${pk_subject}" "${pk_key}" "${pk_crt}"
        fi
    else
        _keygen_generate_keypair "${pk_subject}" "${pk_key}" "${pk_crt}"
    fi

    mkdir -p "${DATA_MOUNT}/PK"
    cp "${pk_crt}" "${DATA_MOUNT}/PK/PK.crt"

    # KEK: board/firmware identity (Type 2 — board_vendor / board_name)
    local kek_subject="/CN=${cn_prefix} Key Exchange Key/O=${board_vendor}/OU=${board_name}"
    local kek_key="${KEYS_DIR}/KEK.key"
    local kek_crt="${KEYS_DIR}/KEK.crt"

    if [[ -f "${kek_crt}" ]] && [[ -f "${kek_key}" ]]; then
        if openssl x509 -in "${kek_crt}" -noout -checkend 0 >/dev/null 2>&1; then
            log_info "Existing KEK certificate is still valid; skipping generation"
            local kek_fp
            kek_fp=$(openssl x509 -in "${kek_crt}" -noout -fingerprint -sha256 2>/dev/null \
                | sed 's/.*Fingerprint=//') || kek_fp="(unknown)"
            log_info "KEK fingerprint: ${kek_fp}"
        else
            log_warn "Existing KEK certificate is expired; generating new one"
            _keygen_generate_keypair "${kek_subject}" "${kek_key}" "${kek_crt}"
        fi
    else
        _keygen_generate_keypair "${kek_subject}" "${kek_key}" "${kek_crt}"
    fi

    mkdir -p "${DATA_MOUNT}/KEK"
    cp "${kek_crt}" "${DATA_MOUNT}/KEK/KEK.crt"

    # DB: boot-target scope (Type 1 — sys_vendor / product_family)
    local db_subject="/CN=${cn_prefix} Allowed DB/O=${sys_vendor}/OU=${product_family}"
    local db_key="${KEYS_DIR}/DB.key"
    local db_crt="${KEYS_DIR}/DB.crt"

    if [[ -f "${db_crt}" ]] && [[ -f "${db_key}" ]]; then
        if openssl x509 -in "${db_crt}" -noout -checkend 0 >/dev/null 2>&1; then
            log_info "Existing DB certificate is still valid; skipping generation"
            local db_fp
            db_fp=$(openssl x509 -in "${db_crt}" -noout -fingerprint -sha256 2>/dev/null \
                | sed 's/.*Fingerprint=//') || db_fp="(unknown)"
            log_info "DB fingerprint: ${db_fp}"
        else
            log_warn "Existing DB certificate is expired; generating new one"
            _keygen_generate_keypair "${db_subject}" "${db_key}" "${db_crt}"
        fi
    else
        _keygen_generate_keypair "${db_subject}" "${db_key}" "${db_crt}"
    fi

    mkdir -p "${DATA_MOUNT}/DB"
    cp "${db_crt}" "${DATA_MOUNT}/DB/DB.crt"

    log_success "Custom owner keys generated in ${KEYS_DIR}"
}

# ---------------------------------------------------------------------------
# _keygen_find_esp()
#   Locate the EFI System Partition block device that is on the same disk
#   as the SB-ENEMA data partition.  Prints the device path on success;
#   returns 1 if the ESP cannot be found.
# ---------------------------------------------------------------------------
_keygen_find_esp() {
    if ! command -v lsblk >/dev/null 2>&1; then
        log_warn "lsblk not found; cannot locate EFI System Partition"
        return 1
    fi

    local data_dev
    data_dev=$(blkid -t UUID="${DATA_UUID}" -o device 2>/dev/null | head -n1)
    if [[ -z "${data_dev}" ]]; then
        data_dev=$(blkid -t LABEL="${DATA_LABEL}" -o device 2>/dev/null | head -n1)
    fi
    [[ -z "${data_dev}" ]] && return 1

    local disk
    disk=$(lsblk -no PKNAME "${data_dev}" 2>/dev/null | head -n1)
    [[ -z "${disk}" ]] && return 1

    local esp_dev
    esp_dev=$(lsblk -lno NAME,PARTTYPE "/dev/${disk}" 2>/dev/null \
              | awk 'tolower($2) == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {print "/dev/" $1; exit}')
    [[ -z "${esp_dev}" ]] && return 1
    echo "${esp_dev}"
}

# ---------------------------------------------------------------------------
# _keygen_sign_bootx64()
#   Sign the BOOTX64.EFI binary on the EFI System Partition with the
#   user-generated DB key/cert so that the SB-ENEMA tool can boot under
#   Secure Boot on next power-on.
# ---------------------------------------------------------------------------
_keygen_sign_bootx64() {
    local db_key="${KEYS_DIR}/DB.key"
    local db_crt="${KEYS_DIR}/DB.crt"

    if ! command -v sbsign >/dev/null 2>&1; then
        log_warn "sbsign not found; skipping BOOTX64.EFI signing (install sbsigntools)"
        return 0
    fi

    local esp_dev
    if ! esp_dev=$(_keygen_find_esp); then
        log_warn "EFI System Partition not found; skipping BOOTX64.EFI signing"
        return 0
    fi

    local esp_mount="/mnt/efi"
    local esp_mounted=0
    if ! mountpoint -q "${esp_mount}" 2>/dev/null; then
        mkdir -p "${esp_mount}"
        if mount -t vfat -o rw "${esp_dev}" "${esp_mount}" 2>/dev/null; then
            esp_mounted=1
        else
            log_warn "Could not mount ESP ${esp_dev} at ${esp_mount}; skipping BOOTX64.EFI signing"
            return 0
        fi
    fi

    local efi_binary="${esp_mount}/EFI/BOOT/BOOTX64.EFI"
    if [[ ! -f "${efi_binary}" ]]; then
        log_warn "BOOTX64.EFI not found at ${efi_binary}; skipping signing"
        [[ "${esp_mounted}" -eq 1 ]] && umount "${esp_mount}" 2>/dev/null || true
        return 0
    fi

    log_info "Signing ${efi_binary} with user DB certificate"
    local signed_tmp
    if ! signed_tmp=$(mktemp "${esp_mount}/BOOTX64.XXXXXX"); then
        log_warn "Could not create temp file on ESP; skipping BOOTX64.EFI signing"
        [[ "${esp_mounted}" -eq 1 ]] && umount "${esp_mount}" 2>/dev/null || true
        return 0
    fi
    local sign_rc=0 sign_stderr
    sign_stderr=$(sbsign --key "${db_key}" --cert "${db_crt}" \
                         --output "${signed_tmp}" "${efi_binary}" 2>&1) || sign_rc=$?
    if [[ "${sign_rc}" -eq 0 ]]; then
        mv "${signed_tmp}" "${efi_binary}"
        log_action "SIGN" "BOOTX64.EFI" "SUCCESS" "signed with user DB cert"
        log_success "BOOTX64.EFI signed with user DB certificate"
    else
        rm -f "${signed_tmp}"
        log_warn "sbsign failed (rc=${sign_rc}): ${sign_stderr}"
    fi

    [[ "${esp_mounted}" -eq 1 ]] && umount "${esp_mount}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# keygen_backup_instructions() — Print and log clear instructions about
#   key storage and backup.
# ---------------------------------------------------------------------------
keygen_backup_instructions() {
    local msg1="Your private keys are stored on this USB drive at ${KEYS_DIR}/"
    local msg2="BACK THESE UP. If you lose them and need to modify Secure Boot variables later, you must re-enter Setup Mode."
    local msg3="The public certificates are enrolled in your firmware. The private keys are NOT stored on your computer."
    local msg4="WARNING: This USB drive contains private keys. Store it securely and do not leave it unattended."

    echo
    echo -e "${BOLD}  KEY BACKUP INSTRUCTIONS${RESET}"
    echo
    echo -e "  ${YELLOW}${msg1}${RESET}"
    echo
    echo -e "  ${RED}${msg2}${RESET}"
    echo
    echo -e "  ${msg3}"
    echo
    echo -e "  ${RED}${BOLD}${msg4}${RESET}"
    echo

    log_info "${msg1}"
    log_info "${msg2}"
    log_info "${msg3}"
    log_warn "${msg4}"
}
