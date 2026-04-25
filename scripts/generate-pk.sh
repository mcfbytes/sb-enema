#!/usr/bin/env bash
# generate-pk.sh — Pre-seed custom PK and KEK certificates into the data partition
# build tree so they are baked into the image before flashing.
#
# Generated files land in data-seed/sb-enema/keys/, which is the same path the
# runtime keygen_generate_keys() function uses (${DATA_MOUNT}/sb-enema/keys/).
# At build time these files are mcopy-ed onto the FAT32 data partition image.
#
# WARNING: Embedding private keys in a build artifact means they will be readable
# by anyone with access to the .img file or the USB stick.  Only use this script
# in a trusted build environment.  For most use cases, let sb-enema generate keys
# at runtime on first boot instead.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KEYS_OUT="${KEYS_OUT:-${ROOT_DIR}/sb_enema/board/sb-enema/data-seed/sb-enema/keys}"

generate_cert() {
    local subject="$1"
    local dir="$2"
    local prefix="$3"

    mkdir -p "${dir}"
    local key="${dir}/${prefix}.key"
    local crt="${dir}/${prefix}.crt"

    if [[ -f "${key}" && -f "${crt}" ]]; then
        echo "Skipping ${prefix}: already exists in ${dir}"
        return
    fi

    echo "Generating ${prefix} certificate in ${dir}"
    umask 077
    openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
        -subj "${subject}" \
        -keyout "${key}" \
        -out "${crt}"
}

generate_cert "/CN=SB-ENEMA PK" "${KEYS_OUT}" "PK"
generate_cert "/CN=SB-ENEMA KEK" "${KEYS_OUT}" "KEK"
