#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SEED_BASE="${SEED_BASE:-${ROOT_DIR}/buildroot-config/board/sb-enema/exfat-seed}"

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

generate_cert "/CN=SB-ENEMA PK" "${SEED_BASE}/PK" "PK"
generate_cert "/CN=SB-ENEMA KEK" "${SEED_BASE}/KEK" "KEK"
