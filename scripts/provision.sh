#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/../sb_enema/board/sb-enema/rootfs-overlay/usr/sbin/sb-enema"

if [[ ! -x "${TARGET_SCRIPT}" ]]; then
    echo "Provisioning script not found at ${TARGET_SCRIPT}" >&2
    exit 1
fi

exec "${TARGET_SCRIPT}" "$@"
