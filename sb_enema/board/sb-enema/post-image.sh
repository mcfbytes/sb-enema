#!/usr/bin/env bash
# Post-image script: prepare FAT32 data partition image (rootless) and final hybrid disk image.
#
# Uses mkfs.fat (dosfstools) to format the data partition image and mtools (mcopy)
# to populate it, both operating directly on the image file without loop-mounting.
# Runs in unprivileged CI containers that lack CAP_SYS_ADMIN.  No sudo, no mount,
# no loop devices.  mkfs.fat is preferred over mformat because it produces a
# standard FAT32 BPB that BusyBox blkid can parse to extract UUID and label.
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die() {
    echo "ERROR: $*" >&2
    exit 1
}

usage() {
    echo "Usage: $0 BINARIES_DIR [TARGET_DIR]" >&2
    echo "  BINARIES_DIR  Buildroot images output dir (e.g. output/br-out/images)" >&2
    echo "  TARGET_DIR    Buildroot target dir (defaults to BINARIES_DIR/../target)" >&2
    exit 1
}

require_tool() {
    local tool="$1"
    local hint="$2"
    command -v "${tool}" >/dev/null 2>&1 || die "${tool} not found – ${hint}"
}

cleanup() {
    rm -rf "${GENIMAGE_TMP}"
}

# ---------------------------------------------------------------------------
# Resolve paths (Buildroot passes BINARIES_DIR / TARGET_DIR as env vars and
# also as positional args; honour both forms).
# ---------------------------------------------------------------------------
BOARD_DIR="$(dirname "$(readlink -f "$0")")"
readonly BOARD_DIR
readonly BINARIES_DIR="${BINARIES_DIR:-${1:-}}"
readonly TARGET_DIR="${TARGET_DIR:-${2:-$(dirname "${BINARIES_DIR}")/target}}"

readonly DATA_SEED_DIR="${BOARD_DIR}/exfat-seed"
# EXFAT_SEED is kept as a backwards-compatible alias; prefer DATA_SEED_DIR.
readonly EXFAT_SEED="${DATA_SEED_DIR}"

# Staging dir: secureboot artefacts produced at build time by
# scripts/prepare-secureboot-objects.sh.  Override with SECUREBOOT_STAGING_DIR.
readonly STAGING_DIR="${SECUREBOOT_STAGING_DIR:-${BOARD_DIR}/../../../output/secureboot-staging}"

# Keep the image filename stable so genimage/genimage.cfg does not need to change.
# The 'exfat' in the name reflects the original format; FAT32 is used now for
# rootless tooling compatibility but the file is consumed identically by genimage.
readonly DATA_IMG="${BINARIES_DIR}/sb-enema-exfat.img"
# DATA_SIZE / EXFAT_SIZE: DATA_SIZE takes precedence; EXFAT_SIZE kept for backwards compatibility.
# Default is 36 MiB.  Must be large enough that mkfs.fat -F 32 produces ≥ 65,525 data
# clusters (the FAT spec boundary between FAT16 and FAT32).  At 32 MiB the cluster
# count falls to ~64,496 — below the threshold — so BusyBox blkid misclassifies the
# filesystem as FAT16 and reads the volume serial from the wrong BPB offset (0x27
# instead of 0x43), returning an empty UUID and breaking automount.  36 MiB yields
# ~72,544 clusters, comfortably above the threshold.
# Override at build time: DATA_SIZE=128M make images
readonly DATA_SIZE="${DATA_SIZE:-${EXFAT_SIZE:-36M}}"

readonly GENIMAGE_CFG="${BOARD_DIR}/genimage/genimage.cfg"
readonly GENIMAGE_TMP="${BINARIES_DIR}/genimage.tmp"

# ---------------------------------------------------------------------------
# Build the data partition image – no mount, no sudo required
# ---------------------------------------------------------------------------
build_data_image() {
    # Create a blank file and format it as FAT32 using mkfs.fat (dosfstools).
    # mkfs.fat writes a standard FAT32 BPB that BusyBox blkid can fully parse
    # (UUID, label, type), unlike mformat which produces a BPB variant that
    # BusyBox blkid only partially reads.  mcopy is still used for content.
    #   -F 32  force FAT32 even for smaller images
    #   -I     ignore "not a safe device" warning when formatting a plain file
    #   -n     set the volume label
    #   -i     set the volume serial (UUID exposed as BEEF-CAFE by blkid)
    rm -f "${DATA_IMG}"
    truncate -s "${DATA_SIZE}" "${DATA_IMG}"
    mkfs.fat -F 32 -I -n "SB-ENEMA" -i BEEFCAFE "${DATA_IMG}"

    # Copy seed files (DB, DBX, KEK, PK, README.txt, certs, logs, …) to root.
    local item
    for item in "${EXFAT_SEED}"/*; do
        [[ -e "${item}" ]] || continue  # skip if glob matched nothing
        mcopy -i "${DATA_IMG}" -s "${item}" ::
    done

    # Copy the sb-enema/ subtree from staging into the data partition so that
    # runtime scripts can find payloads at ${DATA_MOUNT}/sb-enema/payloads/
    # (e.g. /mnt/data/sb-enema/payloads/).
    #
    # Only the sb-enema/ subtree is copied; build-only artefacts
    # (secureboot_artifacts/, Templates/, scripts/, …) are intentionally
    # excluded to keep the image small and deterministic.
    if [[ -d "${STAGING_DIR}/sb-enema" ]]; then
        mcopy -i "${DATA_IMG}" -s "${STAGING_DIR}/sb-enema" ::
        # Copy PreSignedObjects from staging so that enroll-custom.sh can locate
        # Microsoft db certificates at ${DATA_MOUNT}/PreSignedObjects at runtime.
        # Only needed in the per-subtree layout; the fallback branch copies wholesale.
        if [[ -d "${STAGING_DIR}/PreSignedObjects" ]]; then
            mcopy -i "${DATA_IMG}" -s "${STAGING_DIR}/PreSignedObjects" ::
        fi
    elif [[ -d "${STAGING_DIR}" ]]; then
        # Fallback: staging tree predates the per-subtree layout – copy wholesale.
        for item in "${STAGING_DIR}"/*; do
            [[ -e "${item}" ]] || continue
            mcopy -i "${DATA_IMG}" -s "${item}" ::
        done
    fi
}

# ---------------------------------------------------------------------------
# Assemble the EFI System Partition boot directory
#
# Just boot the Linux kernel directly with EFI stub booting;
# no separate bootloader stage.
# ---------------------------------------------------------------------------
assemble_efi_boot() {
    local efi_boot="${BINARIES_DIR}/efi-part/EFI/BOOT"
    mkdir -p "${efi_boot}"

    cp "${BINARIES_DIR}/bzImage" "${BINARIES_DIR}/efi-part/EFI/BOOT/BOOTX64.EFI"
}

# ---------------------------------------------------------------------------
# Run genimage to assemble the final hybrid GPT disk image
# ---------------------------------------------------------------------------
run_genimage() {
    rm -rf "${GENIMAGE_TMP}"

    genimage \
        --rootpath   "${TARGET_DIR}" \
        --tmppath    "${GENIMAGE_TMP}" \
        --inputpath  "${BINARIES_DIR}" \
        --outputpath "${BINARIES_DIR}" \
        --config     "${GENIMAGE_CFG}"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
    [[ -n "${BINARIES_DIR}" ]] || usage

    require_tool mkfs.fat "install dosfstools"
    require_tool mcopy    "install mtools"
    require_tool genimage "install genimage"

    trap cleanup EXIT

    build_data_image
    assemble_efi_boot
    run_genimage
}

main "$@"
