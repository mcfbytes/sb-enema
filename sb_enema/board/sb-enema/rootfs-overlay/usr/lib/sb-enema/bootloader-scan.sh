#!/usr/bin/env bash
# bootloader-scan.sh — Scan EFI bootloader chains to determine whether
# Microsoft Windows Production PCA 2011 is still actively used to sign
# any EFI binary.  Used to gate DBX2024 PCA 2011 CA revocation staging.
# shellcheck disable=SC2034
set -euo pipefail
[[ -n "${_SB_ENEMA_BOOTLOADER_SCAN_SH:-}" ]] && return 0
readonly _SB_ENEMA_BOOTLOADER_SCAN_SH=1

# shellcheck source=common.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/common.sh"
# shellcheck source=log.sh
source "${SB_ENEMA_LIB_DIR:-/usr/lib/sb-enema}/log.sh"

# ---------------------------------------------------------------------------
# Certificate fingerprint constants (lowercase hex, no colons).
# Kept in sync with _AUDIT_MS_WIN_PCA_2011 and _AUDIT_MS_UEFI_CA_2023
# in audit.sh — both sets must be updated together.
# ---------------------------------------------------------------------------
readonly _BSCAN_MS_WIN_PCA_2011="e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
readonly _BSCAN_MS_WIN_UEFI_CA_2023="f6124e34125bee3fe6d79a574eaa7b91c0e7bd9d929c1a321178efd611dad901"

# Exported verdict variable — set by bootloader_scan_pca2011_in_use().
BSCAN_VERDICT=""

# ---------------------------------------------------------------------------
# _bscan_list_internal_disks()
#   Print a newline-separated list of /dev/<name> paths for every non-removable
#   disk found by lsblk.
# ---------------------------------------------------------------------------
_bscan_list_internal_disks() {
    local name type removable

    while IFS=" " read -r name type; do
        [[ "${type}" == "disk" ]] || continue
        removable=""
        removable=$(cat "/sys/block/${name}/removable" 2>/dev/null) || removable="1"
        [[ "${removable}" == "1" ]] && continue
        echo "/dev/${name}"
    done < <(lsblk -dno NAME,TYPE 2>/dev/null)
}

# ---------------------------------------------------------------------------
# _bscan_find_esp_partitions [<disk>]
#   Print a newline-separated list of block device paths for all EFI System
#   Partitions.  If <disk> is given only that disk is searched; otherwise all
#   internal disks are searched.
# ---------------------------------------------------------------------------
_bscan_find_esp_partitions() {
    local disk="${1:-}"
    local -a disks=()

    if [[ -n "${disk}" ]]; then
        disks=("${disk}")
    else
        while IFS= read -r d; do
            [[ -n "${d}" ]] && disks+=("${d}")
        done < <(_bscan_list_internal_disks)
    fi

    local d name parttype
    for d in "${disks[@]}"; do
        while IFS=" " read -r name parttype; do
            # Case-insensitive match on the ESP GUID
            if [[ "${parttype,,}" == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ]]; then
                echo "/dev/${name}"
            fi
        done < <(lsblk -lno NAME,PARTTYPE "${d}" 2>/dev/null)
    done
}

# ---------------------------------------------------------------------------
# _bscan_mount_esp <dev> <mountpoint>
#   Mount an EFI System Partition read-only.  Returns 1 on failure.
# ---------------------------------------------------------------------------
_bscan_mount_esp() {
    local dev="$1"
    local mp="$2"

    log_info "Mounting ESP ${dev} at ${mp} (read-only)"
    if ! mount -t vfat -o ro "${dev}" "${mp}" 2>/dev/null; then
        log_warn "Failed to mount ESP ${dev} at ${mp}"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# _bscan_umount_esp <mountpoint>
#   Unmount an ESP (best-effort; never fails).
# ---------------------------------------------------------------------------
_bscan_umount_esp() {
    local mp="$1"
    umount "${mp}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# _bscan_windows_efi_binaries <esp_mount>
#   Print a newline-separated list of Windows EFI binary paths found on the
#   mounted ESP and on any NTFS partitions on the same disk.
# ---------------------------------------------------------------------------
_bscan_windows_efi_binaries() {
    local esp_mount="$1"

    # Well-known ESP-resident Windows binaries
    local f
    for f in \
        "${esp_mount}/EFI/Microsoft/Boot/bootmgfw.efi" \
        "${esp_mount}/EFI/Microsoft/Boot/bootmgr.efi" \
        "${esp_mount}/EFI/Microsoft/Boot/memtest.efi"; do
        [[ -f "${f}" ]] && echo "${f}"
    done

    # Discover the parent disk of the ESP so we can find the Windows partition
    local esp_dev
    esp_dev=$(findmnt -n -o SOURCE "${esp_mount}" 2>/dev/null) || esp_dev=""
    [[ -z "${esp_dev}" ]] && return 0

    local parent_disk
    parent_disk=$(lsblk -no PKNAME "${esp_dev}" 2>/dev/null | head -n1) || parent_disk=""
    [[ -z "${parent_disk}" ]] && return 0

    local ntfs_tmpdir
    ntfs_tmpdir=$(mktemp -d) || return 0
    # shellcheck disable=SC2064
    trap "umount '${ntfs_tmpdir}' 2>/dev/null || true; rm -rf '${ntfs_tmpdir}'" RETURN

    local name fstype
    while IFS=" " read -r name fstype; do
        [[ "${fstype,,}" == "ntfs3" ]] || [[ "${fstype,,}" == "ntfs" ]] || continue
        local ntfs_dev="/dev/${name}"

        # Try ntfs3 first (in-tree read-only driver), fall back to ntfs.
        # Unmount before retry to avoid "already mounted" errors if ntfs3
        # partially initialises the mount point before returning non-zero.
        if ! mount -t ntfs3 -o ro,noatime "${ntfs_dev}" "${ntfs_tmpdir}" 2>/dev/null; then
            umount "${ntfs_tmpdir}" 2>/dev/null || true
            mount -t ntfs -o ro,noatime "${ntfs_dev}" "${ntfs_tmpdir}" 2>/dev/null || continue
        fi

        for f in \
            "${ntfs_tmpdir}/Windows/System32/winload.efi" \
            "${ntfs_tmpdir}/Windows/System32/hvloader.efi"; do
            [[ -f "${f}" ]] && echo "${f}"
        done

        umount "${ntfs_tmpdir}" 2>/dev/null || true
    done < <(lsblk -lno NAME,FSTYPE "/dev/${parent_disk}" 2>/dev/null)
}

# ---------------------------------------------------------------------------
# _bscan_linux_efi_binaries <esp_mount>
#   Print a newline-separated list of SHIM/Linux EFI binaries found under
#   <esp_mount>/EFI/, excluding the Microsoft/ and BOOT/ subtrees.
# ---------------------------------------------------------------------------
_bscan_linux_efi_binaries() {
    local esp_mount="$1"
    local efi_root="${esp_mount}/EFI"

    [[ -d "${efi_root}" ]] || return 0

    local f
    while IFS= read -r f; do
        # Exclude Microsoft and fallback BOOT directories
        [[ "${f}" == *"/EFI/Microsoft/"* ]] && continue
        [[ "${f}" == *"/EFI/BOOT/"* ]]      && continue
        [[ "${f}" == *"/EFI/boot/"* ]]       && continue

        # Include only recognisable bootloader filenames
        local base
        base=$(basename "${f}")
        case "${base,,}" in
            *shim* | *grub* | *grubx64* | *grubaa64* | *grubarm* | \
            *elilo* | *fwupd* | *fwupdx64*)
                echo "${f}" ;;
        esac
    done < <(find "${efi_root}" \( -name "*.efi" -o -name "*.EFI" \) 2>/dev/null)
}

# ---------------------------------------------------------------------------
# _bscan_extract_signing_ca_fps <efi_binary>
#   Extract the SHA-256 fingerprints of all CA certificates in the Authenticode
#   signing chain embedded in <efi_binary>.  Prints one fingerprint per line.
#
#   Preferred path: osslsigncode (BR2_PACKAGE_OSSLSIGNCODE=y enables this)
#   Fallback path:  sbverify --list (issuer name matching; less reliable)
#
#   Returns 1 if extraction fails; never calls die().
# ---------------------------------------------------------------------------
_bscan_extract_signing_ca_fps() {
    local efi_binary="$1"

    [[ -f "${efi_binary}" ]] || return 1

    local tmpdir
    tmpdir=$(mktemp -d) || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '${tmpdir}'" RETURN

    # --- Preferred path: osslsigncode ---
    if command -v osslsigncode >/dev/null 2>&1; then
        if ! osslsigncode extract-signature \
                -in "${efi_binary}" \
                -out "${tmpdir}/sig.p7" >/dev/null 2>&1; then
            return 1
        fi

        if ! openssl pkcs7 -inform DER \
                -in "${tmpdir}/sig.p7" \
                -print_certs \
                -out "${tmpdir}/chain.pem" 2>/dev/null; then
            return 1
        fi

        [[ -s "${tmpdir}/chain.pem" ]] || return 1

        # Split chain.pem into individual certificates and fingerprint each
        local idx=0
        local cert_pem="${tmpdir}/cert-${idx}.pem"
        local in_cert=0
        local line

        while IFS= read -r line; do
            if [[ "${line}" == "-----BEGIN CERTIFICATE-----" ]]; then
                in_cert=1
                cert_pem="${tmpdir}/cert-${idx}.pem"
                printf '%s\n' "${line}" > "${cert_pem}"
            elif [[ "${line}" == "-----END CERTIFICATE-----" ]]; then
                printf '%s\n' "${line}" >> "${cert_pem}"
                in_cert=0
                local fp
                fp=$(openssl x509 -in "${cert_pem}" -outform DER 2>/dev/null \
                    | sha256sum 2>/dev/null | awk '{print $1}') || true
                [[ -n "${fp}" ]] && echo "${fp}"
                idx=$(( idx + 1 ))
            elif [[ "${in_cert}" -eq 1 ]]; then
                printf '%s\n' "${line}" >> "${cert_pem}"
            fi
        done < "${tmpdir}/chain.pem"

        return 0
    fi

    # --- Fallback path: sbverify --list (issuer name matching) ---
    if command -v sbverify >/dev/null 2>&1; then
        log_warn "osslsigncode not available; using sbverify issuer-name matching for ${efi_binary} (less reliable than fingerprint matching)"

        local issuer
        while IFS= read -r issuer; do
            # Map well-known issuer CNs to their canonical fingerprints so
            # callers can still do fingerprint comparisons even on this path.
            case "${issuer}" in
                *"Windows Production PCA 2011"*)
                    echo "${_BSCAN_MS_WIN_PCA_2011}" ;;
                *"Windows UEFI CA 2023"*)
                    echo "${_BSCAN_MS_WIN_UEFI_CA_2023}" ;;
            esac
        done < <(sbverify --list "${efi_binary}" 2>/dev/null \
                     | grep -i "issuer" | awk -F: '{print $2}')

        return 0
    fi

    # No extraction tool available
    log_warn "Neither osslsigncode nor sbverify found; cannot extract signing certificates from ${efi_binary}"
    return 1
}

# ---------------------------------------------------------------------------
# bootloader_scan_pca2011_in_use()
#   Primary public API.
#
#   Returns:
#     0  and exports BSCAN_VERDICT="CLEAR"         — no PCA 2011 signers found
#     1  and exports BSCAN_VERDICT="PCA2011_IN_USE" — PCA 2011 in use
#     1  and exports BSCAN_VERDICT="SCAN_FAILED"   — scan error / no binaries
# ---------------------------------------------------------------------------
bootloader_scan_pca2011_in_use() {
    local tmpdir
    tmpdir=$(mktemp -d) || { BSCAN_VERDICT="SCAN_FAILED"; export BSCAN_VERDICT; return 1; }
    # shellcheck disable=SC2064
    trap "rm -rf '${tmpdir}'" RETURN

    local pca2011_found=0
    local scanned=0

    local -a esp_list=()
    while IFS= read -r esp; do
        [[ -n "${esp}" ]] && esp_list+=("${esp}")
    done < <(_bscan_find_esp_partitions || true)

    if [[ ${#esp_list[@]} -eq 0 ]]; then
        log_warn "No EFI System Partitions found on internal disks"
        BSCAN_VERDICT="SCAN_FAILED"
        export BSCAN_VERDICT
        return 1
    fi

    local esp esp_mp
    for esp in "${esp_list[@]}"; do
        esp_mp="${tmpdir}/esp-$(basename "${esp}")"
        mkdir -p "${esp_mp}"

        if ! _bscan_mount_esp "${esp}" "${esp_mp}"; then
            log_warn "Skipping ESP ${esp} — could not mount"
            continue
        fi

        local -a binaries=()
        while IFS= read -r b; do
            [[ -n "${b}" ]] && binaries+=("${b}")
        done < <(
            _bscan_windows_efi_binaries "${esp_mp}" 2>/dev/null || true
            _bscan_linux_efi_binaries   "${esp_mp}" 2>/dev/null || true
        )

        _bscan_umount_esp "${esp_mp}"

        local binary fp
        for binary in "${binaries[@]}"; do
            local fps
            fps=$(_bscan_extract_signing_ca_fps "${binary}" 2>/dev/null) || {
                log_warn "Failed to extract signing CAs from ${binary}; skipping"
                continue
            }

            scanned=$(( scanned + 1 ))

            while IFS= read -r fp; do
                [[ -n "${fp}" ]] || continue
                if [[ "${fp}" == "${_BSCAN_MS_WIN_PCA_2011}" ]]; then
                    log_warn "PCA 2011 signer found in: ${binary}"
                    pca2011_found=1
                fi
            done <<< "${fps}"
        done
    done

    if [[ "${pca2011_found}" -eq 1 ]]; then
        BSCAN_VERDICT="PCA2011_IN_USE"
        export BSCAN_VERDICT
        return 1
    fi

    if [[ "${scanned}" -eq 0 ]]; then
        BSCAN_VERDICT="SCAN_FAILED"
        export BSCAN_VERDICT
        return 1
    fi

    BSCAN_VERDICT="CLEAR"
    export BSCAN_VERDICT
    return 0
}

# ---------------------------------------------------------------------------
# bootloader_scan_log_summary()
#   Print a human-readable summary of the last scan result.
# ---------------------------------------------------------------------------
bootloader_scan_log_summary() {
    case "${BSCAN_VERDICT:-}" in
        CLEAR)
            log_success "✔ Bootloader scan complete — no PCA 2011 signers detected. DBX2024 CA revocation may be applied safely."
            ;;
        PCA2011_IN_USE)
            log_warn "⚠ One or more bootloaders are still signed by Microsoft Windows Production PCA 2011. DBX2024 CA revocation will NOT be applied — update Windows (KB5062710 or later) first."
            ;;
        *)
            log_warn "⚠ Bootloader scan failed or found no scannable EFI binaries. DBX2024 CA revocation will NOT be applied (fail-safe)."
            ;;
    esac
}
