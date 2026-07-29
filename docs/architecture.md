# SB-ENEMA architecture overview

## Goals
Produce a minimal Buildroot-based USB image for reprovisioning UEFI Secure Boot variables on systems in Setup Mode. The image ships the tooling needed to manage PK, KEK, db, and dbx, plus a deterministic script to (re)install the values from the USB stick.

## Buildroot configuration
- Target: x86_64 EFI boot with a compressed initramfs.
- Packages: `efitools`, `curl`, `dosfstools`, BusyBox, GRUB2 (EFI).
- Overlays:
  - `/usr/sbin/sb-enema`: interactive/CLI entrypoint that mounts, audits, previews, and enrolls.
  - `/etc/init.d/S20data-mount`: mounts the FAT32 data partition at `/mnt/data` on boot.
  - `/root/.profile`: runs `sb-enema` automatically after the auto-login on the console.
- Kernel: pinned to an explicit 6.18.x longterm release via `BR2_LINUX_KERNEL_CUSTOM_VERSION` rather than tracking Buildroot's default, which follows the newest mainline series and moves with every Buildroot bump. The tarball's SHA-256 is pinned in `sb_enema/patches/linux/linux.hash`, which Buildroot resolves through `BR2_GLOBAL_PATCH_DIR` (pointed at `sb_enema/patches`); `sb_enema/patches/linux-headers/linux-headers.hash` symlinks to it because `linux-headers` downloads the same tarball. Note that Buildroot *exempts* custom-pinned versions from hash checking by default (`BR_NO_CHECK_HASH_FOR` in `linux/linux.mk`), so `BR2_DOWNLOAD_FORCE_CHECK_HASHES=y` is set to make the hashes mandatory. Together these make a version bump fail closed: change the version without changing the hash and the build stops with `ERROR: No hash found`, rather than silently downloading an unverified tarball.
- Kernel fragment enables EFI stub boot, EFI variable access, FAT32 and exFAT filesystem support, loop devices, and necessary NLS support.

## Image layout
`sb_enema/board/sb-enema/genimage/genimage.cfg` produces a hybrid GPT disk image:
- **Partition 1 (FAT32, label EFI):** GRUB EFI binary, kernel `bzImage`, and `rootfs.cpio.gz`.
- **Partition 2 (FAT32, label SB-ENEMA):** Seeded from `sb_enema/board/sb-enema/data-seed/` (contains `README.txt` documenting the partition layout) and, at build time, augmented with `sb-enema/` (payloads, keys dir, `kek_update_map.json`) and `PreSignedObjects/` from `output/secureboot-staging/` produced by `prepare-secureboot-objects.sh`. See `data-seed/README.txt` for a full description of every directory on the partition.

## Provisioning flow (runtime)
1. `S20data-mount` mounts `/dev/disk/by-label/SB-ENEMA` at `/mnt/data`; auto-login runs `sb-enema` via `/root/.profile`.
2. `sb-enema`:
   - Runs an audit/report, then offers Quick Actions (Full Colonic, Microsoft Colonic, Microsoft Suppository) and individual Staging operations.
   - Microsoft payloads are sourced from `/mnt/data/sb-enema/payloads/microsoft/` (pre-built `.auth` files staged at build time); custom mode generates PK/KEK locally via `keygen_generate_keys()`, builds ESLs for PK/KEK/db/dbx, signs them, and applies them with `efi-updatevar`.
   - The **Stage vendor default entries** option (`stage_bios_entries`) reads `KEKDefault` and `dbDefault` EFI variables (the firmware's factory-installed Secure Boot certs, preserved even after the user wipes KEK/db) and stages only those certs whose SHA-1 fingerprint appears in `kek_update_map.json` (recognized OEM vendor PKs), while excluding known test certificates (checked against `known-certs/known-test-pks.txt`) and known Microsoft-owned certs.
   - Logs actions to `/mnt/data/sb-enema/logs/`.

## Build pipeline
- `Makefile` downloads a pinned Buildroot release, applies the provided defconfig, and builds using an out-of-tree output directory.
- `scripts/prepare-secureboot-objects.sh` installs python deps for the `secureboot_objects` submodule, runs `secure_boot_default_keys.py` against SB-ENEMA's own keystore template (`sb_enema/secureboot-templates/SbEnemaRecovery.toml`, overridable via `KEYSTORE=`) to emit firmware payloads, stages the generated payloads and source certificates into `output/secureboot-staging/`, and copies `PostSignedObjects/KEK/kek_update_map.json` to `output/secureboot-staging/sb-enema/kek_update_map.json` for runtime vendor-cert filtering. Note: `scripts/` and `Templates/` from the submodule are staged locally but are not copied onto the data partition image; only `sb-enema/` and `PreSignedObjects/` reach the partition.
- `scripts/check-secureboot-policy.py` runs between generation and staging and fails the build if the generated key set violates a certificate-policy invariant — specifically if `db` omits a compatibility-critical certificate, or if `dbx` revokes a certificate that `db` relies on (a `dbx` match beats a `db` match, so that combination would stop the affected binaries booting entirely). The keystore template's header documents the policy these invariants protect.
- `scripts/generate-pk.sh` remains available to pre-seed custom PK/KEK keypairs into `data-seed/sb-enema/keys/` before building, if you opt out of runtime key generation.
- `post-image.sh` formats the FAT32 data partition image (using `mkfs.fat -F 32` from `dosfstools`), copies the seed tree and staging artefacts via `mcopy`, and runs `genimage` to assemble the final GPT disk image.
- Microsoft Secure Boot assets are sourced from the `third_party/secureboot_objects` submodule. `scripts/prepare-secureboot-objects.sh` installs that repo's Python deps and runs `secure_boot_default_keys.py` to emit firmware payloads (PK/KEK/db/dbx).
