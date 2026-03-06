# Secure Boot Payload Trace

## Flow Diagram (text)

- Microsoft PK Recovery path  
  `third_party/secureboot_objects` → `scripts/prepare-secureboot-objects.sh` (venv + `secure_boot_default_keys.py`) → `output/secureboot-staging/secureboot_artifacts/Firmware/{PK,KEK,DB,DBX}.bin` and `sb-enema/payloads/microsoft/{PK,KEK,db,dbx}.auth` → `post-image.sh` rsyncs staging onto FAT32 data partition → runtime paths `/mnt/data/secureboot_artifacts/*` and `/mnt/data/sb-enema/payloads/microsoft/*.auth` → `msft_enroll` stages certs from `/mnt/data/PreSignedObjects` into `/mnt/data/sb-enema/payloads/{PK,KEK,db}` for preview → `efi-updatevar` writes db → dbx → KEK → PK.
- Custom Owner path  
  User runs `sb-enema` → `custom_generate_keys` writes `/mnt/data/sb-enema/keys/{PK,KEK}.{key,crt}` and copies PK cert to `/mnt/data/PK/PK.crt` → `custom_create_payloads` uses efitools to build `/mnt/data/sb-enema/payloads/{PK,KEK,db,dbx}.auth`; db uses certs from `/mnt/data/PreSignedObjects/DB/Certificates`, dbx pulls `/mnt/data/secureboot_artifacts/Firmware/dbx.bin` (fallback `/mnt/data/PreSignedObjects/DBX/DBX.bin`) → preview/update delta → `efi-updatevar` writes db → dbx → KEK → PK.
- Common assets  
  Templates/scripts from `secureboot_objects` land at `/mnt/data/PreSignedObjects`, `/mnt/data/Templates`, `/mnt/data/scripts` for transparency/debugging; FAT32 seed adds `/PK`, `/KEK`, `/DB`, `/DBX`, `/logs` placeholders.

## Issues Table

| Severity | Stage | File(s) | Issue | Suggested Fix |
| --- | --- | --- | --- | --- |
| High | Runtime bootstrap | sb_enema/board/sb-enema/rootfs-overlay/etc/init.d/S40sb-enema | Init script called non-existent `/usr/sbin/sb-enema-provision.sh`, so the main tool never launched. | Start `/usr/sbin/sb-enema` instead. (Fixed) |
| Medium | CLI helper | scripts/provision.sh | Helper script pointed at removed `buildroot-config/.../sb-enema-provision.sh`, so local invocation failed. | Point to current `sb_enema/board/sb-enema/rootfs-overlay/usr/sbin/sb-enema`. (Fixed) |
| Medium | Build tooling | sb_enema/board/sb-enema/post-image.sh | Requires host `mkfs.fat` (dosfstools) to format the FAT32 data partition; build will stop if host lacks it. | Install `dosfstools` on host. |
| Low | Mountpoint leftovers | sb_enema/board/sb-enema/post-build.sh | Creates `/mnt/sb-enema` in target rootfs, but runtime uses `/mnt/data`. Harmless but unused. | Aligned to `/mnt/data`; `/mnt/sb-enema` no longer created. (Fixed) |

## Dependency Verification

- Build-time
  - [x] git/curl/tar (Makefile download flow)
  - [x] python3 + venv + pip (`prepare-secureboot-objects.sh`)
  - [x] rsync + sudo/loop mount (post-image staging)
  - [x] host `mkfs.fat` (dosfstools; required by post-image.sh to format the FAT32 data partition)
  - [x] host genimage/mtools/dosfstools (enabled in defconfig)
  - [x] secureboot_objects submodule (initialized by `secureboot-objects` target)
- Runtime (per defconfig + kernel fragment)
  - [x] efitools (`efi-updatevar`, `efi-readvar`, `cert-to-efi-sig-list`, `sign-efi-sig-list`)
  - [x] openssl (used throughout enrollment/audit)
  - [x] jq (preview/update parsing)
  - [x] blkid/mount + FAT32 kernel support (kernel fragment and util-linux dep)
  - [x] Data label `SB-ENEMA` mounted at `/mnt/data` (mount.sh)

## Path Consistency Check

| Path | Produced by | Consumed by | Notes |
| --- | --- | --- | --- |
| `/mnt/data` | post-image label `SB-ENEMA` + mount.sh | All runtime scripts | post-build.sh pre-creates `/mnt/data` in target rootfs. |
| `/mnt/data/sb-enema/payloads/microsoft/*.auth` | prepare-secureboot-objects → post-image | `msft_enroll` | Staged from secureboot_artifacts/Firmware `*.bin`. |
| `/mnt/data/PreSignedObjects` | prepare-secureboot-objects → post-image | `_msft_stage_target_certs`, `_custom_stage_target_certs`, dbx fallback | Holds Microsoft certs/templates/scripts. |
| `/mnt/data/secureboot_artifacts/Firmware/dbx.bin` | prepare-secureboot-objects → post-image | `_custom_build_dbx_payload` | Primary dbx ESL source; fallback to PreSignedObjects/DBX/DBX.bin. |
| `/mnt/data/sb-enema/payloads/{PK,KEK,db,dbx}.*` | Microsoft staging or `custom_create_payloads` | `update_compute`, `preview`, `efi-updatevar` | PAYLOAD_DIR in update.sh. |
| `/mnt/data/sb-enema/logs` | log_init (mkdir) | log.sh | Seed tree only provides `/logs`; runtime uses `/sb-enema/logs`. |

## Overall Assessment

The build pipeline now aligns across stages: secure boot objects are generated and staged into `output/secureboot-staging`, post-image copies them onto the FAT32 data partition, and the corrected init script launches `/usr/sbin/sb-enema`, which mounts `/mnt/data`, audits, stages payloads, previews deltas, and applies variables in the correct order. The Microsoft PK Recovery path consumes staged `.auth` files; Custom Owner Mode builds new payloads using staged Microsoft certificates and dbx. The rootfs pre-creates `/mnt/data` as the mount point, consistent with `mount_data_partition()`. With host tooling available and firmware in Setup Mode, the image should boot, auto-login as root, and run `sb-enema` to enroll Secure Boot variables successfully.
