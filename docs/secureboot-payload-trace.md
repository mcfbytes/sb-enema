# Secure Boot Payload Trace

## Flow Diagram (text)

- Microsoft PK Recovery path  
  `third_party/secureboot_objects` → `scripts/prepare-secureboot-objects.sh` (venv + `secure_boot_default_keys.py`) → `output/secureboot-staging/secureboot_artifacts/Firmware/{PK,KEK,DB,DBX}.bin` and `sb-enema/payloads/microsoft/{PK,KEK,db,dbx}.auth` → `post-image.sh` copies staging onto FAT32 data partition → runtime paths `/mnt/data/sb-enema/payloads/microsoft/*.auth` → `handle_microsoft_colonic()` calls `stage_microsoft_pk()` + `stage_microsoft_kek_db_dbx()` which stage certs from `/mnt/data/PreSignedObjects` into `/mnt/data/sb-enema/payloads/{PK,KEK,db,dbx}/` for preview → `enroll()` calls `efi-updatevar` writing db → dbx → KEK → PK.
- Custom Owner path  
  User runs `sb-enema` → `handle_full_colonic()` calls `keygen_generate_keys()` which writes `/mnt/data/sb-enema/keys/{PK,KEK}.{key,crt}` → `stage_user_pk_kek()` + `stage_microsoft_kek_db_dbx()` + `stage_sign_db()` build `/mnt/data/sb-enema/payloads/{PK,KEK,db,dbx}.auth`; db uses certs from `/mnt/data/PreSignedObjects/DB/Certificates`, dbx pulls `/mnt/data/secureboot_artifacts/Firmware/DBX.bin` via `_find_dbx_binary()` (fallback `/mnt/data/PreSignedObjects/DBX/DBX.bin`, then `/mnt/data/sb-enema/payloads/microsoft/dbx.auth`) → `enroll()` previews delta and calls `efi-updatevar` writing db → dbx → KEK → PK.
- Common assets  
  Source certificates from `secureboot_objects` land at `/mnt/data/PreSignedObjects` on the data partition. By default, the `data-seed/` tree seeds `README.txt`; additional files may also be present when pre-seeding keys or other assets. Runtime directories (`sb-enema/payloads/`, `sb-enema/keys/`, `sb-enema/logs/`) are otherwise created on first use.

## Issues Table

| Severity | Stage | File(s) | Issue | Suggested Fix |
| --- | --- | --- | --- | --- |
| Medium | CLI helper | scripts/provision.sh | Helper script pointed at removed `buildroot-config/.../sb-enema-provision.sh`, so local invocation failed. | Point to current `sb_enema/board/sb-enema/rootfs-overlay/usr/sbin/sb-enema`. (Fixed) |
| Medium | Build tooling | sb_enema/board/sb-enema/post-image.sh | Requires host `mkfs.fat` (dosfstools) to format the FAT32 data partition; build will stop if host lacks it. | Install `dosfstools` on host. |

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
| `/mnt/data/sb-enema/payloads/microsoft/*.auth` | prepare-secureboot-objects → post-image | `stage_microsoft_pk()`, `stage_microsoft_kek_db_dbx()` | Staged from secureboot_artifacts/Firmware `*.bin`. |
| `/mnt/data/PreSignedObjects` | prepare-secureboot-objects → post-image | `stage_microsoft_kek_db_dbx()`, `stage_user_kek_db()`, `_find_dbx_binary()` | Holds Microsoft source certificates. |
| `/mnt/data/secureboot_artifacts/Firmware/DBX.bin` | prepare-secureboot-objects → post-image | `_find_dbx_binary()` in `stage.sh` | Primary dbx ESL source; fallback to PreSignedObjects/DBX/DBX.bin then microsoft/dbx.auth. |
| `/mnt/data/sb-enema/payloads/{PK,KEK,db,dbx}.*` | `stage_*` functions or `stage_sign_*()`  | `update_compute()`, `preview_display()`, `enroll()` | PAYLOAD_DIR in common.sh; cleared by `stage_clear()`. |
| `/mnt/data/sb-enema/keys/{PK,KEK}.{key,crt}` | `keygen_generate_keys()` | `stage_user_pk_kek()`, `stage_sign_kek()`, `stage_sign_db()`, `_stage_build_dbx_payload()` | Created on first Full Colonic run; skipped if files already exist. |
| `/mnt/data/sb-enema/kek_update_map.json` | prepare-secureboot-objects (copies from `PostSignedObjects/KEK/`) | `_is_in_kek_update_map()` in `stage.sh` | Required for vendor cert filtering in `stage_bios_entries()`; warning emitted and step skipped if absent. |
| `/mnt/data/sb-enema/logs` | `log_init()` (mkdir on first run) | `log.sh` | Runtime creates this directory; no seed placeholder needed. |

## Overall Assessment

The build pipeline now aligns across stages: secure boot objects are generated and staged into `output/secureboot-staging`, post-image copies them onto the FAT32 data partition, and the corrected init script launches `/usr/sbin/sb-enema`, which mounts `/mnt/data`, audits, stages payloads, previews deltas, and applies variables in the correct order. The Microsoft PK Recovery path consumes staged `.auth` files; Custom Owner Mode builds new payloads using staged Microsoft certificates and dbx. The rootfs pre-creates `/mnt/data` as the mount point, consistent with `mount_data_partition()`. With host tooling available and firmware in Setup Mode, the image should boot, auto-login as root, and run `sb-enema` to enroll Secure Boot variables successfully.
