# Building and using the SB-ENEMA USB image

## Prerequisites
- Host tools: `curl`, `openssl`, `mkfs.fat` (from `dosfstools`), `tar`, `rsync`, `sudo`, `python3-venv`, `git` with submodule support (GitHub Actions workflows install these automatically).

## Build steps
```sh
# Build the image (fetches secureboot_objects submodule, prepares Secure Boot payloads, downloads Buildroot)
make images
```

Artifacts are written to `output/br-out/images/`, including `sb-enema.img` (hybrid disk image), `bzImage`, and `rootfs.cpio.gz`.

## USB provisioning workflow
1. Write `sb-enema.img` to a USB stick (e.g., `sudo dd if=sb-enema.img of=/dev/sdX bs=4M status=progress`).
2. Boot a target machine in **Setup Mode** with UEFI Secure Boot enabled.
3. The image automatically logs in as root and runs `sb-enema`. The init script mounts the `SB-ENEMA` FAT32 data partition at `/mnt/data` before the tool starts.
4. Logs are saved to `/mnt/data/sb-enema/logs/sb-enema-<timestamp>.log`. Re-running is safe and idempotent; PK replacement is refused unless Setup Mode is detected.

## Customization
- Provide your own PK/KEK/db/dbx certs by placing files in the corresponding directories under `buildroot-config/board/sb-enema/exfat-seed/` before building (or directly on the USB’s `SB-ENEMA` partition). If `secureboot_objects` artifacts are present they take precedence.
- The Secure Boot payloads are generated from the `third_party/secureboot_objects` submodule (template defaults to `MicrosoftAndThirdParty`). Adjust `TEMPLATE_NAME` or `ARCH` when running `scripts/prepare-secureboot-objects.sh` to use a different template/architecture.
- To regenerate payloads without a full Buildroot build, run `scripts/prepare-secureboot-objects.sh` directly.
- Adjust kernel/BusyBox options via the fragment files in `buildroot-config/board/sb-enema/`.
