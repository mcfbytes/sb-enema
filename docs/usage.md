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

## Quick-action workflows

| Menu | CLI operation | What it does |
|------|---------------|--------------|
| **[2] Full Colonic** | `full-colonic` | Generate user PK/KEK → enroll Microsoft db/dbx under user KEK. Clean slate; OEM chain replaced. |
| **[3] Microsoft Colonic** | `microsoft-colonic` | Install Microsoft PK → KEK → db/dbx chain (untested on all firmware). |
| **[4] Microsoft Suppository** | `microsoft-suppository` | Keep existing PK; add missing Microsoft KEK/db/dbx. |
| **[9] Stage vendor default entries** | `stage-bios-entries` | Read `KEKDefault`/`dbDefault` EFI variables and stage recognized OEM vendor certs (see below). |

### Stage vendor default entries (`stage-bios-entries`)

Many systems wipe `KEK` and `db` before the tool runs. `KEKDefault` and `dbDefault` are read-only NVRAM variables that the firmware preserves as factory defaults. The **Stage vendor default entries** operation reads those variables and stages certificates that:

1. Have a SHA-1 fingerprint present in `kek_update_map.json` — the Microsoft OEM vendor PK → KEK update map from the `secureboot_objects` submodule. Only certs recognized by Microsoft as legitimate vendor PKs are staged.
2. Are **not** flagged as test/placeholder certificates in `known-certs/known-test-pks.txt`.
3. Are **not** known Microsoft-owned certs (handled separately by the Microsoft staging steps).

Matching `KEKDefault` certs are staged under `PAYLOAD_DIR/KEK/`; matching `dbDefault` certs are staged under `PAYLOAD_DIR/db/`. This step is available as a standalone advanced operation (menu option [9]) and is **not** run automatically by the Full Colonic workflow — combine it manually when you need to preserve recognized OEM entries alongside a user PK/KEK enrollment.

## Customization
- Provide your own PK/KEK keypairs by pre-placing `PK.key`, `PK.crt`, `KEK.key`, `KEK.crt` under `sb_enema/board/sb-enema/data-seed/sb-enema/keys/` before building, or directly on the USB’s `SB-ENEMA` partition at `sb-enema/keys/`. `keygen_generate_keys()` skips generation when the files already exist. See `data-seed/README.txt` for the complete partition layout.
- The Secure Boot payloads are generated from the certificates in the `third_party/secureboot_objects` submodule, driven by SB-ENEMA's own keystore template at `sb_enema/secureboot-templates/SbEnemaRecovery.toml`. That template deliberately lives outside `third_party/` so that a submodule bump cannot silently change which certificates get enrolled; it carries both the 2011 and 2023 certificate generations in `db` and `KEK`, and its header documents why each entry is there. Override with `KEYSTORE=/path/to/other.toml` (or `ARCH=...`) when running `scripts/prepare-secureboot-objects.sh` — for example to build against one of the stock Microsoft templates in `third_party/secureboot_objects/Templates/`.
  - Note that `scripts/check-secureboot-policy.py` runs as part of that script and will reject a key set whose `db` omits a compatibility-critical certificate, or whose `dbx` revokes a certificate that `db` depends on. If you intentionally build a narrower policy (e.g. `MicrosoftOnly`), expect that check to fail — that is the guard doing its job, not a bug.
- To regenerate payloads without a full Buildroot build, run `scripts/prepare-secureboot-objects.sh` directly.
- Adjust Buildroot defaults in `sb_enema/configs/sb_enema_defconfig`, and edit kernel/BusyBox fragments in `sb_enema/board/sb-enema/kernel-fragment.config` and `sb_enema/board/sb-enema/busybox-fragment.config`.
