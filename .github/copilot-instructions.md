# Copilot Instructions for SB-ENEMA

- Buildroot wrapper is `Makefile`; keep all customizations in the external tree `sb_enema/` (configs, packages, overlays). Do not patch upstream Buildroot.
- Configs: use fragments, keep defconfig minimal, and save changes with `make -C output/buildroot-* O=../br-out BR2_EXTERNAL=$(pwd)/sb_enema savedefconfig BR2_DEFCONFIG=../../sb_enema/configs/sb_enema_defconfig`.
- Packages: add `sb_enema/package/<name>/{Config.in,<name>.mk}`, source from `sb_enema/Config.in`, include via `external.mk`; declare deps; use `$(eval $(generic-package))`/`$(eval $(autotools-package))`; prefer host tools.
- Build targets: `make BR2_EXTERNAL=$(pwd)/sb_enema images`; use `clean`/`mrproper` to reset outputs; `secureboot-objects` regenerates payloads; `defconfig` reconfigures.
- Secure Boot: at build time, payloads stage under `output/secureboot-staging/sb-enema/payloads/`, then are copied to the data partition and accessed at runtime via `${DATA_MOUNT}/sb-enema/payloads/` (e.g. `/mnt/data/sb-enema/payloads/`); runtime scripts live in `sb_enema/board/sb-enema/rootfs-overlay/usr/sbin/`; use `safety_preflight`/Setup Mode checks before PK writes and stage per-variable payload dirs for preview/update.
- Conventions: shell scripts start with `#!/usr/bin/env bash` + `set -euo pipefail`, quote vars, lowercase locals; Makefiles use `$(CURDIR)`, `.PHONY`, and `?=` defaults.
- Testing: primary artifact `output/br-out/images/sb-enema.img`; validate via QEMU + OVMF or hardware in Setup Mode.
- Pitfalls: set `BR2_EXTERNAL=$(pwd)/sb_enema`, ensure `sb_enema/Config.in` sources new packages, and run `git submodule update --init --recursive` for Microsoft objects.
