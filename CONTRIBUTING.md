# Contributing

## Prerequisites

Build host dependencies:

- `curl`, `tar`, `git`
- `openssl`
- `mkfs.exfat` (from `exfatprogs`)
- `rsync`, `sudo`
- `python3-venv`

## Building locally

```sh
make images
```

The primary build artifact is `output/br-out/images/sb-enema.img`.

## Running ShellCheck locally

```sh
shellcheck -x \
  sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/*.sh \
  sb_enema/board/sb-enema/post-image.sh \
  sb_enema/board/sb-enema/rootfs-overlay/usr/sbin/sb-enema \
  scripts/*.sh
```

## Submitting changes

1. Fork the repository and create a branch off `master`.
2. Make your changes, ensure the CI build workflow passes, and run ShellCheck locally as described above.
3. Open a PR against `master`. PRs are merged only after the CI build passes.

## Code style

- Bash scripts must begin with `#!/usr/bin/env bash` and `set -euo pipefail`.
  - Some scripts (for example, Buildroot init scripts under `rootfs-overlay/etc/init.d/`) intentionally use `#!/bin/sh` and must remain POSIX-compliant.
- Use `local` for all function-scoped variables; names must be lowercase.
- Scripts must pass ShellCheck with no warnings (`shellcheck -x`).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
