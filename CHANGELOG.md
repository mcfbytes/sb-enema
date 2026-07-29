# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- Developed with extensive assistance from GitHub Copilot and generative AI. -->

## [Unreleased]

### Fixed

- **Certificate policy: stop dropping certificates that machines need in order
  to boot.** Both enrollment paths previously removed Microsoft certificates on
  the grounds that they expire in 2026. Both removals were wrong, because UEFI
  image verification never checks certificate validity dates (the spec's
  authorization process has no expiry step, and EDK II's `Pkcs7Verify()` passes
  `X509_V_FLAG_NO_CHECK_TIME`). Revocation is expressed through `dbx` alone.
  - `Microsoft Windows Production PCA 2011` is enrolled in `db` again. It signs
    the Windows Boot Manager on any installation that has not yet received
    Microsoft's 2023-signed boot manager — a staged rollout still incomplete as
    of mid-2026 — plus WinRE and pre-migration install media. Without it, a
    re-provisioned machine could no longer Secure-Boot the Windows install that
    was working before the tool ran. Affected the Microsoft path (via the
    `MicrosoftAndThirdParty` template) and the custom-PK path (via a
    fingerprint filter in `_stage_build_db_esl`).
  - `Microsoft Corporation KEK CA 2011` is enrolled in `KEK` again. Every
    Microsoft Secure Boot servicing package published to date is signed under
    it, not the 2023 KEK — verifiable from the PKCS#7 signer of
    `PostSignedObjects/DBX/*/DBXUpdate.bin` in the submodule. Excluding it left
    the machine unable to apply any existing Microsoft `dbx` revocation update.
    Affected the custom-PK path (`_stage_build_kek_esl`).
- **`audit.sh` reported the missing certificates as expected.** Absence of
  `Microsoft Windows Production PCA 2011` from `db` was logged as `INFO`
  ("expected absent in current provisioning"); it is now a `WARNING` naming the
  boot-failure consequence. A matching warning was added for a missing
  `Microsoft KEK CA 2011`. Neither is gated on whether the user runs their own
  KEK chain: a user-owned KEK lets the *user* sign db/dbx updates, but does
  nothing to make Microsoft's published, 2011-KEK-signed updates verify — so
  the warning matters most on exactly the custom-owned machines that earlier
  releases mis-provisioned.

### Added

- **SB-ENEMA keystore template**
  (`sb_enema/secureboot-templates/SbEnemaRecovery.toml`): the certificate set
  is now defined by a repo-owned template rather than one of the stock
  `secureboot_objects` templates, so a submodule bump cannot silently change
  enrollment policy. No stock template fits a recovery tool — the ones that
  keep `Windows Production PCA 2011` in `db` drop the 2011 KEK, and vice versa.
  Override with `KEYSTORE=` when running `prepare-secureboot-objects.sh`.
- **Build-time policy guard** (`scripts/check-secureboot-policy.py`): fails the
  build if the generated `db` or `KEK` omits a compatibility-critical
  certificate, or if the generated `dbx` revokes a certificate that `db`
  depends on. The latter is the brick condition — a `dbx` match beats a `db`
  match — and the db policy above is only safe while it holds, so it is now
  enforced instead of assumed. Revocation is detected both as a full
  `EFI_CERT_X509` entry and as an `EFI_CERT_X509_SHA{256,384,512}` hash of the
  TBSCertificate (the encoding firmware actually uses to revoke a CA), and any
  unrecognised `dbx` signature type is a failure rather than being ignored.
- **Keystore fingerprint verification** in `prepare-secureboot-objects.sh`:
  every certificate the template names is checked against the `sha1` the
  template records before generation. Microsoft's generator ignores those
  fields entirely, so without this they were decorative and "a submodule bump
  cannot silently change enrollment policy" held only for filenames, not
  contents. This immediately surfaced that every stock Microsoft template
  carries a stale hash for `dbx_info_msft_latest.json`.
- **Buildroot tarball is now SHA-256 verified** against the PGP-signed release
  manifest before extraction. Buildroot builds and verifies everything else in
  the image, so it was the one unpinned link in the chain. Verification writes
  to a temporary file and only promotes it on success, so a failed check cannot
  leave a poisoned tarball for a later run or a CI cache to reuse.
- **Certificate policy regression tests** (`scripts/test-cert-policy.sh`):
  asserts that both enrollment paths enroll every shipped Microsoft
  certificate, that the keystore template declares the expected sets, and that
  the policy guard accepts good and rejects bad key sets. The original
  exclusions were never covered by a test, which is why they survived.
- **CI now runs the shell test suite** (`unit-tests` job in `lint.yml`). The
  build workflow excludes `rootfs-overlay/**` via `paths-ignore`, so the
  `scripts/test-*.sh` suite previously never ran in CI at all.

### Changed

- **Buildroot 2026.02.3 → 2026.05.1.**
- **Kernel pinned to 6.18.40 longterm** via `BR2_LINUX_KERNEL_CUSTOM_VERSION`,
  replacing Buildroot's default (`BR2_LINUX_KERNEL_LATEST_VERSION`, which is
  7.0.11 in Buildroot 2026.05.1 and moves with every Buildroot bump). The
  tarball SHA-256 is pinned in `sb_enema/patches/linux/linux.hash`, with
  `sb_enema/patches/linux-headers/linux-headers.hash` symlinked to it because
  `linux-headers` downloads the same tarball. Because Buildroot exempts
  custom-pinned versions from hash checking by default, this also sets
  `BR2_DOWNLOAD_FORCE_CHECK_HASHES=y`; without it a version bump with a stale
  hash file would silently download an unverified tarball instead of failing.
  The pin also requires `BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_18=y`:
  Buildroot only derives the kernel-headers series from the version string when
  the *latest* version is selected, and its fallback default is 2.6 — which
  makes glibc unsatisfiable, so kconfig silently substitutes uClibc and the
  build dies thousands of lines later with a misleading headers mismatch.
  `scripts/test-defconfig.sh` now asserts the two stay in step.
- **Renovate** tracks the pinned kernel through a custom `kernel.org`
  datasource (constrained to 6.18.x) and the Buildroot 2026.05 series.
- **GitHub Actions runners moved to `ubuntu-26.04`** across all workflows.
  Note that this image is still in public preview on GitHub-hosted runners.
  It also ships uutils coreutils as the default `install`, which Buildroot
  refuses to build against ([uutils/coreutils#12166](https://github.com/uutils/coreutils/issues/12166)),
  so the build and release workflows now switch `install` to the GNU
  implementation first. Documented in `docs/usage.md` for local builds, which
  hit the same wall on any uutils-based distribution.

### Added

- **Audit engine** (`audit.sh`): detects test/invalid PKs, validates certificate
  expiry, checks 2026 db/dbx readiness, and classifies the current ownership
  model (vendor, Microsoft, custom, or test).
- **Health report** (`report.sh`): severity-graded, color-coded per-variable
  status display with per-certificate fingerprint details.
- **Custom Owner Mode enrollment** (`enroll-custom.sh`): generates a fresh
  PK/KEK pair, stores private keys on the exFAT partition, and enrolls
  Microsoft's db/dbx under the new KEK.
- **Microsoft PK Recovery Mode** (`enroll-microsoft.sh`): installs the full
  Microsoft PK → KEK → db/dbx chain using pre-built, Microsoft-supplied
  `.auth` payloads.
- **Change preview** (`preview.sh`): shows an ADD/REMOVE/KEEP diff per EFI
  variable and requires explicit confirmation before any write.
- **Delta computation** (`update.sh`): computes per-variable cert-level deltas
  (ADD/REMOVE/KEEP arrays) against the current EFI variable state.
- **Structured audit log** (`log.sh`): pipe-delimited, timestamped action log
  written to `${DATA_MOUNT}/sb-enema/logs/`.
- **EFI variable reader** (`efivar.sh`): thin wrapper around `efi-readvar` for
  listing and extracting Secure Boot EFI variables.
- **Certificate fingerprint database** (`certdb.sh`, `known-certs/`): maps
  fingerprints to human-readable vendor/cert names for audit output.
- **Safety checks** (`safety.sh`): Setup Mode assertion, battery check, and
  payload integrity verification before any PK write.
- **Interactive menu and CLI mode** (`/usr/sbin/sb-enema`): 6-option menu plus
  positional `OPERATION` argument (e.g., `sb-enema report|custom|microsoft|...`)
  for scripted use; both paths share the same operation functions.
- **Buildroot external tree** (`sb_enema/`): minimal x86_64 Linux image with
  `efitools`, hybrid GPT image (FAT32 EFI + exFAT data partition).
- **Build-time payload staging** (`scripts/`): `prepare-secureboot-objects.sh`
  copies Microsoft `.auth` payloads into the image; `post-image.sh` rsyncs
  the data partition.

> This is the initial release. All features listed above are new.
> Development made extensive use of GitHub Copilot and generative AI.

### Changed

- **`stage_bios_entries()`** now reads from `KEKDefault` and `dbDefault` EFI
  variables instead of the live `KEK` and `db` variables. Since users may have
  wiped `KEK`/`db` prior to running the tool, the firmware-preserved default
  variables provide a reliable source of factory OEM certificates.
  Inclusion criteria are now explicit: only certs whose SHA-1 fingerprint
  appears as a key in `kek_update_map.json` (the Microsoft OEM vendor PK → KEK
  update map from the `secureboot_objects` submodule) are staged; known
  test/placeholder certificates (`known-test-pks.txt`) and known
  Microsoft-owned certs are excluded. Renamed from "Stage BIOS entries" to
  "Stage vendor default entries" in menus and CLI help.
- **Full Colonic** workflow (`handle_full_colonic`) no longer calls
  `stage_bios_entries()`. Vendor default entry staging is now an explicit
  advanced step (menu option [9] / `stage-bios-entries` CLI) that users invoke
  when they want to preserve recognized OEM certs alongside a user PK/KEK
  enrollment.
- **`prepare-secureboot-objects.sh`** now copies
  `PostSignedObjects/KEK/kek_update_map.json` from the `secureboot_objects`
  submodule to `output/secureboot-staging/sb-enema/kek_update_map.json`, making
  it available on the data partition at `/mnt/data/sb-enema/kek_update_map.json`
  for runtime use by `stage_bios_entries()`.
- **`efivar.sh`** `_efivar_guid_for()` now recognises `KEKDefault`
  (EFI_GLOBAL_GUID) and `dbDefault` (EFI_IMAGE_SECURITY_GUID).

### Fixed

### Security

[Unreleased]: https://github.com/mcfbytes/sb-enema/commits/HEAD
