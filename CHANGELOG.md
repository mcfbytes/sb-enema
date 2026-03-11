# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- Developed with extensive assistance from GitHub Copilot and generative AI. -->

## [Unreleased]

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
