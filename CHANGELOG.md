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

### Fixed

### Security

[Unreleased]: https://github.com/mcfbytes/sb-enema/commits/HEAD
