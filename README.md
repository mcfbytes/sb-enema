# SB-ENEMA 💊

[![build](https://github.com/mcfbytes/sb-enema/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/mcfbytes/sb-enema/actions/workflows/ci.yml)
[![Codacy](https://github.com/mcfbytes/sb-enema/actions/workflows/codacy.yml/badge.svg?branch=master)](https://github.com/mcfbytes/sb-enema/actions/workflows/codacy.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/b490731d43e54cc0bc0973308611cbab)](https://app.codacy.com/gh/mcfbytes/sb-enema/dashboard)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/mcfbytes/sb-enema/badge)](https://scorecard.dev/viewer/?uri=github.com/mcfbytes/sb-enema)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**S**ecure **B**oot **E**mergency **N**uclear-option for **E**xasperated **M**otherboard **A**dministrators

Because sometimes your UEFI needs a deep cleaning. ¯\\\_(ツ)\_/¯

## What Is This?

A bootable USB image that audits, repairs, and re-provisions your UEFI Secure Boot variables (PK, KEK, db, dbx) when your vendor can't be bothered to ship firmware updates. Flash it, boot it, get on with your life.

**TL;DR:** Your motherboard vendor abandoned you. This is your revenge.

## Contents

- [What Is This?](#what-is-this)
- [Supported Scenarios](#supported-scenarios)
- [Warnings and Safety Notes](#️-warnings-and-safety-notes)
- [Secure Boot Ownership Models](#secure-boot-ownership-models)
  - [Vendor-Owned](#vendor-owned-the-default-for-consumer-boards)
  - [Microsoft-Owned](#microsoft-owned-surface-enterprise-whcp)
  - [Custom-Owned](#custom-owned-enthusiasts-security-nerds)
- [Microsoft 2026 Certificate Expiration](#microsoft-2026-certificate-expiration)
  - [The short version](#the-short-version)
  - ["But UEFI firmware doesn't check expiration dates!"](#but-uefi-firmware-doesnt-check-expiration-dates)
  - [Other side-effects of letting the chain rot](#other-side-effects-of-letting-the-chain-rot)
  - [Distributions and vendors moving to the 2023 chain](#distributions-and-vendors-moving-to-the-2023-chain)
  - [Should you actually do anything?](#should-you-actually-do-anything)
- [BitLocker, TPM, and Why This Matters](#bitlocker-tpm-and-why-this-matters)
- [Recovery and Fallback Options](#recovery-and-fallback-options)
- [1.0 Feature Set](#10-feature-set)
- [Image Size](#image-size)
- [Quick Start](#quick-start)
- [Flashing](#flashing)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Supported Scenarios

| Scenario | What SB-ENEMA Does |
|---|---|
| Vendor shipped a test PK | Will detect it, warn you, and offer replacement |
| Vendor never updated db/dbx | Will install current Microsoft db/dbx |
| You want full Secure Boot ownership | Will generate your own PK/KEK and enroll Microsoft db/dbx |
| You need a known-good Secure Boot chain | Will offer a Microsoft PK recovery mode |
| You just want to know if you're 2026-ready | Will run a health check and tell you |
| You wiped KEK/db and want vendor certs back | Will stage recognized OEM certs from KEKDefault/dbDefault |
| Windows user who can't boot a Linux USB | `SecureBootChecker.ps1` runs a full audit from a PowerShell prompt |

## ⚠️ Warnings and Safety Notes

Read this before doing anything. Seriously.

- **Changing PK/KEK/db/dbx _[will*](#bitlocker-tpm-and-why-this-matters)_ trigger BitLocker recovery.** Back up your BitLocker recovery key first. If you don't have it, stop here and go find it.
- **Credential Guard / VBS** may temporarily disable until the next reboot + re-attestation. This is expected.
- **OEM Secure Boot functionality** (vendor-specific features, OEM recovery partitions signed with vendor keys) may break unless you preserve the OEM KEK/db entries. Enthusiast motherboards almost never rely on these.
- **All changes are reversible** via your BIOS "Restore Factory Keys" option. If anything goes sideways, that's your escape hatch.
- Switching platform ownership is a deliberate, conscious action. The tool will preview exactly what will change before applying anything.

## Secure Boot Ownership Models

There are three Secure Boot ownership models you'll encounter in the wild. Understanding which one your system uses—and which one you *want*—is the whole point of this tool.

### Vendor-Owned (the default for consumer boards)

```mermaid
flowchart LR
   subgraph SB["Secure Boot Variables (Vendor-owned state)"]
      PK["OEM Platform Key (PK)"]

      subgraph KEK["KEK Certificates"]
         direction RL

         KEK1[OEM KEK Cert]
         KEK2[Microsoft Corporation KEK CA 2011]
         KEK3[Microsoft Corporation KEK 2K CA 2023]
      end

      subgraph DB["DB Certificates"]
         direction RL

         DB1[OEM DB Cert]
         DB2[Microsoft Corporation UEFI CA 2011]
         DB4[Windows UEFI CA 2023]
         DB5[Microsoft UEFI CA 2023]
         DB6[Microsoft Option ROM UEFI CA 2023]
      end

      subgraph DBX["DBX Hashes"]
         DBX1[Disallowed DBX]
      end
   end

   PK -->|authorizes| KEK
   KEK -->|authorizes| DB
   KEK -->|authorizes| DBX

   subgraph BL[Bootloader]
      OS[Windows Bootloader]
      SHIM[MS shim Bootloader]
      BAD[Revoked binaries]
   end

   DB -->|signs, allows| BL
   DBX -->|blocks| BAD
```


This is what ships on most consumer motherboards. The vendor controls the Platform Key. Microsoft's KEK is included so Windows and WHQL drivers work. In theory, the vendor updates db/dbx via firmware updates. In practice... well, you're here.

### Microsoft-Owned (Surface, enterprise, WHCP)

```mermaid
flowchart LR
   subgraph SB["Secure Boot Variables (Microsoft-owned state)"]
      PK["Windows OEM Devices PK"]

      subgraph KEK["KEK Certificates"]
         direction RL

         KEK3[Microsoft Corporation KEK 2K CA 2023]
      end

      subgraph DB["DB Certificates"]
         direction RL

         DB2[Microsoft Corporation UEFI CA 2011]
         DB4[Windows UEFI CA 2023]
         DB5[Microsoft UEFI CA 2023]
         DB6[Microsoft Option ROM UEFI CA 2023]
      end

      subgraph DBX["DBX Hashes"]
         DBX1[Disallowed DBX]
      end
   end

   PK -->|authorizes| KEK
   KEK -->|authorizes| DB
   KEK -->|authorizes| DBX

   subgraph BL[Bootloader]
      OS[Windows Bootloader]
      SHIM[MS shim Bootloader]
      BAD[Revoked binaries]
   end

   DB -->|signs, allows| BL
   DBX -->|blocks| BAD
```

Used on Surface devices, Windows RT, WHCP test devices, and enterprise-managed hardware. Microsoft controls the whole chain. You probably don't have this unless you bought your machine from Microsoft or your IT department set it up.

### Custom-Owned (enthusiasts, security nerds)

```mermaid
flowchart LR
   subgraph SB["Secure Boot Variables (User-owned state)"]
      PK["User-generated Platform Key (PK)"]

      subgraph KEK["KEK Certificates"]
         direction RL

         KEK1[User-generated KEK]
         KEK3[Microsoft Corporation KEK 2K CA 2023]
      end

      subgraph DB["DB Certificates"]
         direction RL

         DB1[User-generated Cert]
         DB2[Microsoft Corporation UEFI CA 2011]
         DB4[Windows UEFI CA 2023]
         DB5[Microsoft UEFI CA 2023]
         DB6[Microsoft Option ROM UEFI CA 2023]
      end

      subgraph DBX["DBX Hashes"]
         DBX1[Disallowed DBX]
      end
   end

   PK -->|authorizes| KEK
   KEK -->|authorizes| DB
   KEK -->|authorizes| DBX

   subgraph BL[Bootloader]
      OS[Windows Bootloader]
      SHIM[MS shim Bootloader]
      BAD[Revoked binaries]
   end

   DB -->|signs, allows| BL
   DBX -->|blocks| BAD
```

You control the PK and KEK. Microsoft's db/dbx entries are enrolled under your KEK so Windows, WHQL drivers, and the UEFI shim bootloader still work. This gives you deterministic control over what boots on your hardware.

> **Important:** The PK private key is never stored on the target device—only in the EFI variables as a public certificate. If you generate a PK with this tool, the private key is saved to the FAT32 data partition on the USB drive. **Back it up.** If you lose it and need to modify your Secure Boot variables later, you'll need to re-enter Setup Mode and re-provision.

## Microsoft 2026 Certificate Expiration

This is the entire reason SB-ENEMA exists. If you take nothing else away from this README, take this section.

### The short version

The original Microsoft UEFI Secure Boot certificates—issued in 2011 and trusted by virtually every Secure Boot–capable PC ever shipped—begin expiring in **June 2026**. Microsoft has issued replacement certificates dated 2023, and the entire ecosystem (Microsoft, Linux distributions, OEMs, IHVs) is in the middle of a multi-year migration.

The expiring 2011 certificates are:

| Certificate | Variable | Role | Expires |
|---|---|---|---|
| Microsoft Corporation KEK CA 2011 | KEK | Authorizes db/dbx updates from Microsoft | June 2026 |
| Microsoft Windows Production PCA 2011 | db | Signs the Windows bootloader | October 2026 |
| Microsoft Corporation UEFI CA 2011 | db | Signs third-party bootloaders (Linux `shim`, option ROMs) | June 2026 |

The replacement 2023 certificates already published by Microsoft are:

| Certificate | Variable | Replaces |
|---|---|---|
| Microsoft Corporation KEK 2K CA 2023 | KEK | KEK CA 2011 |
| Windows UEFI CA 2023 | db | Windows Production PCA 2011 |
| Microsoft UEFI CA 2023 | db | UEFI CA 2011 (third-party / shim) |
| Microsoft Option ROM UEFI CA 2023 | db | (new — dedicated CA for option ROMs) |

Microsoft's authoritative references:

- **Landing page:** [aka.ms/GetSecureBoot](https://aka.ms/GetSecureBoot) — central index of all Microsoft Secure Boot 2026 resources.
- [Act now: Secure Boot certificates expire in June 2026](https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856) (Windows IT Pro Blog)
- [Secure Boot playbook for certificates expiring in 2026](https://techcommunity.microsoft.com/blog/windows-itpro-blog/secure-boot-playbook-for-certificates-expiring-in-2026/4469235) (deployment playbook)
- [Windows Server Secure Boot playbook for certificates expiring in 2026](https://techcommunity.microsoft.com/blog/windowsservernewsandbestpractices/windows-server-secure-boot-playbook-for-certificates-expiring-in-2026/4495789)
- [Windows Secure Boot certificate expiration and CA updates (KB5062710)](https://support.microsoft.com/en-us/topic/windows-secure-boot-certificate-expiration-and-ca-updates-7ff40d33-95dc-4c3c-8725-a9b95457578e) — deep dive into the mechanics
- [Secure Boot Certificate updates: Guidance for IT professionals and organizations (KB5062713)](https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f)
- [When Secure Boot certificates expire on Windows devices (KB5079373)](https://support.microsoft.com/en-us/topic/when-secure-boot-certificates-expire-on-windows-devices-c83b6afd-a2b6-43c6-938e-57046c80c1c2) — end-user FAQ
- [Refreshing the root of trust: industry collaboration on Secure Boot certificate updates](https://blogs.windows.com/windowsexperience/2026/02/10/refreshing-the-root-of-trust-industry-collaboration-on-secure-boot-certificate-updates/) (Windows Experience Blog)

### "But UEFI firmware doesn't check expiration dates!"

True. Mostly. And it does not save you.

The UEFI specification (§32, Image Authentication) does **not** require firmware to verify the `notBefore` / `notAfter` fields of certificates in `db` or `KEK` when authenticating a PE image at boot time. In practice, every mainstream UEFI implementation—AMI Aptio, Insyde H2O, Phoenix SCT, EDK II / OVMF—ignores X.509 validity periods during boot-time signature verification. An expired CA certificate sitting in `db` will continue to validate signatures on already-signed bootloaders forever.

This is the source of a popular misconception: *"the certs expire but nothing breaks, so why bother?"*

What that argument misses is that boot-time PE verification is only **one** of several places certificates matter. The Secure Boot trust chain breaks in five other places long before any firmware ever attempts a date check:

1. **New signatures stop chaining to a CA your firmware trusts.** The day Microsoft starts signing Windows boot components (`bootmgfw.efi`, `bootmgr.efi`, the kernel, WHQL drivers, option ROMs) exclusively with the 2023 certificates, any system whose `db` contains only the 2011 certificates has no trust path for those new binaries. Boot-time PE verification doesn't care about a CA's *date*—but it absolutely cares whether the leaf signature chains to a CA that is actually present in `db`. If the issuing CA isn't in `db`, the signature is rejected. Expiration is irrelevant; *presence* is everything.

2. **`dbx` (revocation) updates stop being authenticated.** `dbx` is an authenticated EFI variable: updates must be signed by a key chaining to the **KEK**. Once Microsoft stops dual-signing `dbx` payloads with the 2011 KEK, any `dbx` update signed only with the 2023 KEK will be rejected by firmware that lacks the 2023 KEK. Your revocation list freezes in time. Every subsequent vulnerable bootloader—BlackLotus-class threats, leaked OEM keys, CVE-2023-24932 follow-ons, future shim/GRUB CVEs—remains bootable on your machine forever, even after Microsoft and the Linux distros have revoked it for everyone else.

3. **Linux `shim` updates stop verifying.** The `shim` first-stage bootloader used by every Microsoft-signed Linux distribution (Ubuntu, Fedora, Debian, openSUSE, RHEL, SLES, Arch via `shim-signed`, and dozens of derivatives) is signed today by the **Microsoft Corporation UEFI CA 2011**, and going forward by the **Microsoft UEFI CA 2023**. Once distributions ship shims signed *only* by the 2023 CA, those shims will fail Secure Boot verification on firmware that doesn't trust the 2023 CA. Your Linux installer USB will refuse to boot. Your existing Linux install will refuse to boot after a routine `shim` package update.

4. **Option ROM verification fails on new hardware.** New GPUs, NICs, NVMe controllers, RAID HBAs, and other add-in cards ship with option ROMs signed under the new **Microsoft Option ROM UEFI CA 2023**. On a machine with only 2011 certificates in `db`, those option ROMs fail Secure Boot verification. Depending on firmware policy this either silently disables the device, drops to a verification-failure prompt, or—on poorly implemented firmware—hangs the boot.

5. **Windows feature updates and servicing.** Microsoft has stated that Windows updates will, at points during the rollout, refuse to install on systems that have not received the 2023 certificates in `db`/`KEK`. Even before any hard cutoff, individual cumulative updates that replace `bootmgr` with a 2023-signed version can brick the system on next boot if the firmware can't validate the new signature.

So: yes, your existing Windows install keeps booting. For now. Right up until the first Patch Tuesday that ships a 2023-signed `bootmgr` and your firmware shrugs at it.

### Other side-effects of letting the chain rot

- **No protection from newly-discovered vulnerable bootloaders.** Without authenticated `dbx` updates, every published shim/GRUB/bootloader CVE after your last `dbx` is a Secure Boot bypass on your machine. The whole point of Secure Boot is the revocation database; a frozen `dbx` is a defanged Secure Boot.
- **Windows recovery and installation media stops working.** Microsoft Windows installation/recovery media built after the 2023 transition is signed with the 2023 chain. Boot it on a 2011-only system with Secure Boot enabled and you get `Security Violation` / `Image failed to authenticate` and the installer never starts. You either disable Secure Boot to recover (defeating the point) or you can't recover at all.
- **WHQL driver loading at boot.** Storage and network drivers loaded during the early UEFI/boot phase that are WHQL-signed under the 2023 chain will fail to load—potentially leaving the system unable to see its own boot disk.
- **BitLocker recovery, repeatedly.** Firmware updates that retroactively add the 2023 certs (the path most OEMs are taking) change PCR 7 and trigger BitLocker recovery prompts. Doing the migration deliberately, once, on your terms, is strictly better than getting surprised by it later.
- **Cross-signed binaries are a temporary bridge, not a fix.** Microsoft is currently dual-signing some artifacts (signed by both 2011 and 2023 CAs). This is a transition aid only. Once dual-signing ends, single-signed 2023 artifacts will not verify against a 2011-only `db`.
- **Loss of Measured Boot / attestation integrity.** Remote attestation services (Azure Attestation, Intune compliance, enterprise NAC) increasingly require evidence that the device is on the 2023 trust chain. Stale firmware fails attestation policies even when the box still boots locally.

### Distributions and vendors moving to the 2023 chain

This is a snapshot of the public migration state at the time of writing. It changes constantly; treat this as "these projects have publicly committed and started shipping," not as a complete or current list.

- **Microsoft Windows 11 24H2 and later** — ships the 2023 CAs to firmware via Windows Update, gated and rolled out in waves. Opt-in on managed devices via the `MicrosoftUpdateManagedOptIn` registry value documented in KB5062713.
- **Windows Server 2025** — covered by the dedicated Windows Server Secure Boot playbook; same 2023 chain.
- **Fedora** — Fedora 42+ ships `shim` signed by Microsoft UEFI CA 2023; the Fedora `shim-review` requests have been updated and merged.
- **Ubuntu** — Canonical has published 2023-CA signed shims for 24.04 LTS and later, documented in their Secure Boot policy updates.
- **Debian** — Debian 13 ("trixie") ships a 2023-CA signed shim alongside the 2011-signed one during the transition.
- **openSUSE / SUSE Linux Enterprise** — SLES 15 SP6, Leap 15.6, and Tumbleweed have shipped shims signed under the 2023 chain.
- **Red Hat Enterprise Linux** — RHEL 9.5+ and RHEL 10 ship 2023-CA signed shims.
- **Arch Linux** (via `shim-signed`) — tracks upstream shim builds dual-signed under the new chain.
- **Major OEMs** — Dell, HP, Lenovo, ASUS, MSI, Gigabyte, ASRock, Supermicro, and Framework have all published firmware updates that add the 2023 KEK and db entries to their default key databases (`KEKDefault` / `dbDefault`). Whether you have actually *received* one of those updates is a separate question, which is the entire premise of this tool.

### Should you actually do anything?

If your machine boots Windows or Linux from a 2011-signed bootloader today, and you never install OS updates, never plug in new hardware, never expect to apply a `dbx` revocation again, and never need to boot recovery media—then technically nothing breaks the moment June 2026 rolls around. Your existing signed binaries continue to verify against your existing (now-expired) CAs in `db`, because firmware doesn't enforce expiration dates. The "expiration is symbolic" crowd is, in that narrow sense, correct.

For everyone else—anyone who runs Windows Update, anyone who upgrades their Linux distribution, anyone who buys a new GPU or NVMe drive, anyone who relies on `dbx` for actual protection against bootkits, anyone who needs working recovery media—the 2023 certificates need to be present in your firmware **before** the 2011 ones become operationally useless. Either your motherboard vendor ships a firmware update that does it for you, or you do it yourself.

That is what SB-ENEMA is for.

## BitLocker, TPM, and Why This Matters

This tool modifies Secure Boot variables (PK/KEK/DB/DBX). These changes may alter TPM PCR measurements, especially PCR 7 (Secure Boot policy), PCR 4 (boot manager), and PCR 0 (firmware). BitLocker protects its volume master key by sealing it to a specific PCR profile.

When the final PCR values differ from the values BitLocker previously sealed against, Windows may require a BitLocker recovery key on the next boot.

However, not all Secure Boot variable changes produce new PCR measurements. Many UEFI implementations measure only the effective Secure Boot state (e.g., SecureBootEnabled, SetupMode) rather than the raw contents of PK/KEK/DB. If the system returns to the same effective Secure Boot state after the change, the resulting PCR values may match the previous ones, and BitLocker will not prompt for recovery.

Additionally, once Windows completes a successful boot after a Secure Boot change, it may automatically re‑seal the BitLocker key to the new PCR profile. Subsequent reboots will then proceed without a recovery prompt.

In short: Secure Boot variable changes can trigger BitLocker recovery, but whether they do depends on the firmware’s PCR measurement behavior and whether Windows has already re‑sealed the TPM key.

**What to expect:**

1. You change PK/KEK/db/dbx (or update firmware—same effect).
2. On next Windows boot, BitLocker prompts for your recovery key.
3. You enter the recovery key. BitLocker re-seals to the new PCR values.
4. Subsequent boots work normally.
5. Credential Guard / VBS may show as disabled until Windows re-attests the new Secure Boot state. A reboot or two fixes this.

This is correct, expected behavior. Microsoft designed it this way. Don't panic.

## Recovery and Fallback Options

Things went wrong, or you changed your mind. Here are your options, from easiest to most drastic.

### A. Restore Factory Keys (OEM Defaults)

- Available in every UEFI BIOS under the Secure Boot settings.
- Restores the vendor's original PK/KEK/db/dbx.
- Use this if OEM tools, OEM recovery partitions, or firmware updates require vendor-specific keys.
- This is the "undo" button. It always works.

### B. Custom Secure Boot Ownership — "Full Colonic" (Recommended for Enthusiasts)

- Generates your own PK and KEK and enrolls Microsoft's db/dbx for Windows compatibility.
- The SB-ENEMA boot volume itself is re-signed with your new DB key so it can boot under Secure Boot on the next power-on.
- OEM-specific Secure Boot features may not work—but if you're building your own rigs, you almost certainly don't use them.
- The tool generates a fresh PK/KEK/DB key pair and stores the private keys on the USB drive. Back them up.

### C. Microsoft PK Recovery Mode — "Microsoft Colonic"

- Switches to: Microsoft PK → Microsoft KEK → Microsoft db/dbx.
- Produces a fully valid, standards-compliant Secure Boot chain.
- OEM-specific Secure Boot features may break (same as option B).
- BIOS firmware updates still work—they use a separate firmware-update signing key, not the Secure Boot chain.
- Reversible by restoring factory keys.
- Use this when the vendor PK is invalid, expired, or a known test key, and you don't want to manage your own keys.

### D. Add Missing Microsoft Entries — "Microsoft Suppository"

- Keeps your current PK. Adds missing Microsoft KEK/db/dbx to the firmware.
- Use this when your system already has a valid PK but is missing current Microsoft 2023 CA certificates or an up-to-date revocation list.

> ⚠️ Switching platform ownership is a deliberate action. The tool will show you exactly what it plans to do and ask for confirmation.

## 1.0 Feature Set

See [ROADMAP.md](ROADMAP.md) for the full breakdown. The short version:

- Detect invalid or test PKs
- Compare PK/KEK/db against known vendor defaults
- Validate whether the Secure Boot chain is 2026-ready
- Extract and display current Secure Boot configuration
- Warn when the vendor hasn't shipped updated firmware
- Help take ownership with custom PK/KEK/db
- Install Microsoft's db/dbx under your own KEK
- Secure Boot health report
- "What will change?" preview before applying anything
- Microsoft PK Recovery Mode with appropriate warnings
- Custom Owner Mode with deterministic PK/KEK/db generation
- "Restore OEM Defaults" reminder and instructions
- Stage recognized vendor OEM certs from firmware-preserved `KEKDefault`/`dbDefault` variables
- Self-sign the SB-ENEMA `BOOTX64.EFI` with your new DB key after Custom Owner Mode enrollment
- Windows Secure Boot health checker (`SecureBootChecker.ps1`) — no Linux required
- Audit firmware-preserved default variables (`PKDefault`, `KEKDefault`, `dbDefault`, `dbxDefault`) for 2026 readiness and regression risk

## Image Size

The raw `sb-enema.img` is ~140 MiB, yet it compresses to ~20 MiB. This is normal and intentional.

GPT disk images have fixed-size partitions. Both the EFI System Partition and the data partition are pre-allocated to a known size so that `dd` and Rufus can write the image directly to any USB stick without resizing. Unused space within each partition is zero-filled, which compresses extremely well.

| Partition | Raw size | Typical content |
|---|---|---|
| EFI System (`boot.vfat`) | 100 MiB | `BOOTX64.EFI` (kernel, ~12 MiB) + `rootfs.cpio.gz` (~15 MiB) |
| Data (`SB-ENEMA`) | 32 MiB | Secureboot payloads, generated keys, logs |

**Override partition sizes at build time:**

```sh
# Larger data partition (e.g. 128 MiB)
DATA_SIZE=128M make dist
```

**Produce a compressed image for distribution (ZIP – Windows-friendly):**

```sh
make dist
# Output: dist/sb-enema.zip  (~20 MiB, ZIP – extract and flash sb-enema.img)
# The raw .img is still usable directly with dd or Rufus.
```

## Quick Start

```sh
# Clone with submodules (the Microsoft certs live there)
git clone --recursive https://github.com/mcfbytes/sb-enema.git
cd sb-enema

# Build (requires: curl, openssl, mkfs.fat, rsync, sudo, python3-venv)
make dist

# Output lands in dist/sb-enema.img
```

## Flashing

**Rufus (Windows):**
1. Select `sb-enema.img`
2. Partition scheme: GPT
3. Target system: UEFI (non-CSM)
4. Start, wait, done

**dd (Linux/macOS):**
```sh
sudo dd if=output/br-out/images/sb-enema.img of=/dev/sdX bs=4M status=progress && sync
```

## Usage

1. **Back up your BitLocker recovery key.** (Settings → Update & Security → Device encryption, or `manage-bde -protectors -get C:`, or check your Microsoft account.)
2. Put target machine into UEFI **Setup Mode** (Secure Boot settings → "Clear Keys" / "Reset to Setup Mode").
3. Boot from the USB.
4. Follow the on-screen prompts. Review the "What will change?" summary.
5. Reboot into your now-secured system.
6. Enter your BitLocker recovery key when prompted. It re-seals automatically.
7. Send a polite email to your vendor asking why *you* had to do this.

## Project Structure

```
├── Makefile                    # Wrapper for Buildroot build
├── SecureBootChecker.ps1       # Windows-native Secure Boot health checker
├── sb_enema/                   # Buildroot external tree (configs, overlays, packages)
│   ├── configs/                # Buildroot defconfig (minimal x86_64 Linux)
│   ├── package/                # Custom packages (efitools, sbsigntools)
│   └── board/sb-enema/
│       └── rootfs-overlay/usr/
│           ├── sbin/
│           │   └── sb-enema                # Main runtime entry point (menu + CLI)
│           └── lib/sb-enema/
│               ├── audit.sh                # Secure Boot health audit engine
│               ├── report.sh               # Health report renderer
│               ├── preview.sh              # Change preview & user confirmation
│               ├── update.sh               # Delta computation (ADD/REMOVE/KEEP)
│               ├── stage.sh                # Staging functions (PK/KEK/db/dbx payloads)
│               ├── enroll.sh               # Generic enrollment (applies staged payloads)
│               ├── keygen.sh               # Key generation, GUID management, backup instructions
│               ├── safety.sh               # Safety guardrails (Setup Mode, payload integrity)
│               ├── certdb.sh               # Certificate fingerprint lookups
│               ├── efivar.sh               # EFI variable I/O (including KEKDefault/dbDefault)
│               ├── mount.sh                # Partition mount helpers
│               ├── log.sh                  # Structured logging
│               ├── common.sh               # Shared constants & helpers
│               └── known-certs/            # Certificate fingerprint databases
├── scripts/                    # Build-time helpers (payload prep, test scripts)
├── third_party/
│   └── secureboot_objects/     # Microsoft reference certs/templates (submodule)
└── docs/                       # Detailed architecture & usage docs
```

## How It Works

This is a [Buildroot](https://buildroot.org/)-based project that builds a minimal Linux environment containing `efitools` for UEFI variable manipulation. The build process:

1. Pulls Microsoft's `secureboot_objects` repo (templates, scripts, pre-signed objects)
2. Generates firmware payloads (PK/KEK/db/dbx) using Microsoft's Python tooling
3. Packages everything into a hybrid GPT image with:
   - FAT32 EFI boot partition (kernel, initramfs)
   - FAT32 data partition (certs, payloads, logs, generated private keys)

At runtime:

1. Automatically logs in as root and runs `sb-enema` (via `/root/.profile`).
2. The FAT32 data partition is mounted at `/mnt/data` before `sb-enema` starts.
3. Audits current Secure Boot state: identifies test PKs, validates certificate expiry, checks 2026 readiness
4. Identifies the current ownership model (vendor-owned, Microsoft-owned, custom, or test)
5. Renders a health report with per-certificate status and severity-graded findings
6. For any provisioning operation: computes the delta (what will be added/removed/kept per variable), shows a preview, and requires explicit confirmation before touching anything
7. Applies variables in the correct order (db → dbx → KEK → PK) using `efi-updatevar`
8. Logs every action with timestamps to the USB drive

All generated private keys stay on the FAT32 data partition. They never touch the target system.

## Requirements

**Build host:**
- `curl`, `tar`, `git`
- `openssl`
- `mkfs.fat` (from `dosfstools`)
- `rsync`, `sudo`
- `python3-venv`

**Target system:**
- x86_64 UEFI with Secure Boot support
- Must be in **Setup Mode** (keys cleared)

## Contributing

Found a bug? Have a vendor horror story? PRs welcome.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

- [Buildroot](https://buildroot.org/) — for making embedded Linux tolerable
- [Microsoft secureboot_objects](https://github.com/microsoft/secureboot_objects) — ironically, Microsoft maintains better Secure Boot tooling than most motherboard vendors
- Every forum post from 2015 explaining how to manually enroll keys — we've all been there

---

*"My vendor's last firmware update was during the Obama administration."* — Anonymous SB-ENEMA user
