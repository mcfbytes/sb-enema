# Security Policy

SB-ENEMA directly manipulates UEFI Secure Boot variables (PK, KEK, db, dbx) and handles cryptographic key material. We take the security of this project seriously.

## Supported Versions

| Version             | Supported |
| ------------------- | --------- |
| Development branch  | ✅        |
| < 1.0 (pre-release) | ❌        |

Once v1.0 ships, only the latest release will receive security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please use GitHub's **private vulnerability reporting** feature:
*Settings → Security → Advisories → Report a vulnerability*

When reporting, include:

- Affected version or commit
- Steps to reproduce
- Potential impact (especially regarding Secure Boot chain integrity or key material exposure)

> This is a hobby project — we cannot guarantee a response time, but we will make a good-faith effort to triage and address reported vulnerabilities.

## Scope

**In scope:**

- Key material handling (generation, storage, signing)
- EFI variable manipulation logic
- Build pipeline integrity (supply-chain concerns)
- Buildroot / image build process

**Out of scope:**

- Upstream [`microsoft/secureboot_objects`](https://github.com/microsoft/secureboot_objects) — report those to Microsoft directly
- Upstream Buildroot bugs — report those to the [Buildroot project](https://buildroot.org)
