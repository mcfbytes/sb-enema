# SB-ENEMA Roadmap

What's coming, what's aspirational, and what's probably a terrible idea we'll do anyway.

## 1.0 — "It Actually Works" Release

The minimum feature set for a tool that doesn't embarrass us.

### Core Features

- [x] Detect invalid or test PKs
- [x] Compare PK/KEK/db against known vendor defaults
- [x] Validate whether the Secure Boot chain is 2026-ready
- [x] Extract PK/KEK/db from the current Secure Boot configuration
- [x] Warn users when their vendor has not shipped updated firmware
- [x] Help users take ownership with a custom PK/KEK/db
- [x] Help users install Microsoft's db/dbx under their own KEK
- [x] Provide a "Secure Boot Health Report" summarizing issues
- [x] Provide a "What will change?" preview before applying updates
- [x] Provide a "Microsoft PK Recovery Mode" option with warnings
- [x] Provide a "Custom Owner Mode" option with deterministic PK/KEK/db generation
- [x] Provide a "Restore OEM Defaults" reminder and instructions

### Safety Guardrails

- Refuse PK replacement outside Setup Mode
- Preview all changes before applying
- Log every action to the USB drive
- Store generated PK private keys on the exFAT partition with clear backup instructions

## Stretch Goals

Nice-to-have features that would make this tool genuinely impressive but aren't blocking 1.0.

- Extract PK/KEK/db from vendor firmware images (UEFI capsule parsing)
- Compare firmware-embedded defaults vs current NVRAM values
- Detect mismatched or placeholder PKDefault/KEKDefault/dbDefault
- Generate a reproducible Secure Boot provisioning bundle (same inputs → same outputs)
- Export a JSON report for audit or support purposes

## Future Ideas

Things we'd like to build eventually. No timeline, no promises, just ambition.

### Vendor Intelligence

- Hardware vendor auto-detection (DMI/SMBIOS) and automatic cert selection
- Vendor PK database — a curated collection of known vendor PKs and their status (valid, expired, test, revoked)
- Vendor firmware update status tracking — "Your board's last update was 2019. Thoughts and prayers."

### User-Provided Certificates

- Support for enrolling user-supplied PK/KEK/db certificates
- PKCS#12 / PEM import
- Certificate chain validation before enrollment

### Audit and Reporting

- Attestation reports suitable for compliance review
- Diff-style output: "Here's what changed since last provisioning"
- Integration with OS-level Secure Boot health tools

### Provisioning at Scale

- Batch provisioning mode for fleet deployments
- Network-boot variant (PXE/HTTP boot) for labs and IT departments
- Configuration profiles: define a target Secure Boot state, apply it to N machines

### Community

- Public database of known-bad vendor PKs (test keys, expired certs, shared keys across vendors)
- "Shame board" — vendors ranked by Secure Boot hygiene (we can dream)

## Long-Term Vision

Secure Boot should be a solved problem. It isn't, because vendors treat it as a compliance checkbox rather than a security feature. SB-ENEMA exists to bridge the gap between "vendor shipped it" and "vendor maintains it."

The end goal: a tool that any technically competent user can boot, understand the state of their Secure Boot chain in under 30 seconds, and fix it in under 60. No firmware engineering degree required.

If vendors eventually ship proper firmware updates and maintain their Secure Boot chains, this tool becomes unnecessary. We'd love that. We're not holding our breath.

---

*Last updated: 2026-02*
