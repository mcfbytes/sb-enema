#!/usr/bin/env python3
"""Append certificate-class and SVN revocations to a generated DBX signature list.

Why this exists
---------------
microsoft/secureboot_objects publishes three kinds of revocation in
PreSignedObjects/DBX/dbx_info_msft_latest.json:

  images       -- Authenticode hashes of individual revoked binaries
  certificates -- whole certificate authorities that are no longer trusted
  svns         -- Secure Version Number floors, below which a signed binary is
                  rejected even though its signature is still valid

Its converter (secure_boot_default_keys.py::_convert_json_to_signature_list)
reads only `data["images"]`.  The other two are loaded and silently dropped, so
a stock build produces a dbx with no certificate-level revocation at all.

This appends the missing two classes to an already-generated DBX ESL.

Why it is opt-in
----------------
The certificate entry currently in that file revokes "Microsoft Windows
Production PCA 2011" for CVE-2023-24932, and the SVN entries set a floor on the
Windows Boot Manager.  Because a dbx match beats a db match, applying either on
a machine whose Windows has not yet migrated to the 2023-signed boot manager
makes that machine unbootable.  That is precisely the failure SB-ENEMA's default
policy exists to prevent, and it is why Microsoft ships these only in the
explicitly optional DBXUpdate2024 package, warning that it "will be unable to
boot existing Windows boot media".

So this is a hardening tier, not a fix: it is only coherent alongside a db that
has already dropped the certificates being revoked.  scripts/check-secureboot-policy.py
enforces that coupling, and will fail the build if a certificate appears in both
db and dbx.

Usage:
  append-dbx-revocations.py <DBX.bin> <dbx_info.json> <cert_dir> [--certificates] [--svns]

Rewrites <DBX.bin> in place.  Exit codes: 0 ok, 2 usage/parse error.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path

# UEFI signature-list type GUIDs (edk2 MdePkg/Include/Guid/ImageAuthentication.h).
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
EFI_CERT_X509_SHA256_GUID = uuid.UUID("3bd2a492-96c0-4079-b420-fcf98ef103ed")

MICROSOFT_OWNER_GUID = uuid.UUID("77fa9abd-0359-4d32-bd60-28f4e78f784b")

SHA256_LEN = 32


def read_der_tlv(buf: bytes, offset: int):
    """Return (tag, value_offset, value_length) for the DER TLV at `offset`."""
    if offset + 2 > len(buf):
        raise ValueError("truncated DER element")
    tag = buf[offset]
    length = buf[offset + 1]
    cursor = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or cursor + count > len(buf):
            raise ValueError("unsupported or truncated DER length")
        length = int.from_bytes(buf[cursor:cursor + count], "big")
        cursor += count
    if cursor + length > len(buf):
        raise ValueError("DER element overruns buffer")
    return tag, cursor, length


def tbs_certificate(cert_der: bytes) -> bytes:
    """Return the TBSCertificate substring, including its own tag and length.

    Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, ... } and the UEFI
    TBS hash covers the tbsCertificate element as it appears in the certificate.
    """
    tag, value_offset, _ = read_der_tlv(cert_der, 0)
    if tag != 0x30:
        raise ValueError("certificate is not a DER SEQUENCE")
    inner_tag, inner_value_offset, inner_length = read_der_tlv(cert_der, value_offset)
    if inner_tag != 0x30:
        raise ValueError("tbsCertificate is not a DER SEQUENCE")
    return cert_der[value_offset:inner_value_offset + inner_length]


def signature_list(sig_type: uuid.UUID, payloads: list[bytes], owner: uuid.UUID) -> bytes:
    """Encode one EFI_SIGNATURE_LIST holding fixed-size entries."""
    if not payloads:
        return b""
    sizes = {len(p) for p in payloads}
    if len(sizes) != 1:
        raise ValueError(f"signature list entries must be uniform, got sizes {sorted(sizes)}")
    sig_size = 16 + sizes.pop()
    body = b"".join(owner.bytes_le + p for p in payloads)
    header = sig_type.bytes_le + struct.pack("<III", 28 + len(body), 0, sig_size)
    return header + body


def locate_certificate(cert_dir: Path, value: str) -> Path:
    """Resolve a `certificates[].value` filename to a path under cert_dir."""
    direct = cert_dir / value
    if direct.is_file():
        return direct
    matches = sorted(cert_dir.rglob(value))
    if not matches:
        raise FileNotFoundError(f"certificate {value!r} not found under {cert_dir}")
    return matches[0]


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}
    unknown = flags - {"--certificates", "--svns"}
    if len(args) != 3 or unknown:
        print(
            f"usage: {Path(argv[0]).name} <DBX.bin> <dbx_info.json> <cert_dir> "
            f"[--certificates] [--svns]",
            file=sys.stderr,
        )
        return 2

    dbx_path, json_path, cert_dir = Path(args[0]), Path(args[1]), Path(args[2])
    for path in (dbx_path, json_path):
        if not path.is_file():
            print(f"ERROR: not found: {path}", file=sys.stderr)
            return 2
    if not cert_dir.is_dir():
        print(f"ERROR: not a directory: {cert_dir}", file=sys.stderr)
        return 2

    if not flags:
        print("  no revocation classes requested; dbx left unchanged")
        return 0

    try:
        info = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read {json_path}: {exc}", file=sys.stderr)
        return 2

    appended = b""

    if "--certificates" in flags:
        entries = info.get("certificates") or []
        digests, names = [], []
        for entry in entries:
            value = entry.get("value")
            if not value:
                print(f"ERROR: certificates entry has no 'value': {entry}", file=sys.stderr)
                return 2
            try:
                der = locate_certificate(cert_dir, value).read_bytes()
                digests.append(hashlib.sha256(tbs_certificate(der)).digest())
            except (FileNotFoundError, ValueError, OSError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 2
            names.append(entry.get("subjectName", value))
        if digests:
            appended += signature_list(EFI_CERT_X509_SHA256_GUID, digests, MICROSOFT_OWNER_GUID)
            for name in names:
                print(f"  + certificate revocation: {name}")

    if "--svns" in flags:
        values = []
        for entry in info.get("svns") or []:
            raw = entry.get("value")
            if not raw:
                print(f"ERROR: svns entry has no 'value': {entry}", file=sys.stderr)
                return 2
            try:
                blob = bytes.fromhex(raw)
            except ValueError as exc:
                print(f"ERROR: svns value is not hex ({raw!r}): {exc}", file=sys.stderr)
                return 2
            if len(blob) != SHA256_LEN:
                print(
                    f"ERROR: svns value must be {SHA256_LEN} bytes, got {len(blob)} for {raw!r}",
                    file=sys.stderr,
                )
                return 2
            values.append(blob)
            print(
                f"  + SVN floor: {entry.get('filename', '?')} "
                f"v{entry.get('version', '?')} ({entry.get('description', '')})"
            )
        if values:
            # SVN markers are carried as EFI_CERT_SHA256 entries; the 32-byte
            # value already encodes the GUID and version and is used verbatim.
            appended += signature_list(EFI_CERT_SHA256_GUID, values, MICROSOFT_OWNER_GUID)

    if not appended:
        print("  requested revocation classes were empty; dbx left unchanged")
        return 0

    dbx_path.write_bytes(dbx_path.read_bytes() + appended)
    print(f"  appended {len(appended)} bytes of revocations to {dbx_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
