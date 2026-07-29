#!/usr/bin/env python3
"""Guard the certificate-policy invariants of a generated Secure Boot key set.

Run by scripts/prepare-secureboot-objects.sh against the ESLs that
secure_boot_default_keys.py just produced, before anything is staged into the
image.

Why this exists
---------------
SB-ENEMA deliberately keeps "Microsoft Windows Production PCA 2011" in db so
that a Windows installation whose boot manager has not yet been re-signed under
"Windows UEFI CA 2023" keeps booting.  That is only safe while dbx does not
revoke the certificate itself: per UEFI 2.x section 32.5, a dbx match wins over
a db match, so an EFI_CERT_X509 entry for PCA 2011 in dbx would override the db
entry and stop those machines booting entirely.

Today the upstream converter emits image hashes only -- dbx_info_msft_latest.json
does mark PCA 2011 as revoked for CVE-2023-24932, but that revocation is not
rendered into the built ESL.  That is an upstream implementation detail, not a
guarantee, and it is load-bearing for our db policy.  If a submodule bump ever
starts emitting certificate-class revocations, this check fails the build
instead of shipping an image that bricks the machines it is meant to repair.

Certificate revocation is detected in both encodings the spec allows: a full
EFI_CERT_X509 entry, and an EFI_CERT_X509_SHA{256,384,512} hash of the
TBSCertificate (which is what firmware actually uses to revoke a CA).  Any dbx
entry type this tool does not recognise is treated as a failure rather than
ignored, so the guard cannot fail open on an encoding added later.

Usage: check-secureboot-policy.py <DB.bin> <DBX.bin> [KEK.bin]
Exit codes: 0 ok, 1 invariant violated, 2 usage/parse error.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import uuid
from pathlib import Path

# EFI signature-list type GUIDs (UEFI spec, table "Signature Database"; values
# cross-checked against edk2 MdePkg/Include/Guid/ImageAuthentication.h).
EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")

# A dbx entry may revoke a CA by the hash of its TBSCertificate rather than by
# embedding the whole certificate.  This is the encoding firmware actually uses
# for certificate-level revocation, so a guard that only understands
# EFI_CERT_X509 would fail open on precisely the case it exists to catch.
EFI_CERT_X509_SHA256_GUID = uuid.UUID("3bd2a492-96c0-4079-b420-fcf98ef103ed")
EFI_CERT_X509_SHA384_GUID = uuid.UUID("7076876e-80c2-4ee6-aad2-28b349a6865b")
EFI_CERT_X509_SHA512_GUID = uuid.UUID("446dbf63-2502-4cda-bcfa-2465d2b0fe9d")

TBS_HASH_TYPES = {
    EFI_CERT_X509_SHA256_GUID: "sha256",
    EFI_CERT_X509_SHA384_GUID: "sha384",
    EFI_CERT_X509_SHA512_GUID: "sha512",
}

# Signature types this tool knows how to reason about.  Anything else in dbx is
# treated as unrecognised and fails the check rather than being ignored.
KNOWN_SIGNATURE_TYPES = {
    EFI_CERT_X509_GUID,
    EFI_CERT_SHA256_GUID,
} | set(TBS_HASH_TYPES)

# WIN_CERTIFICATE / EFI_VARIABLE_AUTHENTICATION_2 constants.
WIN_CERT_TYPE_EFI_GUID = 0x0EF1
WIN_CERT_REVISION_2_00 = 0x0200
AUTH2_HEADER_PREFIX = 16  # sizeof(EFI_TIME)

# Certificates whose presence in dbx would invalidate our db policy, by SHA-256
# of the DER encoding.  Keep in sync with the [DB] section of
# sb_enema/secureboot-templates/SbEnemaRecovery.toml.
COMPAT_CRITICAL_DB_CERTS = {
    "e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961":
        "Microsoft Windows Production PCA 2011",
    "48e99b991f57fc52f76149599bff0a58c47154229b9f8d603ac40d3500248507":
        "Microsoft Corporation UEFI CA 2011",
}

# Certificates that must be present in KEK, by SHA-256 of the DER encoding.
# Keep in sync with the [KEK] section of SbEnemaRecovery.toml.  The 2011 KEK is
# required because every Microsoft Secure Boot servicing package published to
# date is signed under it; without it the machine can never apply a Microsoft
# dbx update.
COMPAT_CRITICAL_KEK_CERTS = {
    "a1117f516a32cefcba3f2d1ace10a87972fd6bbe8fe0d0b996e09e65d802a503":
        "Microsoft Corporation KEK CA 2011",
    "3cd3f0309edae228767a976dd40d9f4affc4fbd5218f2e8cc3c9dd97e8ac6f9d":
        "Microsoft Corporation KEK 2K CA 2023",
}


def _read_der_tlv(buf: bytes, offset: int):
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
    """Return the TBSCertificate substring of an X.509 certificate.

    Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, ... }, and the
    UEFI TBS hash covers the tbsCertificate element including its own tag and
    length bytes.
    """
    tag, value_offset, _ = _read_der_tlv(cert_der, 0)
    if tag != 0x30:
        raise ValueError("certificate is not a DER SEQUENCE")
    inner_tag, inner_value_offset, inner_length = _read_der_tlv(cert_der, value_offset)
    if inner_tag != 0x30:
        raise ValueError("tbsCertificate is not a DER SEQUENCE")
    return cert_der[value_offset:inner_value_offset + inner_length]


def strip_auth2_header(blob: bytes) -> bytes:
    """Return the raw ESL, dropping an EFI_VARIABLE_AUTHENTICATION_2 wrapper.

    Firmware/*.bin are raw ESLs; Imaging/*.bin are wrapped.  Detect rather than
    assume, so this works on either.
    """
    if len(blob) < AUTH2_HEADER_PREFIX + 8:
        return blob
    length, revision, cert_type = struct.unpack_from("<IHH", blob, AUTH2_HEADER_PREFIX)
    if cert_type == WIN_CERT_TYPE_EFI_GUID and revision == WIN_CERT_REVISION_2_00:
        end = AUTH2_HEADER_PREFIX + length
        if 0 < length and end <= len(blob):
            return blob[end:]
    return blob


def iter_signatures(esl: bytes):
    """Yield (signature_type, signature_data) for every entry in an ESL chain."""
    offset = 0
    while offset + 28 <= len(esl):
        sig_type = uuid.UUID(bytes_le=esl[offset:offset + 16])
        list_size, header_size, sig_size = struct.unpack_from("<III", esl, offset + 16)

        # Malformed or truncated: raise rather than skip, so a structurally
        # broken ESL can never be quietly certified as containing no
        # revocations.  header_size is bounds-checked too, since an oversized
        # value would otherwise silently produce an empty body.
        body_size = list_size - 28 - header_size
        if (list_size < 28 + header_size
                or sig_size <= 16
                or offset + list_size > len(esl)
                or body_size < 0
                or body_size % sig_size != 0):
            raise ValueError(
                f"malformed signature list at offset {offset} "
                f"(list_size={list_size}, header_size={header_size}, "
                f"sig_size={sig_size})"
            )

        body = esl[offset + 28 + header_size: offset + list_size]
        for index in range(len(body) // sig_size):
            entry = body[index * sig_size:(index + 1) * sig_size]
            yield sig_type, entry[16:]  # strip the SignatureOwner GUID

        offset += list_size

    if offset != len(esl):
        raise ValueError(
            f"trailing bytes after final signature list "
            f"({len(esl) - offset} byte(s) at offset {offset})"
        )


def load_esl(path: Path):
    return list(iter_signatures(strip_auth2_header(path.read_bytes())))


def main(argv: list[str]) -> int:
    if not 3 <= len(argv) <= 4:
        print(
            f"usage: {Path(argv[0]).name} <DB.bin> <DBX.bin> [KEK.bin]",
            file=sys.stderr,
        )
        return 2

    db_path, dbx_path = Path(argv[1]), Path(argv[2])
    kek_path = Path(argv[3]) if len(argv) == 4 else None
    for path in [db_path, dbx_path] + ([kek_path] if kek_path else []):
        if not path.is_file():
            print(f"ERROR: not found: {path}", file=sys.stderr)
            return 2

    try:
        db_entries = load_esl(db_path)
        dbx_entries = load_esl(dbx_path)
        kek_entries = load_esl(kek_path) if kek_path else []
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    def cert_fingerprints(entries):
        return {
            hashlib.sha256(data).hexdigest()
            for kind, data in entries
            if kind == EFI_CERT_X509_GUID
        }

    db_certs = cert_fingerprints(db_entries)
    kek_certs = cert_fingerprints(kek_entries)
    dbx_certs = cert_fingerprints(dbx_entries)

    # Certificate-level revocations expressed as a hash of the TBSCertificate.
    # Index our db certs the same way so the two can be compared.
    db_tbs = {}
    for kind, data in db_entries:
        if kind != EFI_CERT_X509_GUID:
            continue
        try:
            tbs = tbs_certificate(data)
        except ValueError:
            continue  # not parseable; the DER-identity check still covers it
        for algorithm in TBS_HASH_TYPES.values():
            db_tbs.setdefault(algorithm, {})[
                hashlib.new(algorithm, tbs).hexdigest()
            ] = hashlib.sha256(data).hexdigest()

    dbx_tbs = {}
    for kind, data in dbx_entries:
        algorithm = TBS_HASH_TYPES.get(kind)
        if algorithm:
            dbx_tbs.setdefault(algorithm, set()).add(data.hex())

    dbx_hashes = sum(1 for kind, _ in dbx_entries if kind == EFI_CERT_SHA256_GUID)
    dbx_tbs_count = sum(len(v) for v in dbx_tbs.values())
    unknown_types = {
        kind for kind, _ in dbx_entries if kind not in KNOWN_SIGNATURE_TYPES
    }

    print(
        f"  db:  {len(db_certs)} certificate(s)\n"
        f"  kek: {len(kek_certs)} certificate(s)"
        + ("" if kek_path else " (not checked)")
        + f"\n  dbx: {len(dbx_certs)} certificate entr(ies), "
        f"{dbx_tbs_count} TBS-hash revocation(s), {dbx_hashes} image hash(es)"
    )

    failures = []

    # 1. Hard failure: dbx revokes a certificate we rely on in db.  This is the
    #    brick condition -- dbx wins, so the db entry becomes dead weight and
    #    every binary signed under that CA stops booting.  Check both encodings:
    #    the whole certificate, and a hash of its TBSCertificate.
    for fingerprint in sorted(db_certs & dbx_certs):
        name = COMPAT_CRITICAL_DB_CERTS.get(fingerprint, fingerprint)
        failures.append(
            f"'{name}' is present in BOTH db and dbx (as a full certificate). "
            f"dbx takes precedence (UEFI 2.x 32.5), so enrolling this set would "
            f"stop every binary signed by that CA from booting."
        )

    for algorithm, revoked in sorted(dbx_tbs.items()):
        for digest in sorted(revoked & set(db_tbs.get(algorithm, {}))):
            fingerprint = db_tbs[algorithm][digest]
            name = COMPAT_CRITICAL_DB_CERTS.get(fingerprint, fingerprint)
            failures.append(
                f"'{name}' is in db but revoked by dbx via its {algorithm} "
                f"TBSCertificate hash. dbx takes precedence, so every binary "
                f"signed by that CA would stop booting."
            )

    # 2. Hard failure: a compatibility-critical certificate is missing.
    #    Catches a template edit or submodule bump that silently drops one.
    for fingerprint, name in COMPAT_CRITICAL_DB_CERTS.items():
        if fingerprint not in db_certs:
            failures.append(
                f"'{name}' is missing from db. It is required so that "
                f"pre-2023-signed boot managers, install media and option ROMs "
                f"keep booting after re-provisioning."
            )

    if kek_path:
        for fingerprint, name in COMPAT_CRITICAL_KEK_CERTS.items():
            if fingerprint not in kek_certs:
                failures.append(
                    f"'{name}' is missing from KEK. Both Microsoft KEKs are "
                    f"required: servicing packages published to date are signed "
                    f"under the 2011 KEK, and the 2023 KEK is the forward path."
                )

    # 3. Hard failure: a dbx entry type this tool does not understand. Refusing
    #    is the only safe response -- an unrecognised type could be a
    #    certificate revocation in an encoding added after this was written,
    #    and treating it as "nothing to see" is exactly the fail-open the
    #    guard exists to prevent.
    for kind in sorted(unknown_types, key=str):
        failures.append(
            f"dbx contains an unrecognised signature type {{{kind}}}. This "
            f"check cannot prove it does not revoke a certificate db depends "
            f"on; teach check-secureboot-policy.py about it before shipping."
        )

    # 4. Soft signal: certificate-class revocations that do not hit our db are
    #    a change in upstream behaviour worth a human look, but not unsafe.
    for fingerprint in sorted(dbx_certs - db_certs):
        print(
            f"  NOTE: dbx revokes a certificate that is not in our db "
            f"({fingerprint}). Not a failure, but upstream behaviour has changed "
            f"-- re-read the policy notes in SbEnemaRecovery.toml.",
            file=sys.stderr,
        )

    if failures:
        print("\nERROR: Secure Boot certificate policy check FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\nSee sb_enema/secureboot-templates/SbEnemaRecovery.toml for the "
            "policy these invariants protect.",
            file=sys.stderr,
        )
        return 1

    print("  Certificate policy invariants OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
