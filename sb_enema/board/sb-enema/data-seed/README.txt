SB-ENEMA FAT32 data partition — seed and runtime layout
=========================================================

This directory (data-seed/) is the build-time seed for the SB-ENEMA FAT32
data partition (label: SB-ENEMA, mounted at /mnt/data at runtime).

At build time, prepare-secureboot-objects.sh populates additional directories
in the staging area, and post-image.sh copies the required staged content
onto the partition image: sb-enema/, PreSignedObjects/, and any seed
entries from data-seed/.

Runtime partition layout
------------------------

  sb-enema/
    payloads/         Staging area for .auth files and cert subdirs.
                      Populated at runtime by the stage_* functions inside
                      sb-enema.  Do NOT modify manually while sb-enema is
                      running; contents are volatile.
      microsoft/      Pre-built Microsoft-signed .auth payloads (PK, KEK,
                      db, dbx) placed here at build time.  Read-only.
      SHA256SUMS      Integrity manifest for all .auth files.  Checked by
                      safety_check_payload_integrity() before enrollment.
    keys/             User-generated PK and KEK keypairs written by
                      keygen_generate_keys() during Full Colonic.
                      Treat as sensitive; back up after enrollment.
    kek_update_map.json
                      Maps SHA-1 vendor PK fingerprints to KEK update bins.
                      Consumed by stage_bios_entries() to filter recognized
                      OEM certificates from KEKDefault/dbDefault.
    logs/             Enrollment logs written by log_init() on each run.
                      Safe to read and archive.

  PreSignedObjects/   Microsoft source certificates (DER) for KEK and db,
                      sourced from the secureboot_objects submodule.
                      Used by stage_microsoft_kek_db_dbx() at runtime.
                      Read-only; do not modify.

Customisation
-------------

To use custom PK/KEK certificates instead of the auto-generated ones:

  1. Pre-place your PK.key / PK.crt and KEK.key / KEK.crt under
       sb-enema/keys/
     on the partition before running sb-enema.  keygen_generate_keys()
     will skip generation if the files already exist.

  2. To include custom db certificates (e.g. your own code-signing cert),
     run option [8] "Stage User-generated KEK, DB" from the sb-enema menu
     after mounting the partition in a running system, or pre-stage them
     under sb-enema/payloads/db/ and run option [12] "Apply staged changes".

DO NOT put certificates directly into the partition root or into ad-hoc
directories — the runtime does not scan arbitrary locations.  All cert
paths used by the runtime are documented above.
