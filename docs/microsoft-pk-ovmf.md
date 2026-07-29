# Why the Microsoft-owned PK cannot be enrolled under OVMF

**Summary:** enrolling Microsoft's Platform Key under OVMF is not a bug in
SB-ENEMA and is not fixable from our side. OVMF requires a PK update to be
signed by the private key of the certificate contained in that update. For
Microsoft's PK that key is Microsoft's. The other three variables — KEK, db and
dbx — enroll normally, and CI covers them.

This does not affect real hardware. The flow works on shipping AMI/Insyde
firmware, which does not impose the same requirement.

## What happens

`sb-enema microsoft-colonic` in a fresh Setup Mode OVMF machine:

```
action=ENROLL target=db   status=WRITE_OK
action=ENROLL target=dbx  status=WRITE_OK
action=ENROLL target=KEK  status=VERIFIED
Running: efi-updatevar -f /mnt/data/sb-enema/payloads/PK.auth PK
Cannot write to PK, wrong filesystem permissions
action=ENROLL target=PK   status=FAIL   detail=efi-updatevar returned exit code 1
```

The message is misleading in two ways. It comes from efitools, not the kernel,
and it has nothing to do with filesystem permissions: `set_variable()` in
`lib/kernel_efivars.c` returns the `errno` from the `write()` to efivarfs, and
the kernel maps `EFI_SECURITY_VIOLATION` to `EACCES`. efitools prints its
"wrong filesystem permissions" string for `EACCES`. So the firmware is
rejecting the write.

## Measurement

Same ESL, same firmware, same Setup Mode machine; only the signing key differs:

```sh
cert-to-efi-sig-list -g $G a.crt a.esl

sign-efi-sig-list -g $G -k b.key -c b.crt PK a.esl foreign.auth   # signed by B
efi-updatevar -f foreign.auth PK          # -> Cannot write to PK, rc=1

sign-efi-sig-list -g $G -k a.key -c a.crt PK a.esl self.auth      # signed by A
efi-updatevar -f self.auth PK             # -> rc=0
```

| PK payload signed by | Result |
|---|---|
| a foreign key (certificate not in the ESL) | rejected, `EFI_SECURITY_VIOLATION` |
| the key matching the certificate in the ESL | accepted |

That is `PcdRequireSelfSignedPk` behaviour: edk2's `ProcessVarWithPk()` skips
authentication in Setup Mode only when that feature PCD is FALSE. Upstream
`OvmfPkg/OvmfPkgX64.dsc` sets it FALSE, so the shipped Debian/Ubuntu builds
evidently enable it, but the behaviour is what matters here and it is measured
rather than inferred.

Every secure-boot-capable firmware image shipped by the `ovmf` package behaves
the same way:

| Firmware | Foreign-signed PK |
|---|---|
| `OVMF_CODE_4M.secboot.fd`  | rejected |
| `OVMF_CODE_4M.ms.fd`       | rejected |
| `OVMF_CODE_4M.snakeoil.fd` | rejected |

## Why the existing fallback cannot help

`_enroll_pk_with_fallback()` re-signs the PK ESL with an ephemeral throwaway
key when the first write fails. Against a self-signed requirement that cannot
work: the certificate inside the ESL is still Microsoft's, and the throwaway key
does not correspond to it. Measured — the retry fails identically.

The fallback is still worth keeping. It targets a different firmware defect:
one that rejects the *empty* PKCS#7 in Microsoft's pre-signed payload while not
requiring a self-signed PK. That combination is plausible, and the retry is
cheap. It is simply not a workaround for this case, and the code and menu text
now say so rather than implying a general recovery.

## Why the payload looks the way it does

`Imaging/PK.bin` from `secureboot_objects` wraps the PK ESL in an
`EFI_VARIABLE_AUTHENTICATION_2` whose PKCS#7 is a 37-byte degenerate
`SignedData` — no signers, no certificates — with a 2010-03-06 timestamp. That
is the standard Setup-Mode enrollment shape: valid structure, no signature,
accepted by firmware that does not authenticate PK writes in Setup Mode.

SB-ENEMA uses that pre-signed file rather than the raw ESL because efitools
refuses `-e` (raw ESL) mode for PK even in Setup Mode:

```c
/* efi-updatevar.c:283 */
if (esl_mode && (!variable_is_setupmode() || strcmp(variables[i], "PK") == 0)) {
        if (!key_file) {
                fprintf(stderr, "Can't update variable%s without a key\n", ...);
                exit(1);
```

That restriction is an efitools policy choice, not a firmware one. Note the
asymmetry it creates: for KEK/db/dbx, `-e` makes efitools build its own
degenerate `EFI_VARIABLE_AUTHENTICATION_2` (empty signature, timestamp one year
in the future) around the ESL, which is structurally the same thing Microsoft
ships for PK. Those writes succeed. Only PK is authenticated by the firmware,
so only PK fails.

## Testing consequences

`scripts/qemu-enroll-test.sh` runs two scenarios:

- **custom-owned** (`full-colonic`) — user-generated PK/KEK plus Microsoft
  db/dbx. Fully covered, including PK, because the user PK is self-signed by
  construction.
- **microsoft-chain** (`microsoft-suppository`) — Microsoft's pre-signed
  KEK/db/dbx payloads with PK left untouched. This exercises the identical
  Microsoft payload chain that `microsoft-colonic` uses, so the certificate
  policy is covered; only the PK write is not.

`microsoft-colonic` itself is not run in CI. Covering it would require building
OVMF with `PcdRequireSelfSignedPk=FALSE`, which is disproportionate: it would
test our code against a firmware configuration no distribution ships.

The gap is therefore narrow and specific — the PK write itself, on the
Microsoft-owned path — and it remains covered only by testing on real hardware.
