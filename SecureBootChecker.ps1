# SecureBootChecker.ps1
# SB-ENEMA Secure Boot Health Report — Windows edition.
#
# Replicates the report_full() / audit_run_all() logic from the SB-ENEMA bash
# toolchain (audit.sh + report.sh) so Windows users can assess whether their
# system needs the tool before booting the SB-ENEMA live image.
#
# Run from the repo root after "git submodule update --init --recursive".
# Requires Administrator privileges (needed to read UEFI variables).
#
# Checks performed (mirroring audit.sh):
#   audit_pk()   — PK present, not a test key, not expired, not expiring before 2026-06-01
#   audit_kek()  — Microsoft KEK 2023 present (or user-owned KEK chain)
#   audit_db()   — Microsoft UEFI CA 2023 / Windows UEFI CA 2023 present
#   audit_dbx()  — Revocation list has >= 100 SHA-256 hashes
#   audit_2026_ready() — composite 2026-readiness verdict

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# ---------------------------------------------------------------------------
# Known certificate SHA-256 fingerprints — mirrors the constants in audit.sh
# and the known-certs/*.txt database files.
# Fingerprints are lowercase hex, no colons (SHA-256 of the raw DER bytes).
# ---------------------------------------------------------------------------

# KEK certificates
$MS_KEK_2011  = "a1117f516a32cefcba3f2d1ace10a87972fd6bbe8fe0d0b996e09e65d802a503"
$MS_KEK_2023  = "3cd3f0309edae228767a976dd40d9f4affc4fbd5218f2e8cc3c9dd97e8ac6f9d"

# db certificates
$MS_UEFI_CA_2011       = "48e99b991f57fc52f76149599bff0a58c47154229b9f8d603ac40d3500248507"
$MS_WIN_PCA_2011       = "e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
$MS_OPTION_ROM_2023    = "e5be3e64c6e66a281457ecdece0d6d0787577aad2a3a0144262c10c14ba8d8f1"
$MS_UEFI_CA_2023       = "f6124e34125bee3fe6d79a574eaa7b91c0e7bd9d929c1a321178efd611dad901"
$WIN_UEFI_CA_2023      = "076f1fea90ac29155ebf77c17682f75f1fdd1be196da302dc8461e350a9ae330"

# PK: Microsoft Windows OEM Devices PK (Surface / WHCP-enrolled systems)
$MS_OEM_DEVICES_PK     = "2f569e8edaf9657dc4951c29598725255c7f821472db71374211fe44d082546f"

# Known test / placeholder PKs (from known-certs/known-test-pks.txt).
# If a system's PK fingerprint matches any of these, Secure Boot is NOT
# providing real security — the private key is publicly known or was never
# intended for production use.
$KNOWN_TEST_PKS = @(
    "cca4e3f3170230030dc3e33d1e3fa7d1383de8b3367430892e93cbccde034ce0",  # AMI test PK variant 1
    "617f9a3582de92b19a14bf45cd7041950f365b1e49bac2633fd02bb106902c8d",  # AMI test PK variant 2
    "01adaf2c334e76a6479516daf618381898323d8f5e7a57bed12bad7ab229209d",  # AMI/ASUS test PK variant 3
    "d7ddc0ac61513b51601e76673826cd44187b5ff85f6c29eacdf8d1e37c52388a",  # AMI test PK variant 4
    "282d2857ee8f28ce622c803cab5031edda9412f08fa3192208344da0c6a42a6e",  # ASUS OEM test PK
    "fe66f36a8c1a0da41bd2665d2f03cfc3f015975b690c90290297815639d69f0b",  # TONGFANG variant 1
    "2345ab8c4c53797c8205661117d653fc30c144ceaa5561fb7812065c9f1f58ba",  # TONGFANG variant 2
    "f1608cb68168eeb07ae7c568308351d8183018355ebd1c79961323e40afbf5b0",  # Clevo variant 1
    "863bfed7d73652c20adadbaaa7a1ddb89de8b1cd96e804af0a5e8162521f8ce2",  # Clevo variant 2
    "15dd51ef7e825ef358195b550f33f562cb39e9434703abc2a374c11dad3924bf",  # Epson test PK
    "40609809370258fe3c01aeb13a4496d0927457163fc21ed84c0caa3dede853f1"   # Aava Mobile test PK
)

# Minimum estimated SHA-256 hash count required to consider dbx current.
# Mirrors _AUDIT_DBX_MIN_HASHES=100 in audit.sh.
# EFI_SIGNATURE_LIST header = 28 bytes; each SHA-256 entry = 48 bytes.
$DBX_MIN_HASHES    = 100
$DBX_MIN_BYTES     = 28 + ($DBX_MIN_HASHES * 48)   # 4828

# 2026 Secure Boot certificate transition deadline (KB5062710).
$TARGET_2026 = [datetime]::new(2026, 6, 1, 0, 0, 0, [System.DateTimeKind]::Utc)

# Well-known cert descriptions (for the variable summary)
$KNOWN_CERT_NAMES = @{
    $MS_KEK_2011       = "Microsoft Corporation KEK CA 2011"
    $MS_KEK_2023       = "Microsoft Corporation KEK 2K CA 2023"
    $MS_UEFI_CA_2011   = "Microsoft Corporation UEFI CA 2011"
    $MS_WIN_PCA_2011   = "Microsoft Windows Production PCA 2011"
    $MS_OPTION_ROM_2023= "Microsoft Option ROM UEFI CA 2023"
    $MS_UEFI_CA_2023   = "Microsoft UEFI CA 2023"
    $WIN_UEFI_CA_2023  = "Windows UEFI CA 2023"
    $MS_OEM_DEVICES_PK = "Windows OEM Devices PK (Microsoft)"
}

foreach ($fp in $KNOWN_TEST_PKS) {
    if (-not $KNOWN_CERT_NAMES.ContainsKey($fp)) {
        $KNOWN_CERT_NAMES[$fp] = "KNOWN TEST / PLACEHOLDER KEY (insecure)"
    }
}

# ---------------------------------------------------------------------------
# Findings accumulator — mirrors AUDIT_FINDINGS in audit.sh.
# Each entry is a hashtable with keys: Severity, Component, Message.
# ---------------------------------------------------------------------------
$script:Findings     = [System.Collections.Generic.List[hashtable]]::new()
$script:PkValid      = $false
$script:PkIsTest     = $false
$script:DbHas2023    = $false
$script:DbxCurrent   = $false
$script:BootloaderPCA2011InUse = $false  # $true if PCA 2011 active in boot chain
$script:BootloaderScanSkipped  = $false  # $true if scan could not run

function Add-Finding {
    param(
        [ValidateSet("CRITICAL","HIGH","WARNING","INFO")]
        [string]$Severity,
        [string]$Component,
        [string]$Message
    )
    $script:Findings.Add(@{ Severity = $Severity; Component = $Component; Message = $Message })
}

# ---------------------------------------------------------------------------
# Get-CertSha256Fingerprint
#   Compute the SHA-256 fingerprint of an X509Certificate2's raw DER bytes
#   and return it as lowercase hex without separators — the same format used
#   in audit.sh and the known-certs/*.txt database files.
# ---------------------------------------------------------------------------
function Get-CertSha256Fingerprint {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($Cert.RawData)
        return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    } finally {
        $sha256.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Get-CertIcon
#   Return a short status tag and colour for a certificate's validity,
#   mirroring _report_cert_icon() in report.sh:
#     [OK]   — valid and not expiring before 2026-06-01
#     [WARN] — valid but expiring before 2026-06-01
#     [EXP]  — already expired
# ---------------------------------------------------------------------------
function Get-CertIcon {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $now = [datetime]::UtcNow
    if ($Cert.NotAfter.ToUniversalTime() -lt $now) {
        return @{ Label = "[EXP] "; Color = "Red" }
    }
    if ($Cert.NotAfter.ToUniversalTime() -lt $TARGET_2026) {
        return @{ Label = "[WARN]"; Color = "Yellow" }
    }
    return @{ Label = "[OK]  "; Color = "Green" }
}

# ---------------------------------------------------------------------------
# Get-EfiVarBytes
#   Retrieve raw bytes for an EFI Secure Boot variable via Get-SecureBootUEFI.
#   Returns $null if the variable is absent or unreadable.
# ---------------------------------------------------------------------------
function Get-EfiVarBytes {
    param([string]$VarName)
    try {
        $result = Get-SecureBootUEFI -Name $VarName -ErrorAction Stop
        return [byte[]]$result.bytes
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Get-X509CertsFromEfiVar
#   Parse an EFI_SIGNATURE_LIST byte array and extract all X509 DER
#   certificates.  Returns an array of X509Certificate2 objects.
#   Mirrors the parsing logic in efivar_extract_certs() (efivar.sh) and the
#   existing parsing loop in the original SecureBootChecker.ps1.
#   EFI_SIGNATURE_LIST layout:
#     [0..15]  SignatureType GUID
#     [16..19] SignatureListSize (uint32 LE)
#     [20..23] SignatureHeaderSize (uint32 LE)
#     [24..27] SignatureSize (uint32 LE)
#     [28..]   SignatureHeader + Array of EFI_SIGNATURE_DATA
#   EFI_SIGNATURE_DATA layout (per entry of size SignatureSize):
#     [0..15]  SignatureOwner GUID
#     [16..]   SignatureData (DER cert for X509 type)
# ---------------------------------------------------------------------------
$EFI_GUID_X509  = [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
$EFI_GUID_SHA256 = [Guid]"c1c41626-504c-4092-aca9-41f936934328"

function Get-X509CertsFromEfiVar {
    param([byte[]]$Bytes)
    $certs = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $certs }

    $offset = 0
    while ($offset + 28 -le $Bytes.Length) {
        $sigTypeGuid  = [Guid]::new([byte[]]$Bytes[$offset..($offset + 15)])
        $listSize     = [BitConverter]::ToUInt32($Bytes, $offset + 16)
        $headerSize   = [BitConverter]::ToUInt32($Bytes, $offset + 20)
        $sigSize      = [BitConverter]::ToUInt32($Bytes, $offset + 24)

        if ($listSize -lt 28 -or ($offset + $listSize) -gt $Bytes.Length) { break }

        if ($sigTypeGuid -eq $EFI_GUID_X509 -and $sigSize -gt 16) {
            $dataOffset = $offset + 28 + $headerSize
            $endOfList  = $offset + $listSize
            while ($dataOffset + $sigSize -le $endOfList) {
                $certBytes = [byte[]]$Bytes[($dataOffset + 16)..($dataOffset + $sigSize - 1)]
                try {
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                    $certs.Add($cert)
                } catch { <# skip unparseable entries #> }
                $dataOffset += $sigSize
            }
        }

        $offset += $listSize
    }
    return $certs
}

# ---------------------------------------------------------------------------
# Count-Sha256HashesInDbx
#   Count the estimated number of SHA-256 hash entries across all
#   EFI_SIGNATURE_LIST entries with type EFI_CERT_SHA256_GUID.
#   Mirrors the raw-size heuristic in audit_dbx() (audit.sh) but is more
#   precise by actually parsing the signature lists.
# ---------------------------------------------------------------------------
function Count-Sha256HashesInDbx {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return 0 }

    $total  = 0
    $offset = 0
    while ($offset + 28 -le $Bytes.Length) {
        $sigTypeGuid = [Guid]::new([byte[]]$Bytes[$offset..($offset + 15)])
        $listSize    = [BitConverter]::ToUInt32($Bytes, $offset + 16)
        $headerSize  = [BitConverter]::ToUInt32($Bytes, $offset + 20)
        $sigSize     = [BitConverter]::ToUInt32($Bytes, $offset + 24)

        if ($listSize -lt 28 -or ($offset + $listSize) -gt $Bytes.Length) { break }

        if ($sigTypeGuid -eq $EFI_GUID_SHA256 -and $sigSize -gt 0) {
            $payloadSize = $listSize - 28 - $headerSize
            if ($payloadSize -gt 0 -and $sigSize -gt 0) {
                $total += [math]::Floor($payloadSize / $sigSize)
            }
        }
        $offset += $listSize
    }
    return $total
}

# ---------------------------------------------------------------------------
# Invoke-AuditPk — mirrors audit_pk() in audit.sh
# ---------------------------------------------------------------------------
function Invoke-AuditPk {
    $bytes = Get-EfiVarBytes "PK"
    if ($null -eq $bytes -or $bytes.Length -eq 0) {
        Add-Finding "INFO" "PK" "PK is empty — system is in Setup Mode"
        $script:PkValid  = $false
        $script:PkIsTest = $false
        return
    }

    $certs = @(Get-X509CertsFromEfiVar $bytes)
    if ($certs.Count -eq 0) {
        Add-Finding "WARNING" "PK" "No X509 certificates found in PK variable"
        $script:PkValid  = $false
        $script:PkIsTest = $false
        return
    }

    # Assume valid until proven otherwise (mirrors audit.sh)
    $script:PkValid  = $true
    $script:PkIsTest = $false

    if ($certs.Count -gt 1) {
        Add-Finding "INFO" "PK" "PK contains $($certs.Count) certificates (typically only one is expected)"
    }

    $now = [datetime]::UtcNow
    for ($i = 0; $i -lt $certs.Count; $i++) {
        $cert = $certs[$i]
        $fp   = Get-CertSha256Fingerprint $cert

        # Check for known test / placeholder PKs
        if ($KNOWN_TEST_PKS -contains $fp) {
            Add-Finding "CRITICAL" "PK" "PK certificate [$i] is a known test/placeholder key ($fp)"
            $script:PkIsTest = $true
            $script:PkValid  = $false
        }

        # Check expiry
        if ($cert.NotAfter.ToUniversalTime() -lt $now) {
            Add-Finding "HIGH" "PK" "PK certificate [$i] is expired (expired $($cert.NotAfter.ToString('yyyy-MM-dd')))"
            $script:PkValid = $false
        } elseif ($cert.NotAfter.ToUniversalTime() -lt $TARGET_2026) {
            Add-Finding "WARNING" "PK" "PK certificate [$i] expires $($cert.NotAfter.ToString('yyyy-MM-dd')) — may not survive 2026 update cycle"
        }

        # Ownership model
        $ownership = if ($fp -eq $MS_OEM_DEVICES_PK) { "microsoft" }
                     elseif ($KNOWN_TEST_PKS -contains $fp) { "test" }
                     else { "unknown/vendor" }
        Add-Finding "INFO" "PK" "Ownership model: $ownership (certificate [$i], fingerprint: $fp)"
    }
}

# ---------------------------------------------------------------------------
# Invoke-AuditKek — mirrors audit_kek() in audit.sh
# ---------------------------------------------------------------------------
function Invoke-AuditKek {
    $bytes = Get-EfiVarBytes "KEK"
    if ($null -eq $bytes -or $bytes.Length -eq 0) {
        Add-Finding "HIGH" "KEK" "KEK database is empty"
        return
    }

    $certs = @(Get-X509CertsFromEfiVar $bytes)
    if ($certs.Count -eq 0) {
        Add-Finding "WARNING" "KEK" "Failed to extract KEK certificates (variable present but no X509 entries)"
        return
    }

    $hasMsKek2023 = $false
    $hasMsKek2011 = $false
    $hasUserKek   = $false

    for ($i = 0; $i -lt $certs.Count; $i++) {
        $fp = Get-CertSha256Fingerprint $certs[$i]
        if     ($fp -eq $MS_KEK_2023) { $hasMsKek2023 = $true }
        elseif ($fp -eq $MS_KEK_2011) { $hasMsKek2011 = $true }
        else {
            # Any non-Microsoft KEK is treated as a user/OEM KEK
            $desc = if ($KNOWN_CERT_NAMES.ContainsKey($fp)) { $KNOWN_CERT_NAMES[$fp] } else { "(unknown, fingerprint: $fp)" }
            Add-Finding "INFO" "KEK" "Non-Microsoft KEK entry [$i]: $desc"
            $hasUserKek = $true
        }
    }

    # Only flag missing 2023 KEK when there is no user-owned KEK chain
    # (in custom-owner mode the user signs db/dbx with their own KEK)
    if (-not $hasMsKek2023 -and -not $hasUserKek) {
        Add-Finding "HIGH" "KEK" "Microsoft Production KEK 2023 is missing"
    }

    if ($hasMsKek2011 -and -not $hasMsKek2023) {
        Add-Finding "WARNING" "KEK" "Legacy Microsoft KEK (2011) present without 2023 replacement"
    }
}

# ---------------------------------------------------------------------------
# Invoke-AuditDb — mirrors audit_db() in audit.sh
# ---------------------------------------------------------------------------
function Invoke-AuditDb {
    $bytes = Get-EfiVarBytes "db"
    if ($null -eq $bytes -or $bytes.Length -eq 0) {
        Add-Finding "HIGH" "db" "Allowed signatures database (db) is empty"
        $script:DbHas2023 = $false
        return
    }

    $certs = @(Get-X509CertsFromEfiVar $bytes)
    if ($certs.Count -eq 0) {
        Add-Finding "WARNING" "db" "Failed to extract db certificates (variable present but no X509 entries)"
        $script:DbHas2023 = $false
        return
    }

    $hasWinPCA2011  = $false
    $hasAny2023     = $false
    $hasOnlyLegacy  = $true
    $now = [datetime]::UtcNow

    foreach ($cert in $certs) {
        $fp = Get-CertSha256Fingerprint $cert

        if ($fp -eq $MS_WIN_PCA_2011) { $hasWinPCA2011 = $true }

        if ($fp -eq $MS_UEFI_CA_2023 -or $fp -eq $WIN_UEFI_CA_2023 -or $fp -eq $MS_OPTION_ROM_2023) {
            $hasAny2023    = $true
            $hasOnlyLegacy = $false
        }

        # Check for expired entries
        if ($cert.NotAfter.ToUniversalTime() -lt $now) {
            $desc = if ($KNOWN_CERT_NAMES.ContainsKey($fp)) { $KNOWN_CERT_NAMES[$fp] } else { $fp }
            Add-Finding "WARNING" "db" "Expired certificate in db: $desc (expired $($cert.NotAfter.ToString('yyyy-MM-dd')))"
        }
    }

    if (-not $hasWinPCA2011) {
        Add-Finding "WARNING" "db" "Microsoft Windows Production PCA 2011 not found in db"
    }

    if ($hasAny2023) {
        $script:DbHas2023 = $true
    } else {
        $script:DbHas2023 = $false
        Add-Finding "HIGH" "db" "Microsoft UEFI CA 2023 certificates missing — required for 2026 readiness"
    }

    if ($hasOnlyLegacy -and $certs.Count -gt 0) {
        Add-Finding "HIGH" "db" "db has no 2023 Microsoft certificates (only pre-2023 entries) — not 2026-ready"
    }
}

# ---------------------------------------------------------------------------
# Invoke-AuditDbx — mirrors audit_dbx() in audit.sh
# ---------------------------------------------------------------------------
function Invoke-AuditDbx {
    $bytes = Get-EfiVarBytes "dbx"
    if ($null -eq $bytes -or $bytes.Length -eq 0) {
        Add-Finding "HIGH" "dbx" "Revocation list (dbx) is missing or empty"
        $script:DbxCurrent = $false
        return
    }

    $hashCount = Count-Sha256HashesInDbx $bytes
    if ($hashCount -lt $DBX_MIN_HASHES) {
        Add-Finding "HIGH" "dbx" "Revocation list missing or outdated (estimated $hashCount SHA-256 hashes, minimum $DBX_MIN_HASHES expected)"
        $script:DbxCurrent = $false
    } else {
        Add-Finding "INFO" "dbx" "Revocation list appears current ($hashCount SHA-256 hashes, $($bytes.Length) bytes)"
        $script:DbxCurrent = $true
    }
}

# ---------------------------------------------------------------------------
# Get-EspMountPoint
#   Returns the drive letter of the EFI System Partition, mounting it if
#   needed via mountvol.  Returns a two-element array: [string driveLetter,
#   bool weDidMount].  Returns $null on any failure; does not throw.
# ---------------------------------------------------------------------------
function Get-EspMountPoint {
    <#
    .SYNOPSIS
    Returns the drive letter of the EFI System Partition, mounting it if needed.
    Returns $null if it cannot be found or mounted.
    #>
    try {
        $partition = Get-Partition -ErrorAction SilentlyContinue |
            Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } |
            Select-Object -First 1
        if ($null -eq $partition) {
            Write-Verbose "Get-EspMountPoint: no ESP partition found via Get-Partition"
            return $null
        }

        # Already has a drive letter
        if ($partition.DriveLetter -and $partition.DriveLetter -ne "`0") {
            return @("$($partition.DriveLetter):", $false)
        }

        # Try to assign a free drive letter using mountvol
        $letterCode = 68..90 | Where-Object { -not (Test-Path "$([char]$_):\") } | Select-Object -First 1
        if ($null -eq $letterCode) {
            Write-Verbose "Get-EspMountPoint: no free drive letters available"
            return $null
        }
        $letter    = [char]$letterCode
        $letterStr = "${letter}:"
        $accessPath = ($partition.AccessPaths | Select-Object -First 1)
        if (-not $accessPath) {
            Write-Verbose "Get-EspMountPoint: partition has no AccessPaths"
            return $null
        }
        $mountOut = & mountvol "$letterStr\" $accessPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Verbose "Get-EspMountPoint: mountvol failed (exit $LASTEXITCODE): $mountOut"
            return $null
        }
        return @($letterStr, $true)
    } catch {
        Write-Verbose "Get-EspMountPoint: exception: $_"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Get-WindowsBootloaderPaths
#   Returns an array of [pscustomobject]@{Path; Description} for Windows EFI
#   bootloader binaries that actually exist on the system.
# ---------------------------------------------------------------------------
function Get-WindowsBootloaderPaths {
    <#
    .SYNOPSIS
    Returns existing Windows EFI bootloader paths from the ESP and System32.
    #>
    param([string]$EspDriveLetter)

    $candidates = @(
        @{ Path = "$EspDriveLetter\EFI\Microsoft\Boot\bootmgfw.efi"; Description = "Windows Boot Manager" }
        @{ Path = "$EspDriveLetter\EFI\Microsoft\Boot\bootmgr.efi";  Description = "Legacy Boot Manager" }
        @{ Path = "$EspDriveLetter\EFI\Microsoft\Boot\memtest.efi";  Description = "Memory Diagnostic" }
        @{ Path = "$env:SystemRoot\System32\winload.efi";             Description = "Windows OS Loader" }
        @{ Path = "$env:SystemRoot\System32\hvloader.efi";            Description = "Hyper-V Loader" }
        @{ Path = "$env:SystemRoot\System32\winresume.efi";           Description = "Windows Resume" }
    )

    $results = @()
    foreach ($c in $candidates) {
        if (Test-Path $c.Path) {
            $results += [pscustomobject]@{ Path = $c.Path; Description = $c.Description }
        } else {
            Write-Verbose "Get-WindowsBootloaderPaths: expected binary not found: $($c.Path)"
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
# Get-LinuxBootloaderPaths
#   Returns an array of [pscustomobject]@{Path; Description} for SHIM / GRUB /
#   fwupd EFI binaries found on the ESP outside the Microsoft directory.
# ---------------------------------------------------------------------------
function Get-LinuxBootloaderPaths {
    <#
    .SYNOPSIS
    Discovers Linux/SHIM EFI bootloader binaries on the ESP (excluding Microsoft).
    #>
    param([string]$EspDriveLetter)

    $results = @()
    try {
        $efiRoot = "$EspDriveLetter\EFI"
        if (-not (Test-Path $efiRoot)) { return $results }

        $allEfi = Get-ChildItem -Path $efiRoot -Recurse -Filter "*.efi" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -notmatch [regex]::Escape("$EspDriveLetter\EFI\Microsoft")
            }

        $namePatterns = @('shim', 'grub', 'fwupd', 'elilo', 'system-boot')
        foreach ($file in $allEfi) {
            $baseLower = $file.BaseName.ToLower()
            $match = $false
            foreach ($pat in $namePatterns) {
                if ($baseLower -like "$pat*" -or $baseLower -eq $pat) {
                    $match = $true
                    break
                }
            }
            if ($match) {
                $results += [pscustomobject]@{ Path = $file.FullName; Description = "Linux/SHIM EFI binary" }
            }
        }
    } catch {
        Write-Verbose "Get-LinuxBootloaderPaths: exception: $_"
    }
    return $results
}

# ---------------------------------------------------------------------------
# Get-EfiBinarySignerCAs
#   Returns an array of X509Certificate2 objects representing all certificates
#   in the Authenticode signing chain of an EFI binary.  Returns an empty
#   array on any failure.
# ---------------------------------------------------------------------------
function Get-EfiBinarySignerCAs {
    <#
    .SYNOPSIS
    Returns all certificates in the Authenticode signing chain of an EFI binary.
    Returns an empty array on failure.
    #>
    param([string]$FilePath)

    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($sig.Status -eq 'NotSigned' -or $null -eq $sig.SignerCertificate) {
            Write-Verbose "Get-EfiBinarySignerCAs: $FilePath is not signed or has no signer certificate"
            return @()
        }

        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.Build($sig.SignerCertificate) | Out-Null
        return @($chain.ChainElements | ForEach-Object { $_.Certificate })
    } catch {
        Write-Verbose "Get-EfiBinarySignerCAs: exception for ${FilePath}: $_"
        return @()
    }
}

# ---------------------------------------------------------------------------
# Test-SignedByPCA2011
#   Returns $true  if any cert in the signing chain matches $MS_WIN_PCA_2011.
#   Returns $false if the chain was inspected and PCA 2011 was not found.
#   Returns $null  if the signing chain could not be inspected.
# ---------------------------------------------------------------------------
function Test-SignedByPCA2011 {
    <#
    .SYNOPSIS
    Tests whether an EFI binary's signing chain includes Microsoft Windows
    Production PCA 2011.  Returns $true/$false/$null (unknown).
    #>
    param([string]$FilePath)

    $certs = Get-EfiBinarySignerCAs -FilePath $FilePath
    if ($certs.Count -eq 0) { return $null }

    foreach ($cert in $certs) {
        $fp = Get-CertSha256Fingerprint $cert
        if ($fp -eq $MS_WIN_PCA_2011) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Get-EfiBinarySigningCAName
#   Returns a human-readable string describing the highest issuer CA found in
#   the signing chain, using $KNOWN_CERT_NAMES if the fingerprint is
#   recognized, otherwise the Issuer DN of the last (root) certificate.
# ---------------------------------------------------------------------------
function Get-EfiBinarySigningCAName {
    <#
    .SYNOPSIS
    Returns a human-readable CA name for the root/issuer of an EFI binary's
    signing chain.
    #>
    param([string]$FilePath)

    $certs = Get-EfiBinarySignerCAs -FilePath $FilePath
    if ($certs.Count -eq 0) { return "(unknown — chain not available)" }

    # Walk from root (last element) looking for a known fingerprint
    for ($i = $certs.Count - 1; $i -ge 0; $i--) {
        $fp = Get-CertSha256Fingerprint $certs[$i]
        if ($KNOWN_CERT_NAMES.ContainsKey($fp)) {
            return $KNOWN_CERT_NAMES[$fp]
        }
    }
    # Fall back to Issuer of the last cert in the chain
    $root = $certs[$certs.Count - 1]
    return $root.Issuer
}

# ---------------------------------------------------------------------------
# Invoke-AuditBootloaderChain
#   Mirrors audit_bootloader_chain_ca() in bootloader-scan.sh (bash).
#   Scans EFI binaries in the Windows and Linux boot chains for PCA 2011
#   signing. Adds findings to $script:Findings.
# ---------------------------------------------------------------------------
function Invoke-AuditBootloaderChain {
    <#
    .SYNOPSIS
    Scans EFI bootloader binaries for Microsoft Windows Production PCA 2011
    signing and adds findings to the global findings list.
    #>

    $espInfo = Get-EspMountPoint
    if ($null -eq $espInfo) {
        Add-Finding "WARNING" "bootloader" "Could not locate or mount EFI System Partition — bootloader CA scan skipped"
        $script:BootloaderScanSkipped = $true
        return
    }

    $esp       = $espInfo[0]
    $weDidMount = $espInfo[1]

    try {
        $windowsPaths = @(Get-WindowsBootloaderPaths -EspDriveLetter $esp)
        $linuxPaths   = @(Get-LinuxBootloaderPaths   -EspDriveLetter $esp)
        $allPaths     = $windowsPaths + $linuxPaths

        if ($allPaths.Count -eq 0) {
            Add-Finding "WARNING" "bootloader" "No EFI bootloader binaries found on ESP — scan inconclusive"
            $script:BootloaderScanSkipped = $true
            return
        }

        $pca2011Found = $false
        $scanFailed   = $false
        $scanCount    = 0

        foreach ($entry in $allPaths) {
            $result = Test-SignedByPCA2011 -FilePath $entry.Path
            if ($null -eq $result) {
                Add-Finding "WARNING" "bootloader" "Could not inspect signing certificate for: $($entry.Description) ($($entry.Path))"
                $scanFailed = $true
                continue
            }
            $scanCount++
            $caName = Get-EfiBinarySigningCAName -FilePath $entry.Path
            if ($result -eq $true) {
                Add-Finding "HIGH" "bootloader" (
                    "Bootloader '$($entry.Description)' is signed by Microsoft Windows Production PCA 2011 — " +
                    "DBX2024 CA revocation must NOT be applied until Windows is updated. " +
                    "Install KB5062710 or later via Windows Update to migrate to Windows UEFI CA 2023."
                )
                $pca2011Found = $true
            } else {
                Add-Finding "INFO" "bootloader" "$($entry.Description): signed by $caName (not PCA 2011 — OK)"
            }
        }

        if ($pca2011Found) {
            Add-Finding "HIGH" "bootloader" (
                "ACTION REQUIRED: One or more Windows boot binaries are still signed by the deprecated " +
                "Microsoft Windows Production PCA 2011 certificate. " +
                "Do NOT apply the DBX2024 optional Secure Boot update until after running Windows Update " +
                "and confirming all boot binaries are re-signed with Windows UEFI CA 2023. " +
                "See: https://support.microsoft.com/kb/5062710"
            )
            $script:BootloaderPCA2011InUse = $true
        } elseif ($scanFailed -and $scanCount -eq 0) {
            # Every binary failed inspection (none succeeded); treat as unsafe
            # (fail-safe: if we could not verify any binary, do not permit DBX2024)
            Add-Finding "WARNING" "bootloader" "Bootloader CA scan failed for all binaries — DBX2024 applicability unknown (treat as unsafe)"
            $script:BootloaderPCA2011InUse = $true  # fail-safe
        } else {
            Add-Finding "INFO" "bootloader" (
                "All scanned bootloaders ($scanCount) use post-2023 Microsoft CA signing. " +
                "DBX2024 PCA 2011 CA revocation can be applied safely."
            )
            $script:BootloaderPCA2011InUse = $false
        }
    } finally {
        if ($weDidMount) {
            try {
                & mountvol "$esp\" /D 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Verbose "Invoke-AuditBootloaderChain: mountvol /D exited with code $LASTEXITCODE for $esp"
                }
            } catch {
                Write-Verbose "Invoke-AuditBootloaderChain: failed to unmount ${esp}: $_"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Invoke-AuditAll — mirrors audit_run_all() / audit_2026_ready() in audit.sh
# ---------------------------------------------------------------------------
function Invoke-AuditAll {
    $script:Findings.Clear()
    $script:PkValid               = $false
    $script:PkIsTest              = $false
    $script:DbHas2023             = $false
    $script:DbxCurrent            = $false
    $script:BootloaderPCA2011InUse = $false
    $script:BootloaderScanSkipped  = $false

    Invoke-AuditPk
    Invoke-AuditKek
    Invoke-AuditDb
    Invoke-AuditDbx
    Invoke-AuditBootloaderChain

    # Composite 2026-readiness verdict (mirrors audit_2026_ready())
    # Note: $script:BootloaderPCA2011InUse is checked separately below. A system
    # can be '2026-ready' (PK/db/dbx in correct state) and yet still have DBX2024
    # blocked because Windows boot binaries are still signed by PCA 2011. These
    # are independent conditions: the 2026-readiness verdict covers variable state,
    # while DBX2024 BLOCKED covers whether applying the optional CA revocation is
    # safe for the current boot chain.
    $ready = $script:PkValid -and (-not $script:PkIsTest) -and $script:DbHas2023 -and $script:DbxCurrent
    if ($ready) {
        Add-Finding "INFO" "2026-readiness" "System is 2026-ready"
    } else {
        Add-Finding "INFO" "2026-readiness" "System is NOT 2026-ready"
        if (-not $script:PkValid)    { Add-Finding "HIGH" "2026-readiness" "PK-invalid" }
        if ($script:PkIsTest)        { Add-Finding "HIGH" "2026-readiness" "PK-is-test-key" }
        if (-not $script:DbHas2023)  { Add-Finding "HIGH" "2026-readiness" "db-missing-2023-certs" }
        if (-not $script:DbxCurrent) { Add-Finding "HIGH" "2026-readiness" "dbx-outdated" }
    }

    # Bootloader PCA 2011 verdict — separate from core readiness, blocks DBX2024 update
    if ($script:BootloaderPCA2011InUse) {
        $script:Findings.Add(@{
            Severity  = "HIGH"
            Component = "2026-readiness"
            Message   = "DBX2024 BLOCKED: Windows boot binaries still signed by PCA 2011. " +
                        "Apply Windows Update (KB5062710) before applying DBX2024."
        })
    }

    return $ready
}

# ---------------------------------------------------------------------------
# Invoke-AuditDefaultVars
#   Reads PKDefault, KEKDefault, dbDefault, dbxDefault and runs the same
#   certificate checks used by Invoke-AuditPk/Kek/Db/Dbx against them.
#   Returns a hashtable describing what the BIOS defaults contain and whether
#   restoring them would be safe / improve / maintain / break 2026 readiness.
#
#   Returned hashtable keys:
#     HasAnyDefaults  — at least one *Default variable is present
#     Pk              — hashtable: Present, IsTest, IsExpired, ExpiresBefore2026, Fingerprints
#     Kek             — hashtable: CertCount, HasMs2023, HasMs2011Only, HasUserKek
#     Db              — hashtable: CertCount, Has2023, HasOnlyLegacy, HasExpired
#     Dbx             — hashtable: Present, HashCount, IsCurrent
#     DefaultsReady   — bool: would the defaults pass the 2026-readiness check?
#     SafetyVerdict   — string: "SAFE" | "CAUTION" | "UNSAFE" | "UNKNOWN"
#     SafetyReasons   — string[]: human-readable bullets explaining the verdict
# ---------------------------------------------------------------------------
function Invoke-AuditDefaultVars {
    $result = @{
        HasAnyDefaults = $false
        Pk  = @{ Present = $false; IsTest = $false; IsExpired = $false; ExpiresBefore2026 = $false; Fingerprints = @() }
        Kek = @{ CertCount = 0; HasMs2023 = $false; HasMs2011Only = $false; HasUserKek = $false }
        Db  = @{ CertCount = 0; Has2023 = $false; HasOnlyLegacy = $true; HasExpired = $false }
        Dbx = @{ Present = $false; HashCount = 0; IsCurrent = $false }
        DefaultsReady = $false
        SafetyVerdict = "UNKNOWN"
        SafetyReasons = [System.Collections.Generic.List[string]]::new()
    }

    $now = [datetime]::UtcNow

    # --- PKDefault ---
    $pkBytes = Get-EfiVarBytes "PKDefault"
    if ($pkBytes -and $pkBytes.Length -gt 0) {
        $result.HasAnyDefaults = $true
        $result.Pk.Present = $true
        $certs = @(Get-X509CertsFromEfiVar $pkBytes)
        foreach ($cert in $certs) {
            $fp = Get-CertSha256Fingerprint $cert
            $result.Pk.Fingerprints += $fp
            if ($KNOWN_TEST_PKS -contains $fp)                           { $result.Pk.IsTest = $true }
            if ($cert.NotAfter.ToUniversalTime() -lt $now)               { $result.Pk.IsExpired = $true }
            if ($cert.NotAfter.ToUniversalTime() -lt $TARGET_2026)       { $result.Pk.ExpiresBefore2026 = $true }
        }
    }

    # --- KEKDefault ---
    $kekBytes = Get-EfiVarBytes "KEKDefault"
    if ($kekBytes -and $kekBytes.Length -gt 0) {
        $result.HasAnyDefaults = $true
        $certs = @(Get-X509CertsFromEfiVar $kekBytes)
        $result.Kek.CertCount = $certs.Count
        $hasMs2023 = $false; $hasMs2011 = $false; $hasUser = $false
        foreach ($cert in $certs) {
            $fp = Get-CertSha256Fingerprint $cert
            if     ($fp -eq $MS_KEK_2023) { $hasMs2023 = $true }
            elseif ($fp -eq $MS_KEK_2011) { $hasMs2011 = $true }
            else                          { $hasUser   = $true }
        }
        $result.Kek.HasMs2023    = $hasMs2023
        $result.Kek.HasMs2011Only = ($hasMs2011 -and -not $hasMs2023)
        $result.Kek.HasUserKek   = $hasUser
    }

    # --- dbDefault ---
    $dbBytes = Get-EfiVarBytes "dbDefault"
    if ($dbBytes -and $dbBytes.Length -gt 0) {
        $result.HasAnyDefaults = $true
        $certs = @(Get-X509CertsFromEfiVar $dbBytes)
        $result.Db.CertCount = $certs.Count
        $has2023 = $false; $onlyLegacy = $true
        foreach ($cert in $certs) {
            $fp = Get-CertSha256Fingerprint $cert
            if ($fp -eq $MS_UEFI_CA_2023 -or $fp -eq $WIN_UEFI_CA_2023 -or $fp -eq $MS_OPTION_ROM_2023) {
                $has2023   = $true
                $onlyLegacy = $false
            }
            if ($cert.NotAfter.ToUniversalTime() -lt $now) { $result.Db.HasExpired = $true }
        }
        $result.Db.Has2023      = $has2023
        $result.Db.HasOnlyLegacy = $onlyLegacy
    }

    # --- dbxDefault ---
    $dbxBytes = Get-EfiVarBytes "dbxDefault"
    if ($dbxBytes -and $dbxBytes.Length -gt 0) {
        $result.HasAnyDefaults = $true
        $result.Dbx.Present   = $true
        $count = Count-Sha256HashesInDbx $dbxBytes
        $result.Dbx.HashCount  = $count
        $result.Dbx.IsCurrent  = ($count -ge $DBX_MIN_HASHES)
    }

    if (-not $result.HasAnyDefaults) {
        $result.SafetyVerdict = "UNKNOWN"
        $result.SafetyReasons.Add("No *Default UEFI variables found — BIOS may not expose them, or this firmware does not store factory defaults separately.")
        return $result
    }

    # Defaults 2026-readiness:
    #   PK present and not a test key AND KEK ok AND db has 2023 certs AND dbx is current
    #   (KEK user-chain is acceptable, same logic as Invoke-AuditKek)
    $defaultPkOk  = $result.Pk.Present -and (-not $result.Pk.IsTest) -and (-not $result.Pk.IsExpired)
    $defaultKekOk = $result.Kek.HasMs2023 -or $result.Kek.HasUserKek -or ($result.Kek.CertCount -eq 0)  # absent defaults = unchanged
    $defaultDbOk  = $result.Db.Has2023
    $defaultDbxOk = $result.Dbx.IsCurrent
    $result.DefaultsReady = $defaultPkOk -and $defaultKekOk -and $defaultDbOk -and $defaultDbxOk

    # Safety verdict logic:
    #   UNSAFE   — defaults would install a known test/placeholder PK
    #   CAUTION  — defaults would remove 2023 certs already present in live db/KEK, OR dbx would regress
    #   SAFE     — defaults meet 2026-readiness on their own
    #   CAUTION  — defaults are not 2026-ready but current state also isn't (no regression)

    $reasons = $result.SafetyReasons

    if ($result.Pk.IsTest) {
        $result.SafetyVerdict = "UNSAFE"
        $reasons.Add("Restoring Secure Boot defaults would replace your Platform Key (PK) with a known test/placeholder key whose private key is publicly known or widely distributed among OEMs. This would make Secure Boot non-functional as a security boundary — any attacker could sign arbitrary boot code.")
    }

    if ($result.Pk.IsExpired) {
        if ($result.SafetyVerdict -ne "UNSAFE") { $result.SafetyVerdict = "UNSAFE" }
        $reasons.Add("Restoring Secure Boot defaults would install an expired Platform Key (PK) from PKDefault. An expired PK may be rejected by firmware and would prevent any further authenticated Secure Boot variable updates.")
    }

    # Would restore degrade 2023 db coverage that the live system already has?
    $liveDbHas2023 = $script:DbHas2023
    if ($liveDbHas2023 -and -not $result.Db.Has2023) {
        if ($result.SafetyVerdict -notin @("UNSAFE")) { $result.SafetyVerdict = "CAUTION" }
        $reasons.Add("Restoring Secure Boot defaults would replace your current db (allowed signatures database) with dbDefault, which does not contain the 2023 Microsoft UEFI CA certificates. Your system is currently 2026-ready for db; restoring defaults would break that and require re-applying the latest Microsoft update to regain 2026 readiness.")
    }

    # Would restore degrade dbx coverage?
    $liveDbxCurrent = $script:DbxCurrent
    if ($liveDbxCurrent -and -not $result.Dbx.IsCurrent) {
        if ($result.SafetyVerdict -notin @("UNSAFE")) { $result.SafetyVerdict = "CAUTION" }
        if ($result.Dbx.Present) {
            $reasons.Add("Restoring Secure Boot defaults would replace your current dbx (revocation list, $($script:Findings | Where-Object {$_.Component -eq 'dbx' -and $_.Severity -eq 'INFO'} | Select-Object -First 1 -ExpandProperty Message)) with dbxDefault, which contains only $($result.Dbx.HashCount) SHA-256 revocation hashes (minimum expected: $DBX_MIN_HASHES). This would remove revocations for known-vulnerable bootloaders and make the system easier to compromise via boot-level malware. To recover, re-run the latest monthly Windows Update security package — Microsoft publishes dbx updates through Windows Update (see KB5062710) which will restore a current revocation list. Alternatively, the SB-ENEMA tool can install all latest dbx entries directly from the live image without requiring a Windows Update cycle.")
        } else {
            $reasons.Add("Restoring Secure Boot defaults would clear your dbx (revocation list) entirely — dbxDefault is absent or empty. Without a revocation list, previously revoked and known-vulnerable bootloaders (including older Windows Boot Manager versions) would be permitted to run, undermining Secure Boot's security guarantees. To recover, re-run the latest monthly Windows Update security package — Microsoft publishes dbx updates through Windows Update (see KB5062710 and successors) which will populate a current revocation list. Alternatively, the SB-ENEMA tool can install all latest dbx entries directly from the live image without requiring a Windows Update cycle.")
        }
    }

    # Would KEK 2023 be lost?
    # Only flag if live system has MS KEK 2023 and defaults don't (and no user KEK in defaults)
    if ($script:Findings | Where-Object { $_.Component -eq 'KEK' -and $_.Message -notlike '*missing*' }) {
        # live KEK appears OK; check if defaults would lose Ms2023
        if ($result.Kek.CertCount -gt 0 -and -not $result.Kek.HasMs2023 -and -not $result.Kek.HasUserKek) {
            if ($result.SafetyVerdict -notin @("UNSAFE")) { $result.SafetyVerdict = "CAUTION" }
            $reasons.Add("Restoring Secure Boot defaults would replace your KEK database with KEKDefault, which does not include the Microsoft Corporation KEK 2K CA 2023 certificate. Without this KEK, your firmware cannot authenticate future Microsoft dbx revocation updates delivered via Windows Update (see KB5037036 and successors), leaving the revocation list stuck at its current state.")
        }
    }

    # If still UNKNOWN or no bad reasons found, decide SAFE vs CAUTION based on defaults readiness
    if ($result.SafetyVerdict -eq "UNKNOWN") {
        if ($result.DefaultsReady) {
            $result.SafetyVerdict = "SAFE"
            $reasons.Add("Restoring Secure Boot defaults appears safe: the default variables (PKDefault, KEKDefault, dbDefault, dbxDefault) independently pass the 2026-readiness check. You can restore factory keys without losing 2026 Secure Boot compliance.")
        } else {
            $result.SafetyVerdict = "CAUTION"
            $reasons.Add("Restoring Secure Boot defaults would leave the system in a state that does not independently meet 2026-readiness criteria. The default variables are missing one or more required 2023 Microsoft certificates or an up-to-date revocation list.")
        }
    } elseif ($result.SafetyVerdict -eq "SAFE") {
        # already set above — no extra reason needed
    } elseif ($reasons.Count -eq 0) {
        $reasons.Add("Restoring Secure Boot defaults appears safe based on the information available, but the default variables could not be fully verified. Proceed with caution.")
    }

    return $result
}

# ---------------------------------------------------------------------------
# Write-DefaultsVariableSummary
#   Display the certificate contents of each *Default variable.
#   Called alongside Write-VariableSummary so both summaries appear together.
# ---------------------------------------------------------------------------
function Write-DefaultsVariableSummary {
    param([hashtable]$Audit)

    Write-SectionHr
    Write-Host "  BIOS Default Variable Summary (PKDefault / KEKDefault / dbDefault / dbxDefault)" -ForegroundColor White
    Write-SectionHr
    Write-Host ""

    if (-not $Audit.HasAnyDefaults) {
        Write-Host "  [INFO] " -ForegroundColor Gray -NoNewline
        Write-Host "No *Default UEFI variables found." -ForegroundColor White
        Write-Host "         Your firmware may not expose PKDefault/KEKDefault/dbDefault/dbxDefault," -ForegroundColor DarkGray
        Write-Host "         or 'Restore Factory Keys' resets to OEM values stored elsewhere in flash." -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    foreach ($varName in @("PKDefault", "KEKDefault", "dbDefault", "dbxDefault")) {
        $bytes = Get-EfiVarBytes $varName
        if ($null -eq $bytes -or $bytes.Length -eq 0) {
            Write-Host "  $varName" -ForegroundColor White -NoNewline
            Write-Host ": (not present / empty)" -ForegroundColor DarkGray
            Write-Host ""
            continue
        }

        $certs = @(Get-X509CertsFromEfiVar $bytes)
        Write-Host "  $varName ($($certs.Count) certificate(s))" -ForegroundColor White

        for ($i = 0; $i -lt $certs.Count; $i++) {
            $cert  = $certs[$i]
            $fp    = Get-CertSha256Fingerprint $cert
            $icon  = Get-CertIcon $cert
            $known = if ($KNOWN_CERT_NAMES.ContainsKey($fp)) { $KNOWN_CERT_NAMES[$fp] } else { $null }
            $subj  = $cert.Subject
            $exp   = $cert.NotAfter.ToString("yyyy-MM-dd")

            Write-Host "    [$i] " -NoNewline
            Write-Host $icon.Label -ForegroundColor $icon.Color -NoNewline
            Write-Host " $subj"
            Write-Host "        Expires: $exp" -ForegroundColor DarkCyan
            if ($known) {
                Write-Host "        Known:   " -NoNewline -ForegroundColor DarkCyan
                Write-Host $known -ForegroundColor Green
            } else {
                Write-Host "        Known:   (not in known-certs database)" -ForegroundColor DarkGray
            }
        }

        if ($varName -eq "dbxDefault") {
            $hashCount = Count-Sha256HashesInDbx $bytes
            Write-Host "  dbxDefault also contains: $hashCount SHA-256 hash entries ($($bytes.Length) bytes total)" -ForegroundColor DarkGray
        }

        Write-Host ""
    }
}

# ---------------------------------------------------------------------------
# Write-DefaultsVerdict
#   Display the Restore Factory Keys safety verdict and verbose reasons.
#   Called after Write-Findings and Write-ReadinessBanner.
# ---------------------------------------------------------------------------
function Write-DefaultsVerdict {
    param([hashtable]$Audit)

    Write-SectionHr
    Write-Host "  Restore Factory Keys — Safety Verdict" -ForegroundColor White
    Write-SectionHr
    Write-Host ""

    if (-not $Audit.HasAnyDefaults) {
        Write-Host "  [INFO] No *Default UEFI variables were found; cannot assess restore safety." -ForegroundColor Gray
        Write-Host ""
        return
    }

    $verdictColor = switch ($Audit.SafetyVerdict) {
        "SAFE"    { "Green"  }
        "CAUTION" { "Yellow" }
        "UNSAFE"  { "Red"    }
        default   { "Gray"   }
    }

    $verdictLabel = switch ($Audit.SafetyVerdict) {
        "SAFE"    { "  |  OK  SAFE TO RESTORE                     |" }
        "CAUTION" { "  |  !!  RESTORE WITH CAUTION                |" }
        "UNSAFE"  { "  |  XX  DO NOT RESTORE — UNSAFE             |" }
        default   { "  |  ??  CANNOT DETERMINE SAFETY             |" }
    }

    Write-Host "  +------------------------------------------+" -ForegroundColor $verdictColor
    Write-Host $verdictLabel                                       -ForegroundColor $verdictColor
    Write-Host "  +------------------------------------------+" -ForegroundColor $verdictColor
    Write-Host ""

    $defaultsReadyLabel = if ($Audit.DefaultsReady) { "YES" } else { "NO" }
    $defaultsReadyColor = if ($Audit.DefaultsReady) { "Green" } else { "Red" }
    Write-Host "  Defaults are 2026-ready independently: " -NoNewline
    Write-Host $defaultsReadyLabel -ForegroundColor $defaultsReadyColor
    Write-Host ""

    Write-Host "  What restoring Secure Boot defaults would mean for this system:" -ForegroundColor White
    Write-Host ""
    $idx = 1
    foreach ($reason in $Audit.SafetyReasons) {
        # Word-wrap at 74 chars for readability
        $words = $reason -split ' '
        $line  = "    $idx. "
        $indent = "       "
        foreach ($word in $words) {
            if (($line + $word).Length -gt 78) {
                Write-Host $line -ForegroundColor $verdictColor
                $line = $indent + $word + ' '
            } else {
                $line += $word + ' '
            }
        }
        if ($line.Trim()) { Write-Host $line.TrimEnd() -ForegroundColor $verdictColor }
        Write-Host ""
        $idx++
    }
}

# ---------------------------------------------------------------------------
# Write-SectionHr / Write-Hr — visual separators mirroring report.sh
# ---------------------------------------------------------------------------
function Write-Hr { Write-Host ("=" * 80) }
function Write-SectionHr { Write-Host ("-" * 80) }

# ---------------------------------------------------------------------------
# Write-VariableSummary
#   For each Secure Boot variable (PK, KEK, db, dbx), list the X509
#   certificates with subject, issuer, expiry, status icon, and known-cert
#   identification.  Mirrors report_variable_summary() in report.sh.
# ---------------------------------------------------------------------------
function Write-VariableSummary {
    Write-SectionHr
    Write-Host "  Variable Summary" -ForegroundColor White
    Write-SectionHr
    Write-Host ""

    foreach ($varName in @("PK", "KEK", "db", "dbx")) {
        $bytes = Get-EfiVarBytes $varName

        if ($null -eq $bytes -or $bytes.Length -eq 0) {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
            Write-Host "${varName}: (empty)" -ForegroundColor White
            Write-Host ""
            continue
        }

        $certs = @(Get-X509CertsFromEfiVar $bytes)
        Write-Host "  $varName ($($certs.Count) certificate(s))" -ForegroundColor White

        for ($i = 0; $i -lt $certs.Count; $i++) {
            $cert  = $certs[$i]
            $fp    = Get-CertSha256Fingerprint $cert
            $icon  = Get-CertIcon $cert
            $known = if ($KNOWN_CERT_NAMES.ContainsKey($fp)) { $KNOWN_CERT_NAMES[$fp] } else { $null }
            $subj  = $cert.Subject
            $iss   = $cert.Issuer
            $exp   = $cert.NotAfter.ToString("yyyy-MM-dd")

            Write-Host "    [$i] " -NoNewline
            Write-Host $icon.Label -ForegroundColor $icon.Color -NoNewline
            Write-Host " $subj"
            Write-Host "        Issuer:  $iss" -ForegroundColor DarkCyan
            Write-Host "        Expires: $exp" -ForegroundColor DarkCyan
            if ($known) {
                Write-Host "        Known:   " -NoNewline -ForegroundColor DarkCyan
                Write-Host $known -ForegroundColor Green
            } else {
                Write-Host "        Known:   (not in known-certs database)" -ForegroundColor DarkGray
            }
        }

        # For dbx: also report SHA-256 hash count
        if ($varName -eq "dbx") {
            $hashCount = Count-Sha256HashesInDbx $bytes
            Write-Host "  dbx also contains: $hashCount SHA-256 hash entries ($($bytes.Length) bytes total)" -ForegroundColor DarkGray
        }

        Write-Host ""
    }
}

# ---------------------------------------------------------------------------
# Write-Findings
#   Display audit findings grouped by severity (CRITICAL, HIGH, WARNING, INFO).
#   Mirrors report_findings() in report.sh.
# ---------------------------------------------------------------------------
function Write-Findings {
    Write-SectionHr
    Write-Host "  Audit Findings" -ForegroundColor White
    Write-SectionHr
    Write-Host ""

    if ($script:Findings.Count -eq 0) {
        Write-Host "  No findings." -ForegroundColor Green
        Write-Host ""
        return
    }

    foreach ($sev in @("CRITICAL", "HIGH", "WARNING", "INFO")) {
        $sevFindings = $script:Findings | Where-Object { $_.Severity -eq $sev }
        if (-not $sevFindings) { continue }

        $color = switch ($sev) {
            "CRITICAL" { "Red" }
            "HIGH"     { "Red" }
            "WARNING"  { "Yellow" }
            default    { "Gray" }
        }

        foreach ($f in $sevFindings) {
            Write-Host "  [$sev] " -ForegroundColor $color -NoNewline
            Write-Host "$($f.Component): " -ForegroundColor White -NoNewline
            Write-Host $f.Message -ForegroundColor $color
        }
        Write-Host ""
    }
}

# ---------------------------------------------------------------------------
# Write-BootloaderFindings
#   Display bootloader certificate chain analysis findings under a dedicated
#   heading, separate from the general findings list.
# ---------------------------------------------------------------------------
function Write-BootloaderFindings {
    <#
    .SYNOPSIS
    Prints bootloader CA findings grouped under a dedicated section heading.
    #>
    Write-SectionHr
    Write-Host "  Bootloader Certificate Chain Analysis" -ForegroundColor White
    Write-SectionHr
    Write-Host ""

    if ($script:BootloaderScanSkipped) {
        Write-Host "  (Bootloader scan was skipped — run as Administrator with the EFI System Partition accessible)" -ForegroundColor Yellow
        Write-Host ""
    }

    $bootFindings = @($script:Findings | Where-Object { $_.Component -eq "bootloader" })
    if ($bootFindings.Count -eq 0) {
        Write-Host "  No bootloader findings." -ForegroundColor Green
        Write-Host ""
        return
    }

    foreach ($sev in @("CRITICAL", "HIGH", "WARNING", "INFO")) {
        $sevFindings = @($bootFindings | Where-Object { $_.Severity -eq $sev })
        if ($sevFindings.Count -eq 0) { continue }

        $color = switch ($sev) {
            "CRITICAL" { "Red" }
            "HIGH"     { "Red" }
            "WARNING"  { "Yellow" }
            default    { "Gray" }
        }

        foreach ($f in $sevFindings) {
            Write-Host "  [$sev] " -ForegroundColor $color -NoNewline
            Write-Host $f.Message -ForegroundColor $color
        }
        Write-Host ""
    }
}

# ---------------------------------------------------------------------------
# Write-ReadinessBanner
#   Display the 2026-readiness PASS / FAIL banner.
#   Mirrors report_2026_readiness() in report.sh.
# ---------------------------------------------------------------------------
function Write-ReadinessBanner {
    param([bool]$Ready)
    Write-SectionHr
    Write-Host "  2026 Readiness" -ForegroundColor White
    Write-SectionHr
    Write-Host ""

    if ($Ready) {
        Write-Host "  +------------------------------------------+" -ForegroundColor Green
        Write-Host "  |  OK  2026-READY                          |" -ForegroundColor Green
        Write-Host "  +------------------------------------------+" -ForegroundColor Green
    } else {
        Write-Host "  +------------------------------------------+" -ForegroundColor Red
        Write-Host "  |  !!  NOT 2026-READY                      |" -ForegroundColor Red
        Write-Host "  +------------------------------------------+" -ForegroundColor Red
        Write-Host ""
        Write-Host "  What's missing:" -ForegroundColor White
        $critical = $script:Findings | Where-Object { $_.Severity -eq "CRITICAL" -or $_.Severity -eq "HIGH" }
        foreach ($f in $critical) {
            Write-Host "    * [$($f.Severity)] $($f.Component): $($f.Message)" -ForegroundColor Red
        }
    }
    Write-Host ""
}

# ===========================================================================
# Entry point
# ===========================================================================

# Require Administrator (needed to call Get-SecureBootUEFI)
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires Administrator privileges." -ForegroundColor Red
    exit 1
}

Write-Hr
Write-Host "  SB-ENEMA Secure Boot Health Report" -ForegroundColor Cyan
Write-Hr
Write-Host ""
Write-Host "  Date (UTC): $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host ""

# Secure Boot enabled/disabled
try {
    $sbEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($sbEnabled) {
        Write-Host "  Secure Boot: " -NoNewline
        Write-Host "enabled" -ForegroundColor Green
    } else {
        Write-Host "  Secure Boot: " -NoNewline
        Write-Host "disabled" -ForegroundColor Red
    }
} catch {
    Write-Host "  Secure Boot: " -NoNewline
    Write-Host "unknown (could not read UEFI variable: $_)" -ForegroundColor Yellow
}

# Setup Mode: PK is empty → Setup Mode active (firmware allows unauthenticated PK writes)
$pkBytes = Get-EfiVarBytes "PK"
$setupMode = ($null -eq $pkBytes -or $pkBytes.Length -eq 0)
if ($setupMode) {
    Write-Host "  Setup Mode:  " -NoNewline
    Write-Host "yes (PK is empty)" -ForegroundColor Yellow
} else {
    Write-Host "  Setup Mode:  no"
}
Write-Host ""

# Run all audit checks
$ready = Invoke-AuditAll

# Analyze *Default variables (must run after Invoke-AuditAll so $script:DbHas2023
# and $script:DbxCurrent are populated for regression comparison)
$defaultsAudit = Invoke-AuditDefaultVars

# Print report sections:
#   1. Live variable summary  }
#   2. Default variable summary }  both summaries together
#   3. Audit findings          }
#   4. Bootloader CA findings  }
#   5. 2026 readiness banner   }  verdicts together
#   6. Restore defaults verdict}
Write-VariableSummary
Write-DefaultsVariableSummary -Audit $defaultsAudit
Write-Findings
Write-BootloaderFindings
Write-ReadinessBanner -Ready $ready
Write-DefaultsVerdict -Audit $defaultsAudit

Write-Hr
Write-Host ""
Write-Host "  To fix issues, boot the SB-ENEMA live image or use your BIOS 'Restore Factory Keys'" -ForegroundColor Gray
Write-Host "  option. See README.md and docs/usage.md for details." -ForegroundColor Gray
Write-Host ""
