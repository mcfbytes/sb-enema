# SB-ENEMA Secure Boot reprovisioning USB image

## What this image does
- Boots a minimal Linux environment that mounts the `SB-ENEMA` exFAT partition.
- Applies UEFI Secure Boot variables (PK/KEK/db/dbx) using staged payloads generated from `microsoft/secureboot_objects`, preferring the prebuilt binaries and falling back to local ESL/signing if absent.
- Logs actions to `/mnt/sb-enema/logs/provision.log` and refuses PK replacement unless the platform is in Setup Mode.

## How to flash
1. Download the release assets:
   - `sb-enema.zip`
   - `SHA256SUMS`
2. Verify the ZIP integrity:
   ```sh
   # Linux (GNU coreutils)
   sha256sum -c SHA256SUMS --ignore-missing
   # macOS (built-in shasum) – compare output with the first line of SHA256SUMS
   shasum -a 256 sb-enema.zip
   # Windows PowerShell – compare output with the first line of SHA256SUMS
   (Get-FileHash sb-enema.zip -Algorithm SHA256).Hash.ToLower()
   ```
3. Extract `sb-enema.img` from `sb-enema.zip` (Windows Explorer, 7-Zip, or `unzip sb-enema.zip`).
4. Optionally verify the extracted image:
   ```sh
   # Linux
   sha256sum -c SHA256SUMS --ignore-missing
   # macOS – compare output with the second line of SHA256SUMS
   shasum -a 256 sb-enema.img
   ```
5. Flash `sb-enema.img` to a USB stick using a tool like Rufus (Windows) or `dd` (Linux/macOS):
   - Rufus: select the image, choose the target USB device, and start. Ensure partition scheme = GPT and target system = UEFI (non-CSM).
   - Linux/macOS example:
     ```sh
     sudo dd if=sb-enema.img of=/dev/sdX bs=4M status=progress && sync
     ```
6. Boot the target machine from the USB stick with UEFI Secure Boot in Setup Mode. Provisioning runs automatically; review `/mnt/sb-enema/logs/provision.log` afterward.
