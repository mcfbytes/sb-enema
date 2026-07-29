#!/usr/bin/env bash

set -euo pipefail

TARGET_DIR="$1"

# Ensure mount point exists for the exFAT volume
mkdir -p "${TARGET_DIR}/mnt/data"

# Use agetty to support auto-login
ln -sf agetty "${TARGET_DIR}/sbin/getty"

# Attach a second getty to the serial port.
#
# Buildroot generates a single inittab entry for BR2_TARGET_GENERIC_GETTY_PORT,
# which is "console" -- i.e. whatever the last console= kernel argument selects.
# That is deliberately tty0 (see kernel-fragment.config) so a machine with no
# usable serial port still shows the tool on screen. This adds an independent
# session on ttyS0 so the image is also drivable over serial, which is what the
# automated QEMU boot test in CI attaches to.
#
# Appended rather than shipped as an overlay file because Buildroot generates
# /etc/inittab itself; an overlay would replace it wholesale and silently drop
# whatever Buildroot puts there.
INITTAB="${TARGET_DIR}/etc/inittab"
SERIAL_GETTY='ttyS0::respawn:/sbin/getty -L --autologin root ttyS0 115200 vt100 # SB-ENEMA serial'
if [ -f "${INITTAB}" ] && ! grep -qF 'SB-ENEMA serial' "${INITTAB}"; then
    printf '%s\n' "${SERIAL_GETTY}" >> "${INITTAB}"
fi
