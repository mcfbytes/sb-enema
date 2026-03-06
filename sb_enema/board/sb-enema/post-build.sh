#!/bin/sh
set -e

TARGET_DIR="$1"

# Ensure mount point exists for the exFAT volume
mkdir -p "${TARGET_DIR}/mnt/data"

# Use agetty to support auto-login
ln -sf agetty "${TARGET_DIR}/sbin/getty"
