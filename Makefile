# --- Buildroot versioning ----------------------------------------------------
BUILDROOT_VERSION ?= 2026.02
BUILDROOT_URL ?= https://buildroot.org/downloads/buildroot-$(BUILDROOT_VERSION).tar.gz

ROOT_DIR := $(CURDIR)
OUTPUT_DIR := $(ROOT_DIR)/output
BR_TARBALL := $(OUTPUT_DIR)/buildroot-$(BUILDROOT_VERSION).tar.gz
BR_DIR := $(OUTPUT_DIR)/buildroot-$(BUILDROOT_VERSION)
BR_OUT := $(OUTPUT_DIR)/br-out
BR_DL := $(OUTPUT_DIR)/dl

export BR2_EXTERNAL := $(ROOT_DIR)/sb_enema

.PHONY: all secureboot-objects dist

all: $(BR_DIR) sb_enema_defconfig secureboot-objects
	$(MAKE) -C $(BR_DIR) O=$(BR_OUT) BR2_DL_DIR=$(BR_DL) all

secureboot-objects:
	scripts/prepare-secureboot-objects.sh

# Produce a ZIP-compressed copy of the disk image for distribution.
# ZIP is natively supported on Windows – the primary target audience.
# The raw image (~80 MiB) is zero-padded; it compresses to ~20 MiB.
# Usage: make dist          → dist/sb-enema.zip + dist/SHA256SUMS
dist: all
	mkdir -p $(ROOT_DIR)/dist
	cp $(BR_OUT)/images/sb-enema.img $(ROOT_DIR)/dist/
	zip -j $(ROOT_DIR)/dist/sb-enema.zip $(ROOT_DIR)/dist/sb-enema.img
	(cd $(ROOT_DIR)/dist && sha256sum sb-enema.zip > SHA256SUMS)
	(cd $(BR_OUT)/images && sha256sum sb-enema.img) >> $(ROOT_DIR)/dist/SHA256SUMS
	cp docs/release-README.md dist/README.md
	@echo "Compressed image: $(ROOT_DIR)/dist/sb-enema.zip"

# --- Download & extract Buildroot -------------------------------------------
$(BR_TARBALL):
	@mkdir -p $(OUTPUT_DIR)
	curl -fsSL $(BUILDROOT_URL) -o $@

$(BR_DIR): $(BR_TARBALL)
	tar -C $(OUTPUT_DIR) -xf $(BR_TARBALL)
	touch $(BR_DIR)

# --- Forward all Buildroot targets ------------------------------------------
%: $(BR_DIR)
	$(MAKE) -C $(BR_DIR) O=$(BR_OUT) BR2_DL_DIR=$(BR_DL) $@
