################################################################################
#
# efitools
#
################################################################################

EFITOOLS_VERSION = 1.9.2
EFITOOLS_SITE = https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git/snapshot
EFITOOLS_SOURCE = efitools-$(EFITOOLS_VERSION).tar.gz
EFITOOLS_LICENSE = GPL-2.0-only
EFITOOLS_LICENSE_FILES = COPYING

EFITOOLS_DEPENDENCIES = gnu-efi openssl

# We only need the Linux userspace CLI tools (efi-readvar, efi-updatevar,
# sign-efi-sig-list, cert-to-efi-sig-list, etc.), not the EFI applications
# (KeyTool.efi, etc.).  Build just the BINARIES target to avoid pulling in
# the full EFI PE/COFF link chain which requires CRT objects we don't ship.
#
# INCDIR is hardcoded in Make.rules to /usr/include/efi — override it to
# point at the staging directory so the cross-compiler doesn't trip
# Buildroot's unsafe-path check.

EFITOOLS_INCDIR = \
	-I$(@D)/include/ \
	-I$(STAGING_DIR)/usr/include/efi \
	-I$(STAGING_DIR)/usr/include/efi/x86_64 \
	-I$(STAGING_DIR)/usr/include/efi/protocol

EFITOOLS_BINARIES = \
	cert-to-efi-sig-list sig-list-to-certs sign-efi-sig-list \
	hash-to-efi-sig-list efi-readvar efi-updatevar cert-to-efi-hash-list \
	flash-var

define EFITOOLS_BUILD_CMDS
	$(TARGET_MAKE_ENV) $(MAKE) -C $(@D) \
		CC="$(TARGET_CC)" AR="$(TARGET_AR)" \
		PKG_CONFIG="$(PKG_CONFIG_HOST_BINARY)" \
		INCDIR="$(EFITOOLS_INCDIR)" \
		CPPFLAGS="-D_GNU_SOURCE -DCONFIG_x86_64" \
		CFLAGS="$(TARGET_CFLAGS) -fshort-wchar" LDFLAGS="$(TARGET_LDFLAGS)" \
		$(EFITOOLS_BINARIES)
endef

define EFITOOLS_INSTALL_TARGET_CMDS
	$(INSTALL) -D $(@D)/efi-updatevar $(TARGET_DIR)/usr/sbin/efi-updatevar
	$(INSTALL) -D $(@D)/efi-readvar $(TARGET_DIR)/usr/sbin/efi-readvar
	$(INSTALL) -D $(@D)/sign-efi-sig-list $(TARGET_DIR)/usr/sbin/sign-efi-sig-list
	$(INSTALL) -D $(@D)/cert-to-efi-sig-list $(TARGET_DIR)/usr/sbin/cert-to-efi-sig-list
	$(INSTALL) -D $(@D)/hash-to-efi-sig-list $(TARGET_DIR)/usr/sbin/hash-to-efi-sig-list
endef

$(eval $(generic-package))
