################################################################################
#
# sbsigntools
#
################################################################################

SBSIGNTOOLS_VERSION = 0.9.5
SBSIGNTOOLS_SITE = https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git/snapshot
SBSIGNTOOLS_SOURCE = sbsigntools-$(SBSIGNTOOLS_VERSION).tar.gz
SBSIGNTOOLS_LICENSE = GPL-3.0 LGPL-3.0 LGPL-2.1 CC0-1.0
SBSIGNTOOLS_LICENSE_FILES = COPYING

# ccan is a bundled library shipped separately (same as the Gentoo ebuild)
SBSIGNTOOLS_CCAN_SOURCE = sbsigntool-0.8-ccan.tar.gz
SBSIGNTOOLS_CCAN_SITE = https://dev.gentoo.org/~tamiko/distfiles
SBSIGNTOOLS_EXTRA_DOWNLOADS = $(SBSIGNTOOLS_CCAN_SITE)/$(SBSIGNTOOLS_CCAN_SOURCE)

# gnu-efi is a build-only staging dependency (headers + crt objects);
# openssl and util-linux (libuuid) are also needed at runtime.
SBSIGNTOOLS_DEPENDENCIES = gnu-efi openssl util-linux

SBSIGNTOOLS_AUTORECONF = YES

# Extract ccan into the source tree after the main tarball is unpacked.
# The ccan tarball has the layout lib/ccan/... so strip the leading
# component to land ccan/ directly into $(@D)/lib/.
define SBSIGNTOOLS_EXTRACT_CCAN
	$(TAR) --strip-components=1 -C $(@D)/lib \
		-xf $(DL_DIR)/sbsigntools/$(SBSIGNTOOLS_CCAN_SOURCE)
endef
SBSIGNTOOLS_POST_EXTRACT_HOOKS += SBSIGNTOOLS_EXTRACT_CCAN

# Fix the hard-coded AR in lib/ccan/Makefile.in so cross-compilation works.
define SBSIGNTOOLS_FIX_CCAN_AR
	$(SED) '/^AR /s:=.*:= $(TARGET_AR):' $(@D)/lib/ccan/Makefile.in
endef
SBSIGNTOOLS_POST_EXTRACT_HOOKS += SBSIGNTOOLS_FIX_CCAN_AR

# Set EFI_ARCH in configure.ac to match the target architecture before
# autoreconf regenerates the configure script.
ifeq ($(BR2_i386),y)
SBSIGNTOOLS_EFI_ARCH = ia32
else ifeq ($(BR2_x86_64),y)
SBSIGNTOOLS_EFI_ARCH = x86_64
else ifeq ($(BR2_aarch64)$(BR2_aarch64_be),y)
SBSIGNTOOLS_EFI_ARCH = aarch64
else ifeq ($(BR2_arm)$(BR2_armeb),y)
SBSIGNTOOLS_EFI_ARCH = arm
else ifeq ($(BR2_RISCV_64),y)
SBSIGNTOOLS_EFI_ARCH = riscv64
endif

define SBSIGNTOOLS_SET_EFI_ARCH
	$(SED) '/^EFI_ARCH=/s:=.*:=$(SBSIGNTOOLS_EFI_ARCH):' $(@D)/configure.ac
endef
SBSIGNTOOLS_POST_PATCH_HOOKS += SBSIGNTOOLS_SET_EFI_ARCH

SBSIGNTOOLS_CONF_ENV = \
	EFI_CRT_PATH="$(STAGING_DIR)/usr/lib" \
	CPPFLAGS="$(TARGET_CPPFLAGS) \
		-DOPENSSL_API_COMPAT=0x10100000L \
		-I$(STAGING_DIR)/usr/include/efi \
		-I$(STAGING_DIR)/usr/include/efi/$(SBSIGNTOOLS_EFI_ARCH)"

# Override the EFI_CPPFLAGS substituted by configure (which hardcodes
# /usr/include/efi) so that make picks up headers from the staging tree.
SBSIGNTOOLS_MAKE_OPTS = \
	EFI_CPPFLAGS="-I$(STAGING_DIR)/usr/include/efi \
		-I$(STAGING_DIR)/usr/include/efi/$(SBSIGNTOOLS_EFI_ARCH) \
		-DEFI_FUNCTION_WRAPPER"

$(eval $(autotools-package))
