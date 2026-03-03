# shellcheck shell=sh
# /root/.profile — SB-ENEMA root login profile
#
# Run the SB-ENEMA provisioning tool automatically on login.
# If the tool exits for any reason the login shell continues and
# presents an interactive prompt (bash or busybox sh).
/usr/sbin/sb-enema || true
