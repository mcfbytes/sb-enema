# shellcheck shell=sh
# /root/.profile — SB-ENEMA root login profile
#
# Run the SB-ENEMA provisioning tool automatically on login.
# If the tool exits for any reason the login shell continues and
# presents an interactive prompt (bash or busybox sh).
#
# Except on the serial line. post-build.sh attaches a second getty to ttyS0 so
# the image can be driven non-interactively -- the QEMU boot test logs in there
# and runs `sb-enema <operation>` directly. Auto-starting the menu on both
# consoles would put two instances on the same EFI variables at once, which
# already produced a real failure: both raced to mount efivarfs and the loser
# aborted with "Device or resource busy". So the serial line gets a plain shell
# and the operator (or CI) starts the tool explicitly.
case "$(tty 2>/dev/null)" in
    /dev/ttyS*)
        ;;
    *)
        /usr/sbin/sb-enema || true
        ;;
esac
