#!/usr/bin/env bash
# Which remote desktop the Linux installer picks, on pretend computers (no real system is touched).
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/install/lib/common.sh"
. "$DIR/install/lib/remote-desktop.sh"
fail=0
DM_LINK=/nonexistent/display-manager.service

# Pretend computer: which programs exist, what grdctl --help says, the systemd default target, a login screen link
pretend() {  # $1 programs (space separated)  $2 grdctl help text  $3 default target  $4 login screen? (1/0)
  PROGS=" $1 " GRD_HELP="$2" TARGET="$3"
  DM_LINK=/nonexistent; [ "$4" = 1 ] && DM_LINK="$DIR/install/lib/common.sh"  # any file that exists
}
have() { [[ "$PROGS" == *" $1 "* ]]; }
grdctl() { echo "$GRD_HELP"; }
systemctl() { case "$1" in get-default) echo "$TARGET" ;; list-unit-files) have grdctl ;; esac; }

check() {  # name expected
  local got; got="$(rdp_kind)"
  if [ "$got" = "$2" ]; then echo "ok   $1 -> $got"; else echo "FAIL $1: expected $2, got $got"; fail=1; fi
}

pretend "grdctl" "Usage: grdctl [--system] [--headless] COMMAND" graphical.target 1;  check "Ubuntu 24.04+ / Debian 13 GNOME" gnome
pretend "grdctl" "Usage: grdctl [--headless] COMMAND" graphical.target 1;            check "Debian 12 GNOME 43" xrdp
pretend "" "" graphical.target 1;                                                    check "Debian Xfce / KDE / Mint" xrdp
pretend "raspi-config" "" graphical.target 1;                                        check "Raspberry Pi OS desktop" vnc
pretend "raspi-config" "" graphical.target 0;                                        check "Raspberry Pi OS Lite" none
pretend "" "" graphical.target 0;                                                    check "Server, no desktop (default target still graphical)" none
pretend "grdctl" "Usage: grdctl [--system] COMMAND" multi-user.target 0;             check "GNOME 46+ installed, booting to text" gnome

[ "$fail" = 0 ] && echo "all remote desktop checks passed"
exit "$fail"
