#!/usr/bin/env bash
# Removes the Network Command Center. Asks separately about each extra (Pi-hole, AdGuard Home, Tailscale,
# remote desktop) because you may use them for other things. Your dashboard history is kept unless you say so.
set -uo pipefail
DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
for f in "$DIR"/install/lib/common.sh; do . "$f"; done
[ "$(id -u)" -ne 0 ] || die "Run this as your normal user, not with sudo."

step "Removing the dashboard service"
"$DIR/ncc" uninstall >/dev/null 2>&1 || true
rm -f "$HOME/.local/share/applications/network-command-center.desktop"
ok "Dashboard stopped and removed from startup"

if have tailscale && tailscale serve status 2>/dev/null | grep -q 127.0.0.1:8088; then
  ask "Stop sharing the dashboard on Tailscale?" y && { tailscale serve reset 2>/dev/null; tailscale funnel reset 2>/dev/null; ok "Sharing stopped"; }
fi
if have pihole && ask "Uninstall Pi-hole too? (ads stop being blocked)" n; then
  sudo pihole uninstall
fi
if [ -x /opt/AdGuardHome/AdGuardHome ] && ask "Uninstall AdGuard Home too? (ads stop being blocked)" n; then
  sudo /opt/AdGuardHome/AdGuardHome -s uninstall >/dev/null 2>&1
  sudo rm -f /etc/systemd/resolved.conf.d/ncc-adguardhome.conf
  [ -s /etc/ncc-resolv.conf.before ] && sudo ln -sf "$(cat /etc/ncc-resolv.conf.before)" /etc/resolv.conf
  sudo systemctl restart systemd-resolved 2>/dev/null || true
  sudo rm -rf /opt/AdGuardHome /etc/ncc-resolv.conf.before
  ok "AdGuard Home removed and DNS restored"
fi
if have tailscale && ask "Uninstall Tailscale too? (your phone loses access to this computer)" n; then
  sudo tailscale logout 2>/dev/null; sudo apt-get remove -y -qq tailscale >/dev/null && ok "Tailscale removed"
fi
if have grdctl && ask "Turn off remote desktop?" n; then
  sudo grdctl --system rdp disable && sudo systemctl disable --now gnome-remote-desktop.service >/dev/null 2>&1
  rm -f "$HOME/remote-login.txt"; ok "Remote desktop off"
fi
if ask "Delete the dashboard's history, accounts and saved passwords? (can't be undone)" n; then
  rm -rf "$DIR/data" "$HOME/.config/ncc"; ok "Deleted"
fi
say ""
say "  The program files are still in $DIR. Delete that folder if you don't want them."
