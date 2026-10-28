#!/usr/bin/env bash
# Network Command Center installer for Linux (Ubuntu, Debian, Linux Mint, Raspberry Pi OS).
#
#   ./install/install.sh                    pick a pack from a menu
#   ./install/install.sh --pack everything  no menu (packs: dashboard, shield, everything)
#   ./install/install.sh --pack shield --yes   no questions at all (accepts the defaults)
#
# Run it as your normal user; it asks for your password when a step needs it.
set -uo pipefail

DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
CONF="$DIR/config/ncc.env"
SECRETS_DIR="$HOME/.config/ncc"
SECRETS="$SECRETS_DIR/secrets.env"
PORT=8088 PIHOLE_WEB_PORT=8081 AGH_WEB_PORT=8082 RDP_USER=remote
for f in "$DIR"/install/lib/*.sh; do . "$f"; done

PACK="" ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --pack) PACK="${2:-}"; shift ;;
    --pack=*) PACK="${1#*=}" ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
  shift
done

[ "$(id -u)" -ne 0 ] || die "Run this as your normal user, not with sudo. It asks for your password when needed."

cat <<EOF

${C}${B}  NCC // NETWORK COMMAND CENTER${N}
  A home network dashboard: internet health, speed tests, devices, ad blocking and alerts.

EOF
os_detect
net_detect
ok "$OS_NAME ($ARCH), network connection found"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null || die "Needs Python 3.9 or newer."

# ------------------------------------------------------------------ choose what to install
[ -n "$PACK" ] || PACK=$(choose "Which pack do you want?" \
  "dashboard|Dashboard only - just the dashboard. Nothing else is installed." \
  "shield|Home Shield - dashboard + Pi-hole ad blocker for every device at home." \
  "everything|Everything - dashboard + Pi-hole + Tailscale (phone access from anywhere) + remote desktop." \
  "custom|Custom - choose each piece yourself.")
echo

STYLE=scifi BLOCKER=none TAILSCALE=0 RDP=0 CONTROLS=0
case "$PACK" in
  dashboard) ;;
  shield) BLOCKER=pihole ;;
  everything) BLOCKER=pihole TAILSCALE=1 CONTROLS=1; has_gnome_rdp && RDP=1 ;;
  custom)
    say "  Pictures of each look: https://github.com/ollietech02/network-command-center#looks"
    STYLE=$(choose "Which look?" \
      "scifi|Sci-fi - dark command center with glowing accents" \
      "hacker|Hacker - black and green terminal" \
      "clean|Clean - light, simple and friendly")
    BLOCKER=$(choose "Ad blocker for your whole home?" \
      "pihole|Pi-hole - the classic. Blocks ads and trackers for every device." \
      "adguard|AdGuard Home - similar, with a more modern look" \
      "none|None")
    echo
    ask "Install Tailscale, so you can open the dashboard from your phone anywhere? (free account)" y && TAILSCALE=1
    if has_gnome_rdp; then ask "Turn on remote desktop (control this computer from another one)?" n && RDP=1; fi
    ask "Show restart buttons (dashboard, ad blocker, this computer) on the dashboard?" y && CONTROLS=1
    ;;
  *) die "Unknown pack '$PACK'. Use: dashboard, shield, everything or custom." ;;
esac
ROUTER=generic
router_is_att && ROUTER=att

# ------------------------------------------------------------------ say exactly what will happen, then ask
step "Here's the plan"
say "  • Install the dashboard in $DIR and start it at http://localhost:$PORT (only this computer can open it)"
say "  • Look: $STYLE (you can change it any time in Tools & settings)"
[ "$ROUTER" = att ] && say "  • AT&T gateway found: extra router stats turned on (read-only)"
case "$BLOCKER" in
  pihole)  say "  • Install Pi-hole. This computer's own lookups go through it. Your router is NOT changed." ;;
  adguard) say "  • Install AdGuard Home. This computer's own lookups go through it. Your router is NOT changed." ;;
esac
[ "$TAILSCALE" = 1 ] && say "  • Install Tailscale and help you make a free account (private access from your phone)"
[ "$RDP" = 1 ] && say "  • Turn on remote desktop, reachable only from your home network and Tailscale"
say "  • Nothing is opened to the internet, and no router or firewall settings are changed."
echo
ask "Go ahead?" y || { say "  Nothing was changed."; exit 0; }

sudo -v || die "Needs your password for the install steps."
while true; do sudo -n true 2>/dev/null; sleep 50; kill -0 "$$" 2>/dev/null || exit; done &

# ------------------------------------------------------------------ base packages + config
step "Installing what the dashboard needs"
sudo apt-get update -qq
PKGS="python3 iproute2 iputils-ping dnsutils curl git ca-certificates openssl"
[ -n "${XDG_CURRENT_DESKTOP:-}" ] && PKGS="$PKGS libnotify-bin"
# shellcheck disable=SC2086
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKGS >/dev/null || die "Package install failed."
ok "Packages ready"

mkdir -p "$DIR/config" "$DIR/data"
[ -f "$CONF" ] || cp "$DIR/config/ncc.env.example" "$CONF"
env_set "$CONF" PORT "$PORT"
env_set "$CONF" STYLE "$STYLE"
env_set "$CONF" ROUTER "$ROUTER"
env_set "$CONF" SYSTEM_CONTROLS "$CONTROLS"
mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"; touch "$SECRETS"; chmod 600 "$SECRETS"
ok "Settings saved in $CONF"

BLOCKER_DONE="" TS_URL=""
case "$BLOCKER" in
  pihole) install_pihole ;;
  adguard) install_adguard ;;
esac

step "Starting the dashboard"
"$DIR/ncc" start >/dev/null
sudo loginctl enable-linger "$USER" >/dev/null 2>&1 || true   # keeps it running after you log out / after a restart
for _ in $(seq 1 20); do curl -fs -m2 "http://127.0.0.1:$PORT/api/health" >/dev/null && break; sleep 1; done
curl -fs -m2 "http://127.0.0.1:$PORT/" >/dev/null && ok "Dashboard running" || warn "Dashboard didn't answer yet. Check: ./ncc logs"
if [ -d "$HOME/.local/share/applications" ] || [ -n "${XDG_CURRENT_DESKTOP:-}" ]; then
  mkdir -p "$HOME/.local/share/applications"
  cat >"$HOME/.local/share/applications/network-command-center.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Network Command Center
Comment=Home network dashboard
Exec=$DIR/ncc-app
Icon=$DIR/app/static/icon-192.png
Categories=Network;Monitor;
EOF
  ok "Added \"Network Command Center\" to your apps menu"
fi

[ "$TAILSCALE" = 1 ] && { install_tailscale; "$DIR/ncc" restart >/dev/null; }
[ "$RDP" = 1 ] && { install_remote_desktop; "$DIR/ncc" restart >/dev/null; }

# ------------------------------------------------------------------ what's left for you
step "Done! Here's what's left for you"
say "  ${B}Open the dashboard:${N} http://localhost:$PORT  (or \"Network Command Center\" in your apps)"
[ -n "$TS_URL" ] && say "  ${B}On your phone:${N} turn Tailscale on, open $TS_URL, and set a PIN on the computer first (Security tab)."
if [ -n "$BLOCKER_DONE" ]; then
  say "  ${B}Make $BLOCKER_DONE protect every device at home${N} (the installer never changes your router):"
  if [ "$ROUTER" = att ]; then
    cat <<EOF
    AT&T gateways don't let you change the DNS server, so $BLOCKER_DONE hands out the addresses instead:
    1. Give this computer a fixed address outside AT&T's range, e.g. ${LAN_IP%.*}.2
       (Settings → Wi-Fi → ⚙ → IPv4 → Manual).
    2. Turn on $BLOCKER_DONE's DHCP server, then turn OFF the gateway's
       (http://$GW_IP → Home Network → Subnets & DHCP → DHCPv4 Server: Off).
    The dashboard's $BLOCKER_DONE tab has a step-by-step "Whole-home setup" guide with the exact values.
EOF
  else
    cat <<EOF
    1. In your router's settings, give this computer a fixed address ("DHCP reservation") so it stays ${LAN_IP:-the same}.
    2. Set the router's DNS server to ${LAN_IP:-this computer's address}.
       (That address is private: it only works inside your home and isn't visible on the internet.)
    The dashboard's $BLOCKER_DONE tab has a "Whole-home setup" guide with steps for popular routers.
EOF
  fi
  say "    Until then, only this computer's ads are blocked."
fi
say "  ${B}Phone alerts and email codes:${N} set them up in the dashboard, Security tab (free; nothing to install)."
[ "$TAILSCALE" = 1 ] && say "  ${B}Use it from any browser without Tailscale:${N} optional, Security tab → Web access (off until you turn it on)."
say "  ${B}Uninstall:${N} $DIR/install/uninstall.sh"
echo
