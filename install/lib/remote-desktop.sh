# Remote desktop: control this computer from another one. Reachable from your home network and Tailscale only (no
# router changes). Which tool depends on the desktop (rdp_kind):
#   gnome  GNOME 46+ "Remote Login" (Ubuntu 24.04+, Debian 13 with GNOME): RDP, starts at the login screen
#   vnc    Raspberry Pi OS with desktop: its built-in VNC server (switched on with raspi-config), shows the screen
#   xrdp   any other desktop (Debian 12, Xfce, MATE, KDE, Cinnamon...): RDP from Debian's own xrdp package, which
#          opens its own desktop session
#   none   no desktop at all (servers, Raspberry Pi OS Lite): nothing to show

# A graphical login screen is set up (display-manager.service points at gdm3, lightdm, sddm...). Not
# "systemctl get-default": that says graphical.target on many servers with no screen at all.
has_desktop() { [ -e "${DM_LINK:-/etc/systemd/system/display-manager.service}" ]; }

# GNOME's system-wide Remote Login needs GNOME 46 or newer: older grdctl has no --system (Debian 12 has GNOME 43)
has_gnome_rdp() {
  have grdctl && systemctl list-unit-files gnome-remote-desktop.service >/dev/null 2>&1 \
    && grdctl --help 2>&1 | grep -q -- '--system'
}

rdp_kind() {
  if have raspi-config && has_desktop; then echo vnc
  elif has_gnome_rdp; then echo gnome
  elif has_desktop; then echo xrdp
  else echo none
  fi
}

rdp_plan() {  # one line for "Here's the plan"
  case "$(rdp_kind)" in
    gnome) echo "Turn on remote desktop (GNOME Remote Login), reachable only from your home network and Tailscale" ;;
    vnc)   echo "Turn on remote desktop (Raspberry Pi's built-in VNC), reachable only from your home network and Tailscale" ;;
    xrdp)  echo "Install remote desktop (xrdp, from your system's own packages), reachable only from your home network and Tailscale" ;;
  esac
}

# Where to connect: the home address, plus the Tailscale name when there is one
_rdp_where() { printf '%s at home%s' "$LAN_IP" "${TS_URL:+, or $(echo "${TS_URL#https://}" | cut -d. -f1) with Tailscale}"; }

install_remote_desktop() {
  local kind out="$HOME/remote-login.txt"
  kind="$(rdp_kind)"
  case "$kind" in
    gnome) _rdp_gnome ;;
    vnc)   _rdp_vnc ;;
    xrdp)  _rdp_xrdp ;;
    *) step "Remote desktop"; warn "This computer has no desktop to show (no screen login), so remote desktop was skipped."; return ;;
  esac || { warn "Remote desktop couldn't be turned on. Nothing else was affected."; return; }
  env_set "$CONF" REMOTE_DESKTOP 1
  env_set "$CONF" RDP_KIND "$kind"
  env_set "$CONF" RDP_USER "$RDP_USER"
  chmod 600 "$out"
}

_rdp_gnome() {
  step "Turning on remote desktop (GNOME Remote Login)"
  local d=/var/lib/gnome-remote-desktop/.local/share/gnome-remote-desktop pw
  pw="$(randpw 16)"
  sudo install -d -o gnome-remote-desktop -g gnome-remote-desktop -m 700 "$d"
  if ! sudo test -s "$d/rdp-tls.crt"; then
    sudo openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes -subj "/CN=$(hostname)" \
      -keyout "$d/rdp-tls.key" -out "$d/rdp-tls.crt" 2>/dev/null
    sudo chown gnome-remote-desktop:gnome-remote-desktop "$d/rdp-tls.key" "$d/rdp-tls.crt"
    sudo chmod 600 "$d/rdp-tls.key"
  fi
  sudo grdctl --system rdp set-tls-key "$d/rdp-tls.key" &&
  sudo grdctl --system rdp set-tls-cert "$d/rdp-tls.crt" &&
  sudo grdctl --system rdp set-credentials "$RDP_USER" "$pw" &&
  sudo grdctl --system rdp enable || return 1
  sudo systemctl enable --now gnome-remote-desktop.service >/dev/null 2>&1
  ( umask 077
    printf 'Remote desktop (GNOME Remote Login / RDP)\nComputer: %s\nUsername: %s\nPassword: %s\n\nConnect with Windows "Remote Desktop Connection", the Windows App (Mac, iPhone, Android) or Remmina (Linux).\nAfter connecting you see the normal login screen: use your usual password there.\nChange this password in Settings > System > Remote Desktop > Remote Login.\n' \
      "$(_rdp_where)" "$RDP_USER" "$pw" >"$HOME/remote-login.txt" )
  ok "Remote desktop is on. Username $RDP_USER; the password is in ~/remote-login.txt (only you can read it)"
}

_rdp_vnc() {
  step "Turning on remote desktop (Raspberry Pi's built-in VNC)"
  sudo raspi-config nonint do_vnc 0 || return 1  # 0 = on (raspi-config's convention)
  RDP_USER="$USER"
  ( umask 077
    printf 'Remote desktop (VNC, built into Raspberry Pi OS)\nComputer: %s\nUsername: %s\nPassword: your normal password for this Raspberry Pi\n\nConnect with a VNC app: RealVNC Viewer (free, Windows/Mac/iPhone/Android) or TigerVNC.\nYou see the Pi'"'"'s screen exactly as it is. Turn it off with: sudo raspi-config nonint do_vnc 1\n' \
      "$(_rdp_where)" "$USER" >"$HOME/remote-login.txt" )
  ok "Remote desktop is on. Sign in as $USER with your normal password (a VNC app is needed: see ~/remote-login.txt)"
}

_rdp_xrdp() {
  step "Installing remote desktop (xrdp)"
  sudo apt-get install -y -qq xrdp >/dev/null || return 1
  getent group ssl-cert >/dev/null && sudo adduser xrdp ssl-cert >/dev/null 2>&1  # lets xrdp read its certificate key
  sudo systemctl enable --now xrdp >/dev/null 2>&1 || return 1
  RDP_USER="$USER"
  ( umask 077
    printf 'Remote desktop (xrdp / RDP)\nComputer: %s\nUsername: %s\nPassword: your normal password for this computer\n\nConnect with Windows "Remote Desktop Connection", the Windows App (Mac, iPhone, Android) or Remmina (Linux).\nxrdp opens its own desktop session, separate from the screen. It works best when you are signed out at the computer\nitself (one person can'"'"'t be signed in twice on most desktops).\nTurn it off with: sudo systemctl disable --now xrdp\n' \
      "$(_rdp_where)" "$USER" >"$HOME/remote-login.txt" )
  ok "Remote desktop is on. Sign in as $USER with your normal password (details in ~/remote-login.txt)"
}
