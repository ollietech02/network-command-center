# Remote desktop with GNOME's built-in "Remote Login" (RDP). No one has to approve at the computer, and it
# works at the login screen. Reachable from your home network and Tailscale only (no router changes).

install_remote_desktop() {
  step "Turning on remote desktop (GNOME Remote Login)"
  if ! has_gnome_rdp; then
    warn "This computer doesn't have GNOME Remote Login (it needs the GNOME desktop, e.g. Ubuntu). Skipped."
    return
  fi
  local d=/var/lib/gnome-remote-desktop/.local/share/gnome-remote-desktop pw out="$HOME/remote-login.txt"
  pw="$(randpw 16)"
  sudo install -d -o gnome-remote-desktop -g gnome-remote-desktop -m 700 "$d"
  if ! sudo test -s "$d/rdp-tls.crt"; then
    sudo openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes -subj "/CN=$(hostname)" \
      -keyout "$d/rdp-tls.key" -out "$d/rdp-tls.crt" 2>/dev/null
    sudo chown gnome-remote-desktop:gnome-remote-desktop "$d/rdp-tls.key" "$d/rdp-tls.crt"
    sudo chmod 600 "$d/rdp-tls.key"
  fi
  sudo grdctl --system rdp set-tls-key "$d/rdp-tls.key"
  sudo grdctl --system rdp set-tls-cert "$d/rdp-tls.crt"
  sudo grdctl --system rdp set-credentials "$RDP_USER" "$pw"
  sudo grdctl --system rdp enable
  sudo systemctl enable --now gnome-remote-desktop.service >/dev/null 2>&1
  ( umask 077
    printf 'Remote desktop (GNOME Remote Login / RDP)\nComputer: %s at home%s\nUsername: %s\nPassword: %s\n\nAfter connecting you see the normal login screen: use your usual password there.\nChange this password in Settings > System > Remote Desktop > Remote Login.\n' \
      "$LAN_IP" "${TS_URL:+, or $(echo "${TS_URL#https://}" | cut -d. -f1) with Tailscale}" "$RDP_USER" "$pw" >"$out" )
  env_set "$CONF" REMOTE_DESKTOP 1
  env_set "$CONF" RDP_USER "$RDP_USER"
  ok "Remote desktop is on. Username $RDP_USER; the password is in $out (only you can read it)"
}
