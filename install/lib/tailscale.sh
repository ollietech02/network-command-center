# Tailscale from its official package repository, then sign-in (the installer waits while you
# make a free account), then the dashboard is shared privately to your own Tailscale devices.

install_tailscale() {
  step "Installing Tailscale (reach the dashboard from your phone, anywhere)"
  if ! have tailscale; then
    [ -n "$PKG_DISTRO" ] && [ -n "$OS_CODENAME" ] || die "Tailscale: unknown Linux version. See https://tailscale.com/download/linux"
    local repo="https://pkgs.tailscale.com/stable/$PKG_DISTRO/$OS_CODENAME"
    curl -fsS -m 15 -o /dev/null "$repo.noarmor.gpg" || die "Tailscale has no packages for $OS_NAME yet. See https://tailscale.com/download/linux"
    curl -fsSL "$repo.noarmor.gpg" | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
    curl -fsSL "$repo.tailscale-keyring.list" | sudo tee /etc/apt/sources.list.d/tailscale.list >/dev/null
    sudo apt-get update -qq && sudo apt-get install -y -qq tailscale >/dev/null || die "Tailscale didn't install."
    ok "Tailscale installed from pkgs.tailscale.com (official)"
  else
    ok "Tailscale is already installed"
  fi
  sudo systemctl enable --now tailscaled >/dev/null 2>&1 || true
  sudo tailscale set --operator="$USER" 2>/dev/null || true   # lets the dashboard manage sharing without sudo

  if [ "$(tailscale status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("BackendState",""))' 2>/dev/null)" != Running ]; then
    cat <<EOF

  ${B}Time to make your free Tailscale account.${N}
  1. A sign-in link appears below. Open it on any device (hold Ctrl and click it here).
  2. Sign in with Google, Microsoft, Apple or GitHub. That creates the account; it's free.
  3. Click ${B}Connect${N}. This installer continues by itself when you're done.
  Then put the Tailscale app on your phone and sign in with the same account.

EOF
    sudo tailscale up --operator="$USER" || die "Tailscale sign-in didn't finish. Run the installer again to retry."
  fi
  ok "Signed in to Tailscale"

  local dns
  dns="$(tailscale status --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')"
  env_set "$CONF" ALLOWED_HOSTS "$dns"
  # HTTPS sharing needs "HTTPS certificates" turned on once for the account; tailscale prints a link if it isn't
  say "  Sharing the dashboard on your private Tailscale network..."
  if ! timeout 120 tailscale serve --bg "http://127.0.0.1:$PORT"; then
    warn "Tailscale asked to turn on HTTPS for your account. Open the link above, click Enable, then press Enter."
    pause
    timeout 120 tailscale serve --bg "http://127.0.0.1:$PORT" || warn "Sharing didn't turn on. Later: tailscale serve --bg http://127.0.0.1:$PORT"
  fi
  TS_URL="https://$dns"
  ok "On your phone (with Tailscale on): $TS_URL"
}
