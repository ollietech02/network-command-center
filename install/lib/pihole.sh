# Pi-hole v6 from its official GitHub repository (newest release tag), installed unattended with a
# pre-filled config. Rolls back the DNS change if this computer can't look up names afterwards.

install_pihole() {
  step "Installing Pi-hole (ad blocker)"
  if [ -e /etc/pihole/pihole.toml ] || [ -e /etc/pihole/setupVars.conf ]; then
    warn "Pi-hole is already installed here. Leaving its settings alone and just connecting the dashboard."
  else
    local tag tmp
    tag="$(git ls-remote --tags --refs --sort=-v:refname https://github.com/pi-hole/pi-hole.git 'v6*' 2>/dev/null | head -1 | sed 's#.*refs/tags/##')"
    [ -n "$tag" ] || die "Couldn't reach github.com to download Pi-hole."
    tmp="$(mktemp -d)"
    git clone -q --depth 1 --branch "$tag" https://github.com/pi-hole/pi-hole.git "$tmp/pi-hole" || die "Pi-hole download failed."
    ok "Downloaded Pi-hole $tag from github.com/pi-hole (official)"

    local rev=""
    [ -n "$LAN_CIDR" ] && [ -n "$GW_IP" ] && rev="  revServers = [\"true,$LAN_CIDR,$GW_IP\"]"
    sudo mkdir -p /etc/pihole
    sudo tee /etc/pihole/pihole.toml >/dev/null <<TOML
[dns]
  upstreams = ["1.1.1.1", "1.0.0.1"]
  interface = "$NET_DEV"
  listeningMode = "LOCAL"
  queryLogging = true
$rev
[webserver]
  port = "127.0.0.1:${PIHOLE_WEB_PORT}o,[::1]:${PIHOLE_WEB_PORT}o"
[misc]
  privacylevel = 0
TOML
    say "  Running Pi-hole's own installer (a few minutes)..."
    if ! (cd "$tmp/pi-hole/automated install" && sudo bash basic-install.sh --unattended); then
      pihole_rollback "Pi-hole's installer stopped with an error"
    fi
    rm -rf "$tmp"
    sleep 3
    systemctl is-active --quiet pihole-FTL || pihole_rollback "Pi-hole isn't running"
    dig +short +time=3 @127.0.0.1 example.com | grep -q . || pihole_rollback "Pi-hole doesn't answer lookups"
    dig +short +time=3 example.com | grep -q . || pihole_rollback "this computer can't look up names through Pi-hole"
    ok "Pi-hole is running and answering"
  fi

  local pw
  pw="$(randpw 24)"
  sudo pihole setpassword "$pw" >/dev/null 2>&1 || warn "Couldn't set Pi-hole's password (set it later with: sudo pihole setpassword)"
  secret_set PIHOLE_PASSWORD "$pw"
  env_set "$CONF" PIHOLE_URL "http://127.0.0.1:$PIHOLE_WEB_PORT"
  env_set "$CONF" PIHOLE_LISTS 1
  env_set "$CONF" PIHOLE_BLOCK 1
  ok "Dashboard connected to Pi-hole (its password is in $SECRETS)"
  BLOCKER_DONE="Pi-hole"
}

pihole_rollback() {
  fail "$1. Undoing the DNS change so this computer keeps working."
  sudo systemctl stop pihole-FTL 2>/dev/null || true
  sudo rm -f /etc/systemd/resolved.conf.d/90-pi-hole-disable-stub-listener.conf
  sudo systemctl restart systemd-resolved 2>/dev/null || true
  sleep 2
  die "Pi-hole was not set up. Your internet works as before. Details: sudo journalctl -u pihole-FTL"
}
