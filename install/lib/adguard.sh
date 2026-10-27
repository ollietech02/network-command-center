# AdGuard Home from its official GitHub release, checked against the release's own checksums file,
# then set up through its first-run API (no browser wizard). Rolls back the DNS change if lookups break.

AGH_DIR=/opt/AdGuardHome

install_adguard() {
  step "Installing AdGuard Home (ad blocker)"
  local a
  case "$ARCH" in
    x86_64) a=amd64 ;; aarch64|arm64) a=arm64 ;; armv7l) a=armv7 ;; armv6l) a=armv6 ;; i686|i386) a=386 ;;
    *) die "AdGuard Home has no build for this processor ($ARCH)." ;;
  esac
  local pw; pw="$(randpw 24)"

  if [ -x "$AGH_DIR/AdGuardHome" ]; then
    warn "AdGuard Home is already installed here. Leaving it alone and just connecting the dashboard."
    warn "Put its username and password in $SECRETS as ADGUARD_USER= and ADGUARD_PASSWORD=, then run ./ncc restart."
    env_set "$CONF" ADGUARD_URL "http://127.0.0.1:$AGH_WEB_PORT"
    BLOCKER_DONE="AdGuard Home"
    return
  fi

  local tmp f base=https://github.com/AdguardTeam/AdGuardHome/releases/latest/download
  tmp="$(mktemp -d)"; f="AdGuardHome_linux_${a}.tar.gz"
  curl -fsSL -o "$tmp/$f" "$base/$f" && curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" \
    || die "Couldn't download AdGuard Home from github.com."
  (cd "$tmp" && grep -E " (\./)?$f\$" checksums.txt | grep -q . && grep -E " (\./)?$f\$" checksums.txt | sha256sum -c --quiet -) || die "AdGuard Home download didn't match its checksum. Stopped."
  ok "Downloaded AdGuard Home from github.com/AdguardTeam (checksum OK)"
  sudo tar -xzf "$tmp/$f" -C /opt
  rm -rf "$tmp"
  sudo "$AGH_DIR/AdGuardHome" -s install >/dev/null 2>&1 || die "AdGuard Home's service didn't install."

  # Ubuntu's own DNS helper sits on port 53; move it aside (AdGuard's documented way)
  if systemctl is-active --quiet systemd-resolved; then
    sudo mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNS=127.0.0.1\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/ncc-adguardhome.conf >/dev/null
    readlink /etc/resolv.conf | sudo tee /etc/ncc-resolv.conf.before >/dev/null || true
    sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    sudo systemctl restart systemd-resolved
  fi

  for _ in $(seq 1 20); do curl -fs -m2 http://127.0.0.1:3000/ >/dev/null && break; sleep 1; done
  local body
  body=$(printf '{"web":{"ip":"127.0.0.1","port":%s},"dns":{"ip":"0.0.0.0","port":53},"username":"admin","password":"%s"}' "$AGH_WEB_PORT" "$pw")
  curl -fsS -m 20 -H 'Content-Type: application/json' -d "$body" http://127.0.0.1:3000/control/install/configure >/dev/null \
    || adguard_rollback "AdGuard Home's first-run setup failed"
  sleep 3
  dig +short +time=3 @127.0.0.1 example.com | grep -q . || adguard_rollback "AdGuard Home doesn't answer lookups"
  dig +short +time=3 example.com | grep -q . || adguard_rollback "this computer can't look up names through AdGuard Home"
  ok "AdGuard Home is running and answering"

  secret_set ADGUARD_USER admin
  secret_set ADGUARD_PASSWORD "$pw"
  env_set "$CONF" ADGUARD_URL "http://127.0.0.1:$AGH_WEB_PORT"
  env_set "$CONF" PIHOLE_LISTS 1
  ok "Dashboard connected to AdGuard Home (user admin; password in $SECRETS)"
  BLOCKER_DONE="AdGuard Home"
}

adguard_rollback() {
  fail "$1. Undoing the DNS change so this computer keeps working."
  sudo "$AGH_DIR/AdGuardHome" -s stop >/dev/null 2>&1 || true
  sudo rm -f /etc/systemd/resolved.conf.d/ncc-adguardhome.conf
  if [ -s /etc/ncc-resolv.conf.before ]; then sudo ln -sf "$(cat /etc/ncc-resolv.conf.before)" /etc/resolv.conf; fi
  sudo systemctl restart systemd-resolved 2>/dev/null || true
  die "AdGuard Home was not set up. Your internet works as before. Remove it with: sudo $AGH_DIR/AdGuardHome -s uninstall"
}
