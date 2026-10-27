# Shared helpers for the installer. Sourced by install.sh; not run on its own.

if [ -t 1 ]; then
  B=$'\e[1m'; DIM=$'\e[2m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
else
  B=""; DIM=""; G=""; Y=""; R=""; C=""; N=""
fi

say()   { printf '%s\n' "$*"; }
step()  { printf '\n%s==> %s%s\n' "$C$B" "$*" "$N"; }
ok()    { printf '  %s✔%s %s\n' "$G" "$N" "$*"; }
warn()  { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
fail()  { printf '  %s✖%s %s\n' "$R" "$N" "$*"; }
die()   { fail "$*"; exit 1; }

# ask "Question" default(y|n) -> returns 0 for yes
ask() {
  local q="$1" d="${2:-n}" a hint="[y/N]"
  [ "$d" = y ] && hint="[Y/n]"
  if [ "${ASSUME_YES:-0}" = 1 ]; then [ "$d" = y ]; return; fi
  while true; do
    read -r -p "  $q $hint " a </dev/tty || a=""
    a="${a:-$d}"
    case "${a,,}" in y|yes) return 0 ;; n|no) return 1 ;; esac
  done
}

# choose "Question" "opt1|Label 1" "opt2|Label 2" ...  -> prints the chosen opt (first is the default)
choose() {
  local q="$1"; shift
  local i=1 o a
  printf '\n  %s%s%s\n' "$B" "$q" "$N" >/dev/tty
  for o in "$@"; do printf '    %s%d)%s %s\n' "$C" "$i" "$N" "${o#*|}" >/dev/tty; i=$((i + 1)); done
  if [ "${ASSUME_YES:-0}" = 1 ]; then printf '%s' "${1%%|*}"; return; fi
  while true; do
    read -r -p "  Pick 1-$#, Enter = 1: " a </dev/tty || a=""
    a="${a:-1}"
    if [[ "$a" =~ ^[0-9]+$ ]] && [ "$a" -ge 1 ] && [ "$a" -le $# ]; then
      o="${!a}"; printf '%s' "${o%%|*}"; return
    fi
  done
}

pause() { [ "${ASSUME_YES:-0}" = 1 ] || read -r -p "  ${1:-Press Enter to continue...}" _ </dev/tty || true; }

# random password: letters and digits only, so it is easy to type on a phone
randpw() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-20}"; }

# set KEY=VALUE in a simple env file (creates it; keeps other lines)
env_set() {
  local f="$1" k="$2" v="$3"
  touch "$f"
  grep -v "^$k=" "$f" >"$f.tmp" || true
  printf '%s=%s\n' "$k" "$v" >>"$f.tmp"
  mv "$f.tmp" "$f"
}

secret_set() {  # private secrets file, readable only by you
  mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
  env_set "$SECRETS" "$1" "$2"; chmod 600 "$SECRETS"
}

have() { command -v "$1" >/dev/null 2>&1; }

os_detect() {
  [ -r /etc/os-release ] || die "Can't tell which Linux this is (no /etc/os-release)."
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-linux}"; OS_LIKE="${ID_LIKE:-}"; OS_NAME="${PRETTY_NAME:-Linux}"
  OS_CODENAME="${VERSION_CODENAME:-}"
  # Mint, Pop!_OS, Zorin etc. use Ubuntu's packages
  if [ -n "${UBUNTU_CODENAME:-}" ] && [ "$OS_ID" != ubuntu ]; then PKG_DISTRO=ubuntu; OS_CODENAME="$UBUNTU_CODENAME"
  elif [ "$OS_ID" = raspbian ]; then PKG_DISTRO=raspbian
  elif [ "$OS_ID" = ubuntu ] || [ "$OS_ID" = debian ]; then PKG_DISTRO="$OS_ID"
  elif [[ " $OS_LIKE " == *" ubuntu "* ]]; then PKG_DISTRO=ubuntu
  elif [[ " $OS_LIKE " == *" debian "* ]]; then PKG_DISTRO=debian
  else PKG_DISTRO=""
  fi
  ARCH="$(uname -m)"
  have apt-get || die "This installer needs a Debian-family Linux (Ubuntu, Debian, Linux Mint, Raspberry Pi OS). Found: $OS_NAME"
  have systemctl || die "This installer needs systemd."
}

net_detect() {
  GW_IP="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
  NET_DEV="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
  LAN_IP="$(ip -4 -o addr show dev "$NET_DEV" 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
  LAN_CIDR="$(ip -4 -o route show dev "$NET_DEV" scope link 2>/dev/null | awk '{print $1; exit}')"
}

# 1 if the router is an AT&T gateway (its read-only status page answers without a login)
router_is_att() {
  [ -n "${GW_IP:-}" ] && curl -fsS -m 4 "http://$GW_IP/cgi-bin/sysinfo.ha" 2>/dev/null | grep -q "Model Number"
}

has_gnome_rdp() { have grdctl && systemctl list-unit-files gnome-remote-desktop.service >/dev/null 2>&1; }
