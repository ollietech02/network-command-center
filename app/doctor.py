#!/usr/bin/env python3
"""Network Command Center health report ("ncc doctor"), safe to paste into any AI assistant.

Standard library only. Read-only: it changes nothing. Passwords, tokens, email addresses, the Tailscale
network name and the phone-alert topic are removed before anything is printed. Run it with
`./ncc doctor` (Linux) or `ncc doctor` (Windows); the dashboard's "Copy for my AI" button uses it too.
"""
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
WIN = os.name == "nt"
REPO = "https://github.com/ollietech02/network-command-center"


def redact(text):
    """Remove what must never leave the computer. Private home addresses (192.168.x.x) stay: they're needed to diagnose."""
    t = str(text)
    t = re.sub(r"(?i)\b(\w*(?:password|passwd|token|secret|api[_-]?key|app[_-]?pass)\w*\s*[=:]\s*|pin\s*[=:]\s*)\S+", r"\1[removed]", t)
    t = re.sub(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", "[email removed]", t)
    t = re.sub(r"\b([\w-]+)\.([\w-]+)\.ts\.net\b", r"[this computer].[tailnet].ts.net", t)
    t = re.sub(r"(https?://[^/\s]*ntfy[^/\s]*/)[\w-]+", r"\1[topic removed]", t)
    t = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9+/=._-]{8,}", r"\1 [removed]", t)
    t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", _ip, t)
    host = platform.node()
    if len(host) > 2:
        t = re.sub(re.escape(host), "[computer name]", t, flags=re.I)
    home = str(Path.home())
    if len(home) > 3:
        t = t.replace(home, "~")
    return t


def _ip(m):
    """Home-network and well-known public DNS addresses stay; any other internet address is someone's location."""
    try:
        a = ipaddress.ip_address(m.group(0))
    except ValueError:
        return m.group(0)
    if not a.is_global or str(a) in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"):
        return m.group(0)
    return "[internet address]"


def _run(cmd, timeout=10):
    try:
        kw = {"creationflags": 0x08000000} if WIN else {}
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace", **kw)
        return p.returncode, p.stdout + p.stderr
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def load_env(path):
    out = {}
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def fetch(port, path, timeout=6):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"_error": type(e).__name__}


def service_state():
    if WIN:
        code, out = _run(["schtasks", "/query", "/tn", "Network Command Center", "/fo", "list"])
        m = re.search(r":\s*(Running|Ready|Disabled|Queued)\s*$", out, re.M)
        return "Task Scheduler task: " + (m.group(1) if m else ("found" if code == 0 else "not installed"))
    code, out = _run(["systemctl", "--user", "is-active", "ncc.service"])
    return "systemd user service ncc.service: " + (out.strip() or "unknown")


def log_tail(n=40):
    if WIN:
        p = BASE / "data" / "ncc.log"
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
        except OSError:
            return ["(no log file yet)"]
    else:
        _, out = _run(["journalctl", "--user", "-u", "ncc.service", "-n", str(n), "--no-pager", "-o", "cat"])
        lines = out.splitlines()[-n:]
    return [redact(l)[:300] for l in lines]


def tailscale_state():
    exe = shutil.which("tailscale") or (r"C:\Program Files\Tailscale\tailscale.exe" if WIN and Path(r"C:\Program Files\Tailscale\tailscale.exe").exists() else None)
    if not exe:
        return "not installed"
    code, out = _run([exe, "status", "--json"])
    try:
        st = json.loads(out[out.index("{"):])
        state = st.get("BackendState")
    except ValueError:
        state = "unknown"
    _, sv = _run([exe, "serve", "status"])
    sharing = "dashboard shared on Tailscale" if "127.0.0.1:" in sv else "dashboard not shared"
    return f"{state}; {sharing}"


def build(status, cfg, secrets_keys, extra=None, logs=None):
    """The report as Markdown. `status` is what /api/status returns ({} if the dashboard isn't answering)."""
    L = []
    add = L.append
    add("# Network Command Center health report")
    add(f"Made {time.strftime('%Y-%m-%d %H:%M')} on the computer that runs the dashboard. Passwords, emails and private names are removed.")
    add(f"Project and AI guide: {REPO} (AGENTS.md in the dashboard folder explains how everything works).")
    add("")
    add("## Computer")
    osname = f"Windows {platform.release()} (build {platform.version()})" if WIN else (_os_release() or platform.platform())
    add(f"- System: {osname}, {platform.machine()}; Python {platform.python_version()}")
    add(f"- Dashboard folder: {redact(str(BASE))}")
    for k, v in (extra or {}).items():
        add(f"- {k}: {redact(v)}")
    add("")
    add("## Settings (config/ncc.env, secrets left out)")
    keys = ("PORT", "BIND", "STYLE", "ROUTER", "PIHOLE_URL", "ADGUARD_URL", "PIHOLE_CONTROLS", "PIHOLE_LISTS", "PIHOLE_BLOCK",
            "SYSTEM_CONTROLS", "AI_ASSISTANT", "AI_ENABLED", "REMOTE_DESKTOP", "RDP_KIND", "INTERVAL", "WAN_TARGET", "GATEWAY")
    add("- " + ", ".join(f"{k}={redact(cfg[k])}" for k in keys if cfg.get(k) not in (None, "")))
    add(f"- ALLOWED_HOSTS set: {'yes' if cfg.get('ALLOWED_HOSTS') else 'no'}")
    add(f"- Saved secrets (names only): {', '.join(sorted(secrets_keys)) or 'none'}")
    add("")
    add("## Dashboard")
    if not status or status.get("_error"):
        add(f"- NOT ANSWERING on http://127.0.0.1:{cfg.get('PORT', '8088')} ({(status or {}).get('_error', 'no reply')})")
    else:
        last = status.get("last") or {}
        add(f"- Version {status.get('version')}; last check {int(time.time() - (last.get('ts') or time.time()))} s ago")
        for k in ("gw", "wan", "https", "dns"):
            v = last.get(k) or {}
            add(f"- {dict(gw='Router', wan='Internet ping', https='Website check', dns='DNS lookup')[k]}: "
                f"{'OK' if v.get('ok') else 'FAILING'}" + (f", {v.get('ms')} ms" if v.get("ms") is not None else "")
                + (f", {v.get('loss')}% loss" if v.get("loss") else ""))
        add(f"- Internet overall: {'up' if last.get('internet') else 'DOWN'}")
        s = last.get("sys") or {}
        if s:
            add(f"- This computer: CPU {s.get('cpu')}%, memory {s.get('mem_pct')}% used, disk {s.get('disk_pct')}% used"
                + (f", {s.get('temp')} C" if s.get("temp") else "") + f", up {int((s.get('uptime') or 0) // 3600)} h")
        ph = status.get("pihole") or {}
        if ph.get("configured"):
            add(f"- Ad blocker ({ph.get('name')}): {'OK' if ph.get('ok') else 'NOT OK'}, blocking {ph.get('blocking')}, "
                f"{ph.get('pct')}% blocked today, DNS {'OK' if (ph.get('dns') or {}).get('ok') else 'FAILING'}"
                + (f", error {redact(ph.get('error'))}" if ph.get("error") else ""))
        else:
            add("- Ad blocker: none connected")
        dm = status.get("device_meta") or {}
        if dm:
            add(f"- Devices: list from {dm.get('source')}; {dm.get('ping_replied')}/{dm.get('pinged')} answered ping")
        f = status.get("findings") or []
        add("")
        add("## Problems the dashboard sees right now")
        if f:
            for x in f:
                add(f"- [{x.get('level')}] {redact(x.get('title'))}: {redact(x.get('detail'))}")
        else:
            add("- none")
    if logs:
        add("")
        add("## Recent log lines")
        add("```")
        L.extend(logs)
        add("```")
    return "\n".join(L) + "\n"


def _os_release():
    try:
        return load_env("/etc/os-release").get("PRETTY_NAME")
    except Exception:
        return None


def main():
    cfg = {"PORT": "8088"}
    cfg.update(load_env(BASE / "config" / "ncc.env"))
    secrets_keys = list(load_env(Path.home() / ".config" / "ncc" / "secrets.env"))
    status = fetch(cfg.get("PORT", "8088"), "/api/status")
    extra = {"Service": service_state(), "Tailscale": tailscale_state()}
    sys.stdout.write(build(status, cfg, secrets_keys, extra, log_tail(15 if "--short" in sys.argv else 40)))


if __name__ == "__main__":
    main()
