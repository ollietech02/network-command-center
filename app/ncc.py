#!/usr/bin/env python3
"""Network Command Center - single-process collector + web UI.

Standard library only. Binds to 127.0.0.1 by default. Read-only by default:
Pi-hole changes are off unless PIHOLE_CONTROLS=1 (blocking toggle) or
PIHOLE_LISTS=1 (allow/deny lists) or PIHOLE_BLOCK=1 (per-device internet block); restart buttons need SYSTEM_CONTROLS=1. Every POST requires a per-process CSRF token.
"""
import base64
import collections
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
STATIC = BASE / "app" / "static"
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)
WIN = os.name == "nt"
sys.path.insert(0, str(Path(__file__).resolve().parent))  # -I leaves the script's own folder off the path
import doctor  # noqa: E402  (the "ncc doctor" health report, also behind "Copy for my AI")
if WIN:
    import ncc_win as W
    _ts = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tailscale"
    if _ts.is_dir() and str(_ts).lower() not in os.environ.get("PATH", "").lower():
        os.environ["PATH"] += os.pathsep + str(_ts)  # installed after this sign-in started: not on our PATH yet
    if sys.stdout is None:  # pythonw (no console): keep a small log file instead
        _lf = DATA / "ncc.log"
        if _lf.exists() and _lf.stat().st_size > 2_000_000:
            _lf.replace(DATA / "ncc.log.1")
        sys.stdout = sys.stderr = open(_lf, "a", buffering=1, encoding="utf-8")


def load_env(path):
    out = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return out


CFG = {
    "BIND": "127.0.0.1", "PORT": "8088", "INTERVAL": "60", "DEVICE_INTERVAL": "300",
    "GATEWAY": "", "WAN_TARGET": "1.1.1.1", "HTTPS_URL": "https://www.google.com/generate_204",
    "DNS_TEST_NAME": "example.com", "PIHOLE_URL": "", "PIHOLE_CONTROLS": "0", "PIHOLE_LISTS": "0", "PIHOLE_BLOCK": "0", "SYSTEM_CONTROLS": "0",
    "AI_ENABLED": "0", "AI_ASSISTANT": "", "AI_MODEL": "", "NTFY_URL": "", "DESKTOP_NOTIFY": "1", "SPEEDTEST_EVERY_MIN": "60",
    "RETENTION_DAYS": "30", "ADGUARD_URL": "", "ROUTER": "generic", "STYLE": "scifi", "REMOTE_DESKTOP": "0", "RDP_USER": "remote",
}
CFG.update(load_env(BASE / "config" / "ncc.env"))
SECRETS = load_env(Path.home() / ".config" / "ncc" / "secrets.env")


def load_csrf():
    """Keep the CSRF token across restarts so an open dashboard window can still save (file is chmod 600)."""
    f = DATA / ".csrf"
    try:
        t = f.read_text().strip()
        if len(t) >= 32:
            return t
    except OSError:
        pass
    t = secrets.token_urlsafe(24)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(t)
    return t


CSRF = load_csrf()
STOP = threading.Event()
LOCK = threading.Lock()
VERSION = "1.0"  # first official version, 2026-10-26
STATE = {"started": time.time(), "last": {}, "pihole": {"configured": False}, "devices": [],
         "gateway": {}, "security": {}, "listeners": []}


_SSL = {}


def ssl_ctx(insecure=False):
    """Build each SSL context once; creating one per request churns memory."""
    if insecure not in _SSL:
        c = ssl.create_default_context()
        if insecure:
            c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        _SSL[insecure] = c
    return _SSL[insecure]


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


def run(cmd, timeout=10):
    if WIN:
        return W.run(cmd, timeout)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, ""


# ---------------------------------------------------------------- database
@contextmanager
def db():
    """Commit and *close* - `with sqlite3.connect()` alone leaves the connection (and its page cache) open."""
    c = sqlite3.connect(DATA / "ncc.db", timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA cache_size=-256")
    try:
        with c:
            yield c
    finally:
        c.close()


def init_db():
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS checks(ts INTEGER PRIMARY KEY, internet INTEGER, gw_ok INTEGER,
          gw_ms REAL, gw_loss REAL, wan_ms REAL, wan_loss REAL, https_ok INTEGER, https_ms REAL,
          dns_ok INTEGER, dns_ms REAL, pihole_ok INTEGER, cpu REAL, mem REAL, temp REAL,
          rx_bps REAL, tx_bps REAL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER,
          level TEXT, kind TEXT, msg TEXT);
        CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT, name TEXT, vendor TEXT,
          conn TEXT, gw_status TEXT, gw_last TEXT, first_seen INTEGER, last_seen INTEGER,
          ping_ok INTEGER, ping_ts INTEGER, baseline INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS usage(day TEXT PRIMARY KEY, rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS speedtests(ts INTEGER PRIMARY KEY, down_mbps REAL, up_mbps REAL,
          ping_ms REAL, jitter_ms REAL, colo TEXT, trigger TEXT);
        """)
        cols = {r[1] for r in c.execute("PRAGMA table_info(devices)")}
        if "label" not in cols:
            c.execute("ALTER TABLE devices ADD COLUMN label TEXT")
        if "dtype" not in cols:
            c.execute("ALTER TABLE devices ADD COLUMN dtype TEXT")
        if "maker" not in cols:
            c.execute("ALTER TABLE devices ADD COLUMN maker TEXT")


def kv_get(k, default=None):
    with db() as c:
        r = c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    return json.loads(r["v"]) if r else default


# ---------------------------------------------------------------- user settings (Tools & settings tab)
WEEKLY_SECTIONS = ("internet", "speed", "data", "pihole", "devices", "signins", "sites", "laptop")
SESSION_HOURS = (1, 12, 24, 168, 720)       # how long a sign-in lasts: 1 h, 12 h, 1 day, 7 days, 30 days
LIVE_PERIODS = (1, 2, 5, 10)                 # seconds between live dashboard updates
SPEED_EVERY = (10, 30, 60, 120, 180, 360, 720)  # minutes between scheduled speed tests


def settings():
    try:
        every = int(CFG["SPEEDTEST_EVERY_MIN"])
    except ValueError:
        every = 60
    s = {"live_period": 1, "speedtest_mode": "every", "speedtest_every_min": every, "speedtest_at": "03:00", "web_access": False,
         "web_session_h": 168, "pin_session_h": 720, "weekly_report": True, "weekly_day": 6, "weekly_hour": 18,
         "weekly_sections": list(WEEKLY_SECTIONS), "speed_quiet_on": False, "speed_quiet_from": "23:00", "speed_quiet_to": "07:00",
         "speed_alert_mbps": 0, "data_cap_gb": 0, "billing_day": 1, "site_interval_min": 5, "site_fail_n": 2, "site_slow_ms": 0}
    s.update(kv_get("settings", {}) or {})
    return s


def save_settings(body):
    s = settings()
    if "live_period" in body:
        v = body["live_period"]
        if v not in LIVE_PERIODS:
            raise ValueError("Update speed must be 1, 2, 5 or 10 seconds.")
        s["live_period"] = v
    if "speedtest_mode" in body:
        if body["speedtest_mode"] not in ("every", "daily", "off"):
            raise ValueError("Unknown speed test schedule.")
        s["speedtest_mode"] = body["speedtest_mode"]
    if "speedtest_every_min" in body:
        if body["speedtest_every_min"] not in SPEED_EVERY:
            raise ValueError("Unknown speed test interval.")
        s["speedtest_every_min"] = body["speedtest_every_min"]
    if "speedtest_at" in body:
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(body["speedtest_at"])):
            raise ValueError("Time must look like 03:00.")
        s["speedtest_at"] = body["speedtest_at"]
    if "ai_assistant" in body:
        if body["ai_assistant"] not in list(AI_TOOLS) + ["off"]:
            raise ValueError("Unknown AI assistant.")
        s["ai_assistant"] = body["ai_assistant"]
    if "web_access" in body:
        s["web_access"] = body["web_access"] is True
        if not s["web_access"]:
            kv_set("settings", s)
            kick_streams()  # web visitors watching right now are cut off
    if "weekly_report" in body:
        s["weekly_report"] = body["weekly_report"] is True
    if "weekly_day" in body:
        if body["weekly_day"] not in range(7):
            raise ValueError("Unknown day.")
        s["weekly_day"] = body["weekly_day"]
    if "weekly_hour" in body:
        if body["weekly_hour"] not in range(24):
            raise ValueError("Unknown hour.")
        s["weekly_hour"] = body["weekly_hour"]
    hhmm = r"([01]\d|2[0-3]):[0-5]\d"
    if "speed_quiet_on" in body:
        s["speed_quiet_on"] = body["speed_quiet_on"] is True
    for k in ("speed_quiet_from", "speed_quiet_to"):
        if k in body:
            if not re.fullmatch(hhmm, str(body[k])):
                raise ValueError("Time must look like 23:00.")
            s[k] = body[k]
    checks = {"speed_alert_mbps": (0, 5000, "Slow-speed alert must be 0 (off) to 5000 Mbps."),
              "data_cap_gb": (0, 100000, "Data cap must be 0 (none) to 100000 GB."),
              "billing_day": (1, 28, "Billing day must be 1 to 28."),
              "site_slow_ms": (0, 60000, "Slow limit must be 0 (off) to 60000 ms.")}
    for k, (lo, hi, msg) in checks.items():
        if k in body:
            if not isinstance(body[k], int) or isinstance(body[k], bool) or not lo <= body[k] <= hi:
                raise ValueError(msg)
            s[k] = body[k]
    if "site_interval_min" in body:
        if body["site_interval_min"] not in (1, 5, 15, 30, 60):
            raise ValueError("Unknown check interval.")
        s["site_interval_min"] = body["site_interval_min"]
    if "site_fail_n" in body:
        if body["site_fail_n"] not in (1, 2, 3, 5):
            raise ValueError("Unknown number of failures.")
        s["site_fail_n"] = body["site_fail_n"]
    if "weekly_sections" in body:
        if not isinstance(body["weekly_sections"], list) or not set(body["weekly_sections"]) <= set(WEEKLY_SECTIONS):
            raise ValueError("Unknown report section.")
        s["weekly_sections"] = [x for x in WEEKLY_SECTIONS if x in body["weekly_sections"]]
    for k in ("web_session_h", "pin_session_h"):
        if k in body:
            if body[k] not in SESSION_HOURS:
                raise ValueError("Unknown sign-in length.")
            s[k] = body[k]
    kv_set("settings", s)
    return s


def kv_set(k, v):
    with db() as c:
        c.execute("INSERT OR REPLACE INTO kv VALUES(?,?)", (k, json.dumps(v)))


# ---------------------------------------------------------------- events / notify
_last_notify = {}
NTFY_FILE = DATA / ".ntfy"  # own file, so rewriting secrets.env (e.g. a new Pi-hole password) can't erase it


def ntfy_url():
    try:
        u = NTFY_FILE.read_text().strip()
    except OSError:
        u = ""
    return u or CFG.get("NTFY_URL") or SECRETS.get("NTFY_URL") or ""


def new_ntfy_topic():
    url = f"https://ntfy.sh/ncc-{secrets.token_hex(10)}"
    fd = os.open(NTFY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(url + "\n")
    _last_notify.clear()
    return url


# Optional: ntfy.sh also emails each alert (free, ~16 emails a day). For a Family Setup Apple Watch, which can't run
# the ntfy app but does get Mail. The address lives in its own 600 file and is never logged or shown in full.
EMAIL_FILE = DATA / ".alert_email"
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


ALERT_EMAILS_MAX = 5


def alert_emails():
    """Every address that gets email copies of alerts (one per line in data/.alert_email)."""
    try:
        return [x.strip() for x in EMAIL_FILE.read_text().splitlines() if x.strip()]
    except OSError:
        return []


def set_alert_emails(addrs):
    clean = []
    for addr in addrs:
        addr = (addr or "").strip()
        if not addr:
            continue
        if len(addr) > 254 or not EMAIL_RE.match(addr):
            raise ValueError(f"\"{addr[:60]}\" doesn't look like an email address.")
        if addr.lower() not in (c.lower() for c in clean):
            clean.append(addr)
    if len(clean) > ALERT_EMAILS_MAX:
        raise ValueError(f"Up to {ALERT_EMAILS_MAX} alert emails.")
    if not clean:
        EMAIL_FILE.unlink(missing_ok=True)
        return []
    fd = os.open(EMAIL_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(clean) + "\n")
    return clean


def mask_email(addr):
    if "@" not in addr:
        return ""
    user, dom = addr.split("@", 1)
    return f"{user[:1]}{'•' * min(6, max(1, len(user) - 1))}@{dom}"


# ---- email goes out through the user's own Gmail (ntfy.sh stopped sending email for accounts-free users in 2026).
# data/.smtp holds {user, pass} (a Google app password), mode 600; it is never sent to the browser or logged.
SMTP_FILE = DATA / ".smtp"


def smtp_conf():
    try:
        c = json.loads(SMTP_FILE.read_text())
        return c if c.get("user") and c.get("pass") else None
    except (OSError, ValueError):
        return None


def _smtp_login(user, pw):
    s = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15, context=ssl.create_default_context())
    try:
        s.login(user, pw)
    except smtplib.SMTPAuthenticationError:
        s.close()
        raise
    except smtplib.SMTPServerDisconnected:  # Gmail hangs up instead of answering for some unknown addresses
        s.close()
        raise smtplib.SMTPAuthenticationError(535, b"disconnected during login")
    except Exception:
        s.close()
        raise
    return s


def set_smtp(user, pw):
    """Check the Gmail address + app password with a real login before saving them."""
    user, pw = (user or "").strip(), re.sub(r"\s+", "", pw or "")
    if len(user) > 254 or not EMAIL_RE.match(user):
        raise ValueError("That doesn't look like a Gmail address.")
    if not re.fullmatch(r"[A-Za-z]{16}", pw):
        raise ValueError("An app password is 16 letters (Google shows it in 4 groups of 4).")
    try:
        _smtp_login(user, pw).quit()
    except smtplib.SMTPAuthenticationError:
        raise ValueError("Gmail didn't accept that address and app password. Check both and try again.")
    except (OSError, smtplib.SMTPException) as e:
        raise RuntimeError(f"Couldn't reach Gmail ({type(e).__name__}). Is the internet up?")
    fd = os.open(SMTP_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"user": user, "pass": pw}, fh)
    return user


def send_email(to, subject, body):
    """Send one email to each address in `to` over a single Gmail connection. Returns how many went out."""
    c = smtp_conf()
    if not c:
        return 0
    sent = 0
    s = _smtp_login(c["user"], c["pass"])
    try:
        for addr in to:
            m = EmailMessage()
            m["From"], m["To"], m["Subject"] = f"Network Command Center <{c['user']}>", addr, subject
            m["Date"], m["Message-ID"] = formatdate(localtime=True), make_msgid(domain="ncc.local")
            m.set_content(body)
            try:
                s.send_message(m)
                sent += 1
            except smtplib.SMTPException as e:  # never log the address
                log("email failed:", type(e).__name__)
    finally:
        try:
            s.quit()
        except Exception:
            pass
    return sent


def send_ntfy(title, msg, level, email_copy=True):
    """Push to the ntfy topic and email a copy, if set. Returns (push_ok, email_ok or None when no email is set)."""
    url, emails = ntfy_url(), (alert_emails() if email_copy else [])
    mail = None
    if emails:
        try:
            mail = send_email(emails, title, msg) == len(emails)
        except Exception as e:  # never let a mail problem stop the push
            log("alert email failed:", type(e).__name__)
            mail = False
    if not url:
        return False, mail
    tags = {"crit": "rotating_light", "warn": "warning"}.get(level, "white_check_mark")
    headers = {"Title": title, "Tags": tags, "Priority": "high" if level == "crit" else "default"}
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=msg.encode(), headers=headers), timeout=8).close()
        return True, mail
    except Exception as e:  # never let notification failures break collection
        log("ntfy failed:", type(e).__name__)
        return False, mail


_log_seen = {}


def log_once(key, *msg, period=3600):
    """Log a line at most once per period per key (internet bots hit the public address all day)."""
    now = time.time()
    if now - _log_seen.get(key, 0) < period:
        return
    if len(_log_seen) > 2000:
        _log_seen.clear()
    _log_seen[key] = now
    log(*msg)


def event(level, kind, msg, notify=True):
    with db() as c:
        c.execute("INSERT INTO events(ts,level,kind,msg) VALUES(?,?,?,?)", (int(time.time()), level, kind, msg))
    log(f"[{level}] {kind}: {msg}")
    if notify and level in ("warn", "crit") or notify == "phone":
        now = time.time()
        key = msg if kind in ("new-device", "web-signin", "site-down", "site-up") else kind  # every new device / web sign-in gets its own alert
        if now - _last_notify.get(key, 0) < 900:  # 15-minute rate limit per kind
            return
        _last_notify[key] = now
        if CFG["DESKTOP_NOTIFY"] == "1" and WIN:
            W.notify(f"NCC: {kind}", msg)
        elif CFG["DESKTOP_NOTIFY"] == "1" and shutil.which("notify-send"):
            run(["notify-send", "-a", "Network Command Center",
                 "-u", "critical" if level == "crit" else "normal", f"NCC: {kind}", msg], 5)
        return send_ntfy(f"NCC: {kind}", msg, level)


# ---------------------------------------------------------------- network checks
def default_gateway():
    if CFG["GATEWAY"]:
        return CFG["GATEWAY"]
    if WIN:
        return W.iface().get("gateway")
    _, out = run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\S+)", out)
    return m.group(1) if m else None


def local_iface():
    if WIN:
        return {k: v for k, v in W.iface().items() if k in ("dev", "ip", "subnet")}
    _, out = run(["ip", "-j", "route", "show", "default"])
    try:
        r = json.loads(out)[0]
        dev = r["dev"]
        _, a = run(["ip", "-j", "addr", "show", dev])
        info = next(x for x in json.loads(a)[0]["addr_info"] if x["family"] == "inet")
        net = ipaddress.ip_network(f"{info['local']}/{info['prefixlen']}", strict=False)
        return {"dev": dev, "ip": info["local"], "subnet": str(net)}
    except Exception:
        return {}


def ping(host, count=3, timeout=1):
    if WIN:
        return W.ping(host, count, timeout)
    code, out = run(["ping", "-n", "-q", "-c", str(count), "-W", str(timeout), "-i", "0.3", host],
                    count * timeout + 5)
    loss = re.search(r"([\d.]+)% packet loss", out)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", out)
    return {"ok": code == 0, "loss": float(loss.group(1)) if loss else 100.0,
            "ms": float(rtt.group(1)) if rtt else None}


def https_check(url):
    t = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ncc/1.0"})
        with urllib.request.urlopen(req, timeout=8, context=ssl_ctx()) as r:
            r.read(256)
            return {"ok": r.status < 500, "ms": round((time.monotonic() - t) * 1000, 1)}
    except urllib.error.HTTPError as e:
        return {"ok": e.code < 500, "ms": round((time.monotonic() - t) * 1000, 1)}
    except Exception as e:
        return {"ok": False, "ms": None, "err": type(e).__name__}


def dig_a(server, name, timeout=2):
    """A-record answers from one DNS server (list of addresses; empty if none or no reply)."""
    if WIN or not shutil.which("dig"):
        return W.dns_a(name, server, timeout)["ips"] if WIN else []
    _, out = run(["dig", "+short", f"+time={timeout}", "+tries=2", "@" + server, name, "A"], 4 * timeout)
    return [x for x in out.split() if re.fullmatch(r"[\d.]+", x)]


def dns_check(name, server=None):
    if WIN:
        server = server or W.system_dns()
        if not server:
            return {"ok": False, "ms": None}
        r = W.dns_a(name, server)
        return {"ok": r["ok"], "ms": r["ms"]}
    cmd = ["dig", "+time=2", "+tries=1", "+noall", "+answer", "+stats", name]
    if server:
        cmd.insert(1, "@" + server)
    code, out = run(cmd, 6)
    ms = re.search(r"Query time: (\d+) msec", out)
    answered = bool(re.search(r"\sIN\s+(A|CNAME)\s", out))
    return {"ok": code == 0 and answered, "ms": float(ms.group(1)) if ms else None}


# ---------------------------------------------------------------- system metrics
_cpu_prev = {}


def cpu_pct(key):
    if WIN:
        idle, total = W.cpu_times()
    else:
        with open("/proc/stat") as f:
            v = list(map(int, f.readline().split()[1:]))
        idle, total = v[3] + v[4], sum(v)
    cpu, prev = None, _cpu_prev.get(key)
    if prev:
        dt = total - prev[1]
        cpu = round(100 * (1 - (idle - prev[0]) / dt), 1) if dt else 0.0
    _cpu_prev[key] = (idle, total)
    return cpu


def meminfo():
    if WIN:
        return W.meminfo()
    mi = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, val = line.split(":")
            mi[k] = int(val.split()[0]) * 1024
    return mi


def cpu_temp():
    if WIN:
        return None  # Windows only shares CPU temperature with admin tools
    for z in Path("/sys/class/thermal").glob("thermal_zone*"):
        try:
            if (z / "type").read_text().strip() == "x86_pkg_temp":
                return int((z / "temp").read_text()) / 1000
        except Exception:
            pass
    return None


def net_dev(dev):
    """(rx_bytes, tx_bytes) for one interface from /proc/net/dev."""
    if WIN:
        return W.net_dev(dev)
    with open("/proc/net/dev") as f:
        for line in f:
            if line.strip().startswith(dev + ":"):
                v = line.split(":", 1)[1].split()
                return int(v[0]), int(v[8])
    return None


def uptime_s():
    return W.uptime() if WIN else float(open("/proc/uptime").read().split()[0])


def sysmetrics():
    if WIN:
        cpu, mi, du = cpu_pct("main"), meminfo(), shutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\")
        return {"cpu": cpu, "cores": os.cpu_count(), "load": None, "mem_total": mi["MemTotal"], "mem_avail": mi["MemAvailable"],
                "mem_pct": round(100 * (1 - mi["MemAvailable"] / mi["MemTotal"]), 1),
                "swap_total": mi["SwapTotal"], "swap_used": mi["SwapTotal"] - mi["SwapFree"],
                "disk_total": du.total, "disk_free": du.free, "disk_pct": round(100 * du.used / du.total, 1),
                "disk_name": os.environ.get("SystemDrive", "C:"), "temp": None, "temps": {}, "battery": W.battery(),
                "uptime": W.uptime(), "ncc_rss": W.own_rss(), "os": "windows"}
    cpu = cpu_pct("main")
    mi = meminfo()
    st = os.statvfs("/")
    temps = {}
    for z in Path("/sys/class/thermal").glob("thermal_zone*"):
        try:
            temps[(z / "type").read_text().strip()] = int((z / "temp").read_text()) / 1000
        except Exception:
            pass
    for h in Path("/sys/class/hwmon").glob("hwmon*"):
        try:
            if (h / "name").read_text().strip() != "coretemp":
                continue
            for t in h.glob("temp*_input"):
                lbl = t.with_name(t.name.replace("_input", "_label"))
                key = lbl.read_text().strip() if lbl.exists() else t.name
                temps["coretemp " + key] = int(t.read_text()) / 1000
        except Exception:
            pass
    cpu_temp = temps.get("x86_pkg_temp") or temps.get("coretemp Package id 0")
    bat = None
    bp = Path("/sys/class/power_supply/BAT0")
    if bp.exists():
        try:
            bat = {"pct": int((bp / "capacity").read_text()), "status": (bp / "status").read_text().strip()}
        except Exception:
            pass
    load = open("/proc/loadavg").read().split()[:3]
    return {
        "cpu": cpu, "cores": os.cpu_count(), "load": [float(x) for x in load],
        "mem_total": mi["MemTotal"], "mem_avail": mi["MemAvailable"],
        "mem_pct": round(100 * (1 - mi["MemAvailable"] / mi["MemTotal"]), 1),
        "swap_total": mi.get("SwapTotal", 0), "swap_used": mi.get("SwapTotal", 0) - mi.get("SwapFree", 0),
        "disk_total": st.f_blocks * st.f_frsize, "disk_free": st.f_bavail * st.f_frsize,
        "disk_pct": round(100 * (1 - st.f_bavail / st.f_blocks), 1),
        "temp": cpu_temp, "temps": temps, "battery": bat,
        "uptime": float(open("/proc/uptime").read().split()[0]),
        "ncc_rss": int(re.search(r"VmRSS:\s+(\d+)", open("/proc/self/status").read()).group(1)) * 1024,
    }


# ---------------------------------------------------------------- AT&T gateway (BGW210 status pages)
def gw_fetch(path, timeout=10):
    if CFG["ROUTER"] != "att":  # these status pages exist only on AT&T gateways (BGW210/BGW320 family)
        raise RuntimeError("router stats are only for AT&T gateways (ROUTER=att)")
    gw = default_gateway()
    with urllib.request.urlopen(f"http://{gw}{path}", timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _cell(s):
    s = re.sub(r"<br\s*/?>", "\n", s)
    s = re.sub(r"<img[^>]*alt=\"([^\"]*)\"[^>]*>", r" (\1)", s)
    return html.unescape(re.sub(r"<[^>]+>", "", s)).replace("\xa0", " ").strip()


def gw_rows(page):
    return [(_cell(k), _cell(v)) for k, v in re.findall(r"<th[^>]*>(.*?)</th>\s*<td[^>]*>(.*?)</td>", page, re.S)]


_wan_prev = None


def gateway_broadband():
    """Parse broadbandstatistics.ha (read-only status page, no login)."""
    global _wan_prev
    rows = gw_rows(gw_fetch("/cgi-bin/broadbandstatistics.ha"))
    d = {}
    for k, v in rows:
        d.setdefault(k, v)  # first occurrence = IPv4 / WAN interface section
    out = {"connection": d.get("Broadband Connection"), "source": d.get("Broadband Connection Source"),
           "type": d.get("Broadband Network Type"), "line": d.get("Line State"),
           "speed": d.get("Current Speed (Mbps)"), "rx_drops": d.get("Receive Drops"),
           "tx_drops": d.get("Transmit Drops"), "rx_errors": d.get("Receive Errors"),
           "tx_errors": d.get("Transmit Errors"), "ipv6": d.get("Status")}
    try:
        rx, tx, now = int(d["Receive Bytes"]), int(d["Transmit Bytes"]), time.time()
        out["rx_total"], out["tx_total"] = rx, tx
        if _wan_prev and rx == _wan_prev[0] and tx == _wan_prev[1] and now - _wan_prev[2] < 3:
            return out  # the gateway refreshes its counters every second or two: wait for new numbers, don't report 0
        if _wan_prev and rx >= _wan_prev[0] and tx >= _wan_prev[1]:
            dt = now - _wan_prev[2]
            out["rx_bps"] = round((rx - _wan_prev[0]) * 8 / dt)
            out["tx_bps"] = round((tx - _wan_prev[1]) * 8 / dt)
        _wan_prev = (rx, tx, now)
        out["rx_total"], out["tx_total"] = rx, tx
    except (KeyError, ValueError):
        pass
    return out


def gateway_sysinfo():
    info = {}
    for k, v in gw_rows(gw_fetch("/cgi-bin/sysinfo.ha")):
        if k in ("Manufacturer", "Model Number", "Software Version", "Time Since Last Reboot"):
            info[k] = v
    return info


def gateway_devices():
    page = gw_fetch("/cgi-bin/devices.ha", 20)
    devs = []
    for blk in re.split(r"<tr><th scope=\"row\">MAC Address</th>", page)[1:]:
        d = {}
        for k, v in gw_rows("<tr><th>MAC Address</th>" + blk):
            d.setdefault(k, v)
        mac = d.get("MAC Address", "").lower()
        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            continue
        ip, name = "", d.get("Name", "")
        if "IPv4 Address / Name" in d:
            parts = [p.strip() for p in d["IPv4 Address / Name"].split("/", 1)]
            ip, name = parts[0], parts[1] if len(parts) > 1 else ""
        conn = d.get("Connection Type", "")
        band = re.search(r"(2\.4|5) GHz", conn)
        sig = re.search(r"Wi-Fi (\d) bars", conn)
        if conn.startswith("Wi-Fi"):
            conn_s = "Wi-Fi " + (band.group(0) if band else "")
        else:
            conn_s = conn.split("\n")[0].strip()
        devs.append({"mac": mac, "ip": ip, "name": name, "status": d.get("Status", ""),
                     "last": d.get("Last Activity", ""), "conn": conn_s.strip(),
                     "signal": int(sig.group(1)) if sig else None})
    return devs


# ---------------------------------------------------------------- vendor lookup (local IEEE OUI db)
_oui = {}


def vendors(macs):
    need = {m[:8].replace(":", "").upper() for m in macs} - set(_oui)
    if need:
        f = Path("/usr/share/ieee-data/oui.csv")
        if f.exists():
            import csv
            with f.open(newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.reader(fh):
                    if len(row) > 2 and row[1] in need:
                        _oui[row[1]] = row[2].strip()
        for n in need:
            _oui.setdefault(n, "")
    res = {}
    for m in macs:
        if int(m[1], 16) & 2:
            res[m] = "Private / randomized MAC"
        else:
            res[m] = _oui.get(m[:8].replace(":", "").upper()) or "Unknown vendor"
    return res


def classify(name, vendor):
    s = f"{name} {vendor}".lower()
    rules = [("phone", r"iphone|android|pixel|galaxy|phone"), ("tv / media", r"tv|webos|roku|chromecast|firetv|apple tv|sonos"),
             ("laptop / pc", r"macbook|laptop|desktop|thinkpad|-pc\b|windows"),
             ("tablet", r"ipad|tablet"), ("dns / pi-hole", r"pihole|pi-hole"),
             ("raspberry pi", r"raspberry"), ("printer", r"printer|epson|brother|canon|hp inc"),
             ("smart home", r"echo|alexa|nest|ring|wyze|tuya|espressif|kasa|hue|simplelink|resideo|honeywell|amazon"),
             ("wi-fi extender", r"airties|att_4920|extender|mesh"), ("camera hub", r"vmb\d|arlo")]
    for label, rx in rules:
        if re.search(rx, s):
            return label
    return ""


def refresh_devices():
    iface = local_iface()
    try:
        gdevs = gateway_devices()
        src = "gateway"
    except Exception as e:
        log("gateway device list failed:", type(e).__name__)
        gdevs, src = [], "neighbor-table-only"
    # merge kernel neighbor table (devices this PC has talked to)
    neigh = {}
    try:
        for n in (W.neighbors() if WIN else json.loads(run(["ip", "-j", "neigh", "show"])[1])):
            if n.get("lladdr") and ":" not in n.get("dst", ""):
                mac = n["lladdr"].lower()
                # a MAC can appear under its old and new address; keep the one that answered most recently
                if mac not in neigh or "REACHABLE" in n.get("state", []):
                    neigh[mac] = (n["dst"], n.get("state", []))
    except Exception:
        pass
    bymac = {d["mac"]: d for d in gdevs}
    # the gateway's list keeps addresses from before Pi-hole took over DHCP; prefer the current lease
    leases = {}
    if PIHOLE and PIHOLE.ver == 6:
        try:
            leases = PIHOLE.leases()
        except Exception as e:
            log("pihole leases failed:", type(e).__name__)
    for mac, d in bymac.items():
        if mac in leases:
            d["ip"] = leases[mac]
        elif mac in neigh and "REACHABLE" in neigh[mac][1]:
            d["ip"] = neigh[mac][0]
    for mac, (ip, _st) in neigh.items():
        bymac.setdefault(mac, {"mac": mac, "ip": ip, "name": "", "status": "", "last": "", "conn": "", "signal": None})
        if not bymac[mac]["ip"]:
            bymac[mac]["ip"] = ip
    me = iface.get("ip")
    active = [d for d in bymac.values() if d["status"] == "on" or d["mac"] in neigh]
    # reachability: one ping to each active device with an IP in our own subnet only
    net = ipaddress.ip_network(iface["subnet"]) if iface.get("subnet") else None
    targets = [d for d in active if d["ip"] and net and ipaddress.ip_address(d["ip"]) in net]
    with ThreadPoolExecutor(8) as ex:
        res = dict(zip([d["mac"] for d in targets], ex.map(lambda d: ping(d["ip"], 3, 1)["ok"], targets)))
        # second, slower try for the ones that missed: sleeping phones/watches can take a few seconds to wake
        again = [d for d in targets if not res[d["mac"]]]
        res.update(zip([d["mac"] for d in again], ex.map(lambda d: ping(d["ip"], 4, 2)["ok"], again)))
    vend = vendors(list(bymac))
    now = int(time.time())
    baseline_done = kv_get("device_baseline_done", False)
    new_devs = []
    with db() as c:
        for mac, d in bymac.items():
            row = c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
            seen_now = d["status"] == "on" or mac in neigh
            pok = res.get(mac)
            if row is None:
                c.execute("""INSERT INTO devices(mac, ip, name, vendor, conn, gw_status, gw_last, first_seen,
                             last_seen, ping_ok, ping_ts, baseline) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (mac, d["ip"], d["name"], vend[mac], d["conn"], d["status"], d["last"],
                           now, now if seen_now else None, None if pok is None else int(pok),
                           now if pok is not None else None, 0 if baseline_done else 1))
                if baseline_done and seen_now:
                    new_devs.append(d)
            else:
                c.execute("""UPDATE devices SET ip=COALESCE(NULLIF(?,''),ip), name=COALESCE(NULLIF(?,''),name),
                             vendor=?, conn=COALESCE(NULLIF(?,''),conn), gw_status=?, gw_last=?,
                             last_seen=CASE WHEN ? THEN ? ELSE last_seen END,
                             ping_ok=COALESCE(?,ping_ok), ping_ts=CASE WHEN ? IS NULL THEN ping_ts ELSE ? END
                             WHERE mac=?""",
                          (d["ip"], d["name"], vend[mac], d["conn"], d["status"], d["last"],
                           int(seen_now), now, None if pok is None else int(pok), pok, now, mac))
    if not baseline_done:
        kv_set("device_baseline_done", True)
        event("info", "inventory", f"Baseline inventory recorded: {len(bymac)} devices known to the gateway.", False)
    for d in new_devs:
        event("warn", "new-device", f"New device joined: {d['name'] or 'unnamed'} {d['ip']} ({d['mac']}, "
              f"{vend[d['mac']]}). Unknown is not the same as malicious - verify it is yours.")
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM devices ORDER BY gw_status='on' DESC, last_seen DESC")]
    hint_rows(rows)
    for r in rows:
        r["kind"] = "this computer" if r["ip"] == me else ("gateway" if r["ip"] == default_gateway() else classify(r["name"] or "", r["vendor"] or ""))
        r["active"] = r["gw_status"] == "on" or r["mac"] in neigh
    user_types(rows)
    with LOCK:
        STATE["devices"] = rows
        STATE["device_meta"] = {"source": src, "ts": now, "iface": iface, "pinged": len(targets),
                                "ping_replied": sum(1 for v in res.values() if v)}


def is_private_mac(mac):
    return bool(int(mac[1], 16) & 2)


def hint_rows(rows):
    """Suggest a label for an unnamed private-MAC device whose hostname matches exactly one
    labelled device that isn't online right now (a phone that rotated its address). Only a hint."""
    labelled = {}
    for r in rows:
        if r.get("label") and r.get("name"):
            labelled.setdefault(r["name"], []).append(r)
    for r in rows:
        r["label_hint"] = None
        cands = labelled.get(r.get("name") or "", [])
        if not r.get("label") and is_private_mac(r["mac"]) and len(cands) == 1 and cands[0]["gw_status"] != "on":
            r["label_hint"] = {"label": cands[0]["label"], "mac": cands[0]["mac"]}


LABEL_RX = re.compile(r"[\x00-\x1f\x7f<>]")


def user_types(rows):
    for r in rows:
        # a company the user picked replaces the looked-up vendor (e.g. "Private / randomized MAC")
        r.setdefault("vendor_auto", r.get("vendor"))
        r["maker_user"] = bool(r.get("maker"))
        r["vendor"] = r.get("maker") or r["vendor_auto"]
        if r["maker_user"] and r.get("kind") not in ("this computer", "gateway"):
            r["kind"] = classify(r.get("name") or "", r["maker"]) or r.get("kind")
        r["kind_user"] = bool(r.get("dtype"))
        if r["kind_user"]:
            r["kind"] = r["dtype"]


def set_device(mac, label, dtype=False, maker=False):
    """Save a user name (and optionally a device type / company; False leaves that field alone)."""
    mac = str(mac).lower()
    if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("bad MAC address")
    label = LABEL_RX.sub("", str(label or "")).strip()[:40] or None
    sets, args = ["label=?"], [label]
    if dtype is not False:
        dtype = LABEL_RX.sub("", str(dtype or "")).strip().lower()[:24] or None
        sets.append("dtype=?")
        args.append(dtype)
    if maker is not False:
        maker = LABEL_RX.sub("", str(maker or "")).strip()[:40] or None
        sets.append("maker=?")
        args.append(maker)
    with db() as c:
        if not c.execute(f"UPDATE devices SET {', '.join(sets)} WHERE mac=?", (*args, mac)).rowcount:
            raise ValueError("unknown device")
        row = dict(c.execute("SELECT label, dtype, maker, name, vendor, ip FROM devices WHERE mac=?", (mac,)).fetchone())
    with LOCK:
        for r in STATE["devices"]:
            if r["mac"] == mac:
                r["label"], r["dtype"], r["maker"] = row["label"], row["dtype"], row["maker"]
                if not row["dtype"] and r.get("kind") not in ("this computer", "gateway"):  # back to the automatic guess
                    r["kind"] = classify(row["name"] or "", row["vendor"] or "")
        hint_rows(STATE["devices"])
        user_types(STATE["devices"])
    return {"ok": True, "mac": mac, "label": row["label"], "type": row["dtype"], "maker": row["maker"]}


def maker_search(q):
    """Company names from the local IEEE list containing q (for the Company picker)."""
    q = str(q).strip().lower()[:40]
    if len(q) < 2:
        return {"makers": []}
    f = Path("/usr/share/ieee-data/oui.csv")
    found = {}
    if f.exists():
        import csv
        with f.open(newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) > 2 and q in row[2].lower():
                    n = row[2].strip()
                    found[n] = found.get(n, 0) + 1
    # names that start with the query first, then the biggest makers (most address blocks)
    best = sorted(found, key=lambda n: (not n.lower().startswith(q), -found[n], n))
    return {"makers": best[:25]}


def oui_lookup(prefix):
    """Manufacturer blocks (IEEE MA-L) that start with a hex prefix. Scans the file; no cache kept."""
    p = re.sub(r"[^0-9a-f]", "", str(prefix).lower())[:6].upper()
    if len(p) < 2:
        return {"prefix": p, "count": 0, "vendors": []}
    f = Path("/usr/share/ieee-data/oui.csv")
    hits = []
    if f.exists():
        import csv
        with f.open(newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) > 2 and row[1].startswith(p):
                    hits.append((row[1], row[2].strip()))
    hits.sort()
    return {"prefix": p, "count": len(hits), "vendors": [{"oui": o, "vendor": v} for o, v in hits[:12]]}


# ---------------------------------------------------------------- Pi-hole (v6 REST API or v5 api.php)
class PiHole:
    name = "Pi-hole"

    def __init__(self, url, password):
        self.url, self.pw, self.sid, self.ver = url.rstrip("/"), password, None, None

    def _req(self, path, method="GET", body=None, auth=True):
        hdr = {"Accept": "application/json", "Content-Type": "application/json"}
        if auth and self.sid:
            hdr["X-FTL-SID"] = self.sid
        req = urllib.request.Request(self.url + path, method=method, headers=hdr,
                                     data=json.dumps(body).encode() if body is not None else None)
        ctx = ssl_ctx(CFG.get("PIHOLE_INSECURE_TLS") == "1") if self.url.startswith("https") else None  # v6 ships a self-signed cert
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            return json.loads(r.read() or b"{}")

    def detect(self):
        try:
            self._req("/api/info/version", auth=False)
            self.ver = 6
        except urllib.error.HTTPError as e:
            self.ver = 6 if e.code == 401 else 5
        except (urllib.error.URLError, OSError, ValueError):
            self.ver = 5
        return self.ver

    def login(self):
        r = self._req("/api/auth", "POST", {"password": self.pw}, auth=False)
        self.sid = r.get("session", {}).get("sid")

    def v6(self, path, method="GET", body=None):
        try:
            return self._req(path, method, body)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            self.login()
            return self._req(path, method, body)

    def v5(self, query):
        q = query + (f"&auth={urllib.request.quote(self.pw)}" if self.pw else "")
        with urllib.request.urlopen(f"{self.url}/admin/api.php?{q}", timeout=8) as r:
            return json.loads(r.read() or b"{}")

    def stats(self):
        if self.ver is None:
            self.detect()
        if self.ver == 6:
            s = self.v6("/api/stats/summary")
            b = self.v6("/api/dns/blocking")
            td = self.v6("/api/stats/top_domains?count=8")
            ta = self.v6("/api/stats/top_domains?blocked=true&count=8")
            tc = self.v6("/api/stats/top_clients?count=8")
            v = self.v6("/api/info/version")
            q = s.get("queries", {})
            return {"ok": True, "api": "v6", "version": v.get("version", {}).get("core", {}).get("local", {}).get("version"),
                    "total": q.get("total"), "blocked": q.get("blocked"), "pct": q.get("percent_blocked"),
                    "cached": q.get("cached"), "forwarded": q.get("forwarded"),
                    "clients": s.get("clients", {}).get("active"), "gravity": s.get("gravity", {}).get("domains_being_blocked"),
                    "blocking": b.get("blocking"), "timer": b.get("timer"),
                    "top_domains": [[x["domain"], x["count"]] for x in td.get("domains", [])],
                    "top_blocked": [[x["domain"], x["count"]] for x in ta.get("domains", [])],
                    "top_clients": [[x.get("name") or x.get("ip"), x["count"]] for x in tc.get("clients", [])]}
        s = self.v5("summaryRaw")
        top = self.v5("topItems=8") if self.pw else {}
        src = self.v5("getQuerySources=8") if self.pw else {}
        return {"ok": True, "api": "v5", "version": None, "total": s.get("dns_queries_today"),
                "blocked": s.get("ads_blocked_today"), "pct": s.get("ads_percentage_today"),
                "cached": s.get("queries_cached"), "forwarded": s.get("queries_forwarded"),
                "clients": s.get("unique_clients"), "gravity": s.get("domains_being_blocked"),
                "blocking": s.get("status"), "timer": None,
                "top_domains": list(top.get("top_queries", {}).items()) if isinstance(top.get("top_queries"), dict) else [],
                "top_blocked": list(top.get("top_ads", {}).items()) if isinstance(top.get("top_ads"), dict) else [],
                "top_clients": [[k.split("|")[0], v] for k, v in src.get("top_sources", {}).items()] if isinstance(src.get("top_sources"), dict) else []}

    def light(self):
        """Cheap summary for the live stream (2 requests on v6)."""
        if self.ver is None:
            self.detect()
        if self.ver == 6:
            q = self.v6("/api/stats/summary").get("queries", {})
            b = self.v6("/api/dns/blocking")
            return {"total": q.get("total"), "blocked": q.get("blocked"), "pct": q.get("percent_blocked"),
                    "blocking": b.get("blocking"), "timer": b.get("timer")}
        s = self.v5("summaryRaw")
        return {"total": s.get("dns_queries_today"), "blocked": s.get("ads_blocked_today"),
                "pct": s.get("ads_percentage_today"), "blocking": s.get("status"), "timer": None}

    BLOCKED_RX = re.compile(r"GRAVITY|REGEX|DENYLIST|BLACKLIST|BLOCKED|SPECIAL")

    def recent_queries(self, n=20):
        if self.ver != 6:
            return None
        q = self.v6(f"/api/queries?length={int(n)}").get("queries", [])
        return [{"t": x.get("time"), "domain": x.get("domain"), "type": x.get("type"),
                 "client": (x.get("client") or {}).get("name") or (x.get("client") or {}).get("ip"),
                 "status": x.get("status"), "blocked": bool(self.BLOCKED_RX.search(x.get("status") or "")),
                 "ms": round((x.get("reply") or {}).get("time", 0) * 1000, 1) if (x.get("reply") or {}).get("time") is not None else None}
                for x in q]

    # allow/deny lists (v6 only). Pi-hole v6 reloads its lists by itself after each change.
    def leases(self):
        """{mac: ip} from Pi-hole's DHCP server (authoritative now that Pi-hole hands out addresses)."""
        return {x["hwaddr"].lower(): x["ip"] for x in self.v6("/api/dhcp/leases").get("leases", [])
                if x.get("hwaddr") and x.get("ip")}

    def domains(self):
        return [{k: x.get(k) for k in ("domain", "type", "kind", "comment", "enabled", "date_added", "id")}
                for x in self.v6("/api/domains").get("domains", [])]

    def add_domain(self, typ, kind, domain, comment=""):
        return self.v6(f"/api/domains/{typ}/{kind}", "POST", {"domain": domain, "comment": comment, "enabled": True})

    def del_domain(self, typ, kind, domain):
        q = urllib.request.quote(domain, safe="")
        return self._req_ok(f"/api/domains/{typ}/{kind}/{q}", "DELETE")

    def _req_ok(self, path, method):
        try:
            return self.v6(path, method)
        except json.JSONDecodeError:  # DELETE answers 204 with no body
            return {}

    def search(self, domain):
        r = self.v6(f"/api/search/{urllib.request.quote(domain, safe='')}?partial=false&N=20").get("search", {})
        return {"lists": [{"type": x.get("type"), "kind": x.get("kind"), "domain": x.get("domain")} for x in r.get("domains", [])],
                "gravity": [{"type": x.get("type"), "address": x.get("address")} for x in r.get("gravity", [])]}

    def restart_dns(self):
        return self.v6("/api/action/restartdns", "POST", {})

    def _call(self, path, method, body=None):
        try:
            return self.v6(path, method, body)
        except json.JSONDecodeError:  # 204 with no body
            return {}

    # --- per-device block: a group whose only rule is the regex ".*", and Pi-hole DHCP set to ignore the MAC
    def block_group(self, create=False):
        """Id of the NCC block group (and make sure its catch-all rule exists and covers ONLY that group)."""
        g = next((x for x in self.v6("/api/groups").get("groups", []) if x["name"] == BLOCK_GROUP), None)
        if g is None:
            if not create:
                return None
            self._call("/api/groups", "POST", {"name": BLOCK_GROUP, "enabled": True,
                                               "comment": "Devices blocked from the Network Command Center"})
            g = next(x for x in self.v6("/api/groups").get("groups", []) if x["name"] == BLOCK_GROUP)
        gid = g["id"]
        if create:
            rule = next((d for d in self.v6("/api/domains/deny/regex").get("domains", []) if d["domain"] == ".*"), None)
            if rule is None:
                self._call("/api/domains/deny/regex", "POST", {"domain": ".*", "groups": [gid], "enabled": True,
                                                               "comment": BLOCK_RULE_NOTE})
                rule = next(d for d in self.v6("/api/domains/deny/regex").get("domains", []) if d["domain"] == ".*")
            if rule.get("groups") != [gid]:  # never let the catch-all apply to the Default group (= every device)
                self._call("/api/domains/deny/regex/" + urllib.request.quote(".*", safe=""), "PUT",
                           {"groups": [gid], "enabled": True, "comment": BLOCK_RULE_NOTE})
        return gid

    def blocked_clients(self):
        gid = self.block_group()
        if gid is None:
            return {}
        return {c["client"].lower(): {"since": c.get("date_added"), "comment": c.get("comment") or ""}
                for c in self.v6("/api/clients").get("clients", []) if gid in (c.get("groups") or [])}

    def dhcp_hosts(self):
        return list(self.v6("/api/config/dhcp").get("config", {}).get("dhcp", {}).get("hosts") or [])

    def set_dhcp_hosts(self, hosts):
        return self._call("/api/config", "PATCH", {"config": {"dhcp": {"hosts": hosts}}})

    def set_blocking(self, enable, seconds=None):
        if self.ver == 6:
            return self.v6("/api/dns/blocking", "POST", {"blocking": enable, "timer": seconds})
        return self.v5("enable" if enable else f"disable={int(seconds or 0)}")


class AdGuardHome:
    """AdGuard Home behind the same methods the dashboard uses for Pi-hole (stats, live feed, lists, pause).
    Per-device blocking and DHCP reservations are Pi-hole only."""
    name, ver = "AdGuard Home", 6

    def __init__(self, url, user, password):
        self.url, self.user, self.pw = url.rstrip("/"), user, password

    def _req(self, path, method="GET", body=None):
        hdr = {"Accept": "application/json", "Content-Type": "application/json",
               "Authorization": "Basic " + base64.b64encode(f"{self.user}:{self.pw}".encode()).decode()}
        req = urllib.request.Request(self.url + path, method=method, headers=hdr,
                                     data=json.dumps(body).encode() if body is not None else None)
        with urllib.request.urlopen(req, timeout=8) as r:
            raw = r.read()
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:  # several POSTs answer plain "OK"
            return {}

    @staticmethod
    def _pairs(items):
        return [list(x.items())[0] for x in items or [] if x]

    def stats(self):
        st, s = self._req("/control/status"), self._req("/control/stats")
        total = s.get("num_dns_queries") or 0
        blocked = sum(s.get(k) or 0 for k in ("num_blocked_filtering", "num_replaced_safebrowsing", "num_replaced_parental"))
        fl = self._req("/control/filtering/status")
        return {"ok": True, "api": "adguard", "version": st.get("version"), "total": total, "blocked": blocked,
                "pct": round(100 * blocked / total, 1) if total else 0, "cached": None, "forwarded": None,
                "clients": len(s.get("top_clients") or []),
                "gravity": sum(f.get("rules_count") or 0 for f in fl.get("filters") or [] if f.get("enabled")),
                "blocking": "enabled" if st.get("protection_enabled") else "disabled",
                "timer": (st.get("protection_disabled_duration") or 0) / 1000 or None,
                "top_domains": self._pairs(s.get("top_queried_domains"))[:8],
                "top_blocked": self._pairs(s.get("top_blocked_domains"))[:8],
                "top_clients": self._pairs(s.get("top_clients"))[:8]}

    def light(self):
        x = self.stats()
        return {k: x[k] for k in ("total", "blocked", "pct", "blocking", "timer")}

    def recent_queries(self, n=20):
        out = []
        for x in self._req(f"/control/querylog?limit={int(n)}").get("data", []):
            t = re.sub(r"(\.\d{6})\d+", r"\1", x.get("time") or "").replace("Z", "+00:00")
            try:
                ts = datetime.fromisoformat(t).timestamp()
            except ValueError:
                ts = None
            reason = x.get("reason") or ""
            out.append({"t": ts, "domain": (x.get("question") or {}).get("name"), "type": (x.get("question") or {}).get("type"),
                        "client": (x.get("client_info") or {}).get("name") or x.get("client"), "status": reason,
                        "blocked": reason.startswith("Filtered") and reason != "FilteredSafeSearch",
                        "ms": float(x["elapsedMs"]) if x.get("elapsedMs") else None})
        return out

    def leases(self):
        d = self._req("/control/dhcp/status")
        return {x["mac"].lower(): x["ip"] for x in (d.get("leases") or []) + (d.get("static_leases") or [])
                if x.get("mac") and x.get("ip")}

    # your own allow/deny lists = AdGuard "custom filtering rules"
    @staticmethod
    def _rule(typ, kind, domain):
        body = f"/{domain}/" if kind == "regex" else f"||{domain}^"
        return ("@@" if typ == "allow" else "") + body

    def _rules(self):
        return list(self._req("/control/filtering/status").get("user_rules") or [])

    def domains(self):
        out = []
        for i, r in enumerate(self._rules()):
            m = re.fullmatch(r"(@@)?(?:\|\|([^\^/]+)\^|/(.+)/)", r.strip())
            if m:
                out.append({"domain": m.group(2) or m.group(3), "type": "allow" if m.group(1) else "deny",
                            "kind": "regex" if m.group(3) else "exact", "comment": "", "enabled": True, "date_added": None, "id": i})
        return out

    def add_domain(self, typ, kind, domain, comment=""):
        rules, new = self._rules(), self._rule(typ, kind, domain)
        if new not in rules:
            self._req("/control/filtering/set_rules", "POST", {"rules": rules + [new]})
        return {}

    def del_domain(self, typ, kind, domain):
        old = self._rule(typ, kind, domain)
        self._req("/control/filtering/set_rules", "POST", {"rules": [r for r in self._rules() if r.strip() != old]})
        return {}

    def search(self, domain):
        r = self._req("/control/filtering/check_host?name=" + urllib.request.quote(domain, safe=""))
        reason, mine = r.get("reason") or "", any((x.get("filter_list_id") or 0) == 0 for x in r.get("rules") or [])
        typ = "allow" if reason == "NotFilteredWhiteList" else "deny" if reason.startswith("Filtered") else None
        if not typ:
            return {"lists": [], "gravity": []}
        return {"lists": [{"type": typ, "kind": "exact", "domain": domain}] if mine else [],
                "gravity": [] if mine else [{"type": "allow" if typ == "allow" else "block", "address": "AdGuard filter"}]}

    def restart_dns(self):
        return {}  # AdGuard applies rule changes at once

    def blocked_clients(self):
        return {}

    def set_blocking(self, enable, seconds=None):
        body = {"enabled": bool(enable)}
        if not enable and seconds:
            body["duration"] = int(seconds) * 1000
        return self._req("/control/protection", "POST", body)


PH_LOCK = threading.Lock()
# PIHOLE is "the ad blocker": Pi-hole, or AdGuard Home when ADGUARD_URL is set (the installer sets one or the other)
if CFG["ADGUARD_URL"]:
    PIHOLE = AdGuardHome(CFG["ADGUARD_URL"], SECRETS.get("ADGUARD_USER", "admin"), SECRETS.get("ADGUARD_PASSWORD", ""))
elif CFG["PIHOLE_URL"]:
    PIHOLE = PiHole(CFG["PIHOLE_URL"], SECRETS.get("PIHOLE_PASSWORD", ""))
else:
    PIHOLE = None


DOMAIN_RX = re.compile(r"(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?")


def norm_domain(s):
    """Accept a bare domain, a pasted URL, or *.domain; return (domain, wildcard)."""
    s = str(s or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s).split("/")[0].split("?")[0].split("#")[0]
    s = s.rsplit("@", 1)[-1]
    s = re.sub(r":\d+$", "", s).rstrip(".")
    wild = s.startswith("*.")
    if wild:
        s = s[2:]
    if not DOMAIN_RX.fullmatch(s) or "." not in s:
        raise ValueError("That doesn't look like a domain name (example: ads.example.com).")
    return s, wild


BLOCK_GROUP = "NCC blocked devices"
BLOCK_RULE_NOTE = "NCC: blocks everything, only for devices in the NCC blocked devices group"
BLOCKED = {}


def everyone_ok():
    """True if Pi-hole still answers normally for this PC (i.e. the catch-all is not hitting everybody)."""
    host = re.sub(r"^https?://", "", PIHOLE.url).split("/")[0].rsplit(":", 1)[0]
    ips = dig_a(host, CFG["DNS_TEST_NAME"])
    return bool(ips) and "0.0.0.0" not in ips


def refresh_blocked():
    global BLOCKED
    try:
        b = PIHOLE.blocked_clients() if PIHOLE and PIHOLE.ver == 6 else {}
        if b:  # "strong" = also refused an address by Pi-hole's DHCP
            ign = {h.lower().split(",")[0] for h in PIHOLE.dhcp_hosts() if h.lower().endswith(",ignore")}
            for mac, v in b.items():
                v["strong"] = mac in ign
        BLOCKED = b
    except Exception as e:
        log("blocked list failed:", type(e).__name__)
    return BLOCKED


def device_block(body):
    """Block / unblock one device's internet through Pi-hole. Never touches the gateway.

    block: DNS only (instant). strong=True also refuses it a DHCP address, which makes Pi-hole restart for a few seconds.
    """
    if not isinstance(PIHOLE, PiHole) or CFG["PIHOLE_BLOCK"] != "1":
        raise PermissionError("Device blocking is off (PIHOLE_BLOCK=0 in config/ncc.env).")
    if PIHOLE.ver != 6:
        raise ValueError("Device blocking needs Pi-hole v6.")
    mac = str(body.get("mac", "")).lower()
    if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("bad MAC address")
    action = body.get("action")
    d = next((r for r in STATE["devices"] if r["mac"] == mac), {})
    name = d.get("label") or d.get("name") or mac
    if action == "block":
        if d.get("kind") in ("this computer", "gateway") or d.get("ip") in (local_iface().get("ip"), default_gateway()):
            raise ValueError("This PC (the Pi-hole) and the gateway can't be blocked; the whole network depends on them.")
        gid = PIHOLE.block_group(create=True)
        if not everyone_ok():  # the rule must only hit the group; undo straight away if not
            PIHOLE._call("/api/domains/deny/regex/" + urllib.request.quote(".*", safe=""), "DELETE")
            raise RuntimeError("Safety check failed: Pi-hole stopped answering for everyone, so the block rule was removed again.")
        note = f"NCC block: {name}"[:60]
        if mac in PIHOLE.blocked_clients() or any(c["client"].lower() == mac for c in PIHOLE.v6("/api/clients").get("clients", [])):
            PIHOLE._call("/api/clients/" + urllib.request.quote(mac, safe=""), "PUT", {"groups": [gid], "comment": note})
        else:
            PIHOLE._call("/api/clients", "POST", {"client": mac, "groups": [gid], "comment": note})
        strong = bool(body.get("strong"))
        if strong:
            hosts = PIHOLE.dhcp_hosts()
            if not any(h.lower().startswith(mac) for h in hosts):
                PIHOLE.set_dhcp_hosts(hosts + [f"{mac},ignore"])
        event("warn", "device-block", f"Blocked internet for {name} ({mac}) via Pi-hole "
              f"({'lookups + no address' if strong else 'lookups only'}).", False)
    elif action == "unblock":
        PIHOLE._call("/api/clients/" + urllib.request.quote(mac, safe=""), "DELETE")
        hosts = PIHOLE.dhcp_hosts()
        keep = [h for h in hosts if not h.lower().startswith(mac + ",ignore")]
        if keep != hosts:
            PIHOLE.set_dhcp_hosts(keep)
        event("info", "device-block", f"Unblocked {name} ({mac}).", False)
    else:
        raise ValueError("action must be block or unblock")
    return {"ok": True, "mac": mac, "blocked": mac in refresh_blocked()}


# ---------------------------------------------------------------- remote access (Tailscale serve -> 127.0.0.1)
PIN_FILE, SESS_FILE = DATA / ".remote_pin", DATA / ".sessions"
SESS_LOCK = threading.Lock()
PIN_FAILS = []  # timestamps of wrong PINs (rate limit)


def _write_private(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh)


def _read_json(path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def pin_set():
    return PIN_FILE.exists()


def set_pin(pin):
    pin = str(pin or "")
    if not re.fullmatch(r"\d{6,12}", pin):
        raise ValueError("The PIN must be 6 to 12 digits.")
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 200_000).hex()
    _write_private(PIN_FILE, {"salt": salt, "hash": h, "iter": 200_000})
    with SESS_LOCK:  # a new PIN signs every phone out
        _write_private(SESS_FILE, {})
    event("info", "remote", "Remote-access PIN set (all remote sessions signed out).", False)


def check_pin(pin, meta=None):
    now = time.time()
    PIN_FAILS[:] = [t for t in PIN_FAILS if now - t < 900]
    if len(PIN_FAILS) >= 5:
        raise PermissionError("Too many wrong PINs. Try again in 15 minutes.")
    rec = _read_json(PIN_FILE, None)
    if not rec:
        raise PermissionError("Remote access PIN isn't set yet. Set it on the laptop (Security tab → Remote access).")
    h = hashlib.pbkdf2_hmac("sha256", str(pin or "").encode(), bytes.fromhex(rec["salt"]), rec["iter"]).hex()
    if not hmac.compare_digest(h, rec["hash"]):
        PIN_FAILS.append(now)
        event("warn", "remote", f"Wrong remote-access PIN ({len(PIN_FAILS)} in 15 min).", len(PIN_FAILS) >= 3)
        raise PermissionError("Wrong PIN.")
    PIN_FAILS.clear()
    return new_session("pin", meta=meta)


LAST_SEEN = {}  # session hash -> last request time (memory only, so browsing doesn't rewrite the file)


def session_length(kind):
    return settings()["web_session_h" if kind == "web" else "pin_session_h"] * 3600


def new_session(kind, user=None, meta=None):
    now, tok = time.time(), secrets.token_urlsafe(32)
    with SESS_LOCK:
        ss = {k: v for k, v in _read_json(SESS_FILE, {}).items() if (v["exp"] if isinstance(v, dict) else v) > now}
        ss[hashlib.sha256(tok.encode()).hexdigest()] = {"exp": now + session_length(kind), "kind": kind, "user": user,
                                                        "created": int(now), **(meta or {})}
        _write_private(SESS_FILE, ss)
    return tok


def _sess_expiry(v):
    """A shorter 'sign-in lasts' setting also cuts sessions that are already signed in."""
    if isinstance(v, (int, float)):
        v = {"exp": v, "kind": "pin"}
    if v.get("created"):
        return v, min(v["exp"], v["created"] + session_length(v["kind"]))
    return v, v["exp"]


def session_ok(tok, public=False):
    """PIN sessions work only over Tailscale; a web (username/password) session works from both."""
    if not tok:
        return False
    h = hashlib.sha256(tok.encode()).hexdigest()
    v = _read_json(SESS_FILE, {}).get(h)
    if not v:
        return False
    v, exp = _sess_expiry(v)
    if exp <= time.time() or (public and v["kind"] != "web"):
        return False
    if v["kind"] == "web" and v.get("user") not in web_users():
        return False
    LAST_SEEN[h] = time.time()
    return True


def session_role(tok):
    """'view' for a web account set to view-only; 'edit' for everyone else (PIN, full web accounts, the laptop)."""
    if not tok:
        return "edit"
    v = _read_json(SESS_FILE, {}).get(hashlib.sha256(tok.encode()).hexdigest())
    if isinstance(v, dict) and v.get("kind") == "web":
        return web_users().get(v.get("user"), {}).get("role", "edit")
    return "edit"


def set_web_role(user, role):
    us = web_users()
    if user not in us or role not in ("edit", "view"):
        raise ValueError("Unknown account or role.")
    us[user]["role"] = role
    _write_private(WEB_FILE, {"users": us})
    event("info", "web-access", f"Web account {user} set to {'can edit' if role == 'edit' else 'view only'}.", False)


def list_sessions():
    now, out = time.time(), []
    for h, v in _read_json(SESS_FILE, {}).items():
        v, exp = _sess_expiry(v)
        if exp > now:
            out.append({"id": h[:16], "kind": v["kind"], "user": v.get("user") or v.get("tsuser"), "ip": v.get("ip"),
                        "blockable": bool(v.get("dev") or v.get("ip")),
                        "role": web_users().get(v.get("user"), {}).get("role", "edit") if v["kind"] == "web" else "edit",
                        "browser": v.get("ua"), "created": v.get("created"), "expires": int(exp),
                        "last_seen": int(LAST_SEEN[h]) if h in LAST_SEEN else None})
    return sorted(out, key=lambda x: -(x["last_seen"] or x["created"] or 0))


# ---- blocked devices: never allowed to sign in again (web or Tailscale), until unblocked (laptop or Tailscale).
# A device is matched by its device ID (a random, long-lived cookie set on its first visit) or by its IP address.
BLOCK_FILE = DATA / ".blocked_devices"


def blocked_list():
    return (_read_json(BLOCK_FILE, {}) or {}).get("items", [])


def is_blocked(dev, ip):
    return any((b.get("dev") and b["dev"] == dev) or (b.get("ip") and b["ip"] == ip) for b in blocked_list())


def block_session(sid, by_ip=True):
    ss = _read_json(SESS_FILE, {})
    h = next((h for h in ss if len(sid) == 16 and h.startswith(sid)), None)
    if not h or not isinstance(ss[h], dict):
        raise ValueError("That session is gone. It may have signed out already.")
    v = ss[h]
    if not v.get("dev") and not v.get("ip"):
        raise ValueError("This older sign-in has no device details to block. Sign it out instead.")
    items = blocked_list()
    items.append({"dev": v.get("dev"), "ip": v.get("ip") if by_ip else None, "at": int(time.time()),
                  "label": f"{v.get('user') or v.get('tsuser') or 'Tailscale device'} · {v.get('ua') or 'unknown browser'}"[:90]})
    _write_private(BLOCK_FILE, {"items": items[-100:]})
    with SESS_LOCK:  # also sign out every session from that device
        ss = _read_json(SESS_FILE, {})
        _write_private(SESS_FILE, {k: x for k, x in ss.items()
                                   if not (isinstance(x, dict) and ((v.get("dev") and x.get("dev") == v["dev"])
                                                                    or (by_ip and v.get("ip") and x.get("ip") == v["ip"])))})
    kick_streams()
    event("warn", "web-access", f"Blocked a device from signing in: {items[-1]['label']}"
          + (f" (IP {v.get('ip')})" if by_ip and v.get("ip") else "") + ".", False)


def unblock(n):
    items = blocked_list()
    if not 0 <= n < len(items):
        raise ValueError("Not in the list.")
    b = items.pop(n)
    _write_private(BLOCK_FILE, {"items": items})
    event("info", "web-access", f"Unblocked device: {b.get('label')}.", False)


def drop_session_id(sid):
    """Sign out one session by its short id, or everyone with sid == '*'."""
    with SESS_LOCK:
        ss = _read_json(SESS_FILE, {})
        gone = [h for h in ss if sid == "*" or (len(sid) == 16 and h.startswith(sid))]
        for h in gone:
            ss.pop(h)
            LAST_SEEN.pop(h, None)
        _write_private(SESS_FILE, ss)
    kick_streams()
    if gone:
        event("info", "web-access", f"Signed out {'everyone' if sid == '*' else 'a session'} from the dashboard ({len(gone)}).", False)
    return len(gone)


def drop_user_sessions(user):
    with SESS_LOCK:
        ss = _read_json(SESS_FILE, {})
        _write_private(SESS_FILE, {k: v for k, v in ss.items() if not (isinstance(v, dict) and v.get("user") == user)})
    kick_streams()


def kick_streams():
    """Wake every open live stream so a signed-out browser is cut off now, not on its next page load."""
    with LIVE_COND:
        LIVE["kick"] += 1
        LIVE_COND.notify_all()


# ---- web access (Tailscale Funnel: a public https address, no Tailscale needed on the computer). Approved by the user
# 2026-10-21 with full control. One username + password per family member (scrypt hashes in data/.web_logins, added
# and removed only on the laptop), a lockout after 5 wrong tries in an hour, a phone alert on every web sign-in, and
# an off switch (setting web_access).
WEB_FILE = DATA / ".web_logins"
WEB_FAILS = []
WEB_LOCK_S = 3600


def _scrypt(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, maxmem=64 * 1024 * 1024).hex()


def web_users():
    return (_read_json(WEB_FILE, {}) or {}).get("users", {})


def clean_emails(emails):
    if isinstance(emails, str):
        emails = re.split(r"[\s,;]+", emails)
    out = []
    for e in emails or []:
        e = str(e).strip()
        if not e:
            continue
        if len(e) > 254 or not EMAIL_RE.match(e):
            raise ValueError(f"\"{e[:40]}\" doesn't look like an email address.")
        if e.lower() not in (x.lower() for x in out):
            out.append(e)
    if not out:
        raise ValueError("Add at least one email: sign-in codes are sent there.")
    if len(out) > 5:
        raise ValueError("At most 5 emails per person.")
    return out


def set_web_emails(user, emails):
    us = web_users()
    if user not in us:
        raise ValueError("No such account.")
    us[user]["emails"] = clean_emails(emails)
    _write_private(WEB_FILE, {"users": us})
    event("info", "web-access", f"Sign-in code emails changed for {user} ({len(us[user]['emails'])}).", False)


def set_web_user(user, pw, role=None, emails=None):
    """Add a person, or change their password (which signs their browsers out)."""
    user, pw = str(user or "").strip().lower(), str(pw or "")
    if not re.fullmatch(r"[a-z0-9._-]{3,32}", user):
        raise ValueError("Username: 3-32 letters, numbers, dots, dashes or underscores.")
    if len(pw) < 10 or len(pw) > 128:
        raise ValueError("Password must be at least 10 characters.")
    if user in pw.lower() or pw.isdigit() or len(set(pw)) < 5:
        raise ValueError("That password is too easy to guess. Mix words, numbers and symbols, and don't include the username.")
    us = web_users()
    if user not in us and len(us) >= 10:
        raise ValueError("That's the most accounts (10).")
    salt, existed = secrets.token_hex(16), user in us
    emails = clean_emails(emails) if (emails or not existed) else us[user].get("emails")
    if not emails:
        emails = clean_emails(emails)  # raises: everyone needs a code email
    us[user] = {"salt": salt, "hash": _scrypt(pw, salt), "created": us.get(user, {}).get("created") or int(time.time()),
                "role": role if role in ("edit", "view") else us.get(user, {}).get("role", "edit"), "emails": emails}
    _write_private(WEB_FILE, {"users": us})
    drop_user_sessions(user)
    event("info", "web-access", f"Web sign-in {'password changed' if existed else 'account added'}: {user}.", False)


def remove_web_user(user):
    us = web_users()
    if us.pop(str(user), None) is None:
        raise ValueError("No such account.")
    _write_private(WEB_FILE, {"users": us})
    drop_user_sessions(user)
    event("info", "web-access", f"Web sign-in account removed: {user}.", False)


_DUMMY_SALT = secrets.token_hex(16)


# ---- two-step web sign-in: after the password, a 6-digit code goes to every email on the account (sent from Gmail).
OTP = {}          # pending id -> {user, hash, exp, tries, resends, sent_at, who, meta}
OTP_TTL = 600


def _otp_hash(pending, code):
    return hashlib.sha256(f"{pending}:{code}".encode()).hexdigest()


def send_code(emails, code):
    msg = (f"Your Network Command Center sign-in code is {code}\n\nIt expires in 10 minutes. If you didn't just try to "
           "sign in, someone knows your password: tell whoever runs the dashboard so they can change it.")
    try:
        return send_email(emails, f"NCC sign-in code: {code}", msg)
    except Exception as ex:  # never log the address or the code
        log("sign-in code email failed:", type(ex).__name__)
        return 0


def _issue_code(pending, p):
    code = f"{secrets.randbelow(10 ** 6):06d}"
    emails = web_users().get(p["user"], {}).get("emails") or []
    if not smtp_conf():
        raise PermissionError("Sign-in code emails aren't set up on the laptop yet.")
    if not send_code(emails, code):
        raise PermissionError("Couldn't send the code email. Try again in a minute.")
    p.update({"hash": _otp_hash(pending, code), "exp": time.time() + OTP_TTL, "tries": 0, "sent_at": time.time()})
    return [mask_email(e) for e in emails]


def _web_fail(who, what):
    WEB_FAILS.append(time.time())
    n = len(WEB_FAILS)
    event("crit" if n >= 5 else "warn", "web-signin-fail",
          f"{what} from {who} ({n} in the last hour)." + (" Web sign-in locked for an hour." if n >= 5 else ""),
          "phone" if n in (3, 5) else False)


def _web_gate():
    if not settings().get("web_access"):
        raise PermissionError("Web access is turned off.")
    now = time.time()
    WEB_FAILS[:] = [t for t in WEB_FAILS if now - t < WEB_LOCK_S]
    if len(WEB_FAILS) >= 5:
        raise PermissionError("Too many wrong tries. Web sign-in is locked for an hour.")
    for k in [k for k, v in OTP.items() if v["exp"] < now]:
        OTP.pop(k, None)


def check_web_login(user, pw, who, meta=None):
    """Step 1: username + password. Returns a pending id; the code is emailed."""
    _web_gate()
    user = str(user or "").strip().lower()[:32]
    rec = web_users().get(user)
    h = _scrypt(str(pw or "")[:128], rec["salt"] if rec else _DUMMY_SALT)  # same work either way: no hint which names exist
    if not rec or not hmac.compare_digest(h, rec["hash"]):
        _web_fail(who, "Wrong web sign-in")
        raise PermissionError("Wrong username or password.")
    if not rec.get("emails"):
        raise PermissionError("This account has no email for sign-in codes yet. Ask the owner to add one in the Security tab.")
    if len(OTP) > 50:
        raise PermissionError("Too many sign-ins in progress. Try again in a few minutes.")
    pending = secrets.token_urlsafe(24)
    p = {"user": user, "who": who, "meta": meta, "resends": 0}
    to = _issue_code(pending, p)
    OTP[pending] = p
    log(f"web sign-in: password OK for {user}, code emailed to {len(to)} address(es)")
    return pending, to


def resend_web_code(pending):
    _web_gate()
    p = OTP.get(str(pending or ""))
    if not p:
        raise PermissionError("That sign-in expired. Start again.")
    if time.time() - p["sent_at"] < 60:
        raise PermissionError("Wait a minute before asking for another code.")
    if p["resends"] >= 3:
        raise PermissionError("Too many new codes. Start the sign-in again.")
    p["resends"] += 1
    return _issue_code(pending, p)


def check_web_code(pending, code):
    """Step 2: the emailed code. Returns a session token."""
    _web_gate()
    pending = str(pending or "")
    p = OTP.get(pending)
    if not p or p["exp"] < time.time():
        OTP.pop(pending, None)
        raise PermissionError("That code expired. Sign in again.")
    code = re.sub(r"\D", "", str(code or ""))[:6]
    if not hmac.compare_digest(_otp_hash(pending, code), p["hash"]):
        p["tries"] += 1
        _web_fail(p["who"], f"Wrong sign-in code for {p['user']}")
        if p["tries"] >= 5:
            OTP.pop(pending, None)
            raise PermissionError("Too many wrong codes. Sign in again.")
        raise PermissionError("Wrong code. Check the newest email.")
    OTP.pop(pending, None)
    user, who = p["user"], p["who"]
    if user not in web_users():
        raise PermissionError("That account was removed.")
    WEB_FAILS.clear()
    event("warn", "web-signin", f"Web sign-in: {user} from {who} at {time.strftime('%H:%M')} (password + email code). "
          "If this wasn't them, remove the account or turn off web access (Security tab, on the laptop or a Tailscale device).", "phone")
    return new_session("web", user, p["meta"])


def drop_session(tok):
    with SESS_LOCK:
        ss = _read_json(SESS_FILE, {})
        ss.pop(hashlib.sha256(str(tok).encode()).hexdigest(), None)
        _write_private(SESS_FILE, ss)


# ---------------------------------------------------------------- whole-home setup guide (Pi-hole tab)
def blocker_setup():
    """Facts for the 'make every device use the ad blocker' guide. Read-only: it never changes the router."""
    iface = local_iface()
    out = {"router": CFG["ROUTER"], "blocker": PIHOLE.name if PIHOLE else None, "lan_ip": iface.get("ip"),
           "gateway": default_gateway(), "fixed_ip": None, "admin_url": None, "clients": None,
           "os": "windows" if WIN else "linux",
           # AdGuard Home's DHCP server doesn't exist on Windows, so the "ad blocker hands out addresses" route is out
           "dhcp_ok": not (WIN and isinstance(PIHOLE, AdGuardHome))}
    if WIN:
        w = W.iface(0)
        out["fixed_ip"] = (not w["dhcp"]) if w else None
        out["network_private"] = (w.get("category") or "").lower() in ("private", "domainauthenticated") if w else None
    if PIHOLE:
        out["admin_url"] = PIHOLE.url + ("/admin/" if isinstance(PIHOLE, PiHole) else "/")
        try:
            out["clients"] = PIHOLE.stats().get("clients")
        except Exception:
            pass
    if shutil.which("nmcli") and iface.get("dev"):
        _, con = run(["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", iface["dev"]], 5)
        if con.strip():
            _, m = run(["nmcli", "-g", "ipv4.method", "connection", "show", con.strip()], 5)
            out["fixed_ip"] = m.strip() == "manual" if m.strip() else None
    return out


def remote_status():
    out = {"installed": bool(shutil.which("tailscale")), "pin_set": pin_set(), "state": None, "url": None, "serving": False,
           "login_url": None}
    if not out["installed"]:
        return out
    code, js = run(["tailscale", "status", "--json"], 8)
    try:
        st = json.loads(js)
        out["state"] = st.get("BackendState")
        out["login_url"] = st.get("AuthURL") or None
        dns = (st.get("Self") or {}).get("DNSName", "").rstrip(".")
        out["url"] = f"https://{dns}" if dns else None
        peers = list((st.get("Peer") or {}).values())
        # Funnel's relay servers (tag:ingress, shared in by Tailscale) show up as peers while the public address is on.
        relays = [p for p in peers if "tag:ingress" in (p.get("Tags") or []) or p.get("HostName") == "funnel-ingress-node"]
        out["funnel_relays"] = {"count": len(relays), "online": sum(1 for p in relays if p.get("Online"))}

        def nice(p):  # iPhones/iPads often report "localhost": use the machine name from Tailscale instead
            h = p.get("HostName") or ""
            if not h or h.lower() in ("localhost", "iphone", "ipad"):
                h = (p.get("DNSName") or h).split(".")[0] or h
            return h
        out["phones"] = sorted(({"name": nice(p), "os": p.get("OS"), "online": p.get("Online"),
                                 "last_seen": p.get("LastSeen") if not p.get("Online") else None}
                                for p in peers if p not in relays), key=lambda x: (not x["online"], x["name"].lower()))
    except ValueError:
        pass
    code, js = run(["tailscale", "serve", "status", "--json"], 8)
    try:
        sv = json.loads(js or "{}")
        out["serving"] = "8088" in js and bool(sv)
        allow = sv.get("AllowFunnel") or {}
        out["funnel"] = any(v for k, v in allow.items() if k.endswith(":443"))
    except ValueError:
        pass
    return out


def set_funnel(on):
    """Fixed commands only. Off = back to Tailscale-only (serve), so your Tailscale devices keep working."""
    target = f"http://127.0.0.1:{int(CFG['PORT'])}"
    if on:
        code, _ = run(["tailscale", "funnel", "--bg", target], 30)
    else:
        code, _ = run(["tailscale", "funnel", "--https=443", "off"], 30)
        code, _ = run(["tailscale", "serve", "--bg", target], 30)
    st = remote_status()
    if code != 0 or bool(st.get("funnel")) != on:
        raise RuntimeError("Tailscale didn't accept the change. Try again, or run the commands in the README.")
    event("warn" if on else "info", "web-access", f"Public web address (Funnel) turned {'on' if on else 'off'} from the dashboard.", False)
    return st


def system_restart(what):
    """Fixed restart actions only (no user input reaches a command line)."""
    if CFG["SYSTEM_CONTROLS"] != "1":
        raise PermissionError("Restart buttons are off (SYSTEM_CONTROLS=0 in config/ncc.env).")
    if what == "pihole":
        if not PIHOLE:
            raise ValueError("Pi-hole not configured")
        PIHOLE.restart_dns()
        event("info", "restart", "Pi-hole DNS restarted from the dashboard.", False)
        return {"ok": True, "msg": "Pi-hole restarted. Lookups pause for a few seconds."}
    if what == "dashboard":
        event("info", "restart", "Dashboard restart requested.", False)
        threading.Timer(1, W.restart_self if WIN else
                        lambda: subprocess.Popen(["systemctl", "--user", "--no-block", "restart", "ncc.service"])).start()
        return {"ok": True, "msg": "Restarting the dashboard. It reloads by itself in about 10 seconds."}
    if what == "laptop":
        event("warn", "restart", "Laptop reboot requested from the dashboard.", False)
        threading.Timer(2, W.reboot if WIN else lambda: subprocess.Popen(["systemctl", "reboot"])).start()
        return {"ok": True, "msg": "Rebooting this laptop. Pi-hole and the dashboard are back in about 1-2 minutes."}
    raise ValueError("unknown restart target")


def answers_blocked(domain):
    """Ask Pi-hole directly; its blocking mode answers 0.0.0.0 / :: for blocked names."""
    host = re.sub(r"^https?://", "", PIHOLE.url).split("/")[0].rsplit(":", 1)[0]
    return "0.0.0.0" in dig_a(host, domain)


def expected_blocked(domain):
    s = PIHOLE.search(domain)
    if any(x["type"] == "allow" for x in s["lists"]) or any(x["type"] == "allow" for x in s["gravity"]):
        return False
    return any(x["type"] == "deny" for x in s["lists"]) or any(x["type"] == "block" for x in s["gravity"])


def pihole_list_change(body):
    """Add/remove an allow or deny entry, then confirm with a real lookup. If Pi-hole is still
    answering the old way, restart its DNS service once and check again."""
    op, typ = body.get("op"), body.get("list")
    if op not in ("add", "remove") or typ not in ("allow", "deny"):
        raise ValueError("op must be add/remove and list must be allow/deny")
    if op == "remove":
        kind, entry = body.get("kind"), str(body.get("domain", ""))[:500]
        if kind not in ("exact", "regex") or not entry:
            raise ValueError("bad entry")
        PIHOLE.del_domain(typ, kind, entry)
        test = entry if kind == "exact" else body.get("test")
    else:
        dom, wild = norm_domain(body.get("domain"))
        wild = wild or bool(body.get("subdomains"))
        kind, entry = ("regex", r"(\.|^)" + re.escape(dom).replace(r"\-", "-") + "$") if wild else ("exact", dom)
        comment = LABEL_RX.sub("", str(body.get("comment") or ""))[:100] or "added from NCC dashboard"
        for x in PIHOLE.domains():
            if x["domain"] == entry and x["kind"] == kind:
                where = "block" if x["type"] == "deny" else "allow"
                if x["type"] == typ:
                    raise ValueError(f"{dom} is already on the {where} list.")
                raise ValueError(f"{dom} is on the {where} list. Remove it there first.")
        try:
            PIHOLE.add_domain(typ, kind, entry, comment)
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = json.loads(e.read() or b"{}").get("error", {}).get("message", "")
            except ValueError:
                pass
            raise ValueError(detail or f"Pi-hole refused the change (HTTP {e.code})")
        test = dom
    word = {"allow": "allow list", "deny": "block list"}[typ]
    event("info", "pihole-list", f"Pi-hole: {'added' if op == 'add' else 'removed'} {entry} {'to' if op == 'add' else 'from'} the {word} (from dashboard).", False)
    out = {"ok": True, "entry": entry, "kind": kind, "list": typ, "restarted": False, "verified": None, "test": test}
    if not test or not DOMAIN_RX.fullmatch(test):
        out["note"] = "Saved. Pi-hole applies list changes immediately; pattern entries can't be test-looked-up."
        return out
    if op == "add":
        want = typ == "deny"
    else:
        want = expected_blocked(test)
    for attempt in range(2):
        time.sleep(0.6)
        got = answers_blocked(test)
        if got == want:
            out["verified"] = True
            break
        if attempt == 0:
            PIHOLE.restart_dns()
            out["restarted"] = True
            event("info", "pihole-list", "Pi-hole DNS restarted automatically so a list change takes effect.", False)
            for _ in range(20):
                time.sleep(0.5)
                if dns_check(CFG["DNS_TEST_NAME"], re.sub(r"^https?://", "", PIHOLE.url).split("/")[0].rsplit(":", 1)[0])["ok"]:
                    break
    else:
        out["verified"] = False
    out["now_blocked"] = got
    return out


def pihole_poll():
    if not PIHOLE:
        return {"configured": False}
    host = re.sub(r"^https?://", "", PIHOLE.url).split("/")[0].split(":")[0]
    out = {"configured": True, "name": PIHOLE.name, "host": host, "controls": CFG["PIHOLE_CONTROLS"] == "1", "lists": CFG["PIHOLE_LISTS"] == "1"}
    refresh_blocked()
    out["dns"] = dns_check(CFG["DNS_TEST_NAME"], host)
    try:
        out.update(PIHOLE.stats())
    except Exception as e:
        out.update({"ok": False, "error": f"{type(e).__name__}: {str(e)[:120]}".replace(PIHOLE.pw or "\0", "***")})
    out["ok"] = bool(out.get("ok")) or out["dns"]["ok"]
    return out


# ---------------------------------------------------------------- security
def scan_auth_log():
    """Incrementally count failed authentication lines in /var/log/auth.log (readable via adm group)."""
    p = Path("/var/log/auth.log")
    sec = STATE["security"]
    if WIN:  # the Windows sign-in log (Security) can only be read by an administrator
        sec["auth"] = {"available": False, "reason": "Windows keeps sign-in failures in a log only administrators can read"}
        return
    if not os.access(p, os.R_OK):
        sec["auth"] = {"available": False, "reason": "auth.log not readable"}
        return
    st = p.stat()
    pos = kv_get("auth_pos", {"ino": None, "off": 0})
    if pos["ino"] != st.st_ino or pos["off"] > st.st_size:
        pos = {"ino": st.st_ino, "off": max(0, st.st_size - 200_000) if pos["ino"] is None else 0}
    pat = re.compile(r"Failed password|authentication failure|Invalid user|FAILED SU|incorrect password attempts", re.I)
    hits = []
    with p.open("rb") as f:
        f.seek(pos["off"])
        for raw in f:
            line = raw.decode("utf-8", "replace")
            if pat.search(line):
                hits.append(line[:200].strip())
        pos["off"] = f.tell()
    kv_set("auth_pos", pos)
    recent = (sec.get("auth", {}).get("recent") or []) + hits
    sec["auth"] = {"available": True, "recent": recent[-10:], "new": len(hits),
                   "sshd": bool(shutil.which("sshd")) and run(["systemctl", "is-active", "ssh"])[1].strip() == "active"}
    if len(hits) >= 5:
        event("warn", "auth-failures", f"{len(hits)} failed authentication attempts logged since last check (see auth.log).")


def scan_listeners():
    if WIN:
        cur = W.listeners()
    else:
        _, out = run(["ss", "-H", "-tln"])
        cur = sorted({l.split()[3] for l in out.splitlines() if len(l.split()) > 3})
    public = sorted(a for a in cur if not re.match(r"(127\.|\[::1\]|\[::ffff:127\.)", a))
    prev = kv_get("listeners_public")
    if prev is not None:
        for a in set(public) - set(prev):
            event("warn", "new-listener", f"A new network-reachable listening port appeared on this PC: {a}")
    kv_set("listeners_public", public)
    with LOCK:
        STATE["listeners"] = cur
        STATE["security"]["listeners_public"] = public


# ---------------------------------------------------------------- main collector loop
_down_since = None
_fails = 0
_flags = {}


def flag(kind, cond, level, msg_on, msg_off):
    """Emit an event only on state transitions."""
    was = _flags.get(kind, False)
    if cond and not was:
        event(level, kind, msg_on)
    elif not cond and was:
        event("info", kind, msg_off, False)
    _flags[kind] = cond


def collect():
    global _down_since, _fails
    gw = default_gateway()
    with ThreadPoolExecutor(6) as ex:
        f_gw = ex.submit(ping, gw) if gw else None
        f_wan = ex.submit(ping, CFG["WAN_TARGET"])
        f_https = ex.submit(https_check, CFG["HTTPS_URL"])
        f_dns = ex.submit(dns_check, CFG["DNS_TEST_NAME"])
        f_ph = ex.submit(pihole_poll)
        f_bb = ex.submit(gateway_broadband)
        sysm = sysmetrics()
        g = f_gw.result() if f_gw else {"ok": False, "loss": 100, "ms": None}
        w, h, d, ph = f_wan.result(), f_https.result(), f_dns.result(), f_ph.result()
        try:
            bb = f_bb.result()
        except Exception as e:
            bb = {"error": type(e).__name__}
    internet = h["ok"] or w["ok"]
    now = int(time.time())
    with db() as c:
        c.execute("INSERT OR REPLACE INTO checks VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (now, int(internet), int(g["ok"]), g["ms"], g["loss"], w["ms"], w["loss"], int(h["ok"]),
                   h["ms"], int(d["ok"]), d["ms"], None if not ph.get("configured") else int(ph.get("ok", False)),
                   sysm["cpu"], sysm["mem_pct"], sysm["temp"], bb.get("rx_bps"), bb.get("tx_bps")))
    # outage state machine: 2 consecutive failures = outage
    _fails = 0 if internet else _fails + 1
    if _fails == 2 and _down_since is None:
        _down_since = now - int(CFG["INTERVAL"])
        cause = "gateway unreachable (local Wi-Fi/LAN problem)" if not g["ok"] else \
            f"gateway reachable but internet is not (gateway reports broadband: {bb.get('connection', 'unknown')})"
        event("crit", "internet-outage", f"Internet outage detected - {cause}.")
    elif internet and _down_since is not None:
        # the outage alert itself can't reach the phone while the internet is down, so tell it now
        event("info", "internet-recovered", f"Internet restored after {(now - _down_since) // 60} min.", "phone")
        _down_since = None
    flag("gateway", not g["ok"], "crit", f"Router {gw} not responding to ping.", "Gateway reachable again.")
    flag("dns", internet and not d["ok"], "warn", "DNS lookups are failing while the internet is up.", "DNS resolution recovered.")
    if ph.get("configured"):
        # separate kinds so the "back on" alert isn't swallowed by the 15-minute rate limit of the "off" one
        ph_down = not ph.get("ok")
        if ph_down and not _flags.get("pihole"):
            event("crit", "pihole-off", "Pi-hole turned off. Devices are using the gateway's backup DNS, so ads aren't blocked "
                  "and new devices can't join the Wi-Fi.", "phone")
        elif not ph_down and _flags.get("pihole"):
            event("info", "pihole-on", "Pi-hole is back on. Ad blocking is working again.", "phone")
        _flags["pihole"] = ph_down
    if not _flags.get("booted") and internet:
        _flags["booted"] = True
        try:
            up = uptime_s()
        except (OSError, ValueError):
            up = 1e9
        if up < 900:  # announce only real boots, not dashboard restarts
            event("info", "laptop-on", f"The laptop is on again (started {int(up // 60)} min ago). Pi-hole and the dashboard are running.", "phone")
    flag("memory", sysm["mem_avail"] < 0.08 * sysm["mem_total"], "warn",
         f"Memory pressure: only {sysm['mem_avail'] // 2**20} MiB available.", "Memory pressure cleared.")
    flag("disk", sysm["disk_pct"] > 90, "warn", f"Disk {sysm['disk_pct']}% full.", "Disk usage back under 90%.")
    flag("temperature", (sysm["temp"] or 0) >= 90, "warn", f"CPU temperature high: {sysm['temp'] * 9 / 5 + 32:.0f} °F.", "CPU temperature normal.")
    try:
        record_usage(bb)
        check_data_cap()
    except Exception as e:
        log("usage error:", repr(e))
    with LOCK:
        STATE["last"] = {"ts": now, "gateway_ip": gw, "gw": g, "wan": w, "https": h, "dns": d,
                         "internet": internet, "down_since": _down_since, "sys": sysm}
        STATE["gateway"].update({"broadband": bb})
        STATE["pihole"] = ph


def loop():
    init_db()
    try:
        STATE["gateway"]["info"] = gateway_sysinfo()
    except Exception as e:
        STATE["gateway"]["info"] = {"error": type(e).__name__}
    cpu_pct("main")  # prime CPU delta
    try:
        gateway_broadband()  # prime WAN byte counters so the first loop has a throughput delta
    except Exception:
        pass
    with db() as c:  # show last-known inventory until the first scan completes
        rows = [dict(r) for r in c.execute("SELECT * FROM devices ORDER BY gw_status='on' DESC, last_seen DESC")]
    gw = default_gateway()
    for r in rows:
        r["active"] = r["gw_status"] == "on"
        r["kind"] = "gateway" if r["ip"] == gw else classify(r["name"] or "", r["vendor"] or "")
    hint_rows(rows)
    user_types(rows)
    with LOCK:
        STATE["devices"] = rows
    time.sleep(5)
    next_dev = 0
    next_daily = 0
    interval = max(30, int(CFG["INTERVAL"]))
    while not STOP.is_set():
        t0 = time.time()
        try:
            collect()
        except Exception as e:
            log("collect error:", repr(e))
        if t0 >= next_dev:
            for fn in (refresh_devices, scan_auth_log, scan_listeners):
                try:
                    fn()
                except Exception as e:
                    log(fn.__name__, "error:", repr(e))
            next_dev = t0 + max(120, int(CFG["DEVICE_INTERVAL"]))
        try:
            maybe_nightly_speedtest()
        except Exception as e:
            log("nightly speed test error:", repr(e))
        for fn in (maybe_check_sites, maybe_weekly_report):
            try:
                fn()
            except Exception as e:
                log(fn.__name__, "error:", repr(e))
        if t0 >= next_daily:
            cutoff = int(t0) - int(CFG["RETENTION_DAYS"]) * 86400
            with db() as c:
                c.execute("DELETE FROM checks WHERE ts<?", (cutoff,))
                c.execute("DELETE FROM events WHERE ts<?", (cutoff,))
            try:
                STATE["gateway"]["info"] = gateway_sysinfo()
            except Exception:
                pass
            next_daily = t0 + 86400
        STOP.wait(max(5, interval - (time.time() - t0)))


# ---------------------------------------------------------------- live stream (runs only while a viewer is connected)
LIVE = {"clients": 0, "seq": 0, "frame": None, "kick": 0}  # kick: bumped on sign-out so open streams re-check at once
LIVE_COND = threading.Condition()
LIVE_PERIOD = 1.0
# The gateway page takes ~0.6 s and Pi-hole a few ms. Both are fetched in a helper thread so a slow reply never holds
# up the 1-second frame; each frame carries the newest values they have.
LIVE_SRC = {"wan": {}, "pihole": None, "busy": False}


def live_fetch(want_wan, want_ph, ph_hist):
    try:
        if want_wan:
            try:
                bb = gateway_broadband()
                if bb.get("rx_bps") is not None or not LIVE_SRC["wan"]:
                    LIVE_SRC["wan"] = {k: bb.get(k) for k in ("rx_bps", "tx_bps", "connection")}
                with LOCK:
                    STATE["gateway"]["broadband"] = bb
            except Exception:
                LIVE_SRC["wan"] = {}
        if want_ph:
            try:
                st = PIHOLE.light()
                t = time.time()
                ph = {k: st.get(k) for k in ("total", "blocked", "pct", "blocking", "timer")}
                # queries per minute over the last ~60 s, so one query in one second doesn't read as "60 a minute"
                if st.get("total") is not None:
                    if ph_hist and st["total"] < ph_hist[-1][0]:
                        ph_hist.clear()  # counter reset (FTL restart)
                    ph_hist.append((st["total"], t))
                    while len(ph_hist) > 1 and t - ph_hist[0][1] > 60:
                        ph_hist.popleft()
                old = ph_hist[0] if ph_hist else None
                ph["qpm"] = round((st["total"] - old[0]) * 60 / (t - old[1]), 1) if old and t - old[1] >= 10 else None
                ph.update({"ok": True, "queries": PIHOLE.recent_queries(25)})
                LIVE_SRC["pihole"] = ph
            except Exception as e:
                LIVE_SRC["pihole"] = {"ok": False, "error": type(e).__name__}
    finally:
        LIVE_SRC["busy"] = False


def live_loop():
    nic_prev = wan_t = ph_t = 0
    ph_hist = collections.deque()
    while not STOP.is_set():
        with LIVE_COND:
            while LIVE["clients"] == 0 and not STOP.is_set():
                LIVE_COND.wait(5)
                nic_prev = None
        t0 = time.time()
        period = LIVE_PERIOD
        try:
            dev = (STATE.get("device_meta") or {}).get("iface", {}).get("dev") or local_iface().get("dev")
            mi = meminfo()
            frame = {"ts": t0, "cpu": cpu_pct("live"), "mem_pct": round(100 * (1 - mi["MemAvailable"] / mi["MemTotal"]), 1),
                     "mem_avail": mi["MemAvailable"], "swap_used": mi["SwapTotal"] - mi["SwapFree"], "temp": cpu_temp()}
            gw = default_gateway()
            p = ping(gw, 1, 1) if gw else {"ok": False, "ms": None}
            frame["gw_ok"], frame["gw_ms"] = p["ok"], p["ms"]
            nd = net_dev(dev) if dev else None
            if nd and nic_prev:
                dt = t0 - nic_prev[2]
                frame["nic_rx_bps"] = round(max(0, nd[0] - nic_prev[0]) * 8 / dt)
                frame["nic_tx_bps"] = round(max(0, nd[1] - nic_prev[1]) * 8 / dt)
            nic_prev = (nd[0], nd[1], t0) if nd else None
            period = settings()["live_period"]
            frame["period"] = period
            if not LIVE_SRC["busy"]:
                want_wan, want_ph = t0 - wan_t >= period - .2, bool(PIHOLE) and t0 - ph_t >= period - .2
                if want_wan or want_ph:
                    wan_t, ph_t = (t0 if want_wan else wan_t), (t0 if want_ph else ph_t)
                    LIVE_SRC["busy"] = True
                    threading.Thread(target=live_fetch, args=(want_wan, want_ph, ph_hist), daemon=True).start()
            frame["wan"] = LIVE_SRC["wan"]
            frame["pihole"] = LIVE_SRC["pihole"]
            with LIVE_COND:
                LIVE["seq"] += 1
                LIVE["frame"] = frame
                LIVE_COND.notify_all()
        except Exception as e:
            log("live error:", repr(e))
        STOP.wait(max(0.5, period - (time.time() - t0)))


# ---------------------------------------------------------------- diagnostics / assistant
def history(hours=24):
    since = int(time.time()) - hours * 3600
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM checks WHERE ts>=? ORDER BY ts", (since,))]
    return rows


def outage_report(days=30):
    """Outages = runs of failed internet checks in the stored history. Gaps (laptop off/asleep) end a run."""
    iv = max(30, int(CFG["INTERVAL"]))
    since = int(time.time()) - days * 86400
    with db() as c:
        rows = c.execute("SELECT ts, internet, gw_ok FROM checks WHERE ts>=? ORDER BY ts", (since,)).fetchall()
    outs, cur, prev = [], None, None
    for r in rows:
        gap = prev is not None and r["ts"] - prev > 3 * iv
        if cur and (r["internet"] or gap):
            cur["end"] = r["ts"] if r["internet"] and not gap else prev
            outs.append(cur)
            cur = None
        if not r["internet"]:
            if cur is None:
                cur = {"start": r["ts"], "checks": 0, "local": 0}
            cur["checks"] += 1
            cur["local"] += 0 if r["gw_ok"] else 1
        prev = r["ts"]
    if cur:
        cur["end"], cur["ongoing"] = None, True
        outs.append(cur)
    now = int(time.time())
    for o in outs:
        o["secs"] = max(iv, (o["end"] or now) - o["start"])
        o["blip"] = o["checks"] < 2  # one failed check; the live alert needs two in a row
        o["cause"] = "Wi-Fi / laptop ↔ gateway" if o["local"] * 2 > o["checks"] else "Internet (provider side)"
    lt = time.localtime()
    month0 = int(time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1)))
    real = [o for o in outs if not o["blip"]]
    tot = lambda xs: {"count": len(xs), "secs": sum(o["secs"] for o in xs),
                      "longest": max((o["secs"] for o in xs), default=0)}
    return {"outages": outs[::-1][:100], "month": tot([o for o in real if o["start"] >= month0]),
            "days": days, "all": tot(real), "blips": len(outs) - len(real),
            "covered_from": rows[0]["ts"] if rows else None, "samples": len(rows)}


def blocked_by_device():
    """Pi-hole's per-client blocked counts (today, 24 h window) mapped to dashboard device names."""
    if not isinstance(PIHOLE, PiHole) or PIHOLE.ver != 6:
        return {"clients": [], "error": "needs Pi-hole v6"}
    blk = PIHOLE.v6("/api/stats/top_clients?blocked=true&count=15").get("clients", [])
    allq = {x.get("ip"): x.get("count", 0) for x in PIHOLE.v6("/api/stats/top_clients?count=100").get("clients", [])}
    byip = {}
    for d in STATE["devices"]:
        if d.get("ip"):
            byip[d["ip"]] = d
    out = []
    for x in blk:
        ip = x.get("ip")
        d = byip.get(ip, {})
        tot = allq.get(ip) or 0
        out.append({"ip": ip, "name": d.get("label") or d.get("name") or x.get("name") or ip, "mac": d.get("mac"),
                    "kind": d.get("kind"), "blocked": x.get("count", 0), "total": tot,
                    "pct": round(100 * x.get("count", 0) / tot, 1) if tot else None})
    return {"clients": out}


# ---------------------------------------------------------------- speed test (Cloudflare, stdlib only)
SPEED = {"running": False, "phase": None, "last_error": None}
SPEED_LOCK = threading.Lock()


def _cf_conn():
    import http.client
    return http.client.HTTPSConnection("speed.cloudflare.com", timeout=30, context=ssl_ctx())


def speedtest(trigger="manual"):
    """~10 latency probes, 10 + 25 MB download, 2 x 5 MB upload. Measures through this laptop's Wi-Fi."""
    if not SPEED_LOCK.acquire(blocking=False):
        return {"error": "A speed test is already running."}
    try:
        SPEED.update(running=True, phase="latency", last_error=None)
        c = _cf_conn()
        lat, colo = [], None
        for _ in range(10):
            t = time.perf_counter()
            c.request("GET", "/__down?bytes=0", headers={"User-Agent": "ncc/1.0"})
            r = c.getresponse()
            r.read()
            lat.append((time.perf_counter() - t) * 1000)
            colo = colo or r.getheader("cf-meta-colo")
        lat.sort()
        ping = statistics_median(lat[:-2] or lat)
        jitter = sum(abs(a - b) for a, b in zip(lat, lat[1:])) / max(1, len(lat) - 1)
        SPEED["phase"] = "download"
        down = 0.0
        for size in (10_000_000, 25_000_000):
            c.request("GET", f"/__down?bytes={size}", headers={"User-Agent": "ncc/1.0"})
            r = c.getresponse()
            t, n = time.perf_counter(), 0
            while True:
                b = r.read(65536)
                if not b:
                    break
                n += len(b)
            down = max(down, n * 8 / (time.perf_counter() - t) / 1e6)
        SPEED["phase"] = "upload"
        up = 0.0
        chunk = b"0" * 65536
        for size in (5_000_000, 5_000_000):
            body = (chunk[: min(65536, size - i)] for i in range(0, size, 65536))
            t = time.perf_counter()
            c.request("POST", "/__up", body=body, headers={"User-Agent": "ncc/1.0", "Content-Length": str(size),
                                                           "Content-Type": "application/octet-stream"})
            c.getresponse().read()
            up = max(up, size * 8 / (time.perf_counter() - t) / 1e6)
        c.close()
        row = (int(time.time()), round(down, 1), round(up, 1), round(ping, 1), round(jitter, 1), colo, trigger)
        with db() as d:
            d.execute("INSERT OR REPLACE INTO speedtests VALUES(?,?,?,?,?,?,?)", row)
        log(f"speed test ({trigger}): {row[1]} down / {row[2]} up Mbps, {row[3]} ms")
        lim = settings().get("speed_alert_mbps") or 0
        if lim and row[1] < lim:
            event("warn", "slow-speed", f"Speed test: {row[1]:.0f} Mbps down, below your {lim} Mbps alert. "
                  "It measures through this laptop's Wi-Fi, so check the gateway if it keeps happening.", "phone")
        return {"ok": True, "ts": row[0], "down_mbps": row[1], "up_mbps": row[2], "ping_ms": row[3], "jitter_ms": row[4], "colo": colo}
    except Exception as e:
        SPEED["last_error"] = type(e).__name__
        log("speed test failed:", repr(e))
        return {"error": f"Speed test failed ({type(e).__name__})."}
    finally:
        SPEED.update(running=False, phase=None)
        SPEED_LOCK.release()


def statistics_median(xs):
    xs = sorted(xs)
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2


def speed_history(days=30):
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM speedtests WHERE ts>=? ORDER BY ts",
                                           (int(time.time()) - days * 86400,))]
    return {"tests": rows, "running": SPEED["running"], "phase": SPEED["phase"], "last_error": SPEED["last_error"]}


def maybe_nightly_speedtest():
    """Scheduled speed test, as set in Tools & settings: every N minutes, once a day at a set time, or off.
    ~45 MB per test. Skipped while the internet is down or a test is already running."""
    st = settings()
    if st["speedtest_mode"] == "off" or SPEED["running"] or not (STATE.get("last") or {}).get("internet"):
        return
    if st["speedtest_mode"] == "every" and st.get("speed_quiet_on"):
        lt = time.localtime()
        now_m, f, t = lt.tm_hour * 60 + lt.tm_min, *(int(x[:2]) * 60 + int(x[3:]) for x in (st["speed_quiet_from"], st["speed_quiet_to"]))
        if (f <= now_m < t) if f < t else (now_m >= f or now_m < t):
            return  # quiet hours: no automatic tests
    if st["speedtest_mode"] == "daily":
        lt = time.localtime()
        h, m = map(int, st["speedtest_at"].split(":"))
        mins = lt.tm_hour * 60 + lt.tm_min - (h * 60 + m)
        slot = "d" + time.strftime("%Y-%m-%d", lt) + st["speedtest_at"]
        if not 0 <= mins < 60:  # within the hour after the set time (the laptop may have been asleep right at it)
            return
        trigger = "daily"
    else:
        every = st["speedtest_every_min"] * 60
        slot = f"e{every}-{int(time.time() // every)}"
        trigger = "hourly" if every == 3600 else f"every {st['speedtest_every_min']} min"
    if kv_get("speedtest_slot") == slot:
        return
    kv_set("speedtest_slot", slot)
    threading.Thread(target=speedtest, args=(trigger,), daemon=True).start()


# ---------------------------------------------------------------- data usage (from the gateway's WAN byte counters)
def record_usage(bb):
    """Add what the whole home used since the last check to today's total. A gateway restart resets its counters to 0;
    then the new count is what was used since. Time the laptop was off lands on the day it's back (can't split it)."""
    rx, tx = bb.get("rx_total"), bb.get("tx_total")
    if rx is None or tx is None:
        return
    prev = kv_get("usage_prev")
    kv_set("usage_prev", [rx, tx])
    if not prev:
        return
    drx = rx - prev[0] if rx >= prev[0] else rx
    dtx = tx - prev[1] if tx >= prev[1] else tx
    day = time.strftime("%Y-%m-%d")
    with db() as c:
        c.execute("INSERT INTO usage(day,rx,tx) VALUES(?,?,?) ON CONFLICT(day) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx",
                  (day, drx, dtx))


def billing_cycle():
    """(start, next start) of the current billing month, as local midnight timestamps."""
    bd = settings().get("billing_day", 1)
    lt = time.localtime()
    y, m = lt.tm_year, lt.tm_mon
    if lt.tm_mday < bd:
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    start = time.mktime((y, m, bd, 0, 0, 0, 0, 0, -1))
    ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
    return start, time.mktime((ny, nm, bd, 0, 0, 0, 0, 0, -1))


def usage_report(days=31):
    lt = time.localtime()
    start, end = billing_cycle()
    sday = time.strftime("%Y-%m-%d", time.localtime(start))
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT day, rx, tx FROM usage ORDER BY day DESC LIMIT ?", (days,))][::-1]
        m = c.execute("SELECT COALESCE(SUM(rx),0) rx, COALESCE(SUM(tx),0) tx FROM usage WHERE day>=?", (sday,)).fetchone()
        first = c.execute("SELECT MIN(day) FROM usage").fetchone()[0]
    frac = (time.time() - start) / (end - start)
    tot = m["rx"] + m["tx"]
    proj = tot / frac if frac > 0.05 and first and first <= sday else None
    today = time.strftime("%Y-%m-%d", lt)
    td = next((r for r in rows if r["day"] == today), {"rx": 0, "tx": 0})
    cap = (settings().get("data_cap_gb") or 0) * 1e9
    return {"days": rows, "month": {"rx": m["rx"], "tx": m["tx"], "total": tot, "projected": proj, "from": sday,
                                    "until": time.strftime("%Y-%m-%d", time.localtime(end - 86400))},
            "today": td, "tracking_since": first, "cap": cap or None, "cap_pct": round(100 * tot / cap, 1) if cap else None}


def check_data_cap():
    u = usage_report(1)
    if not u["cap"]:
        return
    sent = kv_get("cap_alerts", {}) or {}
    cyc = u["month"]["from"]
    for pct in (100, 80):  # past both at once: one alert, the bigger one
        if u["cap_pct"] >= pct and sent.get(str(pct)) != cyc:
            for p in (80, 100):
                if p <= pct:
                    sent[str(p)] = cyc
            kv_set("cap_alerts", sent)
            event("crit" if pct == 100 else "warn", "data-cap", f"Data usage: {_fmt_bytes(u['month']['total'])} used, "
                  f"{u['cap_pct']:.0f}% of your {_fmt_bytes(u['cap'])} monthly cap (billing month started {cyc}).", "phone")
            break


# ---------------------------------------------------------------- website checker
SITE_STATE = {}   # url -> {ok, ms, code, error, ts, fails, alerted}
_sites_next = 0


def sites():
    return kv_get("sites", []) or []


def _public_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True  # can't resolve: let the check report it as down
    for i in infos:
        ip = ipaddress.ip_address(i[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def site_add(url, name=""):
    url = str(url or "").strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname or len(url) > 300 or "@" in p.netloc:
        raise ValueError("That doesn't look like a website address.")
    if not _public_host(p.hostname):
        raise ValueError("Only public websites can be checked (not addresses inside your home network).")
    ss = sites()
    if any(s["url"] == url for s in ss):
        raise ValueError("Already on the list.")
    if len(ss) >= 20:
        raise ValueError("That's the most sites (20).")
    name = re.sub(r"[<>]", "", str(name or "").strip())[:40] or p.hostname
    ss.append({"url": url, "name": name})
    kv_set("sites", ss)
    threading.Thread(target=check_site, args=(url,), daemon=True).start()
    return ss


def site_remove(url):
    ss = [s for s in sites() if s["url"] != url]
    kv_set("sites", ss)
    SITE_STATE.pop(url, None)
    return ss


def check_site(url):
    st = SITE_STATE.setdefault(url, {"fails": 0, "alerted": False})
    t0 = time.time()
    try:
        host = urllib.parse.urlparse(url).hostname
        if not _public_host(host):
            raise ValueError("private address")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (NCC website checker)"})
        try:
            with urllib.request.urlopen(req, timeout=12) as r:
                r.read(2048)
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        ok = code < 500  # 4xx still means the site answered (many block robots); 5xx means it's broken
        st.update({"ok": ok, "code": code, "error": None if ok else f"HTTP {code}"})
    except Exception as e:
        st.update({"ok": False, "code": None, "error": {"URLError": "no answer", "TimeoutError": "timed out",
                                                         "timeout": "timed out"}.get(type(e).__name__, type(e).__name__)})
    st.update({"ms": round((time.time() - t0) * 1000), "ts": int(time.time())})
    name = next((s["name"] for s in sites() if s["url"] == url), url)
    internet = (STATE.get("last") or {}).get("internet")
    if st["ok"]:
        if st["alerted"]:
            event("info", "site-up", f"{name} is working again.", "phone")
        st.update({"fails": 0, "alerted": False})
    else:
        st["fails"] += 1
        if st["fails"] >= settings().get("site_fail_n", 2) and not st["alerted"] and internet:  # your internet is fine, so it's the site
            st["alerted"] = True
            event("warn", "site-down", f"{name} isn't working ({st['error']}), but your internet is fine. "
                  "It's probably a problem on their side.", "phone")


def maybe_check_sites(force=False):
    global _sites_next
    if not force and time.time() < _sites_next:
        return
    _sites_next = time.time() + 60 * settings().get("site_interval_min", 5)
    with ThreadPoolExecutor(4) as ex:
        list(ex.map(check_site, [s["url"] for s in sites()]))


# ---------------------------------------------------------------- Wi-Fi neighbors (this laptop's own scan, read-only)
_wifi = {"ts": 0, "data": None}


def wifi_neighbors(rescan=False):
    if _wifi["data"] and not rescan and time.time() - _wifi["ts"] < 60:
        return _wifi["data"]
    if rescan and time.time() - _wifi["ts"] < 20:
        rescan = False  # scanning is slow and briefly busies the Wi-Fi card
    if not _wifi["data"]:
        rescan = True  # the system's cached list can be nearly empty (e.g. only the current band) until a real scan
    if WIN:
        nets, note = W.wifi()
        my_ssid = next((n["ssid"] for n in nets if n["mine"]), None)
        for n in nets:
            n["home"] = n["ssid"] == my_ssid or bool(my_ssid and n["ssid"].startswith(my_ssid))
        nets.sort(key=lambda n: (not n["home"], -n["signal"]))
        data = {"networks": nets, "ts": int(time.time()), "my_ssid": my_ssid, "note": note}
        _wifi.update({"ts": time.time(), "data": data})
        return data
    code, out = run(["nmcli", "-t", "-e", "yes", "-f", "IN-USE,SSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi", "list",
                     "--rescan", "yes" if rescan else "auto"], 30)
    nets = []
    for line in out.splitlines():
        f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
        if len(f) < 6:
            continue
        try:
            ch, freq, sig = int(f[2]), int(f[3].split()[0]), int(f[4])
        except ValueError:
            continue
        nets.append({"mine": f[0] == "*", "ssid": f[1] or "(hidden network)", "channel": ch,
                     "band": "2.4 GHz" if freq < 3000 else "5 GHz" if freq < 5925 else "6 GHz", "signal": sig,
                     "security": f[5] or "open"})
    my_ssid = next((n["ssid"] for n in nets if n["mine"]), None)
    for n in nets:
        n["home"] = n["ssid"] == my_ssid or (my_ssid and n["ssid"].startswith(my_ssid))
    nets.sort(key=lambda n: (not n["home"], -n["signal"]))
    data = {"networks": nets, "ts": int(time.time()), "my_ssid": my_ssid}
    _wifi.update({"ts": time.time(), "data": data})
    return data


# ---------------------------------------------------------------- weekly report (phone alert only, never email)
def _fmt_bytes(b):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1000 or u == "TB":
            return f"{b:.0f} {u}" if u in ("B", "KB") else f"{b:.1f} {u}"
        b /= 1000


def _fmt_secs(s):
    return f"{s // 60} min" if s < 3600 else f"{s / 3600:.1f} h"


def weekly_report_text():
    now = int(time.time())
    since = now - 7 * 86400
    lines = []
    with db() as c:
        r = c.execute("SELECT COUNT(*) n, SUM(internet) up FROM checks WHERE ts>=?", (since,)).fetchone()
        sp = c.execute("SELECT AVG(down_mbps) d, AVG(up_mbps) u, MIN(down_mbps) lo, COUNT(*) n FROM speedtests WHERE ts>=?",
                       (since,)).fetchone()
        ev = {k: n for k, n in c.execute("SELECT kind, COUNT(*) FROM events WHERE ts>=? GROUP BY kind", (since,))}
        u = c.execute("SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM usage WHERE day>=?",
                      (time.strftime("%Y-%m-%d", time.localtime(since + 86400)),)).fetchone()
    o = outage_report(7)["all"]
    want = set(settings().get("weekly_sections") or WEEKLY_SECTIONS)
    if r["n"] and "internet" in want:
        line = f"🌐 Internet: {100 * (r['up'] or 0) / r['n']:.2f}% online"
        line += f", {o['count']} outage{'s' if o['count'] != 1 else ''} ({_fmt_secs(o['secs'])} total, longest {_fmt_secs(o['longest'])})" if o["count"] else ", no outages"
        lines.append(line)
    if sp["n"] and "speed" in want:
        lines.append(f"⚡ Speed: {sp['d']:.0f} down / {sp['u']:.0f} up Mbps on average, slowest {sp['lo']:.0f} down ({sp['n']} tests)")
    if (u[0] or u[1]) and "data" in want:
        lines.append(f"📶 Data used: {_fmt_bytes(u[0] + u[1])} ({_fmt_bytes(u[0])} down, {_fmt_bytes(u[1])} up)")
    if PIHOLE and "pihole" in want:
        try:
            ps = PIHOLE.v6(f"/api/stats/database/summary?from={since}&until={now}")
            lines.append(f"🛡 Pi-hole: {ps.get('sum_blocked', 0):,} of {ps.get('sum_queries', 0):,} lookups blocked "
                         f"({ps.get('percent_blocked') or 0:.0f}%)")
        except Exception:
            pass
    nd = ev.get("new-device", 0)
    if "devices" in want:
        lines.append(f"📱 New devices: {nd}" + (" (see the Devices tab)" if nd else ""))
    ws, wf = ev.get("web-signin", 0), ev.get("web-signin-fail", 0)
    if (ws or wf) and "signins" in want:
        lines.append(f"🔐 Web sign-ins: {ws}" + (f", {wf} wrong tries" if wf else ""))
    sd = ev.get("site-down", 0)
    if sites() and "sites" in want:
        lines.append(f"🌍 Websites: {'all up all week' if not sd else f'{sd} went down at some point'}")
    pd = ev.get("pihole-off", 0)
    if (pd or ev.get("laptop-on", 0)) and "laptop" in want:
        lines.append(f"💻 Laptop: {ev.get('laptop-on', 0)} restart(s), Pi-hole off {pd} time(s)")
    return "\n".join(lines) or "No data yet."


def send_weekly_report():
    if not ntfy_url():
        raise RuntimeError("Phone alerts aren't set up.")
    push, _ = send_ntfy("NCC weekly report", weekly_report_text(), "info", email_copy=False)
    if not push:
        raise RuntimeError("Couldn't reach ntfy.")
    with db() as c:
        c.execute("INSERT INTO events(ts,level,kind,msg) VALUES(?,?,?,?)", (int(time.time()), "info", "weekly-report",
                                                                           "Weekly report sent to the phone."))


def maybe_weekly_report():
    st = settings()
    if not st.get("weekly_report"):
        return
    lt = time.localtime()
    if lt.tm_wday != st["weekly_day"] or lt.tm_hour != st["weekly_hour"]:
        return
    day = time.strftime("%Y-%m-%d", lt)
    if kv_get("weekly_sent") == day:
        return
    kv_set("weekly_sent", day)
    send_weekly_report()


def uptime_stats():
    out = {}
    with db() as c:
        for label, hrs in (("24h", 24), ("7d", 168), ("30d", 720)):
            r = c.execute("SELECT COUNT(*) n, SUM(internet) up, SUM(gw_ok) gw FROM checks WHERE ts>=?",
                          (int(time.time()) - hrs * 3600,)).fetchone()
            out[label] = {"samples": r["n"], "internet": round(100 * r["up"] / r["n"], 2) if r["n"] else None,
                          "gateway": round(100 * r["gw"] / r["n"], 2) if r["n"] else None}
    return out


def diagnose():
    """Rule-based findings computed only from measured data."""
    s = STATE["last"]
    if not s:
        return [{"level": "info", "title": "Collecting", "detail": "First measurements are still being taken."}]
    f = []
    sysm, g, w, h, d = s["sys"], s["gw"], s["wan"], s["https"], s["dns"]
    bb = STATE["gateway"].get("broadband", {})
    if not g["ok"]:
        f.append({"level": "crit", "title": "Gateway unreachable",
                  "detail": f"This PC cannot ping the router ({s['gateway_ip']}). The problem is between this computer and the router: check that Wi-Fi is connected, move closer, or toggle Wi-Fi off/on."})
    elif not s["internet"]:
        f.append({"level": "crit", "title": "Internet down, router OK",
                  "detail": f"The gateway answers but the internet does not. The gateway reports broadband '{bb.get('connection', 'unknown')}', line '{bb.get('line', 'unknown')}'. If it says Down, the outage is on your internet provider's side - check the router's internet light and the provider's outage page."})
    else:
        f.append({"level": "good", "title": "Internet up",
                  "detail": f"HTTPS check {'passed' if h['ok'] else 'failed'} ({h['ms']} ms). Ping to {CFG['WAN_TARGET']}: {w['ms']} ms, {w['loss']}% loss. Gateway ping {g['ms']} ms."})
        if w["loss"] and w["loss"] > 0:
            f.append({"level": "warn", "title": "Packet loss", "detail": f"{w['loss']}% packet loss to the internet in the last test."})
        if g["ms"] and g["ms"] > 30:
            f.append({"level": "warn", "title": "Slow Wi-Fi to router", "detail": f"Ping to the gateway is {g['ms']} ms (usually under 10 ms). Likely weak Wi-Fi signal or interference."})
    if s["internet"] and not d["ok"]:
        f.append({"level": "warn", "title": "DNS failing", "detail": "Internet is reachable but name lookups fail. Check the DNS server (gateway or Pi-hole)."})
    ph = STATE["pihole"]
    if not ph.get("configured"):
        f.append({"level": "info", "title": "Pi-hole not connected",
                  "detail": "No ad blocker (Pi-hole or AdGuard Home) is set up. Run the installer again to add one."})
    elif not ph.get("ok"):
        f.append({"level": "warn", "title": "Pi-hole down", "detail": f"Pi-hole at {ph.get('host')} is not answering ({ph.get('error', 'no DNS reply')})."})
    else:
        f.append({"level": "good" if ph.get("blocking") in ("enabled", True) else "warn", "title": f"Pi-hole {ph.get('blocking')}",
                  "detail": f"{ph.get('total')} queries today, {ph.get('pct') and round(float(ph['pct']), 1)}% blocked."})
    if sysm["mem_avail"] < 0.15 * sysm["mem_total"]:
        hogs = top_processes()
        f.append({"level": "warn", "title": "Low memory",
                  "detail": f"Only {sysm['mem_avail'] // 2**20} MiB available, swap used {sysm['swap_used'] // 2**20} MiB. Biggest users: " + ", ".join(f"{n} (~{m} MiB)" for n, m in hogs[:3]) + ". Closing browser tabs is the quickest fix."})
    if sysm["cpu"] and sysm["cpu"] > 85:
        f.append({"level": "warn", "title": "CPU busy", "detail": f"CPU at {sysm['cpu']}%, load {sysm['load']}."})
    if sysm["temp"] and sysm["temp"] >= 85:
        f.append({"level": "warn", "title": "Running hot", "detail": f"CPU package at {sysm['temp'] * 9 / 5 + 32:.0f} °F. Check vents/fan."})
    devs = STATE["devices"]
    act = [x for x in devs if x.get("active")]
    nopong = [x for x in act if x.get("ping_ok") == 0]
    if nopong:
        f.append({"level": "info", "title": f"{len(nopong)} active devices ignore ping",
                  "detail": "The gateway says they are connected, but they did not answer ping. Phones and TVs often do this to save battery; it is not necessarily a fault."})
    return f


def top_processes(n=5):
    if WIN:
        agg = {}
        for name, kb in W.processes():
            agg[name] = agg.get(name, 0) + kb
        return sorted(((k, v // 1024) for k, v in agg.items()), key=lambda x: -x[1])[:n]
    _, out = run(["ps", "-eo", "rss=,comm=", "--sort=-rss"])
    agg = {}
    for line in out.splitlines():
        p = line.split(None, 1)
        if len(p) == 2:
            agg[p[1].strip()] = agg.get(p[1].strip(), 0) + int(p[0])
    return sorted(((k, v // 1024) for k, v in agg.items()), key=lambda x: -x[1])[:n]


def snapshot_for_ai():
    s = STATE["last"]
    sysm = dict(s.get("sys", {}))
    sysm.pop("temps", None)
    devs = [{k: x.get(k) for k in ("ip", "label", "name", "vendor", "conn", "active", "ping_ok", "kind")}
            for x in STATE["devices"] if x.get("active")]
    ph = {k: v for k, v in STATE["pihole"].items() if k not in ("top_clients",)}
    try:  # per-device lookups and blocks, with the names the user gave each device
        ph["lookups_by_device_24h"] = [{k: x.get(k) for k in ("name", "ip", "blocked", "total", "pct")}
                                      for x in blocked_by_device().get("clients", [])]
    except Exception as e:
        ph["lookups_by_device_24h"] = f"unavailable ({type(e).__name__})"
    with db() as c:
        ev = [dict(r) for r in c.execute("SELECT ts,level,kind,msg FROM events ORDER BY id DESC LIMIT 15")]
    bb = {k: v for k, v in STATE["gateway"].get("broadband", {}).items()}
    return {"now": time.strftime("%Y-%m-%d %H:%M"), "latest_checks": {k: s.get(k) for k in ("gw", "wan", "https", "dns", "internet", "down_since")},
            "system": sysm, "top_memory_processes_mib": top_processes(), "gateway_model": STATE["gateway"].get("info"),
            "gateway_broadband": bb, "pihole": ph, "active_devices": devs, "uptime_pct": uptime_stats(),
            "recent_events": ev, "rule_findings": diagnose()}


# The person's own AI assistant, through its own command-line program and their own sign-in (never a shared account).
# Each one runs without tools where the program allows it, in an empty folder, and only for requests from this computer.
AI_TOOLS = {"claude": "Claude Code", "codex": "Codex", "gemini": "Gemini CLI"}


def ai_exe(name):
    exe = shutil.which(name)
    if not exe and name == "claude":
        p = Path.home() / ".local" / "bin" / ("claude.exe" if WIN else "claude")
        exe = str(p) if p.exists() else None
    return exe


def ai_assistant():
    a = settings().get("ai_assistant")
    if a is None:
        a = CFG["AI_ASSISTANT"] or ("claude" if CFG["AI_ENABLED"] == "1" else "off")
    return a if a in AI_TOOLS else "off"


def ai_command(name, exe, sandbox):
    model = CFG["AI_MODEL"].strip()
    if name == "claude":
        return [exe, "-p", "--model", model or "claude-haiku-5-5", "--tools", "", "--strict-mcp-config",
                "--no-session-persistence", "--setting-sources", ""], None
    if name == "codex":
        out = sandbox / "answer.txt"
        out.unlink(missing_ok=True)
        cmd = [exe, "exec", "--sandbox", "read-only", "--skip-git-repo-check", "--color", "never", "-o", str(out)]
        return cmd + (["-m", model] if model else []) + ["-"], out
    if name == "gemini":
        return [exe, "-p", "Answer the request given on standard input.", "--approval-mode", "default"] + (["-m", model] if model else []), None
    raise ValueError("unknown assistant")


def ask_ai(question):
    name = ai_assistant()
    exe = ai_exe(name) if name != "off" else None
    if not exe:
        return f"AI unavailable: {AI_TOOLS.get(name, 'no assistant')} isn't installed on this computer (or isn't on its PATH)."
    prompt = ("You are the read-only troubleshooting assistant for a home network dashboard. Answer the user's question "
              "in plain, friendly language using ONLY the monitoring data below. If the data does not show something, say so "
              "instead of guessing. Keep it under 180 words. Suggest safe next checks; never claim you changed anything. "
              "Do not run commands or read files.\n\n"
              f"MONITORING DATA (JSON):\n{doctor.redact(json.dumps(snapshot_for_ai(), default=str))}\n\nQUESTION: {question}")
    sandbox = DATA / "ai-sandbox"
    sandbox.mkdir(exist_ok=True)
    try:
        cmd, out_file = ai_command(name, exe, sandbox)
        # the programs need more memory than this service's cap allows, so give them their own short-lived, capped unit
        if shutil.which("systemd-run"):
            cmd = ["systemd-run", "--user", "--quiet", "--wait", "--pipe", "--collect", "-p", "MemoryMax=700M",
                   "-p", "CPUQuota=60%", f"--working-directory={sandbox}"] + cmd
        p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=180, cwd=sandbox, errors="replace",
                           **({"creationflags": W.NO_WINDOW} if WIN else {}))
        ans = out_file.read_text(errors="replace").strip() if out_file and out_file.exists() else p.stdout.strip()
        return ans or (f"AI error ({AI_TOOLS[name]}): " + doctor.redact(p.stderr.strip()[-300:]))
    except Exception as e:
        return f"AI unavailable: {type(e).__name__}"


def ai_handoff(status):
    """Everything someone's own AI needs to help, passwords and private names removed ("Copy for my AI")."""
    extra = {"Service": doctor.service_state(), "Tailscale": doctor.tailscale_state()}
    report = doctor.build(status, CFG, list(SECRETS), extra, doctor.log_tail(25))
    folder = doctor.redact(str(BASE))
    run_cmd = r"ncc doctor" if WIN else "./ncc doctor"
    return (f"I use Network Command Center ({doctor.REPO}), a home network dashboard. It runs on my "
            f"{'Windows' if WIN else 'Linux'} computer in the folder {folder}.\n\n"
            f"My problem: [describe it here]\n\n"
            f"If you can work on that computer (Claude Code, Codex, Gemini CLI, Cursor and others), open that folder first: "
            f"AGENTS.md there explains how the dashboard works, the commands to use (start with `{run_cmd}`), and the safety "
            f"rules. Ask me before changing anything. If you can't, just help me with the report below.\n\n" + report)


QUICK = {
    "internet": ("Why is my internet down?", lambda f: [x for x in f if x["title"].startswith(("Internet", "Gateway", "Packet", "Slow", "DNS"))]),
    "pihole": ("Is Pi-hole working?", lambda f: [x for x in f if "Pi-hole" in x["title"]]),
    "unreachable": ("Which devices are unreachable?", None),
    "slow": ("Why is my computer slow?", lambda f: [x for x in f if x["title"] in ("Low memory", "CPU busy", "Running hot")]),
    "next": ("What should I investigate next?", lambda f: [x for x in f if x["level"] in ("crit", "warn")]),
}


def rule_answer(topic):
    f = diagnose()
    if topic == "unreachable":
        act = [x for x in STATE["devices"] if x.get("active") and x.get("ping_ok") == 0]
        if not act:
            return "Every active device that was pinged replied."
        lines = [f"- {x['name'] or x['mac']} ({x['ip'] or 'no IP'}, {x['conn'] or 'unknown link'})" for x in act]
        return ("The gateway lists these as connected, but they did not answer ping (often normal for phones/TVs):\n" + "\n".join(lines))
    sel = QUICK.get(topic, QUICK["next"])[1](f)
    if topic == "slow" and not sel:
        s = STATE["last"]["sys"]
        return (f"Nothing alarming: CPU {s['cpu']}%, {s['mem_avail'] // 2**20} MiB RAM available, "
                f"swap used {s['swap_used'] // 2**20} MiB, temp {s['temp']} C. Top memory users: "
                + ", ".join(f"{n} ~{m} MiB" for n, m in top_processes(3)) + ".")
    if topic == "next" and not sel:
        return "No warnings right now. Everything measured is within normal ranges."
    return "\n".join(f"[{x['level'].upper()}] {x['title']}: {x['detail']}" for x in sel) or "No related findings."


# ---------------------------------------------------------------- approved diagnostic actions
HOST_RX = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")


def action(name, arg):
    iface = local_iface()
    if name == "ping":
        ip = ipaddress.ip_address(arg)  # raises on invalid input
        if iface.get("subnet") and ip not in ipaddress.ip_network(iface["subnet"]) and str(ip) != CFG["WAN_TARGET"]:
            raise ValueError("Only addresses on your own subnet (or the WAN test target) may be pinged.")
        return ping(str(ip), 4, 1)
    if name == "dns":
        if not HOST_RX.match(arg):
            raise ValueError("Invalid hostname")
        res = {"system": dns_check(arg), "gateway": dns_check(arg, default_gateway())}
        if PIHOLE:
            res["pihole"] = dns_check(arg, re.sub(r"^https?://", "", PIHOLE.url).split("/")[0].split(":")[0])
        return res
    if name == "recheck":
        collect()
        return {"ok": True}
    if name == "rescan":
        refresh_devices()
        return STATE.get("device_meta")
    if name == "trace":
        if not HOST_RX.match(arg):
            raise ValueError("Invalid hostname")
        if WIN:
            return {"output": W.trace(arg)[-3000:]}
        exe = shutil.which("tracepath")
        if not exe:
            return {"error": "tracepath not installed"}
        _, out = run([exe, "-n", "-m", "15", arg], 40)
        return {"output": out[-3000:]}
    raise ValueError("Unknown action")


def status_body():
    with LOCK:
        body = {"last": STATE["last"], "pihole": STATE["pihole"], "gateway": STATE["gateway"],
                "device_meta": STATE.get("device_meta"), "security": STATE["security"],
                "uptime": uptime_stats(), "findings": diagnose(), "started": STATE["started"], "version": VERSION,
                "config": {"interval": CFG["INTERVAL"], "wan_target": CFG["WAN_TARGET"],
                           "ai": ai_assistant() != "off", "ai_name": AI_TOOLS.get(ai_assistant()), "pihole_controls": CFG["PIHOLE_CONTROLS"] == "1",
                           "pihole_lists": CFG["PIHOLE_LISTS"] == "1",
                           "system_controls": CFG["SYSTEM_CONTROLS"] == "1",
                           "ntfy": bool(ntfy_url())}}
    body["gateway"] = {k: v for k, v in body["gateway"].items()}
    return body


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    server_version = "ncc"

    def log_message(self, fmt, *a):
        pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        allowed = {"127.0.0.1", "localhost", "::1", CFG["BIND"]} | set(filter(None, CFG.get("ALLOWED_HOSTS", "").split(",")))
        return host in allowed

    def _remote(self):
        """Came in through Tailscale serve (a proxy on this machine), not from a browser on the laptop."""
        return bool(self.headers.get("X-Forwarded-For") or self.headers.get("Tailscale-User-Login")
                    or (self.headers.get("Host") or "").rsplit(":", 1)[0].endswith(".ts.net"))

    def _client_ip(self):
        return (self.headers.get("X-Forwarded-For") or "").split(",")[-1].strip()  # the proxy appends the real one last

    def _manager(self):
        """May manage web access: the laptop itself, or one of your own Tailscale devices signed in with the PIN."""
        if not self._remote():
            return True
        if self._public():
            return False
        v = _read_json(SESS_FILE, {}).get(hashlib.sha256((self._cookie() or "").encode()).hexdigest())
        return isinstance(v, dict) and v.get("kind") == "pin"

    def _public(self):
        """Came from the open web through Tailscale Funnel rather than from one of your Tailscale devices."""
        if not self._remote():
            return False
        if self.headers.get("Tailscale-Funnel-Request") or not self.headers.get("Tailscale-User-Login"):
            return True  # Tailscale only adds the user headers for your own devices (and strips any a visitor sends)
        try:
            ip = ipaddress.ip_address(self._client_ip())
        except ValueError:
            return True
        return not (ip in ipaddress.ip_network("100.64.0.0/10") or ip in ipaddress.ip_network("fd7a:115c:a1e0::/48"))

    def _device(self):
        """This browser's device ID (set on its first visit), used to block a device for good."""
        m = re.search(r"(?:^|;\s*)ncc_d=([\w-]{20,64})", self.headers.get("Cookie") or "")
        if m:
            return m.group(1)
        if not getattr(self, "_new_dev", None):
            self._new_dev = secrets.token_urlsafe(24)
            self._extra = getattr(self, "_extra", []) + [("Set-Cookie", f"ncc_d={self._new_dev}; Path=/; Max-Age={5 * 365 * 86400}; "
                                                                       "HttpOnly; Secure; SameSite=Strict")]
        return self._new_dev

    def _blocked(self):
        return self._remote() and is_blocked(self._device(), self._client_ip())

    def _cookie(self):
        m = re.search(r"(?:^|;\s*)ncc_s=([\w-]+)", self.headers.get("Cookie") or "")
        return m.group(1) if m else None

    def _authed(self):
        if not self._remote():
            return True
        if self._blocked():
            return False
        if self._public() and not settings().get("web_access"):
            return False
        return session_ok(self._cookie(), self._public())

    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body, default=str)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        for k, v in getattr(self, "_extra", []):
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._extra, self._new_dev = [], None
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        path = self.path.split("?")[0]
        q = dict(x.split("=", 1) for x in self.path.split("?", 1)[1].split("&") if "=" in x) if "?" in self.path else {}
        if path in ("/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"):
            return self._send(200, (STATIC / path.lstrip("/")).read_bytes(), "image/png")
        if not self._authed() and path not in ("/manifest.webmanifest", "/icon.svg"):
            if path.startswith("/api/"):
                return self._send(401, {"error": "sign in"})
            mode = ("web" if settings().get("web_access") and web_users() else "off") if self._public() else "pin"
            if self._blocked():
                mode = "blocked"
            if mode != "pin" and self._remote():  # why a visitor got the web sign-in instead of the PIN (no names or cookies)
                why = ("came through Funnel (public internet)" if self.headers.get("Tailscale-Funnel-Request")
                       else "no Tailscale user header" if not self.headers.get("Tailscale-User-Login") else "address not on Tailscale")
                ua = re.sub(r"[^\w ./();,-]", "", (self.headers.get("User-Agent") or "")[:70])
                log_once(("login", self._client_ip()), f"login page: {mode} for {self._client_ip()} ({ua or 'unknown browser'}) - {why}")
            page = (STATIC / "login.html").read_text().replace("__CSRF__", CSRF).replace("__MODE__", mode).replace("__LEAD__", {
                "pin": "Enter your PIN", "web": "Sign in with your username and password",
                "off": "Web access is turned off. It can be turned on from the laptop or a Tailscale device (Security tab).",
                "blocked": "This device is blocked from signing in."}[mode])
            return self._send(200, page, "text/html; charset=utf-8")
        if path in ("/", "/index.html"):
            page = (STATIC / "index.html").read_text().replace("__CSRF__", CSRF).replace("__STYLE__", CFG["STYLE"] if CFG["STYLE"] in ("scifi", "hacker", "clean") else "scifi")
            return self._send(200, page, "text/html; charset=utf-8")
        if path in ("/wall", "/tv"):
            return self._send(200, (STATIC / "wall.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/api/live":
            return self._sse()
        if path in ("/manifest.webmanifest", "/icon.svg"):
            f = STATIC / path.lstrip("/")
            return self._send(200, f.read_bytes(), "application/manifest+json" if path.endswith("manifest") else "image/svg+xml")
        if path == "/api/health":
            age = time.time() - (STATE["last"].get("ts") or STATE["started"])
            return self._send(200 if age < 3 * int(CFG["INTERVAL"]) else 503, {"ok": age < 3 * int(CFG["INTERVAL"]), "age": round(age), "version": VERSION})
        if path == "/api/status":
            return self._send(200, status_body())
        if path == "/api/ai":
            return self._send(200, {"assistant": ai_assistant(), "names": AI_TOOLS, "local": not self._remote(),
                                    "installed": {k: bool(ai_exe(k)) for k in AI_TOOLS}})
        if path == "/api/ai/handoff":
            if not self._manager():
                return self._send(403, {"error": "Only on this computer or one of your own Tailscale devices."})
            return self._send(200, {"text": ai_handoff(status_body())})
        if path == "/api/history":
            hrs = min(720, max(1, int(q.get("hours", "24"))))
            return self._send(200, history(hrs))
        if path == "/api/devices":
            return self._send(200, {"devices": STATE["devices"], "meta": STATE.get("device_meta"), "blocked": BLOCKED,
                                    "can_block": isinstance(PIHOLE, PiHole) and CFG["PIHOLE_BLOCK"] == "1"})
        if path == "/api/pihole/domains":
            if not PIHOLE:
                return self._send(404, {"error": "Pi-hole not configured"})
            try:
                return self._send(200, {"domains": PIHOLE.domains(), "editable": CFG["PIHOLE_LISTS"] == "1"})
            except Exception as e:
                return self._send(502, {"error": type(e).__name__})
        if path == "/api/readme":
            return self._send(200, (BASE / "README.md").read_text(), "text/plain; charset=utf-8")
        if path == "/api/blocker/setup":
            return self._send(200, blocker_setup())
        if path == "/api/remote":
            st = remote_status()
            st["you_are_remote"] = self._remote()
            st["you_are_web"] = self._public()
            st["you_role"] = session_role(self._cookie()) if self._remote() else "edit"
            st["you_manage"] = self._manager()
            st["rdp"] = {"on": CFG["REMOTE_DESKTOP"] == "1", "user": CFG["RDP_USER"], "lan_ip": local_iface().get("ip")}
            if self._manager():  # account names and lock state: the laptop, or your own Tailscale devices with the PIN
                st.update({"web_users": [{"user": k, "created": v.get("created"), "role": v.get("role", "edit"),
                                          "emails": v.get("emails") or []}
                                         for k, v in sorted(web_users().items())],
                           "web_access": settings().get("web_access"), "sessions": list_sessions(),
                           "blocked": [{"label": b.get("label"), "ip": b.get("ip"), "dev": bool(b.get("dev")), "at": b.get("at")}
                                       for b in blocked_list()],
                           "web_session_h": settings()["web_session_h"], "pin_session_h": settings()["pin_session_h"],
                           "session_hours": SESSION_HOURS,
                           "web_locked": len([t for t in WEB_FAILS if time.time() - t < WEB_LOCK_S]) >= 5})
            return self._send(200, st)
        if path == "/api/usage":
            return self._send(200, usage_report())
        if path == "/api/sites":
            return self._send(200, {"sites": [{**s, **{k: v for k, v in SITE_STATE.get(s["url"], {}).items()
                                                      if k in ("ok", "ms", "code", "error", "ts")}} for s in sites()],
                                     "slow_ms": settings().get("site_slow_ms") or 0,
                                     "interval_min": settings().get("site_interval_min", 5)})
        if path == "/api/wifi":
            return self._send(200, wifi_neighbors(q.get("rescan") == "1"))
        if path == "/api/report/weekly":
            return self._send(200, {"text": weekly_report_text()})
        if path == "/api/settings":
            return self._send(200, {**settings(), "live_periods": LIVE_PERIODS, "speed_every": SPEED_EVERY})
        if path == "/api/alerts":
            u = ntfy_url()
            m = re.match(r"(https?://[^/]+)/([\w-]+)$", u)
            return self._send(200, {"configured": bool(m), "server": m.group(1) if m else None,
                                    "topic": m.group(2) if m else None, "emails": [mask_email(e) for e in alert_emails()],
                                    "gmail": mask_email((smtp_conf() or {}).get("user", "")) or None, "remote": self._remote()})
        if path == "/api/outages":
            return self._send(200, outage_report(30))
        if path == "/api/speedtest":
            return self._send(200, speed_history(30))
        if path == "/api/pihole/blocked_by_device":
            try:
                return self._send(200, blocked_by_device())
            except Exception as e:
                return self._send(502, {"clients": [], "error": type(e).__name__})
        if path == "/api/makers":
            return self._send(200, maker_search(urllib.request.unquote(q.get("q", ""))))
        if path == "/api/oui":
            return self._send(200, oui_lookup(urllib.request.unquote(q.get("p", ""))))
        if path == "/api/pihole/search":
            try:
                dom, _ = norm_domain(urllib.request.unquote(q.get("d", "")))
                return self._send(200, {"domain": dom, "blocked_now": answers_blocked(dom), **PIHOLE.search(dom)})
            except ValueError as e:
                return self._send(400, {"error": str(e)})
        if path == "/api/events":
            with db() as c:
                return self._send(200, [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100")])
        self._send(404, {"error": "not found"})

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        with LIVE_COND:
            LIVE["clients"] += 1
            LIVE_COND.notify_all()
            seq, kick = LIVE["seq"], LIVE["kick"]
        try:
            if LIVE["frame"]:
                self.wfile.write(f"data: {json.dumps(LIVE['frame'], default=str)}\n\n".encode())
                self.wfile.flush()
            while not STOP.is_set():
                with LIVE_COND:
                    LIVE_COND.wait_for(lambda: LIVE["seq"] != seq or LIVE["kick"] != kick or STOP.is_set(), timeout=15)
                    changed, seq, frame, kick = LIVE["seq"] != seq, LIVE["seq"], LIVE["frame"], LIVE["kick"]
                if self._remote() and not self._authed():  # signed out (or web access turned off) while watching
                    self.wfile.write(b"event: signout\ndata: {}\n\n")
                    self.wfile.flush()
                    break
                msg = f"data: {json.dumps(frame, default=str)}\n\n" if changed else ": keepalive\n\n"
                self.wfile.write(msg.encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with LIVE_COND:
                LIVE["clients"] -= 1

    def do_POST(self):
        self._extra, self._new_dev = [], None
        if not self._host_ok() or self.headers.get("X-NCC-Token") != CSRF:
            if self._remote():
                log_once(("refused", self._client_ip()), f"POST {self.path.split('?')[0]} refused from {self._client_ip()}: "
                         + ("wrong host" if not self._host_ok() else "missing/old page token") + " (once an hour per address)")
            return self._send(403, {"error": "forbidden"})
        if self.path.startswith("/api/web/login"):
            log(f"POST {self.path} from {self._client_ip()}")
        if self.path in ("/api/web/login", "/api/web/login/code", "/api/web/login/resend", "/api/remote/login") and self._blocked():
            return self._send(403, {"error": "This device is blocked from signing in."})
        if self.path == "/api/web/login":
            if not self._public():
                return self._send(403, {"error": "Use your PIN on Tailscale devices."})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                b = json.loads(self.rfile.read(min(n, 4096)) or b"{}")
                ua = re.sub(r"[^\w ./();,-]", "", (self.headers.get("User-Agent") or "")[:60])
                pending, to = check_web_login(b.get("user"), b.get("password"),
                                              f"{self._client_ip() or 'unknown'} ({ua or 'unknown browser'})",
                                              {"ip": self._client_ip(), "ua": ua, "dev": self._device()})
            except PermissionError as e:
                return self._send(403, {"error": str(e)})
            except (ValueError, AttributeError):
                return self._send(400, {"error": "bad request"})
            return self._send(200, {"step": "code", "pending": pending, "to": to})
        if self.path in ("/api/web/login/code", "/api/web/login/resend"):
            if not self._public():
                return self._send(403, {"error": "Use your PIN on Tailscale devices."})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                b = json.loads(self.rfile.read(min(n, 4096)) or b"{}")
                if self.path.endswith("resend"):
                    return self._send(200, {"ok": True, "to": resend_web_code(b.get("pending"))})
                tok = check_web_code(b.get("pending"), b.get("code"))
            except PermissionError as e:
                return self._send(403, {"error": str(e)})
            except (ValueError, AttributeError):
                return self._send(400, {"error": "bad request"})
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", f"ncc_s={tok}; Path=/; Max-Age={session_length('web')}; HttpOnly; Secure; SameSite=Strict")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/remote/login":
            if self._public():
                return self._send(403, {"error": "Sign in with your username and password."})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                ua = re.sub(r"[^\w ./();,-]", "", (self.headers.get("User-Agent") or "")[:60])
                tok = check_pin(json.loads(self.rfile.read(min(n, 4096)) or b"{}").get("pin"),
                                {"ip": self._client_ip(), "ua": ua, "tsuser": self.headers.get("Tailscale-User-Login"),
                                 "dev": self._device()})
            except PermissionError as e:
                return self._send(403, {"error": str(e)})
            except ValueError:
                return self._send(400, {"error": "bad request"})
            event("info", "remote", f"Remote sign-in from {self.headers.get('Tailscale-User-Login') or 'Tailscale device'}.", False)
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", f"ncc_s={tok}; Path=/; Max-Age={session_length('pin')}; HttpOnly; Secure; SameSite=Strict")
            self.end_headers()
            self.wfile.write(body)
            return
        if not self._authed():
            return self._send(401, {"error": "sign in"})
        # view-only web accounts: looking things up is fine, changing anything is not
        if self._remote() and self.path.split("?")[0] not in ("/api/remote/logout", "/api/action", "/api/ask") \
                and session_role(self._cookie()) == "view":
            return self._send(403, {"error": "Your account is view only. Ask the laptop's owner if you need to change something."})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(min(n, 10000)) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        path = self.path.split("?")[0]
        try:
            if path == "/api/ask":
                question = str(body.get("question", ""))[:500]
                topic = body.get("topic")
                if topic in QUICK and not body.get("ai"):
                    return self._send(200, {"answer": rule_answer(topic), "source": "rules"})
                if body.get("ai") and ai_assistant() != "off" and not self._remote():
                    return self._send(200, {"answer": ask_ai(question), "source": ai_assistant()})
                why = ("AI answers are off. Pick your assistant in Tools & settings → AI assistant." if ai_assistant() == "off"
                       else "AI answers only work on the computer itself, so nobody else can use your AI account.")
                return self._send(200, {"answer": rule_answer("next") + (f"\n\n({why})" if body.get("ai") else ""), "source": "rules"})
            if path == "/api/action":
                return self._send(200, action(str(body.get("name")), str(body.get("arg", ""))[:255]))
            if path == "/api/remote/pin":
                if self._remote():
                    return self._send(403, {"error": "The PIN can only be changed on the laptop itself."})
                set_pin(body.get("pin"))
                return self._send(200, {"ok": True})
            if path == "/api/alerts/setup":
                if self._remote():
                    return self._send(403, {"error": "Phone alerts can only be set up on the laptop itself."})
                new_ntfy_topic()
                log("ntfy: new topic created")
                return self._send(200, {"ok": True})
            if path == "/api/web/funnel":
                if not self._manager():
                    return self._send(403, {"error": "Only on the laptop or one of your Tailscale devices (not from the open web)."})
                try:
                    st = set_funnel(body.get("on") is True)
                except RuntimeError as e:
                    return self._send(500, {"error": str(e)})
                return self._send(200, {"ok": True, "funnel": st.get("funnel")})
            if path in ("/api/sessions/block", "/api/blocked/remove"):
                if not self._manager():
                    return self._send(403, {"error": "Only on the laptop or one of your Tailscale devices (not from the open web)."})
                try:
                    if path.endswith("remove"):
                        unblock(int(body.get("n", -1)))
                    else:
                        block_session(str(body.get("id") or ""), body.get("by_ip") is not False)
                except (ValueError, TypeError) as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200, {"ok": True})
            if path == "/api/sites":
                try:
                    a = body.get("action")
                    if a == "add":
                        site_add(body.get("url"), body.get("name"))
                    elif a == "remove":
                        site_remove(str(body.get("url") or ""))
                    elif a == "check":
                        maybe_check_sites(force=True)
                    else:
                        raise ValueError("Unknown action.")
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200, {"ok": True})
            if path == "/api/report/weekly":
                try:
                    send_weekly_report()
                except RuntimeError as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200, {"ok": True})
            if path == "/api/sessions/drop":
                if not self._manager():
                    return self._send(403, {"error": "Only on the laptop or one of your Tailscale devices (not from the open web)."})
                return self._send(200, {"ok": True, "dropped": drop_session_id(str(body.get("id") or ""))})
            if path == "/api/web/unlock":
                if not self._manager():
                    return self._send(403, {"error": "Only on the laptop or one of your Tailscale devices (not from the open web)."})
                WEB_FAILS.clear()
                event("info", "web-access", "Web sign-in lock cleared from the dashboard.", False)
                return self._send(200, {"ok": True})
            if path in ("/api/web/user", "/api/web/user/remove"):
                if not self._manager():
                    return self._send(403, {"error": "Only on the laptop or one of your Tailscale devices (not from the open web)."})
                try:
                    if path.endswith("remove"):
                        remove_web_user(body.get("user"))
                    elif "password" in body:
                        set_web_user(body.get("user"), body.get("password"), body.get("role"), body.get("emails"))
                    else:
                        if "role" in body:
                            set_web_role(body.get("user"), body.get("role"))
                        if "emails" in body:
                            set_web_emails(body.get("user"), body.get("emails"))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200, {"ok": True, "users": sorted(web_users())})
            if path == "/api/settings":
                if "ai_assistant" in body and self._remote():
                    return self._send(403, {"error": "The AI assistant can only be chosen on the computer itself."})
                if not self._manager() and {"web_access", "web_session_h", "pin_session_h"} & set(body):
                    return self._send(403, {"error": "Only on the laptop or one of your Tailscale devices (not from the open web)."})
                if body.get("web_access") is True and not web_users():
                    return self._send(400, {"error": "Add at least one username and password first."})
                try:
                    s = save_settings(body)
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                log("settings changed:", ", ".join(f"{k}={s[k]}" for k in sorted(body) if k in s))
                return self._send(200, {"ok": True, **s})
            if path in ("/api/gmail", "/api/gmail/remove", "/api/gmail/test"):
                if self._remote():
                    return self._send(403, {"error": "Email sending can only be set up on the laptop itself."})
                if path == "/api/gmail/remove":
                    SMTP_FILE.unlink(missing_ok=True)
                    log("gmail: sending account removed")
                    return self._send(200, {"ok": True})
                if path == "/api/gmail/test":
                    c = smtp_conf()
                    if not c:
                        return self._send(400, {"error": "Gmail isn't set up yet."})
                    try:
                        to = alert_emails() or [c["user"]]
                        n = send_email(to, "NCC test email",
                                       "This is a test email from your Network Command Center. Email sending works!")
                    except Exception as e:
                        return self._send(502, {"error": f"Gmail refused it ({type(e).__name__})."})
                    return self._send(200, {"ok": n == len(to), "to": [mask_email(e) for e in to]})
                try:
                    user = set_smtp(str(body.get("user") or "")[:300], str(body.get("password") or "")[:200])
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                except RuntimeError as e:
                    return self._send(502, {"error": str(e)})
                log("gmail: sending account set")
                return self._send(200, {"ok": True, "gmail": mask_email(user)})
            if path == "/api/alerts/email":
                if not self._manager():
                    return self._send(403, {"error": "Alert emails can only be changed on the laptop or one of your Tailscale devices."})
                cur = alert_emails()
                try:  # {add: address} | {remove: index into the list} | {email: ""} to stop all
                    if "add" in body:
                        new = set_alert_emails(cur + [str(body.get("add") or "")[:300]])
                        if len(new) == len(cur):
                            raise ValueError("Type an email address to add (or it's already on the list).")
                    elif "remove" in body:
                        i = body.get("remove")
                        if not isinstance(i, int) or not 0 <= i < len(cur):
                            raise ValueError("That email isn't on the list any more. Reload the page.")
                        new = set_alert_emails(cur[:i] + cur[i + 1:])
                    else:
                        new = set_alert_emails([] if not body.get("email") else [str(body["email"])[:300]])
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                log(f"ntfy: alert emails changed ({len(new)})")
                return self._send(200, {"ok": True, "emails": [mask_email(e) for e in new]})
            if path == "/api/remote/logout":
                drop_session(self._cookie() or "")
                return self._send(200, {"ok": True})
            if path == "/api/alerts/test":
                if not ntfy_url():
                    return self._send(400, {"error": "Phone alerts aren't set up yet."})
                _last_notify.pop("test", None)
                sent = event("info", "test", "Test alert from your Network Command Center. Phone alerts work!", "phone")
                push, mail = sent if sent else (False, None)
                return self._send(200, {"ok": push, "email": mail})
            if path == "/api/speedtest":
                if SPEED["running"]:
                    return self._send(409, {"error": "A speed test is already running."})
                threading.Thread(target=speedtest, args=("manual",), daemon=True).start()
                return self._send(200, {"ok": True, "started": True})
            if path == "/api/system/restart":
                try:
                    return self._send(200, system_restart(body.get("what")))
                except PermissionError as e:
                    return self._send(403, {"error": str(e)})
            if path == "/api/devices/block":
                with PH_LOCK:
                    try:
                        return self._send(200, device_block(body))
                    except PermissionError as e:
                        return self._send(403, {"error": str(e)})
                    except urllib.error.HTTPError as e:
                        return self._send(502, {"error": f"Pi-hole refused the change (HTTP {e.code})."})
                    except RuntimeError as e:
                        return self._send(500, {"error": str(e)})
            if path == "/api/devices/label":
                return self._send(200, set_device(body.get("mac"), body.get("label"), body["type"] if "type" in body else False,
                                                    body["maker"] if "maker" in body else False))
            if path in ("/api/pihole/domains", "/api/pihole/restartdns"):
                if not PIHOLE or CFG["PIHOLE_LISTS"] != "1":
                    return self._send(403, {"error": "List editing is off (PIHOLE_LISTS=0 in config/ncc.env)."})
                if path == "/api/pihole/restartdns":
                    PIHOLE.restart_dns()
                    event("info", "pihole-control", "Pi-hole DNS restarted from dashboard.", False)
                    return self._send(200, {"ok": True})
                with PH_LOCK:
                    return self._send(200, pihole_list_change(body))
            if path == "/api/pihole/blocking":
                if not PIHOLE or CFG["PIHOLE_CONTROLS"] != "1":
                    return self._send(403, {"error": "Pi-hole controls are disabled (PIHOLE_CONTROLS=0)."})
                enable = bool(body.get("enable"))
                secs = body.get("seconds")
                secs = None if enable else min(3600, max(30, int(secs or 300)))
                r = PIHOLE.set_blocking(enable, secs)
                event("info", "pihole-control", f"Pi-hole blocking {'enabled' if enable else f'disabled for {secs}s'} from dashboard.", False)
                return self._send(200, {"ok": True, "result": r})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": type(e).__name__})
        self._send(404, {"error": "not found"})


def main():
    init_db()
    threading.Thread(target=loop, daemon=True).start()
    threading.Thread(target=live_loop, daemon=True).start()
    srv = ThreadingHTTPServer((CFG["BIND"], int(CFG["PORT"])), H)
    srv.daemon_threads = True

    def on_term(*_):
        # systemd reports "stopping" only when the whole computer is shutting down or rebooting
        state = "" if WIN else run(["systemctl", "is-system-running"], 3)[1]
        if "stopping" in state:
            event("warn", "laptop-off", "The laptop is shutting down or restarting. The Wi-Fi keeps working, but ads "
                  "won't be blocked and new devices can't join until it's back.", "phone")
        STOP.set()
        threading.Thread(target=srv.shutdown).start()
    signal.signal(signal.SIGTERM, on_term)
    log(f"NCC listening on http://{CFG['BIND']}:{CFG['PORT']}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
