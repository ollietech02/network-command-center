"""Windows versions of the few things ncc.py reads from Linux (/proc, ip, nmcli, ss...).

Standard library only: ctypes for the system counters, and short fixed PowerShell / netsh / tasklist
commands for the rest. No user input ever reaches a command line. Imported by ncc.py only on Windows.
"""
import ctypes
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import threading
import time
from ctypes import wintypes

NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW: the dashboard runs without a console, so don't flash one per command
PS = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]
TASK = "Network Command Center"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
iphlp = ctypes.WinDLL("iphlpapi")


def run(cmd, timeout=10, env=None):
    try:
        # PowerShell is told to print UTF-8; ping, netsh and tasklist print in the console's own code page
        enc = "utf-8" if cmd[0].lower().startswith("powershell") else "oem"
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=NO_WINDOW,
                           env=env, encoding=enc, errors="replace")
        return p.returncode, p.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return -1, ""


def ps_json(script, timeout=20):
    """Run a fixed PowerShell snippet that ends in ConvertTo-Json; always returns a list."""
    code, out = run(PS + ["[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script], timeout)
    try:
        v = json.loads(out) if out.strip() else []
    except ValueError:
        return []
    return v if isinstance(v, list) else [v]


# ---------------------------------------------------------------- network interface (cached: PowerShell is slow to start)
_IF = {"ts": 0, "v": {}}
_IF_LOCK = threading.Lock()
_IF_PS = r"""
$r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' } |
     Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
if ($r) {
  $a = Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  $i = Get-NetIPInterface -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
  $d = (Get-DnsClientServerAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
  $p = Get-NetConnectionProfile -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1
  [pscustomobject]@{dev=[string]$r.ifIndex; alias=$r.InterfaceAlias; gw=$r.NextHop; ip=$a.IPAddress; prefix=$a.PrefixLength;
                    dhcp=[string]$i.Dhcp; dns=@($d); category=[string]$p.NetworkCategory} | ConvertTo-Json -Compress
}
"""


def iface(max_age=60):
    with _IF_LOCK:
        if time.time() - _IF["ts"] < max_age and _IF["v"]:
            return _IF["v"]
        v = {}
        for x in ps_json(_IF_PS):
            try:
                net = ipaddress.ip_network(f"{x['ip']}/{x['prefix']}", strict=False)
                v = {"dev": x["dev"], "ip": x["ip"], "subnet": str(net), "gateway": x.get("gw"), "alias": x.get("alias"),
                     "dhcp": (x.get("dhcp") or "").lower() == "enabled", "dns": [d for d in (x.get("dns") or []) if d],
                     "category": x.get("category")}
            except (KeyError, ValueError, TypeError):
                pass
        _IF.update(ts=time.time() if v else time.time() - max_age + 10, v=v)  # retry sooner after a failure
        return v


def ping(host, count=3, timeout=1):
    # Windows ping's words are translated, but every reply line contains "TTL=" and "<n>ms"
    code, out = run(["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host], count * (timeout + 1) + 5)
    replies = [l for l in out.splitlines() if "TTL=" in l.upper()]
    ms = [float(m.group(1)) for l in replies for m in [re.search(r"[=<]\s*([\d.]+)\s*ms", l)] if m]
    return {"ok": bool(replies), "loss": round(100.0 * (count - len(replies)) / count, 1),
            "ms": round(sum(ms) / len(ms), 1) if ms else None}


# ---------------------------------------------------------------- DNS (Windows has no dig: a tiny A-record lookup)
def _qname(name):
    out = b""
    for part in name.rstrip(".").split("."):
        b = part.encode("idna")
        if not 0 < len(b) < 64:
            raise ValueError("bad name")
        out += bytes([len(b)]) + b
    return out + b"\0"


def _skip_name(buf, i):
    while True:
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def dns_a(name, server, timeout=2.0):
    """Ask one DNS server for A records. Returns {"ok", "ms", "ips", "answered"}; ok=False on timeout/error."""
    qid = secrets.randbits(16)
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _qname(name) + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t = time.monotonic()
    try:
        s.sendto(pkt, (server, 53))
        while True:
            buf, _ = s.recvfrom(2048)
            if len(buf) >= 12 and struct.unpack(">H", buf[:2])[0] == qid:
                break
        ms = round((time.monotonic() - t) * 1000, 1)
        flags, qd, an = struct.unpack(">HHH", buf[2:8])
        i = 12
        for _ in range(qd):
            i = _skip_name(buf, i) + 4
        ips, answered = [], False
        for _ in range(an):
            i = _skip_name(buf, i)
            typ, _cls, _ttl, ln = struct.unpack(">HHIH", buf[i:i + 10])
            i += 10
            if typ == 1 and ln == 4:
                ips.append(socket.inet_ntoa(buf[i:i + 4]))
            if typ in (1, 5):
                answered = True
            i += ln
        return {"ok": flags & 0xF == 0 and answered, "ms": ms, "ips": ips, "answered": answered}
    except (OSError, ValueError, struct.error, IndexError):
        return {"ok": False, "ms": None, "ips": [], "answered": False}
    finally:
        s.close()


def system_dns():
    d = iface().get("dns") or []
    return d[0] if d else None


# ---------------------------------------------------------------- system counters (ctypes)
class FILETIME(ctypes.Structure):
    _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]


def _ft(f):
    return (f.hi << 32) | f.lo


def cpu_times():
    """(idle, total) in 100 ns ticks, like the first line of /proc/stat."""
    idle, kern, user = FILETIME(), FILETIME(), FILETIME()
    k32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user))
    return _ft(idle), _ft(kern) + _ft(user)  # kernel time already includes idle


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD), ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def meminfo():
    """Same keys ncc.py reads from /proc/meminfo. 'Swap' is the page file: commit limit minus RAM."""
    m = MEMORYSTATUSEX()
    m.dwLength = ctypes.sizeof(m)
    k32.GlobalMemoryStatusEx(ctypes.byref(m))
    swap = max(0, m.ullTotalPageFile - m.ullTotalPhys)
    used = max(0, (m.ullTotalPageFile - m.ullAvailPageFile) - (m.ullTotalPhys - m.ullAvailPhys))
    return {"MemTotal": m.ullTotalPhys, "MemAvailable": m.ullAvailPhys, "SwapTotal": swap, "SwapFree": max(0, swap - used)}


k32.GetTickCount64.restype = ctypes.c_ulonglong


def uptime():
    return k32.GetTickCount64() / 1000.0


class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte), ("BatteryLifePercent", ctypes.c_ubyte),
                ("SystemStatusFlag", ctypes.c_ubyte), ("BatteryLifeTime", wintypes.DWORD), ("BatteryFullLifeTime", wintypes.DWORD)]


def battery():
    s = SYSTEM_POWER_STATUS()
    if not k32.GetSystemPowerStatus(ctypes.byref(s)) or s.BatteryFlag & 128 or s.BatteryFlag == 255 or s.BatteryLifePercent > 100:
        return None  # desktop PC, or unknown
    status = "Charging" if s.BatteryFlag & 8 else ("Full" if s.BatteryLifePercent >= 99 else "Not charging") if s.ACLineStatus == 1 else "Discharging"
    return {"pct": int(s.BatteryLifePercent), "status": status}


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + \
               [(n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                               "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                                               "PagefileUsage", "PeakPagefileUsage")]


k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]


def own_rss():
    c = PROCESS_MEMORY_COUNTERS()
    c.cb = ctypes.sizeof(c)
    k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb)
    return int(c.WorkingSetSize)


class MIB_IFROW(ctypes.Structure):
    _fields_ = [("wszName", ctypes.c_wchar * 256), ("dwIndex", wintypes.DWORD), ("dwType", wintypes.DWORD),
                ("dwMtu", wintypes.DWORD), ("dwSpeed", wintypes.DWORD), ("dwPhysAddrLen", wintypes.DWORD),
                ("bPhysAddr", ctypes.c_ubyte * 8), ("dwAdminStatus", wintypes.DWORD), ("dwOperStatus", wintypes.DWORD),
                ("dwLastChange", wintypes.DWORD), ("dwInOctets", wintypes.DWORD), ("dwInUcastPkts", wintypes.DWORD),
                ("dwInNUcastPkts", wintypes.DWORD), ("dwInDiscards", wintypes.DWORD), ("dwInErrors", wintypes.DWORD),
                ("dwInUnknownProtos", wintypes.DWORD), ("dwOutOctets", wintypes.DWORD), ("dwOutUcastPkts", wintypes.DWORD),
                ("dwOutNUcastPkts", wintypes.DWORD), ("dwOutDiscards", wintypes.DWORD), ("dwOutErrors", wintypes.DWORD),
                ("dwOutQLen", wintypes.DWORD), ("dwDescrLen", wintypes.DWORD), ("bDescr", ctypes.c_ubyte * 256)]


_oct = {}


def net_dev(dev):
    """(rx_bytes, tx_bytes) for one interface index. The Windows counters are 32-bit, so count the wraps."""
    try:
        row = MIB_IFROW()
        row.dwIndex = int(dev)
        if iphlp.GetIfEntry(ctypes.byref(row)) != 0:
            return None
    except (ValueError, OSError):
        return None
    prev = _oct.get(dev)
    rx, tx = row.dwInOctets, row.dwOutOctets
    if prev:
        rx += prev[2] + (1 << 32 if rx < prev[0] else 0)
        tx += prev[3] + (1 << 32 if tx < prev[1] else 0)
        base_rx, base_tx = rx - row.dwInOctets, tx - row.dwOutOctets
    else:
        base_rx = base_tx = 0
    _oct[dev] = (row.dwInOctets, row.dwOutOctets, base_rx, base_tx)
    return rx, tx


# ---------------------------------------------------------------- devices, ports, processes, Wi-Fi
def neighbors():
    """Like `ip -j neigh`: [{dst, lladdr, state:[...]}] from Windows' neighbor table (state names aren't translated)."""
    out = []
    for n in ps_json("Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                     "Where-Object { $_.State -ne 'Unreachable' -and $_.State -ne 'Permanent' } | "
                     "Select-Object IPAddress,LinkLayerAddress,@{n='State';e={[string]$_.State}} | ConvertTo-Json -Compress"):
        mac = (n.get("LinkLayerAddress") or "").replace("-", ":").lower()
        ip = n.get("IPAddress") or ""
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or mac.startswith("01:00:5e") or ip.endswith(".255"):
            continue
        out.append({"dst": ip, "lladdr": mac, "state": [(n.get("State") or "").upper()]})
    return out


def listeners():
    """Listening TCP addresses like `ss -tln` prints them: 0.0.0.0:135, [::]:445, 127.0.0.1:8088."""
    out = set()
    for c in ps_json("Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
                     "Select-Object LocalAddress,LocalPort | ConvertTo-Json -Compress"):
        a, p = c.get("LocalAddress") or "", c.get("LocalPort")
        if a and p is not None:
            out.add(f"[{a}]:{p}" if ":" in a else f"{a}:{p}")
    return sorted(out)


def processes():
    """[(name, KiB)] from tasklist (memory column: digits only, so any thousands separator works)."""
    _, out = run(["tasklist", "/fo", "csv", "/nh"], 15)
    rows = []
    for line in out.splitlines():
        f = re.findall(r'"([^"]*)"', line)
        if len(f) >= 5:
            kb = re.sub(r"\D", "", f[4])
            if kb:
                rows.append((re.sub(r"\.exe$", "", f[0], flags=re.I), int(kb)))
    return rows


def wifi():
    """Nearby Wi-Fi from `netsh wlan`. Keys are translated on non-English Windows, so read by shape, not by word."""
    code, out = run(["netsh", "wlan", "show", "networks", "mode=bssid"], 20)
    _, me = run(["netsh", "wlan", "show", "interfaces"], 10)
    my_bssid = next((m.group(1).lower() for m in re.finditer(r"^\s*BSSID\s*:\s*([0-9a-fA-F:]{17})", me, re.M)), None)
    nets, ssid, sec, cur = [], None, "", None
    for line in out.splitlines():
        m = re.match(r"^SSID \d+\s*:\s?(.*)$", line)
        if m:
            ssid, sec, cur, fields = m.group(1).strip(), "", None, 0
            continue
        if ssid is None:
            continue
        m = re.match(r"^\s+BSSID \d+\s*:\s*([0-9a-fA-F:]{17})", line)
        if m:
            cur = {"bssid": m.group(1).lower(), "ssid": ssid or "(hidden network)", "signal": None, "channel": None,
                   "band": None, "security": sec or "unknown"}
            nets.append(cur)
            continue
        kv = re.match(r"^\s+[^:]+?\s*:\s*(.*)$", line)
        if not kv:
            continue
        val = kv.group(1).strip()
        if cur is None:
            fields += 1
            if fields == 2:  # Network type, then Authentication
                sec = val
            continue
        if cur["signal"] is None and re.fullmatch(r"\d+%", val):
            cur["signal"] = int(val[:-1])
        elif cur["signal"] is not None and cur["channel"] is None and re.fullmatch(r"\d{1,3}", val):
            cur["channel"] = int(val)
        elif re.fullmatch(r"(2[.,]4|5|6)\s*GHz", val):
            cur["band"] = val.replace(",", ".").replace(" ", "").replace("GHz", " GHz")
    res = []
    for n in nets:
        if n["signal"] is None or n["channel"] is None:
            continue
        n["band"] = n["band"] or ("2.4 GHz" if n["channel"] <= 14 else "5 GHz")
        n["mine"] = bool(my_bssid) and n.pop("bssid") == my_bssid
        n.pop("bssid", None)
        res.append(n)
    note = None
    if not res:
        note = ("Windows didn't share the Wi-Fi list. On Windows 11, turn on Settings → Privacy & security → Location "
                "(and 'Let desktop apps access your location'), then scan again." if re.search(r"location|wlanapi|denied", out + me, re.I)
                else "No Wi-Fi networks found (this computer may be on a cable, or Wi-Fi is off).")
    return res, note


# ---------------------------------------------------------------- notifications and restarts
_TOAST = r"""
$t=[Security.SecurityElement]::Escape($env:NCC_T); $m=[Security.SecurityElement]::Escape($env:NCC_M)
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime] | Out-Null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))
"""


def notify(title, msg):
    """A Windows notification. The text travels in environment variables, never inside the command."""
    env = dict(os.environ, NCC_T=title[:200], NCC_M=msg[:600])
    threading.Thread(target=run, args=(PS + [_TOAST], 20, env), daemon=True).start()


def restart_self():
    """Ask Task Scheduler to start the dashboard again in a few seconds, then exit this copy."""
    subprocess.Popen(PS + [f"Start-Sleep 4; Start-ScheduledTask -TaskName '{TASK}'"], creationflags=NO_WINDOW | 0x00000008,
                     close_fds=True)  # 0x8 = DETACHED_PROCESS: keeps running after we exit
    threading.Timer(1, lambda: os._exit(0)).start()


def reboot():
    subprocess.Popen(["shutdown", "/r", "/t", "5", "/c", "Network Command Center: restart requested from the dashboard"],
                     creationflags=NO_WINDOW)


def trace(host):
    _, out = run(["tracert", "-d", "-h", "15", "-w", "1000", host], 60)
    return out
