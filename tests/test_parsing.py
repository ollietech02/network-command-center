"""Checks that run anywhere (Linux or Windows): the health report's redaction and the Windows output parsers,
fed with sample output from English and German Windows. Run: python3 -I tests/test_parsing.py"""
import ctypes
import os
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP))
if os.name != "nt":  # let ncc_win import on Linux: the system calls are never made in these tests
    class _F:
        restype = argtypes = None

        def __call__(self, *a, **k):
            return 0

    class _DLL:
        def __getattr__(self, n):
            return _F()
    ctypes.WinDLL = lambda *a, **k: _DLL()
import doctor  # noqa: E402
import ncc_win as W  # noqa: E402

FAILS = []


def check(name, got, want):
    if got != want:
        FAILS.append(f"{name}: got {got!r}, want {want!r}")


# ---- redaction
R = doctor.redact
check("password", R("PIHOLE_PASSWORD=abc123 x"), "PIHOLE_PASSWORD=[removed] x")
check("ping kept", R("Ping to 1.1.1.1: 12 ms"), "Ping to 1.1.1.1: 12 ms")
check("email", R("sent to someone@example.com"), "sent to [email removed]")
check("ntfy", R("https://ntfy.sh/secret-topic-1 ok"), "https://ntfy.sh/[topic removed] ok")
check("tailnet", R("open https://mypc.tail1234.ts.net"), "open https://[this computer].[tailnet].ts.net")
check("bearer", R("Authorization: Bearer abcdefghijkl"), "Authorization: Bearer [removed]")
check("public v4", R("login from 104.37.27.64"), "login from [internet address]")
check("public v6", R("from 2600:1700:1990:aaa0:2484:9b25:66c9:c8df x"), "from [internet address] x")
check("private kept", R("gateway 192.168.1.254, tailscale 100.71.148.1"), "gateway 192.168.1.254, tailscale 100.71.148.1")
check("time kept", R("at 10:55:25"), "at 10:55:25")

# ---- Windows ping (reply lines always contain TTL= and <n>ms, whatever the language)
PINGS = {
    "en": ("Reply from 1.1.1.1: bytes=32 time=12ms TTL=57\nReply from 1.1.1.1: bytes=32 time=14ms TTL=57\nRequest timed out.\n",
           {"ok": True, "loss": 33.3, "ms": 13.0}),
    "de": ("Antwort von 192.168.1.254: Bytes=32 Zeit<1ms TTL=64\nAntwort von 192.168.1.254: Bytes=32 Zeit=2ms TTL=64\n"
           "Antwort von 192.168.1.254: Bytes=32 Zeit=3ms TTL=64\n", {"ok": True, "loss": 0.0, "ms": 2.0}),
    "unreachable": ("Reply from 192.168.1.37: Destination host unreachable.\n" * 3, {"ok": False, "loss": 100.0, "ms": None}),
}
real_run = W.run
for k, (out, want) in PINGS.items():
    W.run = lambda cmd, timeout=10, env=None, o=out: (0, o)
    check("ping " + k, W.ping("x", 3, 1), want)

# ---- tasklist (any thousands separator)
W.run = lambda cmd, timeout=10, env=None: (0, '"chrome.exe","1","Console","1","215,332 K"\n"pythonw.exe","5","Console","1","48 520 K"\n'
                                              '"x.exe","6","Console","1","1.024 K"\n')
check("tasklist", W.processes(), [("chrome", 215332), ("pythonw", 48520), ("x", 1024)])

# ---- netsh Wi-Fi list (English and German keys)
NETS = """
SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 88%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36
         Bss Load:
             Connected Stations:        3
    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 70%
         Channel            : 6

SSID 2 : Nachbar
    Netzwerktyp             : Infrastruktur
    Authentifizierung       : WPA3-Personal
    BSSID 1                 : 77:88:99:aa:bb:cc
         Signal             : 41%
         Band               : 6 GHz
         Kanal              : 37
"""
ME = "    SSID                   : HomeNet\n    BSSID                  : aa:bb:cc:dd:ee:01\n"
W.run = lambda cmd, timeout=10, env=None: (0, NETS if "networks" in cmd else ME)
nets, note = W.wifi()
check("wifi count", len(nets), 3)
check("wifi mine", [n["mine"] for n in nets], [True, False, False])
check("wifi bands", [n["band"] for n in nets], ["5 GHz", "2.4 GHz", "6 GHz"])
check("wifi channels", [n["channel"] for n in nets], [36, 6, 37])
check("wifi security", nets[2]["security"], "WPA3-Personal")
W.run = lambda cmd, timeout=10, env=None: (1, "Network shell commands need location permission to access WLAN information.")
check("wifi location note", "Location" in (W.wifi()[1] or ""), True)
W.run = real_run

if FAILS:
    print("FAILED:\n  " + "\n  ".join(FAILS))
    sys.exit(1)
print("all parsing checks passed")
