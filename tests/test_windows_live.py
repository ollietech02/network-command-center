"""Runs the Windows readings for real (Windows only): every function must return sensible values.
Run: python -X utf8 -I tests\\test_windows_live.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
import ncc_win as W  # noqa: E402

FAILS = []


def check(name, ok, got):
    print(f"{'ok  ' if ok else 'FAIL'} {name}: {got!r}"[:300])
    if not ok:
        FAILS.append(name)


i = W.iface(0)
check("iface", bool(i.get("ip") and i.get("dev") and i.get("subnet")), i)
check("gateway", bool(i.get("gateway")), i.get("gateway"))
p = W.ping("127.0.0.1", 2, 1)
check("ping localhost", p["ok"] and p["loss"] == 0, p)
d = W.dns_a("example.com", "1.1.1.1")
check("dns 1.1.1.1", d["ok"] and d["ips"], d)
check("system dns server", bool(W.system_dns()), W.system_dns())
idle, total = W.cpu_times()
check("cpu times", 0 < idle < total, (idle, total))
m = W.meminfo()
check("memory", 0 < m["MemAvailable"] < m["MemTotal"] and m["SwapFree"] <= m["SwapTotal"], m)
check("uptime", W.uptime() > 10, W.uptime())
check("battery (None on servers)", W.battery() is None or 0 <= W.battery()["pct"] <= 100, W.battery())
check("own memory", 5_000_000 < W.own_rss() < 500_000_000, W.own_rss())
n1 = W.net_dev(i.get("dev"))
check("network counters", n1 is not None and n1[0] >= 0, n1)
nb = W.neighbors()
check("neighbors", isinstance(nb, list) and all(":" in x["lladdr"] for x in nb), nb[:3])
ls = W.listeners()
check("listening ports", any(x.endswith(":135") or x.endswith(":445") for x in ls), ls[:8])
pr = W.processes()
check("processes", any(n.lower().startswith("python") for n, _ in pr), pr[:5])
nets, note = W.wifi()
check("wifi (servers have none: a note instead)", bool(nets) or bool(note), (nets[:2], note))
tr = W.trace("127.0.0.1")
check("tracert", "127.0.0.1" in tr, tr[-120:])

if FAILS:
    print("FAILED:", ", ".join(FAILS))
    sys.exit(1)
print("all Windows checks passed")
