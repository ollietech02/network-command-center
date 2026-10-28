# AGENTS.md: guide for AI assistants

You are helping someone with **Network Command Center (NCC)**, a home network dashboard that runs on their own
computer (Linux or Windows). They are probably not a programmer: explain things in plain words, one step at a time.
This file tells you how the project works, how to check on it, how to fix common problems, and the rules to follow.

## Rules (always follow these)

1. **Start by looking, not changing.** Run the health report first (`./ncc doctor` on Linux, `ncc doctor` on Windows,
   from the dashboard folder). It's read-only and has passwords removed.
2. **Ask before changing anything** outside this folder, and say what it does and how to undo it. That includes:
   DNS settings, the router, Wi-Fi, the firewall, the ad blocker's settings or lists, installing or removing programs,
   system services, power settings and user accounts. Never change router settings yourself; give the person the steps.
3. **Never show, print, copy or send secrets.** They live in `~/.config/ncc/secrets.env` (Windows:
   `%USERPROFILE%\.config\ncc\secrets.env`) and in `data/.smtp`, `data/.ntfy`, `data/.web_logins`, `data/.remote_pin`,
   `data/.sessions`, `data/.csrf`, and `~/remote-login.txt`. You may check whether a key *exists* (e.g. `grep -c '^PIHOLE_PASSWORD=' file`),
   never its value. Don't paste log lines with email addresses or internet addresses into anything public.
4. **Don't open anything to the internet.** No router port forwarding, no turning on Tailscale Funnel ("web access"),
   no binding the dashboard to anything but `127.0.0.1`, unless the person clearly asks and understands it.
5. **Don't delete** their data (`data/`, `config/ncc.env`, backups) or uninstall anything without asking. Before editing
   a file, make a copy (`./ncc backup` backs up everything).
6. **Don't block devices or call a device dangerous** because it's unknown. Phones use random private addresses, so
   "new device" alerts are usually a phone.
7. **Only scan or test their own network.** Never other people's.
8. If something costs money (a paid service or account), explain and ask first.

## What it is

- One Python program, standard library only (no pip packages): `app/ncc.py`. It checks the internet every minute
  (ping, a website, DNS), lists devices on the network, talks to the ad blocker, runs speed tests, sends alerts, and
  serves the web page `app/static/index.html` at **http://127.0.0.1:8088** (only this computer can open it).
- Optional extras the installer can add: **Pi-hole** (Linux) or **AdGuard Home** (Linux/Windows) to block ads for every
  device, **Tailscale** to open the dashboard from a phone anywhere (privately), and **remote desktop**.
- Python 3.9 or newer. On Linux it runs as a systemd *user* service `ncc.service`; on Windows as a Task Scheduler task
  named "Network Command Center" (`pythonw -X utf8 -I app\ncc.py`) that starts when the person signs in.

## Files

| Path | What it is |
|---|---|
| `app/ncc.py` | The whole dashboard: checks, database, alerts, ad blocker adapters (`PiHole`, `AdGuardHome`), web server and API |
| `app/ncc_win.py` | Windows versions of the Linux-only parts (system counters, network, devices, Wi-Fi, notifications) |
| `app/doctor.py` | The read-only health report (`ncc doctor`) and the redaction used by "Copy for my AI" |
| `app/static/index.html` | The web page (HTML, CSS and JavaScript in one file); `wall.html` is the TV/wall view |
| `config/ncc.env` | Settings (`config/ncc.env.example` explains each one). Restart after changing it |
| `data/ncc.db` | SQLite history (checks, devices, events, speed tests). `data/ncc.log` on Windows is the log |
| `ncc` / `ncc.cmd` | Control script (Linux / Windows) |
| `install/install.sh`, `install/lib/*.sh` | Linux installer (Debian family: Ubuntu, Debian, Mint, Raspberry Pi OS) |
| `install-windows.cmd`, `install/windows/*.ps1` | Windows installer; `admin.ps1` holds every step that needs administrator rights |

## Commands (run from the dashboard folder)

| Linux | Windows | Does |
|---|---|---|
| `./ncc doctor` | `ncc doctor` | Health report (read-only, safe to share) |
| `./ncc status` | `ncc status` | Is it running? |
| `./ncc logs 100` | `ncc logs 100` | Last log lines |
| `./ncc restart` | `ncc restart` | Restart the dashboard (safe; takes ~10 s) |
| `./ncc test` | `ncc test` | Syntax + health + page check |
| `./ncc backup` | `ncc backup` | Backup to `backups/` (contains passwords: keep private) |

On Windows in PowerShell, type `.\ncc` instead of `ncc`. Read-only API endpoints you can query with curl or a browser on
this computer: `/api/health`, `/api/status` (latest checks + `findings`), `/api/devices`, `/api/history?hours=24`,
`/api/blocker/setup`. Changes go through POST requests that need the page's CSRF token: don't script them; use the
dashboard or ask the person.

## Fixing common problems

Always run the health report first and read its "Problems the dashboard sees" section.

- **Dashboard won't open.** `ncc status`. If not running: `ncc restart`, then `ncc logs 50`. A Python traceback in the
  log points to the line. Port 8088 already in use? Another copy may be running (`ss -tlnp | grep 8088` on Linux,
  `Get-NetTCPConnection -LocalPort 8088` on Windows).
- **"Internet down" but the router answers.** The provider or modem side. Compare "Router" and "Internet ping" in the
  report. Restarting the router is the person's decision: tell them how, don't do it.
- **"Router not responding".** This computer's Wi-Fi or cable. Check its connection first.
- **"DNS failing" while the internet is up.** Test the ad blocker directly: Linux `dig @127.0.0.1 example.com`,
  Windows `Resolve-DnsName example.com -Server 127.0.0.1`. If that fails, the ad blocker is down: Pi-hole
  `sudo systemctl status pihole-FTL` / `pihole status`; AdGuard Home `sudo systemctl status AdGuardHome` or on Windows
  `Get-Service AdGuardHome`. Restarting those services is fine to suggest (ask first). Short, repeated failures that
  recover by themselves are usually the upstream DNS or a busy Wi-Fi; check the ad blocker's query log for errors.
- **Ad blocker shows "Unreachable".** Wrong address or password in the settings: `PIHOLE_URL`/`ADGUARD_URL` in
  `config/ncc.env`, password key in secrets.env (check it exists; don't print it). Pi-hole's own web page is at
  `http://127.0.0.1:8081/admin`, AdGuard Home's at `http://127.0.0.1:8082`.
- **Ads still showing on other devices.** Devices aren't using the ad blocker yet. The dashboard's ad blocker tab has a
  "Whole-home setup" guide for their router. Never change the router yourself.
- **Phone can't open it through Tailscale.** `tailscale status` on the computer (is it "Running"?), and
  `tailscale serve status` (should point at `http://127.0.0.1:8088`). The phone needs the Tailscale app on and signed
  in with the same account.
- **Windows: no devices / no Wi-Fi list.** Device lists come from PowerShell `Get-NetNeighbor`; the Wi-Fi list needs
  Windows 11 Location turned on (Settings → Privacy & security → Location).
- **High memory or CPU.** The report lists the top memory users. The dashboard itself normally uses 50-100 MB.

## Changing the code

- Keep it standard-library only and stay compatible with Python 3.9. Match the style around your change: short
  functions, a one-line comment where the *why* isn't obvious.
- Security model (keep it): the server binds to `127.0.0.1`; every POST needs the `X-NCC-Token` header; requests from
  Tailscale/web are "remote" and get fewer powers (`_remote()`, `_manager()`, `_public()` in `ncc.py`); commands are
  fixed lists, and no text from a person or the network ever reaches a shell.
- Windows-only code goes in `app/ncc_win.py` behind `if WIN:`; keep the Linux path unchanged.
- Check your change: `python3 -I -m py_compile app/ncc.py app/ncc_win.py app/doctor.py`, then `./ncc restart` and
  `./ncc test`. For the page, open the dashboard and check the browser console for errors.
- Show the person what you changed and keep the backup until they're happy.

## Reporting a bug in the project itself

If it's a real bug in NCC (not a setting), help the person file it at
https://github.com/ollietech02/network-command-center/issues (Report a problem), with the steps and the health report.
Remove private details first.
