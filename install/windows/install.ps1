# Network Command Center installer for Windows 10 and 11.
#
#   install-windows.cmd                     pick a pack from a menu
#   install-windows.cmd -Pack everything    no menu (packs: dashboard, shield, everything)
#   install-windows.cmd -Pack shield -Yes   no questions at all (accepts the defaults)
#
# Run it as your normal user. Windows asks once for administrator permission if a step needs it.
# Plain ASCII on purpose: Windows PowerShell 5.1 misreads other characters in files without a BOM.
param([string]$Pack = '', [switch]$Yes, [switch]$Help)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
. "$PSScriptRoot\common.ps1"

$Dir = (Resolve-Path "$PSScriptRoot\..\..").Path
$Conf = "$Dir\config\ncc.env"
$SecDir = "$env:USERPROFILE\.config\ncc"
$Secrets = "$SecDir\secrets.env"
$Port = 8088; $AghPort = 8082
$script:AssumeYes = [bool]$Yes
if ($Help) { Get-Content $PSCommandPath | Select-Object -Skip 1 -First 7 | ForEach-Object { $_ -replace '^# ?', '' }; exit 0 }

Write-Host ''
Write-Host '  NCC // NETWORK COMMAND CENTER' -ForegroundColor Cyan
Write-Host '  A home network dashboard: internet health, speed tests, devices, ad blocking and alerts.'
Write-Host ''

$build = [Environment]::OSVersion.Version.Build
if ($build -lt 17763) { Die 'Needs Windows 10 (version 1809 or newer) or Windows 11.' }
$Net = NetDetect
if (-not $Net) { Die "No network connection found. Connect to your home Wi-Fi or network and run this again." }
$WinName = if ($build -ge 22000) { 'Windows 11' } else { 'Windows 10' }
Ok "$WinName ($env:PROCESSOR_ARCHITECTURE), network connection found"
$Python = FindPython
$HomeEd = IsHomeEdition

# ------------------------------------------------------------------ choose what to install
if (-not $Pack) {
  $everything = 'everything|Everything - dashboard + AdGuard Home + Tailscale (phone access from anywhere)' + $(if (-not $HomeEd) { ' + Remote Desktop' } else { '' }) + '.'
  $Pack = Choose 'Which pack do you want?' @(
    'dashboard|Dashboard only - just the dashboard. Nothing else is installed.',
    'shield|Home Shield - dashboard + AdGuard Home ad blocker for every device at home.',
    $everything,
    'custom|Custom - choose each piece yourself.')
}
$Style = 'scifi'; $Blocker = 'none'; $Tailscale = $false; $Rdp = $false; $Controls = $false
switch ($Pack) {
  'dashboard' { }
  'shield' { $Blocker = 'adguard' }
  'everything' { $Blocker = 'adguard'; $Tailscale = $true; $Controls = $true; $Rdp = -not $HomeEd }
  'custom' {
    $Style = Choose 'Which look?' @('scifi|Sci-fi - dark command center with glowing accents', 'hacker|Hacker - black and green terminal', 'clean|Clean - light, simple and friendly')
    $Blocker = Choose 'Ad blocker for your whole home?' @('adguard|AdGuard Home - blocks ads and trackers for every device (Pi-hole needs Linux)', 'none|None')
    Write-Host ''
    $Tailscale = Ask 'Install Tailscale, so you can open the dashboard from your phone anywhere? (free account)' 'y'
    if (-not $HomeEd) { $Rdp = Ask 'Turn on Remote Desktop (control this computer from another one)?' 'n' }
    $Controls = Ask 'Show restart buttons (dashboard, this computer) on the dashboard?' 'y'
  }
  default { Die "Unknown pack '$Pack'. Use: dashboard, shield, everything or custom." }
}
$Router = if (RouterIsAtt $Net.Gateway) { 'att' } else { 'generic' }
$Private = $Net.Category -in 'Private', 'DomainAuthenticated'
$MakePrivate = $false
if ($Blocker -eq 'adguard' -and -not $Private) {
  Write-Host ''
  Warn 'Windows treats this network as "Public", which stops other devices at home from using the ad blocker.'
  $MakePrivate = Ask 'Is this your home network? If yes, mark it as a Private (home) network' 'y'
}

# ------------------------------------------------------------------ say exactly what will happen, then ask
Step "Here's the plan"
if (-not $Python) { Say '  * Install Python 3.12 (the language the dashboard is written in) from python.org, just for you' }
Say "  * Install the dashboard in $Dir and start it at http://localhost:$Port (only this computer can open it)"
Say '  * Start it automatically when you sign in to Windows'
Say "  * Look: $Style (you can change it any time in Tools & settings)"
if ($Router -eq 'att') { Say '  * AT&T gateway found: extra router stats turned on (read-only)' }
if ($Blocker -eq 'adguard') {
  Say "  * Install AdGuard Home. This computer's own lookups go through it (1.1.1.1 as the backup). Your router is NOT changed."
  Say '  * Windows Firewall: let devices on your home network use it (port 53, home network only)'
}
if ($MakePrivate) { Say '  * Mark this network as Private (home)' }
if ($Tailscale) { Say '  * Install Tailscale and help you make a free account (private access from your phone)' }
if ($Rdp) { Say '  * Turn on Remote Desktop, reachable only from your home network and Tailscale' }
Say '  * Nothing is opened to the internet, and no router or Wi-Fi settings are changed.'
$needAdmin = $Blocker -eq 'adguard' -or $MakePrivate -or $Tailscale -or $Rdp
if ($needAdmin) { Say '  * Windows will ask once for permission ("Do you want to allow this app to make changes?"): click Yes.' }
Write-Host ''
if (-not (Ask 'Go ahead?' 'y')) { Say '  Nothing was changed.'; exit 0 }

# ------------------------------------------------------------------ Python
if (-not $Python) {
  Step 'Installing Python'
  if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
    Die 'Python is needed. Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH"), then run this again.'
  }
  & winget.exe install -e --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements | Out-Host
  $Python = FindPython
  if (-not $Python) { Die 'Python did not install. Install it from https://www.python.org/downloads/, then run this again.' }
  Ok 'Python installed'
}
$PythonW = Join-Path (Split-Path $Python) 'pythonw.exe'
if (-not (Test-Path $PythonW)) { $PythonW = $Python }

# ------------------------------------------------------------------ settings
Step 'Saving settings'
New-Item -ItemType Directory -Force -Path "$Dir\config", "$Dir\data" | Out-Null
if (-not (Test-Path $Conf)) { Copy-Item "$Dir\config\ncc.env.example" $Conf }
EnvSet $Conf PORT $Port
EnvSet $Conf STYLE $Style
EnvSet $Conf ROUTER $Router
EnvSet $Conf SYSTEM_CONTROLS $(if ($Controls) { 1 } else { 0 })
EnvSet $Conf PYTHONW $PythonW
SecretsReady $SecDir $Secrets
Ok "Settings saved in $Conf"

# ------------------------------------------------------------------ the administrator steps, all at once
$BlockerDone = $null; $TsUrl = $null; $AdminOut = @{}
if ($needAdmin) {
  $tasks = @()
  if ($Blocker -eq 'adguard') { $tasks += 'adguard', 'firewall' }
  if ($MakePrivate) { $tasks += 'private' }
  if ($Tailscale) { $tasks += 'tailscale' }
  if ($Rdp) { $tasks += 'rdp' }
  $aghPw = RandPw 24
  $in = "$Dir\data\.setup-in.json"
  @{ tasks = $tasks; ifindex = $Net.Index; agh_port = $AghPort; agh_pw = $aghPw } | ConvertTo-Json | Set-Content $in -Encoding ASCII
  Remove-Item "$Dir\data\.setup-out.json" -ErrorAction SilentlyContinue
  Step 'Administrator steps (a separate window opens; click Yes when Windows asks)'
  try {
    Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSScriptRoot\admin.ps1`"", '-Dir', "`"$Dir`"")
  } catch { Warn 'Administrator permission was not given, so the ad blocker, Tailscale and Remote Desktop steps were skipped.' }
  Remove-Item $in -Force -ErrorAction SilentlyContinue   # it held the new AdGuard Home password
  if (Test-Path "$Dir\data\.setup-out.json") { $AdminOut = Get-Content "$Dir\data\.setup-out.json" -Raw | ConvertFrom-Json; Remove-Item "$Dir\data\.setup-out.json" }
  foreach ($k in $tasks) {
    $v = $AdminOut.$k
    if ($v -and $v -notin 'ok', 'exists') { Fail "$k : $v" }
  }
  if ($AdminOut.adguard -eq 'ok') {
    Add-Content $Secrets "ADGUARD_USER=admin"; Add-Content $Secrets "ADGUARD_PASSWORD=$aghPw"
    EnvSet $Conf ADGUARD_URL "http://127.0.0.1:$AghPort"
    EnvSet $Conf PIHOLE_LISTS 1
    Ok "Dashboard connected to AdGuard Home (user admin; password in $Secrets)"
    $BlockerDone = 'AdGuard Home'
  } elseif ($AdminOut.adguard -eq 'exists') {
    EnvSet $Conf ADGUARD_URL "http://127.0.0.1:$AghPort"
    Warn "AdGuard Home was already installed. Put its username and password in $Secrets as ADGUARD_USER= and ADGUARD_PASSWORD=, then run: ncc restart"
    $BlockerDone = 'AdGuard Home'
  }
  if ($Rdp -and $AdminOut.rdp -eq 'ok') { EnvSet $Conf REMOTE_DESKTOP 1; EnvSet $Conf RDP_USER $env:USERNAME }
}

# ------------------------------------------------------------------ start the dashboard
Step 'Starting the dashboard'
& "$Dir\install\windows\ncc.ps1" start | Out-Null
$up = $false
for ($i = 0; $i -lt 25; $i++) { if (Health $Port) { $up = $true; break }; Start-Sleep 1 }
if ($up) { Ok 'Dashboard running' } else { Warn "Dashboard didn't answer yet. Check: ncc logs" }

# Start menu + desktop shortcut that opens it like an app (Microsoft Edge app window)
$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
$sh = New-Object -ComObject WScript.Shell
foreach ($lnk in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Network Command Center.lnk", "$([Environment]::GetFolderPath('Desktop'))\Network Command Center.lnk")) {
  $s = $sh.CreateShortcut($lnk)
  if ($edge) { $s.TargetPath = $edge; $s.Arguments = "--app=http://localhost:$Port/" } else { $s.TargetPath = "http://localhost:$Port/" }
  $s.IconLocation = "$Dir\app\static\icon.ico"
  $s.Description = 'Home network dashboard'
  $s.Save()
}
Ok 'Added "Network Command Center" to the Start menu and desktop'

# ------------------------------------------------------------------ Tailscale sign-in (as you, not as administrator)
if ($Tailscale -and $AdminOut.tailscale -eq 'ok') {
  Step 'Tailscale sign-in'
  $ts = TailscaleExe
  $state = try { (& $ts status --json | ConvertFrom-Json).BackendState } catch { '' }
  if ($state -ne 'Running') {
    Say ''
    Say '  Time to make your free Tailscale account.'
    Say '  1. A sign-in link appears below (or a browser opens). Open it.'
    Say '  2. Sign in with Google, Microsoft, Apple or GitHub. That creates the account; it is free.'
    Say '  3. Click Connect. This installer continues by itself when you are done.'
    Say '  Then put the Tailscale app on your phone and sign in with the same account.'
    Say ''
    & $ts up | Out-Host
  }
  $st = try { & $ts status --json | ConvertFrom-Json } catch { $null }
  if ($st -and $st.BackendState -eq 'Running') {
    Ok 'Signed in to Tailscale'
    $dns = $st.Self.DNSName.TrimEnd('.')
    EnvSet $Conf ALLOWED_HOSTS $dns
    Say '  Sharing the dashboard on your private Tailscale network...'
    & $ts serve --bg "http://127.0.0.1:$Port" | Out-Host
    if ($LASTEXITCODE -ne 0) {
      Warn 'Tailscale asked to turn on HTTPS for your account. Open the link above, click Enable, then press Enter.'
      if (-not $script:AssumeYes) { Read-Host '  Press Enter to continue' | Out-Null }
      & $ts serve --bg "http://127.0.0.1:$Port" | Out-Host
      if ($LASTEXITCODE -ne 0) { Warn "Sharing didn't turn on. Later: tailscale serve --bg http://127.0.0.1:$Port" }
    }
    $TsUrl = "https://$dns"
    & "$Dir\install\windows\ncc.ps1" restart | Out-Null
    Ok "On your phone (with Tailscale on): $TsUrl"
  } else { Warn 'Tailscale sign-in did not finish. Open the Tailscale app from the Start menu to sign in later.' }
}

# ------------------------------------------------------------------ what's left for you
Step "Done! Here's what's left for you"
Say "  Open the dashboard: http://localhost:$Port  (or ""Network Command Center"" in the Start menu)"
if ($TsUrl) { Say "  On your phone: turn Tailscale on, open $TsUrl, and set a PIN on this computer first (Security tab)." }
if ($AdminOut.rdp -eq 'ok') { Say "  Remote Desktop: connect to this computer's name or address and sign in with your normal Windows account ($env:USERNAME)." }
if ($BlockerDone) {
  Say "  Make $BlockerDone protect every device at home (the installer never changes your router):"
  if ($Router -eq 'att') {
    Say "    AT&T gateways don't let you change the DNS server, and on Windows $BlockerDone can't hand out addresses,"
    Say "    so set the DNS on each device to this computer's address. The dashboard's $BlockerDone tab shows how."
    Say '    (For the whole home at once on AT&T, use a Raspberry Pi or Linux computer with Pi-hole instead.)'
  } else {
    Say "    1. In your router's settings, give this computer a fixed address (""DHCP reservation"") so it stays $($Net.IP)."
    Say "    2. Set the router's DNS server to $($Net.IP)."
    Say "       (That address is private: it only works inside your home and isn't visible on the internet.)"
    Say "    The dashboard's $BlockerDone tab has a ""Whole-home setup"" guide with steps for popular routers."
  }
  Say "    Until then, only this computer's ads are blocked."
}
Say '  Phone alerts and email codes: set them up in the dashboard, Security tab (free; nothing to install).'
Say "  Everyday commands: open a terminal in $Dir and type: ncc status | ncc restart | ncc logs"
Say "  Uninstall: double-click uninstall-windows.cmd in $Dir"
Write-Host ''
if (-not $script:AssumeYes) { Read-Host 'Press Enter to close' | Out-Null }
