# The steps that need administrator rights, gathered in one place so Windows asks only once.
# Started by install.ps1 / uninstall.ps1 with "Run as administrator". It reads what to do from
# data\.setup-in.json and writes the results to data\.setup-out.json. Plain ASCII on purpose.
param([Parameter(Mandatory = $true)][string]$Dir)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with the progress bar on
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
. "$PSScriptRoot\common.ps1"

$In = Get-Content "$Dir\data\.setup-in.json" -Raw | ConvertFrom-Json
$Out = @{}
$AghDir = "$env:ProgramFiles\AdGuardHome"
$DnsBefore = "$AghDir\ncc-dns-before.json"
$RulePrefix = 'Network Command Center:'
try { Start-Transcript -Path "$Dir\data\setup-admin.log" -Force | Out-Null } catch {}

function Save { $Out | ConvertTo-Json | Set-Content "$Dir\data\.setup-out.json" -Encoding ASCII }

function DnsWorks($server) {
  try {
    $a = if ($server) { Resolve-DnsName example.com -Type A -Server $server -DnsOnly -QuickTimeout -ErrorAction Stop }
         else { Resolve-DnsName example.com -Type A -DnsOnly -QuickTimeout -ErrorAction Stop }
    return [bool]($a | Where-Object { $_.Type -eq 'A' })
  } catch { return $false }
}

function RestoreDns {
  if (-not (Test-Path $DnsBefore)) { return }
  $b = Get-Content $DnsBefore -Raw | ConvertFrom-Json
  if ($b.static) { Set-DnsClientServerAddress -InterfaceIndex $b.index -ServerAddresses ($b.static -split '[, ]+' | Where-Object { $_ }) }
  else { Set-DnsClientServerAddress -InterfaceIndex $b.index -ResetServerAddresses }
  Remove-Item $DnsBefore -Force
  Clear-DnsClientCache
}

function RemoveAdGuard {
  if (Test-Path "$AghDir\AdGuardHome.exe") { Start-Process "$AghDir\AdGuardHome.exe" -ArgumentList '-s', 'uninstall' -Wait -WindowStyle Hidden }
  RestoreDns
  Get-NetFirewallRule -DisplayName "$RulePrefix AdGuard Home*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

function InstallAdGuard {
  Step 'Installing AdGuard Home (ad blocker)'
  if (Test-Path "$AghDir\AdGuardHome.exe") { $Out.adguard = 'exists'; Warn 'AdGuard Home is already installed. Leaving it alone.'; return }
  if (Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' }) {
    throw 'Another program on this computer already answers DNS (port 53), so AdGuard Home cannot start. Nothing was changed.'
  }
  $a = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } 'x86' { '386' } default { throw 'No AdGuard Home build for this processor.' } }
  $f = "AdGuardHome_windows_$a.zip"
  $base = 'https://github.com/AdguardTeam/AdGuardHome/releases/latest/download'
  $tmp = Join-Path $env:TEMP ("ncc-agh-" + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  Invoke-WebRequest "$base/$f" -OutFile "$tmp\$f" -UseBasicParsing
  Invoke-WebRequest "$base/checksums.txt" -OutFile "$tmp\checksums.txt" -UseBasicParsing
  $want = (Get-Content "$tmp\checksums.txt" | Where-Object { $_ -match "\s(\./)?$([regex]::Escape($f))$" } | Select-Object -First 1)
  if (-not $want) { throw 'The AdGuard Home checksum list has no entry for this download. Stopped.' }
  $want = ($want -split '\s+')[0].ToLower()
  $got = (Get-FileHash "$tmp\$f" -Algorithm SHA256).Hash.ToLower()
  if ($want -ne $got) { throw "AdGuard Home download didn't match its checksum. Stopped." }
  Ok 'Downloaded AdGuard Home from github.com/AdguardTeam (checksum OK)'
  Expand-Archive "$tmp\$f" -DestinationPath $env:ProgramFiles -Force
  Remove-Item $tmp -Recurse -Force
  # Start-Process, not &: AdGuard Home logs to stderr, which Windows PowerShell 5.1 would treat as an error
  $p = Start-Process "$AghDir\AdGuardHome.exe" -ArgumentList '-s', 'install' -Wait -PassThru -WindowStyle Hidden
  if ($p.ExitCode -ne 0) { throw "AdGuard Home's service didn't install." }

  try {
    for ($i = 0; $i -lt 30; $i++) { try { Invoke-WebRequest 'http://127.0.0.1:3000/' -UseBasicParsing -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep 1 } }
    $body = @{ web = @{ ip = '127.0.0.1'; port = [int]$In.agh_port }; dns = @{ ip = '0.0.0.0'; port = 53 }; username = 'admin'; password = $In.agh_pw } | ConvertTo-Json
    Invoke-WebRequest 'http://127.0.0.1:3000/control/install/configure' -Method Post -Body $body -ContentType 'application/json' -UseBasicParsing -TimeoutSec 30 | Out-Null
    Start-Sleep 3
    if (-not (DnsWorks '127.0.0.1')) { throw "AdGuard Home doesn't answer lookups" }
    Ok 'AdGuard Home is running and answering'

    # This computer asks AdGuard Home first, with a public DNS as the backup if AdGuard Home ever stops
    $g = (Get-NetAdapter -InterfaceIndex $In.ifindex).InterfaceGuid
    $static = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -ErrorAction SilentlyContinue).NameServer
    @{ index = [int]$In.ifindex; static = [string]$static } | ConvertTo-Json | Set-Content $DnsBefore -Encoding ASCII
    Set-DnsClientServerAddress -InterfaceIndex $In.ifindex -ServerAddresses '127.0.0.1', '1.1.1.1'
    Clear-DnsClientCache
    Start-Sleep 2
    if (-not (DnsWorks $null)) { throw "this computer can't look up names through AdGuard Home" }
    Ok "This computer's own lookups now go through AdGuard Home"
    $Out.adguard = 'ok'
  } catch {
    $why = $_.Exception.Message
    Fail "$why. Undoing so this computer keeps working."
    RemoveAdGuard
    if (Test-Path $AghDir) { Remove-Item $AghDir -Recurse -Force -ErrorAction SilentlyContinue }
    throw "$why. AdGuard Home was not set up; your internet works as before."
  }
}

function AllowDns {
  # Other devices at home may ask AdGuard Home. Home (Private) networks and the local subnet only.
  Get-NetFirewallRule -DisplayName "$RulePrefix AdGuard Home*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  foreach ($p in 'UDP', 'TCP') {
    New-NetFirewallRule -DisplayName "$RulePrefix AdGuard Home DNS ($p, home network)" -Direction Inbound -Protocol $p -LocalPort 53 `
      -RemoteAddress LocalSubnet -Profile Private, Domain -Action Allow -Program "$AghDir\AdGuardHome.exe" | Out-Null
  }
  Ok 'Windows Firewall: devices on your home network may use AdGuard Home (port 53, home network only)'
  $Out.firewall = 'ok'
}

function MakePrivate {
  Set-NetConnectionProfile -InterfaceIndex $In.ifindex -NetworkCategory Private
  Ok 'This network is now marked as a Private (home) network'
  $Out.private = 'ok'
}

function InstallTailscale {
  Step 'Installing Tailscale'
  if (TailscaleExe) { Ok 'Tailscale is already installed'; $Out.tailscale = 'ok'; return }
  $a = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } elseif ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') { 'amd64' } else { 'x86' }
  $msi = Join-Path $env:TEMP "tailscale-setup-$a.msi"
  Invoke-WebRequest "https://pkgs.tailscale.com/stable/tailscale-setup-latest-$a.msi" -OutFile $msi -UseBasicParsing
  $sig = Get-AuthenticodeSignature $msi
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Tailscale') {
    Remove-Item $msi -Force; throw "The Tailscale download isn't signed by Tailscale. Stopped."
  }
  Ok 'Downloaded Tailscale from pkgs.tailscale.com (signed by Tailscale Inc.)'
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /quiet /norestart" -Wait -PassThru
  Remove-Item $msi -Force -ErrorAction SilentlyContinue
  if ($p.ExitCode -notin 0, 3010) { throw "Tailscale didn't install (code $($p.ExitCode))." }
  Ok 'Tailscale installed'
  $Out.tailscale = 'ok'
}

function EnableRdp {
  Step 'Turning on Remote Desktop'
  if (IsHomeEdition) { throw 'Windows Home cannot accept Remote Desktop connections (Pro, Education and Enterprise can).' }
  Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
  Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
  Get-NetFirewallRule -DisplayName "$RulePrefix Remote Desktop*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  # Only the home network and Tailscale; Windows' own Remote Desktop rules (open to any address) stay off
  New-NetFirewallRule -DisplayName "$RulePrefix Remote Desktop (home network)" -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress LocalSubnet -Profile Private, Domain -Action Allow | Out-Null
  New-NetFirewallRule -DisplayName "$RulePrefix Remote Desktop (Tailscale)" -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress 100.64.0.0/10 -Action Allow | Out-Null
  Ok 'Remote Desktop is on (home network and Tailscale only)'
  $Out.rdp = 'ok'
}

function DisableRdp {
  Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
  Get-NetFirewallRule -DisplayName "$RulePrefix Remote Desktop*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  Ok 'Remote Desktop is off'
  $Out.rdp_off = 'ok'
}

function UninstallAdGuard {
  RemoveAdGuard
  Remove-Item $AghDir -Recurse -Force -ErrorAction SilentlyContinue
  Ok 'AdGuard Home removed and DNS restored'
  $Out.adguard_off = 'ok'
}

function UninstallTailscale {
  $k = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
       Get-ItemProperty | Where-Object { $_.DisplayName -eq 'Tailscale' -and $_.PSChildName -match '^\{' } | Select-Object -First 1
  if (-not $k) { throw 'Tailscale was not found in the installed programs list. Remove it in Settings -> Apps.' }
  Start-Process msiexec.exe -ArgumentList "/x $($k.PSChildName) /quiet /norestart" -Wait
  Ok 'Tailscale removed'
  $Out.tailscale_off = 'ok'
}

$steps = [ordered]@{ adguard = { InstallAdGuard }; firewall = { AllowDns }; private = { MakePrivate }; tailscale = { InstallTailscale }
                     rdp = { EnableRdp }; rdp_off = { DisableRdp }; adguard_off = { UninstallAdGuard }; tailscale_off = { UninstallTailscale } }
foreach ($k in $steps.Keys) {
  if ($In.tasks -notcontains $k) { continue }
  if ($k -eq 'firewall' -and $Out.adguard -ne 'ok') { continue }
  try { & $steps[$k] } catch { Fail $_.Exception.Message; $Out[$k] = $_.Exception.Message }
  Save
}
Save
try { Stop-Transcript | Out-Null } catch {}
