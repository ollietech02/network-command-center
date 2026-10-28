# Shared helpers for the Windows installer, uninstaller and the ncc control script.
# Plain ASCII on purpose: Windows PowerShell 5.1 misreads other characters in files without a BOM.

$Task = 'Network Command Center'

function Say($m)  { Write-Host $m }
function Step($m) { Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "  [x]  $m" -ForegroundColor Red }
function Die($m)  { Fail $m; Write-Host ''; Read-Host 'Press Enter to close' | Out-Null; exit 1 }

function Ask($q, $def = 'y') {
  if ($script:AssumeYes) { return $def -eq 'y' }
  $hint = if ($def -eq 'y') { '[Y/n]' } else { '[y/N]' }
  while ($true) {
    $a = (Read-Host "  $q $hint").Trim().ToLower()
    if ($a -eq '') { $a = $def }
    if ($a -in 'y', 'yes') { return $true }
    if ($a -in 'n', 'no') { return $false }
  }
}

# Choose 'Question' @('key|Text', ...) -> key. The first one is the default.
function Choose($q, $opts) {
  if ($script:AssumeYes) { return $opts[0].Split('|')[0] }
  Write-Host ''; Write-Host "  $q" -ForegroundColor White
  for ($i = 0; $i -lt $opts.Count; $i++) { Write-Host ("    {0}) {1}" -f ($i + 1), $opts[$i].Split('|', 2)[1]) }
  while ($true) {
    $a = (Read-Host "  Type a number [1]").Trim()
    if ($a -eq '') { $a = '1' }
    $n = 0
    if ([int]::TryParse($a, [ref]$n) -and $n -ge 1 -and $n -le $opts.Count) { return $opts[$n - 1].Split('|')[0] }
  }
}

function RandPw($len = 24) {
  $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  $b = New-Object byte[] ($len * 2)
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  -join ($b | Select-Object -First $len | ForEach-Object { $chars[$_ % $chars.Length] })
}

# KEY=value in a settings file (UTF-8 without BOM, which is what the dashboard reads)
function EnvSet($file, $key, $val) {
  $lines = @()
  if (Test-Path $file) { $lines = @([IO.File]::ReadAllLines($file)) }
  $found = $false
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "^\s*#?\s*$([regex]::Escape($key))=") { $lines[$i] = "$key=$val"; $found = $true; break }
  }
  if (-not $found) { $lines += "$key=$val" }
  [IO.File]::WriteAllLines($file, [string[]]$lines)
}

function EnvGet($file, $key) {
  if (-not (Test-Path $file)) { return $null }
  foreach ($l in [IO.File]::ReadAllLines($file)) { if ($l -match "^\s*$([regex]::Escape($key))=(.*)$") { return $Matches[1].Trim() } }
  return $null
}

# The secrets folder is readable only by this Windows account (and the system).
function SecretsReady($dir, $file) {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  if (-not (Test-Path $file)) { [IO.File]::WriteAllText($file, '') }
  # Only this account and Windows itself (SYSTEM) may read it. Name the account by its SID: USERDOMAIN\USERNAME
  # isn't always the real account name (Microsoft accounts, renamed users), and a wrong name would lock everyone out.
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & icacls.exe $dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*${sid}:(OI)(CI)F" /Q | Out-Null
  & icacls.exe $file /reset /Q | Out-Null   # the file takes the folder's permissions
  try { [IO.File]::AppendAllText($file, '') } catch { Die "Can't write $file after protecting it: $($_.Exception.Message)" }
}

function NetDetect {
  $r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' } |
       Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
  if (-not $r) { return $null }
  $a = Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  $p = Get-NetConnectionProfile -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1
  [pscustomobject]@{ Index = $r.ifIndex; Alias = $r.InterfaceAlias; Gateway = $r.NextHop; IP = $a.IPAddress
                     Category = [string]$p.NetworkCategory }
}

# A real Python 3.9+ (not the Microsoft Store shortcut). Returns the path to python.exe, or $null.
function FindPython {
  $cands = @()
  $py = Get-Command py.exe -ErrorAction SilentlyContinue
  if ($py) { try { $cands += (& $py.Source -3 -c 'import sys;print(sys.executable)' 2>$null) } catch {} }
  $cands += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe", "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | ForEach-Object FullName
  $p = Get-Command python.exe -ErrorAction SilentlyContinue
  if ($p -and $p.Source -notlike '*WindowsApps*') { $cands += $p.Source }
  foreach ($c in $cands) {
    if (-not $c -or -not (Test-Path $c)) { continue }
    try { & $c -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>$null; if ($LASTEXITCODE -eq 0) { return $c } } catch {}
  }
  return $null
}

function RouterIsAtt($gw) {
  if (-not $gw) { return $false }
  try { (Invoke-WebRequest "http://$gw/cgi-bin/sysinfo.ha" -UseBasicParsing -TimeoutSec 4).Content -match 'Model Number' } catch { $false }
}

function IsHomeEdition {
  $e = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).EditionID
  return ($e -like 'Core*')
}

function TailscaleExe {
  $c = Get-Command tailscale.exe -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $p = "$env:ProgramFiles\Tailscale\tailscale.exe"
  if (Test-Path $p) { return $p }
  return $null
}

function Health($port) {
  try { (Invoke-WebRequest "http://127.0.0.1:$port/api/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200 } catch { $false }
}
