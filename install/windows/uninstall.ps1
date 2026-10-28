# Removes the Network Command Center from Windows. Asks separately about AdGuard Home, Tailscale and
# Remote Desktop, because you may use them for other things. Your dashboard history is kept unless you say so.
# Plain ASCII on purpose: Windows PowerShell 5.1 misreads other characters in files without a BOM.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"
$Dir = (Resolve-Path "$PSScriptRoot\..\..").Path
$Conf = "$Dir\config\ncc.env"

Step 'Removing the dashboard'
& "$PSScriptRoot\ncc.ps1" uninstall | Out-Null
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Network Command Center.lnk", "$([Environment]::GetFolderPath('Desktop'))\Network Command Center.lnk" -ErrorAction SilentlyContinue
Ok 'Dashboard stopped and removed from startup'

$tasks = @()
$ts = TailscaleExe
if ($ts) {
  $sv = try { & $ts serve status 2>$null | Out-String } catch { '' }
  if ($sv -match '127\.0\.0\.1:8088' -and (Ask 'Stop sharing the dashboard on Tailscale?' 'y')) { try { & $ts serve reset 2>$null; & $ts funnel reset 2>$null } catch {}; Ok 'Sharing stopped' }
}
if ((Test-Path "$env:ProgramFiles\AdGuardHome\AdGuardHome.exe") -and (Ask 'Uninstall AdGuard Home too? (ads stop being blocked)' 'n')) { $tasks += 'adguard_off' }
if ($ts -and (Ask 'Uninstall Tailscale too? (your phone loses access to this computer)' 'n')) { try { & $ts logout 2>$null } catch {}; $tasks += 'tailscale_off' }
if ((EnvGet $Conf REMOTE_DESKTOP) -eq '1' -and (Ask 'Turn off Remote Desktop?' 'n')) { $tasks += 'rdp_off' }

if ($tasks.Count) {
  New-Item -ItemType Directory -Force -Path "$Dir\data" | Out-Null
  @{ tasks = $tasks } | ConvertTo-Json | Set-Content "$Dir\data\.setup-in.json" -Encoding ASCII
  Step 'Administrator steps (click Yes when Windows asks)'
  try {
    Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSScriptRoot\admin.ps1`"", '-Dir', "`"$Dir`"")
    $o = Get-Content "$Dir\data\.setup-out.json" -Raw | ConvertFrom-Json
    foreach ($k in $tasks) { if ($o.$k -eq 'ok') { Ok "$k done" } else { Fail "$k : $($o.$k)" } }
  } catch { Warn 'Administrator permission was not given, so those parts were left as they are.' }
  Remove-Item "$Dir\data\.setup-in.json", "$Dir\data\.setup-out.json" -ErrorAction SilentlyContinue
  if ($tasks -contains 'rdp_off') { EnvSet $Conf REMOTE_DESKTOP 0 }
}
if (Ask "Delete the dashboard's history, accounts and saved passwords? (can't be undone)" 'n') {
  Remove-Item "$Dir\data", "$env:USERPROFILE\.config\ncc" -Recurse -Force -ErrorAction SilentlyContinue; Ok 'Deleted'
}
Say ''
Say "  The program files are still in $Dir. Delete that folder if you don't want them."
Read-Host 'Press Enter to close' | Out-Null
