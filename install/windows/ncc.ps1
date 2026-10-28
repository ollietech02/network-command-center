# Network Command Center control script for Windows. Usage: ncc {start|stop|restart|status|logs [n]|doctor|open|test|backup|uninstall}
# (ncc.cmd in the main folder runs this.) It runs as a Task Scheduler task that starts when you sign in.
param([string]$Cmd = 'status', [string]$Arg = '')
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"
$Dir = (Resolve-Path "$PSScriptRoot\..\..").Path
$Conf = "$Dir\config\ncc.env"
$Port = EnvGet $Conf PORT; if (-not $Port) { $Port = 8088 }
$Url = "http://127.0.0.1:$Port"

function TaskExists { [bool](Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue) }

function InstallTask {
  $py = EnvGet $Conf PYTHONW
  if (-not $py -or -not (Test-Path $py)) {
    $p = FindPython; if (-not $p) { throw 'Python not found. Run install-windows.cmd again.' }
    $py = Join-Path (Split-Path $p) 'pythonw.exe'; EnvSet $Conf PYTHONW $py
  }
  $me = "$env:USERDOMAIN\$env:USERNAME"
  $a = New-ScheduledTaskAction -Execute $py -Argument "-X utf8 -I `"$Dir\app\ncc.py`"" -WorkingDirectory $Dir
  $t = New-ScheduledTaskTrigger -AtLogOn -User $me
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
         -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -Priority 7   # below normal, like Nice=10 on Linux
  $p = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName $Task -Action $a -Trigger $t -Settings $s -Principal $p -Description 'Home network dashboard' -Force | Out-Null
}

function WaitUp { for ($i = 0; $i -lt 20; $i++) { if (Health $Port) { return $true }; Start-Sleep 1 }; return $false }

switch ($Cmd) {
  'start' {
    InstallTask; Start-ScheduledTask -TaskName $Task
    if (-not (WaitUp)) {
      # Task Scheduler didn't start it (it needs a signed-in desktop session): start it directly this time
      Warn 'Task Scheduler did not start the dashboard; starting it directly. It will start with Windows after the next sign-in.'
      Start-Process (EnvGet $Conf PYTHONW) -ArgumentList '-X', 'utf8', '-I', "`"$Dir\app\ncc.py`"" -WorkingDirectory $Dir -WindowStyle Hidden
      [void](WaitUp)
    }
    Say "Dashboard: $Url"
  }
  'stop' { if (TaskExists) { Stop-ScheduledTask -TaskName $Task } }
  'restart' {
    InstallTask
    Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 10 -and (Health $Port); $i++) { Start-Sleep 1 }
    Start-ScheduledTask -TaskName $Task; [void](WaitUp); Say "Dashboard: $Url"
  }
  'status' {
    if (TaskExists) { $t = Get-ScheduledTask -TaskName $Task; Say "Task: $($t.State)" } else { Say 'Task: not installed' }
    try { Say (Invoke-WebRequest "$Url/api/health" -UseBasicParsing -TimeoutSec 5).Content } catch { Say 'health endpoint not responding' }
  }
  'logs' { $n = if ($Arg) { [int]$Arg } else { 100 }; if (Test-Path "$Dir\data\ncc.log") { Get-Content "$Dir\data\ncc.log" -Tail $n } else { Say 'No log yet.' } }
  'open' { Start-Process "http://localhost:$Port/" }
  'doctor' { $py = (EnvGet $Conf PYTHONW) -replace 'pythonw\.exe$', 'python.exe'; & $py -X utf8 -I "$Dir\app\doctor.py" $Arg }
  'test' {
    $py = EnvGet $Conf PYTHONW; $py = $py -replace 'pythonw\.exe$', 'python.exe'
    & $py -I -m py_compile "$Dir\app\ncc.py" "$Dir\app\ncc_win.py" "$Dir\app\doctor.py"; if ($LASTEXITCODE -eq 0) { Say 'syntax OK' } else { Say 'syntax FAIL'; exit 1 }
    if (Health $Port) { Say 'health OK' } else { Say 'health FAIL'; exit 1 }
    try { if ((Invoke-WebRequest "$Url/" -UseBasicParsing -TimeoutSec 10).Content -match 'Network Command Center') { Say 'UI OK' } else { throw 'x' } } catch { Say 'UI FAIL'; exit 1 }
  }
  'backup' {
    New-Item -ItemType Directory -Force -Path "$Dir\backups" | Out-Null
    $stage = Join-Path $env:TEMP ("ncc-backup-" + [guid]::NewGuid()); New-Item -ItemType Directory -Path "$stage\data", "$stage\secrets" | Out-Null
    $py = (EnvGet $Conf PYTHONW) -replace 'pythonw\.exe$', 'python.exe'
    if (Test-Path "$Dir\data\ncc.db") { & $py -I -c "import sqlite3,sys;s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d)" "$Dir\data\ncc.db" "$stage\data\ncc.db" }
    Get-ChildItem "$Dir\data" -Force -File | Where-Object { $_.Name -in '.ntfy', '.alert_email', '.web_logins', '.remote_pin', '.blocked_devices', '.smtp' } | Copy-Item -Destination "$stage\data"
    Copy-Item "$Dir\config" "$stage\config" -Recurse
    Copy-Item "$env:USERPROFILE\.config\ncc\*" "$stage\secrets" -ErrorAction SilentlyContinue
    $f = "$Dir\backups\ncc-$(Get-Date -Format yyyyMMdd-HHmmss).zip"
    Compress-Archive "$stage\*" $f; Remove-Item $stage -Recurse -Force
    Say "Backup written: $f (contains passwords - keep it private)"
  }
  'uninstall' {
    if (TaskExists) { Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $Task -Confirm:$false }
    Say "Dashboard removed from startup. Program files left in $Dir."
  }
  default { Say 'usage: ncc {start|stop|restart|status|logs [n]|doctor|open|test|backup|uninstall}'; exit 1 }
}
