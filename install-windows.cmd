@echo off
rem Network Command Center installer for Windows 10 and 11. Double-click it, or run: install-windows.cmd -Pack shield
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\windows\install.ps1" %*
if errorlevel 1 pause
