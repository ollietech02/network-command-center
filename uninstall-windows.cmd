@echo off
rem Removes the Network Command Center from Windows (asks about each extra separately).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\windows\uninstall.ps1"
