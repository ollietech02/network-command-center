@echo off
rem Network Command Center control script for Windows. Usage: ncc start, stop, restart, status, logs, open, test, backup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\windows\ncc.ps1" %*
